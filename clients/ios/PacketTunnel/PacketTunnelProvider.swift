import Foundation
import Network
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let workQueue = DispatchQueue(label: "org.onionroute.packet-tunnel")
    private let pathMonitor = NWPathMonitor()
    private var core: RustCore?
    private var acceptingPackets = false
    private var lastPathHealthy = false

    override func startTunnel(
        options: [String: NSObject]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        workQueue.async { [weak self] in
            guard let self else { return }
            do {
                let configuration = try self.validatedConfiguration()
                let core = try RustCore(eventCapacity: 256, memoryBudgetBytes: 48 * 1024 * 1024)
                try core.setCountry(configuration.country)
                try core.setMode(configuration.mode)
                try core.connect()
                self.core = core
                self.startPathMonitor()
                self.setTunnelNetworkSettings(self.networkSettings()) { error in
                    self.workQueue.async {
                        if let error {
                            try? core.tunnelReady(false)
                            completionHandler(error)
                            return
                        }
                        do {
                            try core.tunnelReady(true)
                            self.acceptingPackets = true
                            self.readPackets()
                            self.drainEvents()
                            SharedState().setExtensionState("bootstrapping-tor-blocked")
                            // Production waits for Tor/gateway readiness. The
                            // prototype completes so the full-route TUN remains
                            // installed, but drops every packet fail-closed.
                            completionHandler(nil)
                        } catch {
                            completionHandler(error)
                        }
                    }
                }
            } catch {
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        workQueue.async { [weak self] in
            guard let self else {
                completionHandler()
                return
            }
            self.acceptingPackets = false
            self.pathMonitor.cancel()
            self.core?.shutdown()
            self.core = nil
            SharedState().setExtensionState("stopped-\(reason.rawValue)")
            completionHandler()
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        workQueue.async { [weak self] in
            if let core = self?.core {
                try? core.suspend(monotonicMilliseconds())
            }
            completionHandler()
        }
    }

    override func wake() {
        workQueue.async { [weak self] in
            guard let self, let core = self.core else { return }
            try? core.resume(monotonicMilliseconds(), protectedPathHealthy: self.lastPathHealthy)
        }
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)? = nil
    ) {
        guard messageData.count <= 64 else {
            completionHandler?(nil)
            return
        }
        workQueue.async { [weak self] in
            guard let core = self?.core else {
                completionHandler?(nil)
                return
            }
            switch messageData.first {
            case 1: try? core.rotate(hard: false)
            case 2: try? core.rotate(hard: true)
            case 3: try? core.requestTokenRefresh()
            case 4: try? core.requestConfigRefresh()
            default: break
            }
            completionHandler?(Data([1]))
        }
    }

    private func networkSettings() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["10.77.0.1"], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        let ipv6 = NEIPv6Settings(addresses: ["fd77:6f6e:696f::1"], networkPrefixLengths: [128])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv4Settings = ipv4
        settings.ipv6Settings = ipv6
        settings.dnsSettings = NEDNSSettings(
            servers: ["10.77.0.2", "fd77:6f6e:696f::2"]
        )
        settings.mtu = 1280
        return settings
    }

    private func startPathMonitor() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            self?.workQueue.async {
                guard let self, let core = self.core else { return }
                let healthy = path.status == .satisfied
                self.lastPathHealthy = healthy
                let captiveOrUnvalidated = path.status == .requiresConnection
                try? core.setNetwork(
                    available: healthy,
                    expensive: path.isExpensive,
                    constrained: path.isConstrained,
                    captive: captiveOrUnvalidated
                )
            }
        }
        pathMonitor.start(queue: workQueue)
    }

    private func readPackets() {
        guard acceptingPackets else { return }
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            self.workQueue.async {
                autoreleasepool {
                    guard self.acceptingPackets, let core = self.core else { return }
                    var acceptedBytes = 0
                    for packet in packets.prefix(32) {
                        guard !packet.isEmpty, packet.count <= 128 * 1024 else { continue }
                        guard acceptedBytes + packet.count <= 256 * 1024 else { break }
                        acceptedBytes += packet.count
                        _ = try? core.submit(packet: packet)
                    }
                }
                self.readPackets()
            }
        }
    }

    private func drainEvents() {
        guard acceptingPackets, let core else { return }
        while true {
            let next: RustCore.Event?
            do { next = try core.pollEvent() }
            catch { break }
            guard let event = next else { break }
            if event.kind == 2 {
                SharedState().setExtensionState("state-\(event.value)")
            }
        }
        workQueue.asyncAfter(deadline: .now() + .milliseconds(100)) { [weak self] in
            self?.drainEvents()
        }
    }

    private func validatedConfiguration() throws -> (country: String, mode: UInt32) {
        guard
            let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol,
            let configuration = tunnelProtocol.providerConfiguration,
            let major = configuration["abiMajor"] as? Int,
            major == 1,
            let country = configuration["country"] as? String,
            country.utf8.count == 2,
            country.utf8.allSatisfy({ $0 >= 65 && $0 <= 90 }),
            let modeNumber = configuration["mode"] as? NSNumber,
            modeNumber.uint32Value <= 3
        else { throw TunnelError.invalidConfiguration }
        return (country, modeNumber.uint32Value)
    }
}

private enum TunnelError: LocalizedError {
    case invalidConfiguration

    var errorDescription: String? { "Invalid or incompatible tunnel configuration" }
}

private func monotonicMilliseconds() -> UInt64 {
    DispatchTime.now().uptimeNanoseconds / 1_000_000
}
