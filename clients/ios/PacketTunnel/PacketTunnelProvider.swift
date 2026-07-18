import Foundation
import Network
import NetworkExtension
import Darwin

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let workQueue = DispatchQueue(label: "org.onionroute.packet-tunnel")
    private var pathMonitor: NWPathMonitor?
    private var core: RustCore?
    private var acceptingPackets = false
    private var lastPathHealthy = false
    private var packetPumpGeneration: UInt64 = 0

    override func startTunnel(
        options: [String: NSObject]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        workQueue.async { [weak self] in
            guard let self else {
                completionHandler(TunnelError.providerUnavailable)
                return
            }
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
                            self.failStart(core: core, error: error, completionHandler: completionHandler)
                            return
                        }
                        do {
                            let startupStatus = try core.tunnelReady(true)
                            self.drainEvents()
                            SharedState().setExtensionState(
                                startupStatus == OR_STATUS_UNAVAILABLE
                                    ? "blocked-production-runtime-unavailable"
                                    : "bootstrapping-tor-blocked"
                            )
                            // Keep the full-route TUN installed while the protected
                            // core bootstraps. Packet reads start only after the
                            // core reports the Connected state.
                            completionHandler(nil)
                        } catch {
                            self.failStart(core: core, error: error, completionHandler: completionHandler)
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
            self.deactivatePacketPumps()
            self.pathMonitor?.cancel()
            self.pathMonitor = nil
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
            do {
                switch messageData.first {
                case 1: try core.rotate(hard: false)
                case 2: try core.rotate(hard: true)
                case 3: try core.requestTokenRefresh()
                case 4: try core.requestConfigRefresh()
                default: throw TunnelError.invalidMessage
                }
                completionHandler?(Data([1]))
            } catch {
                completionHandler?(Data([0]))
            }
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

    private func failStart(
        core: RustCore,
        error: Error,
        completionHandler: @escaping (Error?) -> Void
    ) {
        deactivatePacketPumps()
        pathMonitor?.cancel()
        pathMonitor = nil
        try? core.tunnelReady(false)
        core.shutdown()
        if self.core === core { self.core = nil }
        SharedState().setExtensionState("blocked-start-failed")
        completionHandler(error)
    }

    private func startPathMonitor() {
        pathMonitor?.cancel()
        let monitor = NWPathMonitor()
        pathMonitor = monitor
        monitor.pathUpdateHandler = { [weak self] path in
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
        monitor.start(queue: workQueue)
    }

    private func activatePacketPumps() {
        guard !acceptingPackets, core != nil else { return }
        acceptingPackets = true
        packetPumpGeneration &+= 1
        let generation = packetPumpGeneration
        readPackets(generation: generation)
        drainOutputPackets(generation: generation)
    }

    private func deactivatePacketPumps() {
        acceptingPackets = false
        packetPumpGeneration &+= 1
    }

    private func readPackets(generation: UInt64) {
        guard acceptingPackets, generation == packetPumpGeneration else { return }
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            self.workQueue.async {
                self.processPackets(packets, from: 0, generation: generation)
            }
        }
    }

    private func processPackets(_ packets: [Data], from start: Int, generation: UInt64) {
        autoreleasepool {
            guard
                acceptingPackets,
                generation == packetPumpGeneration,
                let core
            else { return }

            var index = start
            let endIndex = PacketBatchBudget.standard.endIndex(in: packets, from: start)
            while index < endIndex {
                let packet = packets[index]
                if packet.isEmpty || packet.count > 128 * 1024 {
                    index += 1
                    continue
                }
                do {
                    let status = try core.submit(packet: packet)
                    if status == OR_STATUS_BACKPRESSURE {
                        let retryIndex = index
                        workQueue.asyncAfter(deadline: .now() + .milliseconds(10)) { [weak self] in
                            self?.processPackets(packets, from: retryIndex, generation: generation)
                        }
                        return
                    }
                    if status == OR_STATUS_UNAVAILABLE {
                        deactivatePacketPumps()
                        SharedState().setExtensionState("blocked-packet-core-unavailable")
                        return
                    }
                } catch {
                    deactivatePacketPumps()
                    SharedState().setExtensionState("blocked-packet-core-error")
                    return
                }
                index += 1
            }

            if index < packets.count {
                let nextIndex = index
                workQueue.async { [weak self] in
                    self?.processPackets(packets, from: nextIndex, generation: generation)
                }
            } else {
                readPackets(generation: generation)
            }
        }
    }

    private func drainOutputPackets(generation: UInt64) {
        guard acceptingPackets, generation == packetPumpGeneration, let core else { return }
        var packets: [RustCore.Packet] = []
        var bytes = 0
        do {
            while packets.count < 32 && bytes < 256 * 1024, let packet = try core.pollPacket() {
                if !packets.isEmpty && bytes + packet.data.count > 256 * 1024 {
                    guard writeOutputPackets(packets) else { return }
                    packets.removeAll(keepingCapacity: true)
                    bytes = 0
                }
                packets.append(packet)
                bytes += packet.data.count
            }
        } catch {
            deactivatePacketPumps()
            SharedState().setExtensionState("blocked-packet-output-error")
            return
        }
        guard packets.isEmpty || writeOutputPackets(packets) else { return }
        workQueue.asyncAfter(deadline: .now() + .milliseconds(10)) { [weak self] in
            self?.drainOutputPackets(generation: generation)
        }
    }

    private func writeOutputPackets(_ packets: [RustCore.Packet]) -> Bool {
        let payloads = packets.map(\.data)
        let protocols = packets.map { packet in
            NSNumber(
                value: packet.protocolVersion == UInt32(OR_PACKET_PROTOCOL_IPV4)
                    ? AF_INET
                    : AF_INET6
            )
        }
        guard packetFlow.writePackets(payloads, withProtocols: protocols) else {
            deactivatePacketPumps()
            SharedState().setExtensionState("blocked-packet-output-rejected")
            return false
        }
        return true
    }

    private func drainEvents() {
        guard let core else { return }
        while true {
            let next: RustCore.Event?
            do { next = try core.pollEvent() }
            catch { break }
            guard let event = next else { break }
            if event.kind == 2 {
                SharedState().setExtensionState("state-\(event.value)")
                if event.value == 4 {
                    activatePacketPumps()
                } else if [3, 5, 6, 7, 8].contains(event.value) {
                    deactivatePacketPumps()
                }
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
    case invalidMessage
    case providerUnavailable

    var errorDescription: String? {
        switch self {
        case .invalidConfiguration: return "Invalid or incompatible tunnel configuration"
        case .invalidMessage: return "Invalid tunnel control message"
        case .providerUnavailable: return "Packet tunnel provider is unavailable"
        }
    }
}

private func monotonicMilliseconds() -> UInt64 {
    DispatchTime.now().uptimeNanoseconds / 1_000_000
}
