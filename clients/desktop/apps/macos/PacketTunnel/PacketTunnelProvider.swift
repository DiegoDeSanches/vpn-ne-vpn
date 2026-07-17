import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var running = false

    override func startTunnel(
        options: [String : NSObject]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "100.64.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["100.64.0.2"], subnetMasks: ["255.255.255.252"])
        ipv4.includedRoutes = [.default()]
        settings.ipv4Settings = ipv4
        let ipv6 = NEIPv6Settings(addresses: ["fd00:6f6e:696f:6e::2"], networkPrefixLengths: [128])
        ipv6.includedRoutes = [.default()]
        settings.ipv6Settings = ipv6
        let dns = NEDNSSettings(servers: ["100.64.0.1", "fd00:6f6e:696f:6e::1"])
        dns.matchDomains = [""]
        dns.matchDomainsNoSearch = true
        settings.dnsSettings = dns
        settings.mtu = 1280

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard error == nil, onionroute_core_start() == 0 else {
                completionHandler(error ?? ProviderError.coreStartFailed)
                return
            }
            self?.running = true
            self?.readPackets()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        running = false
        onionroute_core_stop()
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard messageData.count <= 65_540 else { completionHandler?(nil); return }
        var response = Data(count: 65_540)
        var responseLength = 0
        let status = messageData.withUnsafeBytes { input in
            response.withUnsafeMutableBytes { output in
                onionroute_daemon_handle_ipc(
                    input.bindMemory(to: UInt8.self).baseAddress, input.count,
                    output.bindMemory(to: UInt8.self).baseAddress, output.count,
                    &responseLength)
            }
        }
        guard status == 0, responseLength <= response.count else { completionHandler?(nil); return }
        response.count = responseLength
        completionHandler?(response)
    }

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, self.running else { return }
            for (packet, family) in zip(packets, protocols) {
                packet.withUnsafeBytes { bytes in
                    _ = onionroute_core_ingest_packet(
                        bytes.bindMemory(to: UInt8.self).baseAddress,
                        bytes.count,
                        family.int32Value)
                }
            }
            self.readPackets()
        }
    }
}

private enum ProviderError: Error { case coreStartFailed }

