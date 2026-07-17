import Foundation
import NetworkExtension

final class TunnelManager: Sendable {
    func installAndConnect(country: String, mode: UInt32) async throws {
        let managers = try await loadManagers()
        let manager = managers.first ?? NETunnelProviderManager()
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = "org.onionroute.mobile.PacketTunnel"
        tunnelProtocol.serverAddress = "Tor v3 onion service / private exit gateway"
        tunnelProtocol.providerConfiguration = [
            "abiMajor": 1,
            "country": country,
            "mode": mode,
        ]
        // This is the strongest public consumer routing request, not an absolute
        // firewall: iOS documents unavoidable system-traffic exclusions.
        tunnelProtocol.includeAllNetworks = true
        tunnelProtocol.enforceRoutes = true
        tunnelProtocol.excludeLocalNetworks = false
        tunnelProtocol.excludeAPNs = false
        tunnelProtocol.excludeCellularServices = false
        tunnelProtocol.disconnectOnSleep = false

        manager.protocolConfiguration = tunnelProtocol
        manager.localizedDescription = "OnionRoute Tor privacy tunnel"
        manager.isEnabled = true
        manager.onDemandRules = [NEOnDemandRuleConnect()]
        manager.isOnDemandEnabled = true
        try await save(manager)
        try await load(manager)
        try manager.connection.startVPNTunnel()
        SharedState().setDesiredConnection(true)
    }

    func disconnect() async {
        guard let manager = (try? await loadManagers())?.first else { return }
        manager.connection.stopVPNTunnel()
        manager.isOnDemandEnabled = false
        try? await save(manager)
        SharedState().setDesiredConnection(false)
    }

    private func loadManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { continuation in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: managers ?? []) }
            }
        }
    }

    private func save(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: ()) }
            }
        }
    }

    private func load(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: ()) }
            }
        }
    }
}
