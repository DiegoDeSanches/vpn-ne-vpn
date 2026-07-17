import Foundation
import NetworkExtension
import Security
import SwiftProtobuf

@MainActor
final class TunnelController: ObservableObject {
    @Published private(set) var statusKey = "status.disconnected"
    @Published private(set) var exitCountry = "Automatic"
    @Published private(set) var anonymityMode = "Standard"
    @Published private(set) var bootstrap = 0.0
    @Published private(set) var gatewayStatus = "Not applicable"
    @Published private(set) var latencyBucket = "Not available"
    @Published private(set) var killSwitch = "Disabled"
    @Published private(set) var blockedLeaks: UInt64 = 0

    private var manager: NETunnelProviderManager?
    private var subscriptionTask: Task<Void, Never>?
    private var sequence: UInt64 = 0

    func activate() async {
        do {
            manager = try await loadOrCreateManager()
            subscriptionTask?.cancel()
            subscriptionTask = Task { [weak self] in await self?.eventSubscriptionLoop() }
        } catch {
            statusKey = "status.blocked"
            killSwitch = "Failed; blocking"
        }
    }

    func connect() async {
        guard let manager else { return }
        do {
            try manager.connection.startVPNTunnel()
            _ = try await request(command: .connect(.init()))
        } catch { statusKey = "status.blocked" }
    }

    func disconnectKeepingBlock() async {
        do {
            var disconnect = Onionroute_Desktop_Ipc_V1_DisconnectRequest()
            disconnect.keepKillSwitch = true
            _ = try await request(command: .disconnect(disconnect))
            // The provider decides when teardown is safe; UI never stops it first.
        } catch { statusKey = "status.blocked" }
    }

    func hardRotate() async {
        do {
            var rotate = Onionroute_Desktop_Ipc_V1_RotateRequest()
            rotate.kind = .hardNewIdentity
            try await confirmedRequest(command: .rotate(rotate), action: .hardRotation)
        } catch { statusKey = "status.degraded" }
    }

    private func eventSubscriptionLoop() async {
        var backoff: UInt64 = 250_000_000
        while !Task.isCancelled {
            do {
                let response = try await request(command: .getState(.init()))
                if case .state(let state) = response.payload { apply(state) }
                backoff = 250_000_000
                try await Task.sleep(nanoseconds: 1_000_000_000)
            } catch {
                statusKey = "status.preparing"
                try? await Task.sleep(nanoseconds: backoff)
                backoff = min(backoff * 2, 5_000_000_000)
            }
        }
    }

    private func request(
        command: Onionroute_Desktop_Ipc_V1_Request.OneOf_Command,
        confirmation: Data = Data()
    ) async throws -> Onionroute_Desktop_Ipc_V1_Response {
        guard let session = manager?.connection as? NETunnelProviderSession else { throw IpcError.unavailable }
        var request = Onionroute_Desktop_Ipc_V1_Request()
        request.command = command
        request.confirmationID = confirmation
        var envelope = Onionroute_Desktop_Ipc_V1_Envelope()
        envelope.version = version()
        envelope.requestID = secureRandom(count: 16)
        sequence += 1
        envelope.sequence = sequence
        envelope.body = .request(request)
        let responseData = try await send(session, frame: try frame(envelope))
        let responseEnvelope = try decodeFrame(responseData)
        guard case .response(let response) = responseEnvelope.body else { throw IpcError.invalidResponse }
        return response
    }

    private func confirmedRequest(
        command: Onionroute_Desktop_Ipc_V1_Request.OneOf_Command,
        action: Onionroute_Desktop_Ipc_V1_CriticalAction
    ) async throws {
        let challenge = try await request(command: command)
        guard challenge.status == .confirmationRequired,
              case .confirmation(let confirmation) = challenge.payload,
              confirmation.action == action,
              confirmation.confirmationID.count == 16 else { throw IpcError.invalidResponse }
        _ = try await request(command: command, confirmation: confirmation.confirmationID)
    }

    private func apply(_ state: Onionroute_Desktop_Ipc_V1_StateSnapshot) {
        bootstrap = Double(state.torBootstrapPercent)
        exitCountry = state.exitCountryCode.isEmpty ? "Automatic" : state.exitCountryCode
        blockedLeaks = state.blockedLeakCount
        statusKey = state.phase == .blocked ? "status.blocked" :
                    state.phase == .connected ? "status.protected" : "status.preparing"
        anonymityMode = state.anonymityMode == .maximum ? "Maximum" :
                        state.anonymityMode == .enhanced ? "Enhanced" :
                        state.anonymityMode == .directTor ? "Direct Tor" : "Standard"
        gatewayStatus = String(describing: state.gatewayStatus)
        latencyBucket = String(describing: state.latencyBucket)
        killSwitch = String(describing: state.killSwitch)
    }

    private func loadOrCreateManager() async throws -> NETunnelProviderManager {
        let existing = try await NETunnelProviderManager.loadAllFromPreferences()
        let manager = existing.first ?? NETunnelProviderManager()
        if existing.isEmpty {
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.onionroute.desktop.PacketTunnel"
            proto.serverAddress = "OnionRoute protected route"
            proto.includeAllNetworks = true
            proto.excludeLocalNetworks = false
            manager.protocolConfiguration = proto
            manager.localizedDescription = "OnionRoute"
            manager.isEnabled = true
            let rule = NEOnDemandRuleConnect()
            manager.onDemandRules = [rule]
            manager.isOnDemandEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
        }
        return manager
    }
}

private enum IpcError: Error { case unavailable, invalidResponse, oversized }

private func version() -> Onionroute_Desktop_Ipc_V1_ProtocolVersion {
    var value = Onionroute_Desktop_Ipc_V1_ProtocolVersion(); value.major = 1; value.minor = 0; return value
}

private func secureRandom(count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    precondition(SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess)
    return Data(bytes)
}

private func frame(_ envelope: Onionroute_Desktop_Ipc_V1_Envelope) throws -> Data {
    let payload = try envelope.serializedData()
    guard payload.count <= 65_536 else { throw IpcError.oversized }
    var length = UInt32(payload.count).bigEndian
    var output = Data(bytes: &length, count: 4); output.append(payload); return output
}

private func decodeFrame(_ data: Data) throws -> Onionroute_Desktop_Ipc_V1_Envelope {
    guard data.count >= 4 else { throw IpcError.invalidResponse }
    let length = data.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    guard length <= 65_536, data.count == Int(length) + 4 else { throw IpcError.oversized }
    return try .init(serializedBytes: data.dropFirst(4))
}

private func send(_ session: NETunnelProviderSession, frame: Data) async throws -> Data {
    try await withCheckedThrowingContinuation { continuation in
        do {
            try session.sendProviderMessage(frame) { response in
                guard let response else { continuation.resume(throwing: IpcError.invalidResponse); return }
                continuation.resume(returning: response)
            }
        } catch { continuation.resume(throwing: error) }
    }
}
