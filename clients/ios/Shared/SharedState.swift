import Foundation

struct SharedState: Sendable {
    private static let suite = "group.org.onionroute.mobile"

    func setDesiredConnection(_ desired: Bool) {
        defaults?.set(desired, forKey: "desiredConnection.v1")
    }

    func desiredConnection() -> Bool {
        defaults?.bool(forKey: "desiredConnection.v1") ?? false
    }

    func setExtensionState(_ state: String) {
        // Closed local schema only; never store destinations, addresses or tokens.
        let allowedPrefixes = ["state-", "stopped-", "blocked-", "bootstrapping-tor-blocked"]
        guard allowedPrefixes.contains(where: state.hasPrefix) else { return }
        defaults?.set(state, forKey: "extensionState.v1")
    }

    func extensionState() -> String? {
        defaults?.string(forKey: "extensionState.v1")
    }

    private var defaults: UserDefaults? { UserDefaults(suiteName: Self.suite) }
}
