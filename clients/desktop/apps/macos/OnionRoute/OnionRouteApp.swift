import SwiftUI

@main
struct OnionRouteApp: App {
    @StateObject private var tunnel = TunnelController()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(tunnel)
                .task { await tunnel.activate() }
        }
        Settings { SettingsScreen().environmentObject(tunnel) }
    }
}

