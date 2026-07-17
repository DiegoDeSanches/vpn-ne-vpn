import SwiftUI

struct ContentView: View {
    @State private var status = "Not configured"
    private let manager = TunnelManager()

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 18) {
                Text(status).font(.headline)
                Text(
                    "Network Extension is only the local packet interface. " +
                    "The server path is Tor, not IPsec or another VPN protocol. " +
                    "This prototype blocks packets until the production Rust/Tor adapter is integrated."
                )
                Text(
                    "iOS always excludes some system traffic, including DHCP and captive-portal negotiation. " +
                    "Consumer per-app split tunneling is not offered; managed per-app VPN requires deployment support."
                )
                Text(
                    "Prototype privacy: no site history or traffic content is collected. Diagnostics are local " +
                    "closed-schema states only. Production terms and territory availability need legal review."
                )
                Button("Install configuration and connect") {
                    Task {
                        do {
                            try await manager.installAndConnect(country: "US", mode: 0)
                            status = "Tunnel active; protected core is still fail-closed in this prototype"
                        } catch {
                            status = "Configuration failed: \(error.localizedDescription)"
                        }
                    }
                }
                Button("Disconnect") {
                    Task {
                        await manager.disconnect()
                        status = "Disconnected by user"
                    }
                }
                Spacer()
            }
            .padding()
            .navigationTitle("OnionRoute")
        }
    }
}
