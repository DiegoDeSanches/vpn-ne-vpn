import SwiftUI

enum Destination: String, CaseIterable, Identifiable {
    case home, country, anonymity, route, rotation, splitTunneling, killSwitch
    case diagnostics, subscription, settings
    var id: String { rawValue }
    var title: LocalizedStringKey {
        switch self {
        case .home: "nav.home"
        case .country: "nav.country"
        case .anonymity: "nav.anonymity"
        case .route: "nav.route"
        case .rotation: "nav.rotation"
        case .splitTunneling: "nav.splitTunneling"
        case .killSwitch: "nav.killSwitch"
        case .diagnostics: "nav.diagnostics"
        case .subscription: "nav.subscription"
        case .settings: "nav.settings"
        }
    }
}

struct ContentView: View {
    @EnvironmentObject private var tunnel: TunnelController
    @State private var selection: Destination? = .home

    var body: some View {
        NavigationSplitView {
            List(Destination.allCases, selection: $selection) { destination in
                NavigationLink(value: destination) { Text(destination.title) }
            }
            .navigationTitle("app.name")
            .accessibilityLabel("a11y.navigation")
        } detail: {
            Group {
                switch selection ?? .home {
                case .home: HomeScreen()
                case .country: CountryScreen()
                case .anonymity: AnonymityScreen()
                case .route: RouteScreen()
                case .rotation: RotationScreen()
                case .splitTunneling: SplitTunnelingScreen()
                case .killSwitch: KillSwitchScreen()
                case .diagnostics: DiagnosticsScreen()
                case .subscription: SubscriptionScreen()
                case .settings: SettingsScreen()
                }
            }
            .frame(minWidth: 620, minHeight: 520)
            .padding(28)
        }
    }
}

struct HomeScreen: View {
    @EnvironmentObject private var tunnel: TunnelController
    @State private var confirmDisconnect = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text(tunnel.statusKey).font(.largeTitle.bold())
                    .accessibilityLabel("a11y.mainStatus")
                Grid(alignment: .leading, horizontalSpacing: 28, verticalSpacing: 12) {
                    statusRow("label.exitCountry", tunnel.exitCountry)
                    statusRow("label.anonymityMode", tunnel.anonymityMode)
                    GridRow { Text("label.torBootstrap"); ProgressView(value: tunnel.bootstrap, total: 100) }
                    statusRow("label.gatewayStatus", tunnel.gatewayStatus)
                    statusRow("label.latencyBucket", tunnel.latencyBucket)
                    statusRow("label.killSwitch", tunnel.killSwitch)
                    statusRow("label.blockedLeaks", "\(tunnel.blockedLeaks)")
                }
                .padding().background(.quaternary, in: RoundedRectangle(cornerRadius: 16))

                Label("warning.udpBlocked", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange).accessibilityAddTraits(.isStaticText)
                HStack {
                    Button("action.connect") { Task { await tunnel.connect() } }
                        .buttonStyle(.borderedProminent)
                    Button("action.disconnect") { confirmDisconnect = true }
                        .buttonStyle(.bordered)
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
        .confirmationDialog("action.disconnect", isPresented: $confirmDisconnect, titleVisibility: .visible) {
            Button("action.disconnect", role: .destructive) { Task { await tunnel.disconnectKeepingBlock() } }
            Button("action.cancel", role: .cancel) {}
        } message: { Text("warning.failClosed") }
    }

    private func statusRow(_ label: LocalizedStringKey, _ value: String) -> some View {
        GridRow { Text(label).foregroundStyle(.secondary); Text(value).fontWeight(.semibold) }
    }
}

struct CountryScreen: View {
    @State private var country = "AUTO"
    var body: some View {
        Form {
            Picker("label.exitCountry", selection: $country) {
                Text("Automatic").tag("AUTO")
                Text("Germany").tag("DE")
                Text("Netherlands").tag("NL")
                Text("Switzerland").tag("CH")
            }
            Text("Only country-level selection is shown; city and coordinate precision are not inferred.")
                .foregroundStyle(.secondary)
        }.navigationTitle("nav.country")
    }
}

struct AnonymityScreen: View {
    @State private var mode = "standard"
    var body: some View {
        Form {
            modeOption("standard", "mode.standard.title", "mode.standard.description")
            modeOption("enhanced", "mode.enhanced.title", "mode.enhanced.description")
            modeOption("maximum", "mode.maximum.title", "mode.maximum.description")
            modeOption("directTor", "mode.directTor.title", "mode.directTor.description")
        }.navigationTitle("nav.anonymity")
    }
    private func modeOption(_ id: String, _ title: LocalizedStringKey, _ description: LocalizedStringKey) -> some View {
        Button { mode = id } label: {
            HStack(alignment: .top) {
                Image(systemName: mode == id ? "checkmark.circle.fill" : "circle")
                VStack(alignment: .leading) { Text(title).font(.headline); Text(description).foregroundStyle(.secondary) }
            }
        }.buttonStyle(.plain)
    }
}

struct RouteScreen: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("nav.route").font(.largeTitle.bold())
            Text("Tor  →  Private exit gateway  →  Internet").font(.title3.monospaced())
            Text("Specific Tor relays and onion service addresses are intentionally hidden.").foregroundStyle(.secondary)
            Spacer()
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct RotationScreen: View {
    @EnvironmentObject private var tunnel: TunnelController
    @State private var automatic = true
    @State private var confirmHard = false
    var body: some View {
        Form {
            Toggle("Automatic soft rotation", isOn: $automatic)
            Button("action.newIdentity") { confirmHard = true }
        }
        .navigationTitle("nav.rotation")
        .confirmationDialog("action.newIdentity", isPresented: $confirmHard, titleVisibility: .visible) {
            Button("action.confirm", role: .destructive) { Task { await tunnel.hardRotate() } }
            Button("action.cancel", role: .cancel) {}
        } message: { Text("warning.hardRotation") }
    }
}

struct SplitTunnelingScreen: View {
    var body: some View {
        Form {
            Text("Application rules are enforced by the privileged host before packets enter TUN.")
            Button("Review and confirm policy replacement") { }
        }.navigationTitle("nav.splitTunneling")
    }
}

struct KillSwitchScreen: View {
    @State private var enabled = true
    @State private var confirmDisable = false
    var body: some View {
        Form {
            Toggle("nav.killSwitch", isOn: Binding(get: { enabled }, set: { value in
                if value { enabled = true } else { confirmDisable = true }
            }))
            Text("warning.failClosed").foregroundStyle(.secondary)
        }
        .navigationTitle("nav.killSwitch")
        .confirmationDialog("Disable kill switch?", isPresented: $confirmDisable) {
            Button("action.confirm", role: .destructive) { enabled = false }
            Button("action.cancel", role: .cancel) {}
        }
    }
}

struct DiagnosticsScreen: View {
    var body: some View {
        Form {
            Button("Export redacted diagnostics") { }
            Text("Exports contain only allowlisted coarse state and expire automatically.")
        }.navigationTitle("nav.diagnostics")
    }
}

struct SubscriptionScreen: View {
    var body: some View {
        Form { LabeledContent("Subscription", value: "Unavailable") }
            .navigationTitle("nav.subscription")
    }
}

struct SettingsScreen: View {
    @State private var launch = true
    @State private var connect = false
    var body: some View {
        Form {
            Toggle("Launch at login", isOn: $launch)
            Toggle("Connect on launch", isOn: $connect)
            Picker("Language", selection: .constant("system")) { Text("System").tag("system") }
        }.navigationTitle("nav.settings")
    }
}

