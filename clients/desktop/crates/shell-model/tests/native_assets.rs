#[test]
fn ui_processes_are_declared_unprivileged_and_do_not_own_network_core() {
    let windows = include_str!("../../../apps/windows/OnionRoute.App/app.manifest");
    assert!(windows.contains("level=\"asInvoker\""));
    assert!(!windows.contains("requireAdministrator"));

    let mac_app = include_str!("../../../apps/macos/OnionRoute/OnionRoute.entitlements");
    let mac_provider = include_str!("../../../apps/macos/PacketTunnel/RustBridge.h");
    assert!(mac_app.contains("com.apple.security.app-sandbox"));
    assert!(mac_provider.contains("onionroute_core_start"));

    let linux_service = include_str!("../../../installers/linux/onionroute.service");
    let linux_ui = include_str!("../../../apps/linux/src/main.rs");
    assert!(linux_service.contains("CapabilityBoundingSet=CAP_NET_ADMIN"));
    assert!(!linux_ui.contains("CAP_NET_ADMIN"));
    assert!(!linux_ui.contains("/dev/net/tun"));
}

#[test]
fn native_shells_keep_udp_and_fail_closed_warnings_visible() {
    let windows = include_str!("../../../apps/windows/OnionRoute.App/MainWindow.xaml");
    let mac = include_str!("../../../apps/macos/OnionRoute/ContentView.swift");
    let linux = include_str!("../../../apps/linux/ui/main.ui");
    assert!(windows.contains("UDP is not supported"));
    assert!(mac.contains("warning.udpBlocked"));
    assert!(linux.contains("UDP is unsupported"));
    for source in [windows, mac, linux] {
        assert!(!source.to_ascii_lowercase().contains("complete anonymity"));
        assert!(!source.to_ascii_lowercase().contains("direct fallback"));
    }
}
