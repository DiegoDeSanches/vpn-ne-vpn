//! Compile-time platform contract inventory. Native adapters must implement the
//! corresponding OS APIs and fail closed if any required capability is absent.

pub mod linux;
pub mod macos;
pub mod windows;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformDescriptor {
    pub daemon_host: &'static str,
    pub tunnel: &'static str,
    pub firewall: &'static str,
    pub ipc: &'static str,
    pub secure_storage: &'static str,
    pub authorization: &'static str,
    pub reboot_recovery: &'static str,
}

pub const WINDOWS: PlatformDescriptor = PlatformDescriptor {
    daemon_host: "Windows Service",
    tunnel: "Wintun",
    firewall: "Windows Filtering Platform",
    ipc: "Named Pipes with token verification and explicit ACL",
    secure_storage: "DPAPI machine scope",
    authorization: "Windows access token and signed service identity",
    reboot_recovery: "automatic service plus persistent WFP fail-closed policy",
};

pub const MACOS: PlatformDescriptor = PlatformDescriptor {
    daemon_host: "NEPacketTunnelProvider",
    tunnel: "Network Extension packet flow",
    firewall: "Network Extension enforced routes and on-demand policy",
    ipc: "NETunnelProviderSession messages with audit-token/code-signing verification",
    secure_storage: "Keychain access group",
    authorization: "App Group and designated code requirement",
    reboot_recovery: "saved NETunnelProviderManager on-demand configuration",
};

pub const LINUX: PlatformDescriptor = PlatformDescriptor {
    daemon_host: "systemd system service",
    tunnel: "/dev/net/tun",
    firewall: "nftables atomic ruleset",
    ipc: "Unix SOCK_SEQPACKET with SO_PEERCRED and mode 0660 ACL",
    secure_storage: "Secret Service collection",
    authorization: "SO_PEERCRED, socket ACL, and polkit for enrollment",
    reboot_recovery: "Before=network-online.target plus persistent nftables block",
};

#[cfg(target_os = "windows")]
pub const NATIVE: PlatformDescriptor = WINDOWS;
#[cfg(target_os = "macos")]
pub const NATIVE: PlatformDescriptor = MACOS;
#[cfg(target_os = "linux")]
pub const NATIVE: PlatformDescriptor = LINUX;
