# macOS packaging prototype

The application and Packet Tunnel system extension are signed with the same
approved Team ID and explicit App Group/Keychain access group. The package is
signed with Developer ID Installer, submitted with `notarytool`, stapled and then
checked by `verify-release.sh`. User approval of the Network Extension is an OS
flow and is never bypassed by installer scripts.

The app saves an on-demand `NETunnelProviderManager` with `includeAllNetworks`;
the provider treats missing/corrupt App Group recovery intent as blocked. The
signed extension, not SwiftUI, owns Rust FFI and Keychain access. Clean-VM tests
must cover approval denial, reboot, extension crash, update, revoked signature
and removal while the fail-closed profile is active.

