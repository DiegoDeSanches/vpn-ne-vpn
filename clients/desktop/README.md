# OnionRoute desktop (experimental integration shell)

This subtree owns desktop presentation, local IPC, privileged OS wrappers and
installer prototypes. It does not implement packet processing, Tor routing,
gateway protocol, DNS, circuit selection, or cryptography. Those remain in the
shared Rust core and are reached through `CoreControl` adapters in the privileged
daemon/Network Extension process.

## Components

- `crates/ipc`: canonical protobuf v1 local control schema, 64 KiB framing,
  semantic validation, and an OS peer-authentication boundary.
- `crates/shell-model`: privilege-free screen model, localized copy identifiers,
  safe error mapping and accessibility contracts.
- `crates/daemon`: fail-closed lifecycle ordering, critical-action challenges,
  recovery intent and allowlist-only diagnostics export.
- `apps/windows`: WinUI 3 unprivileged shell. It reaches a Windows Service only
  through an ACL-protected Named Pipe.
- `apps/macos`: SwiftUI shell plus `NEPacketTunnelProvider`; the provider is the
  privileged system component and hosts the Rust core through a narrow FFI.
- `apps/linux`: GTK shell. It reaches a system daemon through an ACL-protected
  Unix socket and uses polkit only for enrollment/admin operations.
- `installers`: non-production packaging prototypes for driver/system component
  enrollment, signed installation and predictable reboot recovery.

## Build and test

The desktop crates intentionally form a nested workspace because the protected
root `Cargo.toml` cannot be changed until CP-0006 is accepted.

```powershell
cargo test --manifest-path clients/desktop/Cargo.toml --workspace
```

Native shells require their platform SDKs: Visual Studio with WinUI 3 and WiX 4,
Xcode with Network Extension entitlement and SwiftProtobuf, or GTK 4 development
packages. Installer files contain explicit `EXPERIMENTAL` markers and must not be
shipped before signing/notarization, WFP/nftables leak tests and driver recovery
tests pass on clean VMs.

## Security invariants

- Kill switch is engaged and independently verified before packet tunnel start.
- An unknown lifecycle state is projected as blocked, never disconnected.
- UI process loss only starts IPC reconnect; it never tears down protection.
- Daemon/core shutdown completes before the kill switch can be disengaged.
- No clearnet fallback command exists in IPC.
- IPC contains no onion address, capability token, hostname, remote IP or
  free-form backend error.
- Diagnostics accept closed enums and coarse buckets only, are hashed, and are
  automatically removed after their bounded retention.

