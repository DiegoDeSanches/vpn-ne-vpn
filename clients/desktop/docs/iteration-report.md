# Desktop iteration report

## Implemented

- Privilege-free screen/presentation model for Home, Country, Anonymity, Route,
  Rotation, Split tunneling, Kill switch, Diagnostics, Subscription and Settings.
- Home state projection: connect/disconnect, exit country, anonymity mode, Tor
  bootstrap, gateway health, coarse latency, kill switch, blocked leak aggregate
  and persistent UDP warning.
- Canonical desktop protobuf IPC v1 with 64 KiB framing, version negotiation,
  semantic validation, strict per-direction sequence, reconnect-safe sessions,
  bounded event subscription/acknowledgement and closed error codes.
- OS-authentication interfaces for Windows token/ACL + SCM/Authenticode, Apple
  audit token/designated requirement, and Unix `SO_PEERCRED`/ACL/image ownership.
- Single-use 60-second confirmation challenges for hard rotation, disabling kill
  switch, disconnect-and-unblock and split-policy replacement.
- Daemon lifecycle wrapper that persists recovery intent, installs and verifies
  kill switch before TUN, keeps protection independent of UI lifetime and refuses
  to unblock until teardown is independently recorded as complete.
- Allowlist-only JSON diagnostics, SHA-256 integrity metadata, fixed export
  directory, bounded retention and automatic expiry cleanup.
- Windows WinUI 3/Named Pipe shell prototype, macOS SwiftUI +
  `NEPacketTunnelProvider`/Rust FFI prototype and Linux GTK/Unix
  `SOCK_SEQPACKET` prototype.
- WiX/Wintun/WFP, signed/notarized macOS pkg and systemd/nftables/polkit Linux
  installer prototypes with reboot recovery policy.
- English and Russian canonical string catalogs plus accessibility/UX contract
  tests and protobuf fuzz target.

## Files added

- `clients/desktop/Cargo.toml`, lockfile and `README.md`.
- `clients/desktop/crates/ipc/**` including protobuf schema, validation, tests and
  fuzz target.
- `clients/desktop/crates/shell-model/**` and `clients/desktop/locales/**`.
- `clients/desktop/crates/daemon/**` including platform wrappers and security
  tests.
- `clients/desktop/apps/windows/**`, `apps/macos/**`, `apps/linux/**`.
- `clients/desktop/installers/windows/**`, `installers/macos/**`,
  `installers/linux/**`.
- `clients/desktop/docs/**`.
- `docs/contract-proposals/CP-0006-desktop-workspace-members.md`.

## Public interfaces created

- Protobuf package `onionroute.desktop.ipc.v1` (experimental local IPC only).
- Rust framing/validation API in `onionroute-desktop-ipc`.
- `PeerAuthenticator` and opaque `AuthenticatedPeer` OS boundary.
- `PlatformControl`, `CoreControl`, `DaemonRuntime` and `IpcSession` desktop-owned
  adapter interfaces.
- `WindowsPlatformApi`, `LinuxPlatformApi` and Apple/Windows/Unix peer evidence
  adapters. Concrete native bindings must satisfy them without changing shared
  core contracts.
- `SCREEN_SPECS`, `UiState` and localization `StringKey` presentation contract.

## Assumptions

- Split tunneling is enforced before packets enter TUN, as documented by
  client-core.
- The reviewed native service/extension is the only process that links the Rust
  core and secure storage.
- OS installers can establish immutable publisher/team/package identity roots and
  service-only recovery storage ACLs.
- Direct Tor is explicit public-Tor-exit mode, never clearnet or error fallback.
- Unknown/corrupt recovery state means `Blocked`.

## Tests passing

Command:

```text
docker run --rm -e CARGO_TARGET_DIR=/tmp/onionroute-target \
  -v <workspace>:/workspace -w /workspace/clients/desktop \
  rust:1.78-bookworm cargo test --workspace --locked
```

Result: 25 passed, 0 failed. Doc tests also pass. `cargo check --workspace
--tests` and `cargo fmt --check` pass. The fuzz target compiles separately under
`cargo fuzz` when libFuzzer is installed.

## Tests failing or not run

- No Rust unit/integration test fails.
- Native WinUI, Swift/Xcode and GTK builds were not run because their SDKs are not
  installed in the current workspace host.
- WFP/Wintun, Network Extension, nftables/TUN, suspend/reboot, accessibility
  automation and packet-capture leak tests require signed clean VMs/devices and
  are not simulated as production evidence.
- Clippy was not run because the available toolchains lack the component.

## Dependencies expected from other agents

- Architecture acceptance of CP-0006 and desktop IPC release ownership.
- Concrete `CoreControl` adapter from the existing client-core/circuit-manager
  owners without changing their public interfaces.
- Approved Windows publisher certificate, Apple Team ID/entitlement and Linux
  signing keys/package matrix.
- Signed pinned Wintun payload and reviewed WFP/native nftables adapters.
- Control-plane subscription projection that remains separate from data-plane
  identities/tokens.
- QA clean-VM leak, reboot, crash, upgrade and rollback harness.

## Security risks found

- Persistent WFP base filters may leave a boot window unless the Windows threat
  model approves their boot enforcement design or requires a boot-start callout.
- A system daemon and per-user Secret Service session have a lifecycle mismatch
  on Linux; headless/reboot recovery needs an approved machine secure-store path.
- Network Extension approval/revocation can change outside the app; unknown state
  must remain blocked and needs real-device validation.
- Stable application identity for split tunneling differs across OS and can drift
  on upgrades; path-only identity is insufficient.
- Native publisher placeholders deliberately fail closed; unsigned developer
  builds cannot authenticate until explicit dev signing roots are provisioned.

## Contract proposals

- CP-0006 proposes adding desktop crates to the protected root workspace and
  integrating a core adapter after owner review. No protected contract was
  modified directly.

## Ready for integration

- Rust IPC/schema/lifecycle/presentation crates and mocks.
- Native UI source prototypes and entitlement/manifest definitions.
- Installer/recovery policy prototypes.
- Documentation, ADR, string catalogs, unit/integration/accessibility tests and
  fuzz harness.

Not production-ready: concrete signed native API bindings, platform builds and
clean-VM leak/reboot certification remain required.

