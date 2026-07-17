# Client/mobile iteration report — 2026-07-17

## Implemented

- Experimental versioned Rust C ABI with registry handles, explicit ownership,
  cancellation, bounded event queue, panic boundary, thread-safe destruction and
  lifecycle/version negotiation.
- Android Kotlin prototype with separate-process foreground `VpnService`, JNI C
  shim, full IPv4/IPv6 routing, Keystore encryption, per-app exclusions,
  always-on support metadata, network callbacks and battery-aware reconnect.
- iOS Swift containing app and `NEPacketTunnelProvider`, C FFI wrapper, shared
  Keychain/App Group, bounded packet batches, path monitoring and sleep recovery.
- Lifecycle, App Store risk and battery benchmark documents.
- Cross-platform mobile pcap leak matrix and executable validator.

## Files and public interfaces

New roots are `crates/mobile-ffi`, `clients/android`, `clients/ios`, `docs/mobile`
and `tests/leak-tests/mobile`. Public ABI declarations are documented in
`crates/mobile-ffi/include/onionroute_mobile.h` and `API.md`.

## Assumptions

- Mobile OS minimums are Android 10/API 29 and iOS 17 for the prototype.
- Android secure token storage is unavailable before first unlock; direct-boot
  service stays blocked.
- iOS consumer per-app VPN is not claimed.
- Signed directory/token formats remain owned by their protected contracts.

## Repository limitation

The workspace contains an empty `.git` directory, so Git reports “not a git
repository” and the required `client/mobile` branch cannot be created or checked.
All edits are nevertheless isolated to new mobile-owned paths plus ADR/contract,
test and iteration-report documents; protected root/proto/common contracts were
not modified.

## Tests

- `cargo clippy --manifest-path crates/mobile-ffi/Cargo.toml --all-targets -- -D warnings`: pass through the self-contained gnullvm target.
- `cargo test --manifest-path crates/mobile-ffi/Cargo.toml`: 12/12 ABI unit
  tests and all doc tests pass through the self-contained gnullvm target.
- Android/iOS builds and physical leak/battery tests are not run: SDK/Xcode,
  signing entitlements, native mobile Rust artifacts and devices are unavailable.

## Dependencies on other teams

- Acceptance and implementation of CP-0006 by architecture, network core, Tor,
  directory/token and integration owners.
- Security review of platform socket protection and store claims.
- Provisioning/entitlement and organization/legal work for Apple distribution.

## Security risks

- iOS has unavoidable `includeAllNetworks` system exclusions.
- Android service-process kill is not gap-free without lockdown.
- Apple may reject local TCP flow conversion under TN3120 interpretation.
- C Tor and dual-route rotation may exceed extension memory/energy budgets.
- Direct Tor socket protection needs request/ack integration before connect.

## Contract proposals

- CP-0006: mobile client-core adapter and workspace member.

## Ready for integration

ABI lifecycle/ownership tests, platform shell structure, secure-storage adapters,
documentation and test specifications. Packet forwarding is deliberately not
ready and remains fail-closed pending CP-0006.

## Open questions

1. Will architecture accept CP-0006 and which team owns the runtime factory?
2. Must Android launch require lockdown, or merely recommend it with limited claims?
3. Is managed-device iOS per-app VPN a separate SKU?
4. What measured memory, battery, bootstrap and handoff budgets gate beta?
5. Will Apple DTS accept Tor flow conversion as a supported packet-tunnel use?
