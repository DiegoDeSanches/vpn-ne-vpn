# CP-0006: add desktop Rust crates to the root workspace

## Problem

The desktop implementation needs shared CI, dependency policy and integration
tests, but the root `Cargo.toml` is protected and currently lists only
`crates/common-types`. Desktop crates therefore use a temporary nested workspace.

## Current contract

Root workspace membership is architecture-owned. `clients/desktop/Cargo.toml`
contains `ipc`, `shell-model` and `daemon` members independently and depends on no
root crate while the client-core adapter remains mocked.

## Proposed change

After owner review, add the three desktop crates to root workspace membership,
adopt root workspace dependency versions and add a concrete desktop
`CoreControl` adapter to `crates/client-core`/`crates/circuit-manager`. Keep the
desktop IPC schema under `clients/desktop`; it must not become a gateway or
control-plane contract.

## Affected teams

Architecture/contracts, client/desktop, core/network-engine,
core/tor-backend, QA/integration and CI owners.

## Compatibility

No existing Rust or wire API changes. `CoreControl` remains a desktop-owned
adapter. Flattening the workspace changes build topology only.

## Migration

1. Review desktop dependency versions and schema ownership.
2. Add workspace members and remove the nested `[workspace]` declaration.
3. Implement adapters without changing core public traits.
4. Run existing root and desktop test suites on all three OS targets.

## Risks

- Platform-only dependencies can break non-native workspace builds unless fully
  target-gated.
- Accidentally coupling desktop IPC to gateway/control protobuf would weaken the
  trust boundary.
- A daemon adapter may duplicate core orchestration if ownership is not reviewed.

## Tests

- `cargo test --workspace` on Windows, macOS and Linux.
- UI-close/daemon-crash/reboot lifecycle tests.
- OS peer credential and ACL negative tests.
- DNS/IPv6/QUIC leak tests during connect, rotation and recovery.
- Schema golden-byte, oversized frame and unknown-enum tests.

