# CP-0001: add network-engine crates to the root workspace

## Problem

`client-core`, `packet-engine`, `dns-engine`, and `policy-engine` must be built by
the repository-wide Cargo commands, but the root `Cargo.toml` is protected.

## Current contract

The root workspace contains only `crates/common-types`.

## Proposed change

Add these members to the root workspace and remove the temporary empty `[workspace]`
tables from their manifests:

- `crates/client-core`
- `crates/packet-engine`
- `crates/dns-engine`
- `crates/policy-engine`

## Affected teams

Architecture/contracts, core/network-engine, QA/integration and CI owners.

## Compatibility

Additive. No Rust or wire public interface changes.

## Migration

Accept the proposal, update the protected workspace member list, remove the four
temporary standalone workspace declarations, and regenerate the root lockfile.

## Risks

Workspace dependency resolution may expose clippy or feature unification failures.

## Tests

Run `cargo test --workspace --all-features`, `cargo clippy --workspace --all-targets`
and `cargo doc --workspace --no-deps`.

