# CP-0004: add gateway-daemon to the root Rust workspace

- Status: Proposed
- Owner requested: architecture/contracts
- Date: 2026-07-17

## Problem

`crates/gateway-daemon` is implemented as a standalone Cargo workspace because the
root `Cargo.toml` is protected. Root CI therefore does not build the exit gateway.

## Current contract

The root workspace contains only `crates/common-types`. A local prost adapter mirrors
the protected `proto/common/v1` and `proto/gateway/v1` wire tags because the current
build-time generator dependency graph requires Edition 2024.

## Proposed change

Add `crates/gateway-daemon` to root workspace members and remove its temporary local
`[workspace]` table. Keep protobuf adapter code local to the crate; do not add it to
`common-types`. CI should compare adapter golden bytes/descriptors with the protected
proto contract.

## Affected teams

- architecture/contracts
- gateway/egress
- protocol/gateway-v1
- control/auth-tokens
- qa/integration
- infra/platform

## Compatibility

No wire or Rust public contract changes. Cargo feature resolution and the root lock
file will change and require CI review.

## Migration

1. Add the member in the protected root manifest.
2. Remove the nested workspace marker.
3. Regenerate the root lock file with the pinned MSRV.
4. Add gateway unit/security tests to CI and keep load tests in a scheduled job.

## Risks

- Dependency MSRV or feature unification may affect existing crates.
- The local prost adapter can drift unless descriptor/golden checks remain mandatory.
- Root CI must have no network dependency after dependency caching is established.

## Tests

- `cargo test -p onionroute-gateway-daemon`
- Root `cargo test --workspace`
- protobuf descriptor/privacy checks
- Linux namespace leak test job
