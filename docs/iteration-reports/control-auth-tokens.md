# Iteration report: control/auth-tokens

- Date: 2026-07-17
- Intended branch: `control/auth-tokens`
- Repository note: the supplied `.git` directory is empty, so branch creation,
  diff and commit verification were not possible.

## Implemented

- Standalone `onionroute-auth-tokens` crate with bounded canonical protobuf
  token encoding, Ed25519 issuance/verification, fixed policy profiles, expiry
  buckets, role/region scope, mandatory-MVP PoP, local keyring, cached
  revocation interface and anonymous session reservations.
- Standalone account-plane token service with entitlement and device-slot
  boundaries, coarse policy mapping, fixed-size batches and a mock billing
  adapter (no payment-provider implementation).
- Candidate protobuf/API schema compiled at service build time with vendored
  protoc while protected root `proto/` remains unchanged.
- Replay comparison and selected multi-gateway fail-closed store contract.
- Threat model, key hierarchy/rotation plan, account/data-plane design, ADR and
  migration roadmap to RFC 9576/9578 Blind RSA or VOPRF profiles.
- Decoder fuzz target plus unit and cross-crate integration tests.

## Files added

### Auth token crate

- `crates/auth-tokens/Cargo.toml`, `Cargo.lock`, `README.md`;
- `src/lib.rs`, `codec.rs`, `error.rs`, `issuer.rs`, `policy.rs`, `replay.rs`,
  `revocation.rs`, `types.rs`, `verifier.rs`, `wire.rs`;
- `tests/token_security.rs`;
- `fuzz/Cargo.toml`, `Cargo.lock`, `fuzz_targets/token_decode.rs`.

### Token service

- `services/token-service/Cargo.toml`, `Cargo.lock`, `build.rs`, `README.md`;
- `src/lib.rs`, `billing.rs`, `device_slots.rs`, `error.rs`, `service.rs`,
  `types.rs`;
- `api/onionroute/token/v1/token_service.proto`;
- `tests/account_data_plane.rs`.

### Architecture/security documentation

- `docs/adr/0013-mvp-pop-capability-tokens.md`;
- `docs/account-plane-anonymous-data-plane.md`;
- `docs/replay-protection-design.md`;
- `docs/auth-token-key-rotation.md`;
- `docs/security/auth-tokens-threat-model.md`;
- `docs/anonymous-credentials-roadmap.md`;
- `docs/contract-proposals/CP-0007-auth-token-v1.md`;
- this report.

The ADR index was updated. Protected `proto/`, `crates/common-types/`, root
`Cargo.toml`, CI and existing gateway public APIs were not modified.

## Public interfaces created

Data-plane crate:

- `TokenIssuer`;
- `TokenVerifier`;
- `TokenStore`;
- `RevocationProvider`;
- canonical capability/policy/request/grant types;
- `LocalEd25519TokenIssuer`, `LocalTokenVerifier`, `InMemoryTokenStore` and
  `InMemoryRevocationProvider` experimental implementations.

Account-plane service:

- `BillingEntitlementProvider`;
- `DeviceSlotManager`;
- `TokenService`;
- `MockBillingAdapter` and `InMemoryDeviceSlotManager` test implementations.

The gateway adapter to the existing protected `AuthenticationVerifier` is
intentionally deferred until CP-0007 approval.

## Assumptions

- Token starts are five-minute buckets and TTL is exactly 15 minutes.
- PoP is optional in the wire format but required by MVP verifier policy.
- Tokens are scoped to exactly one entry/relay/exit role; separate hop tokens
  prevent direct token-ID joining.
- Three fixed plan/limit/device/bandwidth classes and four region sets are the
  complete v1 policy space. Product values need approval before production.
- Batch size is 1..8; all members share policy, role and time window.
- Production replay state is linearizable fleet-wide and fails closed; the
  in-memory store only demonstrates the contract.
- Revocation snapshots refresh every five minutes, remain valid for 60 minutes,
  and normal subscription cancellation relies on short TTL.
- Issuer manifests are signed by an offline root and online keys are HSM/KMS
  non-exportable; the manifest loader is a pending dependency.

## Tests passing

- `cargo +stable-x86_64-pc-windows-gnu test --manifest-path crates/auth-tokens/Cargo.toml`:
  10 security/integration tests passed.
- `cargo +stable-x86_64-pc-windows-gnu test --manifest-path services/token-service/Cargo.toml`:
  4 cross-plane integration tests passed; build also compiled the candidate
  protobuf with vendored protoc.
- Both crates pass `cargo clippy --all-targets -- -D warnings`.
- Both crates pass `cargo fmt --check`.
- `scripts/check-architecture.ps1` passes (11 traits, 14 states, 10 diagrams,
  35 failure scenarios, 16 ADRs in the concurrently updated workspace).

## Tests not passing / not executed

- The libFuzzer target was added, but native compilation cannot complete in the
  supplied Windows environment because `g++.exe`/MSVC Build Tools and
  `cargo-fuzz` are absent. Rust unit/integration builds use the installed GNU
  toolchain successfully. CI with cargo-fuzz and a C++ compiler must execute the
  target before production review.
- The default MSVC Rust toolchain cannot link because `link.exe` is absent; this
  is an environment issue, not a code failure.

## Dependencies expected from other teams

- `architecture/contracts`: accept/adjust CP-0007 and canonical schema location.
- `control/directory`: signed exact-byte issuer-key and revocation bundle.
- `gateway/egress`, `gateway/multihop`, `protocol/gateway-v1`: adapter and trusted
  gateway-binding/challenge plumbing after contract approval.
- `infra/platform`: HSM/KMS issuer, offline root ceremony and linearizable
  anonymous multi-gateway token store.
- `client/desktop`, `client/mobile`, `core/network-engine`: ephemeral PoP private
  key lifecycle, per-role token cache and batch refill behavior.
- `qa/integration`, `security/threat-model`: store partitions, clock skew,
  malformed protobuf, log audit and blind-protocol conformance.

## Security risks found

- A token valid at multiple hop roles would be a direct cross-hop join key; MVP
  therefore enforces exactly one role per token.
- A directly signed MVP response can be linked by a malicious/co-located token
  service through memory, logging or timing. Typed separation is not equivalent
  to cryptographic unlinkability; blind issuance remains required.
- A Bloom filter cannot safely enforce replay/session counts because false
  positives deny users and updates are not linearizable.
- A partitioned/unavailable replay store must choose safety and reject new
  sessions; availability requires quorum engineering, not local fallback.
- Rare plan/region/role cohorts remain fingerprintable even with closed enums;
  cohort policy needs privacy review.
- Per-token revocation can become a correlation database if used routinely.
- The signed key/revocation bundle loader and production distributed store are
  not implemented in this iteration.

## Contract proposals

- `CP-0007-auth-token-v1.md`: canonical token schema, batch API, Rust boundaries
  and migration without modifying current protected contracts.

## Open questions

1. Which linearizable regional/global store and partition policy will satisfy
   fleet-wide active-session enforcement without an account-plane route?
2. Are 15-minute TTL, five-minute buckets, batch size eight and the three
   concrete policy profiles acceptable to product, abuse and privacy review?
3. Which maintained RFC 9474/9578 Blind RSA library and HSM profile will be
   independently reviewed? Publicly verifiable Blind RSA is the current leading
   choice; RFC 9578 VOPRF verification needs issuer secret evaluation.
4. Who owns the signed issuer-manifest/revocation protobuf and offline-root
   ceremony?
5. How are account-side issuance quotas, retries and device replacement handled
   without producing a redemption nullifier or stable data-plane device ID?
6. Is TTL-bounded subscription cancellation sufficient, and what incident bar
   permits exceptional per-token revocation?
7. What minimum anonymity-set threshold disables a rare plan/region/role cohort?

## Ready for integration

The standalone interfaces, MVP codec/crypto verification, account boundary,
mock adapters, candidate schema, documentation and tests are ready for review.
Production enablement is not ready until CP-0007, cryptographic review, signed
key distribution, gateway adapter, HSM/KMS issuer and distributed `TokenStore`
are completed. Gateway must remain deny-all rather than use a local/in-memory
fallback before those gates pass.
