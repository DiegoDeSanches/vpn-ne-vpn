# Iteration report: protocol/gateway-v1

- Date: 2026-07-17
- Zone: protocol framing, multiplexing, flow control, reference transport only
- Contract status: CP-0003 proposed; architecture approval required before merge

## Implemented

- Four-file Protobuf v1 contract with every requested message and no account ID.
- Canonical unsigned-varint length framing, 64-KiB pre-allocation limit, strict
  top-level wire scanner and bounded incremental decoder.
- Highest-common version negotiation with silent-downgrade detection, required
  capabilities and explicit incompatible-peer error.
- Fresh OS-random nonces/session ID and domain-separated SHA-256 session binding;
  capability-token/PoP verification remains an external reviewed boundary.
- Async Tokio session over generic `AsyncRead + AsyncWrite`, with per-direction
  sequence and fail-closed state transitions.
- Odd monotonic non-reusable stream/query IDs, TCP open/accept/reject, data,
  half-close, cancellation, resolve, rotation control, ping/pong/error/go-away.
- Per-stream plus connection windows with checked arithmetic and hard caps.
- Bounded global, per-stream and control queues; eight-control-frame burst plus
  one-frame round-robin data scheduling.
- Capability enforcement uses post-auth granted capabilities, preventing a token
  from using a feature that hello advertised but auth did not grant.
- Idle-stream expiration API and bounded cancellation; caller/driver supplies the
  periodic timer tick.
- Payload/destination/token-safe `FrameSummary` and `orp-dump` decoder with no
  logging/telemetry dependency.
- Golden, property, conformance, privacy, flow, fairness, fail-closed and
  end-to-end client/server tests; libFuzzer decoder target.

## Files added or replaced

- `proto/gateway/v1/{gateway,types,handshake,stream}.proto`
- `crates/gateway-protocol/Cargo.toml`, `Cargo.lock`, `build.rs`, `README.md`
- `crates/gateway-protocol/src/{lib,error,limits,framing,validation,negotiation,binding,flow,scheduler,session,client,server,debug}.rs`
- `crates/gateway-protocol/tests/{framing_conformance,flow_control,fail_closed,privacy_contract,reference_session}.rs`
- `crates/gateway-protocol/examples/orp-dump.rs`
- `crates/gateway-protocol/fuzz/Cargo.toml`, `Cargo.lock`,
  `fuzz_targets/decode_frame.rs`
- `docs/gateway-protocol-v1.md`
- `docs/adr/0010-gateway-v1-length-prefixed-multiplexing.md`
- `docs/contract-proposals/CP-0003-gateway-protocol-v1.md`
- this report

## Public interfaces

- Protobuf messages enumerated in CP-0003 and the normative candidate spec.
- `ClientReference`, `ClientAuthenticator`, `AuthenticationMaterial`.
- `ServerReference`, `AuthenticationVerifier`, `AuthenticationDecision`.
- `Session`, `SessionPhase`, `PeerRole` and typed multiplexing operations.
- `FrameDecoder`, `encode_frame`, `read_frame`, `write_frame`.
- `ProtocolLimits`, `FlowController`, version/capability helpers.
- `FrameSummary`, `DebugDecoder`.

No existing `common-types` public API or root workspace manifest was changed.

## Assumptions

- The supplied production byte stream is already confidential and authenticated
  (normally pinned TLS 1.3 inside the intended Tor route).
- Token/PoP cryptography and token expiry/spend policy are owned by
  `auth-tokens`; the gateway verifier receives no account context.
- Only the client creates logical TCP streams and resolve query IDs in v1.
- Hostnames arrive as validated ASCII/IDNA A-labels; Unicode-to-IDNA conversion is
  a caller boundary.
- `expire_idle_streams` is called by the owning async driver on a periodic timer.
- One multiplexed session is the MVP default. A 2–4-session isolated pool is a
  later measured `client-core/circuit-manager` policy.

## Verification

Passed in the official Linux `rust:1.78` container:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test --all-targets`: 16 passed, 0 failed
- fuzz workspace `cargo check`, including `libfuzzer-sys` target
- repository `scripts/check-architecture.ps1`: passed (11 traits, 14 states,
  10 diagrams, 35 failure scenarios, 12 ADRs)

The decoder property test exercised arbitrary inputs up to 200,000 bytes while
asserting the retained buffer never exceeds 64 KiB + prefix. A sustained
libFuzzer campaign/corpus run was not performed in this iteration; the target
compiles and is ready for QA/CI fuzz infrastructure.

Windows-native Rust compilation was not available because the host lacks the
MSVC linker/SDK. Linux Rust 1.78 compilation and tests are authoritative for this
platform-neutral crate.

## Dependencies expected from other agents

- Architecture: approve CP-0003, add the crate to the root workspace, establish
  the first released `buf breaking` baseline.
- Auth tokens: implement `AuthenticationVerifier` and decide which capabilities
  require mandatory PoP.
- Gateway egress: consume validated typed open/resolve events and reply without
  logging destination values.
- Client core/Tor backend: provide pinned protected byte transport, drive idle
  ticks and keep kill switch fail-closed on any session error.
- QA/security: sustained fuzzing, fault injection, slow-consumer tests and
  cross-language golden vectors.

## Security risks found

- A single TCP/Tor stream retains wire-level HOL; local fairness cannot remove it.
- Generated Protobuf `Debug` contains secrets/destinations; consumers must use
  `FrameSummary` only.
- Bearer tokens without PoP remain replayable within token-scheme policy; this
  crate binds auth to a session but cannot choose the token cryptography.
- Parallel Tor sessions may improve latency but increase resource use and
  correlation surface; they require anonymity-policy review.
- The session advertises a hard TTL, but product orchestration must schedule
  make-before-break replacement and close at that TTL; no reconnect/fallback is
  implemented in this transport crate.

## Contract proposals

- `CP-0003-gateway-protocol-v1.md` — proposed, pending architecture review.

## Open questions

1. Approve the v1 tags/names and whether `ResolveDomain` replaces the earlier raw
   DNS-wire draft for all MVP use cases.
2. Select/review the anonymous token and PoP scheme and its exact capability map.
3. Assign numeric critical-extension IDs before the first optional critical
   feature rollout; v1 currently enables none.
4. Decide whether the production driver uses one session or a capped 2–4 session
   pool after Tor-circuit/HOL measurements.
5. Decide whether idle timer driving and hard session-TTL scheduling live in a
   reusable session-driver task or remain in `client-core`/gateway daemon.

## Ready for integration

The standalone crate, schema candidate, reference endpoints, tests and fuzz target
are ready for architecture/security review and adapter integration. Root workspace
membership and deployment should wait for CP-0003 acceptance.
