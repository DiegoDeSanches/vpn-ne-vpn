# onionroute-gateway-protocol

Reference transport implementation for OnionRoute private-gateway protocol v1.
It is runtime-specific only at the Tokio `AsyncRead + AsyncWrite` boundary and has
no Tor, egress, account, billing, UI, resolver, telemetry or QUIC dependency.

Public entry points:

- `ClientReference::connect`: hello, maximal-version check, nonce binding and
  anonymous authentication.
- `ServerReference::accept`: hello, explicit incompatibility error and external
  `AuthenticationVerifier` boundary.
- `Session`: multiplexed open/data/half-close/cancel/resolve/control operations,
  explicit `flush`/`receive`, dual flow-control windows and idle expiry.
- `FrameDecoder`: bounded incremental decoder suitable for fuzzing and adapters.
- `FrameSummary` and `examples/orp-dump.rs`: payload-safe diagnostics.

The caller must wrap production I/O in the project-approved pinned TLS transport
and must keep the kill switch engaged on any protocol/transport failure. Do not log
generated Protobuf types: their derived debug form can contain destinations,
tokens and payloads.

Build and test independently while CP-0003 awaits root-workspace approval:

```text
cargo test --manifest-path crates/gateway-protocol/Cargo.toml
cargo run --manifest-path crates/gateway-protocol/Cargo.toml --example orp-dump < capture.orp
cd crates/gateway-protocol/fuzz
cargo fuzz run decode_frame
```

`orp-dump` is intentionally a stream summary, not a capture recorder. It never
prints payload/destination/token bytes. Capturing production plaintext streams is
outside this tool and prohibited by the project logging policy.

## Integration boundary

`AuthenticationVerifier` is implemented by `auth-tokens`. The gateway application
consumes validated `OpenTcpStream`/`ResolveDomain` events and replies through typed
methods; this crate never performs egress. The client supplies the protected byte
stream obtained from `TorBackend`/`CircuitManager`; no Tor type enters this crate.

Important assumptions and the parallel-stream analysis are in
`docs/adr/0010-gateway-v1-length-prefixed-multiplexing.md`. The normative candidate
wire description is `docs/gateway-protocol-v1.md`.
