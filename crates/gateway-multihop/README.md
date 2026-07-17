# OnionRoute Enhanced gateway transport

Status: **experimental**, pending acceptance of CP-0008 and an external security review.

This standalone crate implements the Enhanced data-plane boundary:

```text
client terminal TLS over Tor
  -> entry (anonymous entry credential, route selection, opaque relay)
  -> TLS 1.3 mTLS inter-gateway connection
  -> exit (terminal TLS, anonymous exit credential, DNS + ACL + TCP egress)
```

The entry-facing API has no source-address type. The inter-gateway schema has no
account, user, device, payment, source-IP, destination, or DNS field. Destination
plaintext is carried only inside the opaque terminal TLS session and is decoded
by the exit gateway.

## Public integration points

- `tls::{EntryTlsConnector, ExitTlsAcceptor}`: TLS 1.3-only mTLS, role-specific
  roots, exact short-lived leaf pins, ALPN, disabled 0-RTT/resumption, TLS exporter.
- `protocol::{connect_entry, accept_exit, ProtocolConnection}`: replay-resistant
  hello/Finished, version negotiation, multiplexed logical relay sessions and
  gateway-v1-compatible flow-control semantics.
- `entry::EntryGateway`: verifies an entry-scoped anonymous credential, selects a
  strictly diverse route and pumps opaque bytes with a hard byte cap.
- `exit::{ExitGatewayAdapter, ExitEgressAdapter}`: per-entry admission and
  independently checked hostname/port/DNS/IP/TCP egress.
- `route::select_enhanced_route`: hard provider, AS, management-domain, country,
  protocol, maintenance, revocation and load constraints.
- `mux::{FairMuxQueue, ConnectionPoolLimiter}`: bounded fair queues and pool caps.
- `quota::EntryQuotaManager`: per-entry connection/session/bandwidth quotas.
- `recovery::FailClosedRecovery`: Enhanced reconnect or block; no clearnet action.

## Build and tests

The crate remains outside the protected root workspace until CP-0008 is accepted:

```text
cargo test --manifest-path crates/gateway-multihop/Cargo.toml
cargo test --manifest-path crates/gateway-multihop/Cargo.toml --test security
cargo test --manifest-path crates/gateway-multihop/Cargo.toml --test load
cd crates/gateway-multihop/fuzz
cargo fuzz run decode_inter_gateway_frame
```

Production wiring must provide:

1. a signed-directory adapter containing the CP-0008 fields;
2. Vault/KMS implementations of `RotationSource`;
3. an exit terminal-session handler that terminates the separate client-to-exit
   TLS identity and routes every request through `ExitEgressAdapter`;
4. an approved exit DNS resolver (the system resolver is not supplied here).

Never log Protobuf values, credentials, TLS exporter bytes, certificate material,
terminal session bytes, DNS names, destinations or resolved addresses.
