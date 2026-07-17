# OnionRoute gateway daemon (experimental)

`onionroute-gateway-daemon` is the terminal private exit for the TCP-only MVP. It
accepts TLS 1.3 only on a loopback listener intended for a Tor v3 Onion Service,
verifies an anonymous capability token, resolves a hostname through explicitly
configured DNS servers, repeats address policy checks immediately before a
direct-IP TCP dial, and multiplexes bounded streams with protocol credit.

The implementation is experimental until the auth-token owner supplies the
reviewed offline verifier and OS/network-namespace leak tests pass. The shipped
binary uses `DenyAllAuthenticationVerifier`: this is intentional fail-closed
behavior, not a development allow-list.

## Public Rust interfaces

- `auth::AuthenticationVerifier`: offline capability-token verification. The
  request and grant contain no account, device, payment, issuance, or client-IP
  identity.
- `dns::DnsResolver` / `DnsTransport`: bounded resolution and a mockable upstream
  boundary. `WireDnsResolver` supports UDP with bounded TCP fallback.
- `egress::EgressDialer`: direct-IP TCP connect boundary used by security tests.
- `acl::AclEngine`: hostname/port pre-check and resolved IP post-check. Emergency
  rules can add denials but cannot create allows.
- `session::SessionManager`: anonymous TTL sessions, per-token limits, draining,
  bandwidth quotas, and keyed short-window anti-scan counters.
- `health::Metrics`: fixed counters without arbitrary labels.

The local prost adapter mirrors `proto/gateway/v1` tags without changing that
protected contract; a golden wire test guards the adapter. Build-time generation is
avoided because its current dependency graph requires Edition 2024 and violates the
repository Rust 1.78 baseline. The crate remains a standalone workspace until
`docs/contract-proposals/CP-0004-gateway-daemon-workspace-member.md` is accepted.

## Privacy invariants

The daemon does not log tokens, hostnames, addresses, ports, payloads, account IDs,
Tor circuits, or protocol session IDs. Optional privacy events have a closed enum,
coarse time bucket, catalog gateway ID, and an eight-byte per-session random handle;
they live only in a bounded in-memory buffer and expire automatically.

Destination material is held only while resolving/connecting and in active socket
state. Anti-scan detection stores a keyed 128-bit digest for at most one configured
window; the process key is random and never exported.

## Development

```text
cargo test --manifest-path crates/gateway-daemon/Cargo.toml
cargo test --manifest-path crates/gateway-daemon/Cargo.toml --test load -- --ignored
```

See `deploy/DEPLOYMENT.md` for the Linux namespace, nftables, Tor, TLS, and systemd
assumptions.

## Open integration questions

1. The reviewed anonymous token format, issuer-key distribution, replay/nullifier
   storage, and proof-of-possession rules are owned by `control/auth-tokens`.
2. Production TLS key delivery and SPKI publication need the KMS/directory owners.
3. The operator must select DNS upstreams and decide whether DNS-over-TLS is
   required; v1 currently uses bounded classic DNS inside the exit namespace.
4. Remote health collection is intentionally absent until an allow-listed gateway
   health schema and mutual authentication are agreed.
