# Enhanced mTLS PKI design

Status: proposed; implementation is experimental.

## PKI hierarchy and identities

```text
offline inter-gateway root
├── entry data-plane issuing CA
│   └── entry service leaf (clientAuth, 4–12 h, max 24 h)
└── exit data-plane issuing CA
    └── exit service leaf (serverAuth, 4–12 h, max 24 h)

separate management root (never trusted by data-plane listeners)
└── management leaves
```

Each gateway role has a distinct service identity unrelated to host SSH,
orchestrator, database, monitoring, terminal client TLS or control-plane
identity. Production may further split issuing CA by provider/region. The data
plane does not use a certificate to obtain Vault, database, admin API or
orchestrator access.

An authenticated signed trust bundle contains:

- role-specific CA certificates;
- exact SHA-256 digest of each current/next short-lived leaf;
- public service ID, role, purpose, validity window;
- emergency-revoked service IDs and certificate digests.

WebPKI validation and exact pin authorization are both required. Pinning is not
a substitute for chain/expiry/EKU/hostname validation.

## Issuance and rotation

1. A workload proves its deployment identity to Vault/cloud KMS over a local
   workload-authenticated channel.
2. The issuer returns a leaf with only the required role EKU and ≤24-hour
   validity. Preferred production lifetime is 4–12 hours.
3. The signed bundle publishes current + next pins before activation.
4. `run_automatic_rotation` polls a `RotationSource`; by default refresh begins
   two hours before expiry. New connections obtain the current store snapshot.
5. Existing TLS connections keep their negotiated key until normal drain, but
   the application checks emergency revocation before new work and closes the
   connection on revocation.
6. If refresh fails and the old identity expires, new handshakes fail closed.

Private keys should be non-exportable where KMS/HSM-backed rustls signing is
available. The MVP `IdentityMaterial` accepts in-memory PKCS#8 for a Vault agent
adapter; values are never logged or exposed through public accessors.

## Replay and resumption

- TLS 1.3 only; client resumption, server tickets, early data and half-RTT data
  are disabled.
- Application hello uses fresh 32-byte nonces, a 60-second clock window and a
  bounded ten-minute replay cache at exit.
- Both Finished values include a rustls TLS exporter unique to the connection,
  service IDs, version, connection ID and direction.

## Lateral movement controls

- Network policy exposes the exit inter-gateway listener only from entry data
  plane networks. Management listener is on a separate interface/security group.
- Exit mTLS verifier trusts only entry data-plane CA. Entry trusts only exit
  data-plane CA.
- Runtime authorization permits an entry peer only `OpenRelaySession` and
  `RelayBytes`; `Management` and `ControlPlane` always return PolicyDenied.
- Exit independently blocks private/link-local/metadata/management networks and
  admin/SMTP/BitTorrent ports before egress.
- Connection pools, per-entry connections/sessions/bytes, frame sizes, queues,
  DNS answers and timeouts have hard limits.

## Emergency response

1. Publish the service ID and/or leaf digest in emergency revocation state.
2. Reject new TLS/application handshakes immediately.
3. Active drivers call `TrustBundle::ensure_active` before accepting new relay
   work, send GOAWAY where possible and close within the drain bound.
4. Rotate the affected issuer only if CA compromise is suspected; bundle overlap
   must never re-authorize a revoked digest.

