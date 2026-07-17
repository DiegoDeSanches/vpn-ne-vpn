# ADR-0014: isolate control API classes and offline-root trust

- Status: Accepted
- Date: 2026-07-17

## Context

Client bootstrap, gateway health, administrator commands, signing, and revocation
have different principals and compromise impact. Sharing a listener, proxy policy,
or key would make a client-parser issue an administrative/signing path and would
allow health metadata to become an identity join point.

## Decision

Use separate processes, listeners, workload identities, database roles, rate
limits, and network policies for these API classes:

| API | Reachability | Authenticated principal |
|---|---|---|
| Client directory/bootstrap | loopback application listener mapped by Tor v3 Onion Service | no persistent client identity |
| Gateway health | dedicated private mTLS proxy | gateway workload ID |
| Administrator | dedicated private operator mTLS proxy | operator role/subject |
| Signing | dedicated private workload mTLS proxy | directory publisher workload |
| Revocation | dedicated private workload mTLS proxy | admin API or publisher workload |

The client service refuses a non-loopback bind and requires a v3 Onion hostname.
The administrator and signing services refuse a listener shared with a configured
client/admin ingress. Public HTTPS is not a control-plane fallback.

The offline Ed25519 root signs bounded trust bundles that authorize short-lived
online intermediate keys. Only the online intermediate is available to the
signing process. The directory signature covers domain-separated exact payload
bytes. Clients pin the root and persist both trust-bundle and directory monotonic
state. Root-signed bundles carry intermediate revocations and enable emergency
online-key rotation.

## Consequences

- Online-key compromise can forge a catalog only during its bounded authorization
  window; it cannot authorize a new intermediate or replace the pinned root.
- Root ceremonies, recovery media, and public-key pin releases are operationally
  heavier and require two-person approval.
- Co-location is permitted only with distinct loopback ports, proxies, service
  accounts, and database credentials.
- Direct clearnet fallback for client bootstrap remains prohibited.

## Verification

- Startup configuration tests reject public/shared listeners.
- Integration tests verify expiry, rollback, revocation, and root authorization.
- Network policy tests prove the client proxy cannot reach admin/signing routes.
- Logs and database schemas are scanned for client/source IP and destination fields.
