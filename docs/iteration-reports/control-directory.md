# Iteration report: control/directory

- Date: 2026-07-17
- Scope: directory, health aggregation, countries, bootstrap, feature flags,
  client versions, gateway revocation, signing, and administrator API
- Explicitly out of scope: user traffic, DNS/TCP flow handling, data plane, egress

## Implemented

- Five separate Rust services: directory, health collector, admin API, online
  signing, and revocation.
- Onion-only client ingress policy plus exact directory download and bounded,
  non-personalized bootstrap endpoint.
- PostgreSQL-backed repositories, bounded pools, an allow-listed directory builder,
  and migration for all requested tables.
- Coarse health aggregation with gateway workload identity, timestamp bounds, and
  monotonic per-gateway samples; no user/source IP model.
- Offline-root/online-intermediate trust, exact JCS/Ed25519 signatures, expiry,
  rollback/equivocation checks, key and gateway revocation, and Tor v3 checksum
  validation.
- Reference selection for Standard/Enhanced/Maximum/Direct Tor using country,
  role, load, health, maintenance, abuse, protocol, client version, provider/AS
  diversity, required capability, and local recent failures.
- Separate private admin/signing/revocation/health ingresses and a mutual-TLS
  administrative OpenAPI contract.
- Atomic draft version reservation and signed publication transition.
- Threat model, signing runbook, format proposal, gateway selection notes, ADR,
  and cross-service boundary tests.

## Files added

- `crates/directory-client/`: format, issuer, verifier, selector, and tests.
- `services/directory-service/`: Onion client API, PostgreSQL public builder/store,
  and API tests.
- `services/health-collector/`: health ingress, aggregation/store, and privacy tests.
- `services/admin-api/`: admin ingress/store, OpenAPI, and isolation tests.
- `services/signing-service/`: online signer, atomic publication, and pipeline tests.
- `services/revocation-service/`: authenticated revocation API/store and tests.
- `services/migrations/0001_control_plane*.sql`.
- `tests/integration/control-plane/`.
- `docs/control-plane/`, ADR-0014, and CP-0006.

## Public interfaces created

- Experimental signed directory v2 and `onionroute-directory-client` Rust API,
  gated on CP-0006 acceptance.
- Client API: `GET /client/v2/directory`, `POST /client/v1/bootstrap`.
- Gateway API: `POST /gateway-health/v1/samples`.
- Administrator API: `/admin/v1/gateways`, countries, feature flags, version rules,
  revocations, incidents, and directory publications.
- Signing API: `POST /signing/v1/directories`.
- Revocation workload API: `GET|POST /revocation/v1/gateways`.

No protected v1 protobuf, `common-types`, root Cargo manifest, gateway wire API,
directory v1, or token format was changed.

## Assumptions

- Client, health, admin, signing, and revocation proxies strip identity headers and
  inject only a verified mTLS/workload subject.
- Tor maps the loopback client listener to a v3 Onion Service; there is no public
  HTTPS route to these handlers.
- Gateway ID is public catalog metadata and unrelated to accounts or users.
- One gateway record has one role. Multi-role infrastructure uses separate public
  gateway records, preserving the requested singular `role` field.
- Feature flags are global platform/version rules. There is no stable per-user
  percentage rollout key.
- Client rollback state is stored atomically in platform secure storage.

## Tests passing

- 7 directory-client security/selection tests.
- 12 service API, privacy, signing, and ingress tests.
- 3 cross-service schema/OpenAPI/ingress boundary tests.
- Rustfmt completed.
- Clippy with `-D warnings` completed for the client and service workspaces.

## Tests not run / not yet available

- PostgreSQL migration execution against a live PostgreSQL instance (no local
  `postgres`/`psql` runtime was available).
- Parser fuzzing and cross-language golden vectors, pending CP-0006 acceptance.
- Tor Onion Service and production network-policy deployment tests.
- Vault/HSM integration and offline two-person root ceremony.
- Independent external gateway health probes and retention-job tests.

## Dependencies expected from other teams

- Architecture/contracts: decide CP-0006 wire format and protected-contract changes.
- Client teams: pinned root release, secure rollback storage, adapter into client-core,
  mobile golden vectors, and ephemeral selection seed generation.
- Infrastructure: Tor Onion Service, separate mTLS ingresses/workload identities,
  database roles, rustls PostgreSQL transport, Vault/HSM signer, retention, and
  Prometheus/Grafana deployment.
- Gateway teams: authenticated coarse health reports and public descriptor keys.
- Security/QA: ceremony review, fuzzing, emergency rotation drill, leak tests, and
  provider/AS assertion validation.

## Security risks found

- A compromised online intermediate can forge short-lived catalogs until a higher
  root-signed revocation bundle is delivered; the short TTL bounds but does not
  remove this window.
- A compromised gateway can lie about its own coarse health. Independent probes
  remain required.
- Provider group and AS data can become stale and expose coarse infrastructure
  correlation.
- Bad client clocks fail closed and can cause availability loss.
- The experimental local signing-seed adapter is not production-approved.
- The reference SQLx build uses `tls-none`; production must place it behind a local
  protected DB proxy/socket or enable reviewed rustls transport.
- SQLx 0.7.4 emits a future-incompatibility warning on Rust 1.97; schedule an
  upgrade after MSRV and query behavior review.

## Contract proposals

- `CP-0006-directory-v2.md`: Proposed. V1 remains unchanged until acceptance.

## Ready for integration

- Service/domain source, migrations, OpenAPI, docs, and in-memory integration mocks.
- Security criteria are covered by executable reference tests.
- Production rollout is not ready until CP-0006, live PostgreSQL, Onion/mTLS network
  policy, and Vault/HSM dependencies above are completed.

## Open questions

1. Accept JCS JSON for v2, or translate the model to a protected protobuf/CBOR
   contract while retaining exact-byte signatures?
2. What are the production directory/intermediate TTLs and client clock-skew budget?
3. Is provider group safe to publish directly, or should it be a coarser rotating
   diversity class?
4. Which Vault/HSM product is authoritative for Ed25519 and offline root custody?
5. What explicit client recovery UX is allowed after rollback-state loss?
6. Which independent probe quorum can override a gateway self-report?

