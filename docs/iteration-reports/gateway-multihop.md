# Iteration report: gateway/multihop

Date: 2026-07-17. Status: experimental, ready for contract/security review; not
ready for production enablement until CP-0008 and PKI deployment are accepted.

## Что реализовано

- TLS 1.3-only rustls mTLS with role roots, exact short-lived leaf pins, ALPN,
  disabled early data/resumption/tickets and TLS exporter binding.
- Versioned inter-gateway handshake, replay cache, multiplexed opaque sessions,
  flow control, GOAWAY/drain and redacted errors.
- Strict Enhanced route selection across provider, AS and management domains.
- Entry anonymous credential boundary and opaque Tor-session forwarding.
- Exit role authorization, per-entry quotas, independent DNS/ACL/TCP egress.
- Bounded fair mux queue, connection pool limiter and fail-closed recovery.
- Unit, security, privacy, failure-recovery, load tests and a decoder fuzz target.

## Добавленные файлы

- `crates/gateway-multihop/**`
- `docs/adr/0016-enhanced-inter-gateway-transport.md`
- `docs/enhanced-inter-gateway-protocol-v1.md`
- `docs/security/enhanced-mtls-pki.md`
- `docs/contract-proposals/CP-0008-enhanced-inter-gateway-directory.md`
- this report.

## Публичные интерфейсы

- `EntryTlsConnector`, `ExitTlsAcceptor`, `IdentityStore`, `TrustBundle`,
  `RotationSource`.
- `connect_entry`, `accept_exit`, `ProtocolConnection`, protocol message types.
- `EntryGateway`, `AnonymousCredentialVerifier`, `RelaySessionFactory`.
- `ExitGatewayAdapter`, `ExitEgressAdapter`, `ExitResolver`, `ExitDialer`,
  `TerminalSessionHandler`.
- `select_enhanced_route`, `FairMuxQueue`, `ConnectionPoolLimiter`,
  `EntryQuotaManager`, `FailClosedRecovery`.

## Предположения

- Accepted ADR-0008 remains normative: client-to-exit terminal TLS is opaque at entry.
- Signed directory supplies truthful provider/AS/management failure domains and pins.
- The Tor onion-service adapter discards source address before `TorSession` creation.
- Exit terminal handler independently verifies an exit-scoped anonymous credential.
- Active TCP streams are not migrated on route failure.

## Проходящие проверки

- `cargo fmt --manifest-path crates/gateway-multihop/Cargo.toml -- --check`.
- `cargo check --locked` in the official Rust 1.78 Linux container.
- `cargo test --locked` in the official Rust 1.78 Linux container: 15 tests and
  documentation tests passed.
- Project security scanner: 6 checks passed.

## Непроходящие/не запущенные проверки

- Native Windows linking remains unavailable: the MSVC target has no Windows
  SDK/`link.exe`, and GNU has no complete MinGW binutils. Linux validation is
  green, so this is a host-toolchain limitation rather than a test failure.
- `cargo clippy` was unavailable in the minimal Rust 1.78 container.
- A sustained fuzz campaign and production-like staging measurements were not run.

## Зависимости от других команд

- CP-0008 acceptance and generated protected contracts.
- Signed directory/trust-bundle publication.
- Vault/KMS `RotationSource` and role-specific CA deployment.
- Exit terminal TLS/protocol-handler wiring and approved protected DNS resolver.
- QA multi-provider/AS staging environment and production-like load baseline.

## Security-риски

- Entry/exit timing and volume correlation remains possible.
- Single TCP transport retains loss-induced HOL.
- Incorrect failure-domain metadata can defeat intended operational diversity.
- Pin/bundle rotation ordering can cause fail-closed outage.
- In-memory private-key material is an MVP limitation until KMS signing integration.
- No absolute anonymity claim is made.

## Contract proposals

- `CP-0008-enhanced-inter-gateway-directory.md`.

## Готово к интеграции

- Standalone crate API, protocol/PKI specifications, adapters, mocks boundaries,
  security/load tests and fuzz target are ready for review.
- Production traffic enablement is explicitly not ready pending the dependencies above.

## Открытые вопросы

1. Which authority validates provider, AS and management failure-domain ownership?
2. Preferred leaf lifetime: 4, 8 or 12 hours, and required overlap duration?
3. Exact CRL/OCSP policy versus signed emergency bundle for already-open links?
4. Whether measured workloads justify a pool above one mTLS connection per exit?
5. Which protected DNS resolver implementation and cache isolation model is approved?
6. Maximum acceptable drain grace and per-entry default bandwidth quota by region?
