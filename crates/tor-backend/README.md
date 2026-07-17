# onionroute-tor-backend

Managed Tor implementation behind the runtime-neutral
`onionroute_common_types::contracts::v1::TorBackend` boundary.

## Implementations

- `CTorBackend`: MVP implementation using one separately supervised C Tor process.
- `ArtiBackend`: explicitly experimental, fail-closed scaffold. It never opens a stream.
- `mock::FakeTorBackend` and `onionroute-mock-tor`: test-only fault backend and process fixture.

Client-core receives `Arc<dyn TorBackend>` / `Arc<dyn TorBackendExt>` and never receives a child
process, control connection, SOCKS address, Tokio stream, or implementation enum.

## Managed API

`TorBackendExt` adds the operations that do not yet exist in common contract v1:

- `start`, `stop`, `bootstrap_progress`;
- `allocate_isolation_context`, `release_isolation_context`;
- `request_soft_rotation`, `request_hard_rotation`;
- `health_status`, `network_changed`;
- `configure_bridges`, `configure_proxy`.

The proposed common-contract change is in
`docs/contract-proposals/CP-0005-managed-tor-backend-v1.md`. Until it is accepted, client-core can
continue using the existing v1 trait and circuit-manager uses this extension as an adapter.

## C Tor security properties

- A fresh private data/cache directory is created for every process and deleted after shutdown.
- Unix uses owner-only directory permissions and an owner-only Unix control socket.
- Windows removes inherited ACLs and grants the directory only to the current account and SYSTEM.
- A Windows loopback control listener is dynamic. Commands require `SAFECOOKIE`; the cookie and
  listener-discovery file are inside the restricted directory.
- `TAKEOWNERSHIP`, child `kill_on_drop`, a crash watcher, graceful `SIGNAL SHUTDOWN`, a bounded wait,
  and forced termination cover controller and child failures.
- SOCKS is dynamically allocated and always uses SOCKS5 authentication isolation. The username is
  the Tor extension `<torS0X>0`; the password is the random 32-byte isolation key encoded as hex.
- Onion endpoints, clearnet destinations, SOCKS credentials and bridge descriptors are never placed
  in tracing fields or shared error strings. Child stdout/stderr are not ingested.
- A process crash cancels all managed stream tokens and reports health as fail-closed. It never
  enables a direct socket fallback.

Bridge and upstream proxy options are validated, bounded, and can change only while stopped.
Executable pluggable transports are an extension point; packaging and signature verification of PT
binaries belongs to platform distribution, not this crate.

## Rotation semantics

- Soft rotation increments the session epoch only. Existing `ByteTransport` values and isolation
  cancellation tokens remain valid; future allocations use fresh contexts.
- Hard rotation is rate-limited, sends one `SIGNAL NEWNYM`, cancels active stream tokens, clears all
  isolation contexts, and increments the epoch. It is never called per connection.
- Network change marks the backend degraded, advances the epoch and sends `SIGNAL ACTIVE`; new work
  remains blocked until health becomes ready again.

All operation-owned retries use `RetryPolicy`/`BoundedBackoff`: full jitter, a finite attempt budget,
and a maximum delay. The health monitor is cancellation-bound and does not restart the network.

## Test commands

```powershell
cargo test --manifest-path crates/tor-backend/Cargo.toml --all-features
cargo clippy --manifest-path crates/tor-backend/Cargo.toml --all-features --all-targets -- -D warnings
```

## Open questions

1. Should Windows production use an inherited owning-controller socket/broker instead of a
   SAFECOOKIE-authenticated loopback listener when C Tor gains a stable supported mechanism?
2. Which signed pluggable-transport bundles and update policy are approved for desktop/mobile?
3. Should authenticated upstream proxy credentials be added via platform secure storage in v2?
4. What minimum supported C Tor version is required for the non-legacy `<torS0X>0` isolation format?
5. Should production add a per-user SOCKS broker or platform firewall rule? C Tor's dynamically
   allocated loopback SOCKS listener is not remotely reachable, but another process under a local
   account can connect to the port even though OnionRoute always supplies isolation credentials.
