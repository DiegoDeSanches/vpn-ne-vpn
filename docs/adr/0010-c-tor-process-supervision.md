# ADR-0010: C Tor as a separately supervised MVP process

- Status: Accepted for MVP
- Date: 2026-07-17
- Extends: ADR-0007

## Context

OnionRoute needs v3 onion streams, mature bridge/pluggable-transport support, SOCKS stream isolation,
bootstrap status and predictable desktop behavior. Arti remains desirable, but its mobile runtime,
bridge coverage, API stability and compatibility with the required lifecycle have not yet completed
product security review.

Embedding C Tor or exposing its control protocol to client-core would enlarge the crash/trust
boundary and make migration harder. A shared system Tor process would also mix OnionRoute isolation
and lifecycle with unrelated applications.

## Decision

The MVP starts one C Tor child process per independently managed Tor context. Each child owns a fresh
private data directory, dynamic SOCKS listener and authenticated local control channel.

- Unix control uses an owner-only Unix socket inside a mode `0700` directory.
- Windows control uses a dynamic loopback listener; `SAFECOOKIE` is mandatory and its cookie is held
  in a directory whose inherited ACL is removed.
- The controller sends `TAKEOWNERSHIP`; the child is kill-on-drop and independently watched.
- Shutdown first sends `SIGNAL SHUTDOWN`, waits for a bounded deadline, then terminates the child.
- SOCKS5 authentication isolation uses the Tor extension username `<torS0X>0` and a fresh random
  isolation parameter. `NEWNYM` is reserved for rate-limited hard rotation.
- Child logs are not ingested and public diagnostics contain only closed static messages.
- Direct Tor is an explicit API, never an availability fallback.

The stable common `TorBackend` remains implementation-neutral. Managed operations stay in a local
extension pending CP-0003.

## Consequences

- C Tor crashes are contained and detected, but process startup and secure filesystem handling are
  platform responsibilities.
- Every independent process consumes additional memory and directory bandwidth; `TorContextPool` is
  therefore bounded to at most 32 contexts.
- Windows has an authenticated loopback listener rather than Unix filesystem-level socket admission.
  Normal local users cannot issue commands without the protected SAFECOOKIE; platform hardening may
  replace this with an inherited controller channel later.
- Pluggable-transport executable provenance must be enforced by signed application packaging.
- Arti migration requires an adapter, not client-core changes, but only after the blockers in
  `docs/arti-migration.md` are closed.

## Alternatives rejected

- Shared system Tor: lifecycle and isolation interference with other local applications.
- In-process C FFI: larger memory-safety and mobile ABI boundary, harder crash containment.
- Arti for initial MVP: missing reviewed parity for the complete required platform matrix.
- Per-connection `NEWNYM`: rate-limited by Tor, disruptive, and unnecessary with SOCKS isolation.

## Verification

- Contract tests for stable `TorBackend` and the managed extension.
- Mock process integration for SAFECOOKIE, bootstrap, SOCKS isolation and graceful shutdown.
- Fault injection for bootstrap failure, process crash, corrupt transient state and network change.
- State-machine tests for soft/hard/identity reset and make-before-break failure.
- Platform security tests verifying Unix modes or Windows ACLs before starting Tor.

## References

- [Tor control protocol commands](https://spec.torproject.org/control-spec/commands.html)
- [Tor control authentication notes](https://spec.torproject.org/control-spec/implementation-notes.html)
- [Tor SOCKS extensions and isolation](https://spec.torproject.org/socks-extensions.html)
