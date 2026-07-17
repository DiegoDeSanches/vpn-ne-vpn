# Arti migration plan

`ArtiBackend` is an experimental fail-closed scaffold behind the same stable `TorBackend` boundary.
It currently stores validated bridge/proxy intent but rejects bootstrap, stream and rotation calls.
This prevents an incomplete implementation from becoming a clearnet fallback.

## Missing functions

- Reviewed bootstrap lifecycle with bounded cancellation/deadline behavior.
- v3 onion-service client streams with exact SOCKS-auth-equivalent isolation semantics.
- Explicit public-exit streams for Direct Tor mode.
- Stable mapping for soft epoch rotation and disruptive hard rotation.
- Bridge and pluggable-transport parity for the approved desktop/mobile set.
- Network-change recovery, dormant/background behavior and bootstrap health events.
- Stream cancellation/ownership that can close all hard-rotation streams without leaks.
- State/cache corruption recovery and crash-safe transient cleanup.

## Known incompatibilities

- C Tor uses a child process, SAFECOOKIE control protocol and SOCKS authentication; Arti is normally
  an in-process Rust client. The adapter must emulate semantics, not control commands.
- `SIGNAL NEWNYM` has no required one-to-one Arti API. Hard rotation needs a reviewed client-context
  replacement strategy.
- C Tor bridge configuration uses torrc `Bridge`/`ClientTransportPlugin`; Arti configuration and PT
  management APIs differ and may not cover every approved transport/version.
- C Tor data-directory layout cannot be reused as Arti state. Migration must use a new directory and
  must not silently trust old cache/state files.
- Error categories and bootstrap progress granularity differ. Shared diagnostics must remain coarse
  and static.

## Mobile FFI/runtime risks

- Rust static-library size, duplicate async runtimes and symbol/allocator conflicts with Kotlin/Swift.
- App suspension can pause timers and network tasks while the system packet tunnel remains active.
- iOS Network Extension memory limits and Android background-process termination.
- Cross-language cancellation, panic containment and callback-after-free hazards.
- Secure storage and filesystem protection differences for guard/state data.
- Pluggable-transport subprocess restrictions, especially on iOS.

No mobile FFI should expose raw Arti streams or client handles. The platform shell should see only
the same runtime-neutral contracts and bounded callbacks used by C Tor.

## Transition blockers

1. Contract suite passes for bootstrap, onion, Direct Tor, isolation, cancellation and shutdown.
2. Approved bridge/PT matrix reaches parity or product explicitly narrows supported transports.
3. Hard rotation and Identity Reset pass unlinkability and active-stream closure review.
4. Network-change and background/suspend tests pass on every supported mobile OS version.
5. Memory, startup latency and binary-size budgets are approved.
6. State corruption cannot trigger a permissive reset or clearnet fallback.
7. Independent security review covers Arti version pinning, supply chain and unsafe/FFI boundaries.
8. Operational rollback can select C Tor before tunnel start without changing a live identity.

## Migration phases

1. Desktop-only experimental feature with no production selection path.
2. Run the shared fake/contract/fault suite and a private Tor test network.
3. Add mobile static-library prototypes behind compile-time experimental flags.
4. Compare coarse health and performance aggregates without destination labels.
5. Security review and limited opt-in beta.
6. Make Arti selectable only after all blockers close; keep C Tor rollback for one release train.

## Open questions

- Which exact Arti release and feature set are supportable for the full release lifetime?
- Which bridge transports can be embedded without subprocesses on iOS?
- Does Arti expose sufficient circuit retirement controls for Maximum-profile hard rotation?
- How are guard/state migrations communicated without implying a stronger anonymity guarantee?
