# CP-0006: mobile client-core adapter and workspace member

## Problem

Android `VpnService` and iOS `NEPacketTunnelProvider` can provide bounded IP
packets, lifecycle signals and protected-socket actions, but `client-core` has no
public construction/orchestration adapter that combines a Tor backend, circuit
manager, signed directory, anonymous token provider and active gateway session.
The root workspace also does not build the new mobile FFI crate.

## Current contract

`ClientCore::new` requires already-constructed packet, DNS, policy and gateway
dispatcher objects. Mobile code may call `handle_packet`, `suspend`, `resume` and
`shutdown` only after another component has safely assembled those objects.

## Proposed change

1. Accept `crates/mobile-ffi` as a root workspace member.
2. Add a runtime-neutral, object-safe `ClientRuntimeFactory` contract that builds
   one bounded `ClientCore` session from verified configuration, an anonymous
   token set, a Tor backend and platform socket-protection acknowledgements.
3. Add an owned `MobilePacketAdapter` with bounded submit/output queues,
   cancellation, `suspend/resume`, rotations and deterministic shutdown.
4. Keep the C ABI in `mobile-ffi`; no C types enter `common-types`.
5. Represent Android socket protection as a queued request/ack operation. No Tor
   socket may call `connect` until `VpnService.protect(fd)` succeeds.

## Affected teams

Architecture/contracts, core/network-engine, core/tor-backend, control/directory,
control/auth-tokens, client/mobile, QA/integration and security/threat-model.

## Compatibility

Additive Rust contracts and a new workspace member. The C ABI starts at major 1.
No protobuf, directory or token wire format changes are proposed.

## Migration

Until acceptance, `mobile-ffi` is a standalone workspace and exposes lifecycle
control only. `or_client_submit_packet` returns `UNAVAILABLE`; Android and iOS keep
their full-route TUN active and drop packets. After acceptance, inject the real
factory behind the unchanged ABI and enable `set_core_ready(true)` only after Tor
and the gateway session pass independent health checks.

## Risks

- Incorrect socket protection can create a tunnel loop or direct traffic leak.
- Re-entrant platform callbacks can deadlock, hence request/ack event queues.
- Tor bootstrap and dual-route rotation can exceed mobile memory/battery budgets.
- A signed config verifier at the wrong boundary could accept rollback or an
  incompatible catalog.

## Tests

- Existing client-core contract tests plus Android/iOS packet-loop adapters.
- Concurrent submit/cancel/destroy and handle misuse fuzzing.
- Wi-Fi/cellular handoff, sleep, process kill, extension restart and low memory.
- Invalid/expired directory, expired token, gateway failover.
- Physical-interface DNS, IPv6, QUIC and direct-destination leak assertions.

