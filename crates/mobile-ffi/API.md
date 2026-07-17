# Mobile C ABI v1

The canonical declarations are in `include/onionroute_mobile.h`.

## Version and construction

`or_client_create` accepts one exact v1 `or_create_options_t`. The caller supplies
an inclusive ABI range. This implementation negotiates 1.0 or returns
`OR_STATUS_INCOMPATIBLE_VERSION`. Event capacity is 8–4096 and the declared
memory budget is 4–256 MiB. The budget is a hard orchestration input; it is not a
claim about an operating-system extension limit.

On success, the caller owns one non-zero 64-bit token. The token is opaque,
process-local, not persistent and not an identity. `or_client_destroy` consumes
it. Destroy removes it from the registry before waiting for current calls, so a
new or repeated call returns `OR_STATUS_INVALID_HANDLE` without dereferencing
freed memory.

## Pointer and ownership rules

- Input pointers are borrowed only for the documented call.
- No pointer may be null unless the declaration says it is optional.
- Pointer/length pairs must describe readable memory in the caller process.
- Output pointers must be aligned, writable and valid for the call.
- Rust never retains a C buffer and C never receives a Rust allocation.
- `or_event_t` is copied into caller-owned storage.
- Country is exactly two uppercase ASCII bytes.
- Packets are 1–131072 bytes.

An invalid address is undefined behavior at the C language boundary; use-after-
destroy is safely detected because clients are numeric registry tokens rather
than allocation addresses.

## Threading and shutdown

All functions may be called concurrently. Operations are serialized per client
where state ordering matters. `or_client_destroy` is deterministic:

1. Remove handle from the public registry.
2. Reject new leases.
3. Wait for leased calls to return.
4. Cancel operation IDs and clear bounded queues.
5. Complete `ShutdownCoordinator` and release the client.

Do not call platform UI or network APIs while holding an FFI call. The ABI has no
direct callbacks; poll `or_client_poll_event` on a dedicated platform queue.

## Event format

Every event has a monotonic process-local sequence, optional operation ID, fixed
kind/code/value fields and up to 64 bytes of bounded data. A sequence gap plus
`OR_EVENT_QUEUE_OVERFLOW` means the consumer was slower than the producer. The
newest safety state is retained; raw destinations, IP addresses, tokens and site
history are forbidden event data.

| Kind | Meaning |
|---|---|
| `ABI_NEGOTIATED` | `value = major << 32 | minor` |
| `STATE_CHANGED` | `value` is `or_client_state` |
| `PLATFORM_ACTION` | platform must perform/ack a closed-schema action |
| `OPERATION` | completion or cancellation status |
| `DIAGNOSTIC` | local closed-schema diagnostic |
| `QUEUE_OVERFLOW` | one or more older events were discarded |

## Lifecycle contract

`connect` stops at `APPLYING_KILL_SWITCH`. The platform creates/verifies its full
route TUN and calls `set_tunnel_ready(true)`. The state then stops at
`BOOTSTRAPPING_TOR`; only the accepted CP-0006 adapter may call
`set_core_ready(true)` after Tor and the anonymous gateway session are healthy.
No timeout or error path changes to a direct route.

Soft and hard rotation are make-before-break requests. `set_network` never tears
down the TUN; an unavailable, captive or uncertain path blocks/reconnects. Sleep
freezes deadlines and resume requires an independent path-health result.

The current prototype returns `OR_STATUS_UNAVAILABLE` for every packet after
validating its bound. This is intentional until CP-0006 supplies the real
`ClientCore` adapter.

