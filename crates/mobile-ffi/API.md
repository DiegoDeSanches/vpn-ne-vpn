# Mobile C ABI v1

The canonical declarations are in `include/onionroute_mobile.h`.

## Version and construction

`or_client_create` accepts one exact v1 `or_create_options_t`. The caller supplies
an inclusive ABI range. This implementation negotiates the highest supported
minor version in that range (currently 1.1) or returns
`OR_STATUS_INCOMPATIBLE_VERSION`. ABI 1.0 callers remain supported. Event capacity is 8–4096 and the declared
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
4. Cancel pending dispatcher I/O and join the bounded Rust runtime actor.
5. Shut down core, gateway session, route and Tor in reverse order.
6. Cancel operation IDs, clear bounded queues and release the client.

Do not call platform UI or network APIs while holding an FFI call. The ABI has no
direct callbacks; poll `or_client_poll_event` on a dedicated platform queue.

## Packet output

ABI 1.1 adds `or_client_poll_packet`. The caller owns a buffer of at most
`OR_MAX_PACKET_BYTES`; Rust returns one complete packet and a protocol value of 4
or 6. If the buffer is too small, the function returns
`OR_STATUS_BUFFER_TOO_SMALL`, reports the required length and leaves the packet
queued. Output packets are bounded by both count and a fraction of the declared
memory budget. The queue never evicts a packet to make room for a newer packet.

Packet bytes are local data-plane output and never enter the diagnostic event
queue. The iOS adapter maps protocol 4/6 to `AF_INET`/`AF_INET6` and writes the
packet through `NEPacketTunnelFlow` only while the protected core is Connected.

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
route TUN and calls `set_tunnel_ready(true)`. The installed CP-0006 factory then
runs on a dedicated bounded actor. Only that actor can publish `CONNECTED`, after
Tor reports 100% bootstrap and the authenticated gateway session independently
reports Active and matches the verified plan. In production,
`set_core_ready(true)` returns `OR_STATUS_UNAVAILABLE`; it cannot turn a platform
assertion into a health proof. `set_core_ready(false)` remains a compatible
fail-closed acknowledgement. No timeout or error path changes to a direct route.

Soft and hard rotation are defined as make-before-break requests. The production
actor currently rejects them with `OR_STATUS_UNAVAILABLE` and preserves the active
protected path until atomic circuit plus gateway-session replacement is supplied.
`set_network` never tears down the TUN; an unavailable, captive or uncertain path
blocks/reconnects. Sleep freezes deadlines and resume requires an independent
path-health result.

When a production factory is installed before the first handle is created,
packet submission copies into a count-bounded actor queue and returns explicit
backpressure when full. The actor sends all synthetic TCP/DNS output through the
existing bounded reverse queue. If no factory is installed, creation remains
usable for diagnostics but tunnel startup fails closed with
`OR_STATUS_UNAVAILABLE`.
