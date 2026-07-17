# ADR-0012: mobile FFI uses registry-backed opaque handles

- Status: Proposed
- Date: 2026-07-17

## Context

Android JNI and the iOS packet tunnel extension need a stable boundary over the
runtime-neutral Rust client core. Exporting `Box<T>` pointers makes a repeated or
concurrent destroy call capable of dereferencing freed memory. Direct callbacks
also make re-entrancy and extension shutdown ordering difficult.

## Decision

ABI v1 exposes a process-local `uint64_t` handle. A synchronized Rust registry
owns `Arc<Client>` values and never intentionally reuses a token. Every call
acquires an operation lease. Destroy removes the token first, rejects new calls,
cancels operations, waits for existing leases, drains bounded state, and then
completes shutdown.

All asynchronous output is a fixed-size event in a bounded polling queue. Events
carry closed-schema numeric codes and at most 64 bytes of bounded data. C callers
never retain Rust references. Every exported entry point catches Rust unwinding;
the library is built with a documented panic boundary and production builds must
also use `panic=abort` or equivalent verified containment for third-party code.

ABI negotiation is an inclusive major/minor range. Major 1 accepts additive
minor changes only. Structs begin with `struct_size`; unknown fields can be added
only by a new function or a size-negotiated successor struct.

## Consequences

- Invalid or destroyed handles fail without touching freed allocations.
- A process crash invalidates all handles; platforms reconstruct from secure,
  minimal persisted intent while keeping their OS tunnel fail-closed.
- The registry is process-local and is not a persistent identity.
- Polling needs a platform event pump, but avoids arbitrary Rust-to-Swift/JNI
  callback re-entrancy.
- The packet adapter remains unavailable until CP-0006 is accepted. Prototypes
  drop packets instead of creating a clearnet fallback.

## Verification

- Concurrent call/destroy and repeated destroy tests.
- Queue-capacity and overflow tests.
- ABI range and struct-size tests.
- Cancellation and deterministic shutdown tests.
- Fuzz all exported pointer/length pairs in a native harness; invalid addresses
  remain a caller contract because no C ABI can validate arbitrary memory.

