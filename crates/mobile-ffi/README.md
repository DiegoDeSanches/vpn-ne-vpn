# OnionRoute mobile FFI (experimental)

This crate owns the versioned C boundary used by Android JNI and the iOS packet
tunnel extension. It does not expose Rust pointers or references. A client is a
process-local 64-bit token backed by a synchronized registry; tokens are never
reused during a normal process lifetime.

The current prototype implements lifecycle, bounded event delivery, cancellation,
network handoff signals, privacy settings and deterministic destruction. Packet
submission validates its input and then returns `OR_STATUS_UNAVAILABLE`: the
production `ClientCore` packet/session construction dependency described by
`CP-0006` has not been accepted. Both mobile prototypes therefore keep their TUN
interfaces up and drop user packets rather than permitting a direct fallback.

Build and test:

```text
cargo test --manifest-path crates/mobile-ffi/Cargo.toml
cargo build --release --manifest-path crates/mobile-ffi/Cargo.toml
```

The canonical public header is `include/onionroute_mobile.h`. ABI additions must
be backward compatible within major version 1. Breaking changes require a new
major version and a contract proposal.

