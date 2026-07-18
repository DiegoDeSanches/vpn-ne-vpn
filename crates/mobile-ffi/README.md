# OnionRoute mobile FFI (experimental)

This crate owns the versioned C boundary used by Android JNI and the iOS packet
tunnel extension. It does not expose Rust pointers or references. A client is a
process-local 64-bit token backed by a synchronized registry; tokens are never
reused during a normal process lifetime.

The adapter implements lifecycle, bounded event delivery, cancellation, network
handoff signals, privacy settings, deterministic destruction, the ABI 1.1 bounded
packet-output queue and the accepted CP-0006 runtime actor. Packet output is never
mixed with diagnostic events and a short caller buffer cannot consume or truncate
a queued packet.

The embedding composition installs one object-safe `ClientRuntimeFactory` before
creating any handle. Factory creation proves Tor bootstrap plus an authenticated,
route-matching gateway session; only the Rust actor can then publish Connected.
Packet submission uses a count-bounded actor queue and explicit backpressure. If
no factory is installed, startup and packet submission return
`OR_STATUS_UNAVAILABLE` and the mobile TUN remains fail-closed.

Build and test:

```text
cargo test --manifest-path crates/mobile-ffi/Cargo.toml
cargo build --release --manifest-path crates/mobile-ffi/Cargo.toml
```

On macOS, `clients/ios/scripts/build-rust-xcframework.sh` builds device and
universal simulator slices with Rust 1.78-compatible dependencies and produces
the local XCFramework consumed by XcodeGen.

The canonical public header is `include/onionroute_mobile.h`. ABI additions must
be backward compatible within major version 1. Breaking changes require a new
major version and a contract proposal.
