# onionroute-common-types

This crate is the inward-facing contract boundary for OnionRoute components. It
contains no platform APIs, network runtime, generated protobuf, cryptographic
implementation, or component implementation.

Implementations depend on this crate; this crate never depends on them. During
parallel development, enable `test-utils` to use deterministic mocks:

```toml
onionroute-common-types = { path = "../common-types", features = ["test-utils"] }
```

Rust contracts live in `contracts::v1`. A breaking contract creates `v2` rather
than mutating `v1`. Wire models remain owned by `proto/` and are deliberately not
duplicated as generated code here.

