# OnionRoute

OnionRoute is a fail-closed system privacy tunnel that routes supported TCP and DNS
traffic through Tor and private gateways. This repository currently contains the
architecture baseline and version 1 integration contracts; component implementations
are intentionally out of scope for this change.

Start here:

- [Architecture](docs/architecture.md)
- [Trust boundaries](docs/trust-boundaries.md)
- [Error model](docs/error-model.md)
- [Protocol versioning and signed directory](docs/protocol-versioning.md)
- [Integration test plan](docs/integration-plan.md)
- [Architecture decisions](docs/adr/README.md)
- [Wire contracts](proto/README.md)
- [Rust contracts and mocks](crates/common-types/README.md)
- [Control-plane directory services](docs/control-plane/README.md)
- [GitHub Releases publishing](docs/releases.md)

The non-negotiable properties are: no clearnet fallback, verified kill switch before
network bootstrap, protected DNS, no account identity in gateway data plane, bounded
inputs/backpressure, and explicit protocol versions.
