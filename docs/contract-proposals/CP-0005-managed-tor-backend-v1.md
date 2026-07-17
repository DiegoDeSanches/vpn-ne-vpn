# CP-0005: managed Tor backend operations

- Status: Proposed
- Date: 2026-07-17
- Owner: `core/tor-backend`

## Problem

The accepted common `TorBackend` v1 exposes bootstrap, onion/direct streams, coarse status and
shutdown. It does not represent separately managed process start/stop, explicit isolation-context
lifetime, soft/hard rotation, bridge/proxy configuration, network change or detailed fail-closed
health. Adding those methods directly would change a protected public contract.

## Current contract

`onionroute_common_types::contracts::v1::TorBackend`:

- `bootstrap`;
- `open_onion_stream`;
- `open_direct_stream`;
- `status`;
- `shutdown`.

## Proposed change

Introduce a backwards-compatible managed extension (implemented locally today as `TorBackendExt`):

- `start`, `stop`, `bootstrap_progress`;
- `allocate_isolation_context(scope)`, `release_isolation_context(context)`;
- `request_soft_rotation`, `request_hard_rotation`;
- `health_status`, `network_changed`;
- `configure_bridges`, `configure_proxy`.

`IsolationScope` is bounded and contains application, anonymity profile, gateway, destination group
and optional browser container. `IsolationContext` adds the backend-owned session epoch and random
`IsolationKey`. Debug output for both is redacted.

`BackendHealth` is closed-schema and contains only lifecycle, bootstrap percent, accepting-streams,
active-stream count and fail-closed flag. It cannot carry destinations, relays or identifiers.

## Affected teams

- `architecture/contracts`: review version placement and naming.
- `core/tor-backend`: C Tor/Arti implementations.
- `core/network-engine`: client-core health and identity-reset adapter.
- `client/desktop`, `client/mobile`: bridge/proxy configuration adapters.
- `qa/integration`, `security/threat-model`: contract and local-access tests.

## Compatibility

Existing consumers continue using `TorBackend` v1. No existing method changes semantics. The local
extension is an adapter until accepted. An eventual common addition should be a v1 minor extension
only if object safety and source compatibility are preserved; otherwise publish contract v2.

## Migration

1. Review this proposal and the redaction/limit types.
2. Add the approved extension/version to `common-types` with deterministic mocks.
3. Switch circuit-manager from the local extension import to the common contract.
4. Add client-core `HealthObserver` and `RotationObserver` adapters.
5. Remove the local duplicate only after all consumers migrate.

## Risks

- Confusing process contexts with SOCKS isolation contexts.
- Making hard rotation available without client-core stream-close coordination.
- Exposing bridge/proxy secrets through Debug or telemetry.
- Treating Direct Tor as fallback rather than explicit mode.
- Contract growth tied too closely to C Tor control commands.

## Tests

- One contract suite for C Tor, fake backend and future Arti.
- Concurrent allocation and forced collision.
- Soft rotation keeps existing transport usable; hard rotation cancels it.
- Bootstrap/crash/network-change health becomes fail-closed.
- Bridge/proxy bounds and stopped-only mutation.
- Redaction test for every public Debug/error value.
