# CP-0002: add write-half shutdown to ByteTransport

## Problem

TCP FIN from a local application is a write-half close. The v1 `ByteTransport`
contract exposes only full `close`, so a connector adapter cannot preserve a
long-lived response after the request half closes.

## Current contract

`ByteTransport` supports `read`, `write`, `flush`, and full `close`.

## Proposed change

Add an object-safe `shutdown_write(&mut self) -> BoxFuture<'_, OnionResult<()>>`.
Implementations must make it idempotent, reject later writes, and continue reads
until the peer closes or a deadline/cancellation fires.

Until accepted, client-core models half-close in its flow state and invokes full
`close` only after both halves close or on failure. It does not fake a direct
fallback.

## Affected teams

Architecture/contracts, gateway protocol, gateway connector, Tor backend,
core/network-engine and QA/integration.

## Compatibility

Source-breaking for existing trait implementers. Wire compatibility depends on
the gateway protocol's existing stream half-close frame and requires confirmation
from `protocol/gateway-v1`.

## Migration

Add the method in a coordinated change, update every transport adapter and mock,
then make the dispatcher call it for `CloseDirection::Write`.

## Risks

An adapter could accidentally map half-close to full close and truncate responses;
shutdown races could leak a stream resource.

## Tests

Contract tests for idempotency, write-after-half-close rejection, continued reads,
remote FIN, simultaneous close, cancellation and shutdown timeout.

