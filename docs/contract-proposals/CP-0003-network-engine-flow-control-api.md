# CP-0003: accept the experimental network-engine flow-control API

## Problem

The MVP packet adapter must not acknowledge application bytes before protected
delivery succeeds, and it must not consume protected bytes without bounded local
TCP credit. Shutdown also needs to interrupt a pending connector future without
acquiring the single-owner core lock.

## Current contract

The protected shared contracts expose ordered `ByteTransport` streams and
`GatewayConnector`, but do not define the local packet-engine action API. CP-0001
has not yet added the network-engine crates to the root workspace. `ByteTransport`
also lacks write-half shutdown, tracked separately by CP-0002.

## Proposed change

Accept the experimental public API implemented by the standalone crates:

- `EngineConfig::{retransmit_interval_ms,max_retransmissions}`;
- `PacketProcessor::protected_read_capacity`;
- successful-write ACK actions returned by `acknowledge_forwarded`;
- `ConnectionDispatcher::read_once_limited`;
- `DispatcherCancellation` and `ClientCore::cancellation_handle`.

The API retains one bounded protected-to-application segment until ACK and exposes
zero read credit while it is outstanding. Cancellation is cooperative and drops
the pending connector future; the connector implementation must be cancellation-safe.

## Affected teams

Architecture/contracts, core/network-engine, protocol/gateway-v1, core/tor-backend,
QA/integration, client/desktop and client/mobile.

## Compatibility

The crates are not root workspace members until CP-0001 is accepted. For early
consumers, the new configuration fields are source-breaking for exhaustive struct
literals, and callers must execute the actions returned by `acknowledge_forwarded`.
No protobuf, directory, token or gateway wire format changes are proposed.

## Migration

Use `EngineConfig::default()` plus field overrides, execute the returned ACK action,
check read credit before polling a protected stream, and retain a cancellation
handle in the runtime's deadline/shutdown task. Keep the CP-0002 adapter behavior
for local write-half close until that proposal is coordinated.

## Risks

- A connector future that is not cancellation-safe could orphan remote resources.
- A runtime that does not schedule `tick` can delay retransmission and timeout.
- The one-segment reverse window limits throughput over a slow local TCP consumer.
- The minimal adapter still requires differential and OS leak testing before production.

## Tests

- ACK-after-protected-write and downstream failure tests.
- Protected read-credit, retransmission and retry-exhaustion tests.
- Local-first and remote-first FIN/half-close tests.
- Cancellation wakeup, reconnect, shutdown and sleep/resume tests.
- Randomized parser, malformed input and OS packet-capture leak suites.
