# onionroute-client-core

`ClientCore` coordinates the bounded packet processor, synthetic DNS mapping,
local policy, gateway-only dispatcher, lifecycle timers, cancellation and
sleep/resume. It does not select Tor circuits and it has no UI, system resolver,
direct socket, billing or gateway-daemon dependency.

The only data-plane egress calls are:

- `GatewayConnector::open_tcp` for Standard/Enhanced/Maximum TCP;
- `GatewayConnector::exchange_dns` for protected non-synthetic DNS.

The prepared gateway session is supplied by the orchestrator/CircuitManager path
defined in ADR-0007. client-core intentionally does not call C Tor or Arti directly.

See [API.md](API.md) for the action contract, buffer ownership, cancellation,
half-close and lifecycle rules.

## Shutdown order

1. Stop accepting packets/flows.
2. Emit local RST and clear bounded queues.
3. Close protected streams.
4. Close the packet tunnel in the platform adapter.
5. Only then may the outer orchestrator verify cleanup and disengage the kill switch.
