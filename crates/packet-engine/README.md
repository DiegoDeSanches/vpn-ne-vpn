# onionroute-packet-engine

This experimental MVP crate validates IPv4/TCP/UDP packets, blocks IPv6 and
unsupported transports, terminates the local TCP leg, maintains bounded flow state,
intercepts UDP/TCP DNS, and emits explicit actions. It has no socket API.

Every flow records local endpoints, optional hostname/application, route isolation,
anonymity profile, gateway ID, monotonic timestamps, TCP state and queue limits.
These values remain process-local and are not metric labels or remote telemetry.

See ADR-0009 for the reviewed TCP stack alternatives and promotion gates.

