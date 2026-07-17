# onionroute-dns-engine

This crate owns DNS wire validation, ECS rejection, short-lived synthetic IPv4
mapping and identity-scoped bounded caching. It never calls a system resolver.

`A` questions receive an address from `198.18.0.0/15`; later TCP flows recover the
hostname from the map and send the hostname through `GatewayConnector`. `AAAA`
questions receive an empty successful answer while MVP IPv6 is blocked. Other
record types use only the explicit protected gateway DNS exchange.

Call `identity_reset`/`flush_cache` before a new identity becomes active.

