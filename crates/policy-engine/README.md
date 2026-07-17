# onionroute-policy-engine

The MVP policy is default-tunnel and fail-closed. It blocks SMTP port 25,
well-known BitTorrent ports, IPv6 literals, loopback/private/link-local/metadata
destinations and invalid endpoints. DNS is always protected.

An explicit split-tunnel application may receive `Bypass`, but client-core has no
direct egress implementation. The platform must exclude that application before
its traffic enters OnionRoute's TUN; a bypass result reaching packet-engine is
blocked as a safety invariant.

