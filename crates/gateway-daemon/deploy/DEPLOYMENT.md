# Private exit deployment guide

Status: experimental Linux deployment. Promotion requires the reviewed token
verifier, TLS/KMS integration, namespace leak tests, and an operator runbook.

## Topology

Run a dedicated Tor client/onion-service process and the gateway daemon in the same
named network namespace, `onionroute-egress`. Both data-plane and management sockets
bind only to namespace loopback. Nothing listens on a public interface. Tor forwards
the v3 onion virtual port to `127.0.0.1:8443`; Prometheus collection must use an agent
in that namespace or an explicitly authenticated local proxy. Do not publish port
9090 through a veth or load balancer.

The namespace owns a dedicated uplink/veth and applies `onionroute-egress.nft` after
every creation. Default input, forward, and output policy is drop. The gateway UID
may emit TCP to public destinations and DNS only to the configured resolvers. The
Tor UID may emit TCP to public Tor relays. Private, loopback, link-local, metadata,
multicast, documentation, benchmark, management, and reserved networks are denied
before UID-specific allows.

## Installation

1. Create fixed system users `onionroute-gateway` and `onionroute-tor`, without
   login shells or home directories. Never run either service as root.
2. Create `/run/netns/onionroute-egress`, its veth/uplink, routes, source-NAT on the
   host if required, and DNS allow-list. Apply the nftables template inside the
   namespace before starting Tor or the gateway.
3. Install the binary read-only at `/usr/local/bin/onionroute-gateway-daemon` and
   configuration at `/etc/onionroute-gateway/gateway.json`, mode `0640`, owned by
   `root:onionroute-gateway`.
4. Deliver a TLS 1.3 certificate chain and private key through Vault/KMS integration.
   The private key is `0640` or stricter; publish its SPKI SHA-256 through the signed
   directory. Onion authentication does not replace terminal TLS identity.
5. Select operator-approved DNS resolvers. Update both `gateway.json` and the nft
   `dns_v4`/IPv6 sets atomically. A DNS failure blocks connect; it never enables the
   host resolver or a clearnet fallback.
6. Configure the dedicated Tor v3 service from the sample and v3 client auth files.
   Run Tor in the same namespace with `SocksPort 0` and `ControlPort 0`.
7. Install the unit, run `systemd-analyze security onionroute-gateway.service`, then
   enable the namespace/firewall service, Tor, and gateway in that order.

## Operations

- `systemctl reload onionroute-gateway` sends `SIGUSR1` and enters draining. New
  network sessions and streams are rejected; existing streams remain until they
  close. Draining is one-way for the process, so restart after the node is removed
  from the signed directory and active stream gauges reach zero.
- `SIGTERM` first enters draining, stops accept, and waits up to the configured grace
  period. After the grace period, remaining tasks are aborted.
- Readiness is `GET /healthz` on namespace loopback. It returns 503 while draining or
  while the egress circuit breaker is open. `/metrics` contains only fixed aggregate
  counters and active gauges without labels.
- The hardened unit discards stdout/stderr. Operational events use only the bounded
  TTL memory buffer and fixed metrics. Never enable payload/frame debug logging or
  packet capture in production.
- Privacy events live only in process memory, have bounded capacity and TTL, and are
  lost on restart by design.

## Verification before traffic

1. From the public network, confirm no daemon or management port is reachable.
2. In the namespace, confirm only loopback owns ports 8443 and 9090.
3. Run SSRF tests for RFC1918, loopback, link-local, IPv6 ULA, cloud metadata, the
   management subnet, multicast, broadcast, and DNS public-to-private rebinding.
4. Capture the uplink during malformed frames, auth outage, DNS outage, draining,
   and egress failure; assert no unexpected UDP, direct fallback, private-network,
   or management traffic.
5. Run connection-storm, slow-client, slow-destination, file-descriptor, memory, and
   shutdown tests under the systemd limits.

## Rollback

Remove the gateway from the signed directory, wait for directory propagation, enter
draining, wait for active streams to reach zero, stop the service, then roll back the
binary. Keep nftables default-drop rules and the namespace in place throughout.
