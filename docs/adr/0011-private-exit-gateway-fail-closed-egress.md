# ADR-0011: fail-closed private exit gateway egress boundary

- Status: Proposed; implementation experimental pending token and OS security review
- Date: 2026-07-17

## Context

The exit gateway is the only private gateway role permitted to resolve terminal
destinations and create Internet sockets. It is exposed through a Tor v3 Onion
Service and must remain bounded under malformed sessions, DNS rebinding, connection
storms, stalled peers, auth outages, and draining. It must not combine account
identity with destination metadata or expose a public ingress interface.

## Decision

The exit uses a loopback-only TLS 1.3 listener shared with a dedicated Tor frontend
inside a named egress network namespace. Protobuf v1 frames use unsigned-varint
length delimiters, strict per-direction sequences, odd monotonic client stream IDs,
bounded pending opens, credit-based reads, and fixed queues.

`OpenTcpRequest` processing is ordered: authenticated unexpired session, anonymous
token quotas, hostname/port ACL, explicit-upstream DNS, validation of every returned
IP, a second DNS lookup, validation again, direct-IP TCP dial, and bounded stream
bridging. The OS never receives a hostname. ACL and nftables independently block
non-public ranges, metadata endpoints, management networks, SMTP/25, configured
administrative ports, arbitrary user UDP, and Tor control ports.

Token verification is an injected offline interface. Until the reviewed token
format is integrated, the runnable adapter rejects every token. Auth timeout or
verifier failure cannot become anonymous allow.

Anti-scan state is a keyed per-process digest with a short window. Events and metrics
have closed schemas; destination, DNS wire, payload, token, account ID, Tor circuit,
IP, port, and protocol session ID are absent. Temporary events are bounded, volatile,
and TTL-purged.

Draining rejects new sessions and new streams but does not revoke active stream
leases. Shutdown stops accept and gives active work a bounded grace period.

## Consequences

- A DNS resolver or auth outage makes new operations unavailable rather than less
  protected.
- Strict revalidation adds DNS latency and can change the selected public address;
  only the second checked answer is dialed.
- Classic DNS is restricted to explicit namespace upstreams for v1. DNS-over-TLS is
  an open operator/privacy decision.
- The Tor frontend must share the namespace because the daemon deliberately refuses
  non-loopback listeners.
- Remote health reporting and cryptographic token logic remain owner-specific
  adapters rather than unreviewed formats in the gateway crate.

## Verification

Unit and integration tests cover SSRF ranges, DNS rebinding, CNAME/parser bounds,
malformed/oversized frames, token expiry, stream exhaustion, draining, DNS/egress
failure, slow peers, and connection storms. Production promotion additionally
requires namespace nftables leak tests and a reviewed auth verifier.
