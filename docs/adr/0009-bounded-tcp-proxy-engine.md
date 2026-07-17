# ADR-0009: bounded TCP proxy engine for the MVP

- Status: Accepted for MVP, implementation remains experimental until OS leak tests pass
- Date: 2026-07-16

## Context

The packet tunnel must terminate local IPv4 TCP, map an application connection to an
ordered protected stream, and remain bounded under retransmission, malformed input,
downstream stalls, sleep/resume, and shutdown. It must not create a clearnet socket.
Implementing a general-purpose TCP/IP stack in this repository would be a high-risk
security and maintenance decision.

The evaluated options were:

| Option | Advantages | MVP disadvantages |
|---|---|---|
| smoltcp | Rust, no unsafe required by our crates, mature wire validation and TCP state machine | A transparent dynamic-endpoint adapter and async stream bridge are still required; socket polling must be integrated carefully |
| lwIP binding | Very mature and used by tun2socks implementations | C FFI and memory-safety boundary, build complexity on desktop/mobile, separate cancellation model |
| Existing tun2socks process/library | Broad protocol experience and tested behavior | Most candidates own DNS/routing policy, expose direct SOCKS assumptions, or make fail-closed and per-flow metadata difficult to prove |
| Minimal custom TCP proxy | Small, auditable surface and exact bounded queues | Easy to get retransmission/window/half-close semantics wrong and not suitable as a general TCP stack |

## Decision

The MVP uses a **tun2socks-style terminating proxy architecture with a minimal
custom TCP proxy engine**. A small checked parser validates the fixed IPv4/TCP/UDP
fields needed by the MVP, including lengths, fragmentation and checksums. It is not
a general IP stack. OnionRoute owns only a deliberately limited, bounded TCP flow
adapter for the local TUN leg: handshake sequencing,
duplicate suppression, cumulative ACKs, FIN/RST, fixed receive window, timeouts,
and bridging to an ordered `GatewayConnector` stream. It does not implement IP
routing, congestion control over a physical network, arbitrary UDP, fragmentation,
or a direct socket backend.

The adapter acknowledges application payload only after the corresponding
bounded `GatewayConnector` write and flush succeed. In the reverse direction it
retains at most one bounded unacknowledged segment, stops protected reads while
that credit is consumed, retransmits on a fixed local timer, and resets after a
bounded retry count. Out-of-order payload is not buffered; the adapter emits the
current cumulative ACK and relies on the local OS stack to retransmit.

Pending gateway futures are cooperatively cancellable through a cloneable handle
owned by the outer runtime. Connection and idle deadlines remain monotonic inputs
to the synchronous packet state machine; the runtime must schedule `tick` and
cancel an in-flight dispatcher future at the same deadline.

This choice is justified only for the narrow local TUN leg and keeps the repository
build reproducible without a C toolchain or external tun2socks process. `smoltcp`
remains the preferred replacement if differential/soak testing finds lifecycle gaps;
such a replacement belongs behind the same action boundary.

The parser and local adapter are experimental until the lifecycle corpus, randomized packet
tests, long soak, and OS packet-capture leak suites pass. A later ADR may replace
the local state adapter with smoltcp TCP sockets behind the same action boundary;
that change must preserve the fail-closed dispatcher and bounded queues.

Only `GatewayConnector::open_tcp` and `GatewayConnector::exchange_dns` may create
data-plane operations for Standard/Enhanced/Maximum modes. `PolicyAction::Bypass`
is never translated into a socket by client-core; platform split tunneling must
exclude an explicitly allow-listed application before its packets enter this TUN.

## Consequences

- The parser and response writer have no OS socket API and cannot fall back to the
  clearnet.
- Fragmented IPv4, IPv6, arbitrary UDP, QUIC and unknown transports fail closed.
- Every queue and flow table has a configured bound.
- Protected-to-application credit is released only by a valid cumulative ACK;
  application-to-protected credit is released only by a successful protected write.
- TCP half-close is modeled internally. The existing shared `ByteTransport` lacks
  a write-half shutdown operation; CP-0002 proposes the compatible contract change.
- Production promotion requires OS-specific pcap leak tests and a differential TCP
  lifecycle suite against a reference stack.
- TCP options, receive reassembly, congestion control and arbitrary IP forwarding
  remain deliberately outside this experimental adapter.

## Verification

- Parser and malformed/random packet tests.
- SYN/retransmit/ACK/data/FIN/half-close/RST lifecycle tests.
- Buffer exhaustion, idle/connect timeout, reconnect, shutdown and resume tests.
- DNS/IPv6/QUIC leak assertions with mocks that expose no direct network API.
