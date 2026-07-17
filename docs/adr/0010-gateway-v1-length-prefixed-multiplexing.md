# ADR-0010: length-prefixed Protobuf and bounded multiplexing for gateway v1

- Status: Proposed for architecture review
- Date: 2026-07-17
- Owner: `protocol/gateway-v1`

## Context

The client and private gateway communicate over a reliable ordered byte stream,
normally application TLS 1.3 inside a Tor stream to a v3 Onion Service. The layer
must carry several logical TCP streams and control messages without depending on
Tor, egress networking, billing, or a UI. QUIC and arbitrary UDP are outside the
MVP.

The main risks are attacker-controlled allocation, ambiguous downgrade, stream ID
reuse, window overflow, an unbounded slow consumer, scheduler starvation, and
accidental logging of destinations or payloads.

## Decision

Gateway v1 uses a canonical unsigned-varint length prefix followed by one
`onionroute.gateway.v1.GatewayFrame` Protobuf value. The encoded message is at
most 64 KiB; a `Data.payload` is at most 32 KiB. Compression is forbidden.

Each direction has an independent sequence starting at one. The server creates a
fresh 16-byte ephemeral session ID. Client-created stream and resolve IDs are odd,
strictly increasing and never reused. Hello exchanges both supported ranges; the
server selects the highest intersection and returns its full range, allowing the
client to detect a silent lower-minor selection.

Multiplexing has connection and per-stream credit. Credit additions and debits are
checked against fixed hard maxima. The sender uses bounded global/per-stream
queues. Control messages may run for eight frames before one logical stream gets a
turn; data uses one-frame round-robin across active streams. This prevents a busy
producer from causing user-scheduler HOL, although it cannot remove loss-induced
HOL in the underlying single ordered Tor stream.

Protobuf unknown optional fields remain forward-compatible. A frame explicitly
lists critical extension IDs; an ID not enabled during hello terminates the
session. Unknown message tags in the v1 control namespace, duplicate singular
envelope fields, non-canonical envelope varints, or a missing oneof body are
protocol violations. New critical semantics therefore cannot be silently ignored.

`RotateSession` is make-before-break coordination only. It never resets sequence
or stream IDs on the current transport. An accepted rotation requires a new
protected transport and a complete fresh handshake.

## Alternatives

### HTTP/2

HTTP/2 already supplies framing, stream lifecycle, flow control and scheduling,
but introduces a much larger state machine, HTTP-specific semantics and dependency
surface. Correct SETTINGS, HPACK, priority and error handling are unnecessary for
the narrow MVP. It remains a possible future major-version choice, not a v1
dependency.

### Strict CBOR

CBOR can be compact and typed at the Rust boundary, but cross-language schema
tooling and compatibility checks are weaker in the current project. Canonical CBOR
also needs its own strictness rules. It provides no decisive MVP advantage over the
already accepted Protobuf toolchain.

## Parallel Tor streams

One multiplexed Tor stream is the v1 default because it needs one TLS/auth
handshake, one bounded state machine and one capability redemption. It is easiest
to reason about and consumes fewer Tor/gateway resources.

Several parallel Tor streams can reduce transport HOL only if they are actually
placed on sufficiently independent Tor circuits. They also increase TLS/auth/token
cost, memory, observable concurrency and traffic-correlation surface. Opening many
streams to the same Onion Service on one circuit does not guarantee useful failure
independence.

The recommended follow-up is a capped pool of 2–4 independently isolated gateway
sessions, enabled only by measured workload and anonymity policy. Each pool member
runs the exact same protocol and limits; streams are never migrated mid-flight.
This policy belongs to `circuit-manager`/`client-core`, not this crate. MVP remains
one multiplexed session.

## Consequences

- The implementation stays small enough for exhaustive semantic validation and
  decoder fuzzing.
- Memory is bounded by negotiated frame/window/queue/stream limits.
- A single transport still has unavoidable TCP/Tor HOL after loss or a stalled
  write; fairness only controls locally queued user traffic.
- Generated Protobuf values can expose sensitive bytes through derived debugging.
  Production code must log only the provided redacted `FrameSummary`.
- The caller must provide a confidential, authenticated transport in production;
  the protocol crate intentionally does not select Tor or implement egress.

## Security assumptions

- Production transport is TLS 1.3 with gateway identity pinned from the signed
  directory, carried through the intended protected route.
- Capability-token and proof-of-possession cryptography is supplied by the
  separately reviewed auth-token component. This crate only computes the
  domain-separated SHA-256 session transcript binding.
- No absolute anonymity claim follows from multiplexing or parallel streams.
