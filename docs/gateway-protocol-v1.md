# OnionRoute private gateway protocol v1

Status: candidate normative specification pending CP-0003 approval.

## Transport and framing

Production uses an authenticated/confidential reliable byte stream, normally
pinned TLS 1.3 through Tor to an Onion Service. The protocol never uses QUIC and
the crate does not know whether the stream came from C Tor, Arti, a test duplex, or
another adapter.

```text
+----------------------+----------------------------------+
| canonical u32 varint | serialized GatewayFrame protobuf |
| encoded body length  | exactly that many bytes           |
+----------------------+----------------------------------+
```

- Prefix: 1–5 bytes, minimal unsigned-varint representation; zero is invalid.
- Encoded `GatewayFrame`: 1..65,536 bytes.
- Compression and padding: not defined in v1.
- `Data.payload`: 1..32,768 bytes.
- Prefix is validated before body allocation.
- Each direction starts at sequence 1 and increments exactly by one; replay,
  gaps and wrap close the session.

## Handshake

```text
Client                                      Gateway
  | ClientHello (range, caps, mode, nonce)    |
  |------------------------------------------->|
  | ServerHello (full range, selected, nonce, |
  | limits, ephemeral session ID)             |
  |<-------------------------------------------|
  | Authenticate (anonymous token, optional   |
  | PoP, SHA-256 transcript binding)          |
  |------------------------------------------->|
  | AuthenticationResult                      |
  |<-------------------------------------------|
```

The range spans one major. The gateway selects the highest common minor. It
returns its complete range, and the client recomputes the selection. A lower or
out-of-range choice is `SilentDowngrade`; no overlap returns the redacted
`ProtocolIncompatible` error and closes. A different major is attempted only on a
new transport explicitly allowed by client policy.

Capabilities are at most 32 ASCII names of at most 64 bytes. `required:name`
makes absence fatal. V1 defines `tcp-connect-v1`, `flow-control-v1`,
`resolve-domain-v1` and `session-rotation-v1`. Security behavior is enabled only
after the server echoes it without the `required:` prefix. Authentication may
grant a strict subset; the active session authorizes only that post-auth subset.

The session binding is:

```text
SHA-256(
  "onionroute-gateway-auth-v1" || 0x00 ||
  client_nonce[32] || server_nonce[32] || session_id[16] ||
  selected_major_be32 || selected_minor_be32
)
```

The optional PoP uses this digest according to the independently reviewed token
scheme. The protocol does not define new signature/MAC cryptography.

Handshake has a hard 30-second default deadline. Authentication completes before
TCP open or resolve. An expired/rejected token does not reveal whether it was
unknown, spent or expired.

## Message/state rules

| Message | Direction/state | Key rule |
|---|---|---|
| `ClientHello` | client, first | empty envelope session ID; nonce is 32 fresh bytes |
| `ServerHello` | server, second | fresh 16-byte ephemeral ID and 32-byte nonce |
| `Authenticate` | client, auth | token ≤4 KiB, PoP ≤4 KiB, binding exactly 32 bytes |
| `AuthenticationResult` | server, auth | typed accept/reject without free-form detail |
| `OpenTcpStream` | client, active | odd strictly increasing ID; hostname/IP never logged |
| `TcpStreamOpened/Rejected` | server | exactly one answer to a pending ID |
| `Data` | either, open stream | charged to both windows; forbidden after sender half-close |
| `WindowUpdate` | either | ID 0 is connection credit, odd ID is stream credit |
| `HalfClose` | either | closes only sender-to-receiver data direction |
| `CloseStream` | either | cancellation/final disposal; queued data is dropped locally |
| `ResolveDomain/Result` | client/server | separate odd monotonic query space; ≤16 answers |
| `RotateSession/Rotated` | client/server | make-before-break; replacement transport required |
| `Ping/Pong` | either | 8..32-byte ephemeral nonce, liveness only |
| `Error` | either | coarse code, no peer-controlled text or sensitive context |
| `GoAway` | either | bounded drain, no new open/resolve afterward |

Client stream IDs are odd, strictly increasing and never reused, including after
reject/cancel. Unknown streams, duplicate opens, repeated half-close, data after
half-close and answers to unknown query IDs fail the session.

## Flow control and memory

Initial connection windows are exchanged in hello; initial stream windows are
exchanged by open/opened. Payload bytes decrement both relevant receive/send
ledgers. An application sends `WindowUpdate` only after consuming bytes, restoring
local receive credit before advertising it. Checked addition forbids wrap and hard
limits credit to 16 MiB per connection and 4 MiB per stream.

Defaults:

| Resource | Default | Hard maximum |
|---|---:|---:|
| Encoded frame | 64 KiB | 64 KiB |
| Data payload | 32 KiB | 32 KiB |
| Concurrent streams | 512 | 4,096 |
| Connection receive window | 4 MiB | 16 MiB |
| Stream receive window | 256 KiB | 4 MiB |
| Total outbound queue | 8 MiB | local policy ≤ available memory |
| Per-stream outbound queue | 256 KiB | total queue |
| Control frames queued | 256 | local policy |
| Outstanding resolves | 128 | local policy |
| Handshake timeout | 30 s | local policy |
| Idle stream timeout | 120 s | hello/server policy ≤ 1 h |

Queue saturation returns `Backpressure`; it never expands a buffer and never
falls back to clearnet. The caller pauses upstream reads or rejects new flows.
The owning async driver calls `expire_idle_streams` on a periodic timer; expiry
queues a typed cancellation and does not permit stream ID reuse.

## Scheduling and HOL

Control traffic receives a maximum burst of eight frames. Active logical streams
then transmit one frame each in round-robin order. Large writes are split into
32-KiB Data frames. Cancellation removes unsent frames for that stream.

This avoids producer-driven starvation but cannot avoid wire HOL: all frames still
share a single TCP/Tor byte stream. A bounded pool of independently isolated
sessions can be evaluated after measurement; v1 defaults to one session and the
protocol crate does not manage the pool.

## Unknown data and extensions

- Duplicate singular envelope fields are rejected rather than last-one-wins.
- Unknown body tags 29–63 are a protocol violation in v1.
- An absent body is always invalid.
- Unknown optional high-tag fields may be ignored by Protobuf.
- `critical_extension_ids` explicitly names semantics unsafe to ignore. Every ID
  must be enabled during hello; v1 currently registers none.
- Unknown enum values controlling state, policy, role or errors are invalid.
- Removing a field reserves its tag/name; changing framing requires a new major.

## Privacy and diagnostics

Gateway schema contains no account, user, device, payment, billing or client-IP
field. Destinations, resolved addresses, payload, tokens, proof, nonces, session
IDs and correlation IDs are sensitive. The protocol crate has no `tracing` or
telemetry dependency. `FrameSummary`/`orp-dump` reports only type, sequence, logical
stream ID, sensitive byte count and a redaction marker; it never retains or prints
the sensitive values.
