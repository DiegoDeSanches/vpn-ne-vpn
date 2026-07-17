# OnionRoute inter-gateway protocol v1

Status: experimental candidate; wire registration awaits CP-0008.

## Transport

- Reliable ordered stream protected by TLS 1.3 mTLS.
- ALPN: `onionroute-inter-gateway/1`.
- TLS 1.2, compression, 0-RTT, PSK resumption and QUIC are forbidden.
- Entry trusts only exit data-plane CA + signed short-lived leaf pins.
- Exit trusts only entry data-plane CA + signed short-lived leaf pins.

## Framing

```text
+----------------------+-----------------------------------+
| canonical u32 varint | InterGatewayFrame protobuf body   |
| body length, 1..5 B  | exactly length bytes, max 64 KiB  |
+----------------------+-----------------------------------+
```

Sequence begins at one independently per direction and increments exactly by
one. Connection ID is empty only for ClientHello, then exactly 16 random bytes.
Unknown/missing body, noncanonical/overflowing prefix, sequence gap/replay,
changed version or connection ID, and oversized body close the connection.

## Handshake

```text
Entry                                      Exit
  | mTLS TLS 1.3 (entry/exit service certs) |
  |------------------------------------------|
  | ClientHello(range, entry ID, nonce, time)|
  |------------------------------------------>|
  | ServerHello(selected, exit ID, nonce, ID)|
  |<------------------------------------------|
  | Finished(TLS exporter + transcript)      |
  |<------------------------------------------|
  | Finished(TLS exporter + transcript)      |
  |------------------------------------------>|
```

The IDs in hello must equal the already pinned mTLS identities and roles. Client
time must be within 60 seconds. Nonces are 32 random bytes. Exit rejects a reused
`(entry_service_id, nonce)` from a bounded ten-minute cache. Finished is SHA-256
over a domain, the 32-byte TLS exporter, both nonces, connection ID, selected
version, length-delimited service IDs and direction. This is channel binding,
not a new encryption or signature scheme.

The server selects the highest common minor within one major. The client rejects
a non-maximal selection as downgrade.

## Active messages

| Message | Direction | Limits/rule |
|---|---|---|
| `OpenSession` | entry → exit | odd, increasing, non-reused ID; terminal protocol version; window; expiry ≤ local max TTL |
| `SessionOpened` | exit → entry | matching pending ID and bounded receive window |
| `SessionRejected` | exit → entry | coarse enum only, no free text |
| `Data` | both | nonempty, ≤32 KiB; charged to connection + session window |
| `WindowUpdate` | both | session ID 0 means connection; checked credit, never above hard max |
| `HalfClose` | both | no further Data from sender |
| `CloseSession` | both | coarse close enum; queues for ID discarded |
| `Ping/Pong` | both | 8..32 ephemeral bytes |
| `GoAway` | both | drain timeout 1..30,000 ms; no new sessions |

The schema intentionally contains no account/user/device/payment identifier,
client/source IP, hostname, destination IP, DNS payload, Tor circuit ID or
management endpoint. `Data` is opaque terminal TLS bytes.

## Limits and backpressure

| Resource | Default | Hard maximum |
|---|---:|---:|
| Encoded frame | 64 KiB | 64 KiB |
| Data payload | 32 KiB | 32 KiB |
| Concurrent relay sessions | 512 | 4,096 |
| Connection window | 4 MiB | 16 MiB |
| Session window | 256 KiB | 4 MiB |
| Handshake | 10 s | local policy |
| Relay session TTL | 1 h | 24 h |
| Drain | local policy | 30 s |

Window exhaustion or bounded queue saturation returns Backpressure. The driver
pauses upstream reads; it never allocates an unbounded buffer and never bypasses
the inter-gateway route.
