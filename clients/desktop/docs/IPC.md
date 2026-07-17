# Desktop IPC v1

Canonical schema:
`crates/ipc/schema/onionroute/desktop/ipc/v1/ipc.proto`.

## Transport

Frames are `uint32` big-endian encoded length followed by one protobuf
`Envelope`. Payload limit is 65,536 bytes. A receiver checks the prefix before
allocation, rejects incomplete/trailing frames, rejects unknown security enums
and closes the session on non-monotonic sequence numbers. Event delivery has a
negotiated maximum unacknowledged window of 256; a full window applies
backpressure rather than dropping security state into an unbounded queue.

## Mutual authentication

Authentication precedes protobuf decoding and never trusts an identity field from
the message:

| OS | UI authenticated by daemon | daemon authenticated by UI |
|---|---|---|
| Windows | Named Pipe ACL, impersonated access token, expected interactive SID, low-privilege client | server PID equals SCM service PID, installed path and Authenticode publisher |
| macOS | Network Extension audit token, App Group and designated code requirement | `NETunnelProviderSession` resolves only the signed installed provider |
| Linux | `SO_PEERCRED`, socket owner/group/mode and authorized desktop UID | peer UID is 0, executable identity from `/proc/<pid>/exe`, installed file ownership/signature policy |

`ClientHello` and `ServerHello` nonces bind only process/session freshness. They
are not shared secrets and do not replace OS authentication. DPAPI, Keychain and
Secret Service values remain inside privileged platform adapters.

## Versioning and limits

The package major is `v1`; envelopes also carry `(major, minor)`. Cross-major
negotiation and unknown policy enum values fail closed. The current supported
version is `1.0`. Collection/string bounds are enforced in Rust after decode:

- frame: 64 KiB;
- split rules: 128, application identifier: 256 bytes;
- event topics: 16, event window: 1..256;
- support correlation code: 16 ASCII alphanumeric characters;
- confirmation challenge: 16 bytes, single-use, 60 seconds, 32 pending maximum;
- diagnostics retention: 1..168 hours.

## Error privacy

`Response` contains a closed `ErrorCode` and optional random support correlation
code. It has no human/backend message field. UI maps the code to local text. This
makes accidental rendering of an onion address, token, hostname or remote IP
structurally impossible in the contract.

