# CP-0003: bounded private-gateway protocol v1

- Status: Proposed; implementation candidate included for review
- Date: 2026-07-17
- Owner: `protocol/gateway-v1`

## Problem

The initial `gateway.proto` does not expose all required hello limits, explicit
session-nonce binding, connection-level flow control, separate TCP open/reject
messages, domain-resolution messages, session rotation, or predictable handling
of critical extensions. There is no reference framing/session implementation.

## Current contract

The current draft has one `GatewayFrame`, request/response pairs, raw DNS wire
messages and per-stream credit. It uses `AuthenticateRequest/Response`,
`OpenTcpRequest/Response` and `ResetStream`. `ClientHello` omits desired country and
maximum frame size. The public normative framing document already selects
unsigned-varint length + Protobuf and odd monotonic stream IDs.

## Proposed change

Split `proto/gateway/v1` into `types.proto`, `handshake.proto`, `stream.proto` and
the top-level `gateway.proto`. Add the exact v1 messages:

`ClientHello`, `ServerHello`, `Authenticate`, `AuthenticationResult`,
`OpenTcpStream`, `TcpStreamOpened`, `TcpStreamRejected`, `Data`, `WindowUpdate`,
`HalfClose`, `CloseStream`, `ResolveDomain`, `ResolveResult`, `RotateSession`,
`SessionRotated`, `Ping`, `Pong`, `Error`, and `GoAway`.

The envelope adds per-direction sequence, selected version, critical extension
IDs and a 16-byte ephemeral session ID. Authentication carries a bounded anonymous
token, optional proof of possession and a 32-byte transcript binding. There are no
account, user, device, payment or client-address fields.

## Affected teams

- `architecture/contracts`: approve schema and workspace integration.
- `control/auth-tokens`: implement the verifier and optional PoP over the binding.
- `gateway/egress`: consume validated open/resolve events and return typed results.
- `core/network-engine`: adapt `GatewayConnector` to the reference client API.
- `core/tor-backend`: provide only an already protected byte transport.
- `qa/integration` and `security/threat-model`: conformance, fault and fuzz review.

## Compatibility

The old schema has not been released, but the rename/restructure is wire-breaking
against that draft. Existing tags are not silently reinterpreted. Until the
architect accepts this proposal, consumers should treat the crate as an adapter
candidate and must not deploy it against the earlier draft.

Once v1 is released, field/tag semantics follow `docs/protocol-versioning.md` and
breaking changes require `onionroute.gateway.v2` on a separate endpoint/session.
Unknown optional high-tag fields can be ignored; unknown critical extension IDs or
message bodies fail closed.

## Migration

1. Architecture approves this CP and the descriptor breaking baseline.
2. Add `crates/gateway-protocol` to the root workspace in an architecture-owned
   change; until then it builds with its own manifest/workspace.
3. Regenerate client/gateway bindings from the four v1 schema files.
4. Replace draft request/response adapters with typed events from this crate.
5. Run client-old/server-new and client-new/server-old incompatibility tests; the
   unsupported peer receives `ERROR_CODE_PROTOCOL_INCOMPATIBLE` before close.
6. Establish the first released `buf breaking` baseline.

## Risks

- Protobuf generated `Debug` can reveal sensitive values if a consumer logs it.
  The crate itself has no logging dependency and supplies a redacted decoder.
- One reliable transport retains loss-induced HOL despite fair local scheduling.
- A bad token verifier could accept bearer material without required PoP; the
  verifier remains outside this protocol crate and needs independent review.
- The Windows host lacks the MSVC linker/SDK. The crate and vendored protoc build
  pass on Linux Rust 1.78 in Docker; Windows CI remains required before a Windows
  artifact release.

## Tests

- Golden canonical framed Ping bytes and all incremental chunk boundaries.
- Reject oversized/non-canonical prefixes, duplicate envelope fields, unknown
  message tags and critical extension IDs.
- Highest-common version and silent-downgrade tests.
- Stream ID reuse, dual-window exhaustion and credit-overflow tests.
- Fair scheduler starvation test.
- End-to-end Tokio duplex hello/auth/open/data and incompatible-version tests.
- Privacy-schema and debug-redaction tests.
- Proptest arbitrary decoder input and `cargo-fuzz` decode target.
