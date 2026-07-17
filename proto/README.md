# OnionRoute wire contracts

The directories below the `proto/` root are public wire contracts. Package names
contain a major version (`onionroute.<area>.v1`). Every top-level request or frame
also carries a negotiated `ProtocolVersion`; package versioning alone is not a
substitute for negotiation.

Ownership:

- `common/v1`: wire primitives only; it must not import any OnionRoute package.
- `directory/v1`: signed, public gateway metadata.
- `gateway/v1`: anonymous data-plane session and flow protocol. Account and
  billing identifiers are forbidden here.
- `control/v1`: client-facing control-plane API. Authentication identity is
  supplied by the control-plane transport, not copied into data-plane messages.
- `health/v1`: allow-listed, coarse health reports without destinations, user
  identifiers, addresses, or traffic contents.

Field-size and frame-size limits are normative in `docs/protocol-versioning.md`.
Generated code is intentionally not committed in this initial contract package.

