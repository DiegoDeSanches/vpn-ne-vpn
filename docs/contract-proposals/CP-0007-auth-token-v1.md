# CP-0007: anonymous capability token v1 and batch issuance API

- Status: Proposed
- Date: 2026-07-17
- Owner: `control/auth-tokens`

## Problem

The protected `proto/control/v1/control.proto` exposes a blind-token-shaped
single-token RPC, while ADR-0003 still marks the concrete algorithm as pending
security review. The gateway contract correctly treats capability bytes as an
opaque value capped at 4 KiB, but there is no approved canonical schema for MVP
signed claims, bucketed batch issuance, verification keys/revocations, PoP or
anonymous replay state.

Changing `proto/`, root `Cargo.toml`, `common-types` or gateway public APIs
directly would violate the protected-contract rule. The implementation is
therefore standalone and the candidate protobuf remains under
`services/token-service/api/` until this proposal is accepted.

## Current contract

`ControlService.MintCapabilityToken` accepts:

- protocol version;
- blinded request bytes;
- free-form requested capability strings.

It returns blind-signature bytes, expiry and issuer key ID. No canonical token
claims or batch/PoP role scope is defined. Gateway transports an opaque token
and proof byte string through its existing authentication boundary.

## Proposed change

### Canonical protobuf

After review, place the candidate as `proto/token/v1/token_service.proto` with:

- `AccountTokenService.MintTokenBatch`;
- account authentication exclusively in transport middleware, never a message
  field;
- 1..8 ephemeral Ed25519 PoP public keys and exactly one requested hop role;
- response of opaque capability tokens with a common not-before/expiry;
- `SignedCapabilityTokenEnvelopeV1`, exact claims, closed policy enums and
  canonical connection-limit fields.

Do not reinterpret the current blind RPC. Either keep it reserved for the
reviewed blind protocol or deprecate it after clients migrate. Add the batch RPC
as a new method/package so old protobuf clients cannot silently change
semantics.

### Public Rust interfaces

Data-plane-safe crate `onionroute-auth-tokens`:

- `TokenIssuer::issue(IssueTokenRequest)` — accepts no identity-bearing type;
- `TokenVerifier::verify(VerificationRequest)` — local crypto/policy checks plus
  anonymous store reservation;
- `TokenStore::reserve/release` — linearizable per-token replay/session state;
- `RevocationProvider::status` — locally cached revocation view.

Account-plane service `onionroute-token-service`:

- `BillingEntitlementProvider::entitlement_for` — minimal payment adapter;
- `DeviceSlotManager::authorize_slot/release_slot` — account-local installation
  accounting;
- `TokenService::mint_batch` — entitlement-to-anonymous-policy orchestration.

The public `CapabilityClaims` schema contains only:

- version and random 32-byte token ID;
- coarse plan, exactly one allowed gateway role and region set;
- coarse device/bandwidth classes and canonical connection limits;
- fixed-bucket not-before/expiry;
- common issuer key ID;
- optional 32-byte PoP public key;
- Ed25519 signature in the outer envelope.

No account, e-mail, name, payment/order ID, client IP or persistent device ID is
permitted.

### Gateway adapter

The existing `AuthenticationVerifier` remains unchanged. A separate adapter
will map `LocalTokenVerifier` output to `AuthenticationGrant` only after this CP
is accepted. Until then gateway's production placeholder remains deny-all; no
public gateway file is changed in this proposal.

## Affected teams

- `architecture/contracts`: package placement, version negotiation and enum
  review.
- `protocol/gateway-v1`, `gateway/egress`, `gateway/multihop`: verifier adapter,
  role binding and shared replay store.
- `control/directory`: signed issuer-key/revocation bundle distribution.
- `control/auth-tokens`: issuer, account service and blind migration.
- `client/desktop`, `client/mobile`, `core/network-engine`: ephemeral PoP key
  cache and per-role batch selection.
- `infra/platform`: HSM/KMS and anonymous distributed store.
- `security/threat-model`, `qa/integration`: protocol review and fault tests.

## Compatibility

- Gateway token bytes remain opaque and within the existing 4 KiB bound.
- No current root workspace member or protected type changes.
- Unknown token versions fail closed; invalid new tokens are never retried as an
  older format.
- Role-specific credentials are compatible with entry/relay/exit separation and
  prevent cross-hop token-ID reuse.
- Future Blind RSA/VOPRF credentials use a new token protocol version behind the
  same opaque gateway field.

## Migration

1. Review ADR-0013, threat model, replay design and candidate protobuf.
2. Accept/adjust this CP and move schema into protected `proto/token/v1`.
3. Add approved workspace members and lock dependency versions in root CI.
4. Implement signed issuer-key/revocation bundle verification.
5. Provide a production `TokenStore` and fault-injection suite.
6. Add the gateway adapter without changing the existing authentication trait.
7. Enable MVP issuance only after security review; retain deny-all otherwise.
8. Introduce blind issuance as an explicit v2 and retire v1 after bounded dual
   stack operation.

## Risks

- The directly signed MVP is not cryptographically unlinkable from its issuer.
- A non-linearizable distributed store permits cross-gateway over-admission.
- Too many policy/region/key cohorts fingerprint users.
- Stale clocks or revocation snapshots cause denial or excess validity.
- Co-located account and issuer logs can recreate the forbidden join.
- Ed25519 local issuer and in-memory stores could be mistaken for production
  implementations; both are marked experimental.

## Tests

- canonical/bounded decode and fuzz target;
- signature tamper, time, issuer-key window and policy-shape tests;
- PoP challenge/gateway binding and missing-key tests;
- exact replay, multi-gateway shared-store count and release tests;
- revoked/stale snapshot fail-closed tests;
- inactive/unavailable billing, entitlement end and device-slot tests;
- integration test with identifiable account input absent from token bytes and
  no billing dependency in gateway verifier construction;
- future protobuf conformance against the canonical moved schema.
