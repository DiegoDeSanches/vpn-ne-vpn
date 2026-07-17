# ADR-0013: MVP short-lived PoP capability tokens

- Status: Proposed; experimental pending security review
- Date: 2026-07-17
- Owner: `control/auth-tokens`
- Refines: ADR-0003 (does not replace the blind-issuance target)

## Context

ADR-0001 separates account and data planes. ADR-0003 selects blind/VOPRF-style
anonymous credentials but leaves the reviewed algorithm and migration sequence
open. The MVP still needs bounded offline gateway authorization while the
control plane can be temporarily unavailable.

A bearer JWT is inappropriate: identity-bearing claims create a direct join to
billing, arbitrary limits fingerprint users, and online introspection makes
gateway availability depend on the account plane.

## Decision

Use an experimental versioned protobuf envelope with Ed25519 signatures from a
standard library. Claims contain a 256-bit random token ID, coarse plan class,
one role-scoped gateway capability, one of four region sets, coarse device and
bandwidth classes, canonical connection limits, fixed-bucket validity, issuer
key ID, and an optional Ed25519 PoP public key. They contain no account,
payment, order, e-mail, name, client IP, or persistent device ID.

MVP policy requires the PoP field even though the v1 envelope represents it as
optional for protocol evolution. A client signs a domain-separated value that
binds the token ID, gateway identity/key digest, and a fresh gateway challenge.

Token windows start on five-minute boundaries and last exactly 15 minutes.
Every token is valid for exactly one hop role. Issuance occurs in same-policy,
same-expiry batches of at most eight credentials with independent random token
IDs and ephemeral PoP keys.

Gateway admission has two parts:

1. local bounded parsing, canonical-policy checks, time/scope checks, cached
   revocation checks, and Ed25519 signature/PoP verification;
2. an atomic reservation in an anonymous data-plane `TokenStore`, keyed only by
   random token/session values, to enforce replay and active-session limits.

A multi-gateway production `TokenStore` must be linearizable per token ID and
must fail closed for new reservations when unavailable. Existing admitted
sessions may continue only until the signed token expiry. A control-plane
outage does not interrupt a valid credential, but prevents renewal; it never
turns a credential into an unbounded grant.

Gateways hold issuer public keys and signed/cached revocation data only. Online
signing keys reside in an HSM/KMS-backed issuer. An offline root signs the key
manifest; it is not present on gateways or online issuers.

## Privacy constraints

- Plan determines device, bandwidth and connection limit values; arbitrary
  per-account combinations are rejected by verifiers.
- The allowed product space is three plan profiles, four region sets and three
  hop roles (only plan-permitted combinations).
- Role-specific credentials prevent entry/relay/exit correlation by token ID.
- Issuer, token service, replay store and gateway must not log raw token IDs,
  token bytes, PoP keys/signatures, challenges, or account-to-batch mappings.
- Per-token revocation is exceptional; normal subscription cancellation is
  bounded by the 15-minute TTL to avoid building a redemption join table.

## Consequences

- Signature and policy verification remains local and does not query billing.
- Replay enforcement requires a highly available anonymous data-plane store.
- A stolen token without its ephemeral PoP private key is not directly usable;
  theft of both remains useful for no longer than the signed expiry.
- The MVP issuer can still correlate issuance and redemption by timing or by
  violating the no-token-ID logging rule. Cryptographic unlinkability arrives
  only with the next issuance protocol.
- `LocalEd25519TokenIssuer`, `InMemoryTokenStore`, and in-memory account
  adapters are test/development components, not production backends.

## Migration target

Adopt the RFC 9576 architecture with separate Attester and Issuer and an RFC
9578 issuance protocol. Publicly verifiable Blind RSA tokens are the leading
fit because gateways need only public verification material. VOPRF issuance is
also prototyped, but RFC 9578's VOPRF token is privately verifiable and would
put issuer secret material or an online verifier in the gateway path. No
cryptographic primitive will be implemented locally.

## Rejected alternatives

- Account JWT at gateway: direct identity linkage and excessive metadata.
- Long-lived bearer tokens: high theft value and poor revocation behavior.
- Pure one-time tokens: excessive batch pressure and hard failure on every
  transient replay-store fault.
- Bloom filter as source of truth: false positives and no atomic session count.
- Gateway-held signing/verification secret: one gateway compromise expands to
  token forgery across the fleet.

## Verification

- Wire fuzzing and 4 KiB size limit.
- Signature, expiry, scope, region, PoP binding, replay, active-session and
  stale-revocation tests.
- Integration test proves an account-local value is absent from minted bytes
  and constructs a gateway with no billing/account dependency.
- Independent cryptographic review and RFC test vectors before blind issuance
  is enabled.
