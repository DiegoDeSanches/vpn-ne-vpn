# Anonymous credential migration roadmap

## Goal

Remove the MVP issuer's ability to link an authenticated issuance event to the
credential later redeemed at a gateway, while preserving coarse entitlement,
role scope, local public verification, replay protection and key rotation.
No cryptographic primitive will be designed or implemented in-house.

The design follows the four logical roles from RFC 9576:

- **Client**: creates blinded requests, caches and redeems credentials;
- **Attester**: account plane that authenticates subscription/device slots and
  grants a fixed number of issuance operations;
- **Issuer**: sees a standardized blinded request and issuance authorization,
  but no account identity;
- **Origin**: OnionRoute gateway that verifies/redeems without account access.

Attester and Issuer need separate deployments, IAM, storage and telemetry.
Non-collusion improves privacy; batching and time separation remain necessary.

## Candidate families

### Blind RSA / publicly verifiable Privacy Pass token

RFC 9578 token type `0x0002` gives blind issuance and public verification.
That fits OnionRoute gateways: they keep only issuer public keys. Use an audited
RFC 9474/RFC 9578 implementation and their published test vectors. Do not add
home-grown blinding, padding, encoding or key generation.

Capabilities cannot become arbitrary public metadata. Define a small token
type/key per coarse policy cohort (and one role per token), or adopt a reviewed
partially blind/public-metadata extension only after its standard, library and
anonymity-set effects pass review. Too many issuer keys/token types partition
users and become a fingerprint.

Primary migration candidate because verification remains local and public.
Trade-off: RSA keys/signatures are larger and blind-signature key operations
need strict HSM/library support.

### VOPRF / privately verifiable Privacy Pass token

RFC 9578 token type `0x0001` uses VOPRF(P-384, SHA-384), based on RFC 9497, for
privately verifiable tokens. The issuer does not learn the final token during
issuance, but verification requires issuer private-key evaluation.

This conflicts with the goal that a gateway hold no issuer secret. It would
require an online anonymous verification service, threshold evaluation, or a
different reviewed publicly verifiable construction; the first option adds a
hard data-plane dependency and correlation surface. Prototype only behind the
same opaque token interface, not as the preferred production gateway profile.

### Privacy Pass-like OnionRoute architecture

Adopt the architecture even if the gateway transport is not HTTP:

1. gateway/directory defines a low-cardinality `TokenChallenge` with token type,
   issuer cohort, role and policy epoch;
2. client authenticates to Attester and requests a fixed batch for that cohort;
3. Attester issues one-use issuance authorizations, unlinkable at the Issuer;
4. client blinds randomized token inputs and sends them to the separate Issuer;
5. client finalizes/unblinds, caches and later redeems one credential;
6. gateway publicly verifies and atomically spends/reserves its random
   authenticator/nullifier until expiry.

Challenges must not contain a gateway-unique or account-selected redemption
context when the resulting anonymity set would be small. Issuer key consistency
and directory views need gossip/auditing so a malicious issuer cannot give one
client a unique key.

### General anonymous credentials

Selective-disclosure/multi-show systems (for example reviewed BBS+/Idemix-like
libraries) could prove attributes such as plan membership and device quota
without revealing identity. They also add presentation-linkability choices,
revocation accumulators, more complex issuance proofs and a much larger audit
surface. They are useful only if OnionRoute later needs several independently
selectable attributes; the MVP's tiny fixed policy set does not justify them.

Do not encode unique bandwidth, expiry, country or device counters as hidden
attributes and assume fingerprinting is solved: disclosed predicates and rare
combinations still partition the anonymity set.

## Staged migration

### Stage 0 — implemented experimental MVP

Signed Ed25519 role-scoped PoP token, fixed buckets, account-free issuer
interface and opaque gateway bytes. This establishes policy/replay/key
boundaries but not cryptographic issuer-redemption unlinkability.

### Stage 1 — protocol abstraction and conformance harness

- Keep gateway transport token bytes opaque and versioned.
- Add `BlindTokenClient`, blinded issuer request/response and RFC test-vector
  harness behind new interfaces; do not change v1 semantics in place.
- Run both implementations in test/shadow issuance without accepting shadow
  tokens for production authorization.
- Complete third-party cryptographic review and dependency/supply-chain review.

### Stage 2 — split Attester and Issuer

- Separate IAM, deployment, logs and network routes.
- Attester maps account entitlement to one of a fixed set of issuance cohorts
  and fixed batch quotas.
- Issuer validates only anonymous issuance authorization and blinded requests.
- Add delay/jitter and client cache refill thresholds; prohibit shared request
  IDs or precise timestamps across services.

### Stage 3 — public Blind RSA dual stack

- Publish reviewed token type and issuer keys before activation.
- Clients request blind tokens but retain MVP tokens during a bounded rollout.
- Gateways accept explicit v1 and blind-token versions with separate metrics,
  never downgrade an invalid new token to the old parser.
- Compare replay, expiry, cohort size and failure behavior; no raw-token joins.

### Stage 4 — retire directly signed issuance

- Stop issuing MVP tokens, wait maximum TTL plus cleanup margin, then remove
  acceptance and online Ed25519 keys.
- Retain only aggregate rollout evidence and audited key-ceremony records.
- Consider VOPRF or general anonymous credentials only for a concrete need and
  after a new ADR/security review.

## Required review gates

- RFC 9578/9474/9497 test vectors pass using the selected maintained library.
- One-more forgery, concurrency, malicious-client and malformed-input testing.
- Issuer-key consistency and downgrade/partitioning analysis.
- Batch quota cannot be inflated by retries/races but also cannot become a
  stable device nullifier at redemption.
- Blind issuance retains role, plan/region cohort and expiry-bucket semantics
  without adding high-cardinality metadata.
- Independent privacy analysis covers collusion among Attester, Issuer,
  gateway, replay store and billing.

## Primary references

- RFC 9576, Privacy Pass Architecture: https://www.rfc-editor.org/rfc/rfc9576.html
- RFC 9577, Privacy Pass HTTP Authentication Scheme: https://www.rfc-editor.org/rfc/rfc9577.html
- RFC 9578, Privacy Pass Issuance Protocols: https://www.rfc-editor.org/rfc/rfc9578.html
- RFC 9474, RSA Blind Signatures: https://www.rfc-editor.org/rfc/rfc9474.html
- RFC 9497, OPRF/VOPRF/POPRF: https://www.rfc-editor.org/rfc/rfc9497.html
