# Threat model: account-separated capability tokens

## Scope and security claims

In scope: entitlement lookup, device-slot authorization, credential issuance,
local gateway verification, revocation material and replay/session state.
Payment processing itself, account login protocol, endpoint malware and Tor's
global traffic-analysis limits are outside this component.

Claim: the gateway token schema and verification dependencies provide no
account/payment/order/e-mail/name/persistent-device identifier and no lookup
route to recover one. This is not a claim that timing or traffic analysis can
never correlate a person and session.

## Assets

- account and billing identity;
- online issuer signing keys and offline manifest root;
- client ephemeral PoP private keys;
- entitlement/device-slot integrity;
- replay-store linearizability and availability;
- unlinkability between issuance and redemption events;
- bounded authorization during failures.

## Trust boundaries

| Boundary | May know | Must not receive |
|---|---|---|
| Account middleware / billing adapter | account, private payment mapping, entitlement | browsing destination/content |
| Device slot manager | account and control-only installation reference | token ID, gateway/session/destination |
| Token issuer | canonical policy, bucket, ephemeral PoP public key | account, payment/order ID, installation ID |
| Gateway verifier | signed token, public keys, role/region, PoP proof | account, billing, e-mail/name, persistent device ID |
| Replay store | random token/session keys, expiry, session limit | account/installation/payment, traffic destination |
| Telemetry | coarse aggregate outcome/profile | raw values from any row above |

## Adversaries and mitigations

### Compromised gateway

It observes presented credentials, local connection metadata and traffic that
its route role can see. It cannot mint tokens because it holds only public
issuer keys. Tokens are role-specific, so the same ID is not intentionally
shown at entry and exit. Raw token logging is forbidden. Residual: colluding
gateways can still use traffic timing/volume and a reused client credential.

### Stolen credential

Token theft alone fails mandatory PoP. Theft of token plus ephemeral private
key permits use only until a 15-minute signed expiry and the canonical active
session cap. The challenge and gateway binding prevent replaying one captured
proof at a different gateway. Residual: endpoint compromise can sign fresh
proofs while the key remains available.

### Malicious client / replay race

Signature and canonical policy prevent self-upgrade. A linearizable fleet-wide
reservation enforces exact replay and active-session count. Store uncertainty
fails closed. Residual: per-flow bandwidth/rate enforcement is gateway-local;
distributed byte accounting is intentionally not an identity-bearing ledger.

### Compromised online issuer

It can mint arbitrary valid tokens within its key window. Key manifests limit
the accepted window; emergency key revocation and short token TTL bound
exposure. It cannot alter the offline root. HSM/KMS blocks key export.

### Compromised billing/control service

It can grant entitlements, deny issuance and correlate the authenticated
request with the returned MVP token in memory/timing. The typed issuer boundary
and no-log rules reduce accidental joins but do not provide cryptographic
unlinkability against this adversary. Blind issuance with separated Attester
and Issuer is required to improve this claim.

### Replay-store compromise

It can deny service, over-admit sessions, or observe random token reuse. It has
no account database access and no destination fields. At-rest encryption,
least-privilege network policy and short TTL limit evidence. Bloom-filter false
positive behavior is never used as authorization truth.

### Control-plane outage

No new token is issued when entitlement cannot be checked. Gateways locally
accept already signed tokens only while time, key and cached revocation checks
pass. Stale revocation data and replay-store failure reject new sessions.
There is no clearnet or unsigned fallback.

### Fingerprinting and enumeration

Arbitrary limits, country lists and expiry timestamps could isolate a user.
Only three plan/limit profiles, four region sets, three role scopes and fixed
expiry buckets are accepted. Errors are closed/coarse and no raw key becomes a
metric label. Residual: a rare plan/region/role cohort can still be small;
operations must measure cohort size only through privacy-reviewed aggregates.

### Issuance/redemption timing correlation

Batch caching, common expiry buckets, independent per-hop tokens and redemption
through the protected path reduce timing precision. Residual is material in the
MVP because issuance is not blind; clients should avoid redeeming the first
token immediately when a cached alternative exists.

## Abuse and denial of service

- All wire inputs are capped at 4 KiB and decoded before allocation growth.
- PoP and signature checks happen before replay-store mutation.
- Batch size is capped at eight and account entitlement is checked before work.
- Production services require request concurrency/rate bounds and backpressure.
- Invalid token storms must not trigger account/control lookups.

## Verification evidence

- Cross-crate integration test builds a verifier with no account/billing
  dependency and checks an identifying account string is absent from token
  bytes.
- Unit/integration tests cover tampering, expiry, wrong role/region, missing or
  misbound PoP, exact replay, session cap/release and stale revocations.
- Decoder fuzz target accepts arbitrary bytes without authorization or panic.
- Pending before production: independent crypto/protocol review, distributed
  store fault-injection, signed-manifest implementation and privacy log audit.
