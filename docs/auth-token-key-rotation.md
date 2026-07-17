# Capability-token key rotation plan

## Key hierarchy

1. **Offline manifest root**: kept offline with dual control; signs issuer-key
   manifests and emergency root transitions. It never signs tokens.
2. **Online token issuer keys**: non-exportable Ed25519 keys in HSM/KMS; sign
   only bounded canonical token claims through `TokenIssuer`.
3. **Gateway material**: public issuer keys, offline-root public key and a
   locally verified revocation snapshot. Gateways hold no signing secret.
4. **Client PoP keys**: ephemeral per credential and deleted after token expiry.

A compromised gateway therefore cannot derive either the online token signing
key or offline root and cannot mint credentials for another gateway.

## Normal rotation

- Generate the next online key in HSM/KMS at least two hours before use.
- Key ID is a common, non-user-specific value such as `token-2026-07-18-a`.
- Publish a monotonically sequenced, offline-root-signed manifest containing
  public key, algorithm/profile, `not_before` and `not_after`.
- Gateways verify the manifest exact bytes, signature, sequence monotonicity,
  bounds and overlap before atomically replacing local material.
- Begin issuance only after propagation telemetry reaches the deployment
  threshold. Never silently fall back to a previous private key.
- Keep the previous public key through its `not_after` plus maximum token TTL,
  clock skew and session cleanup margin. Delete/disable the old private key
  after no valid token can depend on it.

Suggested initial cadence is one online key per 24 hours, with two concurrently
published verification keys. Token validity must fit entirely inside the
issuer-key window; both issuer and verifier enforce this.

## Revocation distribution

A separately signed snapshot contains sequence, generation time, `valid_until`,
revoked issuer key IDs and exceptional random token IDs. Gateways refresh every
five minutes; snapshots are valid for 60 minutes. A gateway rejects rollback,
invalid signature, oversized lists or a snapshot past `valid_until`, and fails
closed for new sessions when its last good snapshot becomes stale.

Subscription cancellation normally stops issuance and waits at most the
15-minute token TTL. Per-token revocation is for a confirmed credential leak or
device-loss response only; routine insertion would create a correlation store.

## Emergency online-key compromise

1. Stop issuance with the affected key; do not issue unsigned or legacy tokens.
2. Add its key ID to the signed revocation snapshot and push an out-of-band
   refresh signal that contains no account/token identifier.
3. Activate a pre-published standby key only after its manifest is verified.
4. Gateways reject the compromised key as soon as the snapshot is installed;
   exposure before propagation remains bounded by the short token TTL.
5. Preserve HSM and deployment audit evidence in a security-only system that
   has no browsing/destination telemetry.

## Offline-root compromise or loss

Root compromise is a fleet trust incident: freeze new issuer manifests, use a
pre-committed recovery root with an independently distributed threshold
approval, ship a gateway software/config trust update, and require an explicit
operator incident process. Root loss without compromise uses the same guarded
recovery path; it never promotes an online issuer key to root.

## Tests and operational gates

- Manifest exact-byte signature, overlap, expiry, rollback and unknown
  algorithm tests.
- Issuer refuses a token window outside key validity.
- Gateway accepts old/new keys during overlap and rejects them after limits.
- Revoked key and stale snapshot fail closed.
- Compromise drill verifies gateway images contain public material only.
- HSM policy permits sign operations for the domain/profile but not key export.

The signed manifest/snapshot loader is an infrastructure dependency and is not
implemented by the in-memory MVP adapters in this iteration.
