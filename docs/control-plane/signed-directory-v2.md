# Experimental signed directory v2 reference format

This document specifies the reference implementation proposed in CP-0006. It is
not an accepted replacement for protected protobuf v1 until CP-0006 is approved.

## Encoding and bounds

- Envelope: UTF-8 JSON, maximum 2 MiB, unknown fields rejected.
- Payload: exact RFC 8785 JSON Canonicalization Scheme bytes, encoded as unpadded
  base64url in the envelope.
- Signature: Ed25519 only, unpadded base64url.
- Directory signature input:
  `ASCII("onionroute-directory-v2") || 0x00 || exact_payload_bytes`.
- Root trust signature input:
  `ASCII("onionroute-directory-trust-v1") || 0x00 || JCS(trust_bundle)`.
- Gateways: at most 4,096. Every repeated collection has a hard verifier limit.
- Onion addresses must be canonical Tor v3 hostnames with a valid version byte and
  SHA3-256 `.onion checksum`, not merely 56 base32 characters.
- Directory validity: at most 6 hours. Recommended production validity is 60–90
  minutes with publication every 15–30 minutes.
- Root trust bundle validity: at most 90 days; intermediate keys should be shorter.

The verifier checks signatures before interpreting trusted payload semantics and
rejects a valid signature over non-canonical payload bytes.

## Envelope

```json
{
  "envelope_version": 1,
  "signing_key_id": "online-2026-07-a",
  "trust_bundle": {
    "bundle": {
      "format_version": 1,
      "bundle_version": 18,
      "root_key_id": "root-2026-a",
      "issued_at": 1784217600,
      "expires_at": 1791993600,
      "signing_keys": [],
      "revoked_signing_key_ids": []
    },
    "signature": "base64url-ed25519"
  },
  "payload": "base64url-exact-jcs-document",
  "signature": "base64url-ed25519"
}
```

`SigningKeyCertificate` contains only `key_id`, `algorithm`, `public_key`,
`valid_from`, and `valid_until`. Private keys, Vault paths, cloud accounts, and
operator identity never enter the bundle.

## Signed payload

`DirectoryDocument` contains:

- `format_version = "2.0"`;
- monotonic `version`;
- `issued_at`, `expires_at`;
- `gateways` using the exact allowlist in CP-0006 and the admin OpenAPI schema;
- `countries`;
- active `revocations`;
- `client_version_rules`;
- non-personalized `feature_flags`.

Country, role, state, platform, channel, bucket, capability, and reason values use
closed or bounded registries. No response is bucketed by account, installation,
device, user IP, or persistent anonymous ID.

## Client verification order

1. Enforce envelope byte limit and reject unknown fields.
2. Require known envelope/trust versions and Ed25519.
3. Select `root_key_id` from the app's pinned root set.
4. Verify the root signature over canonical trust-bundle bytes.
5. Enforce trust-bundle time and monotonic version; reject revoked keys.
6. Locate the named intermediate and validate its algorithm/time/public key.
7. Decode bounded payload and verify the intermediate signature over exact bytes.
8. Decode and re-canonicalize; reject non-canonical bytes.
9. Enforce document time, semantic bounds, uniqueness, and all descriptor limits.
10. Reject a lower directory version. For the same version, require the stored
    SHA-256 exact-payload digest to match, preventing equivocation.
11. Atomically persist version, digest, trust-bundle version, and verified cache.
12. Apply active gateway revocations before selection.

Loss/corruption of rollback state is fail-closed and requires an explicit recovery
flow; the client must not silently reset it.

## Rotation and emergency response

Normal rotation overlaps two root-authorized intermediates. The publisher moves to
the new key only after clients have received a bundle containing it. Emergency
rotation uses a higher root-signed bundle version listing the old key in
`revoked_signing_key_ids` and authorizing the replacement. A compromised online
key cannot create that bundle.

Root rotation requires either a release containing a new pin or an independently
reviewed dual-signature transition design. A single old-root signature is not
sufficient after confirmed root compromise. Pin reset on network input is forbidden.
