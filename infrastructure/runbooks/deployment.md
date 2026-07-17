# Deployment runbook

## Preconditions

1. Download the exact immutable GitHub Release into a fresh directory under
   `/secure/releases/onionroute/<tag>`. Verify the GitHub release attestation,
   the signed `SHA256SUMS`, every checksum, and the detached payload signature.
   Never deploy directly from a developer build directory.
2. Two operators verify release source revision, SBOM, provenance, vulnerability
   exceptions and the signed release/Packer manifests. Image ID and digest must match
   `deployment.json` exactly.
3. Confirm entry/exit provider, ASN, project, KMS, Vault and management domains remain
   distinct. Run `tofu validate` and review a saved plan.
4. Confirm directory, lifecycle, health, Vault-revoke and cloud-isolate v1 adapters are healthy
   over authenticated management paths. No public SSH session is part of deployment.
5. For a control service, run the migration adapter. It may only perform an
   expand-only, backward-compatible migration while old binaries exist.
6. Check capacity: losing the canary plus one additional node must not exhaust the
   role. Freeze unrelated directory and signing changes.

The download and verification commands are documented in
[`docs/releases.md`](../../docs/releases.md). The local files named by
`deployment.json` are a verified cache of GitHub Release assets, not files tracked
in Git.

## Execute

```text
python3 infrastructure/deploy/onionroute_deploy.py \
  --config /secure/change/exit-2026-07-17.json deploy
```

The controller verifies supply-chain evidence, drains the canary, waits for session
bucket 0, replaces it, verifies Tor bootstrap/onion reachability/key expiry/clock and
coarse failure thresholds, then observes it for the configured window. Remaining
nodes drain before the rollout apply. The directory adapter owns monotonic signed
publication; the controller never edits directory bytes.

## Success checks

- New image ID and release digest match provider inventory.
- `up`, readiness, Tor bootstrap and onion availability are healthy for two scrape
  intervals; error/bandwidth/session metrics remain coarse.
- No public socket, IPv6 packet, unexpected UDP, metadata access or private egress is
  observed in provider flow policy tests.
- Administrative audit contains change ID, operator identity, adapter actions and
  image digest only; it contains no traffic metadata.

If any gate fails, stop manual intervention until automatic rollback completes, then
follow `rollback.md`.
