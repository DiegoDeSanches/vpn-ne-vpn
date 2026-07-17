# Controlled security update runbook

Security fixes are delivered by replacing signed immutable images. Updating packages
on a running production node is prohibited because it bypasses provenance, image
validation and rollback evidence.

## Scheduled flow

1. The image pipeline opens a change that advances the pinned Debian snapshot and,
   when required, pinned Vault, Cosign or base-image identifiers. Floating mirrors,
   `latest` tags and unverified downloads are rejected.
2. A clean private builder verifies dependency checksums and the signed OnionRoute
   release, builds every affected role, produces CycloneDX SBOM and provenance, and
   signs both the release and Packer manifests with the release KMS identity.
3. Security and platform reviewers record fixed vulnerabilities, accepted residual
   findings and upstream advisories. Critical or actively exploited fixes use the
   emergency window; all others enter the next scheduled window.
4. Deploy one canary for each affected role and provider/admin domain. Observe at
   least the configured canary window and verify Tor bootstrap, onion reachability,
   clock, key expiry, coarse session/error/bandwidth buckets and egress failures.
5. Roll out in bounded waves. Drain every gateway through the signed directory before
   replacement and retain the previous signed image and compatible schema until the
   rollback window closes.
6. Close the change only after automatic rollback and emergency revocation drills
   succeed in staging and the production fleet inventory reports one expected image
   digest per wave.

## Emergency fix

- Freeze unrelated directory, signing and schema changes.
- If exposure is confirmed, revoke and isolate affected identities first; do not wait
  for an image build.
- Build from the newest reviewed snapshot using the same signature, SBOM, provenance,
  canary and health gates. Two-person approval remains required.
- If no verified image can be produced safely, reduce capacity or fail closed. Do not
  enable public SSH, direct clearnet fallback or live package mutation.

## Rollback and evidence

Rollback uses `rollback.md` and the last verified image manifest. Administrative
evidence contains change ID, advisory IDs, artifact digests, operator identities,
timestamps and coarse health outcomes only. It must never contain client addresses,
destinations, session identifiers or traffic content.

