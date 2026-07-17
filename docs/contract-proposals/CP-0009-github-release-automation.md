# CP-0009: GitHub Release automation

- Status: Proposed
- Owners: `infra/platform`, `qa/integration`, `security/threat-model`
- Related decision: ADR-0017

## Problem

ADR-0017 establishes GitHub Releases as the binary distribution channel. The current
adapter is a reviewed manual publisher because root CI configuration is protected and
cannot be changed unilaterally. Repeating publication manually increases operational
load and makes runner identity, permissions, and approval evidence harder to enforce.

## Current contract

Release operators run `scripts/publish_github_release.py` in two phases. The tool
requires a pre-existing tag, signed checksums, exact draft/local asset equality, and a
clean tracked worktree. No root CI workflow publishes release assets.

## Proposed change

After architecture and security approval, add a protected GitHub Actions release
workflow that:

1. runs only for an approved release-specific SemVer tag or explicit protected
   environment dispatch;
2. uses least-privilege `contents: write` only in the publication job;
3. uses GitHub OIDC/workload identity for KMS access and never stores a raw signing
   key in GitHub;
4. creates a draft, uploads the complete signed asset set, and stops for independent
   environment approval;
5. re-downloads and compares every draft asset before publication;
6. verifies the immutable release attestation after publication;
7. retains only allow-listed digests, approvals, and non-sensitive build evidence.

## Affected teams

- `infra/platform`: workflow, runner identity, KMS and release environment.
- `qa/integration`: qualification evidence and release gate status.
- `security/threat-model`: permissions, OIDC subject policy, provenance and review.
- `client/desktop`, `client/mobile`, `gateway/egress`: platform packaging adapters.

## Compatibility

There is no runtime, protocol, directory, token, or data-plane contract change. The
manual publisher remains supported until the protected workflow is accepted and has
passed a release rehearsal.

## Migration

1. Enable immutable releases and protected release environments.
2. Implement the workflow in a dedicated review branch.
3. Exercise a prerelease with staging-only identities.
4. Compare workflow output with the manual publisher.
5. Require two-person approval, then make automation the primary path.
6. Keep the manual tool as a break-glass adapter with the same checks.

## Risks

- Over-broad `GITHUB_TOKEN` permissions could permit unrelated repository mutation.
- A self-hosted runner could persist release material or credentials.
- Tag-triggered publication could race qualification evidence.
- Publishing before all assets arrive conflicts with immutable releases.
- Logs or provenance could accidentally contain secrets or privacy-sensitive data.

## Tests

- Permission test proves non-publication jobs have read-only repository access.
- Fork and untrusted-branch events cannot reach the release environment.
- Missing tag, signature, SBOM, provenance, approval, or asset blocks publication.
- Asset mutation between draft and publish blocks the workflow.
- OIDC subject/audience mismatch cannot reach KMS.
- Published prerelease passes `gh release verify` and `gh release verify-asset`.
- Secret and privacy scanners cover source, build directory, image, and release assets.
