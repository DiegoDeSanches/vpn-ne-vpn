# ADR-0017: GitHub Releases for binary artifacts

- Status: Accepted
- Date: 2026-07-17
- Owners: `infra/platform`, `security/threat-model`, `qa/integration`

## Context

Installers, gateway bundles, SBOMs, provenance, and image manifests are generated
outputs. Committing them to Git makes review and cloning expensive, leaves stale
binaries adjacent to source, and encourages consumers to use artifacts that are not
bound to a reviewed version tag. A mutable download location would also weaken the
supply-chain guarantees required by release gates G-08, G-09, and G-15.

## Decision

GitHub Releases is the distribution channel for binary release artifacts. Production
repositories must enable immutable releases. Each release:

1. is bound to a pre-existing signed immutable SemVer tag;
2. is created as a draft and populated before publication;
3. includes versioned packaged payloads, detached signatures, SBOM, provenance,
   manifests, `SHA256SUMS`, and its KMS-backed cosign signature;
4. is published only after the downloaded draft exactly matches the local qualified
   asset set;
5. is verified using both OnionRoute signatures/digests and the GitHub immutable
   release attestation.

GitHub is not the cryptographic trust root. A GitHub credential cannot replace the
release-signing key, and raw private keys are never GitHub secrets or release assets.
The automatically generated GitHub source archives are not deployable OnionRoute
artifacts.

Local `artifacts/` directories remain ignored ephemeral staging. Published assets are
never committed to Git or stored with Git LFS. A bad published release is superseded
by a new version; tags and assets are never overwritten.

## Consequences

- Clones contain source and contracts, not release binaries.
- Operators get stable versioned download URLs and GitHub attestations.
- Publication requires GitHub CLI access plus the independent signing/verification
  path.
- Repository administrators must enable immutable releases before production use.
- CI automation remains gated by CP-0009; the reviewed manual publisher is the
  current adapter and does not change protected CI configuration.

## Alternatives rejected

- **Commit binaries to Git:** poor reviewability, repository growth, and no immutable
  release envelope.
- **Git LFS:** moves storage but does not provide the required draft/release lifecycle
  or immutable release attestation.
- **Unsigned GitHub assets:** makes repository compromise sufficient to replace the
  distribution trust root.
