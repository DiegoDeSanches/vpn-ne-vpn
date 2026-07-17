# GitHub Releases publishing

GitHub Releases is the only repository-adjacent distribution channel for OnionRoute
installers, archives, SBOMs, provenance, and image manifests. Generated binaries stay
out of Git. The local `artifacts/` directories are temporary staging areas only.

GitHub is a delivery and immutability layer, not the sole trust root. Consumers and
operators must verify the KMS-backed cosign signature over `SHA256SUMS`, the listed
SHA-256 digests, detached payload signatures, and (when release immutability is
enabled) the GitHub release attestation.

## Repository setup

An administrator must enable
[release immutability](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes)
in repository settings before the first production release. A release-specific
signed tag such as `v0.1.0` must already exist on GitHub; the publisher always uses
[`gh release create --verify-tag`](https://cli.github.com/manual/gh_release_create)
and never lets GitHub create a tag implicitly.

Release operators need:

- GitHub CLI (`gh`) authenticated with release write access;
- `cosign` and the reviewed public verification key;
- a completely clean worktree at the tagged commit;
- release notes and a complete asset directory containing `SHA256SUMS`,
  `SHA256SUMS.sig`, and a detached `.sig` for every installer/archive;
- two-person approval and all gates from `docs/security/release-gates.md`.

GitHub permits up to 1,000 assets per release, each smaller than 2 GiB; the publisher
enforces both limits. Secret-like files, symlinks, directories, empty files, unsigned
payloads, stale checksums, and mismatched versions are rejected before any GitHub
mutation.

## Build release assets

The gateway image builder writes signed assets and evidence to the ignored
`infrastructure/images/artifacts/` staging directory. That directory must be empty at
the start so files from an older release cannot be uploaded accidentally.

```sh
COSIGN_KEY_REF=awskms://... \
SOURCE_REVISION=<full-reviewed-commit> \
BUILDER_ID=<immutable-builder-identity> \
infrastructure/images/build-image.sh <release-dir> 0.1.0 <packer-vars>
```

Platform packaging jobs must produce the same minimum envelope: a versioned archive
or installer, its detached signature, signed `SHA256SUMS`, SBOM, and provenance.
Loose runtime directories are not release assets; package and sign them first.

## Stage a draft

The first phase creates a draft and uploads the entire locally verified set. This
follows GitHub's
[recommended immutable-release sequence](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases):
create a draft, attach all assets, then publish.

```sh
python3 scripts/publish_github_release.py stage \
  --tag v0.1.0 \
  --assets infrastructure/images/artifacts \
  --notes-file /secure/releases/v0.1.0-notes.md \
  --verification-key /secure/trust/release-signing.pub \
  --repo OWNER/REPOSITORY
```

Use `--prerelease` for non-production candidates. `--dry-run` validates local inputs
and prints the planned GitHub CLI command without authentication or network writes.

## Verify the draft and publish

After independent review, the second phase compares the exact remote asset names,
downloads the draft into a temporary directory, compares every size and SHA-256
digest with the local set, and only then publishes it.

```sh
python3 scripts/publish_github_release.py publish \
  --tag v0.1.0 \
  --assets infrastructure/images/artifacts \
  --verification-key /secure/trust/release-signing.pub \
  --repo OWNER/REPOSITORY
```

The publisher never uses `gh release upload --clobber`. If an asset is wrong, delete
the draft and repeat qualification. After publication, create a new version; never
replace an asset or move a release tag.

## Verify a published immutable release

```sh
python3 scripts/publish_github_release.py verify \
  --tag v0.1.0 \
  --assets infrastructure/images/artifacts \
  --verification-key /secure/trust/release-signing.pub \
  --repo OWNER/REPOSITORY
```

For deployment, download into a fresh protected directory and repeat verification:

```sh
gh release download v0.1.0 --repo OWNER/REPOSITORY \
  --dir /secure/releases/onionroute/v0.1.0
cd /secure/releases/onionroute/v0.1.0
cosign verify-blob --key /secure/trust/release-signing.pub \
  --signature SHA256SUMS.sig SHA256SUMS
sha256sum --check SHA256SUMS
gh release verify v0.1.0 --repo OWNER/REPOSITORY
```

Source archives generated automatically by GitHub are not substitutes for the signed
OnionRoute release bundles and do not enter deployment manifests.
