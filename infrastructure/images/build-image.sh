#!/bin/sh
set -eu

usage() {
  echo "usage: $0 RELEASE_DIR VERSION PACKER_VARS" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
release_source=$1
release_version=$2
packer_vars=$3
: "${COSIGN_KEY_REF:?use a KMS-backed cosign key reference}"
: "${SOURCE_REVISION:?set the reviewed source revision}"
: "${BUILDER_ID:?set the immutable builder identity}"

for tool in packer ansible-playbook cosign syft jq sha256sum tar; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 69; }
done
ansible_core_version=$(ansible-playbook --version | sed -n '1s/.*core \([^]]*\).*/\1/p')
[ "$ansible_core_version" = 2.17.12 ] || { echo "Ansible Core 2.17.12 required" >&2; exit 69; }
case "$COSIGN_KEY_REF" in awskms://*|gcpkms://*|hashivault://*) ;; *) echo "KMS-backed cosign key required" >&2; exit 64 ;; esac
case "$release_version" in ''|*[!0-9A-Za-z._-]*) usage ;; esac
[ "${#release_version}" -le 64 ] || usage
case "$SOURCE_REVISION$BUILDER_ID" in *[!0-9A-Za-z._:/@+-]*) exit 64 ;; esac
[ "${#SOURCE_REVISION}" -le 128 ] && [ "${#BUILDER_ID}" -le 256 ] || exit 64
test -d "$release_source"
test -f "$packer_vars"
release_source=$(CDPATH= cd -- "$release_source" && pwd)
packer_vars_dir=$(CDPATH= cd -- "$(dirname -- "$packer_vars")" && pwd)
packer_vars="$packer_vars_dir/$(basename -- "$packer_vars")"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
artifacts="$script_dir/artifacts"
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT INT TERM
mkdir -p "$artifacts"
if find "$artifacts" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  echo "release staging directory must be empty: $artifacts" >&2
  exit 1
fi
cp -a "$release_source/." "$staging/"

if find -P "$staging" ! -type d ! -type f | grep -q .; then
  echo "release input contains a symlink or non-regular object" >&2
  exit 1
fi
if find -P "$staging" -type f -links +1 | grep -q .; then
  echo "release input contains a hard-linked file" >&2
  exit 1
fi
if find "$staging" -type f \( -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name '*.token' \) | grep -q .; then
  echo "release input contains forbidden secret-like files" >&2
  exit 1
fi

syft "dir:$staging" -o cyclonedx-json="$staging/sbom.cdx.json"
jq -n \
  --arg version "$release_version" \
  --arg source_revision "$SOURCE_REVISION" \
  --arg builder "$BUILDER_ID" \
  '{schema:"onionroute-release-provenance-v1",subjectVersion:$version,sourceRevision:$source_revision,builderId:$builder,reproducibility:{inputsPinned:true,bitForBitVerified:false}}' \
  > "$staging/provenance.json"

(cd "$staging" && find . -type f \
  ! -name release.manifest ! -name release.manifest.sig ! -name release.digest \
  -print0 | sort -z | xargs -0 sha256sum > release.manifest)
manifest_digest=$(sha256sum "$staging/release.manifest" | cut -d ' ' -f 1)
printf 'sha256:%s\n' "$manifest_digest" > "$staging/release.digest"
cosign sign-blob --yes --key "$COSIGN_KEY_REF" \
  --output-signature "$staging/release.manifest.sig" \
  "$staging/release.manifest"

bundle="$artifacts/onionroute-$release_version.tar.gz"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -czf "$bundle" -C "$staging" .
bundle_signature="$bundle.sig"
cosign sign-blob --yes --key "$COSIGN_KEY_REF" \
  --output-signature "$bundle_signature" \
  "$bundle"

(
  cd "$script_dir"
  packer init onionroute.pkr.hcl
  packer fmt -check onionroute.pkr.hcl
  packer validate -var-file="$packer_vars" \
    -var "release_version=$release_version" \
    -var "release_digest=sha256:$manifest_digest" \
    -var "release_bundle=$bundle" \
    -var "release_bundle_signature=$bundle_signature" \
    onionroute.pkr.hcl
  packer build -var-file="$packer_vars" \
    -var "release_version=$release_version" \
    -var "release_digest=sha256:$manifest_digest" \
    -var "release_bundle=$bundle" \
    -var "release_bundle_signature=$bundle_signature" \
    onionroute.pkr.hcl
)

packer_manifest="$artifacts/packer-manifest.json"
test -s "$packer_manifest"
cosign sign-blob --yes --key "$COSIGN_KEY_REF" \
  --output-signature "$packer_manifest.sig" \
  "$packer_manifest"

packer_manifest_digest=$(sha256sum "$packer_manifest" | cut -d ' ' -f 1)
image_provenance="$artifacts/image-provenance.json"
jq -n \
  --arg source_revision "$SOURCE_REVISION" \
  --arg builder "$BUILDER_ID" \
  --arg release_digest "sha256:$manifest_digest" \
  --arg manifest_digest "$packer_manifest_digest" \
  --slurpfile manifest "$packer_manifest" \
  '{schema:"onionroute-image-provenance-v1",sourceRevision:$source_revision,builderId:$builder,releaseDigest:$release_digest,packerManifest:{sha256:$manifest_digest},artifacts:[$manifest[0].builds[]|{name:.name,builderType:.builder_type,artifactId:.artifact_id}]}' \
  > "$image_provenance"
cosign sign-blob --yes --key "$COSIGN_KEY_REF" \
  --output-signature "$image_provenance.sig" \
  "$image_provenance"

cp "$staging/sbom.cdx.json" "$artifacts/onionroute-$release_version.sbom.cdx.json"
cp "$staging/provenance.json" "$artifacts/onionroute-$release_version.provenance.json"
cp "$staging/release.manifest" "$artifacts/onionroute-$release_version.release.manifest"
cp "$staging/release.manifest.sig" "$artifacts/onionroute-$release_version.release.manifest.sig"
cp "$staging/release.digest" "$artifacts/onionroute-$release_version.release.digest"

checksums="$artifacts/SHA256SUMS"
(
  cd "$artifacts"
  for asset in *; do
    case "$asset" in SHA256SUMS|SHA256SUMS.sig) continue ;; esac
    test -f "$asset"
    sha256sum "$asset"
  done
) > "$checksums"
cosign sign-blob --yes --key "$COSIGN_KEY_REF" \
  --output-signature "$checksums.sig" \
  "$checksums"
printf 'release_digest=sha256:%s\n' "$manifest_digest"
printf 'release_assets=%s\n' "$artifacts"
