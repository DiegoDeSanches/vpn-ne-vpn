#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: build-bundle.sh <40-hex revision> <run-id> <output.tgz> <signing-key>" >&2
  exit 64
fi

revision="$1"
run_id="$2"
output="$3"
signing_key="$4"
if [[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
  echo "revision must be a full lowercase Git commit SHA" >&2
  exit 64
fi
if [[ ! "$run_id" =~ ^[1-9][0-9]{0,17}$ ]]; then
  echo "run id must be a positive decimal with at most 18 digits" >&2
  exit 64
fi

image="onionroute/control-plane:$revision"
docker image inspect "$image" >/dev/null
image_revision="$(docker image inspect \
  --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
  "$image")"
if [[ "$image_revision" != "$revision" ]]; then
  echo "image revision label does not match the requested revision" >&2
  exit 65
fi
if [[ ! -f "$signing_key" ]]; then
  echo "bundle signing key is not a regular file" >&2
  exit 66
fi

bundle_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "$bundle_dir"
}
trap cleanup EXIT

docker save --output "$bundle_dir/control-plane-image.tar" "$image"
install -m 0444 infrastructure/staging/compose.yaml "$bundle_dir/compose.yaml"
install -m 0444 infrastructure/staging/migrate.sh "$bundle_dir/migrate.sh"
install -m 0444 infrastructure/staging/database-roles.sql \
  "$bundle_dir/database-roles.sql"
install -m 0444 services/migrations/0001_control_plane.sql \
  "$bundle_dir/0001_control_plane.sql"
printf '%s\n' "$revision" > "$bundle_dir/revision"
printf '%s\n' "$run_id" > "$bundle_dir/run-id"
chmod 0444 "$bundle_dir/revision"
chmod 0444 "$bundle_dir/run-id"

(
  cd "$bundle_dir"
  sha256sum \
    revision \
    run-id \
    compose.yaml \
    migrate.sh \
    0001_control_plane.sql \
    database-roles.sql \
    control-plane-image.tar > manifest.sha256
  ssh-keygen -Y sign \
    -f "$signing_key" \
    -n onionroute-staging \
    manifest.sha256 >/dev/null
)

tar \
  --sort=name \
  --mtime='UTC 1970-01-01' \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -C "$bundle_dir" \
  -czf "$output" \
  revision \
  run-id \
  manifest.sha256 \
  manifest.sha256.sig \
  compose.yaml \
  migrate.sh \
  0001_control_plane.sql \
  database-roles.sql \
  control-plane-image.tar

sha256sum "$output"
