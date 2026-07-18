#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: test_bundle.sh <40-hex image revision>" >&2
  exit 64
fi

revision="$1"
run_id=123456789
test_root="$(mktemp -d)"
cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N '' \
  -C onionroute-staging-ci-test \
  -f "$test_root/signing-key"

bash infrastructure/staging/build-bundle.sh \
  "$revision" \
  "$run_id" \
  "$test_root/deployment.tgz" \
  "$test_root/signing-key" >/dev/null

expected_members="$(
  printf '%s\n' \
    0001_control_plane.sql \
    compose.yaml \
    control-plane-image.tar \
    database-roles.sql \
    manifest.sha256 \
    manifest.sha256.sig \
    migrate.sh \
    revision \
    run-id |
    LC_ALL=C sort
)"
actual_members="$(tar -tzf "$test_root/deployment.tgz" | LC_ALL=C sort)"
if [[ "$actual_members" != "$expected_members" ]]; then
  echo "bundle member contract mismatch" >&2
  exit 70
fi

extract_root="$test_root/extracted"
mkdir "$extract_root"
tar -xzf "$test_root/deployment.tgz" -C "$extract_root"
printf 'onionroute-staging-ci %s\n' "$(cat "$test_root/signing-key.pub")" \
  > "$test_root/allowed-signers"

ssh-keygen -Y verify \
  -f "$test_root/allowed-signers" \
  -I onionroute-staging-ci \
  -n onionroute-staging \
  -s "$extract_root/manifest.sha256.sig" \
  < "$extract_root/manifest.sha256" >/dev/null
(
  cd "$extract_root"
  sha256sum --check manifest.sha256
) >/dev/null

cp "$extract_root/run-id" "$test_root/original-run-id"
chmod 0644 "$extract_root/run-id"
printf '%s\n' "$((run_id + 1))" > "$extract_root/run-id"
if (
  cd "$extract_root"
  sha256sum --check manifest.sha256
) >/dev/null 2>&1; then
  echo "tampered workflow run id unexpectedly passed manifest verification" >&2
  exit 70
fi
mv "$test_root/original-run-id" "$extract_root/run-id"

cp "$extract_root/manifest.sha256" "$test_root/tampered-manifest"
printf '# tampered\n' >> "$test_root/tampered-manifest"
if ssh-keygen -Y verify \
  -f "$test_root/allowed-signers" \
  -I onionroute-staging-ci \
  -n onionroute-staging \
  -s "$extract_root/manifest.sha256.sig" \
  < "$test_root/tampered-manifest" >/dev/null 2>&1; then
  echo "tampered bundle manifest unexpectedly passed signature verification" >&2
  exit 70
fi

echo "signed deployment bundle contract passed"
