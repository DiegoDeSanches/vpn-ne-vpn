#!/bin/sh
set -eu

: "${DEBIAN_SNAPSHOT:?missing Debian snapshot timestamp}"
: "${VAULT_VERSION:?missing Vault version}"
: "${VAULT_SHA256:?missing Vault checksum}"
: "${COSIGN_VERSION:?missing cosign version}"
: "${COSIGN_SHA256:?missing cosign checksum}"
: "${RELEASE_VERSION:?missing release version}"
: "${RELEASE_DIGEST:?missing release digest}"

case "$DEBIAN_SNAPSHOT" in 20????????T??????Z) ;; *) exit 64 ;; esac
case "$VAULT_SHA256$COSIGN_SHA256" in *[!0-9a-fA-F]*) exit 64 ;; esac
case "$RELEASE_VERSION" in ''|*[!0-9A-Za-z._-]*) exit 64 ;; esac
[ "${#VAULT_SHA256}" -eq 64 ] && [ "${#COSIGN_SHA256}" -eq 64 ] || exit 64
[ "${#RELEASE_VERSION}" -le 64 ] || exit 64
case "$RELEASE_DIGEST" in sha256:*) release_hash=${RELEASE_DIGEST#sha256:} ;; *) exit 64 ;; esac
[ "${#release_hash}" -eq 64 ] || exit 64
case "$release_hash" in *[!0-9a-f]*) exit 64 ;; esac
case "$VAULT_VERSION$COSIGN_VERSION" in ''|*[!0-9A-Za-z._-]*) exit 64 ;; esac

export DEBIAN_FRONTEND=noninteractive
snapshot="https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/"
security_snapshot="https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/"
printf '%s\n' \
  "deb [check-valid-until=no] $snapshot bookworm main" \
  "deb [check-valid-until=no] $snapshot bookworm-updates main" \
  "deb [check-valid-until=no] $security_snapshot bookworm-security main" \
  > /etc/apt/sources.list
rm -f /etc/apt/sources.list.d/*.list
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl unzip

vault_zip=/tmp/vault.zip
curl --fail --location --proto '=https' --tlsv1.2 \
  "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip" \
  --output "$vault_zip"
printf '%s  %s\n' "$VAULT_SHA256" "$vault_zip" | sha256sum --check --strict
unzip -p "$vault_zip" vault > /usr/bin/vault
chmod 0755 /usr/bin/vault

cosign_file=/tmp/cosign
curl --fail --location --proto '=https' --tlsv1.2 \
  "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" \
  --output "$cosign_file"
printf '%s  %s\n' "$COSIGN_SHA256" "$cosign_file" | sha256sum --check --strict
install -o root -g root -m 0755 "$cosign_file" /usr/bin/cosign

install -d -o root -g root -m 0755 /usr/share/onionroute/trust /opt/onionroute/releases
install -o root -g root -m 0644 /tmp/release-signing.pub /usr/share/onionroute/trust/release-signing.pub
install -o root -g root -m 0644 /tmp/admin-ssh-ca.pub /usr/share/onionroute/trust/admin-ssh-ca.pub

/usr/bin/cosign verify-blob \
  --key /usr/share/onionroute/trust/release-signing.pub \
  --signature /tmp/onionroute-release.tar.gz.sig \
  /tmp/onionroute-release.tar.gz >/dev/null

archive_listing=/tmp/onionroute-release.list
tar -tvzf /tmp/onionroute-release.tar.gz > "$archive_listing"
if awk 'substr($0,1,1) != "-" && substr($0,1,1) != "d" { found=1 } END { exit(found ? 0 : 1) }' "$archive_listing"; then
  echo "release archive contains a link or non-regular object" >&2
  exit 1
fi
if tar -tzf /tmp/onionroute-release.tar.gz | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
  echo "unsafe release archive path" >&2
  exit 1
fi
release_dir="/opt/onionroute/releases/$RELEASE_VERSION"
install -d -o root -g root -m 0755 "$release_dir"
tar -xzf /tmp/onionroute-release.tar.gz -C "$release_dir" --no-same-owner --no-same-permissions

test "$(tr -d '\r\n' < "$release_dir/release.digest")" = "$RELEASE_DIGEST"
/usr/bin/cosign verify-blob \
  --key /usr/share/onionroute/trust/release-signing.pub \
  --signature "$release_dir/release.manifest.sig" \
  "$release_dir/release.manifest" >/dev/null
(cd "$release_dir" && sha256sum --check --strict release.manifest)
find "$release_dir" -type d -exec chmod 0755 {} \;
find "$release_dir" -type f -exec chmod 0644 {} \;
find "$release_dir/bin" -type f -exec chmod 0755 {} \;
chown -R root:root "$release_dir"
ln -s "$release_dir" /opt/onionroute/current

rm -f "$vault_zip" "$cosign_file" /tmp/onionroute-release.tar.gz /tmp/onionroute-release.tar.gz.sig "$archive_listing"
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/release-signing.pub /tmp/admin-ssh-ca.pub
