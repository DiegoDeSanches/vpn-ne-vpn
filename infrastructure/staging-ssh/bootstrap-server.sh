#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ "${EUID}" -ne 0 ]]; then
  echo "run bootstrap-server.sh as root" >&2
  exit 77
fi
if [[ $# -ne 3 ]]; then
  echo "usage: bootstrap-server.sh <deploy-public-key> <bundle-signing-public-key> <controller>" >&2
  exit 64
fi

public_key_file="$1"
signing_public_key_file="$2"
controller_file="$3"
if [[ ! -f "$public_key_file" || ! -f "$signing_public_key_file" || ! -f "$controller_file" ]]; then
  echo "public keys and controller must be regular files" >&2
  exit 66
fi
public_key="$(tr -d '\r\n' < "$public_key_file")"
if [[ ! "$public_key" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]].*)?$ ]]; then
  echo "expected one OpenSSH Ed25519 deploy public key" >&2
  exit 65
fi
signing_public_key="$(tr -d '\r\n' < "$signing_public_key_file")"
if [[ ! "$signing_public_key" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]].*)?$ ]]; then
  echo "expected one OpenSSH Ed25519 bundle-signing public key" >&2
  exit 65
fi
deploy_key_material="$(awk '{print $2}' <<< "$public_key")"
signing_key_material="$(awk '{print $2}' <<< "$signing_public_key")"
if [[ "$deploy_key_material" == "$signing_key_material" ]]; then
  echo "deploy and bundle-signing keys must be distinct" >&2
  exit 65
fi

docker info >/dev/null
docker compose version >/dev/null
command -v flock >/dev/null
command -v openssl >/dev/null
command -v ssh-keygen >/dev/null
command -v sshd >/dev/null

install -m 0755 "$controller_file" /usr/local/sbin/onionroute-staging-deploy
install -d -m 0700 /etc/onionroute-staging/secrets
for secret_name in \
  postgres-superuser-password \
  directory-service-password \
  health-collector-password \
  admin-api-password \
  revocation-service-password; do
  secret_file="/etc/onionroute-staging/secrets/$secret_name"
  if [[ ! -s "$secret_file" ]]; then
    openssl rand -hex 32 > "$secret_file"
  fi
  chown root:10001 "$secret_file"
  chmod 0640 "$secret_file"
done
printf 'onionroute-staging-ci %s\n' "$signing_public_key" \
  > /etc/onionroute-staging/bundle-allowed-signers
chmod 0444 /etc/onionroute-staging/bundle-allowed-signers

install -d -m 0700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 0600 /root/.ssh/authorized_keys

authorized_entry="restrict,command=\"/usr/local/sbin/onionroute-staging-deploy\" $public_key"
authorized_tmp="$(mktemp /root/.ssh/authorized_keys.XXXXXXXX)"
awk '
  $0 == "# BEGIN onionroute-staging-deploy" { managed = 1; next }
  $0 == "# END onionroute-staging-deploy" { managed = 0; next }
  managed { next }
  index($0, "command=\"/usr/local/sbin/onionroute-staging-deploy\"") { next }
  { print }
' /root/.ssh/authorized_keys > "$authorized_tmp"
printf '%s\n%s\n%s\n' \
  '# BEGIN onionroute-staging-deploy' \
  "$authorized_entry" \
  '# END onionroute-staging-deploy' >> "$authorized_tmp"
chmod 0600 "$authorized_tmp"
mv -f -- "$authorized_tmp" /root/.ssh/authorized_keys

sshd -t
ssh-keygen -lf "$public_key_file"
ssh-keygen -lf "$signing_public_key_file"
echo "staging deploy controller installed; root key is restricted to the controller"
