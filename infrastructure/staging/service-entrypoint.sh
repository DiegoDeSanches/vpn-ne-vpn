#!/bin/sh
set -eu

service_name="${1:?service binary is required}"
shift

case "$service_name" in
  onionroute-directory-service)
    database_user=onionroute_directory
    ;;
  onionroute-health-collector)
    database_user=onionroute_health
    ;;
  onionroute-admin-api)
    database_user=onionroute_admin
    ;;
  onionroute-revocation-service)
    database_user=onionroute_revocation
    ;;
  *)
    echo "unsupported staging service" >&2
    exit 64
    ;;
esac

password_file="${OR_DATABASE_PASSWORD_FILE:?database password file is required}"
if [ ! -r "$password_file" ]; then
  echo "database password file is not readable" >&2
  exit 78
fi

database_password="$(cat "$password_file")"
if ! printf '%s' "$database_password" | grep -Eq '^[A-Za-z0-9_-]{32,128}$'; then
  echo "database password must be 32-128 base64url-safe characters" >&2
  exit 78
fi

database_url_prefix="postgresql://${database_user}"
export OR_DATABASE_URL="${database_url_prefix}:${database_password}@127.0.0.1:55432/onionroute"
unset database_password
unset database_url_prefix
unset database_user

if [ "$service_name" = "onionroute-directory-service" ]; then
  hostname_file="${OR_CLIENT_ONION_HOSTNAME_FILE:-/var/lib/tor-directory/hidden_service/hostname}"
  attempts=0
  while [ ! -s "$hostname_file" ]; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 180 ]; then
      echo "Tor v3 onion hostname was not created in time" >&2
      exit 75
    fi
    sleep 1
  done
  onion_hostname="$(tr -d '\r\n' < "$hostname_file")"
  if ! printf '%s' "$onion_hostname" | grep -Eq '^[a-z2-7]{56}\.onion$'; then
    echo "invalid Tor v3 onion hostname" >&2
    exit 78
  fi
  export OR_CLIENT_ONION_HOSTNAME="$onion_hostname"
  unset onion_hostname
fi

exec "/usr/local/bin/$service_name" "$@"
