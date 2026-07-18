#!/bin/sh
set -eu

password_file="/run/secrets/postgres-superuser-password"
if [ ! -r "$password_file" ]; then
  echo "database password file is not readable" >&2
  exit 78
fi

export PGHOST=postgres
export PGPORT=5432
export PGDATABASE=onionroute
export PGUSER=onionroute
export PGPASSWORD="$(cat "$password_file")"
export PGCONNECT_TIMEOUT=5

relations="
countries
gateways
gateway_roles
health_samples
signing_keys
directory_versions
revocations
client_version_rules
incidents
feature_flags
directory_gateway_projection
"

existing=0
total=0
for relation in $relations; do
  total=$((total + 1))
  present="$(psql -X -A -t -q -c "SELECT to_regclass('public.$relation') IS NOT NULL")"
  if [ "$present" = "t" ]; then
    existing=$((existing + 1))
  fi
done

if [ "$existing" -eq 0 ]; then
  psql -X -v ON_ERROR_STOP=1 -f /deploy/0001_control_plane.sql
elif [ "$existing" -ne "$total" ]; then
  echo "partial control-plane schema detected; refusing automatic repair" >&2
  exit 70
fi

function_present="$(psql -X -A -t -q -c \
  "SELECT to_regprocedure('public.create_directory_draft(bigint,text)') IS NOT NULL")"
if [ "$function_present" != "t" ]; then
  echo "control-plane schema verification failed" >&2
  exit 70
fi

for secret_name in \
  directory-service-password \
  health-collector-password \
  admin-api-password \
  revocation-service-password; do
  secret_file="/run/secrets/$secret_name"
  if [ ! -r "$secret_file" ] ||
     ! grep -Eq '^[A-Za-z0-9_-]{32,128}$' "$secret_file"; then
    echo "database role secret is missing or invalid" >&2
    exit 78
  fi
done

export OR_DIRECTORY_DB_PASSWORD="$(cat /run/secrets/directory-service-password)"
export OR_HEALTH_DB_PASSWORD="$(cat /run/secrets/health-collector-password)"
export OR_ADMIN_DB_PASSWORD="$(cat /run/secrets/admin-api-password)"
export OR_REVOCATION_DB_PASSWORD="$(cat /run/secrets/revocation-service-password)"
psql -X -v ON_ERROR_STOP=1 -f /deploy/database-roles.sql
unset \
  OR_DIRECTORY_DB_PASSWORD \
  OR_HEALTH_DB_PASSWORD \
  OR_ADMIN_DB_PASSWORD \
  OR_REVOCATION_DB_PASSWORD

unset PGPASSWORD
echo "control-plane schema is ready"
