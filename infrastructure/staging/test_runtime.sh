#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: test_runtime.sh <40-hex image revision>" >&2
  exit 64
fi

revision="$1"
image_tag="onionroute/control-plane:$revision"
docker image inspect "$image_tag" >/dev/null
image_id="$(docker image inspect --format '{{.Id}}' "$image_tag")"
if [[ ! "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "test image does not have an immutable local image id" >&2
  exit 65
fi

test_root="$(mktemp -d)"
project="onionroute-smoke-${RANDOM}-$$"
cleanup() {
  exit_status=$?
  if [[ "$exit_status" -ne 0 ]]; then
    tor_container="$(docker compose \
      --project-name "$project" \
      --file infrastructure/staging/compose.yaml \
      ps --quiet tor-directory 2>/dev/null || true)"
    if [[ -n "$tor_container" ]]; then
      docker inspect --format '{{json .State.Health}}' "$tor_container" >&2 || true
    fi
    docker compose \
      --project-name "$project" \
      --file infrastructure/staging/compose.yaml \
      logs --no-color >&2 || true
  fi
  docker compose \
    --project-name "$project" \
    --file infrastructure/staging/compose.yaml \
    down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf -- "$test_root"
}
trap cleanup EXIT

for secret_name in \
  postgres-superuser-password \
  directory-service-password \
  health-collector-password \
  admin-api-password \
  revocation-service-password; do
  openssl rand -hex 32 | tr -d '\r\n' > "$test_root/$secret_name"
  chmod 0600 "$test_root/$secret_name"
done

compose_test_root="$test_root"
compose_source_root="$PWD"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    compose_test_root="$(cygpath -m "$test_root")"
    compose_source_root="$(cygpath -m "$PWD")"
    ;;
esac

export OR_CONTROL_PLANE_IMAGE="$image_id"
export OR_POSTGRES_SUPERUSER_PASSWORD_FILE="$compose_test_root/postgres-superuser-password"
export OR_DIRECTORY_DB_PASSWORD_FILE="$compose_test_root/directory-service-password"
export OR_HEALTH_DB_PASSWORD_FILE="$compose_test_root/health-collector-password"
export OR_ADMIN_DB_PASSWORD_FILE="$compose_test_root/admin-api-password"
export OR_REVOCATION_DB_PASSWORD_FILE="$compose_test_root/revocation-service-password"
export OR_MIGRATION_SQL_FILE="$compose_source_root/services/migrations/0001_control_plane.sql"
# Git Bash otherwise rewrites Linux container paths passed after `docker compose exec`.
export MSYS_NO_PATHCONV=1

compose() {
  docker compose \
    --project-name "$project" \
    --file infrastructure/staging/compose.yaml \
    "$@"
}

compose up -d --wait --wait-timeout 120 postgres
host_password_hash="$(sha256sum "$test_root/postgres-superuser-password" | awk '{print $1}')"
container_password_hash="$(compose exec -T postgres \
  sha256sum /run/secrets/postgres-superuser-password | awk '{print $1}')"
if [[ "$host_password_hash" != "$container_password_hash" ]]; then
  echo "PostgreSQL secret mount differs from the generated test secret" >&2
  exit 70
fi
compose exec -T postgres sh -ec '
  export PGPASSWORD="$(cat /run/secrets/postgres-superuser-password)"
  psql -X -h 127.0.0.1 -U onionroute -d onionroute -v ON_ERROR_STOP=1 \
    -c "SELECT 1" >/dev/null
'
compose --profile migration run --rm migrate
compose up -d --remove-orphans --wait --wait-timeout 300

role_report="$(compose exec -T postgres psql -X -U onionroute -d onionroute -Atc \
  "SELECT rolname || ':' || rolsuper || ':' || rolcreatedb || ':' || rolcreaterole
   FROM pg_roles
   WHERE rolname IN ('onionroute_directory','onionroute_health','onionroute_admin','onionroute_revocation')
   ORDER BY rolname" | tr -d '\r')"
expected_roles="$(printf '%s\n' \
  onionroute_admin:false:false:false \
  onionroute_directory:false:false:false \
  onionroute_health:false:false:false \
  onionroute_revocation:false:false:false)"
if [[ "$role_report" != "$expected_roles" ]]; then
  echo "database roles are missing or over-privileged" >&2
  exit 70
fi

directory_password="$(cat "$test_root/directory-service-password")"
compose exec -T -e "PGPASSWORD=$directory_password" postgres \
  psql -X -h 127.0.0.1 -U onionroute_directory -d onionroute \
  -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM directory_versions" >/dev/null
if compose exec -T -e "PGPASSWORD=$directory_password" postgres \
  psql -X -h 127.0.0.1 -U onionroute_directory -d onionroute \
  -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM gateways" >/dev/null 2>&1; then
  echo "directory service role unexpectedly reads internal gateway rows" >&2
  exit 70
fi
unset directory_password

compose exec -T tor-directory sh -ec '
  onion_hostname="$(tr -d "\r\n" < /var/lib/tor-directory/hidden_service/hostname)"
  printf "%s" "$onion_hostname" | grep -Eq "^[a-z2-7]{56}\\.onion$"
  attempts=0
  while [ "$attempts" -lt 8 ]; do
    status="$(curl \
      --silent \
      --show-error \
      --output /dev/null \
      --write-out "%{http_code}" \
      --socks5-hostname 127.0.0.1:29050 \
      --connect-timeout 15 \
      --max-time 30 \
      "http://${onion_hostname}/" 2>/dev/null || true)"
    if printf "%s" "$status" | grep -Eq "^[1-5][0-9]{2}$"; then
      exit 0
    fi
    attempts=$((attempts + 1))
    sleep 5
  done
  exit 75
'

echo "staging runtime smoke passed with least-privilege roles and Onion reachability"
