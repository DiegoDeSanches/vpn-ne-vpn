#!/bin/sh
set -eu

prototype_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
compose_file="$prototype_dir/compose.yaml"
proof_file="$prototype_dir/route-proof.json"

cleanup() {
  if [ "${KEEP_RUNNING:-0}" != "1" ]; then
    docker compose -f "$compose_file" down --volumes --remove-orphans >/dev/null
  fi
}
trap cleanup EXIT INT TERM

docker compose -f "$compose_file" down --volumes --remove-orphans >/dev/null
docker compose -f "$compose_file" build
docker compose -f "$compose_file" up -d gateway controlled-origin onion-service client-tor
proof=$(docker compose -f "$compose_file" run --rm probe)
printf '%s\n' "$proof" | python3 "$prototype_dir/validate_proof.py" > "$proof_file"
cat "$proof_file"

