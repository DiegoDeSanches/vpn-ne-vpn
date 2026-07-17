#!/usr/bin/env bash
set -euo pipefail

# TEST ONLY. Creates only the fixed orqa-* namespace/bridge names below.
BRIDGE=orqa-br0
NAMESPACES=(orqa-client orqa-tor orqa-gateway orqa-fixture)
ADDRESSES=(198.18.0.10/24 198.18.0.20/24 198.18.0.30/24 198.18.0.40/24)

require_root() {
  if [[ ${EUID} -ne 0 ]]; then
    echo "local lab namespace setup requires root" >&2
    exit 2
  fi
}

preflight() {
  for tool in ip tc nft tshark; do
    command -v "${tool}" >/dev/null || { echo "missing required tool: ${tool}" >&2; exit 2; }
  done
}

up() {
  require_root
  preflight
  if ip link show "${BRIDGE}" >/dev/null 2>&1; then
    echo "refusing to reuse existing ${BRIDGE}" >&2
    exit 2
  fi
  for namespace in "${NAMESPACES[@]}"; do
    if ip netns list | awk '{print $1}' | grep -Fxq "${namespace}"; then
      echo "refusing to reuse existing ${namespace}" >&2
      exit 2
    fi
  done
  ip link add "${BRIDGE}" type bridge
  ip link set "${BRIDGE}" up
  for index in "${!NAMESPACES[@]}"; do
    namespace=${NAMESPACES[$index]}
    host_if="orqa-h${index}"
    ns_if="orqa-n${index}"
    ip netns add "${namespace}"
    ip link add "${host_if}" type veth peer name "${ns_if}"
    ip link set "${host_if}" master "${BRIDGE}"
    ip link set "${host_if}" up
    ip link set "${ns_if}" netns "${namespace}"
    ip -n "${namespace}" link set lo up
    ip -n "${namespace}" link set "${ns_if}" name eth0
    ip -n "${namespace}" address add "${ADDRESSES[$index]}" dev eth0
    ip -n "${namespace}" link set eth0 up
  done
  echo "local lab ready; direct reachability is intentionally possible until the product kill switch is applied"
}

down() {
  require_root
  for namespace in "${NAMESPACES[@]}"; do
    if ip netns list | awk '{print $1}' | grep -Fxq "${namespace}"; then
      ip netns delete "${namespace}"
    fi
  done
  if ip link show "${BRIDGE}" >/dev/null 2>&1; then
    ip link delete "${BRIDGE}" type bridge
  fi
  echo "removed only the fixed orqa-* local lab objects"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  preflight) preflight ;;
  *) echo "usage: $0 {preflight|up|down}" >&2; exit 2 ;;
esac
