#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ios_dir="$(cd "${script_dir}/.." && pwd)"
version="0.4.9.11"
archive="tor-${version}.tar.gz"
expected_sha256="2e6c1720118c812acf0079fd47cf91b6bfaba5d766c321c4d3d2a28d6a11a8ed"
download_root="${ios_dir}/.build/ctor-source"
keyring="${ONIONROUTE_TOR_RELEASE_KEYRING:-}"

for command_name in curl gpgv shasum; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "error: required command is unavailable: ${command_name}" >&2
    exit 2
  fi
done
if [[ -z "${keyring}" || ! -f "${keyring}" ]]; then
  echo "error: ONIONROUTE_TOR_RELEASE_KEYRING must name the reviewed Tor release keyring" >&2
  exit 2
fi

mkdir -p "${download_root}"
base_url="https://dist.torproject.org"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "${download_root}/${archive}" "${base_url}/${archive}"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "${download_root}/${archive}.sha256sum" "${base_url}/${archive}.sha256sum"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "${download_root}/${archive}.sha256sum.asc" "${base_url}/${archive}.sha256sum.asc"

gpgv --keyring "${keyring}" \
  "${download_root}/${archive}.sha256sum.asc" \
  "${download_root}/${archive}.sha256sum"

published_sha256="$(awk -v name="${archive}" '$2 == name { print $1 }' "${download_root}/${archive}.sha256sum")"
if [[ "${published_sha256}" != "${expected_sha256}" ]]; then
  echo "error: signed Tor checksum does not match the reviewed ADR pin" >&2
  exit 2
fi
actual_sha256="$(shasum -a 256 "${download_root}/${archive}" | awk '{print $1}')"
if [[ "${actual_sha256}" != "${expected_sha256}" ]]; then
  echo "error: downloaded Tor archive checksum mismatch" >&2
  exit 2
fi

echo "Verified ${archive} (${actual_sha256})"
