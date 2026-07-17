#!/usr/bin/env bash
set -euo pipefail

readonly repository=/workspace
readonly output=/output
readonly manifest="${repository}/clients/desktop/crates/daemon/Cargo.toml"
readonly lockfile="${repository}/clients/desktop/Cargo.lock"
readonly target=x86_64-pc-windows-gnu
readonly binary=onionroute-desktop-daemon.exe
readonly artifact="${CARGO_TARGET_DIR}/${target}/release/${binary}"
readonly staged_output="${output}/.${binary}.container"
readonly staged_checksum="${staged_output}.sha256"

fail() {
    echo "prototype daemon cross-build: $*" >&2
    exit 1
}

[[ -d "${repository}" ]] || fail "repository mount /workspace is missing"
[[ -r "${manifest}" ]] || fail "daemon Cargo.toml is missing or unreadable"
[[ -r "${lockfile}" ]] || fail "desktop Cargo.lock is missing; locked build is required"
[[ -d "${output}" && -w "${output}" ]] || fail "output mount /output is missing or read-only"

rustc --version | grep -Eq '^rustc 1\.78\.' \
    || fail "container must use Rust 1.78.x"
rustup target list --installed | grep -Fxq "${target}" \
    || fail "Rust Windows GNU target is not installed"
command -v x86_64-w64-mingw32-gcc >/dev/null \
    || fail "MinGW-w64 cross-linker is not installed"

cargo build \
    --locked \
    --manifest-path "${manifest}" \
    --package onionroute-desktop-daemon \
    --bin onionroute-desktop-daemon \
    --release \
    --target "${target}"

[[ -s "${artifact}" ]] \
    || fail "Cargo succeeded but ${binary} was not produced"

# Copy to a stable staging name. The Windows host performs the final rename;
# replacing a pre-existing bind-mounted file from inside Docker Desktop can
# otherwise expose stale host-side contents on some filesystem backends.
rm -f "${staged_output}"
rm -f "${staged_checksum}"
cp "${artifact}" "${staged_output}"
chmod 0755 "${staged_output}"
sha256sum "${staged_output}" | cut -d ' ' -f 1 > "${staged_checksum}"
sync "${staged_output}" "${staged_checksum}"

[[ -s "${staged_output}" ]] || fail "copied daemon staging artifact is empty"
[[ -s "${staged_checksum}" ]] || fail "copied daemon staging checksum is empty"
sha256sum "${staged_output}"
