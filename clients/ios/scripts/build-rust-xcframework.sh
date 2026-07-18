#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ios_dir="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${ios_dir}/../.." && pwd)"
manifest="${repo_root}/crates/mobile-ffi/Cargo.toml"
header_dir="${repo_root}/crates/mobile-ffi/include"
build_root="${ios_dir}/.build/rust"
framework_dir="${ios_dir}/Frameworks"
xcframework="${framework_dir}/OnionRouteMobileFFI.xcframework"
cargo_bin="${CARGO:-cargo}"
rust_toolchain="${ONIONROUTE_RUST_TOOLCHAIN:-1.78.0}"
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-17.0}"
export IPHONESIMULATOR_DEPLOYMENT_TARGET="${IPHONESIMULATOR_DEPLOYMENT_TARGET:-17.0}"

for command_name in rustup "${cargo_bin}" xcodebuild lipo; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "error: required command is unavailable: ${command_name}" >&2
    exit 2
  fi
done

rustup toolchain install "${rust_toolchain}" --profile minimal
rustup target add \
  --toolchain "${rust_toolchain}" \
  aarch64-apple-ios \
  aarch64-apple-ios-sim \
  x86_64-apple-ios

for rust_target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
  rustup run "${rust_toolchain}" "${cargo_bin}" build \
    --release \
    --locked \
    --manifest-path "${manifest}" \
    --target-dir "${build_root}" \
    --target "${rust_target}"
done

mkdir -p "${build_root}/simulator-universal/release" "${framework_dir}"
device_library="${build_root}/aarch64-apple-ios/release/libonionroute_mobile_ffi.a"
simulator_arm_library="${build_root}/aarch64-apple-ios-sim/release/libonionroute_mobile_ffi.a"
simulator_intel_library="${build_root}/x86_64-apple-ios/release/libonionroute_mobile_ffi.a"
simulator_library="${build_root}/simulator-universal/release/libonionroute_mobile_ffi.a"

lipo -create \
  "${simulator_arm_library}" \
  "${simulator_intel_library}" \
  -output "${simulator_library}"

case "${xcframework}" in
  "${ios_dir}"/Frameworks/*) rm -rf -- "${xcframework}" ;;
  *) echo "error: refusing to replace unexpected path: ${xcframework}" >&2; exit 2 ;;
esac

xcodebuild -create-xcframework \
  -library "${device_library}" -headers "${header_dir}" \
  -library "${simulator_library}" -headers "${header_dir}" \
  -output "${xcframework}"

echo "Created ${xcframework}"
