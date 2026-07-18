#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ios_dir="$(cd "${script_dir}/.." && pwd)"
derived_data="${ios_dir}/DerivedData"
project="${ios_dir}/OnionRouteMobile.xcodeproj"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: iOS build requires macOS and Xcode" >&2
  exit 2
fi
for command_name in python3 xcodegen xcodebuild; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "error: required command is unavailable: ${command_name}" >&2
    exit 2
  fi
done

python3 "${script_dir}/validate_project.py"
bash "${script_dir}/build-rust-xcframework.sh"
(
  cd "${ios_dir}"
  xcodegen generate
)

xcodebuild \
  -project "${project}" \
  -scheme OnionRouteApp \
  -configuration Debug \
  -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath "${derived_data}" \
  CODE_SIGNING_ALLOWED=NO \
  build-for-testing

if [[ -n "${IOS_SIMULATOR_DESTINATION:-}" ]]; then
  xcodebuild \
    -project "${project}" \
    -scheme OnionRouteApp \
    -configuration Debug \
    -destination "${IOS_SIMULATOR_DESTINATION}" \
    -derivedDataPath "${derived_data}" \
    CODE_SIGNING_ALLOWED=NO \
    test-without-building
else
  echo "Build-for-testing passed. Set IOS_SIMULATOR_DESTINATION to run tests, for example:"
  echo "  IOS_SIMULATOR_DESTINATION='platform=iOS Simulator,name=iPhone 16 Pro' bash scripts/build-and-test.sh"
fi
