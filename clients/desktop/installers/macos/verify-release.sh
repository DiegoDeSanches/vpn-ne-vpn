#!/bin/sh
# EXPERIMENTAL: verification only; signing happens in the protected release job.
set -eu
APP_PATH="${1:?path to OnionRoute.app}"
PKG_PATH="${2:?path to signed OnionRoute.pkg}"
codesign --verify --deep --strict --verbose=2 "$APP_PATH"
spctl --assess --type execute --verbose=2 "$APP_PATH"
pkgutil --check-signature "$PKG_PATH"
xcrun stapler validate "$APP_PATH"
xcrun stapler validate "$PKG_PATH"

