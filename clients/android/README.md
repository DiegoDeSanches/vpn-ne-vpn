# OnionRoute Android prototype

The prototype uses Kotlin, a separate-process foreground `VpnService`, full IPv4
and IPv6 routes, JNI, Android Keystore, per-app exclusions, always-on metadata,
network callbacks and a battery-aware bounded reconnect policy. `VpnService` is
only the local packet interception API. No WireGuard, OpenVPN or IPsec transport
is present.

## Native build

Build `onionroute-mobile-ffi` for `aarch64-linux-android` and
`x86_64-linux-android`, then copy each static library to:

```text
app/src/main/rust/arm64-v8a/libonionroute_mobile_ffi.a
app/src/main/rust/x86_64/libonionroute_mobile_ffi.a
```

Open this directory in Android Studio with Gradle 8.13, Android SDK 36, NDK 28
and JDK 17.
The project intentionally has no checked-in generated binaries or signing keys.

## Safety status

This build establishes a full-route TUN and then blocks packets because CP-0006
is not accepted. Do not label it as a working anonymity product. Always-on and
lockdown are user/device-owner settings; the app can declare support but cannot
silently enable them. Per-app exclusions are incompatible with the expectation
that every app has connectivity in lockdown mode, so the UI must warn that
excluded apps can become offline.
