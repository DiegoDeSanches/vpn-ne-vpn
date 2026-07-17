# OnionRoute iOS prototype

The prototype contains a Swift containing app and `NEPacketTunnelProvider`
extension, shared C ABI wrapper, Keychain access group, App Group state, bounded
packet batches, `NWPathMonitor`, sleep/wake recovery and VPN On Demand.

Generate the Xcode project with XcodeGen:

```text
cd clients/ios
xcodegen generate
```

Build `onionroute-mobile-ffi` as device and simulator static libraries, combine
the supported slices into an XCFramework or place a compatible
`libonionroute_mobile_ffi.a` in `clients/ios/Frameworks`, and update the generated
target linkage. Generated binaries, provisioning profiles, Team IDs and signing
keys are intentionally not committed.

Both targets require the Network Extension (`packet-tunnel-provider`), App Groups
and shared Keychain capabilities in the Apple Developer portal. Replace the
example bundle IDs and App Group with registered values.

## Safety status

The extension installs default IPv4/IPv6 routes and DNS inside the TUN, then
drops packets because CP-0006 is pending. It does not implement a packet filter
or direct proxy fallback. `includeAllNetworks` and `enforceRoutes` are requested
on the provider protocol, but Apple always excludes some system traffic. Per-app
VPN is not presented as a consumer feature; deployment-specific per-app rules
need a separate managed-device product decision.

