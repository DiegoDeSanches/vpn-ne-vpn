# OnionRoute iOS client

The client contains a Swift containing app and `NEPacketTunnelProvider`
extension, shared C ABI wrapper, Keychain access group, App Group state, bounded
packet batches, `NWPathMonitor`, sleep/wake recovery and VPN On Demand.

On a macOS build host with Xcode, XcodeGen and Rust installed, run:

```text
cd clients/ios
bash scripts/build-and-test.sh
```

The script builds `onionroute-mobile-ffi` for device, Apple Silicon simulator and
Intel simulator, creates `Frameworks/OnionRouteMobileFFI.xcframework`, generates
the Xcode project and runs `build-for-testing`. Set `IOS_SIMULATOR_DESTINATION` to
run the unit tests on an installed simulator. Generated frameworks, projects,
provisioning profiles, Team IDs and signing keys are intentionally not committed.
This default build validates the shell and ABI; it is not a production artifact
until the reviewed C Tor static libraries and production gateway composition are
linked.

The platform-independent project contract can also be checked on any host with:

```text
python clients/ios/scripts/validate_project.py
```

Both targets require the Network Extension (`packet-tunnel-provider`), App Groups
and shared Keychain capabilities in the Apple Developer portal. Replace the
example bundle IDs and App Group with registered values.

## Safety and integration status

The extension installs default IPv4/IPv6 routes and DNS inside the TUN, then
waits for a verified Connected event before reading packets. ABI 1.1 provides a
bounded reverse packet path into `NEPacketTunnelFlow`, preserves queued output
when the caller buffer is too small and handles input batches without silently
discarding their tail. Backpressure pauses the current batch and retries it on the
serial extension queue.

CP-0006 and ADR-0018 are accepted. `client-core` now exposes the object-safe
production factory, and the ABI owns a bounded background actor that is the only
source of `Connected`. It processes packets through `ClientCore`, pumps protected
flows, polls Tor plus gateway health and shuts components down in reverse order.
The platform can no longer assert positive core readiness.

ADR-0019 selects the iOS `EmbeddedCTorBackend`, which cross-compiles for arm64 iOS
and calls only the stable `tor_api.h` surface on a dedicated thread. Run
`scripts/verify-ctor-source.sh` with a reviewed Tor release keyring before building
the pinned native dependency.

The final production binary remains intentionally fail-closed until CP-0009 is
accepted and a concrete TLS-pinned `ProductionGatewayConnector` is supplied. The
current gateway daemon and reference gateway-protocol crate use incompatible
unreleased drafts, so the mobile build does not substitute either a mock or a
direct Tor SOCKS path. `includeAllNetworks` is requested, but Apple always excludes
some system traffic. Per-app VPN is not presented as a consumer feature;
deployment-specific per-app rules need a separate managed-device product decision.
