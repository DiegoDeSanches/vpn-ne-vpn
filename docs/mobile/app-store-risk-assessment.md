# iOS App Store and entitlement risk assessment

Assessment date: 2026-07-17. Overall pre-submission risk: **high** until the
Network Extension entitlement, organization account, privacy disclosures and
Apple interpretation of the Tor flow-conversion architecture are confirmed.

## Gating requirements

1. Apple guideline 5.4 requires VPN-service apps to use the `NEVPNManager` family,
   be offered by an organization-enrolled developer, disclose collected data and
   its use on screen before purchase/use, commit not to sell/use/disclose VPN data
   to third parties, obey local law and provide license information where needed:
   [App Review Guidelines 5.4](https://developer.apple.com/app-store/review/guidelines/).
2. Both containing app and provider provisioning must include
   `com.apple.developer.networking.networkextension` with
   `packet-tunnel-provider`: [Network Extensions entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension).
3. App Group and shared Keychain access groups must be registered for the same
   team. Apple documents that App Groups can also act as Keychain access groups:
   [sharing Keychain items](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps).
4. The app must be functional on IPv6-only networks (guideline 2.5.5). The
   prototype claims both default IPv4 and IPv6 routes and must pass NAT64 testing.
5. Signed remote catalog/config is data only. Guideline 2.5.2 forbids downloaded
   code that changes functionality; C Tor, Rust and transport logic ship in the
   reviewed bundle and update through the App Store.

## Architecture review risk

Apple describes a packet tunnel as sending claimed packets over a tunnel to a
remote server for injection. TN3120 warns against using it as a local content
filter, DNS interceptor, listener or generic proxy:
[TN3120](https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers).

OnionRoute is intended to send every supported claimed flow to a remote private
exit over Tor; unsupported UDP is rejected because the product is TCP-only. The
local engine terminates/reconstructs TCP rather than encapsulating original IP
packets, so App Review may still classify it as a proxy-like unsupported use.
Before product investment, request written Developer Technical Support guidance
with a sequence diagram and explain:

- `NEPacketTunnelProvider` is the system full-tunnel interface;
- every accepted TCP/DNS flow reaches a remote exit gateway;
- no local content-filter product is advertised;
- Tor is the privacy transport and the private gateway performs Internet egress;
- unsupported traffic is blocked for protocol/safety reasons, never selectively
  reinjected or routed to a local proxy.

This is the largest unresolved store risk and can be release-blocking even when
the implementation is technically correct.

## Background, memory and lifecycle

Network Extension is the intended background execution mechanism. Do not add
`UIBackgroundModes` to the extension; Apple says that app extensions using it are
rejected and that extension memory limits are substantially below foreground-app
limits: [App Extension Programming Guide](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionCreation.html).

Apple does not publish a contractual numeric `NEPacketTunnelProvider` memory
limit. Treat the prototype's 48 MiB budget as an internal ceiling, test older and
current devices under pressure, and reduce it until a safe margin is observed.
C Tor, directory caches, dual-route rotation and packet queues all count in the
extension process. No App Store claim should cite an unofficial 15/50 MiB number.

## Routing and kill-switch wording

`includeAllNetworks` sends most traffic through the tunnel but Apple always
excludes network-control, captive-portal, certain cellular-service and companion
traffic. Marketing must say “blocks supported app Internet traffic when the
protected path is unavailable,” then enumerate platform exclusions. Do not say
“all packets,” “zero leaks under every condition,” or “absolute anonymity.”

Consumer per-app split tunneling is not offered. Apple provides per-app rules only
for per-app configurations, which are deployment-sensitive:
[per-app rules](https://developer.apple.com/documentation/networkextension/netunnelprovidermanager/apprules).

## Review package

- Review Notes with test account (if any), exact connect steps and architecture diagram.
- Privacy screen video/screenshots shown before first connect or purchase.
- Privacy policy explicitly prohibiting sale/use/disclosure of VPN traffic data.
- Entitlement approval and organization legal entity details.
- Export-control and territory VPN-license assessment.
- Demo gateway/country available throughout review; no hidden modes.
- Support explanation for TCP-only behavior, blocked QUIC and captive portals.
- TestFlight evidence for extension restart, IPv6-only, sleep and low memory.

