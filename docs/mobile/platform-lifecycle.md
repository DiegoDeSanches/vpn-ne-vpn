# Mobile platform lifecycle and recovery

Status: prototype design, 2026-07-17. The platform shells are implemented, while
the production packet/Tor/session factory is pending CP-0006.

## Non-negotiable invariant

Android `VpnService` and iOS `NEPacketTunnelProvider` are local packet interception
interfaces. They do not define the server transport. After interception,
OnionRoute must use the shared Rust flow engine, Tor, a Tor v3 onion service and a
private exit gateway. No failure, timeout, captive portal, rotation or update path
creates a clearnet fallback.

## Lifecycle sequence

```text
OS start / user connect
  -> create ABI handle and restore non-secret desired settings
  -> request full-route IPv4 + IPv6 TUN and protected DNS
  -> verify local interception / kill-switch posture
  -> Rust Tor bootstrap (bounded progress + cancellation)
  -> verify signed catalog and select country/mode route
  -> refresh anonymous capability token when needed
  -> establish onion + gateway session
  -> mark core ready and accept TCP/DNS packets
```

Failure at any arrow leaves the TUN present and user packets blocked. Disconnect
does the reverse: stop new flows, cancel work, close gateway/Tor, destroy the Rust
handle, then let the platform remove interception. A UI-process exit is never a
disconnect request.

## Platform mapping

| Event | Android | iOS | Safety rule |
|---|---|---|---|
| UI crash | Tunnel runs in `:tunnel` process | Extension is a different process | UI loss does not remove TUN |
| Wi-Fi ↔ cellular | `NetworkCallback`, `setUnderlyingNetworks` | `NWPathMonitor`; rebuild protected sockets | Keep TUN; fail active flows; no direct retry |
| Airplane mode | empty underlying networks | unsatisfied path | Block packets; bounded backoff |
| Sleep | foreground VPN remains; no wake lock | `sleep` freezes deadlines; `wake` revalidates | Unhealthy path resets flows |
| Low memory | trim local event/cache buffers | bounded batches and autorelease pools | Never shed kill switch first |
| UI requests disconnect | ignored in Android always-on | disable On Demand before explicit stop | Only explicit authorized stop removes protection |
| OS kills tunnel/extension | always-on restarts; lockdown is needed to block the gap | On Demand requests restart | See platform limitation below |
| Captive portal | unvalidated network is not an underlying path | iOS always excludes captive negotiation traffic | No general app-traffic bypass |

## Network handoff

The old protected path is declared lost before a new network becomes eligible.
The packet interface stays installed. Existing TCP flows reset because their Tor
transport cannot be assumed link-migratable. New flows wait until the replacement
Tor/gateway health proof succeeds. Reconnect delay is exponential and bounded;
power-save, constrained and metered paths increase delay but never enable bypass.

## Sleep and aggressive termination

Neither mobile OS promises that an ordinary process remains alive. Android's
foreground service reduces termination probability; always-on can restart it and
lockdown blocks traffic outside it. iOS runs the packet provider out of process
and VPN On Demand asks the system to relaunch it. Persist only desired connection,
config generation and closed-schema state—never raw routes, site history or a
persistent data-plane user ID.

Android meets the UI-crash criterion by isolating the service process. Without
user/admin lockdown, a service-process kill can remove the VPN interface before
restart; the consumer app cannot silently close that platform gap. On iOS,
`includeAllNetworks` explicitly excludes some system traffic, including DHCP,
captive-portal negotiation, certain cellular services and companion-device
traffic. This limitation is documented by Apple and must be shown to users:
[includeAllNetworks](https://developer.apple.com/documentation/networkextension/nevpnprotocol/includeallnetworks).

## Tor bootstrap and captive portals

There is no fixed mobile bootstrap time that can be promised. Tor reports
controller-facing progress 0–100 and structured problems; controllers should use
a timeout and show useful state rather than infer readiness from elapsed time:
[Tor control bootstrap events](https://spec.torproject.org/control-spec/replies.html).
The release benchmark records cold/warm p50, p95 and p99 on every device/network
class. The UI shows progress, warns after the approved UX threshold and continues
bounded retries under the kill switch.

Captive portal handling never opens a generic bypass. Android shows that the user
must authenticate outside OnionRoute or explicitly stop protection. On iOS the OS
itself excludes captive negotiation from the full tunnel; OnionRoute does not
claim visibility or protection for that traffic.

## Offline-safe configuration and tokens

- Verify signed bytes, version, sequence, expiry and size inside Rust before use.
- Keep the last accepted unexpired catalog atomically; a bad update never replaces it.
- If all catalogs are invalid/expired, block and report `catalog unavailable`.
- Tokens are short-lived and stored in Android Keystore-encrypted storage or the
  shared iOS Keychain access group. Expiry triggers refresh through the protected
  route; no token produces a block, not account fallback.
- App binaries and Rust/Tor code update only through the platform store. Remote
  signed configuration is data and cannot introduce executable functionality.

## User-visible limitations

- TCP only; arbitrary UDP and QUIC are blocked.
- Android per-app exclusions are explicit; in lockdown excluded apps may be offline.
- Consumer iOS builds do not promise per-app split tunneling. Per-app VPN needs a
  separate managed-deployment decision.
- Direct Tor is an explicit anonymity mode, never a fallback.
- OnionRoute improves privacy but cannot guarantee absolute anonymity.

