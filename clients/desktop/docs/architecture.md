# Desktop architecture

Status: experimental implementation boundary.

```text
Unprivileged native UI
    │ typed desktop IPC v1, OS-authenticated, 64 KiB max
    ▼
Privileged host (Windows Service / NEPacketTunnelProvider / systemd daemon)
    ├── recovery intent in OS secure storage
    ├── WFP / Network Extension / nftables kill switch
    ├── Wintun / NEPacketTunnelFlow / dev-net-tun packet adapter
    └── CoreControl adapter
            ▼
       shared Rust client core
```

The UI can render state and submit intent, but it has no TUN handle, route API,
firewall handle, secure-storage token, Tor control connection or direct network
socket. Platform hosts do not reimplement packet, DNS, Tor, gateway or rotation
logic; they enforce OS lifecycle and adapt bytes/events to the shared core.

## Startup and reboot recovery

`RecoveryIntent` is one of `Disconnected`, `Protected`, or `Blocked`. `Protected`
and unknown/corrupt persisted values are fail-closed. During boot the privileged
host installs/verifies its block policy before starting TUN or core. A failed
verification records `Blocked`, leaves the OS block in place and publishes only a
coarse error code.

Windows uses an automatic Windows Service with recovery actions, persistent WFP
filters and a service-owned Wintun adapter. macOS saves a signed
`NETunnelProviderManager` on-demand configuration. Linux starts before
`network-online.target` and loads the atomic nftables block policy before the
daemon. None of these recovery paths require the UI to be running.

## Lifecycle order

Connect:

1. Persist `Protected` recovery intent.
2. Engage kill switch.
3. Independently verify effective block policy.
4. Start the shared core.
5. Start the packet tunnel and publish protected state.

Disconnect and unblock (confirmed):

1. Stop new core work and drain/cancel flows.
2. Stop packet tunnel.
3. Verify protected teardown.
4. Disengage kill switch.
5. Persist `Disconnected`.

Any error before step 4 leaves the kill switch engaged and state `Blocked`.

## Platform split tunneling

Rules contain only an OS-local opaque application identifier and one of
`Protected`, `Bypass`, or `Blocked`. They are evaluated by the OS adapter before
packets enter TUN, matching the client-core assumption. Replacing the policy is a
confirmed critical action. Bypass never becomes an automatic response to a
tunnel error.

## UI privacy projection

The route screen shows role labels (`Tor`, `entry`, `relay`, `private exit`) and a
country-level exit selection. It never exposes relay fingerprints, onion service
addresses, gateway IPs, cities or coordinates. Latency is a coarse bucket. Direct
Tor is an explicit user-selected mode with a public Tor exit; it is not a fallback
and it is never presented as direct clearnet access.

