# ADR 0002: User-mode Direct Tor prototype on Windows

- Status: Accepted for the local experimental prototype only
- Date: 2026-07-17
- Scope: `clients/desktop`, `tests/integration/local-prototype`

## Context

The Windows shell can run without elevation, but the repository does not yet
contain reviewed WFP, Wintun, Windows Service, production directory, or private
gateway authentication implementations. The production desktop runtime is
correctly fail-closed and must not report `Connected` without verified platform
packet capture and filtering. Replacing those checks with mocks would create a
misleading VPN state.

The project still needs an end-to-end prototype that exercises a real Tor route,
the local versioned IPC contract, UI lifecycle, bounded proxying, and failure
handling on an ordinary Windows development machine.

## Decision

Ship a separately labelled `Direct Tor user-mode prototype`:

```text
proxy-aware application
-> 127.0.0.1 application SOCKS5 listener
-> 127.0.0.1 Docker-published C Tor SOCKS5 listener
-> Tor
-> ephemeral v3 onion service
-> local private gateway adapter
-> controlled TCP fixture
```

The desktop console daemon owns the application SOCKS5 listener and exposes the
existing bounded Named Pipe IPC v1 to the WinUI client. `Connect` may report
ready only after both the listener is owned by the daemon and a nonce-bound live
probe has traversed Tor, the v3 onion service, TLS 1.3, the gateway protocol
adapter, and the controlled fixture. Any startup, probe, or upstream failure
leaves the application proxy closed or closes it; there is no destination
direct-connect fallback in the proxy.

The explicit prototype build symbol may authenticate a same-user daemon only
when its executable is located beside the UI. Normal builds retain the installed
service path and signing checks.

## Security boundary

Fail-closed behavior applies only to TCP connections explicitly configured to
use the application SOCKS5 listener. The prototype does **not** provide:

- system-wide packet capture;
- a Windows kill switch or crash-persistent firewall policy;
- system DNS, IPv6, UDP, or QUIC leak prevention;
- exit-country selection;
- production capability tokens, directory signing, billing, or telemetry;
- Standard, Enhanced, or Maximum anonymity modes.

The UI and artifact name must keep this boundary visible. They must never say
that Windows, the device, or unrelated applications are VPN-protected.

## Consequences

- The prototype runs as a standard user and requires Docker Desktop for its
  disposable Tor/onion/gateway fixture.
- Proxy-aware tools can exercise a real route with remote SOCKS hostname
  resolution and TCP only.
- Production `DaemonRuntime`, protected protobuf contracts, and production
  gateway authentication remain unchanged.
- A production Windows MVP still requires a separate elevated Windows Service,
  reviewed WFP/Wintun implementations, signed binaries, and gateway contract and
  authentication convergence.

## Acceptance gates

1. The WinUI client authenticates the colocated prototype daemon and renders
   daemon state changes.
2. A nonce-bound v3 onion route proof succeeds before the state becomes ready.
3. The proxy rejects SOCKS BIND/UDP, IPv6 destinations, SMTP port 25, malformed
   frames, excess clients, and oversized domains.
4. Killing Tor or the route fixture closes/rejects protected proxy connections;
   no code path dials the requested destination directly.
5. Non-administrator startup changes no Windows service, route, firewall, DNS,
   or global proxy setting.

