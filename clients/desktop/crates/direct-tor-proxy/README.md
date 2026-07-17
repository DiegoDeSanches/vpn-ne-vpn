# Direct Tor proxy (EXPERIMENTAL)

This crate is an **application-scoped development prototype**, not a Windows
VPN, system packet tunnel, or kill switch. Only applications explicitly
configured to use its loopback SOCKS5 endpoint are protected. Every other
application can still use the normal Windows network path.

The daemon supplies an already-running, loopback-only C Tor SOCKS endpoint. The
proxy accepts SOCKS5 `CONNECT` on exactly `127.0.0.1`, preserves domain names for
Tor-side resolution, and opens no destination socket itself. If Tor rejects or
loses the stream, the client connection fails; there is no clearnet fallback.

## Supported prototype surface

- IPv4 and validated ASCII/IDNA A-label domain destinations.
- `CONNECT` only.
- Bounded client count, listen backlog, frames, domains, relay buffers and
  handshake/connection/stream deadlines.
- Optional RFC 1929 credentials toward Tor for `IsolateSOCKSAuth`.
- Port 25, IPv6, SOCKS `BIND`, and SOCKS UDP association are rejected locally.

The loopback client listener currently uses SOCKS no-authentication. Other local
processes on the machine can therefore use it while it is running. A daemon must
keep the endpoint lifecycle short and must not advertise it as multi-user safe.
No hostname, destination, credential, payload, IP, or per-flow telemetry is
logged by this crate.

## Daemon API

```rust,no_run
use onionroute_direct_tor_proxy::{
    DirectTorProxy, ProxyConfig, TorSocksEndpoint, UpstreamAuthentication,
};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let tor = TorSocksEndpoint::new(
    "127.0.0.1:19050".parse()?,
    UpstreamAuthentication::UsernamePassword {
        username: b"<torS0X>0".to_vec(),
        password: b"identity-scoped-secret".to_vec(),
    },
)?;
let proxy = DirectTorProxy::start(ProxyConfig::new(0, tor)).await?;
let endpoint = proxy.local_address();
// Publish `endpoint` only to the same-user UI/application integration.
proxy.shutdown().await?;
# Ok(())
# }
```

Use `socks5h`/SOCKS domain mode in the calling application. Supplying a locally
resolved IPv4 address cannot preserve the original hostname and may already have
used the system DNS resolver before this crate receives the request.

## Test

```powershell
cargo test --manifest-path clients/desktop/crates/direct-tor-proxy/Cargo.toml
```

Tests use a loopback mock Tor SOCKS server. They do not claim that Tor itself,
Windows routing, DNS leak protection, WFP, Wintun, or a private gateway works.
