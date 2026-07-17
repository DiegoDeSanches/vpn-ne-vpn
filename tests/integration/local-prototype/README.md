# Local Tor v3 route prototype

This directory is an **experimental, local-development-only** integration
harness. It proves a real bounded TCP round trip through this route:

```text
probe
  -> client Tor SOCKS5
  -> Tor v3 Onion Service
  -> pinned self-signed TLS 1.3
  -> gateway-daemon ProtocolHandler
  -> fixture-only EgressDialer
  -> isolated HTTP origin
```

It is not a VPN, does not install a TUN adapter, and must not be deployed. The
gateway listener remains loopback-only. No host ports are published. A fresh
capability token, TLS key, certificate, and onion-service key are generated in
an ephemeral Docker volume on every clean run and are deleted by the runner.

The controlled origin is assigned `192.175.48.10` only inside an `internal`
Docker network. The local resolver maps only `fixture.onionroute.test` to that
address, and `FixtureOnlyDialer` rejects every address/port except
`192.175.48.10:18080` before delegating the actual TCP connect to the production
`TokioEgressDialer`. This deliberately prevents the test capability from being
used as an unrestricted public exit.

## Run on Windows

Docker Desktop must be running with Linux containers. From PowerShell:

```powershell
tests\integration\local-prototype\run.ps1
```

The first run builds Rust and installs Debian's Tor package, so it can take
several minutes. Success prints one compact JSON object and writes the same
object to the ignored `route-proof.json` file. Any Tor, TLS, authentication,
protocol, flow-control, challenge-echo, or fixture failure produces a non-zero
exit code. Add `-KeepRunning` only for local inspection, then clean up with:

```powershell
docker compose -f tests\integration\local-prototype\compose.yaml down --volumes
```

Linux/macOS can run `./tests/integration/local-prototype/run.sh`.

## Route-proof format

The probe emits exactly one application JSON line (container logs may add their
own prefixes):

```json
{
  "schema": "onionroute.local-prototype.route-proof.v1",
  "ok": true,
  "transport": "socks5+tor-v3-onion+tls1.3+gateway-v1-adapter",
  "gateway_id": "local-prototype-gateway",
  "onion_service": "<ephemeral-v3-hostname>.onion",
  "destination": "fixture.onionroute.test:18080",
  "fixture": "onionroute-controlled-http-v1",
  "response_sha256": "<sha256>",
  "server_certificate_sha256": "<sha256>"
}
```

`validate_proof.py` checks the exact v1 field set, the v3 hostname shape, the
fixed destination, and both SHA-256 values. The HTTP request carries a fresh
32-byte challenge; the proof is emitted only if the origin echoes it through
the complete route.

## Tests

```powershell
python -m unittest tests/integration/local-prototype/test_definition.py
docker build -f tests/integration/local-prototype/Dockerfile .
```

The Docker build runs the Rust unit tests with `--locked` before producing the
runtime image.

## Known integration blocker

This harness intentionally uses the wire adapter exported by
`onionroute-gateway-daemon`, because that is what its `ProtocolHandler` serves.
The adapter currently does not match the protected `proto/gateway/v1` structures
used by `onionroute-gateway-protocol::ClientReference`. The harness does not
modify either protected contract and is therefore not a drop-in client-core
backend. That mismatch must be resolved through the existing contract/ADR
process before production integration.

