# CP-0008: Enhanced inter-gateway directory and wire registration

- Status: Proposed
- Owner: `gateway/multihop`
- Date: 2026-07-17

## Проблема

Enhanced route selection and mTLS cannot be safely derived from the current
protected directory contract. It has provider group and AS, but no independent
management failure-domain identity, no inter-gateway data-plane endpoint, no
role-specific TLS server name, no mTLS trust-bundle reference/pin set and no
registered inter-gateway protocol version.

## Текущий контракт

`directory.v2.GatewayRecord`/the Rust mirror contains gateway role, country,
provider group, AS, onion address, capabilities, gateway protocol versions,
load/health/maintenance and an application signing key. `proto/gateway/v1` has
client-to-gateway TCP/DNS frames but no opaque inter-gateway relay-session
messages. Management identity and token formats are protected and unchanged.

## Предлагаемое изменение

Add signed, public, allow-listed data-plane fields to each gateway descriptor:

- `management_failure_domain_id` — opaque operator/management isolation label;
- `inter_gateway_endpoint` — hostname + TCP port, never a management address;
- `inter_gateway_tls_server_name`;
- `inter_gateway_protocol_versions` (initially `1.0`);
- `inter_gateway_leaf_pins_sha256` with current/next activation windows;
- `inter_gateway_trust_bundle_id` and monotonic bundle version;
- explicit `inter_gateway_data_plane_v1` capability.

Register `onionroute.intergateway.v1.InterGatewayFrame` matching
`docs/enhanced-inter-gateway-protocol-v1.md`. It contains only service and opaque
relay-session fields and must remain separate from account/token schemas.

Until acceptance, `crates/gateway-multihop::route::GatewayDescriptor` is an
adapter populated by deployment tests/mocks. No protected file is changed.

## Затронутые команды

- `architecture/contracts`: directory and Protobuf review/registration.
- `control/directory`: publish and sign the new allow-listed fields/bundle.
- `infra/platform`: issue role-specific leaves and expose only data-plane endpoints.
- `gateway/multihop`: replace local wire/descriptor adapters after acceptance.
- `security/threat-model`: review PKI, correlation and lateral-movement controls.
- `qa/integration`: add multi-provider/AS staging evidence.

## Совместимость

This is additive to the signed directory but old strict parsers use
`deny_unknown_fields`; therefore it requires a new directory format version or
an explicitly versioned optional extension container. Inter-gateway framing is a
new protocol namespace and does not change gateway v1 tags.

Clients that do not implement Enhanced continue Standard/Direct Tor according to
their explicit profile; they must not silently downgrade an Enhanced request.

## Миграция

1. Approve schema and threat-model review.
2. Publish a dual-format directory during a bounded compatibility window.
3. Deploy role-specific PKI/bundle and non-management data-plane endpoints.
4. Run shadow handshakes and route validation without user traffic.
5. Enable Enhanced only for clients/gateways advertising the registered version.
6. Remove the local adapter after all consumers use the protected generated types.

## Риски

- Failure-domain labels may be false or stale; operational ownership validation
  is required before signing.
- Endpoint/pin rotation ordering can cause fail-closed outage.
- Publishing infrastructure metadata can aid targeting; expose only the minimum
  data-plane fields and coarse labels.
- A directory rollback could resurrect revoked pins; enforce monotonic bundle
  versions and existing rollback protection.
- Multiple connections can increase correlation surface; default remains one.

## Тесты

- Signature/rollback/expiry tests for new directory format.
- Route tests requiring provider, AS and management-domain diversity.
- Current/next pin overlap and expired/unknown/revoked pin tests.
- Wrong-role CA/EKU, management identity and endpoint-isolation tests.
- Protocol conformance, fuzzing, backpressure, drain and 10k-producer load tests.
- Evidence that no account ID/source IP/destination is added to inter-gateway wire.
