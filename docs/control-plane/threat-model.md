# Control-plane directory threat model

## Scope and security objectives

In scope: directory serving, health aggregation, country configuration, bootstrap,
feature/version policy, gateway and intermediate-key revocation, signing, admin
commands, PostgreSQL, and their ingresses. User TCP/DNS traffic and gateway egress
are explicitly out of scope.

Objectives are authenticity and freshness of client policy, fail-closed selection,
root-key isolation, least privilege between API classes, absence of traffic/user
identity, and non-disclosure of management infrastructure.

## Assets and trust boundaries

| Asset | Boundary and protection |
|---|---|
| Pinned root public key | Shipped in app; update/recovery process is outside network bootstrap |
| Offline root private key | Offline HSM/media, two-person ceremony; never present in services or PostgreSQL |
| Online intermediate | Signing workload only; Vault/HSM target; short authorization window |
| Monotonic state | Atomic secure client storage for bundle version, directory version, and payload digest |
| Gateway inventory | Admin DB; public publisher reads an allow-listed SQL view only |
| Health samples | Dedicated gateway mTLS identity; no client/source IP or destination fields |
| Admin identity | Private operator ingress and DB audit fields; never serialized publicly |

## Threats, mitigations, residual risk

| Threat | Mitigation | Residual risk / response |
|---|---|---|
| Malicious/compromised directory transport | Root pin plus exact-byte signatures; expiry/rollback checks | Availability can be denied; client remains fail-closed or uses an unexpired verified cache |
| Online signing key compromise | Root-signed bounded certificate, short directory TTL, intermediate revocation | Attacker can forge short-lived policy until a higher root bundle reaches client |
| Root compromise | Offline isolation, two-person ceremonies, no service/root API | Requires app pin release or predesigned dual-root transition; never reset pin remotely |
| Catalog rollback/equivocation | Monotonic version plus stored exact-payload digest | Secure-storage loss is fail-closed and needs explicit recovery |
| Revoked gateway selection | Revocations signed in document and applied before scoring | Until next valid document, exposure is bounded by short TTL; emergency publish is required |
| Management infrastructure disclosure | Rust public type and SQL view are allowlists; schema snapshot tests | Coarse provider/AS still reveals some operator diversity and needs review |
| Health report spoofing | Dedicated gateway mTLS principal must equal body gateway ID; monotonic sequences | A compromised gateway can lie about itself; independent probes are a future control |
| User IP collection through health ingress | No IP field, unknown JSON rejected, no connect-info extraction/request logging | Network proxy naturally observes gateway transport IP; proxy logs must be disabled/redacted |
| Admin/client lateral movement | Separate binaries, listeners, proxies, identities, DB roles, and network policy | Host compromise can cross local boundaries; production should isolate workloads/nodes |
| Parser/memory denial | 2 MiB/collection/body limits, deny unknown fields, bounded DB fields | JCS parsing still allocates within the bound; add fuzz and resource tests before beta |
| Feature-flag fingerprinting | Signed global platform/version rules; no per-user stable rollout key | Platform/version combination is coarse client metadata; response is not server-personalized |
| Provider/AS diversity manipulation | Signed operator-reviewed values and large selector collision penalties | Provider ownership/AS can change; scheduled external validation is required |
| Clock manipulation | Bounded future skew and hard expiry with no bypass | Bad local clock causes safe availability failure |
| SQL race on version publication | Advisory lock for draft version; conditional state transition | Operator can create abandoned drafts; monitor and expire them without reusing versions |

## Logging and retention requirements

- Never log request bodies, headers, source IPs, Onion client circuit metadata,
  destinations, account IDs, or signing payloads.
- Log only coarse service health, error class, directory version, and key ID.
- Delete raw health samples after 30 days or sooner; retain only coarse aggregate
  availability needed for capacity operations.
- Admin actor stays in the administrative store and never in a signed document.
- Signing backend audit records operation/key/version, not seed, signature input,
  trust-bundle contents, or directory payload.

## Security acceptance tests

- Offline valid/tampered/expired/future/rollback/equivocation verification.
- Compromised online key cannot authorize an intermediate or root.
- Revoked, unhealthy, saturated, draining, incompatible, and old-client gateways
  cannot be selected.
- Source/user IP JSON is rejected by health collector and absent from schema.
- Public projection and serialized payload contain none of the forbidden fields.
- Client, admin, health, signing, and revocation listeners cannot be shared.
- Fuzz the envelope, payload, base64, canonicalizer, and OpenAPI request decoders.

