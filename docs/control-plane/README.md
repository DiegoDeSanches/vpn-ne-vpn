# OnionRoute control-plane directory services

This implementation owns catalog metadata and policy only. It does not process
user traffic and contains no egress code.

| Component | Responsibility |
|---|---|
| `services/directory-service` | Exact signed directory download and non-personalized client bootstrap over a Tor v3 Onion Service |
| `services/health-collector` | Authenticated coarse gateway samples and health/load aggregation without user/source IP storage |
| `services/admin-api` | Separate operator API documented by `openapi/admin-v1.yaml` |
| `services/signing-service` | Online-intermediate signing and conditional draft publication; never the root |
| `services/revocation-service` | Gateway revocation lifecycle for admin/publisher workloads |
| `crates/directory-client` | Experimental offline verifier and reference gateway selector for CP-0006 |
| `services/migrations` | PostgreSQL schema and public projection |

Client endpoints are `/client/v2/directory` and `/client/v1/bootstrap`. The
application listener must bind loopback and be mapped only by a configured Tor v3
Onion Service. No clearnet fallback exists. Public HTTPS remains outside this
control plane and is not configured here.

Health, admin, signing, and revocation are distinct private mTLS ingresses. Their
identity headers are trusted only after an ingress strips client-provided values
and injects the verified workload/operator identity. They must use distinct
service accounts, database roles, rate limits, and network policies.

The v2 implementation is experimental until CP-0006 is accepted. Existing v1
protobuf and `common-types` are intentionally unchanged.

## Backpressure and limits

- client bootstrap: 4 KiB request;
- health: 8 KiB request, 8 checks;
- admin: 64 KiB request;
- signing/directory envelope: 2 MiB;
- PostgreSQL pools are explicitly bounded per service;
- overload or database failure returns an error and never produces an unsigned,
  expired, direct-clearnet, or unverified fallback.

## Production dependencies still requiring deployment ownership

- Tor Onion Service configuration and network-policy enforcement;
- Vault/HSM online signer adapter and offline root ceremony;
- service-specific PostgreSQL roles/grants and migration runner;
- rustls-protected PostgreSQL transport (the reference build uses SQLx `tls-none`
  and therefore must be restricted to a local proxy/socket until that deployment
  feature is enabled);
- independent gateway probes and raw-health retention job;
- Prometheus metrics with a closed label registry and no request metadata;
- fuzzing and mobile-language golden-vector implementations after CP acceptance.
