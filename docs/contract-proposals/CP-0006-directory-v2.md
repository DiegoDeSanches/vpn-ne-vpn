# CP-0006: signed gateway directory v2 for control-plane policy

- Status: Proposed
- Owner: `control/directory`
- Date: 2026-07-17

## Problem

The protected `proto/directory/v1/directory.proto` contract contains the Onion
endpoint, roles, protocols, capabilities, a capacity bucket, and descriptor
validity. It cannot express required client-side decisions for health, load,
provider/AS diversity, maintenance, abuse response, minimum client version,
country configuration, feature flags, or gateway revocation. Adding these fields
directly would modify a protected public contract without architecture approval.

## Current contract

`SignedGatewayDirectory` v1 signs exact protobuf payload bytes with an Ed25519
online key and carries `next_signing_keys`. The common client model similarly has
only the subset required by the first MVP selector. Its domain separator is
`onionroute-directory-v1\0`.

## Proposed change

Introduce a versioned v2 signed document described in
`docs/control-plane/signed-directory-v2.md` and prototyped, explicitly
experimentally, in `crates/directory-client`.

The proposal adds:

- the complete allow-listed gateway record requested by the control plane;
- coarse load, capacity, health, maintenance, and abuse states;
- provider and public AS diversity dimensions;
- signed countries, client-version rules, and non-personalized feature flags;
- signed active gateway revocations;
- a root-signed, monotonic trust bundle for online intermediate authorization and
  emergency revocation;
- exact RFC 8785/JCS payload bytes with domain-separated Ed25519 signatures;
- independent rollback state for directory and root trust-bundle versions.

The public projection deliberately has no management address, internal topology,
cloud account, exact capacity, operator ID, account ID, user IP, or persistent
client fingerprint.

## Affected teams

- Architecture/contracts: accept/reject the wire-format choice and root bundle.
- Client desktop/mobile: pin the root, integrate offline verification, persist
  monotonic state atomically, and adapt verified v2 into the client-core model.
- Policy/network engine: accept coarse selection inputs only after a separate
  public-interface ADR.
- Gateway operators: provide public descriptor and coarse authenticated health.
- Security/QA: key ceremony, rollover, rollback, mutation, fuzz, and leak tests.
- Infrastructure: Onion Service ingress, private mTLS ingresses, PostgreSQL roles,
  Vault/HSM integration, and key backup/rotation.

## Compatibility

V1 is unchanged. During migration the directory service publishes v1 and v2 on
different paths and content types. A client advertises no wire preference to the
public service; the app version determines which fixed path it fetches. A v1
client never sees v2. A v2 client may use a still-valid v1 cache only through an
explicit local adapter approved with the client-core contract change.

The v2 domain separator and format version are distinct, so signatures cannot be
replayed across versions.

## Migration

1. Approve the contract and generate golden vectors in at least Rust and one
   mobile language.
2. Add the v2 protobuf/CBOR/JCS decision to the protected contract area. The
   current JCS prototype is not production-authoritative before approval.
3. Land readers and pinned root material before any v2-only gateway metadata.
4. Dual-publish v1 and v2 with the same short expiry and monotonic source version.
5. Observe signature/expiry failures without collecting user or destination data.
6. Make v2 required only after the minimum client rule excludes v1-only clients.
7. Retire v1 after its maximum cache lifetime and a documented emergency window.

## Risks

- JCS implementations may differ; exact golden vectors and canonicality rejection
  are mandatory.
- An online key compromise permits malicious short-lived directories until root
  revocation is delivered. It cannot authorize a new intermediate or root.
- Wall-clock errors can fail closed. Clients need bounded skew handling, never an
  expiry bypass.
- Provider/AS labels are operator assertions and can be stale or dishonest.
- A public provider group can expose more infrastructure correlation than useful;
  groups must remain coarse and reviewed.
- Root loss or compromise requires an app release or a pre-authorized root
  transition ceremony; silent pin reset is prohibited.

## Required tests

- exact-byte golden signature, mutation, non-canonical JSON, and size-bound tests;
- expired/future directory and trust-bundle rejection;
- directory and trust-bundle rollback plus same-version equivocation tests;
- revoked intermediate and gateway rejection;
- emergency intermediate rotation with the old key revoked;
- selector country/profile/role/protocol/client-version/load/health/maintenance,
  provider/AS diversity, and local recent-failure tests;
- schema/API snapshots proving forbidden infrastructure fields are absent;
- parser fuzzing before production acceptance.

