# CP-0011: Experimental staging CI/CD and SSH delivery adapter

- Status: Accepted for experimental staging only
- Owner: infra/platform
- Date: 2026-07-18

## Problem

The repository has no shared backend CI workflow and no runnable delivery adapter
for a pre-production server. Existing CI work is isolated to an iOS branch. Directly
adding a workflow is a protected CI change, while using the production deployment
contract is impossible before its provider, signing, and health adapters exist.

## Current contract

Production artifacts are distributed through immutable, signed GitHub Releases.
Production nodes are replaced through provider APIs and authenticated management
adapters; ordinary public SSH is prohibited. Security release gates are currently
blocked. The gateway binary rejects all capability tokens and the signing service
has no production KMS/HSM implementation.

## Proposed change

Add two versioned GitHub Actions workflows:

1. Backend CI checks architecture and secret policies, the root Rust workspace, the
   services workspace, standalone server workspaces, and a staging Docker build.
2. Pull requests and non-release refs validate the staging image with a read-only
   token. Write permissions exist only in jobs for an exact push to
   `gateway/multihop`: package/status access for publication and status-only access
   for failure cleanup. A successful publisher emits an immutable GHCR digest and a
   bounded promotion artifact containing the exact commit, run ID, run attempt, and
   digest before marking its status successful. A manual staging workflow requires
   that digest status to target the exact successful CI run and match its verified
   promotion artifact, creates a signed deterministic manifest, and streams it to a
   forced SSH deploy controller. The controller owns signature verification,
   migration, health, rollback, and audit behavior.

The deploy workflow uses a protected staging environment, full commit SHA image
tags, strict host-key verification, separate SSH and bundle-signing keys, static
concurrency, compressed and expanded transfer bounds, signed workflow-run
anti-replay state, and no runtime application secrets.

## Affected teams

- architecture/contracts: protected CI policy and staging-only scope;
- infra/platform: Docker image, SSH controller, server bootstrap, and rollback;
- control/directory: directory, health, administrator, and revocation binaries;
- security/threat-model: SSH trust boundary, secret isolation, and release claims;
- qa/integration: CI matrix and staging health evidence.

## Compatibility

No protobuf, token, directory, Rust public API, root Cargo workspace, database table,
or production deployment contract changes. The staging adapter is additive and
cannot target a production GitHub Environment. ADR-0012 remains authoritative for
production.

## Migration

Create the staging GitHub Environment, verify the server Ed25519 host fingerprint
through the provider console, install a dedicated forced-command deploy key and the
distinct bundle-signing public key, and add the five environment secrets documented
in infrastructure/staging-ssh/README.md. Run the deploy workflow manually with the
required confirmation input.

## Risks

- A compromised protected deployment workflow or bundle-signing key can control the
  staging containers through the forced deploy command.
- A compromised SSH key alone cannot replace the signed bundle, but still permits
  denial-of-service attempts against the serialized controller.
- Docker and root remain the same host trust boundary.
- Public SSH increases attack surface compared with the production design.
- A partial database schema could make binary rollback unsafe.
- Docker networking could expose a listener if loopback bindings regress.
- The 1 GiB staging host may not provide enough capacity for all services.
- The four application roles are least-privilege, but the single-host Docker/root
  boundary and loopback PostgreSQL listener remain shared staging trust.

## Tests

- YAML and Docker Compose configuration validation.
- Secret and architecture policy scans.
- Rust fmt, Clippy, and tests with locked dependencies.
- Docker image build, non-root service execution, and loopback-only port assertions.
- Bundle member, compressed/expanded size, revision, workflow-run replay, and
  checksum rejection tests.
- Migration from an empty database and rejection of a partial schema.
- Least-privilege database role checks, Tor bootstrap, Onion self-request, and
  health-gated deploy plus injected-failure binary rollback.
- Read-only PR image validation, gateway-only registry publication, failed-status
  cleanup, and exact CI run/attempt/artifact/digest binding contract checks.
