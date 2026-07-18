# ADR-0021: Restricted SSH delivery for the experimental staging control plane

- Status: Accepted for experimental staging only
- Date: 2026-07-18
- Owners: infra/platform, architecture/contracts, security/threat-model

## Context

ADR-0012 and the production deployment runbooks require immutable provider images,
private management paths, canary replacement, and authenticated adapters. They
prohibit ordinary public SSH deployment. The repository nevertheless needs a small,
single-host integration environment before those production adapters and release
gates are complete.

The gateway daemon still uses a deny-all production authentication adapter and the
signing service lacks its production Vault/HSM adapter. Treating either as a working
production deployment would be misleading and would weaken fail-closed behavior.

## Decision

Add a separate GitHub Environment named staging and a manually dispatched workflow
for the Rust control plane only. Pull requests and non-release refs validate the
commit-SHA-tagged Docker image with a read-only token. Write permissions exist only
in jobs for an exact push to `gateway/multihop`: the publisher receives package and
status access, while a no-checkout cleanup job receives status access only. A
successful publisher builds the gated image, pushes it to GHCR, and uploads a
bounded promotion record containing its immutable digest, commit, workflow run ID,
and run attempt before marking the digest status successful. The deploy workflow
verifies the exact run metadata, fetches the uniquely named run artifact, verifies
the size-bounded artifact archive digest and promotion record, revalidates the exact
Backend CI workflow ID, successful run attempt, and unchanged latest status, promotes
that digest rather than rebuilding source, then repeats the run/status checks
immediately before streaming a signed, checksummed, size-bounded bundle over SSH.

The SSH credential is an environment-specific Ed25519 key installed on the staging
root account with OpenSSH restrict and a forced, root-owned deploy controller. A
distinct Ed25519 signing key signs the internal bundle manifest; only its public key
is installed on the server. The controller accepts only a versioned deploy command,
validates the commit SHA, bundle digest and signature, exact archive member set,
internal file manifest, and image revision label, serializes deployments, runs an
expand-only schema gate, binds the signed bundle to a monotonically accepted GitHub
workflow run ID, waits for Tor bootstrap and an end-to-end request through the
generated Onion Service, and rolls the binaries back to the previous immutable
local image ID on failure. Release metadata is installed atomically and the previous
rollback image is required before migration begins.

PostgreSQL credentials and the Tor v3 service identity remain on the server. A
superuser credential is available only to the migration job; directory, health,
administrator, and revocation services each use a distinct non-superuser role with
explicit grants. GitHub does not receive runtime credentials. Application and
database ports bind only to host loopback; directory client ingress is exposed only
through its Tor v3 Onion Service.

The staging stack includes directory-service, health-collector, admin-api,
revocation-service, PostgreSQL, and the directory Onion Service. It explicitly
excludes signing-service, token-service, gateway-daemon, gateway multihop roles, and
all user data-plane traffic.

## Consequences

- This adapter does not supersede ADR-0012 and is not eligible for production.
- A provider-console-verified SSH host key is mandatory; runtime ssh-keyscan trust is
  rejected.
- GitHub Environment secrets contain only SSH delivery material and the host
  endpoint plus a staging bundle-signing key. Runtime database, application signing,
  Tor, TLS, token, and gateway secrets stay off GitHub.
- The SSH and bundle-signing keys must be distinct. A stolen SSH key alone cannot
  authorize arbitrary root-controlled Compose input.
- Pull-request image validation cannot write packages or commit statuses. A failed
  gateway publication replaces its pending digest status with a failure state.
- A commit status cannot substitute an arbitrary digest from another build: the
  digest must match the promotion artifact of the exact successful run and current
  run attempt. A later rerun creates a new promotion attempt; a pending or failed
  status prevents newly started deploys. Expired artifacts require a fresh successful
  CI run.
- Database migrations are not rolled back. Only expand-only migrations may enter
  this adapter.
- A valid signed bundle can be accepted only once by workflow run order. Retrying a
  failed commit requires a newly dispatched GitHub workflow and newly signed run ID.
- Old images and release metadata are retained for rollback; a reviewed retention
  policy is still required.
- Production remains blocked until the normative release gates, token verifier,
  KMS/HSM adapters, mTLS ingress, leak evidence, canary controller, and immutable
  provider-image workflow are complete.
