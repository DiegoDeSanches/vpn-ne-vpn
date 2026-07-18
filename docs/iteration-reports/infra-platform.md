# Iteration report: infra/platform

- Date: 2026-07-17
- Scope: OpenTofu, immutable images, Ansible, systemd, nftables, Vault delivery,
  deployment, rollback, monitoring, gateway lifecycle and disaster recovery
- Explicitly out of scope: client UI, gateway wire protocol and service business logic

## Implemented

- AWS/GCP private fleets for entry, exit, relay, directory, token, health, signing,
  monitoring and management roles, with no public node addresses or ingress.
- Plan-time entry/exit separation across provider, ASN, administrative project,
  management trust domain, disk KMS key, workload identity and Vault scope.
- Role-specific immutable Debian image pipeline using pinned snapshots/base images,
  private Packer transports, release verification, SBOM, provenance and signed image
  manifests.
- Debian/AppArmor/systemd/nftables hardening, certificate-only loopback SSH over a
  management onion, exact egress allow-lists, IPv6/QUIC/SMTP/private/metadata denies,
  and fail-closed startup.
- Separate workload-identity Vault agents and policies for onion, gateway identity,
  mTLS, directory, token, monitoring and administration material. The directory root
  key is explicitly offline and absent from the online Vault namespace.
- Bounded canary/drain/health/rollout controller with supply-chain binding,
  expand-only migration gate, automatic revocation/rollback and three-plane emergency
  revoke.
- Label-free local privacy exporter, allow-listed Prometheus metrics, alerts and
  Grafana dashboard for resource, Tor, onion, session bucket, bandwidth bucket,
  egress, key-expiry and clock signals.
- Deployment, rollback, key-compromise, region-onboarding, security-update and
  backup/recovery runbooks plus ADR-0012.

## Files added

- `infrastructure/opentofu/`: root configuration, AWS/GCP modules, remote backend and
  production inventory examples, and provider lock file.
- `infrastructure/images/`: Packer template and signed build/prepare/validation scripts.
- `infrastructure/ansible/`, `infrastructure/systemd/`, `infrastructure/nftables/`:
  role image configuration and host/runtime policy.
- `infrastructure/vault/`: secret boundary documentation and policy templates.
- `infrastructure/deploy/`: controller, bounded adapter contract and example config.
- `infrastructure/monitoring/`: Prometheus, alert and Grafana configuration.
- `infrastructure/runbooks/`, `infrastructure/tests/`, ADR-0012 and this report.

## Public interfaces created

- OpenTofu node inventory and outputs documented in `infrastructure/opentofu/README.md`.
- Packer image inputs and signed manifest custom data (`node_role`, `release_digest`).
- Deployment adapter argv/JSON v1 contract in `infrastructure/deploy/ADAPTERS.md`.
- Vault path/readership contract in `infrastructure/vault/SECRETS.md`.
- Fixed, label-free operational metric names and bucket semantics.

No protected protobuf, `common-types`, root Cargo manifest, CI configuration,
directory format, token format or gateway public protocol was changed.

## Assumptions

- Production Vault and PostgreSQL are externally operated HA dependencies reachable
  only at exact private/onion endpoints; this iteration defines consumers and policy,
  not those managed clusters.
- Cloud workload identities are mapped to reviewed Vault auth roles by a separate
  bootstrap authority. Bootstrap metadata carries public references only and is
  bounded to 16 KiB.
- Tor maps local data and management listeners to separately keyed v3 onion services.
- Direct entry/relay/exit transport remains owned by the protocol team; exact next-hop
  addresses can be allowed only after that contract is accepted.
- Directory draining and publication preserve monotonic signed-directory semantics.

## Tests passing

- OpenTofu 1.12.0 `fmt`, provider/module `init`, and `validate` with locked AWS and GCP
  providers.
- Packer 1.11.2 `fmt` and full template `validate` with official provider plugins.
- Ansible Core 2.17.12 playbook `--syntax-check`.
- 19 infrastructure unit/static tests covering secrets/state, topology, cloud exposure,
  nftables, systemd, monitoring privacy, bucketing, rollback and emergency revoke.
- Shell syntax checks, HCL/YAML/JSON parsing and the repository architecture checker.

## Tests not run / not yet available

- Real AWS/GCP plans or applies, signed image builds and provider/ASN validation,
  because no production cloud credentials or inventory were placed in the workspace.
- Staging Tor onion reachability, leak, canary, rollback, Vault outage and multi-role
  compromise drills.
- Vault auth/policy integration, KMS/HSM signing ceremonies, PostgreSQL PITR restore
  and object-lock recovery exercises.
- AppArmor/systemd/nftables boot validation on the final cloud images; these checks are
  present in the image pipeline but require an actual build.

## Dependencies expected from other teams

- Architecture/protocol: accepted direct multihop transport and exact next-hop contract.
- Gateway/control teams: signed role artifacts plus reviewed directory, lifecycle,
  health, migration and cloud-isolate adapter implementations.
- Security: provider/ASN source of truth, HSM/KMS key ceremonies, MFA/SSH CA policy,
  threat-model review and destructive staging drills.
- Operations: production cloud projects, private builder networks, remote state,
  Vault/PostgreSQL clusters, DNS/NTP allow-lists and recovery accounts.
- QA: cross-provider leak tests, capacity/failure injection and measured rollback/RTO.

## Security risks found

- A cloud secret-agent identity can reach metadata by design. The application and Tor
  services have independent nftables/systemd denies, but this boundary needs staging
  verification against UID and cgroup escape paths.
- A compromised online directory signer can publish valid short-lived data until root
  revocation propagates; offline-root custody limits but does not eliminate the window.
- Provider/ASN and administrative-domain metadata can become stale, invalidating the
  intended diversity guarantee unless inventory review is enforced continuously.
- Directory, lifecycle, health and cloud deployment adapters are contracts/mocks,
  not production-approved clients; the reference Vault-revoke adapter still needs a
  live policy test. A faulty adapter could delay drain or revocation.
- Monitoring onion targets reveal gateway inventory to the monitoring role. That role
  must remain isolated and must not gain application or signing credentials.

## Contract proposals

- None. The infrastructure consumes existing contracts through adapters and did not
  modify a protected interface.

## Ready for integration

- Static configuration, policies, image/deployment pipeline, runbooks and test harness
  are ready for review and staging integration.
- Production rollout is not ready until real adapters, signed role artifacts, external
  Vault/PostgreSQL services and cloud/onion staging drills are complete.

## Open questions

1. Which AWS/GCP accounts, public ASNs and independent administrative owners are the
   authoritative production inventory for each first region?
2. Is Vault the common secret broker for both providers, or must either provider use a
   native KMS broker behind the same workload-identity contract?
3. Which exact onion or terminal-encrypted transport endpoints should be allowed for
   entry/relay/exit next hops?
4. What are the production canary observation window, rollout wave size, drain timeout
   and minimum spare-capacity policy per role?
5. Which independent probe quorum is authoritative for onion availability and can
   trigger automated rollback without making monitoring a global trust root?
6. What RPO/RTO values and jurisdictions are approved for the first control-plane
   PostgreSQL and Vault deployments?

---

## 2026-07-18 addendum: experimental staging CI/CD

### Implemented

- Added backend CI for the root workspace, control-plane services, seven standalone
  Rust manifests, architecture/secret checks, Compose policy tests, and an immutable
  staging image build.
- Added manual, protected-environment delivery that promotes the exact CI-published
  GHCR digest, creates an Ed25519-signed bundle, pins the SSH host key, and streams it
  to a forced root-owned controller.
- Added a staging-only Compose stack for PostgreSQL 18, directory, health,
  administrator, revocation, and Tor v3 Onion Service components. Signing, token,
  gateway, and all user data-plane components remain excluded.
- Added expand-only schema migration, bounded input validation, health-gated rollout,
  signed workflow-run anti-replay state, atomic release metadata, immutable-ID
  rollback, audit logging, and server bootstrap with distinct SSH and bundle-signing
  keys.
- Added distinct non-superuser PostgreSQL roles/passwords for all four services,
  final-process PostgreSQL readiness, Tor control-port bootstrap readiness, and an
  end-to-end request through the generated Onion Service.
- Restricted package/status write permissions to the gateway publish job; PR and
  non-release image validation is read-only. Digest promotion now verifies the exact
  Backend CI workflow ID, successful run and run attempt named by the latest status,
  plus the SHA-256 and bounded contents of its unique promotion artifact, then
  rechecks that status;
  the same run/status gates execute again immediately before SSH. Failed publication
  clears a pending status to failure.
- Restored the declared Rust 1.78 MSRV by pinning only incompatible transitive lock
  entries in `services`, `auth-tokens`, and `token-service`.

### Files added or changed

- `.github/workflows/backend-ci.yml`, `.github/workflows/staging-deploy.yml`, and
  `.dockerignore`.
- `infrastructure/staging/` image, Compose, migration/bundle helpers, and tests.
- `infrastructure/staging-ssh/` controller, bootstrap, operator documentation, and
  delivery contract tests.
- ADR-0021, CP-0011, the ADR index, three Cargo lock files, and this report.

### Public interfaces

- GitHub Environment `staging` with five documented environment-secret names.
- Forced-command protocol `deploy <40-hex-revision> <bundle-sha256> <run-id>`.
- Signed bundle member/manifest contract and OCI revision label.

No protobuf, token or directory format, Rust public API, root Cargo manifest, or
production deployment contract changed. CI is a protected configuration change
covered by CP-0011 and ADR-0021.

### Assumptions

- `gateway/multihop` remains the default/deployable branch.
- The staging host is the inspected Ubuntu server at `66.248.207.180`; its SSH host
  key must still be verified through the provider console.
- PostgreSQL and Tor identities remain server-side. GitHub holds only delivery
  credentials and the staging bundle-signing key.
- The `staging` Environment has been created and restricted to `gateway/multihop`;
  its five secrets remain intentionally unset until provider-console bootstrap.
- Repository Actions defaults are read-only, Actions cannot create/approve pull
  requests, and full-length commit SHA pinning is enforced for every referenced
  GitHub Action.

### Tests passing

- Rust 1.78: root compile/tests; strict services fmt/Clippy/tests; Clippy/tests for
  gateway-protocol, gateway-daemon, gateway-multihop, auth-tokens, tor-backend,
  circuit-manager, and token-service.
- Full multi-stage image build with digest-pinned Dockerfile frontend/base images and
  exact OCI revision label.
- Compose contract tests (7), SSH delivery contract tests (14), `actionlint`, YAML
  parsing, shell syntax, signed-bundle happy path, and tampered-signature rejection.
- Local full-stack smoke: PostgreSQL 18 final-process readiness, schema and
  least-privilege role migration, all four Rust services healthy, Tor bootstrap at
  100%, and an HTTP response through the generated v3 Onion Service. The isolated
  test containers, network, volumes, and five passwords were removed afterward.

### Tests not passing or not run

- Root and some standalone historical source is not rustfmt-clean and has pre-existing
  Clippy warnings. CI reports formatting as advisory and keeps compilation/tests
  mandatory; services remain strict with `-D warnings`.
- No live SSH deployment, rollback fault injection, or reboot persistence test was run
  because server root access, pinned host key, and deploy/signing keys are not yet
  installed.

### Dependencies and security risks

- The user/operator must log in through the provider Native-console, verify the host
  key, install Docker Compose v2 and the restricted controller, and then populate the
  five existing GitHub Environment secret slots.
- A protected workflow or bundle-signing-key compromise can control staging
  containers; an SSH-key compromise alone cannot authorize an unsigned bundle.
- Debian packages installed in the runtime stage still come from the current Bookworm
  repository even though base images are digest-pinned. The promoted GHCR digest is
  immutable, but a future rebuild of the same source may differ until an apt snapshot
  is introduced.
- Exact-run promotion artifacts are retained for 30 days. Deploying an older revision
  after expiry requires a fresh successful Backend CI run and promotion record.
- The 1 GiB server capacity and public-SSH attack surface require live observation;
  this adapter remains forbidden for production.

### Contract proposals and readiness

- Created CP-0011 for the protected CI/staging delivery change and ADR-0021 for its
  staging-only trust boundary.
- Code and local evidence are ready for branch review. First live deployment is not
  ready until provider-console bootstrap and GitHub Environment secrets are complete.

### Open questions

1. Can the operator provide an authenticated root console session and independently
   confirm the server Ed25519 host-key fingerprint?
2. Does the repository plan support required reviewers for the `staging` Environment,
   and who should be the reviewer?
3. What retention limit should replace indefinite staging image/release retention
   after the first rollback drill?
