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
