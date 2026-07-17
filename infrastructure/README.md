# OnionRoute platform baseline

Status: experimental, fail-closed infrastructure baseline. The private exit role is
wired to the existing gateway daemon contract. Other service binaries and the
production directory/lifecycle/health/cloud adapters remain integration dependencies; their
units intentionally stay unhealthy when an artifact, config or secret is missing.

## Security model

- AWS and GCP are separate provider/ASN/admin trust domains. OpenTofu rejects an
  entry/exit overlap and gives every node a separate disk KMS key, workload identity,
  Vault scope and management trust domain.
- Nodes have no public address or ingress rule. Image builds use AWS Session Manager
  or GCP IAP; deployment uses provider and authenticated onion APIs. SSH is disabled
  by default and, for break-glass use, listens only on an authenticated management
  onion with a 15-minute Vault-signed certificate.
- Images are immutable and built from pinned Debian snapshots/base image IDs. A
  signed release manifest, SBOM and provenance are checked before image creation,
  again at service start, and the signed Packer manifest is checked before deploy.
- nftables is default-deny for input/output/forward. IPv6, arbitrary UDP, private,
  metadata, management, SMTP/25 and dangerous service destinations are blocked.
  Workload metadata is reachable only by secret agents; the Tor service cgroup has
  a second metadata deny.
- Application, onion, mTLS, directory, token, monitoring and admin credentials use
  different Vault paths/readers. The root directory key is offline only.
- Exact session and bandwidth values remain loopback-local. The central monitoring
  path exposes only buckets and fixed-label operational metrics.

## Layout

- `opentofu/`: two-provider private networks, workload identities, per-node disks
  and topology assertions. State uses an encrypted/locked remote backend supplied
  at init; no secret variable exists.
- `images/`: Packer pipeline using private builders, signed manifests, SBOM and
  provenance.
- `ansible/`, `systemd/`, `nftables/`: role image, hardening and runtime policy.
- `vault/`: secret contract and least-privilege policy templates.
- `deploy/`: canary, drain, health gate, expand-only migration check, automatic
  rollback and emergency revocation orchestration.
- `monitoring/`: Prometheus allow-list, alerts and Grafana provisioning.
- `runbooks/`: deployment, rollback, controlled security updates, compromise,
  region onboarding and DR.

## Reproducible workflow

1. Produce role binaries/configs in a clean release directory. Never put credentials
   there. Set reviewed `SOURCE_REVISION`, immutable `BUILDER_ID` and a KMS-backed
   `COSIGN_KEY_REF`, then run `images/build-image.sh RELEASE_DIR VERSION PACKER_VARS`
   in a Linux builder with short-lived cloud identity.
2. Copy `opentofu/backend.tfbackend.example` outside Git, configure the encrypted
   remote state backend, then run `tofu init -backend-config=...` and `tofu validate`.
3. Create canary/rollout/rollback tfvars from the same reviewed inventory change.
   Run `deploy/onionroute_deploy.py --config ... deploy`.
4. The controller drains each node through the directory adapter, waits for bucket
   zero, applies the signed image, checks Tor/onion/error/key/clock health, observes
   the canary, then proceeds. Any failure revokes and rolls back.

Package security updates are automatic at the image-pipeline level, not by mutating
running nodes: a scheduled rebuild pins the new Debian snapshot, runs the same
verification, canaries one role/provider, then rolls out in bounded waves. Emergency
live package installation is prohibited; isolate and replace the node.
