# ADR-0012: immutable multi-provider platform with identity-based secret delivery

- Status: Proposed, experimental
- Date: 2026-07-17

## Context

Entry and exit compromise must not expose the same provider administration, keys or
management credentials. Runtime secret bootstrap cannot place a token in cloud-init,
OpenTofu state or an image. Deployment must drain and revoke gateways without public
SSH while preserving signed-directory rollback protection.

## Decision

Use AWS and GCP as the initial independent provider/ASN domains and enforce separation
with OpenTofu checks. Build role-specific immutable Debian 12 images from pinned
snapshots through private builders. Nodes have no public address or ingress and expose
data/operations only as Tor v3 onion services. Provider workload identity authenticates
two least-privilege Vault agents: application and onion-key delivery.

Use default-deny nftables plus systemd/AppArmor boundaries. Deployment verifies signed
release/image evidence, performs directory draining, health-gated canary/waves and
automatic rollback. The root directory signing key remains offline; online directory
and token keys are separate. Central monitoring accepts only fixed aggregate/bucket
metrics and never IPs, destinations or arbitrary labels.

## Consequences

- Provider NAT and management/onion control remain required even though nodes have no
  ingress. Workload metadata is a narrow exception available only to secret agents.
- Immutable security updates replace nodes; packages do not mutate in place.
- Production readiness depends on reviewed directory, lifecycle, health and cloud
  isolation adapters, staging approval of the Vault-revoke adapter, and role
  binaries/config contracts not yet present.
- Direct entry/relay/exit transport reachability remains a protocol-owner integration;
  infrastructure will not invent or weaken that interface.

## Verification

Static tests reject secrets, public addresses/listeners, cross-role scopes and privacy-
unsafe monitoring. Image builds run nft/AppArmor/systemd/config checks. Staging tests
inject canary failure, Vault outage, directory outage, clock drift and revocation, and
assert fail-closed rollback without public SSH.
