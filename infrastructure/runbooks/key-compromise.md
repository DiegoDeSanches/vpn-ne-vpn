# Key compromise runbook

Start with the fastest privacy action:

```text
python3 infrastructure/deploy/onionroute_deploy.py \
  --config /secure/change/current.json revoke NODE_ID
```

This publishes directory revocation first, revokes Vault leases/auth roles, then
isolates the instance through the provider API. It is idempotent and needs no SSH.
Target: directory publication within two minutes and provider/Vault isolation within
five minutes.

## Scope by key class

- **Onion service key:** revoke the descriptor/directory entry, disable the
  `-onion` auth role, create a fresh node and authorized-client material. Never reuse
  the onion address.
- **Gateway identity or mTLS:** revoke certificate/issuer serial and node directory
  pin, rotate only the affected trust domain, replace the node. Entry and exit CAs
  are independent.
- **Token signing:** stop issuance, revoke the token issuer key, wait at least the
  maximum token TTL, create a new KMS/Vault key and resume through a canary. Do not
  query account data from gateways.
- **Directory online intermediate:** freeze publication, revoke the intermediate
  using the offline root ceremony, distribute the pre-authorized successor and
  publish a higher sequence. Clients must never accept rollback.
- **Root directory key:** declare a critical incident, use the documented two-person
  offline recovery/next-root ceremony, ship a new signed trust policy/client release.
  Never import the root into an online system to accelerate recovery.
- **Monitoring/admin credential:** revoke its dedicated mount/SSH certificate and
  audit administrative actions. Monitoring compromise does not grant node secrets;
  admin certificates are short-lived and hardware-MFA issuance is mandatory.

Preserve disk snapshots only if incident response approves them; snapshots remain
encrypted by the node-specific KMS key and are never attached to another role.

