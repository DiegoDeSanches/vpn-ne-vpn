# Backup and disaster recovery plan

## Data classes and objectives

| Data | Method | RPO | RTO |
|---|---|---:|---:|
| OpenTofu state | versioned, object-locked, KMS-encrypted remote backend copied to a separate admin project | 15 min | 2 h |
| Vault storage | encrypted Raft snapshot to isolated account; recovery shares offline | 1 h | 4 h |
| PostgreSQL control data | encrypted PITR plus daily cross-region copy; billing/account store remains separate | 5 min | 2 h |
| Directory inventory/sequence | signed append-only administrative record; offline latest-sequence copy | 1 min | 30 min |
| Images/SBOM/provenance | immutable registry/object lock with signed manifest | per release | 30 min |
| Metrics | optional 15-day aggregate retention; no user/destination data | 24 h | no recovery guarantee |

Onion and application private keys are restored only into the same role/node recovery
scope when continuity is explicitly required. Prefer new identities after compromise.
The offline root key is not part of automated backup; custodians test hardware and
documented successor material twice yearly.

## Restore order

1. Establish clean management identity with hardware MFA and verify time/KMS/audit.
2. Restore state and Vault into isolated recovery projects; compare checksums and
   policy scopes before network access.
3. Restore PostgreSQL PITR, run integrity and expand-only schema checks.
4. Rebuild nodes from signed images; never restore mutable root disks as production.
5. Restore the highest directory sequence, revoke identities of lost nodes, publish
   fresh short-expiry directory data, then add gateways by canary.
6. Validate leak tests, emergency revoke and rollback before lifting disaster mode.

Quarterly tests restore into non-routable projects, rotate all test credentials, and
measure RPO/RTO. Evidence contains administrative object IDs and checksums only.

