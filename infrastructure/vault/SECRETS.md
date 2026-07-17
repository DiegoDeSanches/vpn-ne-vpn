# Secret delivery contract

Vault is the online secret broker. AWS IAM and GCP GCE auth bind an immutable
instance identity to one exact node scope, `kv/data/nodes/<node-id>`. AppRole,
cloud-init tokens, static Vault tokens and secret values in OpenTofu are forbidden.
The base Vault auth role name and node name must exactly match the OpenTofu inventory;
the onion role is the same name with `-onion` appended.

Each node has two auth roles. `<vault_auth_role>` can read only application paths;
`<vault_auth_role>-onion` can read only `onion-service` and `onion-management`.
Tokens have a two-minute maximum TTL, are non-renewable, and have no default policy.
Vault Agent re-authenticates with workload identity; disabling the node's unique auth
role therefore bounds a stolen token after emergency revocation. Audit devices record
auth/policy/admin operations, never rendered secret values.

`configure-node-roles.sh` renders one app policy and one onion policy, then creates
machine-oriented batch-token roles bound to the exact AWS role ARN or GCP service
account. It requires a short-lived administrative Vault session and does not accept
or print secret values.

Choose exactly one application policy template matching the role; never combine the
gateway, token, signing and monitoring templates. Render `NODE_SCOPE` to the exact
node scope before applying it. Monitoring uses the dedicated monitoring onion policy;
all other roles use the generic node onion policy.

| Secret class | Path suffix | Fields | Reader | Rotation |
|---|---|---|---|---|
| Onion service key | `onion-service` | complete Tor key files as base64, hostname, one authorized-client line | `debian-tor` agent only | make-before-break directory update |
| Management onion key | `onion-management` | same closed fields | `debian-tor` agent only | independent from data onion |
| Gateway identity | `gateway-identity` | `certificate`, `private_key` | entry/exit service group | before certificate expiry |
| Inter-gateway mTLS | `mtls` | `certificate`, `private_key` | entry/relay/exit or control service group | short-lived certificate |
| Directory online signing | `directory-online-signing` | `private_key` or transit key reference, RFC3339 `expires_at` | signing service only | cross-signed rotation |
| Token signing | `token-signing` | `private_key` or transit key reference, RFC3339 `expires_at` | token service only | token-TTL overlap |
| Monitoring | `monitoring` | `credential`, RFC3339 `expires_at` | monitoring/health role only | 30 days maximum |
| Monitoring onion auth | `monitoring-onion-client` | one Tor client-auth private line | monitoring Tor agent only | after any monitoring compromise |
| Admin | Vault SSH secrets engine | signed SSH certificate only; no stored host password | operator after hardware-MFA login | 15 minutes maximum |

The directory root signing key is generated and retained offline on two-person
controlled hardware. It is never imported into Vault, cloud KMS, a node image,
backup automation, or OpenTofu state. Online directory signatures use a constrained
intermediate. Token and directory signing keys never share a KMS/Vault mount.

Backups contain encrypted Vault storage snapshots and key metadata. Unseal/recovery
material is split across offline custodians. Restore tests use a separate recovery
cluster and never copy production admin credentials.
