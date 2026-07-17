# Account plane and anonymous data plane

## Security objective

The control plane may authenticate an account and evaluate subscription state.
The data plane authorizes only a short-lived random capability. A gateway must
not receive or be able to derive e-mail, name, payment/order/account ID, or a
persistent device ID from the credential schema or verification API.

This is data minimization, not a claim of absolute anonymity. Timing,
high-cardinality policy, client compromise, and collusion can still reduce an
anonymity set and are handled as explicit threats.

## Dependency boundary

```text
account authentication middleware
  -> BillingEntitlementProvider(account_ref)
  -> DeviceSlotManager(account_ref, installation_ref)
  -> canonical anonymous policy
  -> TokenIssuer(policy, bucket, ephemeral PoP key)
  -> opaque credential batch

later, over the tunnel:

client -> gateway -> TokenVerifier(public keys, local revocations, TokenStore)
```

`crates/auth-tokens` deliberately defines no identity-bearing type. Account and
installation references exist only in `services/token-service`. The account is
middleware context and is absent from the public mint request body.

## MVP signed token

The maximum envelope size is 4096 bytes. The signature covers the exact
canonical protobuf bytes of all claims.

| Field | MVP representation | Privacy/validation rule |
|---|---|---|
| token version | `1` | reject all unknown versions |
| random token ID | 32 random bytes | unique per token; never an account-derived value |
| plan class | Basic / Plus / Premium | coarse class only |
| allowed gateway roles | exactly one of entry / relay / exit | role must be plan-permitted; fresh token per hop |
| countries/regions | Europe / Americas / Asia-Pacific / Global | no arbitrary per-account country lists |
| device slot class | Single / Personal / Family | class only; no device ID |
| bandwidth class | Standard / Fast / Priority | gateway maps class to operational limits |
| connection limits | one of three canonical tuples | verifier rejects custom combinations |
| not before / expires at | 5-minute start bucket, exact 15-minute TTL | common expiry cohort |
| issuer key ID | bounded common rotation ID | 1..64 safe ASCII characters |
| PoP public key | 32-byte Ed25519 key | optional on wire; mandatory in MVP policy; fresh per token |
| signature | 64-byte Ed25519 signature | standard library; online issuer key only |

The plan fixes device, bandwidth and connection limits. Region and hop role add
only small, operationally necessary partitions. A batch has one policy, role,
not-before and expiry; only token IDs and ephemeral PoP public keys differ.

## Issuance path

1. Control middleware authenticates the account outside the protobuf message.
2. `BillingEntitlementProvider` returns `Active/Inactive`, coarse plan/region,
   and an entitlement end time. Payment-provider objects never cross the
   adapter.
3. `DeviceSlotManager` checks a control-only installation reference against the
   plan's coarse slot class.
4. The service rounds server time to the standard bucket and refuses issuance
   if the subscription does not cover the complete token window.
5. It sends an account-free `IssueTokenRequest` to `TokenIssuer` for each
   ephemeral PoP key. Batch size is 1..8.
6. The service returns opaque credentials. It must not persist a mapping from
   account/batch request to token ID.

Billing or slot-provider failure denies new issuance. Already issued tokens
remain useful only inside their signed window.

## Redemption path

1. Gateway supplies a fresh 32-byte challenge and its directory identity/key
   digest as `gateway_binding`.
2. Client signs the domain-separated token ID + binding + challenge using the
   token's ephemeral PoP private key.
3. Gateway locally validates bounded/canonical encoding, time, role, region,
   key validity, signature, cached revocation snapshot and PoP.
4. Only after cryptographic checks, the gateway atomically reserves an
   anonymous session in `TokenStore`.
5. The resulting grant exposes policy, expiry and an opaque release lease; it
   contains no account-plane handle.

## Storage and logging

Separate IAM, database credentials, deployments and telemetry pipelines are
required for account data, issuance, anonymous replay state and gateway
traffic. Forbidden in normal logs/traces/metrics:

- raw tokens, token IDs, PoP keys/proofs and gateway challenges;
- account or installation references;
- destination domains/addresses and traffic contents;
- a correlation/request ID copied from issuance into redemption;
- labels derived from token IDs, accounts or destinations.

Allowed metrics are aggregate counters by coarse plan, region, role and error
class, with cardinality budgets and no shared billing analytics pipeline.

## Privacy properties and limitations

The gateway schema has no account join key, and local verification needs no
account service. The MVP is not cryptographically unlinkable from its issuer:
a malicious/co-located token service could observe response bytes or correlate
issuance/redemption timing. Batching, bucketed expiry, strict logging separation
and using the tunnel for redemption reduce this risk; blind issuance is the
required next stage.
