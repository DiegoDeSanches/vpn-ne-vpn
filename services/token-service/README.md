# OnionRoute token service (experimental)

This service is the account-plane side of capability issuance. Authentication
middleware supplies `AuthenticatedAccountContext`; the public mint request has
no account field. `BillingEntitlementProvider` and `DeviceSlotManager` may see
account-local identifiers, while `TokenIssuer` receives only:

- one coarse canonical policy;
- one standard 15-minute validity window;
- one ephemeral proof-of-possession public key.

`MockBillingAdapter` is intentionally not a payment-provider implementation.
Production adapters must keep payment identifiers in their private storage and
return only `BillingEntitlement`.

The protobuf candidate is under `api/` until CP-0007 is accepted. The service is
standalone and does not change the protected root workspace or `proto/` tree.
