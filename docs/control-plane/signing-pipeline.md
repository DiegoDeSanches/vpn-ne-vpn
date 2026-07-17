# Directory signing and publication pipeline

1. An operator authenticated on the dedicated admin mTLS ingress changes gateway,
   country, feature, version, incident, or revocation state.
2. `POST /admin/v1/directory-publications` reserves the next version under a
   PostgreSQL advisory transaction lock. The row is `draft` and cannot be served.
3. `PgDirectoryBuilder` reads only `directory_gateway_projection` plus the
   country/rule/flag/active-revocation allowlists. It produces bounded JCS input.
4. The publisher calls the separate signing workload ingress as
   `directory-publisher`. The signing process has an online intermediate only and
   a pre-provisioned root-signed trust bundle. It has no offline root capability.
5. The signing service enforces issue/expiry/version policy, signs exact bytes,
   and atomically changes only the matching draft to `published`. The prior
   published row becomes `superseded` in the same transaction.
6. The Onion-only directory service reads only the latest unexpired `published`
   envelope and returns its exact bytes. It cannot mutate or sign documents.

Production must replace the explicitly gated local seed adapter with Vault Transit
or an HSM/KMS backend that supports Ed25519, workload authentication, non-exportable
keys, audit without payload logging, and bounded backpressure. The local adapter
requires `OR_EXPERIMENTAL_LOCAL_SIGNER=1`, reads a seed from a file rather than an
environment variable, never accepts a root key, and is not production-approved.

Root ceremonies happen offline with two-person approval. They authorize a bounded
trust bundle, archive a public ceremony record and test vector, and return only the
signed public bundle to the online environment.
