# OnionRoute auth tokens (experimental)

This standalone crate implements the anonymous data-plane credential boundary
proposed in `docs/contract-proposals/CP-0007-auth-token-v1.md`.

- Ed25519 signatures are provided by `ed25519-dalek`; there is no custom crypto.
- The signed claims contain no account, payment, order, e-mail, or device ID.
- Policies are coarse canonical profiles and expiry uses fixed buckets.
- Gateways verify signatures and cached revocation material locally.
- New sessions reserve an anonymous token/session tuple through `TokenStore`.
- MVP verification requires proof of possession by default.

`InMemoryTokenStore` and `LocalEd25519TokenIssuer` are development/test
implementations. Production requires a linearizable shared token store and an
HSM/KMS-backed issuer.

Run:

```text
cargo test --manifest-path crates/auth-tokens/Cargo.toml
cargo fuzz run --manifest-path crates/auth-tokens/fuzz/Cargo.toml token_decode
```
