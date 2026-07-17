//! Experimental OnionRoute capability credentials.
//!
//! This crate is intentionally data-plane safe: it has no account, billing,
//! payment, order, e-mail, or persistent device types. Account-plane adapters
//! live in `services/token-service` and pass only a canonical anonymous policy
//! to [`TokenIssuer`].

mod codec;
mod error;
mod issuer;
mod policy;
mod replay;
mod revocation;
mod types;
mod verifier;
mod wire;

pub use error::{RevocationUpdateError, TokenError, TokenStoreError};
pub use issuer::{LocalEd25519TokenIssuer, TokenIssuer};
pub use policy::{
    BandwidthClass, CapabilityPolicy, ConnectionLimits, DeviceSlotClass, GatewayRole, PlanClass,
    RegionSet,
};
pub use replay::{InMemoryTokenStore, TokenReservation, TokenStore};
pub use revocation::{
    InMemoryRevocationProvider, RevocationProvider, RevocationSnapshot, RevocationStatus,
};
pub use types::{
    CapabilityClaims, IssueTokenRequest, IssuedToken, IssuerPublicKey, ProofOfPossession,
    SessionLease, TokenId, VerificationRequest, VerifiedCapability,
};
pub use verifier::{LocalTokenVerifier, TokenVerifier, VerifierConfig};

pub const TOKEN_VERSION_V1: u16 = 1;
pub const MAX_TOKEN_BYTES: usize = 4 * 1024;
pub const TOKEN_ID_LENGTH: usize = 32;
pub const POP_PUBLIC_KEY_LENGTH: usize = 32;
pub const SIGNATURE_LENGTH: usize = 64;
pub const TOKEN_BUCKET_SECONDS: i64 = 5 * 60;
pub const TOKEN_TTL_SECONDS: i64 = 15 * 60;

/// Creates the exact domain-separated byte string an MVP client signs for
/// proof of possession. `gateway_binding` is the gateway identity/key digest;
/// `challenge` must be freshly generated for each authentication attempt.
pub fn proof_of_possession_message(
    token_id: TokenId,
    gateway_binding: [u8; 32],
    challenge: [u8; 32],
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"onionroute-pop-v1\0";
    let mut message = Vec::with_capacity(DOMAIN.len() + 96);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(token_id.as_bytes());
    message.extend_from_slice(&gateway_binding);
    message.extend_from_slice(&challenge);
    message
}

/// Parses and validates the bounded canonical wire shape without accepting the
/// token. This exists for fuzzing and diagnostics; only [`TokenVerifier::verify`]
/// authorizes a session.
pub fn validate_wire_format(encoded: &[u8]) -> Result<(), TokenError> {
    codec::decode_token(encoded).map(|_| ())
}

/// Extracts the random token ID needed to construct a PoP message. This does
/// not authenticate the token and must not be used as an authorization result.
pub fn unverified_token_id_for_proof(encoded: &[u8]) -> Result<TokenId, TokenError> {
    codec::decode_token(encoded).map(|decoded| decoded.claims.token_id)
}
