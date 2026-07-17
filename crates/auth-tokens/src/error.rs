use thiserror::Error;

/// Closed, non-sensitive errors safe to map to coarse gateway failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TokenError {
    #[error("token input exceeds the configured limit")]
    InputTooLarge,
    #[error("token wire encoding is invalid")]
    InvalidEncoding,
    #[error("unsupported token version")]
    UnsupportedVersion,
    #[error("token policy is not one of the canonical policy profiles")]
    NonCanonicalPolicy,
    #[error("token time window is invalid")]
    InvalidTimeWindow,
    #[error("token is not valid yet")]
    NotYetValid,
    #[error("token has expired")]
    Expired,
    #[error("issuer key identifier is invalid")]
    InvalidKeyId,
    #[error("issuer key is unknown")]
    UnknownIssuerKey,
    #[error("issuer key is not valid for the complete token window")]
    IssuerKeyOutsideValidity,
    #[error("token signature is invalid")]
    InvalidSignature,
    #[error("token is revoked")]
    Revoked,
    #[error("local revocation data is stale")]
    RevocationDataStale,
    #[error("gateway role is outside token scope")]
    RoleNotAllowed,
    #[error("gateway region is outside token scope")]
    RegionNotAllowed,
    #[error("proof of possession is required")]
    ProofOfPossessionRequired,
    #[error("proof of possession is invalid")]
    InvalidProofOfPossession,
    #[error("secure random generation failed")]
    RandomnessUnavailable,
    #[error("token replay was detected")]
    ReplayDetected,
    #[error("anonymous session limit was reached")]
    ConnectionLimitReached,
    #[error("replay protection is unavailable")]
    ReplayProtectionUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TokenStoreError {
    #[error("the same redemption was already accepted")]
    AlreadyReserved,
    #[error("the token has reached its active session limit")]
    LimitReached,
    #[error("the token store is unavailable")]
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RevocationUpdateError {
    #[error("local revocation snapshot lock is unavailable")]
    LockUnavailable,
}
