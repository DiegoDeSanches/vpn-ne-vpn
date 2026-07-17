use std::fmt;

use crate::{CapabilityPolicy, GatewayRole, RegionSet, TokenError, TOKEN_VERSION_V1};

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct TokenId(pub(crate) [u8; 32]);

impl TokenId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TokenId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenId(<redacted>)")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityClaims {
    pub token_version: u16,
    pub token_id: TokenId,
    pub policy: CapabilityPolicy,
    pub not_before: i64,
    pub expires_at: i64,
    pub issuer_key_id: String,
    pub proof_of_possession_public_key: Option<[u8; 32]>,
}

impl CapabilityClaims {
    pub(crate) fn validate_shape(&self) -> Result<(), TokenError> {
        if self.token_version != TOKEN_VERSION_V1 {
            return Err(TokenError::UnsupportedVersion);
        }
        self.policy.validate_canonical()?;
        CapabilityPolicy::validate_window(self.not_before, self.expires_at)?;
        validate_key_id(&self.issuer_key_id)
    }
}

fn validate_key_id(key_id: &str) -> Result<(), TokenError> {
    if key_id.is_empty()
        || key_id.len() > 64
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(TokenError::InvalidKeyId);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueTokenRequest {
    pub policy: CapabilityPolicy,
    pub not_before: i64,
    pub expires_at: i64,
    pub proof_of_possession_public_key: Option<[u8; 32]>,
}

pub struct IssuedToken {
    encoded: Vec<u8>,
    pub not_before: i64,
    pub expires_at: i64,
}

impl IssuedToken {
    pub fn new(encoded: Vec<u8>, not_before: i64, expires_at: i64) -> Self {
        Self {
            encoded,
            not_before,
            expires_at,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.encoded
    }
}

impl fmt::Debug for IssuedToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedToken")
            .field("encoded", &"<redacted>")
            .field("not_before", &self.not_before)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerPublicKey {
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: i64,
    pub not_after: i64,
}

#[derive(Clone)]
pub struct ProofOfPossession {
    pub signature: Vec<u8>,
}

impl fmt::Debug for ProofOfPossession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProofOfPossession(<redacted>)")
    }
}

pub struct VerificationRequest {
    pub encoded_token: Vec<u8>,
    pub required_role: GatewayRole,
    pub gateway_region: RegionSet,
    pub now: i64,
    pub gateway_binding: [u8; 32],
    pub challenge: [u8; 32],
    pub proof_of_possession: Option<ProofOfPossession>,
}

impl fmt::Debug for VerificationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationRequest")
            .field("encoded_token", &"<redacted>")
            .field("required_role", &self.required_role)
            .field("gateway_region", &self.gateway_region)
            .field("now", &self.now)
            .field("gateway_binding", &"<redacted>")
            .field("challenge", &"<redacted>")
            .field("proof_of_possession", &self.proof_of_possession)
            .finish()
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SessionLease {
    pub(crate) token_id: TokenId,
    pub(crate) session_id: [u8; 32],
}

impl SessionLease {
    pub fn token_id(&self) -> TokenId {
        self.token_id
    }
}

impl fmt::Debug for SessionLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionLease(<redacted>)")
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedCapability {
    pub policy: CapabilityPolicy,
    pub expires_at: i64,
    pub lease: SessionLease,
}
