use std::fmt;

use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::codec::{claims_signing_bytes, encode_token};
use crate::{
    CapabilityClaims, IssueTokenRequest, IssuedToken, IssuerPublicKey, TokenError, TokenId,
    TOKEN_ID_LENGTH, TOKEN_VERSION_V1,
};

/// Account-free issuance boundary. Implementations may delegate signing to an
/// HSM/KMS; account and billing identifiers must never be added to this call.
#[async_trait]
pub trait TokenIssuer: Send + Sync + 'static {
    async fn issue(&self, request: IssueTokenRequest) -> Result<IssuedToken, TokenError>;
}

/// Experimental local Ed25519 issuer. Production deployments should inject the
/// same interface backed by a non-exportable online signing key.
pub struct LocalEd25519TokenIssuer {
    key_id: String,
    signing_key: SigningKey,
    key_not_before: i64,
    key_not_after: i64,
}

impl LocalEd25519TokenIssuer {
    pub fn from_secret_bytes(
        key_id: impl Into<String>,
        secret_key: [u8; 32],
        key_not_before: i64,
        key_not_after: i64,
    ) -> Result<Self, TokenError> {
        let key_id = key_id.into();
        let probe = CapabilityClaims {
            token_version: TOKEN_VERSION_V1,
            token_id: TokenId::from_bytes([0; TOKEN_ID_LENGTH]),
            policy: crate::CapabilityPolicy::canonical(
                crate::PlanClass::Basic,
                crate::RegionSet::Europe,
                crate::GatewayRole::Exit,
            )?,
            not_before: 0,
            expires_at: crate::TOKEN_TTL_SECONDS,
            issuer_key_id: key_id.clone(),
            proof_of_possession_public_key: None,
        };
        probe.validate_shape()?;
        if key_not_before < 0 || key_not_after <= key_not_before {
            return Err(TokenError::IssuerKeyOutsideValidity);
        }
        Ok(Self {
            key_id,
            signing_key: SigningKey::from_bytes(&secret_key),
            key_not_before,
            key_not_after,
        })
    }

    pub fn public_key(&self) -> IssuerPublicKey {
        IssuerPublicKey {
            key_id: self.key_id.clone(),
            public_key: self.signing_key.verifying_key().to_bytes(),
            not_before: self.key_not_before,
            not_after: self.key_not_after,
        }
    }
}

impl fmt::Debug for LocalEd25519TokenIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalEd25519TokenIssuer")
            .field("key_id", &self.key_id)
            .field("signing_key", &"<redacted>")
            .field("key_not_before", &self.key_not_before)
            .field("key_not_after", &self.key_not_after)
            .finish()
    }
}

#[async_trait]
impl TokenIssuer for LocalEd25519TokenIssuer {
    async fn issue(&self, request: IssueTokenRequest) -> Result<IssuedToken, TokenError> {
        request.policy.validate_canonical()?;
        crate::CapabilityPolicy::validate_window(request.not_before, request.expires_at)?;
        if request.not_before < self.key_not_before || request.expires_at > self.key_not_after {
            return Err(TokenError::IssuerKeyOutsideValidity);
        }
        if let Some(public_key) = request.proof_of_possession_public_key {
            VerifyingKey::from_bytes(&public_key)
                .map_err(|_| TokenError::InvalidProofOfPossession)?;
        }

        let mut token_id = [0u8; TOKEN_ID_LENGTH];
        getrandom::getrandom(&mut token_id).map_err(|_| TokenError::RandomnessUnavailable)?;
        let claims = CapabilityClaims {
            token_version: TOKEN_VERSION_V1,
            token_id: TokenId::from_bytes(token_id),
            policy: request.policy,
            not_before: request.not_before,
            expires_at: request.expires_at,
            issuer_key_id: self.key_id.clone(),
            proof_of_possession_public_key: request.proof_of_possession_public_key,
        };
        let signing_bytes = claims_signing_bytes(&claims)?;
        let signature = self.signing_key.sign(&signing_bytes).to_bytes();
        let encoded = encode_token(&claims, signature)?;
        Ok(IssuedToken::new(
            encoded,
            claims.not_before,
            claims.expires_at,
        ))
    }
}
