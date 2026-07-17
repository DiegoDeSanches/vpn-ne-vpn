use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::codec::decode_token;
use crate::{
    proof_of_possession_message, IssuerPublicKey, RevocationProvider, RevocationStatus, TokenError,
    TokenReservation, TokenStore, TokenStoreError, VerificationRequest, VerifiedCapability,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifierConfig {
    pub require_proof_of_possession: bool,
    pub maximum_clock_skew_seconds: i64,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            require_proof_of_possession: true,
            maximum_clock_skew_seconds: 30,
        }
    }
}

#[async_trait]
pub trait TokenVerifier: Send + Sync + 'static {
    async fn verify(&self, request: VerificationRequest) -> Result<VerifiedCapability, TokenError>;
}

/// Offline signature/scope verifier plus an anonymous replay-store reservation.
/// Public issuer keys and revocation snapshots are local data; no account-plane
/// lookup occurs on the gateway authentication path.
pub struct LocalTokenVerifier<S, R> {
    keys: HashMap<String, IssuerPublicKey>,
    store: Arc<S>,
    revocations: Arc<R>,
    config: VerifierConfig,
}

impl<S, R> LocalTokenVerifier<S, R>
where
    S: TokenStore,
    R: RevocationProvider,
{
    pub fn new(
        keys: impl IntoIterator<Item = IssuerPublicKey>,
        store: Arc<S>,
        revocations: Arc<R>,
        config: VerifierConfig,
    ) -> Result<Self, TokenError> {
        if config.maximum_clock_skew_seconds < 0 || config.maximum_clock_skew_seconds > 120 {
            return Err(TokenError::InvalidTimeWindow);
        }
        let mut key_map = HashMap::new();
        for key in keys {
            if key.key_id.is_empty() || key_map.insert(key.key_id.clone(), key).is_some() {
                return Err(TokenError::InvalidKeyId);
            }
        }
        Ok(Self {
            keys: key_map,
            store,
            revocations,
            config,
        })
    }

    pub async fn release(&self, capability: VerifiedCapability) -> Result<(), TokenError> {
        self.store
            .release(capability.lease)
            .await
            .map_err(map_store_error)
    }
}

#[async_trait]
impl<S, R> TokenVerifier for LocalTokenVerifier<S, R>
where
    S: TokenStore,
    R: RevocationProvider,
{
    async fn verify(&self, request: VerificationRequest) -> Result<VerifiedCapability, TokenError> {
        let decoded = decode_token(&request.encoded_token)?;
        let claims = decoded.claims;
        let clock_skew = self.config.maximum_clock_skew_seconds;
        if request.now.saturating_add(clock_skew) < claims.not_before {
            return Err(TokenError::NotYetValid);
        }
        // Expiry is strict: clock skew can make activation slightly early but
        // can never extend a stolen credential beyond its signed expiry.
        if request.now >= claims.expires_at {
            return Err(TokenError::Expired);
        }

        let key = self
            .keys
            .get(&claims.issuer_key_id)
            .ok_or(TokenError::UnknownIssuerKey)?;
        if claims.not_before < key.not_before || claims.expires_at > key.not_after {
            return Err(TokenError::IssuerKeyOutsideValidity);
        }
        let verifying_key =
            VerifyingKey::from_bytes(&key.public_key).map_err(|_| TokenError::InvalidSignature)?;
        let signature = Signature::from_bytes(&decoded.signature);
        verifying_key
            .verify_strict(&decoded.claims_bytes, &signature)
            .map_err(|_| TokenError::InvalidSignature)?;

        match self
            .revocations
            .status(&claims.issuer_key_id, claims.token_id, request.now)
        {
            RevocationStatus::Active => {}
            RevocationStatus::Revoked => return Err(TokenError::Revoked),
            RevocationStatus::SnapshotStale => return Err(TokenError::RevocationDataStale),
        }
        if !claims.policy.role_allowed(request.required_role) {
            return Err(TokenError::RoleNotAllowed);
        }
        if !claims.policy.region_set.allows(request.gateway_region) {
            return Err(TokenError::RegionNotAllowed);
        }

        match (
            claims.proof_of_possession_public_key,
            request.proof_of_possession,
        ) {
            (Some(public_key), Some(proof)) => {
                let proof_signature = Signature::from_slice(&proof.signature)
                    .map_err(|_| TokenError::InvalidProofOfPossession)?;
                let proof_key = VerifyingKey::from_bytes(&public_key)
                    .map_err(|_| TokenError::InvalidProofOfPossession)?;
                let message = proof_of_possession_message(
                    claims.token_id,
                    request.gateway_binding,
                    request.challenge,
                );
                proof_key
                    .verify_strict(&message, &proof_signature)
                    .map_err(|_| TokenError::InvalidProofOfPossession)?;
            }
            (Some(_), None) | (None, _) if self.config.require_proof_of_possession => {
                return Err(TokenError::ProofOfPossessionRequired)
            }
            (Some(_), None) | (None, Some(_)) | (None, None) => {}
        }

        let mut hasher = Sha256::new();
        hasher.update(b"onionroute-session-lease-v1\0");
        hasher.update(claims.token_id.as_bytes());
        hasher.update(request.gateway_binding);
        hasher.update(request.challenge);
        let session_id: [u8; 32] = hasher.finalize().into();
        let lease = self
            .store
            .reserve(TokenReservation {
                token_id: claims.token_id,
                session_id,
                now: request.now,
                expires_at: claims.expires_at,
                max_active_sessions: claims.policy.connection_limits.max_active_sessions,
            })
            .await
            .map_err(map_store_error)?;

        Ok(VerifiedCapability {
            policy: claims.policy,
            expires_at: claims.expires_at,
            lease,
        })
    }
}

fn map_store_error(error: TokenStoreError) -> TokenError {
    match error {
        TokenStoreError::AlreadyReserved => TokenError::ReplayDetected,
        TokenStoreError::LimitReached => TokenError::ConnectionLimitReached,
        TokenStoreError::Unavailable => TokenError::ReplayProtectionUnavailable,
    }
}
