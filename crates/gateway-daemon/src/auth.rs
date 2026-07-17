//! Capability-token verification boundary.

use std::time::SystemTime;

use async_trait::async_trait;

use crate::{GatewayErrorCode, GatewayResult};

/// Request view passed to a verifier. It cannot be formatted with `Debug`, and
/// the daemon never persists either byte slice.
pub struct AuthenticationRequest<'a> {
    pub capability_token: &'a [u8],
    pub proof_of_possession: &'a [u8],
    pub now: SystemTime,
}

/// Limits cryptographically bound to an anonymous capability token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenLimits {
    pub max_sessions: usize,
    pub max_concurrent_streams: usize,
    pub connections_per_second: u32,
    pub connection_burst: u32,
    pub bytes_per_second: u64,
    pub bandwidth_burst_bytes: u64,
    pub total_bytes: u64,
}

/// Successful verification output. No account, device, payment, issuance, or
/// client-network identifier is allowed in this type.
#[derive(Clone, Debug)]
pub struct AuthenticationGrant {
    pub expires_at: SystemTime,
    pub capabilities: Vec<String>,
    pub limits: TokenLimits,
}

/// Offline verification interface owned by the auth-token integration. A
/// verifier failure is always a rejection; the gateway never calls an account
/// service or falls back to anonymous access.
#[async_trait]
pub trait AuthenticationVerifier: Send + Sync + 'static {
    async fn verify(
        &self,
        request: AuthenticationRequest<'_>,
    ) -> GatewayResult<AuthenticationGrant>;
}

/// Production-safe placeholder used until the reviewed token format is wired
/// in. It deliberately makes a misconfigured deployment unavailable.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAllAuthenticationVerifier;

#[async_trait]
impl AuthenticationVerifier for DenyAllAuthenticationVerifier {
    async fn verify(
        &self,
        _request: AuthenticationRequest<'_>,
    ) -> GatewayResult<AuthenticationGrant> {
        Err(GatewayErrorCode::AuthenticationUnavailable.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_token_integration_never_allows_anonymous_access() {
        let result = DenyAllAuthenticationVerifier
            .verify(AuthenticationRequest {
                capability_token: b"opaque",
                proof_of_possession: b"proof",
                now: SystemTime::now(),
            })
            .await;
        assert_eq!(
            result.err().unwrap().code,
            GatewayErrorCode::AuthenticationUnavailable
        );
    }
}
