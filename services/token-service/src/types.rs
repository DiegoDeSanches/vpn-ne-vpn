use std::fmt;

use onionroute_auth_tokens::{GatewayRole, IssuedToken, PlanClass, RegionSet};

use crate::TokenServiceError;

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct AccountRef(String);

impl AccountRef {
    pub fn new(value: impl Into<String>) -> Result<Self, TokenServiceError> {
        let value = value.into();
        if value.is_empty() || value.len() > 256 {
            return Err(TokenServiceError::InvalidRequest);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for AccountRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountRef(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct InstallationRef([u8; 32]);

impl InstallationRef {
    pub fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl fmt::Debug for InstallationRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstallationRef(<redacted>)")
    }
}

/// Produced by account authentication middleware, not decoded from the mint
/// request body. It is consumed only by account-plane providers.
#[derive(Clone)]
pub struct AuthenticatedAccountContext {
    pub(crate) account_ref: AccountRef,
}

impl AuthenticatedAccountContext {
    pub fn new(account_ref: AccountRef) -> Self {
        Self { account_ref }
    }
}

impl fmt::Debug for AuthenticatedAccountContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedAccountContext(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntitlementStatus {
    Active,
    Inactive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BillingEntitlement {
    pub status: EntitlementStatus,
    pub plan_class: PlanClass,
    pub region_set: RegionSet,
    pub valid_until: i64,
}

#[derive(Clone, Debug)]
pub struct MintTokenBatchRequest {
    pub installation_ref: InstallationRef,
    /// All credentials in this batch are scoped to this one hop role.
    pub gateway_role: GatewayRole,
    /// One ephemeral Ed25519 public key per requested credential.
    pub proof_of_possession_public_keys: Vec<[u8; 32]>,
}

pub struct MintTokenBatchResponse {
    pub tokens: Vec<IssuedToken>,
    pub not_before: i64,
    pub expires_at: i64,
}

impl fmt::Debug for MintTokenBatchResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MintTokenBatchResponse")
            .field(
                "tokens",
                &format_args!("<redacted; count={}>", self.tokens.len()),
            )
            .field("not_before", &self.not_before)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}
