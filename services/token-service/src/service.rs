use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use onionroute_auth_tokens::{
    CapabilityPolicy, IssueTokenRequest, TokenIssuer, TOKEN_BUCKET_SECONDS, TOKEN_TTL_SECONDS,
};

use crate::{
    AuthenticatedAccountContext, BillingAdapterError, BillingEntitlementProvider, DeviceSlotError,
    DeviceSlotManager, EntitlementStatus, MintTokenBatchRequest, MintTokenBatchResponse,
    TokenServiceError, MAX_TOKEN_BATCH_SIZE,
};

pub struct TokenService<I, B, D> {
    issuer: Arc<I>,
    billing: Arc<B>,
    device_slots: Arc<D>,
}

impl<I, B, D> TokenService<I, B, D>
where
    I: TokenIssuer,
    B: BillingEntitlementProvider,
    D: DeviceSlotManager,
{
    pub fn new(issuer: Arc<I>, billing: Arc<B>, device_slots: Arc<D>) -> Self {
        Self {
            issuer,
            billing,
            device_slots,
        }
    }

    pub async fn mint_batch(
        &self,
        context: AuthenticatedAccountContext,
        request: MintTokenBatchRequest,
    ) -> Result<MintTokenBatchResponse, TokenServiceError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TokenServiceError::EntitlementUnavailable)?;
        let now =
            i64::try_from(now.as_secs()).map_err(|_| TokenServiceError::EntitlementUnavailable)?;
        self.mint_batch_at(context, request, now).await
    }

    /// `now` must come from the server clock. It is explicit for deterministic
    /// tests and must never be populated from the public request body.
    pub async fn mint_batch_at(
        &self,
        context: AuthenticatedAccountContext,
        request: MintTokenBatchRequest,
        now: i64,
    ) -> Result<MintTokenBatchResponse, TokenServiceError> {
        if now < 0
            || request.proof_of_possession_public_keys.is_empty()
            || request.proof_of_possession_public_keys.len() > MAX_TOKEN_BATCH_SIZE
        {
            return Err(TokenServiceError::InvalidRequest);
        }
        let entitlement = self
            .billing
            .entitlement_for(&context.account_ref, now)
            .await
            .map_err(map_billing_error)?;
        if entitlement.status != EntitlementStatus::Active || entitlement.valid_until <= now {
            return Err(TokenServiceError::NotEntitled);
        }

        let not_before = now - now.rem_euclid(TOKEN_BUCKET_SECONDS);
        let expires_at = not_before
            .checked_add(TOKEN_TTL_SECONDS)
            .ok_or(TokenServiceError::InvalidRequest)?;
        if entitlement.valid_until < expires_at {
            return Err(TokenServiceError::EntitlementEndsBeforeTokenWindow);
        }
        let policy = CapabilityPolicy::canonical(
            entitlement.plan_class,
            entitlement.region_set,
            request.gateway_role,
        )
        .map_err(|_| TokenServiceError::NotEntitled)?;
        self.device_slots
            .authorize_slot(
                &context.account_ref,
                request.installation_ref,
                policy.device_slot_class,
            )
            .await
            .map_err(map_device_error)?;

        let mut tokens = Vec::with_capacity(request.proof_of_possession_public_keys.len());
        for proof_key in request.proof_of_possession_public_keys {
            let token = self
                .issuer
                .issue(IssueTokenRequest {
                    policy: policy.clone(),
                    not_before,
                    expires_at,
                    proof_of_possession_public_key: Some(proof_key),
                })
                .await
                .map_err(|_| TokenServiceError::IssuerUnavailable)?;
            tokens.push(token);
        }
        Ok(MintTokenBatchResponse {
            tokens,
            not_before,
            expires_at,
        })
    }
}

fn map_billing_error(error: BillingAdapterError) -> TokenServiceError {
    match error {
        BillingAdapterError::Unavailable => TokenServiceError::EntitlementUnavailable,
        BillingAdapterError::NotFound => TokenServiceError::NotEntitled,
    }
}

fn map_device_error(error: DeviceSlotError) -> TokenServiceError {
    match error {
        DeviceSlotError::LimitReached => TokenServiceError::DeviceSlotLimitReached,
        DeviceSlotError::Unavailable => TokenServiceError::DeviceSlotServiceUnavailable,
    }
}
