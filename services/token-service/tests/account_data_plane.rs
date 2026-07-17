use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use onionroute_auth_tokens::{
    proof_of_possession_message, unverified_token_id_for_proof, GatewayRole,
    InMemoryRevocationProvider, InMemoryTokenStore, LocalEd25519TokenIssuer, LocalTokenVerifier,
    PlanClass, ProofOfPossession, RegionSet, RevocationSnapshot, TokenVerifier,
    VerificationRequest, VerifierConfig, TOKEN_BUCKET_SECONDS, TOKEN_TTL_SECONDS,
};
use onionroute_token_service::{
    AccountRef, AuthenticatedAccountContext, BillingEntitlement, EntitlementStatus,
    InMemoryDeviceSlotManager, InstallationRef, MintTokenBatchRequest, MockBillingAdapter,
    TokenService, TokenServiceError,
};

const NOW: i64 = 1_800_000_123;

fn entitlement(status: EntitlementStatus) -> BillingEntitlement {
    BillingEntitlement {
        status,
        plan_class: PlanClass::Basic,
        region_set: RegionSet::Europe,
        valid_until: NOW + 86_400,
    }
}

fn account(value: &str) -> AccountRef {
    AccountRef::new(value).unwrap()
}

#[tokio::test]
async fn account_identity_stops_before_issuer_and_gateway() {
    let issuer = Arc::new(
        LocalEd25519TokenIssuer::from_secret_bytes(
            "token-2026-07-a",
            [0x31; 32],
            NOW - 3_600,
            NOW + 86_400,
        )
        .unwrap(),
    );
    let public_key = issuer.public_key();
    let billing = Arc::new(MockBillingAdapter::new_available());
    let sensitive_account = "account:customer-9843@example.invalid:payment-456";
    let account_ref = account(sensitive_account);
    billing
        .set_entitlement(account_ref.clone(), entitlement(EntitlementStatus::Active))
        .unwrap();
    let service = TokenService::new(
        issuer,
        billing.clone(),
        Arc::new(InMemoryDeviceSlotManager::default()),
    );
    let pop_key = SigningKey::from_bytes(&[0x42; 32]);
    let response = service
        .mint_batch_at(
            AuthenticatedAccountContext::new(account_ref),
            MintTokenBatchRequest {
                installation_ref: InstallationRef::from_bytes([8; 32]),
                gateway_role: GatewayRole::Exit,
                proof_of_possession_public_keys: vec![pop_key.verifying_key().to_bytes()],
            },
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(
        response.not_before,
        NOW - NOW.rem_euclid(TOKEN_BUCKET_SECONDS)
    );
    assert_eq!(response.expires_at - response.not_before, TOKEN_TTL_SECONDS);
    let token = response.tokens.into_iter().next().unwrap().into_bytes();
    assert!(!token
        .windows(sensitive_account.len())
        .any(|window| window == sensitive_account.as_bytes()));

    // The gateway is constructed only from public verification material,
    // anonymous replay state and revocation state. It has no billing provider.
    let verifier = LocalTokenVerifier::new(
        [public_key],
        Arc::new(InMemoryTokenStore::default()),
        Arc::new(InMemoryRevocationProvider::new(RevocationSnapshot::empty(
            NOW + 3_600,
        ))),
        VerifierConfig::default(),
    )
    .unwrap();
    let token_id = unverified_token_id_for_proof(&token).unwrap();
    let gateway_binding = [0x77; 32];
    let challenge = [0x88; 32];
    let message = proof_of_possession_message(token_id, gateway_binding, challenge);
    let proof = pop_key.sign(&message).to_bytes().to_vec();
    let verified = verifier
        .verify(VerificationRequest {
            encoded_token: token,
            required_role: GatewayRole::Exit,
            gateway_region: RegionSet::Europe,
            now: NOW,
            gateway_binding,
            challenge,
            proof_of_possession: Some(ProofOfPossession { signature: proof }),
        })
        .await
        .unwrap();
    assert_eq!(verified.policy.plan_class, PlanClass::Basic);

    // Billing outage blocks renewal but cannot turn this credential into an
    // unbounded grant; its signed expiry remains unchanged.
    billing.set_available(false).unwrap();
    assert_eq!(verified.expires_at, response.expires_at);
}

#[tokio::test]
async fn inactive_or_unavailable_billing_never_mints() {
    let issuer = Arc::new(
        LocalEd25519TokenIssuer::from_secret_bytes(
            "token-2026-07-b",
            [0x32; 32],
            NOW - 3_600,
            NOW + 86_400,
        )
        .unwrap(),
    );
    let billing = Arc::new(MockBillingAdapter::new_available());
    let account_ref = account("inactive-account");
    billing
        .set_entitlement(
            account_ref.clone(),
            entitlement(EntitlementStatus::Inactive),
        )
        .unwrap();
    let service = TokenService::new(
        issuer,
        billing.clone(),
        Arc::new(InMemoryDeviceSlotManager::default()),
    );
    let request = || MintTokenBatchRequest {
        installation_ref: InstallationRef::from_bytes([1; 32]),
        gateway_role: GatewayRole::Exit,
        proof_of_possession_public_keys: vec![SigningKey::from_bytes(&[0x52; 32])
            .verifying_key()
            .to_bytes()],
    };
    assert_eq!(
        service
            .mint_batch_at(
                AuthenticatedAccountContext::new(account_ref.clone()),
                request(),
                NOW,
            )
            .await
            .unwrap_err(),
        TokenServiceError::NotEntitled
    );
    billing.set_available(false).unwrap();
    assert_eq!(
        service
            .mint_batch_at(
                AuthenticatedAccountContext::new(account_ref),
                request(),
                NOW,
            )
            .await
            .unwrap_err(),
        TokenServiceError::EntitlementUnavailable
    );
}

#[tokio::test]
async fn basic_plan_device_slot_class_is_enforced_in_account_plane_only() {
    let issuer = Arc::new(
        LocalEd25519TokenIssuer::from_secret_bytes(
            "token-2026-07-c",
            [0x33; 32],
            NOW - 3_600,
            NOW + 86_400,
        )
        .unwrap(),
    );
    let billing = Arc::new(MockBillingAdapter::new_available());
    let account_ref = account("basic-account");
    billing
        .set_entitlement(account_ref.clone(), entitlement(EntitlementStatus::Active))
        .unwrap();
    let service = TokenService::new(
        issuer,
        billing,
        Arc::new(InMemoryDeviceSlotManager::default()),
    );
    let pop_key = SigningKey::from_bytes(&[0x62; 32])
        .verifying_key()
        .to_bytes();
    service
        .mint_batch_at(
            AuthenticatedAccountContext::new(account_ref.clone()),
            MintTokenBatchRequest {
                installation_ref: InstallationRef::from_bytes([1; 32]),
                gateway_role: GatewayRole::Exit,
                proof_of_possession_public_keys: vec![pop_key],
            },
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(
        service
            .mint_batch_at(
                AuthenticatedAccountContext::new(account_ref),
                MintTokenBatchRequest {
                    installation_ref: InstallationRef::from_bytes([2; 32]),
                    gateway_role: GatewayRole::Exit,
                    proof_of_possession_public_keys: vec![pop_key],
                },
                NOW,
            )
            .await
            .unwrap_err(),
        TokenServiceError::DeviceSlotLimitReached
    );
}

#[tokio::test]
async fn entitlement_must_cover_the_complete_standard_expiry_bucket() {
    let issuer = Arc::new(
        LocalEd25519TokenIssuer::from_secret_bytes(
            "token-2026-07-d",
            [0x34; 32],
            NOW - 3_600,
            NOW + 86_400,
        )
        .unwrap(),
    );
    let billing = Arc::new(MockBillingAdapter::new_available());
    let account_ref = account("ending-account");
    let bucket_start = NOW - NOW.rem_euclid(TOKEN_BUCKET_SECONDS);
    billing
        .set_entitlement(
            account_ref.clone(),
            BillingEntitlement {
                status: EntitlementStatus::Active,
                plan_class: PlanClass::Basic,
                region_set: RegionSet::Europe,
                valid_until: bucket_start + TOKEN_TTL_SECONDS - 1,
            },
        )
        .unwrap();
    let service = TokenService::new(
        issuer,
        billing,
        Arc::new(InMemoryDeviceSlotManager::default()),
    );
    assert_eq!(
        service
            .mint_batch_at(
                AuthenticatedAccountContext::new(account_ref),
                MintTokenBatchRequest {
                    installation_ref: InstallationRef::from_bytes([4; 32]),
                    gateway_role: GatewayRole::Exit,
                    proof_of_possession_public_keys: vec![SigningKey::from_bytes(&[0x64; 32])
                        .verifying_key()
                        .to_bytes()],
                },
                NOW,
            )
            .await
            .unwrap_err(),
        TokenServiceError::EntitlementEndsBeforeTokenWindow
    );
}
