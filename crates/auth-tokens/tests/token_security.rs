use std::sync::Arc;
use std::{collections::HashSet, iter};

use ed25519_dalek::{Signer, SigningKey};
use onionroute_auth_tokens::{
    proof_of_possession_message, unverified_token_id_for_proof, CapabilityPolicy, GatewayRole,
    InMemoryRevocationProvider, InMemoryTokenStore, IssueTokenRequest, LocalEd25519TokenIssuer,
    LocalTokenVerifier, PlanClass, ProofOfPossession, RegionSet, RevocationSnapshot, TokenError,
    TokenIssuer, TokenVerifier, VerificationRequest, VerifierConfig, MAX_TOKEN_BYTES,
    TOKEN_TTL_SECONDS,
};

const NOW: i64 = 1_800_000_000;
const GATEWAY: [u8; 32] = [0x47; 32];

struct Fixture {
    issuer: LocalEd25519TokenIssuer,
    pop_key: SigningKey,
    verifier: LocalTokenVerifier<InMemoryTokenStore, InMemoryRevocationProvider>,
}

impl Fixture {
    fn new(revocation_valid_until: i64) -> Self {
        let issuer = LocalEd25519TokenIssuer::from_secret_bytes(
            "token-2026-07-a",
            [0x11; 32],
            NOW - 3_600,
            NOW + 86_400,
        )
        .unwrap();
        let verifier = LocalTokenVerifier::new(
            [issuer.public_key()],
            Arc::new(InMemoryTokenStore::default()),
            Arc::new(InMemoryRevocationProvider::new(RevocationSnapshot::empty(
                revocation_valid_until,
            ))),
            VerifierConfig::default(),
        )
        .unwrap();
        Self {
            issuer,
            pop_key: SigningKey::from_bytes(&[0x22; 32]),
            verifier,
        }
    }

    async fn issue(&self) -> Vec<u8> {
        self.issuer
            .issue(IssueTokenRequest {
                policy: CapabilityPolicy::canonical(
                    PlanClass::Basic,
                    RegionSet::Europe,
                    GatewayRole::Exit,
                )
                .unwrap(),
                not_before: NOW,
                expires_at: NOW + TOKEN_TTL_SECONDS,
                proof_of_possession_public_key: Some(self.pop_key.verifying_key().to_bytes()),
            })
            .await
            .unwrap()
            .into_bytes()
    }

    fn request(&self, token: Vec<u8>, challenge: [u8; 32]) -> VerificationRequest {
        let token_id = unverified_token_id_for_proof(&token).unwrap();
        let message = proof_of_possession_message(token_id, GATEWAY, challenge);
        let signature = self.pop_key.sign(&message).to_bytes().to_vec();
        VerificationRequest {
            encoded_token: token,
            required_role: GatewayRole::Exit,
            gateway_region: RegionSet::Europe,
            now: NOW + 1,
            gateway_binding: GATEWAY,
            challenge,
            proof_of_possession: Some(ProofOfPossession { signature }),
        }
    }
}

#[tokio::test]
async fn valid_pop_token_is_accepted_once_and_exact_replay_is_rejected() {
    let fixture = Fixture::new(NOW + 3_600);
    let token = fixture.issue().await;
    let request = fixture.request(token.clone(), [1; 32]);
    fixture.verifier.verify(request).await.unwrap();

    let replay = fixture.request(token, [1; 32]);
    assert_eq!(
        fixture.verifier.verify(replay).await.unwrap_err(),
        TokenError::ReplayDetected
    );
}

#[tokio::test]
async fn proof_is_bound_to_gateway_and_challenge() {
    let fixture = Fixture::new(NOW + 3_600);
    let token = fixture.issue().await;
    let mut request = fixture.request(token, [2; 32]);
    request.gateway_binding = [0x99; 32];
    assert_eq!(
        fixture.verifier.verify(request).await.unwrap_err(),
        TokenError::InvalidProofOfPossession
    );
}

#[tokio::test]
async fn stolen_token_without_pop_private_key_is_rejected() {
    let fixture = Fixture::new(NOW + 3_600);
    let token = fixture.issue().await;
    let mut request = fixture.request(token, [3; 32]);
    request.proof_of_possession = None;
    assert_eq!(
        fixture.verifier.verify(request).await.unwrap_err(),
        TokenError::ProofOfPossessionRequired
    );
}

#[tokio::test]
async fn tampering_expiry_or_signature_cannot_extend_access() {
    let fixture = Fixture::new(NOW + 3_600);
    let mut token = fixture.issue().await;
    let last = token.len() - 1;
    token[last] ^= 1;
    let request = fixture.request(token, [4; 32]);
    assert_eq!(
        fixture.verifier.verify(request).await.unwrap_err(),
        TokenError::InvalidSignature
    );
}

#[tokio::test]
async fn expiry_scope_and_stale_revocation_data_fail_closed() {
    let fixture = Fixture::new(NOW + 3_600);

    let token = fixture.issue().await;
    let mut expired = fixture.request(token, [5; 32]);
    expired.now = NOW + TOKEN_TTL_SECONDS + 31;
    assert_eq!(
        fixture.verifier.verify(expired).await.unwrap_err(),
        TokenError::Expired
    );

    let token = fixture.issue().await;
    let mut wrong_role = fixture.request(token, [6; 32]);
    wrong_role.required_role = GatewayRole::Entry;
    assert_eq!(
        fixture.verifier.verify(wrong_role).await.unwrap_err(),
        TokenError::RoleNotAllowed
    );

    let token = fixture.issue().await;
    let mut wrong_region = fixture.request(token, [7; 32]);
    wrong_region.gateway_region = RegionSet::Americas;
    assert_eq!(
        fixture.verifier.verify(wrong_region).await.unwrap_err(),
        TokenError::RegionNotAllowed
    );

    let stale_fixture = Fixture::new(NOW);
    let token = stale_fixture.issue().await;
    let request = stale_fixture.request(token, [8; 32]);
    assert_eq!(
        stale_fixture.verifier.verify(request).await.unwrap_err(),
        TokenError::RevocationDataStale
    );
}

#[tokio::test]
async fn canonical_connection_limit_is_enforced_and_release_frees_capacity() {
    let fixture = Fixture::new(NOW + 3_600);
    let token = fixture.issue().await;
    let first = fixture
        .verifier
        .verify(fixture.request(token.clone(), [10; 32]))
        .await
        .unwrap();
    fixture
        .verifier
        .verify(fixture.request(token.clone(), [11; 32]))
        .await
        .unwrap();
    assert_eq!(
        fixture
            .verifier
            .verify(fixture.request(token.clone(), [12; 32]))
            .await
            .unwrap_err(),
        TokenError::ConnectionLimitReached
    );

    fixture.verifier.release(first).await.unwrap();
    fixture
        .verifier
        .verify(fixture.request(token, [12; 32]))
        .await
        .unwrap();
}

#[tokio::test]
async fn shared_store_enforces_session_limit_across_gateway_instances() {
    let issuer = LocalEd25519TokenIssuer::from_secret_bytes(
        "token-2026-07-fleet",
        [0x71; 32],
        NOW - 3_600,
        NOW + 86_400,
    )
    .unwrap();
    let pop_key = SigningKey::from_bytes(&[0x72; 32]);
    let token = issuer
        .issue(IssueTokenRequest {
            policy: CapabilityPolicy::canonical(
                PlanClass::Basic,
                RegionSet::Europe,
                GatewayRole::Exit,
            )
            .unwrap(),
            not_before: NOW,
            expires_at: NOW + TOKEN_TTL_SECONDS,
            proof_of_possession_public_key: Some(pop_key.verifying_key().to_bytes()),
        })
        .await
        .unwrap()
        .into_bytes();
    let store = Arc::new(InMemoryTokenStore::default());
    let revocations = Arc::new(InMemoryRevocationProvider::new(RevocationSnapshot::empty(
        NOW + 3_600,
    )));
    let verifier_a = LocalTokenVerifier::new(
        [issuer.public_key()],
        store.clone(),
        revocations.clone(),
        VerifierConfig::default(),
    )
    .unwrap();
    let verifier_b = LocalTokenVerifier::new(
        [issuer.public_key()],
        store,
        revocations,
        VerifierConfig::default(),
    )
    .unwrap();

    let request = |binding: [u8; 32], challenge: [u8; 32]| {
        let token_id = unverified_token_id_for_proof(&token).unwrap();
        let signature = pop_key
            .sign(&proof_of_possession_message(token_id, binding, challenge))
            .to_bytes()
            .to_vec();
        VerificationRequest {
            encoded_token: token.clone(),
            required_role: GatewayRole::Exit,
            gateway_region: RegionSet::Europe,
            now: NOW + 1,
            gateway_binding: binding,
            challenge,
            proof_of_possession: Some(ProofOfPossession { signature }),
        }
    };

    verifier_a
        .verify(request([0xa1; 32], [1; 32]))
        .await
        .unwrap();
    verifier_b
        .verify(request([0xb2; 32], [2; 32]))
        .await
        .unwrap();
    assert_eq!(
        verifier_a
            .verify(request([0xa1; 32], [3; 32]))
            .await
            .unwrap_err(),
        TokenError::ConnectionLimitReached
    );
}

#[test]
fn sensitive_bytes_are_redacted_from_debug_output() {
    let token_id = onionroute_auth_tokens::TokenId::from_bytes([7; 32]);
    assert_eq!(format!("{token_id:?}"), "TokenId(<redacted>)");
    let proof = ProofOfPossession {
        signature: vec![9; 64],
    };
    assert!(!format!("{proof:?}").contains("9, 9"));
}

#[tokio::test]
async fn issuer_rejects_custom_fingerprinting_policy() {
    let fixture = Fixture::new(NOW + 3_600);
    let mut policy =
        CapabilityPolicy::canonical(PlanClass::Basic, RegionSet::Europe, GatewayRole::Exit)
            .unwrap();
    policy.connection_limits.max_active_sessions = 3;
    assert_eq!(
        fixture
            .issuer
            .issue(IssueTokenRequest {
                policy,
                not_before: NOW,
                expires_at: NOW + TOKEN_TTL_SECONDS,
                proof_of_possession_public_key: Some(fixture.pop_key.verifying_key().to_bytes(),),
            })
            .await
            .unwrap_err(),
        TokenError::NonCanonicalPolicy
    );
}

#[tokio::test]
async fn local_revocation_and_wire_size_limit_fail_closed() {
    let fixture = Fixture::new(NOW + 3_600);
    let token = fixture.issue().await;
    let token_id = unverified_token_id_for_proof(&token).unwrap();
    let request = fixture.request(token, [0x44; 32]);
    let snapshot = RevocationSnapshot {
        valid_until: NOW + 3_600,
        revoked_key_ids: HashSet::new(),
        revoked_token_ids: iter::once(token_id).collect(),
    };
    let verifier = LocalTokenVerifier::new(
        [fixture.issuer.public_key()],
        Arc::new(InMemoryTokenStore::default()),
        Arc::new(InMemoryRevocationProvider::new(snapshot)),
        VerifierConfig::default(),
    )
    .unwrap();
    assert_eq!(
        verifier.verify(request).await.unwrap_err(),
        TokenError::Revoked
    );
    assert_eq!(
        onionroute_auth_tokens::validate_wire_format(&vec![0; MAX_TOKEN_BYTES + 1]).unwrap_err(),
        TokenError::InputTooLarge
    );
}
