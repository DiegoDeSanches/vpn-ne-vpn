use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use onionroute_directory_client::{
    sign_trust_bundle, verify_directory, DirectoryDocument, RootTrustBundle, SigningKeyCertificate,
    VerificationContext,
};
use onionroute_signing_service::{LocalOnlineSigner, OnlineSigner};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn online_pipeline_produces_root_verifiable_offline_document() {
    let now = now();
    let root = SigningKey::from_bytes(&[11_u8; 32]);
    let online = SigningKey::from_bytes(&[12_u8; 32]);
    let trust = sign_trust_bundle(
        &root,
        RootTrustBundle {
            format_version: 1,
            bundle_version: 1,
            root_key_id: "root-test".to_owned(),
            issued_at: now - 60,
            expires_at: now + 86_400,
            signing_keys: vec![SigningKeyCertificate {
                key_id: "online-test".to_owned(),
                algorithm: "ed25519".to_owned(),
                public_key: URL_SAFE_NO_PAD.encode(online.verifying_key().to_bytes()),
                valid_from: now - 60,
                valid_until: now + 43_200,
            }],
            revoked_signing_key_ids: vec![],
        },
    )
    .unwrap();
    let signer = LocalOnlineSigner::new(online, "online-test".to_owned(), trust).unwrap();
    let envelope = signer
        .sign(&DirectoryDocument {
            format_version: "2.0".to_owned(),
            version: 1,
            issued_at: now,
            expires_at: now + 3_600,
            gateways: vec![],
            countries: vec![],
            revocations: vec![],
            client_version_rules: vec![],
            feature_flags: vec![],
        })
        .unwrap();
    let bytes = serde_jcs::to_vec(&envelope).unwrap();
    let verified = verify_directory(
        &bytes,
        &VerificationContext {
            now_unix: now,
            max_future_clock_skew_seconds: 300,
            pinned_root_keys: BTreeMap::from([(
                "root-test".to_owned(),
                root.verifying_key().to_bytes(),
            )]),
            highest_trust_bundle_version: None,
            persisted_directory: None,
        },
    )
    .unwrap();
    assert_eq!(verified.document.version, 1);
    assert_eq!(verified.signing_key_id, "online-test");
}
