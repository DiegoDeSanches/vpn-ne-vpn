use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::SigningKey;
use onionroute_directory_client::{
    select_gateway_plan, sign_directory, sign_trust_bundle, verify_directory, AbuseState,
    AnonymityProfile, CapacityBucket, ClientVersionRule, CountryConfig, DirectoryDocument,
    FeatureFlag, GatewayRecord, GatewayRevocation, GatewayRole, HealthState, LoadBucket,
    LocalFailure, MaintenanceState, PersistedDirectoryState, RootTrustBundle, SelectionInput,
    SignedDirectory, SigningKeyCertificate, VerificationContext, VerificationError,
};
use sha3::{Digest, Sha3_256};

const NOW: i64 = 1_800_000_000;

fn gateway(id: &str, role: GatewayRole, provider: &str, asn: u32) -> GatewayRecord {
    GatewayRecord {
        gateway_id: id.to_owned(),
        country_code: "DE".to_owned(),
        city_label: "Frankfurt".to_owned(),
        region: "eu-central".to_owned(),
        role,
        provider_group: provider.to_owned(),
        autonomous_system: asn,
        onion_address: onion_address(1),
        capabilities: vec!["tcp".to_owned(), "multihop".to_owned()],
        supported_protocol_versions: vec!["orp.1".to_owned()],
        minimum_client_version: "1.2.0".to_owned(),
        current_load_bucket: LoadBucket::Low,
        capacity_bucket: CapacityBucket::Large,
        health: HealthState::Healthy,
        maintenance_state: MaintenanceState::Active,
        abuse_state: AbuseState::Active,
        public_signing_key: URL_SAFE_NO_PAD.encode([9_u8; 32]),
        valid_from: NOW - 60,
        valid_until: NOW + 7_200,
    }
}

fn onion_address(seed: u8) -> String {
    let public_key = [seed; 32];
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(public_key);
    hasher.update([3]);
    let checksum = hasher.finalize();
    let mut decoded = Vec::from(public_key);
    decoded.extend_from_slice(&checksum[..2]);
    decoded.push(3);
    format!(
        "{}.onion",
        BASE32_NOPAD.encode(&decoded).to_ascii_lowercase()
    )
}

fn document() -> DirectoryDocument {
    DirectoryDocument {
        format_version: "2.0".to_owned(),
        version: 7,
        issued_at: NOW - 10,
        expires_at: NOW + 3_600,
        gateways: vec![gateway("exit-a", GatewayRole::Exit, "provider-a", 64_501)],
        countries: vec![CountryConfig {
            country_code: "DE".to_owned(),
            display_name_key: "country.de".to_owned(),
            enabled: true,
            supported_profiles: vec![
                AnonymityProfile::Standard,
                AnonymityProfile::Enhanced,
                AnonymityProfile::Maximum,
            ],
        }],
        revocations: vec![],
        client_version_rules: vec![ClientVersionRule {
            platform: "windows".to_owned(),
            channel: "stable".to_owned(),
            minimum_supported_version: "1.2.0".to_owned(),
            recommended_version: "1.3.0".to_owned(),
            latest_version: "1.4.0".to_owned(),
        }],
        feature_flags: vec![FeatureFlag {
            key: "new_identity".to_owned(),
            enabled: true,
            platform: None,
            minimum_client_version: Some("1.2.0".to_owned()),
            maximum_client_version: None,
        }],
    }
}

fn signed(document: &DirectoryDocument) -> (SigningKey, SigningKey, Vec<u8>) {
    let root = SigningKey::from_bytes(&[1_u8; 32]);
    let online = SigningKey::from_bytes(&[2_u8; 32]);
    let bundle = RootTrustBundle {
        format_version: 1,
        bundle_version: 3,
        root_key_id: "root-2026".to_owned(),
        issued_at: NOW - 60,
        expires_at: NOW + 86_400,
        signing_keys: vec![SigningKeyCertificate {
            key_id: "online-2026-07".to_owned(),
            algorithm: "ed25519".to_owned(),
            public_key: URL_SAFE_NO_PAD.encode(online.verifying_key().to_bytes()),
            valid_from: NOW - 60,
            valid_until: NOW + 43_200,
        }],
        revoked_signing_key_ids: vec![],
    };
    let trust = sign_trust_bundle(&root, bundle).unwrap();
    let envelope = sign_directory(&online, "online-2026-07", trust, document).unwrap();
    (root, online, serde_jcs::to_vec(&envelope).unwrap())
}

fn context(root: &SigningKey) -> VerificationContext {
    VerificationContext {
        now_unix: NOW,
        max_future_clock_skew_seconds: 300,
        pinned_root_keys: BTreeMap::from([(
            "root-2026".to_owned(),
            root.verifying_key().to_bytes(),
        )]),
        highest_trust_bundle_version: Some(3),
        persisted_directory: None,
    }
}

#[test]
fn client_verifies_catalog_completely_offline() {
    let document = document();
    let (root, _, bytes) = signed(&document);
    let verified = verify_directory(&bytes, &context(&root)).unwrap();
    assert_eq!(verified.document, document);
    assert_eq!(verified.signing_key_id, "online-2026-07");
}

#[test]
fn expired_catalog_is_rejected() {
    let mut document = document();
    document.issued_at = NOW - 3_600;
    document.expires_at = NOW - 1;
    let (root, _, bytes) = signed(&document);
    assert_eq!(
        verify_directory(&bytes, &context(&root)),
        Err(VerificationError::InvalidValidityWindow)
    );
}

#[test]
fn same_version_equivocation_is_rejected() {
    let original = document();
    let (root, _, original_bytes) = signed(&original);
    let first = verify_directory(&original_bytes, &context(&root)).unwrap();
    let mut changed = original;
    changed.feature_flags[0].enabled = false;
    let (_, _, changed_bytes) = signed(&changed);
    let mut next_context = context(&root);
    next_context.persisted_directory = Some(PersistedDirectoryState {
        version: first.document.version,
        payload_sha256: first.payload_sha256,
    });
    assert_eq!(
        verify_directory(&changed_bytes, &next_context),
        Err(VerificationError::Rollback)
    );
}

#[test]
fn compromised_online_key_cannot_authorize_a_new_intermediate() {
    let document = document();
    let (root, _, bytes) = signed(&document);
    let attacker = SigningKey::from_bytes(&[3_u8; 32]);
    let mut envelope: SignedDirectory = serde_json::from_slice(&bytes).unwrap();
    envelope.trust_bundle.bundle.signing_keys[0].public_key =
        URL_SAFE_NO_PAD.encode(attacker.verifying_key().to_bytes());
    let tampered = serde_jcs::to_vec(&envelope).unwrap();
    assert_eq!(
        verify_directory(&tampered, &context(&root)),
        Err(VerificationError::InvalidSignature)
    );
}

#[test]
fn revoked_gateway_is_never_selected() {
    let mut document = document();
    document.gateways.push(GatewayRecord {
        gateway_id: "exit-b".to_owned(),
        onion_address: onion_address(2),
        ..gateway("unused", GatewayRole::Exit, "provider-b", 64_502)
    });
    document.revocations.push(GatewayRevocation {
        gateway_id: "exit-a".to_owned(),
        reason_code: "key_compromise".to_owned(),
        revoked_at: NOW - 1,
        expires_at: None,
    });
    let plan = select_gateway_plan(&SelectionInput {
        directory: &document,
        selected_country: Some("DE"),
        profile: AnonymityProfile::Standard,
        client_version: "1.4.0",
        protocol_version: "orp.1",
        required_capabilities: &["tcp"],
        recent_failures: &[],
        now_unix: NOW,
        session_seed: [5_u8; 32],
    })
    .unwrap();
    assert_eq!(plan[0].gateway.gateway_id, "exit-b");
}

#[test]
fn selector_prefers_provider_and_as_diversity_and_local_success() {
    let mut document = document();
    document.gateways.extend([
        GatewayRecord {
            gateway_id: "entry-same".to_owned(),
            onion_address: onion_address(3),
            ..gateway("unused", GatewayRole::Entry, "provider-a", 64_501)
        },
        GatewayRecord {
            gateway_id: "entry-diverse".to_owned(),
            onion_address: onion_address(4),
            current_load_bucket: LoadBucket::Medium,
            ..gateway("unused", GatewayRole::Entry, "provider-b", 64_502)
        },
    ]);
    let recent = [LocalFailure {
        gateway_id: "entry-same".to_owned(),
        failure_count: 2,
        last_failure_at: NOW - 10,
    }];
    let plan = select_gateway_plan(&SelectionInput {
        directory: &document,
        selected_country: Some("DE"),
        profile: AnonymityProfile::Enhanced,
        client_version: "1.4.0",
        protocol_version: "orp.1",
        required_capabilities: &["multihop"],
        recent_failures: &recent,
        now_unix: NOW,
        session_seed: [6_u8; 32],
    })
    .unwrap();
    assert_eq!(plan[0].gateway.gateway_id, "entry-diverse");
    assert_eq!(plan[1].gateway.gateway_id, "exit-a");
}

#[test]
fn public_record_cannot_serialize_management_infrastructure() {
    let serialized = serde_jcs::to_string(&document()).unwrap();
    for forbidden in [
        "management_ip",
        "internal_topology",
        "cloud_account",
        "exact_capacity",
        "administrator_id",
    ] {
        assert!(!serialized.contains(forbidden));
    }
}
