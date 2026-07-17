//! Bounded offline verification with root pinning, expiry, and rollback checks.

use std::collections::{BTreeMap, HashSet};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use semver::Version;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use thiserror::Error;

use crate::format::{DirectoryDocument, GatewayRecord, RootTrustBundle, SignedDirectory};
use crate::issuer::domain_message;
use crate::{
    DIRECTORY_SIGNATURE_DOMAIN, MAX_ENVELOPE_BYTES, MAX_GATEWAYS, TRUST_BUNDLE_SIGNATURE_DOMAIN,
};

const MAX_DIRECTORY_LIFETIME_SECONDS: i64 = 6 * 60 * 60;
const MAX_TRUST_BUNDLE_LIFETIME_SECONDS: i64 = 90 * 24 * 60 * 60;
const MAX_SIGNING_KEYS: usize = 16;
const MAX_REVOCATIONS: usize = 8_192;
const MAX_COUNTRIES: usize = 256;
const MAX_FEATURE_FLAGS: usize = 512;
const MAX_VERSION_RULES: usize = 128;

/// Persisted state used to detect same-version equivocation and rollback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistedDirectoryState {
    /// Highest accepted directory version.
    pub version: u64,
    /// SHA-256 of the exact accepted payload bytes.
    pub payload_sha256: [u8; 32],
}

/// Inputs supplied by the client, including its pinned offline root key.
#[derive(Clone, Debug)]
pub struct VerificationContext {
    /// Current wall-clock Unix time.
    pub now_unix: i64,
    /// Maximum accepted future clock skew for issue times.
    pub max_future_clock_skew_seconds: i64,
    /// Pinned root key IDs and their 32-byte Ed25519 public keys.
    pub pinned_root_keys: BTreeMap<String, [u8; 32]>,
    /// Highest root-signed trust bundle version already accepted.
    pub highest_trust_bundle_version: Option<u64>,
    /// Last accepted directory state, if any.
    pub persisted_directory: Option<PersistedDirectoryState>,
}

/// Fully verified offline directory and state that must be persisted atomically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDirectory {
    /// Verified document.
    pub document: DirectoryDocument,
    /// SHA-256 of exact signed payload bytes.
    pub payload_sha256: [u8; 32],
    /// Verified root-signed trust bundle version.
    pub trust_bundle_version: u64,
    /// Online intermediate key that verified the document.
    pub signing_key_id: String,
}

/// Fail-closed directory verification error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VerificationError {
    /// Envelope exceeds a hard byte limit.
    #[error("directory envelope exceeds the hard size limit")]
    EnvelopeTooLarge,
    /// JSON/base64/canonical encoding is invalid.
    #[error("directory encoding is invalid")]
    InvalidEncoding,
    /// An unsupported version or algorithm was supplied.
    #[error("directory format or algorithm is unsupported")]
    UnsupportedFormat,
    /// The root key is not in the pinned client keyring.
    #[error("directory root key is not pinned")]
    UntrustedRoot,
    /// A root or online signature failed.
    #[error("directory signature is invalid")]
    InvalidSignature,
    /// Trust bundle or document is not currently valid.
    #[error("directory is expired or outside its validity window")]
    InvalidValidityWindow,
    /// A trust bundle or directory rollback was detected.
    #[error("directory rollback was detected")]
    Rollback,
    /// The selected intermediate key is missing, invalid, or revoked.
    #[error("directory intermediate signing key is unauthorized")]
    UnauthorizedSigningKey,
    /// The signed payload violates semantic limits or invariants.
    #[error("directory payload violates semantic constraints")]
    InvalidDocument,
}

/// Verifies a serialized envelope without network access.
pub fn verify_directory(
    envelope_bytes: &[u8],
    context: &VerificationContext,
) -> Result<VerifiedDirectory, VerificationError> {
    if !(0..=900).contains(&context.max_future_clock_skew_seconds) {
        return Err(VerificationError::InvalidValidityWindow);
    }
    if envelope_bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(VerificationError::EnvelopeTooLarge);
    }
    let envelope: SignedDirectory =
        serde_json::from_slice(envelope_bytes).map_err(|_| VerificationError::InvalidEncoding)?;
    if envelope.envelope_version != 1 {
        return Err(VerificationError::UnsupportedFormat);
    }

    verify_trust_bundle(&envelope, context)?;
    let certificate = envelope
        .trust_bundle
        .bundle
        .signing_keys
        .iter()
        .find(|key| key.key_id == envelope.signing_key_id)
        .ok_or(VerificationError::UnauthorizedSigningKey)?;
    if certificate.algorithm != "ed25519"
        || certificate.valid_from > context.now_unix
        || certificate.valid_until <= context.now_unix
        || envelope
            .trust_bundle
            .bundle
            .revoked_signing_key_ids
            .iter()
            .any(|key_id| key_id == &envelope.signing_key_id)
    {
        return Err(VerificationError::UnauthorizedSigningKey);
    }

    let public_key = decode_array::<32>(&certificate.public_key)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| VerificationError::InvalidEncoding)?;
    let payload = URL_SAFE_NO_PAD
        .decode(envelope.payload.as_bytes())
        .map_err(|_| VerificationError::InvalidEncoding)?;
    if payload.len() > MAX_ENVELOPE_BYTES {
        return Err(VerificationError::EnvelopeTooLarge);
    }
    let signature_bytes = decode_array::<64>(&envelope.signature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(
            &domain_message(DIRECTORY_SIGNATURE_DOMAIN, &payload),
            &signature,
        )
        .map_err(|_| VerificationError::InvalidSignature)?;

    let document: DirectoryDocument =
        serde_json::from_slice(&payload).map_err(|_| VerificationError::InvalidEncoding)?;
    let canonical = serde_jcs::to_vec(&document).map_err(|_| VerificationError::InvalidEncoding)?;
    if canonical != payload {
        return Err(VerificationError::InvalidEncoding);
    }
    validate_document_semantics(
        &document,
        context.now_unix,
        context.max_future_clock_skew_seconds,
    )?;

    let payload_sha256: [u8; 32] = Sha256::digest(&payload).into();
    if let Some(previous) = context.persisted_directory {
        if document.version < previous.version
            || (document.version == previous.version && payload_sha256 != previous.payload_sha256)
        {
            return Err(VerificationError::Rollback);
        }
    }

    Ok(VerifiedDirectory {
        document,
        payload_sha256,
        trust_bundle_version: envelope.trust_bundle.bundle.bundle_version,
        signing_key_id: envelope.signing_key_id,
    })
}

fn verify_trust_bundle(
    envelope: &SignedDirectory,
    context: &VerificationContext,
) -> Result<(), VerificationError> {
    let bundle = &envelope.trust_bundle.bundle;
    if bundle.format_version != 1 {
        return Err(VerificationError::UnsupportedFormat);
    }
    validate_trust_bundle(bundle, context)?;
    let root_key = context
        .pinned_root_keys
        .get(&bundle.root_key_id)
        .ok_or(VerificationError::UntrustedRoot)?;
    let verifying_key =
        VerifyingKey::from_bytes(root_key).map_err(|_| VerificationError::InvalidEncoding)?;
    let canonical = serde_jcs::to_vec(bundle).map_err(|_| VerificationError::InvalidEncoding)?;
    let signature_bytes = decode_array::<64>(&envelope.trust_bundle.signature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(
            &domain_message(TRUST_BUNDLE_SIGNATURE_DOMAIN, &canonical),
            &signature,
        )
        .map_err(|_| VerificationError::InvalidSignature)
}

fn validate_trust_bundle(
    bundle: &RootTrustBundle,
    context: &VerificationContext,
) -> Result<(), VerificationError> {
    if bundle.bundle_version == 0
        || bundle.issued_at
            > context
                .now_unix
                .saturating_add(context.max_future_clock_skew_seconds)
        || bundle.expires_at <= context.now_unix
        || !valid_lifetime(
            bundle.issued_at,
            bundle.expires_at,
            MAX_TRUST_BUNDLE_LIFETIME_SECONDS,
        )
        || bundle.signing_keys.is_empty()
        || bundle.signing_keys.len() > MAX_SIGNING_KEYS
        || bundle.revoked_signing_key_ids.len() > MAX_SIGNING_KEYS
        || !valid_identifier(&bundle.root_key_id, 64)
    {
        return Err(VerificationError::InvalidValidityWindow);
    }
    if context
        .highest_trust_bundle_version
        .is_some_and(|highest| bundle.bundle_version < highest)
    {
        return Err(VerificationError::Rollback);
    }
    let mut ids = HashSet::new();
    for key in &bundle.signing_keys {
        if !valid_identifier(&key.key_id, 64)
            || key.algorithm != "ed25519"
            || key.valid_from < bundle.issued_at
            || key.valid_until > bundle.expires_at
            || key.valid_until <= key.valid_from
            || decode_array::<32>(&key.public_key).is_err()
            || !ids.insert(&key.key_id)
        {
            return Err(VerificationError::InvalidDocument);
        }
    }
    if bundle
        .revoked_signing_key_ids
        .iter()
        .any(|id| !valid_identifier(id, 64))
    {
        return Err(VerificationError::InvalidDocument);
    }
    Ok(())
}

/// Validates the canonical public document invariants without checking a signature.
/// Producers call this before signing; clients still call it after signature verification.
pub fn validate_document_semantics(
    document: &DirectoryDocument,
    now: i64,
    future_skew: i64,
) -> Result<(), VerificationError> {
    if document.format_version != "2.0" {
        return Err(VerificationError::UnsupportedFormat);
    }
    if document.version == 0
        || document.issued_at > now.saturating_add(future_skew)
        || document.expires_at <= now
        || !valid_lifetime(
            document.issued_at,
            document.expires_at,
            MAX_DIRECTORY_LIFETIME_SECONDS,
        )
    {
        return Err(VerificationError::InvalidValidityWindow);
    }
    if document.gateways.len() > MAX_GATEWAYS
        || document.countries.len() > MAX_COUNTRIES
        || document.revocations.len() > MAX_REVOCATIONS
        || document.client_version_rules.len() > MAX_VERSION_RULES
        || document.feature_flags.len() > MAX_FEATURE_FLAGS
    {
        return Err(VerificationError::InvalidDocument);
    }

    let mut gateway_ids = HashSet::new();
    let mut onion_addresses = HashSet::new();
    for gateway in &document.gateways {
        validate_gateway(gateway, document.issued_at, document.expires_at)?;
        if !gateway_ids.insert(gateway.gateway_id.as_str())
            || !onion_addresses.insert(gateway.onion_address.as_str())
        {
            return Err(VerificationError::InvalidDocument);
        }
    }
    let mut country_codes = HashSet::new();
    for country in &document.countries {
        if !valid_country_code(&country.country_code)
            || !valid_identifier(&country.display_name_key, 96)
            || country.supported_profiles.is_empty()
            || !country_codes.insert(country.country_code.as_str())
        {
            return Err(VerificationError::InvalidDocument);
        }
    }
    let mut revoked = HashSet::new();
    for revocation in &document.revocations {
        if !valid_identifier(&revocation.gateway_id, 64)
            || !valid_identifier(&revocation.reason_code, 64)
            || revocation.revoked_at > document.expires_at
            || revocation
                .expires_at
                .is_some_and(|expires| expires <= revocation.revoked_at)
            || !revoked.insert(revocation.gateway_id.as_str())
        {
            return Err(VerificationError::InvalidDocument);
        }
    }
    for rule in &document.client_version_rules {
        if !valid_platform(&rule.platform)
            || !matches!(rule.channel.as_str(), "stable" | "beta")
            || Version::parse(&rule.minimum_supported_version).is_err()
            || Version::parse(&rule.recommended_version).is_err()
            || Version::parse(&rule.latest_version).is_err()
        {
            return Err(VerificationError::InvalidDocument);
        }
    }
    let mut flag_keys = HashSet::new();
    for flag in &document.feature_flags {
        if !valid_identifier(&flag.key, 96)
            || !flag_keys.insert(flag.key.as_str())
            || flag.platform.as_deref().is_some_and(|p| !valid_platform(p))
            || flag
                .minimum_client_version
                .as_deref()
                .is_some_and(|v| Version::parse(v).is_err())
            || flag
                .maximum_client_version
                .as_deref()
                .is_some_and(|v| Version::parse(v).is_err())
        {
            return Err(VerificationError::InvalidDocument);
        }
    }
    Ok(())
}

fn validate_gateway(
    gateway: &GatewayRecord,
    document_issued_at: i64,
    document_expires_at: i64,
) -> Result<(), VerificationError> {
    let valid_gateway_signing_key = decode_array::<32>(&gateway.public_signing_key)
        .ok()
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
        .is_some();
    if !valid_identifier(&gateway.gateway_id, 64)
        || !valid_country_code(&gateway.country_code)
        || !valid_label(&gateway.city_label, 64)
        || !valid_identifier(&gateway.region, 64)
        || !valid_identifier(&gateway.provider_group, 64)
        || gateway.autonomous_system == 0
        || !valid_onion_address(&gateway.onion_address)
        || gateway.capabilities.len() > 32
        || gateway
            .capabilities
            .iter()
            .any(|capability| !valid_identifier(capability, 64))
        || gateway.supported_protocol_versions.is_empty()
        || gateway.supported_protocol_versions.len() > 16
        || gateway
            .supported_protocol_versions
            .iter()
            .any(|version| !valid_protocol(version))
        || Version::parse(&gateway.minimum_client_version).is_err()
        || !valid_gateway_signing_key
        || gateway.valid_from > document_expires_at
        || gateway.valid_until < document_issued_at
        || gateway.valid_until <= gateway.valid_from
    {
        return Err(VerificationError::InvalidDocument);
    }
    Ok(())
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], VerificationError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| VerificationError::InvalidEncoding)?;
    bytes
        .try_into()
        .map_err(|_| VerificationError::InvalidEncoding)
}

fn valid_onion_address(value: &str) -> bool {
    let Some(service_id) = value.strip_suffix(".onion") else {
        return false;
    };
    if service_id.len() != 56
        || !service_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
    {
        return false;
    }
    let decoded = match BASE32_NOPAD.decode(service_id.to_ascii_uppercase().as_bytes()) {
        Ok(decoded) if decoded.len() == 35 => decoded,
        _ => return false,
    };
    if decoded[34] != 3 {
        return false;
    }
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(&decoded[..32]);
    hasher.update([decoded[34]]);
    let checksum = hasher.finalize();
    decoded[32..34] == checksum[..2]
}

fn valid_country_code(value: &str) -> bool {
    value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn valid_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn valid_label(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn valid_protocol(value: &str) -> bool {
    valid_identifier(value, 32)
}

fn valid_platform(value: &str) -> bool {
    matches!(value, "windows" | "macos" | "linux" | "android" | "ios")
}

fn valid_lifetime(issued_at: i64, expires_at: i64, maximum: i64) -> bool {
    expires_at
        .checked_sub(issued_at)
        .is_some_and(|lifetime| lifetime > 0 && lifetime <= maximum)
}
