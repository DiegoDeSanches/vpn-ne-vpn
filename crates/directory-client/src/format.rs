//! Versioned public document types. Only fields in these types can be published.

use serde::{Deserialize, Serialize};

/// The signed transport envelope. `payload` and signatures use unpadded base64url.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDirectory {
    /// Envelope schema version. The only currently accepted value is 1.
    pub envelope_version: u16,
    /// Intermediate key selected from the root-signed trust bundle.
    pub signing_key_id: String,
    /// Root-signed authorization and revocation state for intermediate keys.
    pub trust_bundle: SignedTrustBundle,
    /// Exact RFC 8785/JCS JSON bytes of `DirectoryDocument`, encoded as base64url.
    pub payload: String,
    /// Ed25519 signature over the directory domain and exact payload bytes.
    pub signature: String,
}

/// Offline-root-signed trust bundle carried with a directory envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTrustBundle {
    /// Canonicalizable bundle body.
    pub bundle: RootTrustBundle,
    /// Ed25519 signature over the trust-bundle domain and canonical bundle bytes.
    pub signature: String,
}

/// Root-authorized intermediate keys and emergency revocations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootTrustBundle {
    /// Trust bundle format version. The only currently accepted value is 1.
    pub format_version: u16,
    /// Monotonic root-signed version used for rollback protection.
    pub bundle_version: u64,
    /// Pinned root key identifier expected by the client.
    pub root_key_id: String,
    /// Unix issuance time in seconds.
    pub issued_at: i64,
    /// Unix hard expiry time in seconds.
    pub expires_at: i64,
    /// Root-authorized online signing keys.
    pub signing_keys: Vec<SigningKeyCertificate>,
    /// Emergency-revoked online key IDs. A listed key can never sign a directory.
    pub revoked_signing_key_ids: Vec<String>,
}

/// Root-authorized online intermediate key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyCertificate {
    /// Stable, non-secret key identifier.
    pub key_id: String,
    /// Signature algorithm. The only currently accepted value is `ed25519`.
    pub algorithm: String,
    /// 32-byte Ed25519 public key encoded as unpadded base64url.
    pub public_key: String,
    /// Beginning of the key validity window, Unix seconds.
    pub valid_from: i64,
    /// End of the key validity window, Unix seconds.
    pub valid_until: i64,
}

/// Exact signed directory payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryDocument {
    /// Directory schema version. The proposed value is `2.0`.
    pub format_version: String,
    /// Monotonic published directory version.
    pub version: u64,
    /// Unix issuance time in seconds.
    pub issued_at: i64,
    /// Unix hard expiry time in seconds.
    pub expires_at: i64,
    /// Public, allow-listed gateway metadata.
    pub gateways: Vec<GatewayRecord>,
    /// Signed country availability and display configuration.
    pub countries: Vec<CountryConfig>,
    /// Signed gateway revocation records.
    pub revocations: Vec<GatewayRevocation>,
    /// Client compatibility and update rules.
    pub client_version_rules: Vec<ClientVersionRule>,
    /// Non-personalized, signed client feature rules.
    pub feature_flags: Vec<FeatureFlag>,
}

/// Public gateway record. Management and infrastructure fields do not exist in this type.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayRecord {
    /// Opaque catalog ID, unrelated to accounts or users.
    pub gateway_id: String,
    /// Upper-case ISO 3166-1 alpha-2 country code.
    pub country_code: String,
    /// Coarse user-facing city label; not a precise location.
    pub city_label: String,
    /// Coarse geographic region.
    pub region: String,
    /// Role this record can serve in a route.
    pub role: GatewayRole,
    /// Coarse provider diversity group, not an account identifier.
    pub provider_group: String,
    /// Public autonomous system number.
    pub autonomous_system: u32,
    /// Tor v3 hostname including the `.onion` suffix.
    pub onion_address: String,
    /// Bounded, allow-listed capability names.
    pub capabilities: Vec<String>,
    /// Supported versioned gateway protocols.
    pub supported_protocol_versions: Vec<String>,
    /// Lowest compatible semantic client version.
    pub minimum_client_version: String,
    /// Coarse current load bucket; never an exact utilization value.
    pub current_load_bucket: LoadBucket,
    /// Coarse capacity bucket; never an exact capacity value.
    pub capacity_bucket: CapacityBucket,
    /// Aggregated gateway health.
    pub health: HealthState,
    /// Operator maintenance state.
    pub maintenance_state: MaintenanceState,
    /// Abuse-response state.
    pub abuse_state: AbuseState,
    /// Gateway application signing key encoded as unpadded base64url.
    pub public_signing_key: String,
    /// Beginning of descriptor validity, Unix seconds.
    pub valid_from: i64,
    /// End of descriptor validity, Unix seconds.
    pub valid_until: i64,
}

/// Gateway role used to build an anonymity profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayRole {
    /// First private hop after Tor for Enhanced/Maximum.
    Entry,
    /// Middle private hop used by Maximum.
    Relay,
    /// Internet-facing private exit.
    Exit,
}

/// Client anonymity profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnonymityProfile {
    /// Tor followed by one private exit.
    Standard,
    /// Tor, private entry, encrypted transport, private exit.
    Enhanced,
    /// Tor, private entry, relay, private exit.
    Maximum,
    /// Public Tor exit; no private gateway is selected.
    DirectTor,
}

/// Coarse load measurement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBucket {
    /// No trustworthy recent sample.
    Unknown,
    /// Low utilization.
    Low,
    /// Medium utilization.
    Medium,
    /// High but still assignable utilization.
    High,
    /// New assignments are not allowed.
    Saturated,
}

/// Coarse advertised capacity class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityBucket {
    /// Small capacity class.
    Small,
    /// Medium capacity class.
    Medium,
    /// Large capacity class.
    Large,
}

/// Aggregated health state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    /// Sufficient fresh successful samples.
    Healthy,
    /// Partially impaired but usable as a last resort.
    Degraded,
    /// Failed health policy and cannot be selected.
    Unhealthy,
    /// No fresh health signal and cannot be selected.
    Unknown,
}

/// Gateway maintenance state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceState {
    /// Accepting new selections.
    Active,
    /// Existing sessions may finish; new selections are blocked.
    Draining,
    /// Explicit maintenance; new selections are blocked.
    Maintenance,
}

/// Coarse abuse-response state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseState {
    /// Normal operation.
    Active,
    /// Restricted capabilities but still usable when requirements match.
    Restricted,
    /// Fully blocked from new selection.
    Blocked,
}

/// Signed country configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CountryConfig {
    /// Upper-case ISO 3166-1 alpha-2 code.
    pub country_code: String,
    /// Localized display key, not free-form operator content.
    pub display_name_key: String,
    /// Whether clients may select this country.
    pub enabled: bool,
    /// Profiles available for this country.
    pub supported_profiles: Vec<AnonymityProfile>,
}

/// Signed gateway revocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayRevocation {
    /// Revoked gateway ID.
    pub gateway_id: String,
    /// Allow-listed public reason code.
    pub reason_code: String,
    /// Unix activation time.
    pub revoked_at: i64,
    /// Optional Unix expiry; absent means permanent.
    pub expires_at: Option<i64>,
}

/// Signed client-version compatibility rule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientVersionRule {
    /// Allow-listed platform (`windows`, `macos`, `linux`, `android`, `ios`).
    pub platform: String,
    /// Release channel (`stable`, `beta`).
    pub channel: String,
    /// Lowest version allowed to use the control plane.
    pub minimum_supported_version: String,
    /// Recommended update floor.
    pub recommended_version: String,
    /// Most recent published version.
    pub latest_version: String,
}

/// Signed non-personalized feature rule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureFlag {
    /// Stable allow-listed feature name.
    pub key: String,
    /// Global switch for the matching rule.
    pub enabled: bool,
    /// Optional platform filter.
    pub platform: Option<String>,
    /// Optional semantic version floor.
    pub minimum_client_version: Option<String>,
    /// Optional semantic version ceiling.
    pub maximum_client_version: Option<String>,
}

/// One selected private gateway hop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedGateway {
    /// Selected role.
    pub role: GatewayRole,
    /// Selected public gateway descriptor.
    pub gateway: GatewayRecord,
}
