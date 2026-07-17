#![forbid(unsafe_code)]
//! Administrator API on a dedicated, loopback-only mTLS ingress.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{post, put};
use axum::{Json, Router};
use onionroute_directory_client::{
    AnonymityProfile, ClientVersionRule, CountryConfig, FeatureFlag, GatewayRecord,
    GatewayRevocation, GatewayRole,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::Mutex;

const ADMIN_SUBJECT_HEADER: &str = "x-onionroute-admin-subject";

/// Admin persistence error that does not expose database details.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdminRepositoryError {
    /// The command conflicts with current state.
    #[error("admin command conflicts with current state")]
    Conflict,
    /// Persistence operation failed.
    #[error("admin persistence operation failed")]
    Persistence,
}

/// Incident input. It must never contain traffic content, destinations, or user identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentInput {
    /// Allow-listed severity (`low`, `medium`, `high`, `critical`).
    pub severity: String,
    /// Short operational summary.
    pub summary: String,
    /// Optional affected public gateway ID.
    pub gateway_id: Option<String>,
}

/// Request to create an unsigned directory draft for the isolated signing pipeline.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationRequest {
    /// Requested validity, constrained to 5 minutes through 6 hours.
    pub validity_seconds: u32,
}

/// Draft accepted for asynchronous signing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicationResponse {
    /// Monotonic reserved directory version.
    pub directory_version: u64,
    /// Pipeline state.
    pub state: String,
}

/// Administrator command persistence contract.
#[async_trait]
pub trait AdminRepository: Send + Sync {
    /// Creates or replaces public gateway metadata.
    async fn upsert_gateway(
        &self,
        actor: &str,
        gateway: GatewayRecord,
    ) -> Result<(), AdminRepositoryError>;
    /// Creates or replaces country configuration.
    async fn upsert_country(
        &self,
        actor: &str,
        country: CountryConfig,
    ) -> Result<(), AdminRepositoryError>;
    /// Creates or replaces a client feature rule.
    async fn upsert_feature_flag(
        &self,
        actor: &str,
        flag: FeatureFlag,
    ) -> Result<(), AdminRepositoryError>;
    /// Creates or replaces one client-version rule.
    async fn upsert_client_version_rule(
        &self,
        actor: &str,
        rule: ClientVersionRule,
    ) -> Result<(), AdminRepositoryError>;
    /// Creates a gateway revocation consumed by the signing pipeline.
    async fn create_revocation(
        &self,
        actor: &str,
        revocation: GatewayRevocation,
    ) -> Result<(), AdminRepositoryError>;
    /// Creates a privacy-minimized operational incident.
    async fn create_incident(
        &self,
        actor: &str,
        incident: IncidentInput,
    ) -> Result<(), AdminRepositoryError>;
    /// Reserves a monotonic draft version.
    async fn create_directory_draft(
        &self,
        actor: &str,
        validity_seconds: u32,
    ) -> Result<u64, AdminRepositoryError>;
}

/// PostgreSQL admin repository.
#[derive(Clone)]
pub struct PgAdminRepository {
    pool: PgPool,
}

impl PgAdminRepository {
    /// Creates a repository with an admin-role database pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AdminRepository for PgAdminRepository {
    async fn upsert_gateway(
        &self,
        actor: &str,
        gateway: GatewayRecord,
    ) -> Result<(), AdminRepositoryError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| AdminRepositoryError::Persistence)?;
        sqlx::query(
            "INSERT INTO gateways \
             (gateway_id, country_code, city_label, region, provider_group, autonomous_system, \
              onion_address, capabilities, supported_protocol_versions, minimum_client_version, \
              current_load_bucket, capacity_bucket, health, maintenance_state, abuse_state, \
              public_signing_key, valid_from, valid_until, updated_by) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16, \
                     to_timestamp($17),to_timestamp($18),$19) \
             ON CONFLICT (gateway_id) DO UPDATE SET \
               country_code=EXCLUDED.country_code, city_label=EXCLUDED.city_label, \
               region=EXCLUDED.region, provider_group=EXCLUDED.provider_group, \
               autonomous_system=EXCLUDED.autonomous_system, onion_address=EXCLUDED.onion_address, \
               capabilities=EXCLUDED.capabilities, supported_protocol_versions=EXCLUDED.supported_protocol_versions, \
               minimum_client_version=EXCLUDED.minimum_client_version, \
               current_load_bucket=EXCLUDED.current_load_bucket, capacity_bucket=EXCLUDED.capacity_bucket, \
               health=EXCLUDED.health, maintenance_state=EXCLUDED.maintenance_state, \
               abuse_state=EXCLUDED.abuse_state, public_signing_key=EXCLUDED.public_signing_key, \
               valid_from=EXCLUDED.valid_from, valid_until=EXCLUDED.valid_until, \
               updated_by=EXCLUDED.updated_by, updated_at=now()",
        )
        .bind(&gateway.gateway_id)
        .bind(&gateway.country_code)
        .bind(&gateway.city_label)
        .bind(&gateway.region)
        .bind(&gateway.provider_group)
        .bind(i64::from(gateway.autonomous_system))
        .bind(&gateway.onion_address)
        .bind(&gateway.capabilities)
        .bind(&gateway.supported_protocol_versions)
        .bind(&gateway.minimum_client_version)
        .bind(load_name(gateway.current_load_bucket))
        .bind(capacity_name(gateway.capacity_bucket))
        .bind(health_name(gateway.health))
        .bind(maintenance_name(gateway.maintenance_state))
        .bind(abuse_name(gateway.abuse_state))
        .bind(&gateway.public_signing_key)
        .bind(gateway.valid_from as f64)
        .bind(gateway.valid_until as f64)
        .bind(actor)
        .execute(&mut *tx)
        .await
        .map_err(map_database_error)?;
        sqlx::query(
            "INSERT INTO gateway_roles (gateway_id, role) VALUES ($1, $2) \
             ON CONFLICT (gateway_id) DO UPDATE SET role=EXCLUDED.role",
        )
        .bind(&gateway.gateway_id)
        .bind(role_name(gateway.role))
        .execute(&mut *tx)
        .await
        .map_err(map_database_error)?;
        tx.commit()
            .await
            .map_err(|_| AdminRepositoryError::Persistence)
    }

    async fn upsert_country(
        &self,
        actor: &str,
        country: CountryConfig,
    ) -> Result<(), AdminRepositoryError> {
        let profiles: Vec<&str> = country
            .supported_profiles
            .iter()
            .map(|profile| profile_name(*profile))
            .collect();
        sqlx::query(
            "INSERT INTO countries \
             (country_code, display_name_key, enabled, supported_profiles, updated_by) \
             VALUES ($1,$2,$3,$4,$5) ON CONFLICT (country_code) DO UPDATE SET \
             display_name_key=EXCLUDED.display_name_key, enabled=EXCLUDED.enabled, \
             supported_profiles=EXCLUDED.supported_profiles, updated_by=EXCLUDED.updated_by, updated_at=now()",
        )
        .bind(&country.country_code)
        .bind(&country.display_name_key)
        .bind(country.enabled)
        .bind(profiles)
        .bind(actor)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(())
    }

    async fn upsert_feature_flag(
        &self,
        actor: &str,
        flag: FeatureFlag,
    ) -> Result<(), AdminRepositoryError> {
        sqlx::query(
            "INSERT INTO feature_flags \
             (flag_key, enabled, platform, minimum_client_version, maximum_client_version, updated_by) \
             VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (flag_key) DO UPDATE SET \
             enabled=EXCLUDED.enabled, platform=EXCLUDED.platform, \
             minimum_client_version=EXCLUDED.minimum_client_version, \
             maximum_client_version=EXCLUDED.maximum_client_version, \
             updated_by=EXCLUDED.updated_by, updated_at=now()",
        )
        .bind(&flag.key)
        .bind(flag.enabled)
        .bind(&flag.platform)
        .bind(&flag.minimum_client_version)
        .bind(&flag.maximum_client_version)
        .bind(actor)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(())
    }

    async fn upsert_client_version_rule(
        &self,
        actor: &str,
        rule: ClientVersionRule,
    ) -> Result<(), AdminRepositoryError> {
        sqlx::query(
            "INSERT INTO client_version_rules \
             (platform, channel, minimum_supported_version, recommended_version, latest_version, updated_by) \
             VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (platform, channel) DO UPDATE SET \
             minimum_supported_version=EXCLUDED.minimum_supported_version, \
             recommended_version=EXCLUDED.recommended_version, latest_version=EXCLUDED.latest_version, \
             updated_by=EXCLUDED.updated_by, updated_at=now()",
        )
        .bind(&rule.platform)
        .bind(&rule.channel)
        .bind(&rule.minimum_supported_version)
        .bind(&rule.recommended_version)
        .bind(&rule.latest_version)
        .bind(actor)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(())
    }

    async fn create_revocation(
        &self,
        actor: &str,
        revocation: GatewayRevocation,
    ) -> Result<(), AdminRepositoryError> {
        sqlx::query(
            "INSERT INTO revocations \
             (subject_type, subject_id, reason_code, revoked_at, expires_at, created_by) \
             VALUES ('gateway',$1,$2,to_timestamp($3), \
                     CASE WHEN $4::double precision IS NULL THEN NULL ELSE to_timestamp($4) END,$5)",
        )
        .bind(&revocation.gateway_id)
        .bind(&revocation.reason_code)
        .bind(revocation.revoked_at as f64)
        .bind(revocation.expires_at.map(|value| value as f64))
        .bind(actor)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(())
    }

    async fn create_incident(
        &self,
        actor: &str,
        incident: IncidentInput,
    ) -> Result<(), AdminRepositoryError> {
        sqlx::query(
            "INSERT INTO incidents (severity, summary, gateway_id, status, created_by) \
             VALUES ($1,$2,$3,'open',$4)",
        )
        .bind(&incident.severity)
        .bind(&incident.summary)
        .bind(&incident.gateway_id)
        .bind(actor)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(())
    }

    async fn create_directory_draft(
        &self,
        actor: &str,
        validity_seconds: u32,
    ) -> Result<u64, AdminRepositoryError> {
        let row = sqlx::query_as::<_, (i64,)>("SELECT create_directory_draft($1, $2)")
            .bind(i64::from(validity_seconds))
            .bind(actor)
            .fetch_one(&self.pool)
            .await
            .map_err(map_database_error)?;
        u64::try_from(row.0).map_err(|_| AdminRepositoryError::Persistence)
    }
}

/// Recorded in-memory command for API isolation tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedCommand {
    /// Authenticated admin subject.
    pub actor: String,
    /// Coarse command name; no request body is retained.
    pub command: String,
}

/// In-memory command sink for integration tests.
#[derive(Default)]
pub struct MemoryAdminRepository {
    commands: Mutex<Vec<RecordedCommand>>,
}

impl MemoryAdminRepository {
    /// Returns recorded command metadata.
    pub async fn commands(&self) -> Vec<RecordedCommand> {
        self.commands.lock().await.clone()
    }

    async fn push(&self, actor: &str, command: &str) {
        self.commands.lock().await.push(RecordedCommand {
            actor: actor.to_owned(),
            command: command.to_owned(),
        });
    }
}

#[async_trait]
impl AdminRepository for MemoryAdminRepository {
    async fn upsert_gateway(
        &self,
        actor: &str,
        _: GatewayRecord,
    ) -> Result<(), AdminRepositoryError> {
        self.push(actor, "upsert_gateway").await;
        Ok(())
    }
    async fn upsert_country(
        &self,
        actor: &str,
        _: CountryConfig,
    ) -> Result<(), AdminRepositoryError> {
        self.push(actor, "upsert_country").await;
        Ok(())
    }
    async fn upsert_feature_flag(
        &self,
        actor: &str,
        _: FeatureFlag,
    ) -> Result<(), AdminRepositoryError> {
        self.push(actor, "upsert_feature_flag").await;
        Ok(())
    }
    async fn upsert_client_version_rule(
        &self,
        actor: &str,
        _: ClientVersionRule,
    ) -> Result<(), AdminRepositoryError> {
        self.push(actor, "upsert_client_version_rule").await;
        Ok(())
    }
    async fn create_revocation(
        &self,
        actor: &str,
        _: GatewayRevocation,
    ) -> Result<(), AdminRepositoryError> {
        self.push(actor, "create_revocation").await;
        Ok(())
    }
    async fn create_incident(
        &self,
        actor: &str,
        _: IncidentInput,
    ) -> Result<(), AdminRepositoryError> {
        self.push(actor, "create_incident").await;
        Ok(())
    }
    async fn create_directory_draft(
        &self,
        actor: &str,
        _: u32,
    ) -> Result<u64, AdminRepositoryError> {
        self.push(actor, "create_directory_draft").await;
        Ok(42)
    }
}

/// Dedicated admin ingress settings. The bind must be loopback and must not equal
/// the client API listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminIngressConfig {
    /// Listener behind an administrator mTLS/authentication proxy.
    pub bind: SocketAddr,
    /// Client API bind, used to prove separation when co-located.
    pub client_api_bind: Option<SocketAddr>,
}

impl AdminIngressConfig {
    /// Enforces a distinct, non-public administrator ingress.
    pub fn validate(&self) -> Result<(), AdminIngressError> {
        if !self.bind.ip().is_loopback() || self.client_api_bind == Some(self.bind) {
            return Err(AdminIngressError::UnsafeOrSharedIngress);
        }
        Ok(())
    }
}

/// Admin ingress policy violation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdminIngressError {
    /// The admin listener is public or shared with the client listener.
    #[error("administrator API requires a separate loopback mTLS ingress")]
    UnsafeOrSharedIngress,
}

#[derive(Clone)]
struct HttpState {
    repository: Arc<dyn AdminRepository>,
}

/// Builds the administrator router. It must never be merged with the client router.
pub fn router(repository: Arc<dyn AdminRepository>) -> Router {
    Router::new()
        .route("/admin/v1/gateways", post(upsert_gateway))
        .route("/admin/v1/countries/:country_code", put(upsert_country))
        .route(
            "/admin/v1/feature-flags/:flag_key",
            put(upsert_feature_flag),
        )
        .route(
            "/admin/v1/client-version-rules",
            post(upsert_client_version_rule),
        )
        .route("/admin/v1/revocations", post(create_revocation))
        .route("/admin/v1/incidents", post(create_incident))
        .route(
            "/admin/v1/directory-publications",
            post(create_directory_draft),
        )
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(HttpState { repository })
}

async fn upsert_gateway(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(gateway): Json<GatewayRecord>,
) -> StatusCode {
    execute(&headers, |actor| async move {
        state.repository.upsert_gateway(&actor, gateway).await
    })
    .await
}

async fn upsert_country(
    State(state): State<HttpState>,
    Path(country_code): Path<String>,
    headers: HeaderMap,
    Json(country): Json<CountryConfig>,
) -> StatusCode {
    if country.country_code != country_code {
        return StatusCode::BAD_REQUEST;
    }
    execute(&headers, |actor| async move {
        state.repository.upsert_country(&actor, country).await
    })
    .await
}

async fn upsert_feature_flag(
    State(state): State<HttpState>,
    Path(flag_key): Path<String>,
    headers: HeaderMap,
    Json(flag): Json<FeatureFlag>,
) -> StatusCode {
    if flag.key != flag_key {
        return StatusCode::BAD_REQUEST;
    }
    execute(&headers, |actor| async move {
        state.repository.upsert_feature_flag(&actor, flag).await
    })
    .await
}

async fn upsert_client_version_rule(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(rule): Json<ClientVersionRule>,
) -> StatusCode {
    execute(&headers, |actor| async move {
        state
            .repository
            .upsert_client_version_rule(&actor, rule)
            .await
    })
    .await
}

async fn create_revocation(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(revocation): Json<GatewayRevocation>,
) -> StatusCode {
    execute(&headers, |actor| async move {
        state.repository.create_revocation(&actor, revocation).await
    })
    .await
}

async fn create_incident(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(incident): Json<IncidentInput>,
) -> StatusCode {
    if !valid_incident(&incident) {
        return StatusCode::BAD_REQUEST;
    }
    execute(&headers, |actor| async move {
        state.repository.create_incident(&actor, incident).await
    })
    .await
}

async fn create_directory_draft(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<PublicationRequest>,
) -> Result<(StatusCode, Json<PublicationResponse>), StatusCode> {
    if !(300..=21_600).contains(&request.validity_seconds) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let actor = admin_subject(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let version = state
        .repository
        .create_directory_draft(actor, request.validity_seconds)
        .await
        .map_err(repository_status)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(PublicationResponse {
            directory_version: version,
            state: "draft".to_owned(),
        }),
    ))
}

async fn execute<F, Fut>(headers: &HeaderMap, operation: F) -> StatusCode
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<(), AdminRepositoryError>>,
{
    let Some(actor) = admin_subject(headers).map(str::to_owned) else {
        return StatusCode::UNAUTHORIZED;
    };
    match operation(actor).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(error) => repository_status(error),
    }
}

fn admin_subject(headers: &HeaderMap) -> Option<&str> {
    let subject = headers.get(ADMIN_SUBJECT_HEADER)?.to_str().ok()?;
    (subject.len() <= 128
        && !subject.is_empty()
        && subject.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'@')
        }))
    .then_some(subject)
}

fn repository_status(error: AdminRepositoryError) -> StatusCode {
    match error {
        AdminRepositoryError::Conflict => StatusCode::CONFLICT,
        AdminRepositoryError::Persistence => StatusCode::SERVICE_UNAVAILABLE,
    }
}

fn valid_incident(incident: &IncidentInput) -> bool {
    matches!(
        incident.severity.as_str(),
        "low" | "medium" | "high" | "critical"
    ) && !incident.summary.is_empty()
        && incident.summary.len() <= 512
        && !incident.summary.chars().any(char::is_control)
        && incident
            .gateway_id
            .as_deref()
            .map_or(true, |id| id.len() <= 64)
}

fn map_database_error(error: sqlx::Error) -> AdminRepositoryError {
    if error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
    {
        AdminRepositoryError::Conflict
    } else {
        AdminRepositoryError::Persistence
    }
}

fn role_name(value: GatewayRole) -> &'static str {
    match value {
        GatewayRole::Entry => "entry",
        GatewayRole::Relay => "relay",
        GatewayRole::Exit => "exit",
    }
}

fn profile_name(value: AnonymityProfile) -> &'static str {
    match value {
        AnonymityProfile::Standard => "standard",
        AnonymityProfile::Enhanced => "enhanced",
        AnonymityProfile::Maximum => "maximum",
        AnonymityProfile::DirectTor => "direct_tor",
    }
}

fn load_name(value: onionroute_directory_client::LoadBucket) -> &'static str {
    match value {
        onionroute_directory_client::LoadBucket::Unknown => "unknown",
        onionroute_directory_client::LoadBucket::Low => "low",
        onionroute_directory_client::LoadBucket::Medium => "medium",
        onionroute_directory_client::LoadBucket::High => "high",
        onionroute_directory_client::LoadBucket::Saturated => "saturated",
    }
}

fn capacity_name(value: onionroute_directory_client::CapacityBucket) -> &'static str {
    match value {
        onionroute_directory_client::CapacityBucket::Small => "small",
        onionroute_directory_client::CapacityBucket::Medium => "medium",
        onionroute_directory_client::CapacityBucket::Large => "large",
    }
}

fn health_name(value: onionroute_directory_client::HealthState) -> &'static str {
    match value {
        onionroute_directory_client::HealthState::Healthy => "healthy",
        onionroute_directory_client::HealthState::Degraded => "degraded",
        onionroute_directory_client::HealthState::Unhealthy => "unhealthy",
        onionroute_directory_client::HealthState::Unknown => "unknown",
    }
}

fn maintenance_name(value: onionroute_directory_client::MaintenanceState) -> &'static str {
    match value {
        onionroute_directory_client::MaintenanceState::Active => "active",
        onionroute_directory_client::MaintenanceState::Draining => "draining",
        onionroute_directory_client::MaintenanceState::Maintenance => "maintenance",
    }
}

fn abuse_name(value: onionroute_directory_client::AbuseState) -> &'static str {
    match value {
        onionroute_directory_client::AbuseState::Active => "active",
        onionroute_directory_client::AbuseState::Restricted => "restricted",
        onionroute_directory_client::AbuseState::Blocked => "blocked",
    }
}
