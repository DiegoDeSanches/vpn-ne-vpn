#![forbid(unsafe_code)]
//! Privacy-minimized gateway health collection and aggregation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use onionroute_directory_client::{CapacityBucket, HealthState, LoadBucket};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::Mutex;

const GATEWAY_ID_HEADER: &str = "x-onionroute-gateway-id";
const SAMPLE_CLOCK_SKEW_SECONDS: i64 = 5 * 60;

/// One allow-listed self-check result. It contains no destination or user dimensions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheck {
    /// Closed check name.
    pub name: String,
    /// Whether the check succeeded.
    pub ok: bool,
    /// Coarse latency bucket (`fast`, `normal`, `slow`, `timeout`).
    pub latency_bucket: String,
}

/// Authenticated gateway health sample. There is intentionally no source/client IP field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthReport {
    /// Gateway identity, required to match the mTLS-authenticated ingress identity.
    pub gateway_id: String,
    /// Monotonic per-gateway sample sequence.
    pub sequence: u64,
    /// Unix observation time.
    pub observed_at: i64,
    /// Gateway self-health.
    pub health: HealthState,
    /// Coarse load bucket.
    pub load_bucket: LoadBucket,
    /// Coarse capacity bucket.
    pub capacity_bucket: CapacityBucket,
    /// Bounded closed check set.
    pub checks: Vec<HealthCheck>,
}

/// Persistence failure exposed without query or infrastructure details.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum HealthRepositoryError {
    /// The sample sequence already exists or moved backwards.
    #[error("health sequence conflict")]
    SequenceConflict,
    /// Database operation failed.
    #[error("health persistence operation failed")]
    Persistence,
}

/// Health sample storage contract.
#[async_trait]
pub trait HealthRepository: Send + Sync {
    /// Records an authenticated report and updates aggregate gateway state.
    async fn record(&self, report: HealthReport) -> Result<(), HealthRepositoryError>;
}

/// PostgreSQL implementation using an atomic sample/aggregate transaction.
#[derive(Clone)]
pub struct PgHealthRepository {
    pool: PgPool,
}

impl PgHealthRepository {
    /// Creates a PostgreSQL health repository.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl HealthRepository for PgHealthRepository {
    async fn record(&self, report: HealthReport) -> Result<(), HealthRepositoryError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| HealthRepositoryError::Persistence)?;
        // Serialize sequences per public gateway ID without introducing a user or
        // network identifier into the lock key or schema.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 91827))")
            .bind(&report.gateway_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| HealthRepositoryError::Persistence)?;
        let highest = sqlx::query_as::<_, (Option<i64>,)>(
            "SELECT MAX(sample_sequence) FROM health_samples WHERE gateway_id=$1",
        )
        .bind(&report.gateway_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| HealthRepositoryError::Persistence)?
        .0
        .unwrap_or(0);
        if i64::try_from(report.sequence).map_err(|_| HealthRepositoryError::SequenceConflict)?
            <= highest
        {
            return Err(HealthRepositoryError::SequenceConflict);
        }
        let checks =
            serde_json::to_value(&report.checks).map_err(|_| HealthRepositoryError::Persistence)?;
        let insert = sqlx::query(
            "INSERT INTO health_samples \
             (gateway_id, sample_sequence, observed_at, health, load_bucket, capacity_bucket, checks) \
             VALUES ($1, $2, to_timestamp($3), $4, $5, $6, $7)",
        )
        .bind(&report.gateway_id)
        .bind(i64::try_from(report.sequence).map_err(|_| HealthRepositoryError::SequenceConflict)?)
        .bind(report.observed_at as f64)
        .bind(health_name(report.health))
        .bind(load_name(report.load_bucket))
        .bind(capacity_name(report.capacity_bucket))
        .bind(checks)
        .execute(&mut *transaction)
        .await;
        if let Err(error) = insert {
            return if error.as_database_error().is_some_and(|database| {
                database.is_unique_violation() || database.is_foreign_key_violation()
            }) {
                Err(HealthRepositoryError::SequenceConflict)
            } else {
                Err(HealthRepositoryError::Persistence)
            };
        }

        let recent = sqlx::query_as::<_, (String,)>(
            "SELECT health FROM health_samples WHERE gateway_id = $1 \
             ORDER BY sample_sequence DESC LIMIT 3",
        )
        .bind(&report.gateway_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| HealthRepositoryError::Persistence)?;
        let states: Vec<HealthState> = recent
            .iter()
            .filter_map(|row| parse_health(&row.0))
            .collect();
        let aggregate = aggregate_health(&states);
        sqlx::query(
            "UPDATE gateways SET health = $2, current_load_bucket = $3, \
             capacity_bucket = $4, updated_at = now() WHERE gateway_id = $1",
        )
        .bind(&report.gateway_id)
        .bind(health_name(aggregate))
        .bind(load_name(report.load_bucket))
        .bind(capacity_name(report.capacity_bucket))
        .execute(&mut *transaction)
        .await
        .map_err(|_| HealthRepositoryError::Persistence)?;
        transaction
            .commit()
            .await
            .map_err(|_| HealthRepositoryError::Persistence)
    }
}

/// In-memory repository for tests. Its stored type statically cannot contain an IP.
#[derive(Default)]
pub struct MemoryHealthRepository {
    reports: Mutex<Vec<HealthReport>>,
}

impl MemoryHealthRepository {
    /// Returns a snapshot of accepted reports.
    pub async fn reports(&self) -> Vec<HealthReport> {
        self.reports.lock().await.clone()
    }
}

#[async_trait]
impl HealthRepository for MemoryHealthRepository {
    async fn record(&self, report: HealthReport) -> Result<(), HealthRepositoryError> {
        let mut reports = self.reports.lock().await;
        if reports.iter().any(|existing| {
            existing.gateway_id == report.gateway_id && existing.sequence >= report.sequence
        }) {
            return Err(HealthRepositoryError::SequenceConflict);
        }
        reports.push(report);
        Ok(())
    }
}

/// Separate gateway ingress configuration. A local mTLS proxy must inject the
/// authenticated gateway ID and strip any incoming copy of that header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthIngressConfig {
    /// Loopback listener used only by the dedicated gateway-health proxy.
    pub bind: SocketAddr,
}

impl HealthIngressConfig {
    /// Rejects public or shared application listeners.
    pub fn validate(&self) -> Result<(), HealthIngressError> {
        if !self.bind.ip().is_loopback() {
            return Err(HealthIngressError::UnsafeBind);
        }
        Ok(())
    }
}

/// Unsafe health ingress configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum HealthIngressError {
    /// Health collector must be behind a dedicated local mTLS ingress.
    #[error("health collector must bind loopback behind dedicated mTLS ingress")]
    UnsafeBind,
}

#[derive(Clone)]
struct HttpState {
    repository: Arc<dyn HealthRepository>,
}

/// Builds the dedicated gateway health API.
pub fn router(repository: Arc<dyn HealthRepository>) -> Router {
    Router::new()
        .route("/gateway-health/v1/samples", post(collect))
        .layer(DefaultBodyLimit::max(8 * 1024))
        .with_state(HttpState { repository })
}

async fn collect(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(report): Json<HealthReport>,
) -> StatusCode {
    let authenticated_gateway = match headers
        .get(GATEWAY_ID_HEADER)
        .and_then(|value| value.to_str().ok())
    {
        Some(identity) if valid_identifier(identity) => identity,
        _ => return StatusCode::UNAUTHORIZED,
    };
    if authenticated_gateway != report.gateway_id || !valid_report(&report, now_unix()) {
        return StatusCode::BAD_REQUEST;
    }
    match state.repository.record(report).await {
        Ok(()) => StatusCode::ACCEPTED,
        Err(HealthRepositoryError::SequenceConflict) => StatusCode::CONFLICT,
        Err(HealthRepositoryError::Persistence) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Aggregates the newest states without any per-user dimension.
pub fn aggregate_health(recent: &[HealthState]) -> HealthState {
    if recent.is_empty() {
        return HealthState::Unknown;
    }
    let healthy = recent
        .iter()
        .filter(|state| **state == HealthState::Healthy)
        .count();
    let unhealthy = recent
        .iter()
        .filter(|state| **state == HealthState::Unhealthy)
        .count();
    if recent.len() >= 3 && unhealthy == recent.len() {
        HealthState::Unhealthy
    } else if healthy >= 2 && unhealthy == 0 {
        HealthState::Healthy
    } else {
        HealthState::Degraded
    }
}

fn valid_report(report: &HealthReport, now: i64) -> bool {
    report.sequence > 0
        && valid_identifier(&report.gateway_id)
        && now.abs_diff(report.observed_at) <= SAMPLE_CLOCK_SKEW_SECONDS as u64
        && report.checks.len() <= 8
        && report.checks.iter().all(|check| {
            matches!(
                check.name.as_str(),
                "onion_reachable" | "gateway_protocol" | "dns_upstream" | "exit_reachability"
            ) && matches!(
                check.latency_bucket.as_str(),
                "fast" | "normal" | "slow" | "timeout"
            )
        })
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn health_name(value: HealthState) -> &'static str {
    match value {
        HealthState::Healthy => "healthy",
        HealthState::Degraded => "degraded",
        HealthState::Unhealthy => "unhealthy",
        HealthState::Unknown => "unknown",
    }
}

fn parse_health(value: &str) -> Option<HealthState> {
    match value {
        "healthy" => Some(HealthState::Healthy),
        "degraded" => Some(HealthState::Degraded),
        "unhealthy" => Some(HealthState::Unhealthy),
        "unknown" => Some(HealthState::Unknown),
        _ => None,
    }
}

fn load_name(value: LoadBucket) -> &'static str {
    match value {
        LoadBucket::Unknown => "unknown",
        LoadBucket::Low => "low",
        LoadBucket::Medium => "medium",
        LoadBucket::High => "high",
        LoadBucket::Saturated => "saturated",
    }
}

fn capacity_name(value: CapacityBucket) -> &'static str {
    match value {
        CapacityBucket::Small => "small",
        CapacityBucket::Medium => "medium",
        CapacityBucket::Large => "large",
    }
}
