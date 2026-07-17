#![forbid(unsafe_code)]
//! Gateway revocation lifecycle service for admin and signing workloads.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use onionroute_directory_client::GatewayRevocation;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::Mutex;

const WORKLOAD_SUBJECT_HEADER: &str = "x-onionroute-workload-subject";

/// Internal request with actor retained only in the administrative database.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRevocationRequest {
    /// Public revocation record that will enter the signed directory.
    pub revocation: GatewayRevocation,
    /// Authenticated human/operator audit subject; never published.
    pub actor: String,
}

/// Revocation repository failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RevocationError {
    /// Conflicting active revocation exists.
    #[error("active revocation already exists")]
    Conflict,
    /// Persistence operation failed.
    #[error("revocation persistence operation failed")]
    Persistence,
}

/// Revocation storage used by the admin and signing pipelines.
#[async_trait]
pub trait RevocationRepository: Send + Sync {
    /// Creates a gateway revocation.
    async fn create(&self, request: CreateRevocationRequest) -> Result<(), RevocationError>;
    /// Returns active public gateway revocations for the next signed document.
    async fn active(&self) -> Result<Vec<GatewayRevocation>, RevocationError>;
}

/// PostgreSQL revocation repository.
#[derive(Clone)]
pub struct PgRevocationRepository {
    pool: PgPool,
}

impl PgRevocationRepository {
    /// Creates a repository with a revocation-service DB role.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RevocationRepository for PgRevocationRepository {
    async fn create(&self, request: CreateRevocationRequest) -> Result<(), RevocationError> {
        sqlx::query(
            "INSERT INTO revocations \
             (subject_type, subject_id, reason_code, revoked_at, expires_at, created_by) \
             VALUES ('gateway',$1,$2,to_timestamp($3), \
                     CASE WHEN $4::double precision IS NULL THEN NULL ELSE to_timestamp($4) END,$5)",
        )
        .bind(&request.revocation.gateway_id)
        .bind(&request.revocation.reason_code)
        .bind(request.revocation.revoked_at as f64)
        .bind(request.revocation.expires_at.map(|value| value as f64))
        .bind(&request.actor)
        .execute(&self.pool)
        .await
        .map_err(|error| {
            if error
                .as_database_error()
                .is_some_and(|database| database.is_unique_violation())
            {
                RevocationError::Conflict
            } else {
                RevocationError::Persistence
            }
        })?;
        Ok(())
    }

    async fn active(&self) -> Result<Vec<GatewayRevocation>, RevocationError> {
        let rows = sqlx::query_as::<_, (String, String, f64, Option<f64>)>(
            "SELECT subject_id, reason_code, EXTRACT(EPOCH FROM revoked_at), \
                    EXTRACT(EPOCH FROM expires_at) \
             FROM revocations WHERE subject_type='gateway' AND revoked_at <= now() \
             AND (expires_at IS NULL OR expires_at > now()) ORDER BY subject_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| RevocationError::Persistence)?;
        Ok(rows
            .into_iter()
            .map(|row| GatewayRevocation {
                gateway_id: row.0,
                reason_code: row.1,
                revoked_at: row.2 as i64,
                expires_at: row.3.map(|value| value as i64),
            })
            .collect())
    }
}

/// In-memory revocation repository.
#[derive(Default)]
pub struct MemoryRevocationRepository {
    records: Mutex<Vec<CreateRevocationRequest>>,
}

#[async_trait]
impl RevocationRepository for MemoryRevocationRepository {
    async fn create(&self, request: CreateRevocationRequest) -> Result<(), RevocationError> {
        let mut records = self.records.lock().await;
        if records
            .iter()
            .any(|existing| existing.revocation.gateway_id == request.revocation.gateway_id)
        {
            return Err(RevocationError::Conflict);
        }
        records.push(request);
        Ok(())
    }

    async fn active(&self) -> Result<Vec<GatewayRevocation>, RevocationError> {
        Ok(self
            .records
            .lock()
            .await
            .iter()
            .map(|record| record.revocation.clone())
            .collect())
    }
}

/// Dedicated revocation workload ingress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationIngressConfig {
    /// Loopback bind behind workload mTLS.
    pub bind: SocketAddr,
    /// Other control-plane listeners that may not be shared.
    pub forbidden_shared_binds: Vec<SocketAddr>,
}

impl RevocationIngressConfig {
    /// Rejects public and shared listeners.
    pub fn validate(&self) -> Result<(), RevocationIngressError> {
        if !self.bind.ip().is_loopback() || self.forbidden_shared_binds.contains(&self.bind) {
            return Err(RevocationIngressError::UnsafeOrSharedIngress);
        }
        Ok(())
    }
}

/// Revocation ingress policy violation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RevocationIngressError {
    /// Listener is public or shared with another API class.
    #[error("revocation API requires a separate private workload ingress")]
    UnsafeOrSharedIngress,
}

#[derive(Clone)]
struct HttpState {
    repository: Arc<dyn RevocationRepository>,
}

/// Builds the internal revocation API.
pub fn router(repository: Arc<dyn RevocationRepository>) -> Router {
    Router::new()
        .route("/revocation/v1/gateways", post(create).get(active))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(HttpState { repository })
}

async fn create(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<CreateRevocationRequest>,
) -> StatusCode {
    if workload_subject(&headers) != Some("admin-api") {
        return StatusCode::UNAUTHORIZED;
    }
    if !valid_request(&request) {
        return StatusCode::BAD_REQUEST;
    }
    match state.repository.create(request).await {
        Ok(()) => StatusCode::CREATED,
        Err(RevocationError::Conflict) => StatusCode::CONFLICT,
        Err(RevocationError::Persistence) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn active(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<Vec<GatewayRevocation>>, StatusCode> {
    if workload_subject(&headers) != Some("directory-publisher") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    state
        .repository
        .active()
        .await
        .map(Json)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

fn workload_subject(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(WORKLOAD_SUBJECT_HEADER)
        .and_then(|value| value.to_str().ok())
}

fn valid_request(request: &CreateRevocationRequest) -> bool {
    !request.actor.is_empty()
        && request.actor.len() <= 128
        && !request.revocation.gateway_id.is_empty()
        && request.revocation.gateway_id.len() <= 64
        && !request.revocation.reason_code.is_empty()
        && request.revocation.reason_code.len() <= 64
        && request
            .revocation
            .expires_at
            .map_or(true, |expires| expires > request.revocation.revoked_at)
}
