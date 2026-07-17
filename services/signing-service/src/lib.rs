#![forbid(unsafe_code)]
//! Isolated online-intermediate directory signing API.
//!
//! The offline root key is intentionally absent from every type and endpoint here.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use onionroute_directory_client::{
    sign_directory, validate_document_semantics, DirectoryDocument, SignedDirectory,
    SignedTrustBundle,
};
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::Mutex;

const SIGNING_SUBJECT_HEADER: &str = "x-onionroute-signing-subject";

/// Online signing failure without secret or document details.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SigningError {
    /// Draft is malformed, stale, or outside the short validity policy.
    #[error("directory draft violates signing policy")]
    InvalidDraft,
    /// The configured online key is not root-authorized by the provisioned bundle.
    #[error("online signing key is unauthorized")]
    UnauthorizedKey,
    /// Publication transaction failed.
    #[error("signed directory publication failed")]
    Publication,
}

/// Isolated signing backend contract. Implementations receive no root private key.
pub trait OnlineSigner: Send + Sync {
    /// Signs one validated draft using an online intermediate.
    fn sign(&self, document: &DirectoryDocument) -> Result<SignedDirectory, SigningError>;
}

/// Reference Ed25519 online signer. Production deployments should construct this
/// from a Vault/HSM-backed adapter rather than an exportable local seed.
pub struct LocalOnlineSigner {
    key: SigningKey,
    key_id: String,
    trust_bundle: SignedTrustBundle,
}

impl LocalOnlineSigner {
    /// Creates an online signer only if the public key is authorized and not revoked.
    pub fn new(
        key: SigningKey,
        key_id: String,
        trust_bundle: SignedTrustBundle,
    ) -> Result<Self, SigningError> {
        let signer = Self {
            key,
            key_id,
            trust_bundle,
        };
        if !signer.is_authorized_at(now_unix()) {
            return Err(SigningError::UnauthorizedKey);
        }
        Ok(signer)
    }

    fn is_authorized_at(&self, now: i64) -> bool {
        let expected_public_key = URL_SAFE_NO_PAD.encode(self.key.verifying_key().to_bytes());
        self.trust_bundle.bundle.format_version == 1
            && self.trust_bundle.bundle.issued_at <= now.saturating_add(300)
            && self.trust_bundle.bundle.expires_at > now
            && self
                .trust_bundle
                .bundle
                .signing_keys
                .iter()
                .any(|certificate| {
                    certificate.key_id == self.key_id
                        && certificate.algorithm == "ed25519"
                        && certificate.public_key == expected_public_key
                        && certificate.valid_from <= now
                        && certificate.valid_until > now
                })
            && !self
                .trust_bundle
                .bundle
                .revoked_signing_key_ids
                .contains(&self.key_id)
    }
}

impl OnlineSigner for LocalOnlineSigner {
    fn sign(&self, document: &DirectoryDocument) -> Result<SignedDirectory, SigningError> {
        let now = now_unix();
        if !self.is_authorized_at(now) {
            return Err(SigningError::UnauthorizedKey);
        }
        validate_draft(document, now)?;
        sign_directory(&self.key, &self.key_id, self.trust_bundle.clone(), document)
            .map_err(|_| SigningError::UnauthorizedKey)
    }
}

/// Atomic handoff from a signed draft to the directory-serving table.
#[async_trait]
pub trait PublicationRepository: Send + Sync {
    /// Publishes only a previously reserved draft version.
    async fn publish(
        &self,
        document: &DirectoryDocument,
        envelope: &SignedDirectory,
    ) -> Result<(), SigningError>;
}

/// PostgreSQL publication repository.
#[derive(Clone)]
pub struct PgPublicationRepository {
    pool: PgPool,
}

impl PgPublicationRepository {
    /// Creates a publication repository using the signer-specific DB role.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PublicationRepository for PgPublicationRepository {
    async fn publish(
        &self,
        document: &DirectoryDocument,
        envelope: &SignedDirectory,
    ) -> Result<(), SigningError> {
        let unsigned = serde_json::to_value(document).map_err(|_| SigningError::Publication)?;
        let signed = serde_jcs::to_vec(envelope).map_err(|_| SigningError::Publication)?;
        let version = i64::try_from(document.version).map_err(|_| SigningError::Publication)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| SigningError::Publication)?;
        sqlx::query(
            "UPDATE directory_versions SET publication_state='superseded' \
             WHERE publication_state='published' AND version < $1",
        )
        .bind(version)
        .execute(&mut *transaction)
        .await
        .map_err(|_| SigningError::Publication)?;
        let result = sqlx::query(
            "UPDATE directory_versions SET unsigned_document=$2, signed_envelope=$3, \
             signing_key_id=$4, issued_at=to_timestamp($5), expires_at=to_timestamp($6), \
             trust_bundle_version=$7, \
             publication_state='published', published_at=now() \
             WHERE version=$1 AND publication_state='draft'",
        )
        .bind(version)
        .bind(unsigned)
        .bind(signed)
        .bind(&envelope.signing_key_id)
        .bind(document.issued_at as f64)
        .bind(document.expires_at as f64)
        .bind(
            i64::try_from(envelope.trust_bundle.bundle.bundle_version)
                .map_err(|_| SigningError::Publication)?,
        )
        .execute(&mut *transaction)
        .await
        .map_err(|_| SigningError::Publication)?;
        if result.rows_affected() != 1 {
            return Err(SigningError::Publication);
        }
        transaction
            .commit()
            .await
            .map_err(|_| SigningError::Publication)
    }
}

/// In-memory publication sink for integration tests.
#[derive(Default)]
pub struct MemoryPublicationRepository {
    published_versions: Mutex<Vec<u64>>,
}

impl MemoryPublicationRepository {
    /// Returns published versions.
    pub async fn published_versions(&self) -> Vec<u64> {
        self.published_versions.lock().await.clone()
    }
}

#[async_trait]
impl PublicationRepository for MemoryPublicationRepository {
    async fn publish(
        &self,
        document: &DirectoryDocument,
        _: &SignedDirectory,
    ) -> Result<(), SigningError> {
        self.published_versions.lock().await.push(document.version);
        Ok(())
    }
}

/// Dedicated signing listener configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningIngressConfig {
    /// Loopback listener behind a workload-authenticated private proxy.
    pub bind: SocketAddr,
    /// Admin listener, which must remain separate.
    pub admin_api_bind: Option<SocketAddr>,
}

impl SigningIngressConfig {
    /// Enforces a private, separate ingress.
    pub fn validate(&self) -> Result<(), SigningIngressError> {
        if !self.bind.ip().is_loopback() || self.admin_api_bind == Some(self.bind) {
            return Err(SigningIngressError::UnsafeOrSharedIngress);
        }
        Ok(())
    }
}

/// Signing ingress policy violation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SigningIngressError {
    /// The signing listener is public or shared with admin ingress.
    #[error("signing API requires a separate private workload ingress")]
    UnsafeOrSharedIngress,
}

#[derive(Clone)]
struct HttpState {
    signer: Arc<dyn OnlineSigner>,
    repository: Arc<dyn PublicationRepository>,
}

/// Builds the internal signing API.
pub fn router(signer: Arc<dyn OnlineSigner>, repository: Arc<dyn PublicationRepository>) -> Router {
    Router::new()
        .route("/signing/v1/directories", post(sign_and_publish))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .with_state(HttpState { signer, repository })
}

async fn sign_and_publish(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(document): Json<DirectoryDocument>,
) -> Result<(StatusCode, Json<SignedDirectory>), StatusCode> {
    let authorized = headers
        .get(SIGNING_SUBJECT_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|subject| subject == "directory-publisher");
    if !authorized {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let envelope = state.signer.sign(&document).map_err(signing_status)?;
    state
        .repository
        .publish(&document, &envelope)
        .await
        .map_err(signing_status)?;
    Ok((StatusCode::CREATED, Json(envelope)))
}

fn validate_draft(document: &DirectoryDocument, now: i64) -> Result<(), SigningError> {
    if document.format_version != "2.0"
        || document.version == 0
        || document.issued_at < now - 300
        || document.issued_at > now + 300
        || document.expires_at <= now
        || !document
            .expires_at
            .checked_sub(document.issued_at)
            .is_some_and(|lifetime| lifetime > 0 && lifetime <= 6 * 60 * 60)
    {
        return Err(SigningError::InvalidDraft);
    }
    validate_document_semantics(document, now, 300).map_err(|_| SigningError::InvalidDraft)?;
    Ok(())
}

fn signing_status(error: SigningError) -> StatusCode {
    match error {
        SigningError::InvalidDraft => StatusCode::BAD_REQUEST,
        SigningError::UnauthorizedKey => StatusCode::SERVICE_UNAVAILABLE,
        SigningError::Publication => StatusCode::CONFLICT,
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
