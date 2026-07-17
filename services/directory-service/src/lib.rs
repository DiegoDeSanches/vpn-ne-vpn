#![forbid(unsafe_code)]
//! Onion-only client directory and bootstrap API.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderValue, Response, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use onionroute_directory_client::SignedDirectory;
use semver::Version;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::RwLock;

pub mod builder;
pub use builder::{DirectoryBuildError, PgDirectoryBuilder};

/// Persisted published envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredDirectory {
    /// Monotonic directory version.
    pub version: u64,
    /// Serialized signed envelope bytes.
    pub envelope: Vec<u8>,
}

/// Storage failure without database details or sensitive values.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RepositoryError {
    /// No unexpired published directory exists.
    #[error("no published unexpired directory is available")]
    Unavailable,
    /// Persistence operation failed.
    #[error("directory persistence operation failed")]
    Persistence,
}

/// Minimal storage contract used by the public client ingress.
#[async_trait]
pub trait DirectoryRepository: Send + Sync {
    /// Loads the newest published, unexpired envelope.
    async fn latest(&self) -> Result<StoredDirectory, RepositoryError>;
}

/// PostgreSQL repository backed by `directory_versions`.
#[derive(Clone)]
pub struct PgDirectoryRepository {
    pool: PgPool,
}

impl PgDirectoryRepository {
    /// Creates a repository using an existing least-privilege pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DirectoryRepository for PgDirectoryRepository {
    async fn latest(&self) -> Result<StoredDirectory, RepositoryError> {
        let row = sqlx::query_as::<_, (i64, Vec<u8>)>(
            "SELECT version, signed_envelope FROM directory_versions \
             WHERE publication_state = 'published' AND expires_at > now() \
             ORDER BY version DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| RepositoryError::Persistence)?
        .ok_or(RepositoryError::Unavailable)?;
        let version = u64::try_from(row.0).map_err(|_| RepositoryError::Persistence)?;
        Ok(StoredDirectory {
            version,
            envelope: row.1,
        })
    }
}

/// In-memory repository for deterministic integration tests and local mocks.
#[derive(Default)]
pub struct MemoryDirectoryRepository {
    latest: RwLock<Option<StoredDirectory>>,
}

impl MemoryDirectoryRepository {
    /// Creates a repository containing one envelope.
    pub fn with_directory(directory: StoredDirectory) -> Self {
        Self {
            latest: RwLock::new(Some(directory)),
        }
    }

    /// Atomically replaces the published envelope.
    pub async fn publish(&self, directory: StoredDirectory) {
        *self.latest.write().await = Some(directory);
    }
}

#[async_trait]
impl DirectoryRepository for MemoryDirectoryRepository {
    async fn latest(&self) -> Result<StoredDirectory, RepositoryError> {
        self.latest
            .read()
            .await
            .clone()
            .ok_or(RepositoryError::Unavailable)
    }
}

/// Startup policy proving that the client API is reachable only through a local
/// Tor Onion Service mapping, never a public clearnet listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientIngressConfig {
    /// Local application listener consumed by Tor's HiddenServicePort mapping.
    pub bind: SocketAddr,
    /// Expected public Tor v3 hostname.
    pub onion_hostname: String,
}

impl ClientIngressConfig {
    /// Rejects any public bind or malformed Onion Service hostname.
    pub fn validate(&self) -> Result<(), IngressConfigError> {
        if !self.bind.ip().is_loopback() || !valid_onion_hostname(&self.onion_hostname) {
            return Err(IngressConfigError::UnsafeClientIngress);
        }
        Ok(())
    }
}

/// Unsafe listener configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IngressConfigError {
    /// The client API is not isolated behind a valid v3 Onion Service mapping.
    #[error("client API must bind loopback behind a Tor v3 Onion Service")]
    UnsafeClientIngress,
}

/// Bounded bootstrap request. It intentionally has no account, install, device,
/// or persistent anonymous identifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRequest {
    /// Semantic client version.
    pub client_version: String,
    /// Allow-listed platform.
    pub platform: String,
    /// Release channel.
    pub channel: String,
}

/// Non-personalized bootstrap response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BootstrapResponse {
    /// Bootstrap response schema version.
    pub format_version: u16,
    /// Signed directory verified by the client using its pinned root.
    pub directory: SignedDirectory,
    /// Coarse suggested refresh interval; expiry always takes precedence.
    pub refresh_after_seconds: u32,
}

#[derive(Clone)]
struct HttpState {
    repository: Arc<dyn DirectoryRepository>,
}

/// Builds the Onion-only client router. Deployment must call `validate` before binding.
pub fn router(repository: Arc<dyn DirectoryRepository>) -> Router {
    Router::new()
        .route("/client/v2/directory", get(get_directory))
        .route("/client/v1/bootstrap", post(client_bootstrap))
        .layer(DefaultBodyLimit::max(4 * 1024))
        .with_state(HttpState { repository })
}

async fn get_directory(State(state): State<HttpState>) -> Response<Body> {
    let stored = match state.repository.latest().await {
        Ok(stored) => stored,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE),
    };
    let mut response = Response::new(Body::from(stored.envelope));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.onionroute.directory-v2+json"),
    );
    apply_private_headers(&mut response);
    response
}

async fn client_bootstrap(
    State(state): State<HttpState>,
    Json(request): Json<BootstrapRequest>,
) -> Response<Body> {
    if !valid_bootstrap_request(&request) {
        return error_response(StatusCode::BAD_REQUEST);
    }
    let stored = match state.repository.latest().await {
        Ok(stored) => stored,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE),
    };
    let directory: SignedDirectory = match serde_json::from_slice(&stored.envelope) {
        Ok(directory) => directory,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE),
    };
    let body = match serde_json::to_vec(&BootstrapResponse {
        format_version: 1,
        directory,
        refresh_after_seconds: 900,
    }) {
        Ok(body) => body,
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    apply_private_headers(&mut response);
    response
}

fn valid_bootstrap_request(request: &BootstrapRequest) -> bool {
    request.client_version.len() <= 32
        && Version::parse(&request.client_version).is_ok()
        && matches!(
            request.platform.as_str(),
            "windows" | "macos" | "linux" | "android" | "ios"
        )
        && matches!(request.channel.as_str(), "stable" | "beta")
}

fn error_response(status: StatusCode) -> Response<Body> {
    let body = if status == StatusCode::BAD_REQUEST {
        r#"{"error":"invalid_request"}"#
    } else {
        r#"{"error":"directory_unavailable"}"#
    };
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    apply_private_headers(&mut response);
    response
}

fn apply_private_headers(response: &mut Response<Body>) {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store, max-age=0"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

fn valid_onion_hostname(hostname: &str) -> bool {
    let Some(service_id) = hostname.strip_suffix(".onion") else {
        return false;
    };
    service_id.len() == 56
        && service_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
}
