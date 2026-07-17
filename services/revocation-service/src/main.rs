#![forbid(unsafe_code)]

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use onionroute_revocation_service::{router, PgRevocationRepository, RevocationIngressConfig};
use sqlx::postgres::PgPoolOptions;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .without_time()
        .init();
    let bind: SocketAddr = env::var("OR_REVOCATION_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8084".to_owned())
        .parse()?;
    let forbidden_shared_binds = ["OR_ADMIN_BIND", "OR_SIGNING_BIND", "OR_CLIENT_BIND"]
        .iter()
        .filter_map(|name| env::var(name).ok())
        .map(|value| value.parse())
        .collect::<Result<Vec<_>, _>>()?;
    let config = RevocationIngressConfig {
        bind,
        forbidden_shared_binds,
    };
    config.validate()?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&env::var("OR_DATABASE_URL")?)
        .await?;
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    info!(bind = %config.bind, "revocation workload ingress ready");
    axum::serve(
        listener,
        router(Arc::new(PgRevocationRepository::new(pool))),
    )
    .await?;
    Ok(())
}
