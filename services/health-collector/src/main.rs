#![forbid(unsafe_code)]

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use onionroute_health_collector::{router, HealthIngressConfig, PgHealthRepository};
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
    let bind: SocketAddr = env::var("OR_HEALTH_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8081".to_owned())
        .parse()?;
    let config = HealthIngressConfig { bind };
    config.validate()?;
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&env::var("OR_DATABASE_URL")?)
        .await?;
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    info!(bind = %config.bind, "gateway health ingress ready behind mTLS proxy");
    axum::serve(listener, router(Arc::new(PgHealthRepository::new(pool)))).await?;
    Ok(())
}
