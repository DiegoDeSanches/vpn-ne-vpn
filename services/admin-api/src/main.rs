#![forbid(unsafe_code)]

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use onionroute_admin_api::{router, AdminIngressConfig, PgAdminRepository};
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
    let bind: SocketAddr = env::var("OR_ADMIN_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8082".to_owned())
        .parse()?;
    let client_api_bind = env::var("OR_CLIENT_BIND")
        .ok()
        .map(|value| value.parse())
        .transpose()?;
    let config = AdminIngressConfig {
        bind,
        client_api_bind,
    };
    config.validate()?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&env::var("OR_DATABASE_URL")?)
        .await?;
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    info!(bind = %config.bind, "administrator ingress ready behind dedicated mTLS proxy");
    axum::serve(listener, router(Arc::new(PgAdminRepository::new(pool)))).await?;
    Ok(())
}
