#![forbid(unsafe_code)]

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use onionroute_directory_service::{router, ClientIngressConfig, PgDirectoryRepository};
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

    let bind: SocketAddr = env::var("OR_CLIENT_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
        .parse()?;
    let config = ClientIngressConfig {
        bind,
        onion_hostname: env::var("OR_CLIENT_ONION_HOSTNAME")?,
    };
    config.validate()?;
    let database_url = env::var("OR_DATABASE_URL")?;
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&database_url)
        .await?;
    let repository = Arc::new(PgDirectoryRepository::new(pool));
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    info!(bind = %config.bind, "directory client ingress ready behind Onion Service");
    axum::serve(listener, router(repository)).await?;
    Ok(())
}
