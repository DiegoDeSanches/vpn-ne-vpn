#![forbid(unsafe_code)]

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use onionroute_directory_client::SignedTrustBundle;
use onionroute_signing_service::{
    router, LocalOnlineSigner, PgPublicationRepository, SigningIngressConfig,
};
use sqlx::postgres::PgPoolOptions;
use tracing::info;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroize;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .without_time()
        .init();
    let bind: SocketAddr = env::var("OR_SIGNING_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8083".to_owned())
        .parse()?;
    let admin_api_bind = env::var("OR_ADMIN_BIND")
        .ok()
        .map(|value| value.parse())
        .transpose()?;
    let config = SigningIngressConfig {
        bind,
        admin_api_bind,
    };
    config.validate()?;

    // Experimental local adapter only. Production deployment replaces this with
    // Vault/HSM signing; the offline root is never accepted by this process.
    if env::var("OR_EXPERIMENTAL_LOCAL_SIGNER").as_deref() != Ok("1") {
        return Err("no production Vault/HSM signer adapter configured".into());
    }
    let mut encoded_seed = tokio::fs::read(env::var("OR_ONLINE_SIGNING_SEED_FILE")?).await?;
    while encoded_seed
        .last()
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        encoded_seed.pop();
    }
    let mut seed_bytes = URL_SAFE_NO_PAD.decode(&encoded_seed)?;
    encoded_seed.zeroize();
    let mut seed: [u8; 32] = seed_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "online signing seed must contain exactly 32 bytes")?;
    seed_bytes.zeroize();
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let trust_bundle: SignedTrustBundle =
        serde_json::from_slice(&tokio::fs::read(env::var("OR_SIGNED_TRUST_BUNDLE_FILE")?).await?)?;
    let signer = Arc::new(LocalOnlineSigner::new(
        key,
        env::var("OR_ONLINE_SIGNING_KEY_ID")?,
        trust_bundle,
    )?);
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&env::var("OR_DATABASE_URL")?)
        .await?;
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    info!(bind = %config.bind, "isolated online signing ingress ready");
    axum::serve(
        listener,
        router(signer, Arc::new(PgPublicationRepository::new(pool))),
    )
    .await?;
    Ok(())
}
