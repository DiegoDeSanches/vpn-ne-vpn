#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use onionroute_gateway_daemon::acl::AclEngine;
use onionroute_gateway_daemon::auth::DenyAllAuthenticationVerifier;
use onionroute_gateway_daemon::config::GatewayConfig;
use onionroute_gateway_daemon::dns::{DnsResolver, UdpTcpDnsTransport, WireDnsResolver};
use onionroute_gateway_daemon::egress::{TcpEgressConnector, TokioEgressDialer};
use onionroute_gateway_daemon::health::{HealthAgent, Metrics, PrivacyEventBuffer};
use onionroute_gateway_daemon::protocol::ProtocolHandler;
use onionroute_gateway_daemon::rate_limit::CircuitBreaker;
use onionroute_gateway_daemon::server::{bind_management, serve_management, GatewayServer};
use onionroute_gateway_daemon::session::SessionManager;
use onionroute_gateway_daemon::{GatewayErrorCode, GatewayResult};
use tokio::sync::watch;
#[tokio::main]
async fn main() {
    if run().await.is_err() {
        std::process::exit(1);
    }
}

async fn run() -> GatewayResult<()> {
    let config_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| "/etc/onionroute-gateway/gateway.json".into());
    let config = GatewayConfig::load(&config_path)?;
    let acl = AclEngine::new(config.acl.clone());
    let resolver: Arc<dyn DnsResolver> = Arc::new(WireDnsResolver::new(
        config.dns.clone(),
        acl.clone(),
        UdpTcpDnsTransport,
    )?);
    let sessions = SessionManager::new(config.limits.clone())?;
    let metrics = Arc::new(Metrics::default());
    let events = Arc::new(PrivacyEventBuffer::new(
        config.privacy_events.clone(),
        config.gateway_id.clone(),
    ));
    let circuit = Arc::new(CircuitBreaker::new(
        config.limits.circuit_failure_threshold,
        Duration::from_secs(config.limits.circuit_cooldown_seconds),
    ));
    let egress = TcpEgressConnector::new(
        acl,
        resolver.clone(),
        Arc::new(TokioEgressDialer),
        circuit.clone(),
        metrics.clone(),
        events.clone(),
        config.limits.connect_timeout(),
    );
    let protocol = ProtocolHandler::new(
        config.gateway_id.clone(),
        config.limits.clone(),
        Arc::new(DenyAllAuthenticationVerifier),
        sessions.clone(),
        egress,
        resolver,
        metrics.clone(),
        events.clone(),
    );
    let server = GatewayServer::new(config.clone(), protocol, sessions.clone(), events.clone());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let management_listener = bind_management(config.management_listener)?;
    let management = tokio::spawn(serve_management(
        management_listener,
        metrics,
        sessions.clone(),
        circuit,
    ));
    let health =
        tokio::spawn(HealthAgent::new(events, sessions.clone(), Duration::from_secs(30)).run());
    let mut server_task = tokio::spawn(server.run(shutdown_rx));

    install_drain_signal(sessions.clone());
    tokio::select! {
        server_result = &mut server_task => {
            management.abort();
            health.abort();
            return server_result.map_err(|_| GatewayErrorCode::Internal)?;
        }
        signal_result = wait_for_shutdown() => signal_result?,
    }
    sessions.set_draining(true);
    let _ = shutdown_tx.send(true);
    let result = server_task.await.map_err(|_| GatewayErrorCode::Internal)?;
    management.abort();
    health.abort();
    result
}

#[cfg(unix)]
fn install_drain_signal(sessions: SessionManager) {
    tokio::spawn(async move {
        let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
        else {
            return;
        };
        while signal.recv().await.is_some() {
            sessions.set_draining(true);
        }
    });
}

#[cfg(not(unix))]
fn install_drain_signal(_sessions: SessionManager) {}

#[cfg(unix)]
async fn wait_for_shutdown() -> GatewayResult<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| GatewayErrorCode::Internal)?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| GatewayErrorCode::Internal)?;
    tokio::select! {
        _ = terminate.recv() => Ok(()),
        _ = interrupt.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown() -> GatewayResult<()> {
    tokio::signal::ctrl_c()
        .await
        .map_err(|_| GatewayErrorCode::Internal.into())
}
