//! Loopback-only TLS listener and isolated management exporter.

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::config::{GatewayConfig, TlsConfig};
use crate::health::{Metrics, PrivacyEventBuffer, PrivacyEventKind};
use crate::protocol::ProtocolHandler;
use crate::rate_limit::CircuitBreaker;
use crate::session::SessionManager;
use crate::{GatewayErrorCode, GatewayResult};

#[derive(Clone)]
pub struct GatewayServer {
    config: GatewayConfig,
    protocol: ProtocolHandler,
    sessions: SessionManager,
    events: Arc<PrivacyEventBuffer>,
}

impl GatewayServer {
    pub fn new(
        config: GatewayConfig,
        protocol: ProtocolHandler,
        sessions: SessionManager,
        events: Arc<PrivacyEventBuffer>,
    ) -> Self {
        Self {
            config,
            protocol,
            sessions,
            events,
        }
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> GatewayResult<()> {
        self.config.validate()?;
        let listener = bounded_listener(
            self.config.onion_listener,
            self.config.limits.listen_backlog,
        )?;
        let tls = TlsAcceptor::from(load_tls(&self.config.tls)?);
        let connections = Arc::new(Semaphore::new(self.config.limits.max_connections));
        let mut tasks = JoinSet::new();

        loop {
            while tasks.try_join_next().is_some() {}
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        self.sessions.set_draining(true);
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let (stream, _) = accepted.map_err(|_| GatewayErrorCode::Internal)?;
                    let Ok(permit) = connections.clone().try_acquire_owned() else {
                        drop(stream);
                        continue;
                    };
                    if self.sessions.is_draining() {
                        let _ = self.events.record(PrivacyEventKind::Draining, None);
                        drop(stream);
                        drop(permit);
                        continue;
                    }
                    let tls = tls.clone();
                    let protocol = self.protocol.clone();
                    let handshake_timeout = self.config.limits.handshake_timeout();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let accepted = tokio::time::timeout(handshake_timeout, tls.accept(stream)).await;
                        if let Ok(Ok(tls_stream)) = accepted {
                            let _ = protocol.serve_io(tls_stream).await;
                        }
                    });
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }

        let grace = Duration::from_secs(self.config.drain_grace_seconds);
        if tokio::time::timeout(grace, async { while tasks.join_next().await.is_some() {} })
            .await
            .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        Ok(())
    }
}

fn bounded_listener(address: std::net::SocketAddr, backlog: u32) -> GatewayResult<TcpListener> {
    if !address.ip().is_loopback() {
        return Err(GatewayErrorCode::InvalidConfiguration.into());
    }
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4().map_err(|_| GatewayErrorCode::InvalidConfiguration)?
    } else {
        TcpSocket::new_v6().map_err(|_| GatewayErrorCode::InvalidConfiguration)?
    };
    socket
        .set_reuseaddr(true)
        .map_err(|_| GatewayErrorCode::InvalidConfiguration)?;
    socket
        .bind(address)
        .map_err(|_| GatewayErrorCode::InvalidConfiguration)?;
    socket
        .listen(backlog)
        .map_err(|_| GatewayErrorCode::InvalidConfiguration.into())
}

fn load_tls(config: &TlsConfig) -> GatewayResult<Arc<rustls::ServerConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut certificate_reader = BufReader::new(
        File::open(&config.certificate_chain)
            .map_err(|_| GatewayErrorCode::InvalidConfiguration)?,
    );
    let certificates: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GatewayErrorCode::InvalidConfiguration)?;
    let mut key_reader = BufReader::new(
        File::open(&config.private_key).map_err(|_| GatewayErrorCode::InvalidConfiguration)?,
    );
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| GatewayErrorCode::InvalidConfiguration)?
        .ok_or(GatewayErrorCode::InvalidConfiguration)?;
    if certificates.is_empty() {
        return Err(GatewayErrorCode::InvalidConfiguration.into());
    }
    let server = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|_| GatewayErrorCode::InvalidConfiguration)?;
    Ok(Arc::new(server))
}

/// Serves only fixed, label-free metrics and readiness on a loopback management
/// socket. It has no mutation or data-plane endpoints.
pub fn bind_management(address: std::net::SocketAddr) -> GatewayResult<TcpListener> {
    bounded_listener(address, 32)
}

pub async fn serve_management(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    sessions: SessionManager,
    circuit: Arc<CircuitBreaker>,
) -> GatewayResult<()> {
    let permits = Arc::new(Semaphore::new(32));
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|_| GatewayErrorCode::Internal)?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let metrics = metrics.clone();
        let sessions = sessions.clone();
        let circuit = circuit.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = handle_management(stream, metrics, sessions, circuit).await;
        });
    }
}

async fn handle_management(
    mut stream: TcpStream,
    metrics: Arc<Metrics>,
    sessions: SessionManager,
    circuit: Arc<CircuitBreaker>,
) -> GatewayResult<()> {
    let mut request = [0u8; 4_096];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut request))
        .await
        .map_err(|_| GatewayErrorCode::Timeout)?
        .map_err(|_| GatewayErrorCode::ProtocolViolation)?;
    if read == request.len()
        || !request[..read]
            .windows(4)
            .any(|window| window == b"\r\n\r\n")
    {
        return Err(GatewayErrorCode::MessageTooLarge.into());
    }
    let request =
        std::str::from_utf8(&request[..read]).map_err(|_| GatewayErrorCode::ProtocolViolation)?;
    let first_line = request
        .lines()
        .next()
        .ok_or(GatewayErrorCode::ProtocolViolation)?;
    let ready = !sessions.is_draining() && !circuit.is_open();
    let (status, content_type, body) = match first_line {
        "GET /metrics HTTP/1.1" => (
            "200 OK",
            "text/plain; version=0.0.4",
            metrics.render_prometheus(sessions.active_sessions(), sessions.active_streams(), ready),
        ),
        "GET /healthz HTTP/1.1" if ready => ("200 OK", "text/plain", "ready\n".to_owned()),
        "GET /healthz HTTP/1.1" => (
            "503 Service Unavailable",
            "text/plain",
            "not-ready\n".to_owned(),
        ),
        _ => ("404 Not Found", "text/plain", "not-found\n".to_owned()),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    tokio::time::timeout(
        Duration::from_secs(2),
        stream.write_all(response.as_bytes()),
    )
    .await
    .map_err(|_| GatewayErrorCode::Timeout)?
    .map_err(|_| GatewayErrorCode::Internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_helper_rejects_public_addresses() {
        assert_eq!(
            bounded_listener("0.0.0.0:0".parse().unwrap(), 1)
                .unwrap_err()
                .code,
            GatewayErrorCode::InvalidConfiguration
        );
    }
}
