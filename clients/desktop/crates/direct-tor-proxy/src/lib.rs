#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Experimental application-scoped SOCKS5-to-Tor proxy.
//!
//! The only outbound socket opened by this crate targets a pre-validated local
//! Tor SOCKS listener. Client destinations are forwarded as SOCKS address bytes;
//! domain names are never resolved by the operating system and there is no
//! direct-connect fallback.

mod config;
mod protocol;

use std::net::SocketAddr;

pub use config::{ProxyConfig, ProxyLimits, TorSocksEndpoint, UpstreamAuthentication};
use thiserror::Error;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::{oneshot, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

/// Startup, listener, or runtime failure. Per-client protocol failures are
/// intentionally contained and are not allowed to stop the listener.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// A caller supplied an unsafe or unbounded configuration.
    #[error("invalid direct Tor proxy configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// The loopback listener could not be created.
    #[error("could not bind the direct Tor proxy loopback listener")]
    Bind(#[source] std::io::Error),
    /// The listener failed after it had started.
    #[error("direct Tor proxy listener failed")]
    Listener(#[source] std::io::Error),
    /// The background task was cancelled or panicked unexpectedly.
    #[error("direct Tor proxy runtime failed")]
    Runtime,
}

/// Running proxy handle intended to be owned by the desktop daemon.
///
/// Dropping the handle signals shutdown. Call [`Self::shutdown`] when teardown
/// completion must be verified before a higher-level protection state changes.
pub struct DirectTorProxy {
    local_address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), ProxyError>>>,
}

impl DirectTorProxy {
    /// Validates the configuration, binds only `127.0.0.1`, and starts the
    /// bounded accept loop. A configured port of zero selects an ephemeral port.
    pub async fn start(config: ProxyConfig) -> Result<Self, ProxyError> {
        config.validate()?;
        let socket = TcpSocket::new_v4().map_err(ProxyError::Bind)?;
        socket.set_reuseaddr(false).map_err(ProxyError::Bind)?;
        socket
            .bind(config.listen_address)
            .map_err(ProxyError::Bind)?;
        let listener = socket
            .listen(config.limits.listen_backlog)
            .map_err(ProxyError::Bind)?;
        let local_address = listener.local_addr().map_err(ProxyError::Bind)?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(run(listener, config, shutdown_rx));
        Ok(Self {
            local_address,
            shutdown: Some(shutdown_tx),
            task: Some(task),
        })
    }

    /// Returns the actual IPv4 loopback address, including an allocated
    /// ephemeral port when port zero was requested.
    pub const fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    /// Signals shutdown, closes all active client sessions, and waits until no
    /// proxy task retains a client or upstream Tor socket.
    pub async fn shutdown(mut self) -> Result<(), ProxyError> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let Some(task) = self.task.take() else {
            return Ok(());
        };
        task.await.map_err(|_| ProxyError::Runtime)?
    }
}

impl Drop for DirectTorProxy {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

async fn run(
    listener: TcpListener,
    config: ProxyConfig,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<(), ProxyError> {
    let permits = std::sync::Arc::new(Semaphore::new(config.limits.max_clients));
    let mut clients = JoinSet::new();
    loop {
        while clients.try_join_next().is_some() {}
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (client, peer) = accepted.map_err(ProxyError::Listener)?;
                if !peer.ip().is_loopback() {
                    drop(client);
                    continue;
                }
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    drop(client);
                    continue;
                };
                let tor = config.tor.clone();
                let limits = config.limits;
                clients.spawn(async move {
                    let _permit = permit;
                    protocol::serve_client(client, tor, limits).await;
                });
            }
            Some(_) = clients.join_next(), if !clients.is_empty() => {}
        }
    }
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    Ok(())
}
