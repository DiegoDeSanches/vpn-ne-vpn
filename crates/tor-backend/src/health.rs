use std::sync::Arc;
use std::time::Duration;

use onionroute_common_types::transport::BoxFuture;
use onionroute_common_types::OnionResult;
use tokio_util::sync::CancellationToken;

use crate::{BackendHealth, BackendLifecycle, TorBackendExt};

/// Adapter implemented by client-core to enter/leave its fail-closed state.
pub trait HealthObserver: Send + Sync {
    /// Receives a destination-free health transition.
    fn health_changed(&self, health: BackendHealth) -> BoxFuture<'_, OnionResult<()>>;
}

/// Polls only coarse backend health and notifies client-core after changes.
///
/// `run` has an explicit cancellation token. It is a monitor, not a retry loop:
/// it does not restart Tor or open network connections on failure.
pub struct TorHealthMonitor {
    backend: Arc<dyn TorBackendExt>,
    observer: Arc<dyn HealthObserver>,
    interval: Duration,
}

impl TorHealthMonitor {
    /// Creates a monitor with a bounded polling interval.
    pub fn new(
        backend: Arc<dyn TorBackendExt>,
        observer: Arc<dyn HealthObserver>,
        interval: Duration,
    ) -> OnionResult<Self> {
        if interval < Duration::from_millis(100) || interval > Duration::from_secs(30) {
            return Err(crate::configuration_error("invalid Tor health interval"));
        }
        Ok(Self {
            backend,
            observer,
            interval,
        })
    }

    /// Reads and publishes one health snapshot, mapping backend failure to fail-closed.
    pub async fn poll_once(&self) -> OnionResult<BackendHealth> {
        let health = match self.backend.health_status().await {
            Ok(health) => health,
            Err(_) => BackendHealth {
                lifecycle: BackendLifecycle::FailedClosed,
                bootstrap_percent: 0,
                accepting_streams: false,
                active_streams: 0,
                fail_closed: true,
            },
        };
        self.observer.health_changed(health).await?;
        Ok(health)
    }

    /// Publishes changed snapshots until explicitly cancelled.
    pub async fn run(&self, cancellation: CancellationToken) -> OnionResult<()> {
        let mut last = None;
        loop {
            let health = match self.backend.health_status().await {
                Ok(health) => health,
                Err(_) => BackendHealth {
                    lifecycle: BackendLifecycle::FailedClosed,
                    bootstrap_percent: 0,
                    accepting_streams: false,
                    active_streams: 0,
                    fail_closed: true,
                },
            };
            if last != Some(health) {
                self.observer.health_changed(health).await?;
                last = Some(health);
            }
            tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                _ = tokio::time::sleep(self.interval) => {}
            }
        }
    }
}
