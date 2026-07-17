//! Closed-schema operational health, TTL privacy events, and Prometheus output.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::PrivacyEventConfig;
use crate::session::SessionManager;
use crate::{GatewayErrorCode, GatewayResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Metric {
    AcceptedSessions = 0,
    RejectedAuthentication = 1,
    OpenedStreams = 2,
    ClosedStreams = 3,
    PolicyViolations = 4,
    DnsFailures = 5,
    EgressFailures = 6,
    ProtocolViolations = 7,
    RateLimitViolations = 8,
    BytesClientToEgress = 9,
    BytesEgressToClient = 10,
    CircuitOpen = 11,
    DrainingRejections = 12,
}

const METRIC_COUNT: usize = 13;

const METRIC_NAMES: [&str; METRIC_COUNT] = [
    "onionroute_gateway_sessions_accepted_total",
    "onionroute_gateway_auth_rejected_total",
    "onionroute_gateway_streams_opened_total",
    "onionroute_gateway_streams_closed_total",
    "onionroute_gateway_policy_violations_total",
    "onionroute_gateway_dns_failures_total",
    "onionroute_gateway_egress_failures_total",
    "onionroute_gateway_protocol_violations_total",
    "onionroute_gateway_rate_limit_violations_total",
    "onionroute_gateway_client_to_egress_bytes_total",
    "onionroute_gateway_egress_to_client_bytes_total",
    "onionroute_gateway_circuit_open_total",
    "onionroute_gateway_draining_rejections_total",
];

/// Metrics have no arbitrary labels and therefore cannot accidentally include
/// a token, destination, account, address, or circuit identifier.
#[derive(Debug)]
pub struct Metrics {
    counters: [AtomicU64; METRIC_COUNT],
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            counters: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl Metrics {
    pub fn increment(&self, metric: Metric) {
        self.add(metric, 1);
    }

    pub fn add(&self, metric: Metric, value: u64) {
        self.counters[metric as usize].fetch_add(value, Ordering::Relaxed);
    }

    pub fn get(&self, metric: Metric) -> u64 {
        self.counters[metric as usize].load(Ordering::Relaxed)
    }

    pub fn render_prometheus(
        &self,
        active_sessions: usize,
        active_streams: usize,
        ready: bool,
    ) -> String {
        let mut output = String::with_capacity(2_048);
        for (index, name) in METRIC_NAMES.iter().enumerate() {
            output.push_str(name);
            output.push(' ');
            output.push_str(&self.counters[index].load(Ordering::Relaxed).to_string());
            output.push('\n');
        }
        output.push_str("onionroute_gateway_active_sessions ");
        output.push_str(&active_sessions.to_string());
        output.push('\n');
        output.push_str("onionroute_gateway_active_streams ");
        output.push_str(&active_streams.to_string());
        output.push('\n');
        output.push_str("onionroute_gateway_ready ");
        output.push_str(if ready { "1\n" } else { "0\n" });
        output
    }
}

/// Allow-listed event categories. There is intentionally no free-form message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyEventKind {
    AuthenticationRejected,
    ProtocolRejected,
    PolicyRejected,
    RateLimited,
    DnsUnavailable,
    EgressUnavailable,
    CircuitOpened,
    Draining,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyEvent {
    pub kind: PrivacyEventKind,
    pub coarse_time_bucket: u64,
    pub gateway_id: Arc<str>,
    pub ephemeral_session_handle: Option<[u8; 8]>,
    pub count: u64,
    expires_at: Instant,
}

/// Bounded in-memory event store. Purging occurs on every read/write and through
/// the health janitor, so events cannot outlive the configured TTL.
#[derive(Debug)]
pub struct PrivacyEventBuffer {
    config: PrivacyEventConfig,
    gateway_id: Arc<str>,
    events: Mutex<VecDeque<PrivacyEvent>>,
}

impl PrivacyEventBuffer {
    pub fn new(config: PrivacyEventConfig, gateway_id: String) -> Self {
        Self {
            config,
            gateway_id: Arc::from(gateway_id),
            events: Mutex::new(VecDeque::new()),
        }
    }

    pub fn record(
        &self,
        kind: PrivacyEventKind,
        ephemeral_session_handle: Option<[u8; 8]>,
    ) -> GatewayResult<()> {
        if !self.config.enabled {
            return Ok(());
        }
        let mut events = self.events.lock().map_err(|_| GatewayErrorCode::Internal)?;
        purge_locked(&mut events);
        while events.len() >= self.config.capacity {
            events.pop_front();
        }
        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        events.push_back(PrivacyEvent {
            kind,
            coarse_time_bucket: unix_seconds / self.config.coarse_bucket_seconds,
            gateway_id: self.gateway_id.clone(),
            ephemeral_session_handle,
            count: 1,
            expires_at: Instant::now() + Duration::from_secs(self.config.ttl_seconds),
        });
        Ok(())
    }

    pub fn snapshot(&self) -> GatewayResult<Vec<PrivacyEvent>> {
        let mut events = self.events.lock().map_err(|_| GatewayErrorCode::Internal)?;
        purge_locked(&mut events);
        Ok(events.iter().cloned().collect())
    }

    pub fn purge(&self) -> GatewayResult<()> {
        let mut events = self.events.lock().map_err(|_| GatewayErrorCode::Internal)?;
        purge_locked(&mut events);
        Ok(())
    }
}

fn purge_locked(events: &mut VecDeque<PrivacyEvent>) {
    let now = Instant::now();
    events.retain(|event| event.expires_at > now);
}

/// Minimal health agent. It performs only local retention cleanup; exporting to
/// a remote collector remains an operator adapter so request-path metadata never
/// enters a generic telemetry client.
pub struct HealthAgent {
    events: Arc<PrivacyEventBuffer>,
    sessions: SessionManager,
    interval: Duration,
}

impl HealthAgent {
    pub fn new(
        events: Arc<PrivacyEventBuffer>,
        sessions: SessionManager,
        interval: Duration,
    ) -> Self {
        Self {
            events,
            sessions,
            interval,
        }
    }

    pub async fn run(self) {
        let mut interval = tokio::time::interval(self.interval);
        loop {
            interval.tick().await;
            let _ = self.events.purge();
            let _ = self.sessions.purge_expired();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn privacy_events_expire_automatically_on_access() {
        let config = PrivacyEventConfig {
            ttl_seconds: 1,
            ..PrivacyEventConfig::default()
        };
        let events = PrivacyEventBuffer::new(config, "gateway-test".into());
        events
            .record(PrivacyEventKind::PolicyRejected, Some([7; 8]))
            .unwrap();
        assert_eq!(events.snapshot().unwrap().len(), 1);
        tokio::time::sleep(Duration::from_millis(1_050)).await;
        assert!(events.snapshot().unwrap().is_empty());
    }
}
