//! Strict gateway configuration and safety validation.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;

use crate::{GatewayErrorCode, GatewayResult};

fn default_onion_listener() -> SocketAddr {
    "127.0.0.1:8443".parse().expect("static socket address")
}

fn default_management_listener() -> SocketAddr {
    "127.0.0.1:9090".parse().expect("static socket address")
}

fn default_tls_cert() -> PathBuf {
    "/etc/onionroute-gateway/tls/server.crt".into()
}

fn default_tls_key() -> PathBuf {
    "/etc/onionroute-gateway/tls/server.key".into()
}

fn default_true() -> bool {
    true
}

/// Complete daemon configuration. Unknown keys are rejected.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GatewayConfig {
    pub gateway_id: String,
    pub onion_listener: SocketAddr,
    pub management_listener: SocketAddr,
    pub tls: TlsConfig,
    pub dns: DnsConfig,
    pub acl: AclConfig,
    pub limits: LimitConfig,
    pub privacy_events: PrivacyEventConfig,
    pub drain_grace_seconds: u64,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            gateway_id: "replace-with-catalog-gateway-id".to_owned(),
            onion_listener: default_onion_listener(),
            management_listener: default_management_listener(),
            tls: TlsConfig::default(),
            dns: DnsConfig::default(),
            acl: AclConfig::default(),
            limits: LimitConfig::default(),
            privacy_events: PrivacyEventConfig::default(),
            drain_grace_seconds: 300,
        }
    }
}

impl GatewayConfig {
    pub fn load(path: &Path) -> GatewayResult<Self> {
        let raw =
            std::fs::read_to_string(path).map_err(|_| GatewayErrorCode::InvalidConfiguration)?;
        let config: Self =
            serde_json::from_str(&raw).map_err(|_| GatewayErrorCode::InvalidConfiguration)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> GatewayResult<()> {
        if self.gateway_id.is_empty()
            || self.gateway_id.len() > 64
            || !self
                .gateway_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(GatewayErrorCode::InvalidConfiguration.into());
        }
        if !self.onion_listener.ip().is_loopback()
            || !self.management_listener.ip().is_loopback()
            || self.onion_listener == self.management_listener
            || self.tls.certificate_chain.as_os_str().is_empty()
            || self.tls.private_key.as_os_str().is_empty()
        {
            return Err(GatewayErrorCode::InvalidConfiguration.into());
        }
        self.dns.validate()?;
        self.acl.validate()?;
        self.limits.validate()?;
        self.privacy_events.validate()?;
        if self.dns.max_response_bytes > self.limits.max_frame_bytes.saturating_sub(1_024) {
            return Err(GatewayErrorCode::InvalidConfiguration.into());
        }
        if self.drain_grace_seconds == 0 || self.drain_grace_seconds > 86_400 {
            return Err(GatewayErrorCode::InvalidConfiguration.into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    pub certificate_chain: PathBuf,
    pub private_key: PathBuf,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            certificate_chain: default_tls_cert(),
            private_key: default_tls_key(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    pub upstreams: Vec<SocketAddr>,
    pub query_timeout_ms: u64,
    pub max_response_bytes: usize,
    pub max_records: usize,
    pub max_cname_depth: usize,
    pub max_addresses: usize,
    pub revalidate: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            // An explicit resolver inside the egress namespace is required.
            upstreams: Vec::new(),
            query_timeout_ms: 3_000,
            max_response_bytes: 16 * 1024,
            max_records: 64,
            max_cname_depth: 8,
            max_addresses: 16,
            revalidate: true,
        }
    }
}

impl DnsConfig {
    fn validate(&self) -> GatewayResult<()> {
        if self.upstreams.is_empty()
            || self.upstreams.len() > 4
            || self.query_timeout_ms == 0
            || self.query_timeout_ms > 30_000
            || !(512..=65_535).contains(&self.max_response_bytes)
            || !(1..=256).contains(&self.max_records)
            || !(1..=16).contains(&self.max_cname_depth)
            || !(1..=64).contains(&self.max_addresses)
        {
            return Err(GatewayErrorCode::InvalidConfiguration.into());
        }
        if self.upstreams.iter().any(|upstream| {
            upstream.port() == 0 || upstream.ip().is_unspecified() || upstream.ip().is_multicast()
        }) {
            return Err(GatewayErrorCode::InvalidConfiguration.into());
        }
        Ok(())
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.query_timeout_ms)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AclConfig {
    pub blocked_ports: HashSet<u16>,
    pub management_networks: Vec<IpNet>,
    pub emergency_deny_networks: Vec<IpNet>,
    pub emergency_deny_host_suffixes: Vec<String>,
    pub cloud_metadata_ips: HashSet<IpAddr>,
}

impl Default for AclConfig {
    fn default() -> Self {
        let blocked_ports = [
            22, 23, 25, 111, 135, 137, 138, 139, 445, 2375, 2376, 3306, 3389, 5432, 5900, 6379,
            6443, 9051, 9151, 9200, 11211, 27017,
        ]
        .into_iter()
        .collect();
        let cloud_metadata_ips = [
            IpAddr::from([169, 254, 169, 254]),
            IpAddr::from([100, 100, 100, 200]),
            IpAddr::from([168, 63, 129, 16]),
        ]
        .into_iter()
        .collect();
        Self {
            blocked_ports,
            management_networks: Vec::new(),
            emergency_deny_networks: Vec::new(),
            emergency_deny_host_suffixes: Vec::new(),
            cloud_metadata_ips,
        }
    }
}

impl AclConfig {
    fn validate(&self) -> GatewayResult<()> {
        if self.blocked_ports.contains(&0)
            || self.management_networks.len() > 64
            || self.emergency_deny_networks.len() > 256
            || self.emergency_deny_host_suffixes.len() > 256
            || self
                .emergency_deny_host_suffixes
                .iter()
                .any(|suffix| suffix.is_empty() || suffix.len() > 253 || !suffix.is_ascii())
        {
            return Err(GatewayErrorCode::InvalidConfiguration.into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitConfig {
    pub max_connections: usize,
    pub listen_backlog: u32,
    pub max_sessions: usize,
    pub max_token_states: usize,
    pub max_sessions_per_token: usize,
    pub max_streams_global: usize,
    pub max_streams_per_session: usize,
    pub max_streams_per_token: usize,
    pub connection_rate_per_second: u32,
    pub connection_rate_burst: u32,
    pub bandwidth_bytes_per_second: u64,
    pub bandwidth_burst_bytes: u64,
    pub token_byte_quota: u64,
    pub max_frame_bytes: usize,
    pub max_data_bytes: usize,
    pub max_token_bytes: usize,
    pub max_proof_bytes: usize,
    pub max_stream_window: usize,
    pub initial_stream_window: usize,
    pub outbound_event_queue: usize,
    pub handshake_timeout_ms: u64,
    pub auth_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub io_timeout_ms: u64,
    pub session_ttl_seconds: u64,
    pub scan_window_seconds: u64,
    pub scan_distinct_destination_limit: usize,
    pub circuit_failure_threshold: u32,
    pub circuit_cooldown_seconds: u64,
}

impl Default for LimitConfig {
    fn default() -> Self {
        Self {
            max_connections: 1_024,
            listen_backlog: 256,
            max_sessions: 1_024,
            max_token_states: 4_096,
            max_sessions_per_token: 2,
            max_streams_global: 16_384,
            max_streams_per_session: 128,
            max_streams_per_token: 256,
            connection_rate_per_second: 16,
            connection_rate_burst: 32,
            bandwidth_bytes_per_second: 8 * 1024 * 1024,
            bandwidth_burst_bytes: 2 * 1024 * 1024,
            token_byte_quota: 4 * 1024 * 1024 * 1024,
            max_frame_bytes: 64 * 1024,
            max_data_bytes: 32 * 1024,
            max_token_bytes: 4 * 1024,
            max_proof_bytes: 4 * 1024,
            max_stream_window: 4 * 1024 * 1024,
            initial_stream_window: 256 * 1024,
            outbound_event_queue: 256,
            handshake_timeout_ms: 10_000,
            auth_timeout_ms: 3_000,
            connect_timeout_ms: 10_000,
            io_timeout_ms: 120_000,
            session_ttl_seconds: 900,
            scan_window_seconds: 60,
            scan_distinct_destination_limit: 64,
            circuit_failure_threshold: 32,
            circuit_cooldown_seconds: 30,
        }
    }
}

impl LimitConfig {
    fn validate(&self) -> GatewayResult<()> {
        let counts_valid = self.max_connections > 0
            && self.max_connections <= 65_536
            && self.listen_backlog > 0
            && self.listen_backlog <= 65_535
            && self.max_sessions > 0
            && self.max_sessions <= self.max_connections
            && self.max_token_states >= self.max_sessions
            && self.max_token_states <= 1_000_000
            && self.max_sessions_per_token > 0
            && self.max_sessions_per_token <= self.max_sessions
            && self.max_streams_global > 0
            && self.max_streams_per_session > 0
            && self.max_streams_per_session <= 4_096
            && self.max_streams_per_token >= self.max_streams_per_session
            && self.connection_rate_per_second > 0
            && self.connection_rate_burst >= self.connection_rate_per_second
            && self.bandwidth_bytes_per_second > 0
            && self.bandwidth_burst_bytes > 0
            && self.token_byte_quota >= self.bandwidth_burst_bytes;
        let protocol_valid = self.max_frame_bytes == 64 * 1024
            && self.max_data_bytes > 0
            && self.max_data_bytes <= 32 * 1024
            && self.max_token_bytes <= 4 * 1024
            && self.max_proof_bytes <= 4 * 1024
            && self.initial_stream_window > 0
            && self.initial_stream_window <= self.max_stream_window
            && self.max_stream_window <= 4 * 1024 * 1024
            && self.outbound_event_queue > 0
            && self.outbound_event_queue <= 16_384;
        let times_valid = self.handshake_timeout_ms > 0
            && self.auth_timeout_ms > 0
            && self.connect_timeout_ms > 0
            && self.io_timeout_ms > 0
            && self.session_ttl_seconds > 0
            && self.session_ttl_seconds <= 86_400
            && self.scan_window_seconds > 0
            && self.scan_distinct_destination_limit > 0
            && self.circuit_failure_threshold > 0
            && self.circuit_cooldown_seconds > 0;
        if !(counts_valid && protocol_valid && times_valid) {
            return Err(GatewayErrorCode::InvalidConfiguration.into());
        }
        Ok(())
    }

    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.handshake_timeout_ms)
    }

    pub fn auth_timeout(&self) -> Duration {
        Duration::from_millis(self.auth_timeout_ms)
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }

    pub fn io_timeout(&self) -> Duration {
        Duration::from_millis(self.io_timeout_ms)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivacyEventConfig {
    pub enabled: bool,
    pub ttl_seconds: u64,
    pub capacity: usize,
    pub coarse_bucket_seconds: u64,
}

impl Default for PrivacyEventConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            ttl_seconds: 900,
            capacity: 4_096,
            coarse_bucket_seconds: 300,
        }
    }
}

impl PrivacyEventConfig {
    fn validate(&self) -> GatewayResult<()> {
        if self.ttl_seconds == 0
            || self.ttl_seconds > 86_400
            || self.capacity == 0
            || self.capacity > 1_000_000
            || self.coarse_bucket_seconds < 60
            || self.coarse_bucket_seconds > 3_600
        {
            return Err(GatewayErrorCode::InvalidConfiguration.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_listeners_are_rejected() {
        let mut config = GatewayConfig::default();
        config.dns.upstreams.push("1.1.1.1:53".parse().unwrap());
        config.onion_listener = "0.0.0.0:8443".parse().unwrap();
        assert_eq!(
            config.validate().unwrap_err().code,
            GatewayErrorCode::InvalidConfiguration
        );
    }

    #[test]
    fn unknown_configuration_keys_are_rejected() {
        let raw = r#"{
            "gateway_id": "gateway-test",
            "onion_listener": "127.0.0.1:8443",
            "management_listener": "127.0.0.1:9090",
            "direct_clearnet_fallback": true
        }"#;
        assert!(serde_json::from_str::<GatewayConfig>(raw).is_err());
    }

    #[test]
    fn sample_configuration_validates() {
        let config: GatewayConfig =
            serde_json::from_str(include_str!("../config/gateway.example.json")).unwrap();
        config.validate().unwrap();
    }
}
