use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use onionroute_gateway_daemon::acl::{AclEngine, Destination};
use onionroute_gateway_daemon::auth::{AuthenticationGrant, TokenLimits};
use onionroute_gateway_daemon::config::{AclConfig, LimitConfig, PrivacyEventConfig};
use onionroute_gateway_daemon::dns::{DnsResolver, Resolution};
use onionroute_gateway_daemon::egress::{BoxedIo, EgressDialer, TcpEgressConnector};
use onionroute_gateway_daemon::health::{Metrics, PrivacyEventBuffer};
use onionroute_gateway_daemon::rate_limit::CircuitBreaker;
use onionroute_gateway_daemon::session::{SessionLease, SessionManager};
use onionroute_gateway_daemon::{GatewayErrorCode, GatewayResult};

struct FixedResolver {
    result: GatewayResult<Resolution>,
}

#[async_trait]
impl DnsResolver for FixedResolver {
    async fn resolve_for_connect(&self, _hostname: &str) -> GatewayResult<Resolution> {
        self.result.clone()
    }

    async fn exchange_wire(&self, _query: &[u8]) -> GatewayResult<Vec<u8>> {
        Err(GatewayErrorCode::DnsFailure.into())
    }
}

struct CountingDialer {
    calls: Arc<AtomicUsize>,
    delay: Duration,
    fail: bool,
}

#[async_trait]
impl EgressDialer for CountingDialer {
    async fn connect(&self, _address: SocketAddr) -> GatewayResult<BoxedIo> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        if self.fail {
            return Err(GatewayErrorCode::EgressFailure.into());
        }
        let (client, _server) = tokio::io::duplex(64);
        Ok(Box::pin(client))
    }
}

fn grant(expiry: SystemTime, streams: usize) -> AuthenticationGrant {
    AuthenticationGrant {
        expires_at: expiry,
        capabilities: vec!["tcp-connect-v1".into(), "flow-control-v1".into()],
        limits: TokenLimits {
            max_sessions: 2,
            max_concurrent_streams: streams,
            connections_per_second: 1_000,
            connection_burst: 1_000,
            bytes_per_second: 10_000_000,
            bandwidth_burst_bytes: 1_000_000,
            total_bytes: 100_000_000,
        },
    }
}

fn session(limits: LimitConfig) -> (SessionManager, SessionLease) {
    let manager = SessionManager::new(limits).unwrap();
    let session = manager
        .register(
            b"opaque-test-token",
            grant(SystemTime::now() + Duration::from_secs(60), 64),
        )
        .unwrap();
    (manager, session)
}

fn connector(
    resolver: Arc<dyn DnsResolver>,
    dialer: Arc<dyn EgressDialer>,
    timeout: Duration,
) -> TcpEgressConnector {
    TcpEgressConnector::new(
        AclEngine::new(AclConfig::default()),
        resolver,
        dialer,
        Arc::new(CircuitBreaker::new(8, Duration::from_secs(60))),
        Arc::new(Metrics::default()),
        Arc::new(PrivacyEventBuffer::new(
            PrivacyEventConfig::default(),
            "gateway-test".into(),
        )),
        timeout,
    )
}

#[tokio::test]
async fn ssrf_private_ip_never_reaches_dialer() {
    let calls = Arc::new(AtomicUsize::new(0));
    let dialer = Arc::new(CountingDialer {
        calls: calls.clone(),
        delay: Duration::ZERO,
        fail: false,
    });
    let resolver = Arc::new(FixedResolver {
        result: Ok(Resolution {
            addresses: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            cname_depth: 0,
            response_bytes: 64,
        }),
    });
    let limits = LimitConfig::default();
    let (_manager, session) = session(limits);
    let error = connector(resolver, dialer, Duration::from_secs(1))
        .open(&session, Destination::Ip("10.0.0.7".parse().unwrap()), 443)
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, GatewayErrorCode::PolicyDenied);
    assert_eq!(calls.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn malicious_resolver_private_answer_is_rechecked() {
    let calls = Arc::new(AtomicUsize::new(0));
    let dialer = Arc::new(CountingDialer {
        calls: calls.clone(),
        delay: Duration::ZERO,
        fail: false,
    });
    let resolver = Arc::new(FixedResolver {
        result: Ok(Resolution {
            addresses: vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
            cname_depth: 0,
            response_bytes: 64,
        }),
    });
    let (_manager, session) = session(LimitConfig::default());
    let error = connector(resolver, dialer, Duration::from_secs(1))
        .open(&session, Destination::Hostname("example.com".into()), 443)
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, GatewayErrorCode::PolicyDenied);
    assert_eq!(calls.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn dns_failure_has_no_clearnet_fallback() {
    let calls = Arc::new(AtomicUsize::new(0));
    let dialer = Arc::new(CountingDialer {
        calls: calls.clone(),
        delay: Duration::ZERO,
        fail: false,
    });
    let resolver = Arc::new(FixedResolver {
        result: Err(GatewayErrorCode::DnsFailure.into()),
    });
    let (_manager, session) = session(LimitConfig::default());
    let error = connector(resolver, dialer, Duration::from_secs(1))
        .open(&session, Destination::Hostname("example.com".into()), 443)
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, GatewayErrorCode::DnsFailure);
    assert_eq!(calls.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn slow_egress_connect_is_bounded_by_timeout() {
    let calls = Arc::new(AtomicUsize::new(0));
    let dialer = Arc::new(CountingDialer {
        calls,
        delay: Duration::from_secs(60),
        fail: false,
    });
    let resolver = Arc::new(FixedResolver {
        result: Ok(Resolution {
            addresses: vec!["1.1.1.1".parse().unwrap()],
            cname_depth: 0,
            response_bytes: 64,
        }),
    });
    let (_manager, session) = session(LimitConfig::default());
    let error = connector(resolver, dialer, Duration::from_millis(20))
        .open(&session, Destination::Hostname("example.com".into()), 443)
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, GatewayErrorCode::Timeout);
}

#[tokio::test]
async fn egress_failure_does_not_fall_back_to_hostname_connect() {
    let calls = Arc::new(AtomicUsize::new(0));
    let dialer = Arc::new(CountingDialer {
        calls: calls.clone(),
        delay: Duration::ZERO,
        fail: true,
    });
    let resolver = Arc::new(FixedResolver {
        result: Ok(Resolution {
            addresses: vec!["1.1.1.1".parse().unwrap()],
            cname_depth: 0,
            response_bytes: 64,
        }),
    });
    let (_manager, session) = session(LimitConfig::default());
    let error = connector(resolver, dialer, Duration::from_secs(1))
        .open(&session, Destination::Hostname("example.com".into()), 443)
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, GatewayErrorCode::EgressFailure);
    assert_eq!(calls.load(Ordering::Acquire), 1);
}

#[test]
fn resource_exhaustion_and_draining_are_fail_closed() {
    let limits = LimitConfig {
        max_streams_per_session: 2,
        max_streams_per_token: 2,
        ..LimitConfig::default()
    };
    let (manager, session) = session(limits);
    let first = session.reserve_stream(b"one").unwrap();
    let second = session.reserve_stream(b"two").unwrap();
    assert_eq!(
        session.reserve_stream(b"three").err().unwrap().code,
        GatewayErrorCode::ResourceExhausted
    );
    manager.set_draining(true);
    assert_eq!(manager.active_streams(), 2);
    assert_eq!(
        session.reserve_stream(b"four").err().unwrap().code,
        GatewayErrorCode::Draining
    );
    drop((first, second));
    assert_eq!(manager.active_streams(), 0);
}

#[test]
fn config_schema_is_valid_json_and_forbids_unknown_fields() {
    let schema = include_str!("../config/gateway.schema.json");
    let value: serde_json::Value = serde_json::from_str(schema).unwrap();
    assert_eq!(value["additionalProperties"], false);
}
