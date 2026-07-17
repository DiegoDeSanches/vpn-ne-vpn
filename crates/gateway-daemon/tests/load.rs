use std::time::{Duration, SystemTime};

use onionroute_gateway_daemon::auth::{AuthenticationGrant, TokenLimits};
use onionroute_gateway_daemon::config::LimitConfig;
use onionroute_gateway_daemon::session::SessionManager;

fn grant() -> AuthenticationGrant {
    AuthenticationGrant {
        expires_at: SystemTime::now() + Duration::from_secs(60),
        capabilities: vec!["tcp-connect-v1".into()],
        limits: TokenLimits {
            max_sessions: 1,
            max_concurrent_streams: 8,
            connections_per_second: 10_000,
            connection_burst: 10_000,
            bytes_per_second: 100_000_000,
            bandwidth_burst_bytes: 10_000_000,
            total_bytes: 1_000_000_000,
        },
    }
}

#[test]
#[ignore = "operator load test"]
fn connection_storm_remains_within_global_session_limit() {
    let limits = LimitConfig {
        max_connections: 256,
        max_sessions: 256,
        ..LimitConfig::default()
    };
    let manager = SessionManager::new(limits).unwrap();
    let mut sessions = Vec::new();
    for index in 0..10_000u64 {
        let token = index.to_be_bytes();
        if let Ok(session) = manager.register(&token, grant()) {
            sessions.push(session);
        }
    }
    assert_eq!(sessions.len(), 256);
    assert_eq!(manager.active_sessions(), 256);
    drop(sessions);
    assert_eq!(manager.active_sessions(), 0);
}
