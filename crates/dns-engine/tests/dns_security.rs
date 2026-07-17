use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use onionroute_common_types::contracts::v1::DnsEngine;
use onionroute_common_types::mocks::MockGatewayConnector;
use onionroute_common_types::types::{
    GatewayId, GatewayRole, GatewaySession, GatewaySessionState, ProtocolVersion,
};
use onionroute_dns_engine::{SyntheticDnsConfig, SyntheticDnsEngine};

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    struct NoopWake;
    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn query(name: &str, record_type: u16) -> Vec<u8> {
    let mut wire = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    wire.extend_from_slice(&record_type.to_be_bytes());
    wire.extend_from_slice(&1u16.to_be_bytes());
    wire
}

fn session() -> GatewaySession {
    GatewaySession {
        session_id: onionroute_common_types::types::SessionId([1; 16]),
        gateway_id: GatewayId("gateway-test".to_owned()),
        role: GatewayRole::Exit,
        protocol_version: ProtocolVersion::new(1, 0),
        state: GatewaySessionState::Active,
        expires_at_unix: i64::MAX,
        max_concurrent_streams: 64,
    }
}

#[test]
fn a_query_gets_short_lived_synthetic_mapping_without_system_dns() {
    let engine = SyntheticDnsEngine::new(SyntheticDnsConfig::default()).expect("valid config");
    let wire = query("Example.COM", 1);
    let request = onionroute_common_types::types::DnsQuery { query_id: 7, wire };
    let gateway = MockGatewayConnector;
    let response =
        block_on(engine.resolve(&request, &session(), &gateway)).expect("synthetic response");
    assert_eq!(response.query_id, 7);
    assert_eq!(&response.wire[..2], &[0x12, 0x34]);
    assert_eq!(u16::from_be_bytes([response.wire[6], response.wire[7]]), 1);
    let address = std::net::Ipv4Addr::new(
        response.wire[response.wire.len() - 4],
        response.wire[response.wire.len() - 3],
        response.wire[response.wire.len() - 2],
        response.wire[response.wire.len() - 1],
    );
    assert_eq!(address.octets()[0..2], [198, 18]);
    assert_eq!(
        engine.lookup_hostname(address).as_deref(),
        Some("example.com")
    );
    assert_eq!(engine.cache_len(), 1);
}

#[test]
fn aaaa_is_empty_and_identity_reset_clears_mapping() {
    let engine = SyntheticDnsEngine::new(SyntheticDnsConfig::default()).expect("valid config");
    let gateway = MockGatewayConnector;
    let a = onionroute_common_types::types::DnsQuery {
        query_id: 1,
        wire: query("example.com", 1),
    };
    block_on(engine.resolve(&a, &session(), &gateway)).expect("A response");
    assert_eq!(engine.cache_len(), 1);

    let aaaa = onionroute_common_types::types::DnsQuery {
        query_id: 2,
        wire: query("example.com", 28),
    };
    let response = block_on(engine.resolve(&aaaa, &session(), &gateway)).expect("AAAA response");
    assert_eq!(u16::from_be_bytes([response.wire[6], response.wire[7]]), 0);
    engine.identity_reset();
    assert_eq!(engine.cache_len(), 0);
}

#[test]
fn cache_is_bounded_and_evicts_lru() {
    let engine = SyntheticDnsEngine::new(SyntheticDnsConfig {
        max_entries: 2,
        ttl: Duration::from_secs(30),
    })
    .expect("valid config");
    let gateway = MockGatewayConnector;
    for (id, name) in ["one.example", "two.example", "three.example"]
        .into_iter()
        .enumerate()
    {
        let request = onionroute_common_types::types::DnsQuery {
            query_id: id as u64,
            wire: query(name, 1),
        };
        block_on(engine.resolve(&request, &session(), &gateway)).expect("synthetic response");
    }
    assert_eq!(engine.cache_len(), 2);
}

#[test]
fn ecs_is_forbidden() {
    let mut wire = query("example.com", 1);
    wire[10..12].copy_from_slice(&1u16.to_be_bytes());
    wire.push(0); // OPT owner
    wire.extend_from_slice(&41u16.to_be_bytes());
    wire.extend_from_slice(&1232u16.to_be_bytes());
    wire.extend_from_slice(&0u32.to_be_bytes());
    wire.extend_from_slice(&8u16.to_be_bytes());
    wire.extend_from_slice(&8u16.to_be_bytes());
    wire.extend_from_slice(&4u16.to_be_bytes());
    wire.extend_from_slice(&[0, 1, 2, 3]);
    let error = SyntheticDnsEngine::parse_query(&wire).expect_err("ECS must fail");
    assert_eq!(
        error.code,
        onionroute_common_types::error::ErrorCode::PolicyDenied
    );
}

#[test]
fn unsupported_opcode_and_truncated_queries_are_rejected_locally() {
    let mut opcode = query("example.com", 1);
    opcode[2] |= 0x08;
    assert!(SyntheticDnsEngine::parse_query(&opcode).is_err());

    let mut truncated = query("example.com", 1);
    truncated[2] |= 0x02;
    assert!(SyntheticDnsEngine::parse_query(&truncated).is_err());
}

#[test]
fn malformed_protected_response_cannot_poison_dns_result() {
    let engine = SyntheticDnsEngine::new(SyntheticDnsConfig::default()).expect("valid config");
    let request = onionroute_common_types::types::DnsQuery {
        query_id: 9,
        wire: query("example.com", 15),
    };
    let gateway = MockGatewayConnector;
    let error = block_on(engine.resolve(&request, &session(), &gateway))
        .expect_err("echoed query is not a valid protected response");
    assert_eq!(
        error.code,
        onionroute_common_types::error::ErrorCode::DnsResolutionFailed
    );
}

#[test]
fn malformed_and_random_dns_never_panics() {
    let mut state = 0x1234_5678_9abc_def0u64;
    for case in 0..5_000usize {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let mut wire = vec![0u8; (state as usize ^ case) % 512];
        for byte in &mut wire {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        assert!(std::panic::catch_unwind(|| SyntheticDnsEngine::parse_query(&wire)).is_ok());
    }
}

#[test]
fn invalid_config_rejects_long_ttl_or_zero_capacity() {
    assert!(SyntheticDnsEngine::new(SyntheticDnsConfig {
        max_entries: 0,
        ttl: Duration::from_secs(30),
    })
    .is_none());
    assert!(SyntheticDnsEngine::new(SyntheticDnsConfig {
        max_entries: 1,
        ttl: Duration::from_secs(61),
    })
    .is_none());
}
