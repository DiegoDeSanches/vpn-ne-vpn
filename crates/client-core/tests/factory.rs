use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use onionroute_client_core::{
    ClientRuntimeConfig, ClientRuntimeFactory, DispatcherConfig, ProductionClientRuntimeFactory,
};
use onionroute_common_types::error::ErrorCode;
use onionroute_common_types::mocks::{
    MockCircuitManager, MockGatewayConnector, MockGatewayDirectoryProvider, MockPolicyEngine,
    MockTokenProvider, MockTorBackend,
};
use onionroute_common_types::types::{
    AnonymityMode, CountryCode, GatewayDescriptor, GatewayId, GatewayRole, OnionEndpoint,
    ProtocolVersion, ProtocolVersionRange, RouteConstraints, TorBootstrapConfig,
    VerifiedGatewayDirectory,
};
use onionroute_dns_engine::SyntheticDnsConfig;
use onionroute_packet_engine::EngineConfig;

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

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn directory(valid_until: i64) -> VerifiedGatewayDirectory {
    VerifiedGatewayDirectory {
        format_version: ProtocolVersion::new(1, 0),
        sequence: 1,
        issued_at_unix: now() - 60,
        valid_until_unix: valid_until,
        gateways: vec![GatewayDescriptor {
            gateway_id: GatewayId("exit-fi-1".to_owned()),
            country: CountryCode(*b"FI"),
            roles: vec![GatewayRole::Exit],
            endpoint: OnionEndpoint {
                service_id: "a".repeat(56),
                port: 443,
            },
            protocols: vec![ProtocolVersion::new(1, 0)],
            tls_spki_sha256: [9; 32],
            capabilities: vec![
                "tcp-connect-v1".to_owned(),
                "flow-control-v1".to_owned(),
                "resolve-domain-v1".to_owned(),
            ],
        }],
        verified_by_key_id: "test-root".to_owned(),
    }
}

fn config(mode: AnonymityMode) -> ClientRuntimeConfig {
    ClientRuntimeConfig {
        route: RouteConstraints {
            mode,
            exit_country: Some(CountryCode(*b"FI")),
            required_features: vec!["tcp-connect-v1".to_owned()],
        },
        tor: TorBootstrapConfig {
            timeout: Duration::from_secs(30),
            bridges_required: false,
        },
        gateway_versions: ProtocolVersionRange {
            minimum: ProtocolVersion::new(1, 0),
            maximum: ProtocolVersion::new(1, 0),
        },
        gateway_features: vec![
            "tcp-connect-v1".to_owned(),
            "flow-control-v1".to_owned(),
            "resolve-domain-v1".to_owned(),
        ],
        token_minimum_validity: Duration::from_secs(60),
        packet: EngineConfig::default(),
        dns: SyntheticDnsConfig::default(),
        dispatcher: DispatcherConfig::default(),
    }
}

fn factory(valid_until: i64) -> ProductionClientRuntimeFactory {
    ProductionClientRuntimeFactory::new(
        Arc::new(MockTorBackend),
        Arc::new(MockCircuitManager),
        Arc::new(MockGatewayConnector),
        Arc::new(MockGatewayDirectoryProvider::new(directory(valid_until))),
        Arc::new(MockTokenProvider),
        Arc::new(MockPolicyEngine),
    )
}

#[test]
fn factory_returns_only_an_active_verified_private_gateway_runtime() {
    let factory = factory(now() + 3_600);
    let mut runtime = block_on(factory.create(&config(AnonymityMode::Standard))).unwrap();
    assert_eq!(
        runtime.session().gateway_id,
        GatewayId("exit-fi-1".to_owned())
    );
    assert_eq!(runtime.session().role, GatewayRole::Exit);
    assert!(block_on(runtime.protected_path_healthy()));
    assert!(block_on(runtime.shutdown(0)).is_ok());
}

#[test]
fn factory_rejects_direct_tor_at_the_private_gateway_boundary() {
    let factory = factory(now() + 3_600);
    let error = match block_on(factory.create(&config(AnonymityMode::DirectTor))) {
        Ok(_) => panic!("private gateway factory must not create Direct Tor"),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::InvalidConfiguration);
    assert!(error.requires_blocking());
}

#[test]
fn factory_rejects_an_expired_directory_even_after_refresh() {
    let factory = factory(now() - 1);
    let error = match block_on(factory.create(&config(AnonymityMode::Standard))) {
        Ok(_) => panic!("expired directory must not produce a runtime"),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::DirectoryExpired);
    assert!(error.requires_blocking());
}
