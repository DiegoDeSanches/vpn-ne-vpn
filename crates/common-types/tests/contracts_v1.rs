#![cfg(feature = "test-utils")]

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use onionroute_common_types::contracts::v1::*;
use onionroute_common_types::mocks::*;
use onionroute_common_types::transport::BoxTransport;
use onionroute_common_types::types::*;
use onionroute_common_types::{VersionedContract, CONTRACT_V1};

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("contract mock unexpectedly returned Pending"),
    }
}

#[test]
fn every_required_mock_exposes_v1_contract() {
    let tor = MockTorBackend;
    let circuits = MockCircuitManager;
    let gateway = MockGatewayConnector;
    let packets = MockPacketEngine::default();
    let dns = MockDnsEngine;
    let policy = MockPolicyEngine;
    let kill_switch = MockKillSwitch::default();
    let storage = MockSecureStorage::default();
    let directory = MockGatewayDirectoryProvider::default();
    let tokens = MockTokenProvider;
    let health = MockHealthReporter::default();

    let contracts: [&dyn VersionedContract; 11] = [
        &tor,
        &circuits,
        &gateway,
        &packets,
        &dns,
        &policy,
        &kill_switch,
        &storage,
        &directory,
        &tokens,
        &health,
    ];
    assert!(contracts
        .into_iter()
        .all(|contract| contract.contract_version() == CONTRACT_V1));

    let _: &dyn TorBackend = &tor;
    let _: &dyn CircuitManager = &circuits;
    let _: &dyn GatewayConnector = &gateway;
    let _: &dyn PacketEngine = &packets;
    let _: &dyn DnsEngine = &dns;
    let _: &dyn PolicyEngine = &policy;
    let _: &dyn KillSwitch = &kill_switch;
    let _: &dyn SecureStorage = &storage;
    let _: &dyn GatewayDirectoryProvider = &directory;
    let _: &dyn TokenProvider = &tokens;
    let _: &dyn HealthReporter = &health;
}

#[test]
fn mocks_support_an_anonymous_gateway_handshake() {
    let token = ready(MockTokenProvider.acquire(&TokenRequest {
        capabilities: vec!["tcp-connect-v1".to_owned()],
        mode: AnonymityMode::Standard,
        minimum_validity: std::time::Duration::from_secs(60),
    }))
    .expect("mock token");
    let transport = Box::new(MemoryTransport::default()) as BoxTransport;
    let request = GatewayDialRequest {
        plan: GatewayPlan {
            mode: AnonymityMode::Standard,
            hops: vec![GatewayHop {
                gateway_id: GatewayId("test-exit".to_owned()),
                role: GatewayRole::Exit,
                onion_endpoint: OnionEndpoint {
                    service_id: "a".repeat(56),
                    port: 443,
                },
                tls_spki_sha256: [8; 32],
            }],
        },
        supported_versions: ProtocolVersionRange {
            minimum: ProtocolVersion::new(1, 0),
            maximum: ProtocolVersion::new(1, 1),
        },
        requested_features: Vec::new(),
    };
    let credentials = GatewayCredentials::new(vec![token]).expect("one private hop");
    let session = ready(MockGatewayConnector.connect(transport, &request, credentials))
        .expect("mock gateway session");
    assert_eq!(session.state, GatewaySessionState::Active);
    assert_eq!(session.protocol_version, ProtocolVersion::new(1, 1));
}

#[test]
fn secrets_are_redacted_in_debug_output() {
    let token = CapabilityToken::new(vec![1, 2, 3]).expect("bounded token");
    let secret = SecretValue::new(vec![4, 5, 6]).expect("bounded secret");
    let host = TcpHost::Hostname("sensitive.example".to_owned());
    let dns = DnsQuery {
        query_id: 9,
        wire: b"sensitive-dns-wire".to_vec(),
    };
    assert!(!format!("{token:?}").contains("1, 2, 3"));
    assert!(!format!("{secret:?}").contains("4, 5, 6"));
    assert!(!format!("{host:?}").contains("sensitive.example"));
    assert!(!format!("{dns:?}").contains("sensitive-dns-wire"));
}
