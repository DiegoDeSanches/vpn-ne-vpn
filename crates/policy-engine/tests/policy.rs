use std::collections::HashSet;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use onionroute_common_types::contracts::v1::PolicyEngine;
use onionroute_common_types::types::{
    AnonymityMode, ApplicationTag, CountryCode, DnsPolicyContext, GatewayDescriptor, GatewayId,
    GatewayRole, OnionEndpoint, PolicyAction, ProtocolVersion, RouteConstraints, TcpFlowRequest,
    TcpHost, VerifiedGatewayDirectory,
};
use onionroute_policy_engine::{MvpPolicyConfig, MvpPolicyEngine};

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

fn request(host: TcpHost, port: u16) -> TcpFlowRequest {
    TcpFlowRequest {
        flow_id: onionroute_common_types::types::FlowId(1),
        host,
        port,
        application: None,
    }
}

#[test]
fn default_tunnels_and_mvp_forbidden_destinations_block() {
    let policy = MvpPolicyEngine::default();
    let public = request(TcpHost::Ip("93.184.216.34".parse().expect("IP")), 443);
    assert_eq!(
        block_on(policy.evaluate_tcp(&public))
            .expect("decision")
            .action,
        PolicyAction::Tunnel
    );

    for blocked in [
        request(TcpHost::Ip("127.0.0.1".parse().expect("IP")), 443),
        request(TcpHost::Ip("169.254.169.254".parse().expect("IP")), 80),
        request(TcpHost::Ip("100.64.0.1".parse().expect("IP")), 443),
        request(TcpHost::Ip("192.0.0.1".parse().expect("IP")), 443),
        request(TcpHost::Ip("198.18.0.1".parse().expect("IP")), 443),
        request(TcpHost::Ip("93.184.216.34".parse().expect("IP")), 25),
        request(TcpHost::Ip("93.184.216.34".parse().expect("IP")), 6881),
        request(TcpHost::Hostname("localhost".to_owned()), 443),
    ] {
        assert_eq!(
            block_on(policy.evaluate_tcp(&blocked))
                .expect("decision")
                .action,
            PolicyAction::Block
        );
    }
}

#[test]
fn dns_never_bypasses() {
    let policy = MvpPolicyEngine::default();
    let context = DnsPolicyContext {
        application: Some(ApplicationTag("split-app".to_owned())),
        record_type: 1,
    };
    assert_eq!(
        block_on(policy.evaluate_dns(&context))
            .expect("decision")
            .action,
        PolicyAction::Tunnel
    );
}

#[test]
fn split_application_requires_platform_exclusion() {
    let app = ApplicationTag("explicit-app".to_owned());
    let policy = MvpPolicyEngine::new(MvpPolicyConfig {
        bypass_applications: HashSet::from([app.clone()]),
    });
    let mut request = request(TcpHost::Ip("93.184.216.34".parse().expect("IP")), 443);
    request.application = Some(app);
    assert_eq!(
        block_on(policy.evaluate_tcp(&request))
            .expect("decision")
            .action,
        PolicyAction::Bypass
    );
}

#[test]
fn route_selection_enforces_roles_country_features_and_distinct_gateways() {
    let descriptor = |id: &str, country: [u8; 2], role: GatewayRole| GatewayDescriptor {
        gateway_id: GatewayId(id.to_owned()),
        country: CountryCode(country),
        roles: vec![role],
        endpoint: OnionEndpoint {
            service_id: "a".repeat(56),
            port: 443,
        },
        tls_spki_sha256: [role as u8 + 1; 32],
        protocols: vec![ProtocolVersion::new(1, 0)],
        capabilities: vec!["tcp-v1".to_owned()],
    };
    let directory = VerifiedGatewayDirectory {
        format_version: ProtocolVersion::new(1, 0),
        sequence: 1,
        issued_at_unix: 0,
        valid_until_unix: i64::MAX,
        gateways: vec![
            descriptor("entry", *b"NL", GatewayRole::Entry),
            descriptor("exit", *b"DE", GatewayRole::Exit),
        ],
        verified_by_key_id: "test-key".to_owned(),
    };
    let constraints = RouteConstraints {
        mode: AnonymityMode::Enhanced,
        exit_country: Some(CountryCode(*b"DE")),
        required_features: vec!["tcp-v1".to_owned()],
    };
    let plan = block_on(MvpPolicyEngine::default().select_gateway_plan(&directory, &constraints))
        .expect("valid route");
    assert_eq!(plan.hops.len(), 2);
    assert_eq!(plan.hops[0].role, GatewayRole::Entry);
    assert_eq!(plan.hops[1].role, GatewayRole::Exit);
    assert_ne!(plan.hops[0].gateway_id, plan.hops[1].gateway_id);
}
