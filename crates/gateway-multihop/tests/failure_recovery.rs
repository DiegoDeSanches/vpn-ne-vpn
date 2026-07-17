use std::time::Duration;

use onionroute_gateway_multihop::recovery::{FailClosedRecovery, FailureClass, RecoveryAction};
use onionroute_gateway_multihop::route::{
    GatewayDescriptor, GatewayRole, LoadBucket, MaintenanceState, ProtocolVersion, RecentFailure,
    RoutePolicy,
};

fn gateway(
    id: &str,
    role: GatewayRole,
    provider: &str,
    asn: u32,
    management: &str,
) -> GatewayDescriptor {
    GatewayDescriptor {
        gateway_id: id.into(),
        role,
        country_code: "NL".into(),
        provider_id: provider.into(),
        autonomous_system: asn,
        management_identity: management.into(),
        protocol_versions: vec![ProtocolVersion { major: 1, minor: 0 }],
        maintenance: MaintenanceState::Active,
        load: LoadBucket::Low,
        revoked: false,
    }
}

#[test]
fn failure_can_only_reconnect_enhanced_or_block() {
    let entry = gateway("entry", GatewayRole::Entry, "provider-a", 64501, "ops-a");
    let exits = vec![
        gateway("exit-a", GatewayRole::Exit, "provider-b", 64502, "ops-b"),
        gateway("exit-b", GatewayRole::Exit, "provider-c", 64503, "ops-c"),
    ];
    let policy = RoutePolicy {
        exit_country: "NL".into(),
        required_version: ProtocolVersion { major: 1, minor: 0 },
        maximum_load: LoadBucket::High,
    };
    let mut recovery = FailClosedRecovery::default();
    let action = recovery
        .recover(
            FailureClass::Transport,
            &entry,
            &exits,
            &policy,
            &[RecentFailure {
                gateway_id: "exit-a".into(),
                consecutive_failures: 8,
            }],
        )
        .unwrap();
    match action {
        RecoveryAction::ReconnectEnhanced { route, after } => {
            assert_eq!(route.exit.gateway_id, "exit-b");
            assert!(after >= Duration::from_millis(250));
        }
        RecoveryAction::Block => panic!("a safe enhanced route exists"),
    }

    assert_eq!(
        recovery
            .recover(FailureClass::Policy, &entry, &exits, &policy, &[])
            .unwrap(),
        RecoveryAction::Block
    );
}

#[test]
fn no_safe_diverse_route_blocks_instead_of_falling_back() {
    let entry = gateway("entry", GatewayRole::Entry, "provider-a", 64501, "ops-a");
    let exits = vec![gateway(
        "colliding-exit",
        GatewayRole::Exit,
        "provider-a",
        64501,
        "ops-a",
    )];
    let mut recovery = FailClosedRecovery::default();
    assert_eq!(
        recovery
            .recover(
                FailureClass::Transport,
                &entry,
                &exits,
                &RoutePolicy {
                    exit_country: "NL".into(),
                    required_version: ProtocolVersion { major: 1, minor: 0 },
                    maximum_load: LoadBucket::High,
                },
                &[],
            )
            .unwrap(),
        RecoveryAction::Block
    );
}
