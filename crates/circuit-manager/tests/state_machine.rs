#![cfg(feature = "test-utils")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use onionroute_circuit_manager::{
    CircuitManager, CircuitManagerConfig, IsolationManager, RotationObserver, RotationScheduler,
    RouteState,
};
use onionroute_common_types::contracts::v1::{CircuitManager as _, TorBackend as _};
use onionroute_common_types::error::ErrorCode;
use onionroute_common_types::transport::BoxFuture;
use onionroute_common_types::types::{
    AnonymityMode, ApplicationTag, FlowId, GatewayHop, GatewayId, GatewayPlan, GatewayRole,
    OnionEndpoint, RotationReason, TcpFlowRequest, TcpHost, TorBootstrapConfig,
};
use onionroute_common_types::OnionResult;
use onionroute_tor_backend::mock::{FakeFault, FakeTorBackend};
use onionroute_tor_backend::{IsolationScope, TorBackendExt};
use tokio_util::sync::CancellationToken;

fn endpoint(character: char) -> OnionEndpoint {
    OnionEndpoint {
        service_id: character.to_string().repeat(56),
        port: 443,
    }
}

fn standard_plan(character: char) -> GatewayPlan {
    GatewayPlan {
        mode: AnonymityMode::Standard,
        hops: vec![GatewayHop {
            gateway_id: GatewayId("test-gateway".to_owned()),
            role: GatewayRole::Exit,
            onion_endpoint: endpoint(character),
            tls_spki_sha256: [7; 32],
        }],
    }
}

async fn ready_fake() -> Arc<FakeTorBackend> {
    let backend = Arc::new(FakeTorBackend::default());
    backend
        .bootstrap(&TorBootstrapConfig {
            timeout: Duration::from_millis(10),
            bridges_required: false,
        })
        .await
        .unwrap();
    backend
}

#[derive(Default)]
struct Observer(Mutex<Vec<&'static str>>);

impl Observer {
    fn events(&self) -> Vec<&'static str> {
        self.0.lock().unwrap().clone()
    }
}

impl RotationObserver for Observer {
    fn hard_rotation_started(&self, _reason: RotationReason) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async move {
            self.0.lock().unwrap().push("notify");
            Ok(())
        })
    }

    fn close_active_streams(&self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async move {
            self.0.lock().unwrap().push("close");
            Ok(())
        })
    }

    fn flush_dns_state(&self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async move {
            self.0.lock().unwrap().push("dns");
            Ok(())
        })
    }

    fn revoke_temporary_gateway_session(&self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async move {
            self.0.lock().unwrap().push("revoke");
            Ok(())
        })
    }

    fn clear_transient_state(&self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async move {
            self.0.lock().unwrap().push("transient");
            Ok(())
        })
    }
}

#[tokio::test]
async fn route_state_machine_and_soft_rotation_preserve_stream() {
    let fake = ready_fake().await;
    let observer = Arc::new(Observer::default());
    let manager = CircuitManager::new(
        Arc::clone(&fake) as Arc<dyn TorBackendExt>,
        observer,
        CircuitManagerConfig::default(),
    )
    .unwrap();
    let lease = manager
        .prepare_route(&standard_plan('a'), RotationReason::Scheduled)
        .await
        .unwrap();
    assert_eq!(
        manager.route_state(lease.route_id).unwrap(),
        Some(RouteState::Prepared)
    );
    let mut stream = manager.open_first_hop(&lease).await.unwrap();
    assert_eq!(
        manager.route_state(lease.route_id).unwrap(),
        Some(RouteState::Active)
    );
    assert_eq!(stream.write(b"still-live").await.unwrap(), 10);

    let outcome = manager.soft_rotate().await.unwrap();
    assert_eq!(outcome.closed_streams, 0);
    assert_eq!(stream.write(b"after-soft").await.unwrap(), 10);
    manager.begin_draining(lease.route_id).await.unwrap();
    assert_eq!(
        manager.route_state(lease.route_id).unwrap(),
        Some(RouteState::Draining)
    );
    manager.retire_route(&lease).await.unwrap();
    manager.retire_route(&lease).await.unwrap();
    assert_eq!(manager.route_state(lease.route_id).unwrap(), None);
}

#[tokio::test]
async fn identity_reset_order_is_complete_and_hard_rotation_is_rate_limited() {
    let fake = ready_fake().await;
    let observer = Arc::new(Observer::default());
    let manager = CircuitManager::new(
        Arc::clone(&fake) as Arc<dyn TorBackendExt>,
        Arc::clone(&observer) as Arc<dyn RotationObserver>,
        CircuitManagerConfig::default(),
    )
    .unwrap();
    let lease = manager
        .prepare_route(&standard_plan('b'), RotationReason::Scheduled)
        .await
        .unwrap();
    let _stream = manager.open_first_hop(&lease).await.unwrap();

    let reset = manager
        .identity_reset(AnonymityMode::Standard)
        .await
        .unwrap();
    assert!(reset.context.session_epoch > 0);
    assert_eq!(manager.route_count().unwrap(), 0);
    assert_eq!(manager.isolation_manager().context_count().unwrap(), 1);
    assert_eq!(
        observer.events(),
        ["notify", "close", "dns", "revoke", "transient"]
    );
    assert_eq!(fake.rotation_counts(), (0, 1));

    let error = manager
        .hard_rotate(AnonymityMode::Standard, RotationReason::UserRequested)
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RotationDeferred);
    assert_eq!(fake.rotation_counts(), (0, 1));
}

#[tokio::test]
async fn failed_replacement_keeps_old_route_active() {
    let fake = ready_fake().await;
    let manager = CircuitManager::new(
        Arc::clone(&fake) as Arc<dyn TorBackendExt>,
        Arc::new(Observer::default()),
        CircuitManagerConfig::default(),
    )
    .unwrap();
    let old = manager
        .prepare_route(&standard_plan('c'), RotationReason::Scheduled)
        .await
        .unwrap();
    let _stream = manager.open_first_hop(&old).await.unwrap();
    fake.inject(FakeFault::GatewayUnavailable);
    let error = manager
        .prepare_rotation(&old, &standard_plan('d'), RotationReason::HealthDegraded)
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::GatewayUnavailable);
    assert_eq!(manager.route_count().unwrap(), 1);
    assert_eq!(
        manager.route_state(old.route_id).unwrap(),
        Some(RouteState::Active)
    );
}

#[tokio::test]
async fn direct_tor_is_an_explicit_gateway_free_path() {
    let fake = ready_fake().await;
    let manager = CircuitManager::new(
        Arc::clone(&fake) as Arc<dyn TorBackendExt>,
        Arc::new(Observer::default()),
        CircuitManagerConfig::default(),
    )
    .unwrap();
    let request = TcpFlowRequest {
        flow_id: FlowId(7),
        host: TcpHost::Hostname("example.test".to_owned()),
        port: 443,
        application: Some(ApplicationTag("direct-app".to_owned())),
    };
    let mut stream = manager
        .open_direct_stream(&request, "direct-web".to_owned(), None)
        .await
        .unwrap();
    assert_eq!(stream.write(b"direct").await.unwrap(), 6);

    let direct_plan = GatewayPlan {
        mode: AnonymityMode::DirectTor,
        hops: Vec::new(),
    };
    let lease = manager
        .prepare_route(&direct_plan, RotationReason::UserRequested)
        .await
        .unwrap();
    let error = match manager.open_first_hop(&lease).await {
        Ok(_) => panic!("Direct Tor route unexpectedly opened as a private first hop"),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::InvalidConfiguration);
}

fn isolation_scope(index: usize) -> IsolationScope {
    IsolationScope {
        application: Some(format!("app-{index}")),
        anonymity_profile: AnonymityMode::Enhanced,
        gateway: Some(format!("gateway-{index}")),
        destination_group: format!("group-{index}"),
        browser_container: Some(format!("container-{index}")),
    }
}

#[tokio::test]
async fn concurrent_contexts_are_distinct() {
    let fake = ready_fake().await;
    let isolation = Arc::new(IsolationManager::new(
        Arc::clone(&fake) as Arc<dyn TorBackendExt>
    ));
    let mut tasks = Vec::new();
    for index in 0..64 {
        let isolation = Arc::clone(&isolation);
        tasks.push(tokio::spawn(async move {
            isolation.allocate(isolation_scope(index)).await.unwrap()
        }));
    }
    let mut keys = Vec::new();
    for task in tasks {
        keys.push(task.await.unwrap().key.0);
    }
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), 64);
    assert_eq!(isolation.context_count().unwrap(), 64);
}

#[tokio::test]
async fn isolation_collision_fails_closed_after_bounded_attempts() {
    let fake = ready_fake().await;
    fake.set_fixed_isolation_key(Some([9; 32]));
    let isolation = IsolationManager::new(Arc::clone(&fake) as Arc<dyn TorBackendExt>);
    isolation.allocate(isolation_scope(1)).await.unwrap();
    let error = isolation.allocate(isolation_scope(2)).await.unwrap_err();
    assert_eq!(error.code, ErrorCode::InvariantViolation);
    assert!(error.requires_blocking());
}

#[tokio::test]
async fn automatic_rotation_tick_is_soft_and_cancellable() {
    let fake = ready_fake().await;
    let manager = CircuitManager::new(
        Arc::clone(&fake) as Arc<dyn TorBackendExt>,
        Arc::new(Observer::default()),
        CircuitManagerConfig::default(),
    )
    .unwrap();
    let scheduler = RotationScheduler::with_seed(Default::default(), 11).unwrap();
    assert!(manager
        .automatic_rotation_tick(&scheduler, std::time::Instant::now())
        .await
        .unwrap());
    assert_eq!(fake.rotation_counts(), (1, 0));

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    manager
        .run_automatic_rotation(AnonymityMode::Standard, &scheduler, cancellation)
        .await
        .unwrap();
    assert_eq!(fake.rotation_counts(), (1, 0));
}
