#![cfg(feature = "test-utils")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use onionroute_common_types::contracts::v1::TorBackend;
use onionroute_common_types::transport::BoxFuture;
use onionroute_common_types::types::{AnonymityMode, OnionEndpoint, TorBootstrapConfig};
use onionroute_common_types::OnionResult;
use onionroute_tor_backend::{
    BackendHealth, CTorBackend, CTorConfig, HealthObserver, IsolationScope, TorBackendExt,
    TorHealthMonitor,
};

fn backend_config(state_parent: PathBuf) -> CTorConfig {
    CTorConfig {
        tor_binary: PathBuf::from(env!("CARGO_BIN_EXE_onionroute-mock-tor")),
        state_parent: Some(state_parent),
        startup_timeout: Duration::from_secs(5),
        shutdown_timeout: Duration::from_secs(5),
        stream_timeout: Duration::from_secs(5),
        health_poll_interval: Duration::from_millis(100),
        ..CTorConfig::default()
    }
}

fn scope(group: &str) -> IsolationScope {
    IsolationScope {
        application: Some("integration-app".to_owned()),
        anonymity_profile: AnonymityMode::Standard,
        gateway: Some("integration-gateway".to_owned()),
        destination_group: group.to_owned(),
        browser_container: Some("integration-container".to_owned()),
    }
}

#[tokio::test]
async fn managed_process_soft_and_hard_rotation() {
    let state_parent = tempfile::tempdir().unwrap();
    // A stale/corrupt sibling is ignored because every process receives a new
    // data directory instead of trusting previous transient state.
    std::fs::write(
        state_parent.path().join("corrupted-state"),
        b"not tor state",
    )
    .unwrap();
    let backend = CTorBackend::new(backend_config(state_parent.path().to_owned())).unwrap();
    let status = backend
        .bootstrap(&TorBootstrapConfig {
            timeout: Duration::from_secs(5),
            bridges_required: false,
        })
        .await
        .unwrap();
    assert!(status.ready);

    let old_context = backend
        .allocate_isolation_context(&scope("old"))
        .await
        .unwrap();
    let endpoint = OnionEndpoint {
        service_id: "a".repeat(56),
        port: 443,
    };
    let mut stream = backend
        .open_onion_stream(&endpoint, &old_context.key)
        .await
        .unwrap();
    assert_eq!(stream.write(b"before").await.unwrap(), 6);
    let mut echoed = [0_u8; 6];
    assert_eq!(stream.read(&mut echoed).await.unwrap(), 6);
    assert_eq!(&echoed, b"before");

    let soft = backend.request_soft_rotation().await.unwrap();
    assert_eq!(soft.closed_streams, 0);
    assert_eq!(stream.write(b"after").await.unwrap(), 5);
    let new_context = backend
        .allocate_isolation_context(&scope("new"))
        .await
        .unwrap();
    assert!(new_context.session_epoch > old_context.session_epoch);
    assert_ne!(new_context.key.0, old_context.key.0);

    let hard = backend.request_hard_rotation().await.unwrap();
    assert!(hard.closed_streams >= 1);
    assert!(stream.write(b"closed").await.is_err());
    backend.stop().await.unwrap();
}

#[derive(Default)]
struct RecordingObserver(Mutex<Vec<BackendHealth>>);

impl HealthObserver for RecordingObserver {
    fn health_changed(&self, health: BackendHealth) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async move {
            self.0.lock().unwrap().push(health);
            Ok(())
        })
    }
}

#[tokio::test]
async fn process_crash_is_reported_fail_closed() {
    let state_parent = tempfile::tempdir().unwrap();
    let backend =
        Arc::new(CTorBackend::new(backend_config(state_parent.path().to_owned())).unwrap());
    backend
        .bootstrap(&TorBootstrapConfig {
            timeout: Duration::from_secs(5),
            bridges_required: false,
        })
        .await
        .unwrap();
    let observer = Arc::new(RecordingObserver::default());
    let monitor = TorHealthMonitor::new(
        Arc::clone(&backend) as Arc<dyn TorBackendExt>,
        Arc::clone(&observer) as Arc<dyn HealthObserver>,
        Duration::from_millis(100),
    )
    .unwrap();

    backend.terminate_process_for_test().await.unwrap();
    tokio::time::sleep(Duration::from_millis(250)).await;
    let health = monitor.poll_once().await.unwrap();
    assert!(health.fail_closed);
    assert!(!health.accepting_streams);
    assert!(observer.0.lock().unwrap().last().unwrap().fail_closed);
}

#[test]
fn invalid_state_parent_fails_before_process_start() {
    let parent = tempfile::tempdir().unwrap();
    let file = parent.path().join("not-a-directory");
    std::fs::write(&file, b"corrupt").unwrap();
    assert!(CTorBackend::new(backend_config(file)).is_err());
}
