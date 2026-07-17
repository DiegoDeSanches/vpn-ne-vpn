#![cfg(feature = "test-utils")]

use std::sync::Arc;
use std::time::Duration;

use onionroute_common_types::contracts::v1::TorBackend;
use onionroute_common_types::error::ErrorCode;
use onionroute_common_types::types::TorBootstrapConfig;
use onionroute_tor_backend::mock::{FakeFault, FakeTorBackend};
use onionroute_tor_backend::{TorBackendExt, TorContextPool};

#[tokio::test]
async fn bootstrap_failure_and_process_crash_are_bounded() {
    let backend = FakeTorBackend::default();
    backend.inject(FakeFault::BootstrapFailure);
    let error = backend
        .bootstrap(&TorBootstrapConfig {
            timeout: Duration::from_millis(10),
            bridges_required: false,
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::TorBootstrapTimeout);

    backend
        .bootstrap(&TorBootstrapConfig {
            timeout: Duration::from_millis(10),
            bridges_required: false,
        })
        .await
        .unwrap();
    backend.inject(FakeFault::ProcessCrash);
    assert_eq!(
        backend.status().await.unwrap_err().code,
        ErrorCode::TorUnavailable
    );
    assert!(backend.health_status().await.unwrap().fail_closed);
}

#[tokio::test]
async fn network_change_disables_new_work_without_fallback() {
    let backend = FakeTorBackend::default();
    backend
        .bootstrap(&TorBootstrapConfig {
            timeout: Duration::from_millis(10),
            bridges_required: false,
        })
        .await
        .unwrap();
    backend.network_changed().await.unwrap();
    let health = backend.health_status().await.unwrap();
    assert!(health.fail_closed);
    assert!(!health.accepting_streams);
}

#[tokio::test]
async fn multiple_tor_process_contexts_are_bounded() {
    let pool = TorContextPool::new(2).unwrap();
    let first: Arc<dyn TorBackendExt> = Arc::new(FakeTorBackend::default());
    let second: Arc<dyn TorBackendExt> = Arc::new(FakeTorBackend::default());
    let first_id = pool.insert(first).unwrap();
    let second_id = pool.insert(second).unwrap();
    assert_ne!(first_id, second_id);
    assert!(pool.get(first_id).unwrap().is_some());
    let third: Arc<dyn TorBackendExt> = Arc::new(FakeTorBackend::default());
    assert_eq!(
        pool.insert(third).unwrap_err().code,
        ErrorCode::Backpressure
    );
    pool.shutdown_all().await.unwrap();
    assert!(pool.is_empty().unwrap());
}
