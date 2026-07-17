use std::sync::Arc;

use async_trait::async_trait;
use onionroute_desktop_daemon::{
    platform::windows::DevFailClosedPlatform, CoreControl, CoreIntent, DaemonError, DaemonRuntime,
    PlatformControl, RecoveryIntent,
};
use onionroute_desktop_ipc::v1::{ApplicationRule, KillSwitchState, TunnelPhase};

struct NeverStartedCore;

#[async_trait]
impl CoreControl for NeverStartedCore {
    async fn start(&self) -> Result<(), DaemonError> {
        panic!("the core must not start before platform protection verifies")
    }

    async fn stop(&self) -> Result<(), DaemonError> {
        Ok(())
    }

    async fn apply(&self, _intent: CoreIntent) -> Result<(), DaemonError> {
        Err(DaemonError::Core)
    }
}

#[tokio::test]
async fn development_platform_never_claims_wfp_or_wintun() {
    let directory = tempfile::tempdir().unwrap();
    let platform = Arc::new(DevFailClosedPlatform::new(
        directory.path().join("recovery.intent"),
    ));
    let runtime = DaemonRuntime::new(platform.clone(), Arc::new(NeverStartedCore));

    assert_eq!(
        runtime.connect().await,
        Err(DaemonError::KillSwitchNotVerified)
    );
    let state = runtime.snapshot().await;
    assert_eq!(
        TunnelPhase::try_from(state.phase).unwrap(),
        TunnelPhase::Blocked
    );
    assert_eq!(
        KillSwitchState::try_from(state.kill_switch).unwrap(),
        KillSwitchState::FailedBlocking
    );
    assert_eq!(
        platform.load_recovery_intent().unwrap(),
        Some(RecoveryIntent::Blocked)
    );
    assert_eq!(
        platform.start_packet_tunnel().await,
        Err(DaemonError::Platform)
    );
    assert_eq!(platform.verify_kill_switch().await, Ok(false));
    assert_eq!(
        platform.replace_split_policy(&[] as &[ApplicationRule]).await,
        Err(DaemonError::Platform)
    );
}

#[test]
fn malformed_recovery_marker_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("recovery.intent");
    std::fs::write(&path, b"connected\n").unwrap();
    let platform = DevFailClosedPlatform::new(path);
    assert_eq!(
        platform.load_recovery_intent(),
        Err(DaemonError::Platform)
    );
}
