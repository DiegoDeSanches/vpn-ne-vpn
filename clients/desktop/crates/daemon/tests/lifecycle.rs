use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use onionroute_desktop_daemon::{
    CoreControl, CoreIntent, DaemonError, DaemonRuntime, DiagnosticEventCode, DiagnosticSnapshot,
    DiagnosticsExporter, PlatformControl, RecoveryIntent,
};
use onionroute_desktop_ipc::v1::{ApplicationRule, KillSwitchState, TunnelPhase};

#[derive(Default)]
struct MockPlatform {
    calls: Mutex<Vec<&'static str>>,
    verify: Mutex<bool>,
}

impl MockPlatform {
    fn passing() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            verify: Mutex::new(true),
        }
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl PlatformControl for MockPlatform {
    async fn persist_recovery_intent(&self, _: RecoveryIntent) -> Result<(), DaemonError> {
        self.calls.lock().unwrap().push("persist");
        Ok(())
    }
    async fn engage_kill_switch(&self) -> Result<(), DaemonError> {
        self.calls.lock().unwrap().push("engage");
        Ok(())
    }
    async fn verify_kill_switch(&self) -> Result<bool, DaemonError> {
        self.calls.lock().unwrap().push("verify");
        Ok(*self.verify.lock().unwrap())
    }
    async fn disengage_kill_switch(&self) -> Result<(), DaemonError> {
        self.calls.lock().unwrap().push("disengage");
        Ok(())
    }
    async fn start_packet_tunnel(&self) -> Result<(), DaemonError> {
        self.calls.lock().unwrap().push("tun-start");
        Ok(())
    }
    async fn stop_packet_tunnel(&self) -> Result<(), DaemonError> {
        self.calls.lock().unwrap().push("tun-stop");
        Ok(())
    }
    async fn replace_split_policy(&self, _: &[ApplicationRule]) -> Result<(), DaemonError> {
        Ok(())
    }
}

#[derive(Default)]
struct MockCore {
    calls: Mutex<Vec<&'static str>>,
}

#[async_trait]
impl CoreControl for MockCore {
    async fn start(&self) -> Result<(), DaemonError> {
        self.calls.lock().unwrap().push("core-start");
        Ok(())
    }
    async fn stop(&self) -> Result<(), DaemonError> {
        self.calls.lock().unwrap().push("core-stop");
        Ok(())
    }
    async fn apply(&self, _: CoreIntent) -> Result<(), DaemonError> {
        Ok(())
    }
}

#[tokio::test]
async fn kill_switch_is_engaged_and_verified_before_tun() {
    let platform = Arc::new(MockPlatform::passing());
    let core = Arc::new(MockCore::default());
    let runtime = DaemonRuntime::new(platform.clone(), core);
    runtime.connect().await.unwrap();
    assert_eq!(
        platform.calls(),
        vec!["persist", "engage", "verify", "tun-start"]
    );
    assert_eq!(
        TunnelPhase::try_from(runtime.snapshot().await.phase).unwrap(),
        TunnelPhase::Connected
    );
}

#[tokio::test]
async fn failed_verification_stays_fail_closed() {
    let platform = Arc::new(MockPlatform::default());
    let runtime = DaemonRuntime::new(platform, Arc::new(MockCore::default()));
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
}

#[tokio::test]
async fn unverified_blocked_state_cannot_disable_the_kill_switch() {
    let platform = Arc::new(MockPlatform::default());
    let runtime = DaemonRuntime::new(platform.clone(), Arc::new(MockCore::default()));
    assert!(runtime.connect().await.is_err());
    assert_eq!(
        runtime.set_kill_switch_enabled(false).await,
        Err(DaemonError::InvalidRequest)
    );
    assert!(!platform.calls().contains(&"disengage"));
}

#[tokio::test]
async fn closing_or_dropping_ui_is_not_part_of_daemon_lifecycle() {
    let platform = Arc::new(MockPlatform::passing());
    let runtime = DaemonRuntime::new(platform.clone(), Arc::new(MockCore::default()));
    runtime.connect().await.unwrap();
    let calls_before_ui_exit = platform.calls();
    // There is deliberately no UI-disconnect callback on DaemonRuntime.
    tokio::task::yield_now().await;
    assert_eq!(platform.calls(), calls_before_ui_exit);
    assert_eq!(
        TunnelPhase::try_from(runtime.snapshot().await.phase).unwrap(),
        TunnelPhase::Connected
    );
}

#[test]
fn diagnostics_export_contains_only_allowlisted_coarse_fields_and_expires() {
    let directory = tempfile::tempdir().unwrap();
    let exporter = DiagnosticsExporter::new(directory.path());
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
    let metadata = exporter
        .export(
            DiagnosticSnapshot {
                app_version: "0.1.0".into(),
                daemon_version: "0.1.0".into(),
                os_family: "windows".into(),
                tunnel_phase: "blocked".into(),
                tor_bootstrap_bucket: 50,
                gateway_status: "unreachable".into(),
                latency_bucket: "not_available".into(),
                kill_switch_state: "engaged".into(),
                blocked_leak_count: 4,
                events: vec![DiagnosticEventCode::LeakBlockedQuic],
            },
            now,
            Duration::from_secs(60),
        )
        .unwrap();
    let text = std::fs::read_to_string(directory.path().join(metadata.file_name)).unwrap();
    assert!(!text.contains(".onion"));
    assert!(!text.contains("token"));
    assert!(!text.contains("hostname"));
    assert_eq!(
        exporter
            .prune_expired(now + Duration::from_secs(61))
            .unwrap(),
        1
    );
}
