use std::sync::Arc;

use async_trait::async_trait;
use onionroute_desktop_ipc::v1::{
    request, AnonymityMode, ApplicationRule, GatewayStatus, KillSwitchState, LatencyBucket,
    RotationKind, StateSnapshot, TunnelPhase,
};
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryIntent {
    Disconnected,
    Protected,
    Blocked,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CoreIntent {
    SetCountry(Option<String>),
    SetAnonymityMode(AnonymityMode),
    SoftRotation,
    HardRotation,
    UpdateSettings {
        locale: String,
        automatic_rotation_minutes: u32,
    },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DaemonError {
    #[error("platform protection operation failed")]
    Platform,
    #[error("shared client core operation failed")]
    Core,
    #[error("kill switch could not be independently verified")]
    KillSwitchNotVerified,
    #[error("daemon request is invalid")]
    InvalidRequest,
}

#[async_trait]
pub trait PlatformControl: Send + Sync {
    async fn persist_recovery_intent(&self, intent: RecoveryIntent) -> Result<(), DaemonError>;
    async fn engage_kill_switch(&self) -> Result<(), DaemonError>;
    async fn verify_kill_switch(&self) -> Result<bool, DaemonError>;
    async fn disengage_kill_switch(&self) -> Result<(), DaemonError>;
    async fn start_packet_tunnel(&self) -> Result<(), DaemonError>;
    async fn stop_packet_tunnel(&self) -> Result<(), DaemonError>;
    async fn replace_split_policy(&self, rules: &[ApplicationRule]) -> Result<(), DaemonError>;
}

#[async_trait]
pub trait CoreControl: Send + Sync {
    async fn start(&self) -> Result<(), DaemonError>;
    async fn stop(&self) -> Result<(), DaemonError>;
    async fn apply(&self, intent: CoreIntent) -> Result<(), DaemonError>;
}

/// Owns only lifecycle order and safe state projection. The UI connection is
/// intentionally not represented here, so UI exit cannot trigger teardown.
pub struct DaemonRuntime<P: PlatformControl, C: CoreControl> {
    platform: Arc<P>,
    core: Arc<C>,
    snapshot: Mutex<StateSnapshot>,
    teardown_verified: Mutex<bool>,
}

impl<P: PlatformControl, C: CoreControl> DaemonRuntime<P, C> {
    pub fn new(platform: Arc<P>, core: Arc<C>) -> Self {
        Self {
            platform,
            core,
            snapshot: Mutex::new(initial_snapshot()),
            teardown_verified: Mutex::new(true),
        }
    }

    pub async fn snapshot(&self) -> StateSnapshot {
        self.snapshot.lock().await.clone()
    }

    pub async fn recover(&self, intent: RecoveryIntent) -> Result<(), DaemonError> {
        if intent == RecoveryIntent::Disconnected {
            *self.teardown_verified.lock().await = true;
            self.set_phase(TunnelPhase::Disconnected).await;
            return Ok(());
        }
        *self.teardown_verified.lock().await = false;
        self.set_kill_switch(KillSwitchState::Engaging).await;
        if self.platform.engage_kill_switch().await.is_err()
            || !self.platform.verify_kill_switch().await.unwrap_or(false)
        {
            self.block().await;
            let _ = self
                .platform
                .persist_recovery_intent(RecoveryIntent::Blocked)
                .await;
            return Err(DaemonError::KillSwitchNotVerified);
        }
        self.set_kill_switch(KillSwitchState::Engaged).await;
        if intent == RecoveryIntent::Blocked {
            self.block().await;
            return Ok(());
        }
        self.connect_after_kill_switch().await
    }

    pub async fn connect(&self) -> Result<(), DaemonError> {
        *self.teardown_verified.lock().await = false;
        self.set_phase(TunnelPhase::Preparing).await;
        self.platform
            .persist_recovery_intent(RecoveryIntent::Protected)
            .await?;
        self.set_kill_switch(KillSwitchState::Engaging).await;
        if self.platform.engage_kill_switch().await.is_err()
            || !self.platform.verify_kill_switch().await.unwrap_or(false)
        {
            self.block().await;
            let _ = self
                .platform
                .persist_recovery_intent(RecoveryIntent::Blocked)
                .await;
            return Err(DaemonError::KillSwitchNotVerified);
        }
        self.set_kill_switch(KillSwitchState::Engaged).await;
        self.connect_after_kill_switch().await
    }

    async fn connect_after_kill_switch(&self) -> Result<(), DaemonError> {
        self.set_phase(TunnelPhase::BootstrappingTor).await;
        if self.core.start().await.is_err() || self.platform.start_packet_tunnel().await.is_err() {
            let core_stopped = self.core.stop().await.is_ok();
            let tunnel_stopped = self.platform.stop_packet_tunnel().await.is_ok();
            *self.teardown_verified.lock().await = core_stopped && tunnel_stopped;
            self.block().await;
            let _ = self
                .platform
                .persist_recovery_intent(RecoveryIntent::Blocked)
                .await;
            return Err(DaemonError::Core);
        }
        let mut state = self.snapshot.lock().await;
        state.phase = TunnelPhase::Connected as i32;
        state.tor_bootstrap_percent = 100;
        state.gateway_status = GatewayStatus::Healthy as i32;
        state.kill_switch = KillSwitchState::Engaged as i32;
        state.state_revision += 1;
        Ok(())
    }

    pub async fn disconnect(&self, keep_kill_switch: bool) -> Result<(), DaemonError> {
        self.set_phase(TunnelPhase::Disconnecting).await;
        let core_result = self.core.stop().await;
        let tunnel_result = self.platform.stop_packet_tunnel().await;
        if core_result.is_err() || tunnel_result.is_err() {
            *self.teardown_verified.lock().await = false;
            self.block().await;
            return Err(DaemonError::Core);
        }
        *self.teardown_verified.lock().await = true;
        if keep_kill_switch {
            self.platform
                .persist_recovery_intent(RecoveryIntent::Blocked)
                .await?;
            self.block().await;
            return Ok(());
        }
        self.platform.disengage_kill_switch().await?;
        self.platform
            .persist_recovery_intent(RecoveryIntent::Disconnected)
            .await?;
        let mut state = self.snapshot.lock().await;
        state.phase = TunnelPhase::Disconnected as i32;
        state.kill_switch = KillSwitchState::Disabled as i32;
        state.tor_bootstrap_percent = 0;
        state.gateway_status = GatewayStatus::NotApplicable as i32;
        state.state_revision += 1;
        Ok(())
    }

    pub async fn set_kill_switch_enabled(&self, enabled: bool) -> Result<(), DaemonError> {
        if enabled {
            self.platform.engage_kill_switch().await?;
            if !self.platform.verify_kill_switch().await? {
                self.block().await;
                return Err(DaemonError::KillSwitchNotVerified);
            }
            self.set_kill_switch_state_only(KillSwitchState::Engaged)
                .await;
            Ok(())
        } else {
            let phase = TunnelPhase::try_from(self.snapshot.lock().await.phase)
                .unwrap_or(TunnelPhase::Unspecified);
            let teardown_verified = *self.teardown_verified.lock().await;
            if !teardown_verified
                || (phase != TunnelPhase::Disconnected && phase != TunnelPhase::Blocked)
            {
                return Err(DaemonError::InvalidRequest);
            }
            self.platform.disengage_kill_switch().await?;
            self.set_kill_switch_state_only(KillSwitchState::Disabled)
                .await;
            Ok(())
        }
    }

    pub async fn apply_non_lifecycle_request(
        &self,
        command: &request::Command,
    ) -> Result<(), DaemonError> {
        match command {
            request::Command::SetCountry(value) => {
                let selection = value
                    .country
                    .as_ref()
                    .and_then(|country| country.selection.as_ref())
                    .ok_or(DaemonError::InvalidRequest)?;
                let country = match selection {
                    onionroute_desktop_ipc::v1::country_selection::Selection::Automatic(true) => {
                        None
                    }
                    onionroute_desktop_ipc::v1::country_selection::Selection::IsoCountryCode(
                        code,
                    ) => Some(code.clone()),
                    _ => return Err(DaemonError::InvalidRequest),
                };
                self.core.apply(CoreIntent::SetCountry(country)).await
            }
            request::Command::SetAnonymityMode(value) => {
                let mode =
                    AnonymityMode::try_from(value.mode).map_err(|_| DaemonError::InvalidRequest)?;
                self.core.apply(CoreIntent::SetAnonymityMode(mode)).await?;
                let mut state = self.snapshot.lock().await;
                state.anonymity_mode = mode as i32;
                state.state_revision += 1;
                Ok(())
            }
            request::Command::Rotate(value) => {
                let rotation =
                    RotationKind::try_from(value.kind).map_err(|_| DaemonError::InvalidRequest)?;
                let intent = match rotation {
                    RotationKind::Soft => CoreIntent::SoftRotation,
                    RotationKind::HardNewIdentity => CoreIntent::HardRotation,
                    RotationKind::Unspecified => return Err(DaemonError::InvalidRequest),
                };
                self.set_phase(TunnelPhase::Rotating).await;
                let result = self.core.apply(intent).await;
                self.set_phase(if result.is_ok() {
                    TunnelPhase::Connected
                } else {
                    TunnelPhase::Degraded
                })
                .await;
                result
            }
            request::Command::UpdateSplitTunneling(value) => {
                self.platform.replace_split_policy(&value.rules).await
            }
            request::Command::UpdateSettings(value) => {
                self.core
                    .apply(CoreIntent::UpdateSettings {
                        locale: value.locale.clone(),
                        automatic_rotation_minutes: value.automatic_rotation_minutes,
                    })
                    .await
            }
            _ => Err(DaemonError::InvalidRequest),
        }
    }

    async fn block(&self) {
        let mut state = self.snapshot.lock().await;
        state.phase = TunnelPhase::Blocked as i32;
        state.kill_switch = KillSwitchState::FailedBlocking as i32;
        state.gateway_status = GatewayStatus::Unreachable as i32;
        state.state_revision += 1;
    }

    async fn set_phase(&self, phase: TunnelPhase) {
        let mut state = self.snapshot.lock().await;
        state.phase = phase as i32;
        state.state_revision += 1;
    }

    async fn set_kill_switch(&self, state_value: KillSwitchState) {
        self.set_kill_switch_state_only(state_value).await;
        if state_value == KillSwitchState::Engaged {
            self.set_phase(TunnelPhase::KillSwitchEngaged).await;
        }
    }

    async fn set_kill_switch_state_only(&self, state_value: KillSwitchState) {
        let mut state = self.snapshot.lock().await;
        state.kill_switch = state_value as i32;
        state.state_revision += 1;
    }
}

fn initial_snapshot() -> StateSnapshot {
    StateSnapshot {
        phase: TunnelPhase::Disconnected as i32,
        exit_country_code: String::new(),
        anonymity_mode: AnonymityMode::Standard as i32,
        tor_bootstrap_percent: 0,
        gateway_status: GatewayStatus::NotApplicable as i32,
        latency_bucket: LatencyBucket::NotAvailable as i32,
        kill_switch: KillSwitchState::Disabled as i32,
        blocked_leak_count: 0,
        udp_blocked: true,
        route_roles: Vec::new(),
        state_revision: 1,
    }
}
