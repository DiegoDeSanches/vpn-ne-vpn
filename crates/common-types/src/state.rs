//! Client connection state machine and recovery decisions.

use crate::error::{ErrorCode, OnionError, RetryClass, SafetyImpact, Severity};

/// Externally observable client connection state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ClientConnectionState {
    /// No interception or protected session is active.
    Disconnected,
    /// Configuration, crash recovery, and prerequisites are being checked.
    Preparing,
    /// Fail-closed traffic rules are being installed and verified.
    ApplyingKillSwitch,
    /// Tor is bootstrapping.
    BootstrappingTor,
    /// A signed gateway directory is being loaded and verified.
    LoadingDirectory,
    /// A role-correct gateway route is being selected.
    SelectingGateway,
    /// A capability token and anonymous gateway session are being established.
    Authenticating,
    /// The protected path is accepting flows.
    Connected,
    /// A replacement route is being built while the old route remains protected.
    Rotating,
    /// No healthy session is available and bounded reconnect is underway.
    Reconnecting,
    /// Protection remains valid but availability or redundancy is reduced.
    Degraded,
    /// Components are draining in safe reverse order.
    Disconnecting,
    /// Traffic is intentionally blocked because protection is absent or uncertain.
    Blocked,
    /// A non-recoverable invariant, configuration, or compatibility error occurred.
    FatalError,
}

impl ClientConnectionState {
    /// Returns whether the state machine permits the proposed transition.
    ///
    /// A caller still needs a concrete trigger and must persist diagnostics. This
    /// method prevents accidental shortcuts around kill-switch application.
    pub const fn can_transition_to(self, next: Self) -> bool {
        use ClientConnectionState as S;
        matches!(
            (self, next),
            (S::Disconnected, S::Preparing)
                | (S::Preparing, S::ApplyingKillSwitch)
                | (S::Preparing, S::Disconnecting)
                | (S::Preparing, S::FatalError)
                | (S::ApplyingKillSwitch, S::BootstrappingTor)
                | (S::ApplyingKillSwitch, S::Blocked)
                | (S::ApplyingKillSwitch, S::Disconnecting)
                | (S::ApplyingKillSwitch, S::FatalError)
                | (S::BootstrappingTor, S::LoadingDirectory)
                | (S::BootstrappingTor, S::Connected)
                | (S::BootstrappingTor, S::Reconnecting)
                | (S::BootstrappingTor, S::Blocked)
                | (S::BootstrappingTor, S::Disconnecting)
                | (S::BootstrappingTor, S::FatalError)
                | (S::LoadingDirectory, S::SelectingGateway)
                | (S::LoadingDirectory, S::Degraded)
                | (S::LoadingDirectory, S::Reconnecting)
                | (S::LoadingDirectory, S::Blocked)
                | (S::LoadingDirectory, S::Disconnecting)
                | (S::LoadingDirectory, S::FatalError)
                | (S::SelectingGateway, S::Authenticating)
                | (S::SelectingGateway, S::LoadingDirectory)
                | (S::SelectingGateway, S::Degraded)
                | (S::SelectingGateway, S::Reconnecting)
                | (S::SelectingGateway, S::Blocked)
                | (S::SelectingGateway, S::Disconnecting)
                | (S::SelectingGateway, S::FatalError)
                | (S::Authenticating, S::Connected)
                | (S::Authenticating, S::SelectingGateway)
                | (S::Authenticating, S::Reconnecting)
                | (S::Authenticating, S::Degraded)
                | (S::Authenticating, S::Blocked)
                | (S::Authenticating, S::Disconnecting)
                | (S::Authenticating, S::FatalError)
                | (S::Connected, S::Rotating)
                | (S::Connected, S::Reconnecting)
                | (S::Connected, S::Degraded)
                | (S::Connected, S::Blocked)
                | (S::Connected, S::Disconnecting)
                | (S::Connected, S::FatalError)
                | (S::Rotating, S::Connected)
                | (S::Rotating, S::Degraded)
                | (S::Rotating, S::Reconnecting)
                | (S::Rotating, S::Blocked)
                | (S::Rotating, S::Disconnecting)
                | (S::Rotating, S::FatalError)
                | (S::Reconnecting, S::BootstrappingTor)
                | (S::Reconnecting, S::LoadingDirectory)
                | (S::Reconnecting, S::SelectingGateway)
                | (S::Reconnecting, S::Authenticating)
                | (S::Reconnecting, S::Connected)
                | (S::Reconnecting, S::Degraded)
                | (S::Reconnecting, S::Blocked)
                | (S::Reconnecting, S::Disconnecting)
                | (S::Reconnecting, S::FatalError)
                | (S::Degraded, S::LoadingDirectory)
                | (S::Degraded, S::SelectingGateway)
                | (S::Degraded, S::Authenticating)
                | (S::Degraded, S::Connected)
                | (S::Degraded, S::Rotating)
                | (S::Degraded, S::Reconnecting)
                | (S::Degraded, S::Blocked)
                | (S::Degraded, S::Disconnecting)
                | (S::Degraded, S::FatalError)
                | (S::Disconnecting, S::Disconnected)
                | (S::Disconnecting, S::Blocked)
                | (S::Disconnecting, S::FatalError)
                | (S::Blocked, S::Preparing)
                | (S::Blocked, S::Disconnecting)
                | (S::Blocked, S::FatalError)
                | (S::FatalError, S::Disconnecting)
        )
    }

    /// Returns true when the kill switch must be engaged in this state.
    pub const fn requires_kill_switch(self) -> bool {
        !matches!(
            self,
            Self::Disconnected | Self::Preparing | Self::ApplyingKillSwitch
        )
    }
}

/// High-level recovery selected from a classified error and current safety state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RecoveryAction {
    /// Retry the current phase within its strict attempt budget.
    RetryCurrentPhase,
    /// Back off while keeping the kill switch engaged.
    ReconnectWithBackoff,
    /// Refresh only the signed directory.
    RefreshDirectory,
    /// Acquire a replacement anonymous capability token.
    RefreshToken,
    /// Keep the old healthy session and defer rotation.
    KeepOldSession,
    /// Force emergency blocking and enter `Blocked`.
    EnterBlocked,
    /// Stop automatic retries and enter `FatalError`.
    EnterFatal,
    /// Wait for an explicit user or administrator action.
    WaitForUser,
}

/// Selects a conservative default recovery action.
pub fn recovery_action(
    error: &OnionError,
    old_path_healthy: bool,
    cached_directory_valid: bool,
) -> RecoveryAction {
    if matches!(error.safety, SafetyImpact::MustBlock) {
        return RecoveryAction::EnterBlocked;
    }
    if matches!(error.severity, Severity::Fatal) {
        return RecoveryAction::EnterFatal;
    }
    if matches!(error.code, ErrorCode::RotationDeferred) && old_path_healthy {
        return RecoveryAction::KeepOldSession;
    }
    if matches!(error.code, ErrorCode::DirectorySignatureInvalid) && cached_directory_valid {
        return RecoveryAction::RetryCurrentPhase;
    }
    match error.retry {
        RetryClass::Never => RecoveryAction::EnterFatal,
        RetryClass::Immediate => RecoveryAction::RetryCurrentPhase,
        RetryClass::Backoff => RecoveryAction::ReconnectWithBackoff,
        RetryClass::AfterDirectoryRefresh => RecoveryAction::RefreshDirectory,
        RetryClass::AfterTokenRefresh => RecoveryAction::RefreshToken,
        RetryClass::UserAction => RecoveryAction::WaitForUser,
    }
}

#[cfg(test)]
mod tests {
    use super::ClientConnectionState as S;

    #[test]
    fn happy_path_requires_kill_switch_before_network_bootstrap() {
        let states = [
            S::Disconnected,
            S::Preparing,
            S::ApplyingKillSwitch,
            S::BootstrappingTor,
            S::LoadingDirectory,
            S::SelectingGateway,
            S::Authenticating,
            S::Connected,
        ];
        assert!(states
            .windows(2)
            .all(|pair| pair[0].can_transition_to(pair[1])));
        assert!(!S::Preparing.can_transition_to(S::BootstrappingTor));
        assert!(!S::Disconnected.can_transition_to(S::Connected));
        assert!(S::BootstrappingTor.can_transition_to(S::Connected));
    }

    #[test]
    fn protected_states_can_fail_closed() {
        for state in [
            S::BootstrappingTor,
            S::LoadingDirectory,
            S::SelectingGateway,
            S::Authenticating,
            S::Connected,
            S::Rotating,
            S::Reconnecting,
            S::Degraded,
        ] {
            assert!(state.requires_kill_switch());
            assert!(state.can_transition_to(S::Blocked));
        }
    }
}
