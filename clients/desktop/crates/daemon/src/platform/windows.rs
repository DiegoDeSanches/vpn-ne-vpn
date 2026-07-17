use std::{fs, path::PathBuf};

use async_trait::async_trait;
use onionroute_desktop_ipc::{
    v1::ApplicationRule, AuthenticatedPeer, PeerAuthenticationError, PeerAuthenticator, PeerRole,
};

use crate::{DaemonError, PlatformControl, RecoveryIntent};

pub const CONTROL_PIPE: &str = r"\\.\pipe\OnionRoute.Control.v1";
pub const CONTROL_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GRGW;;;OW)";
pub const MAX_PIPE_INSTANCES: u32 = 8;

const RECOVERY_DISCONNECTED: &str = "disconnected\n";
const RECOVERY_PROTECTED: &str = "protected\n";
const RECOVERY_BLOCKED: &str = "blocked\n";

/// Thin calls to reviewed Windows implementations (`windows-service`, Wintun
/// API, WFP, DPAPI). No packet/network policy is implemented in this wrapper.
pub trait WindowsPlatformApi: Send + Sync {
    fn dpapi_store_recovery_intent(&self, intent: RecoveryIntent) -> Result<(), DaemonError>;
    fn wfp_install_persistent_fail_closed_filters(&self) -> Result<(), DaemonError>;
    fn wfp_verify_effective_fail_closed_filters(&self) -> Result<bool, DaemonError>;
    fn wfp_remove_filters_after_teardown(&self) -> Result<(), DaemonError>;
    fn wintun_start_adapter(&self) -> Result<(), DaemonError>;
    fn wintun_stop_and_verify_adapter(&self) -> Result<(), DaemonError>;
    fn wfp_replace_application_policy(&self, rules: &[ApplicationRule]) -> Result<(), DaemonError>;
}

/// EXPERIMENTAL console-host adapter.
///
/// This adapter persists only a development recovery marker. It deliberately
/// reports every WFP/Wintun operation as unavailable, so the daemon runtime can
/// exercise IPC and lifecycle failure handling without ever claiming that a
/// system tunnel or kill switch exists. It is not a Windows service adapter and
/// must never be used in a release build.
pub struct DevFailClosedPlatform {
    recovery_path: PathBuf,
}

impl DevFailClosedPlatform {
    pub fn new(recovery_path: impl Into<PathBuf>) -> Self {
        Self {
            recovery_path: recovery_path.into(),
        }
    }

    /// Loads a bounded marker. Missing state is a clean first start; malformed
    /// state is an error and callers must recover as `Blocked`.
    pub fn load_recovery_intent(&self) -> Result<Option<RecoveryIntent>, DaemonError> {
        let bytes = match fs::read(&self.recovery_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(DaemonError::Platform),
        };
        if bytes.len() > RECOVERY_DISCONNECTED.len() {
            return Err(DaemonError::Platform);
        }
        match bytes.as_slice() {
            value if value == RECOVERY_DISCONNECTED.as_bytes() => {
                Ok(Some(RecoveryIntent::Disconnected))
            }
            value if value == RECOVERY_PROTECTED.as_bytes() => Ok(Some(RecoveryIntent::Protected)),
            value if value == RECOVERY_BLOCKED.as_bytes() => Ok(Some(RecoveryIntent::Blocked)),
            _ => Err(DaemonError::Platform),
        }
    }

    pub fn recovery_path(&self) -> &std::path::Path {
        &self.recovery_path
    }

    fn store_recovery_intent(&self, intent: RecoveryIntent) -> Result<(), DaemonError> {
        let value = match intent {
            RecoveryIntent::Disconnected => RECOVERY_DISCONNECTED,
            RecoveryIntent::Protected => RECOVERY_PROTECTED,
            RecoveryIntent::Blocked => RECOVERY_BLOCKED,
        };
        let Some(parent) = self.recovery_path.parent() else {
            return Err(DaemonError::Platform);
        };
        fs::create_dir_all(parent).map_err(|_| DaemonError::Platform)?;
        // A truncated or malformed marker is interpreted as Blocked on the
        // next start. This keeps crash recovery fail closed.
        fs::write(&self.recovery_path, value).map_err(|_| DaemonError::Platform)
    }
}

#[async_trait]
impl PlatformControl for DevFailClosedPlatform {
    async fn persist_recovery_intent(&self, intent: RecoveryIntent) -> Result<(), DaemonError> {
        self.store_recovery_intent(intent)
    }

    async fn engage_kill_switch(&self) -> Result<(), DaemonError> {
        Err(DaemonError::Platform)
    }

    async fn verify_kill_switch(&self) -> Result<bool, DaemonError> {
        Ok(false)
    }

    async fn disengage_kill_switch(&self) -> Result<(), DaemonError> {
        Err(DaemonError::Platform)
    }

    async fn start_packet_tunnel(&self) -> Result<(), DaemonError> {
        Err(DaemonError::Platform)
    }

    async fn stop_packet_tunnel(&self) -> Result<(), DaemonError> {
        // No adapter is ever created by this development implementation.
        Ok(())
    }

    async fn replace_split_policy(&self, _rules: &[ApplicationRule]) -> Result<(), DaemonError> {
        Err(DaemonError::Platform)
    }
}

pub struct WindowsPlatformControl<A> {
    api: A,
}

impl<A> WindowsPlatformControl<A> {
    pub fn new(api: A) -> Self {
        Self { api }
    }
}

#[async_trait]
impl<A: WindowsPlatformApi> PlatformControl for WindowsPlatformControl<A> {
    async fn persist_recovery_intent(&self, intent: RecoveryIntent) -> Result<(), DaemonError> {
        self.api.dpapi_store_recovery_intent(intent)
    }

    async fn engage_kill_switch(&self) -> Result<(), DaemonError> {
        self.api.wfp_install_persistent_fail_closed_filters()
    }

    async fn verify_kill_switch(&self) -> Result<bool, DaemonError> {
        self.api.wfp_verify_effective_fail_closed_filters()
    }

    async fn disengage_kill_switch(&self) -> Result<(), DaemonError> {
        self.api.wfp_remove_filters_after_teardown()
    }

    async fn start_packet_tunnel(&self) -> Result<(), DaemonError> {
        self.api.wintun_start_adapter()
    }

    async fn stop_packet_tunnel(&self) -> Result<(), DaemonError> {
        self.api.wintun_stop_and_verify_adapter()
    }

    async fn replace_split_policy(&self, rules: &[ApplicationRule]) -> Result<(), DaemonError> {
        self.api.wfp_replace_application_policy(rules)
    }
}

pub enum WindowsTransportPeer {
    Client {
        pipe_acl_matches: bool,
        token_is_interactive_owner: bool,
        image_signature_is_approved: bool,
        channel_binding: [u8; 32],
    },
    Server {
        process_id_matches_scm: bool,
        installed_path_matches: bool,
        authenticode_publisher_matches: bool,
        channel_binding: [u8; 32],
    },
}

pub struct WindowsPipeAuthenticator;

impl PeerAuthenticator for WindowsPipeAuthenticator {
    type TransportPeer = WindowsTransportPeer;

    fn authenticate_client(
        &self,
        peer: &Self::TransportPeer,
    ) -> Result<AuthenticatedPeer, PeerAuthenticationError> {
        match peer {
            WindowsTransportPeer::Client {
                pipe_acl_matches: true,
                token_is_interactive_owner: true,
                image_signature_is_approved: true,
                channel_binding,
            } => Ok(AuthenticatedPeer::new(
                PeerRole::UnprivilegedUi,
                *channel_binding,
            )),
            _ => Err(PeerAuthenticationError::NotAuthorized),
        }
    }

    fn authenticate_server(
        &self,
        peer: &Self::TransportPeer,
    ) -> Result<AuthenticatedPeer, PeerAuthenticationError> {
        match peer {
            WindowsTransportPeer::Server {
                process_id_matches_scm: true,
                installed_path_matches: true,
                authenticode_publisher_matches: true,
                channel_binding,
            } => Ok(AuthenticatedPeer::new(
                PeerRole::PrivilegedDaemon,
                *channel_binding,
            )),
            _ => Err(PeerAuthenticationError::NotAuthorized),
        }
    }
}
