use async_trait::async_trait;
use onionroute_desktop_ipc::{
    v1::ApplicationRule, AuthenticatedPeer, PeerAuthenticationError, PeerAuthenticator, PeerRole,
};

use crate::{DaemonError, PlatformControl, RecoveryIntent};

pub const CONTROL_SOCKET: &str = "/run/onionroute/control-v1.sock";
pub const CONTROL_SOCKET_MODE: u32 = 0o660;
pub const MAX_SOCKET_CLIENTS: usize = 8;

/// Thin calls to libsecret/Secret Service, `/dev/net/tun` and atomic nftables.
/// The concrete adapter uses netlink/libnftables rather than a shell command.
pub trait LinuxPlatformApi: Send + Sync {
    fn secret_service_store_recovery_intent(
        &self,
        intent: RecoveryIntent,
    ) -> Result<(), DaemonError>;
    fn nft_apply_atomic_fail_closed_table(&self) -> Result<(), DaemonError>;
    fn nft_verify_effective_fail_closed_table(&self) -> Result<bool, DaemonError>;
    fn nft_remove_table_after_teardown(&self) -> Result<(), DaemonError>;
    fn tun_open_configured_fd(&self) -> Result<(), DaemonError>;
    fn tun_close_and_verify_routes(&self) -> Result<(), DaemonError>;
    fn nft_replace_application_policy(&self, rules: &[ApplicationRule]) -> Result<(), DaemonError>;
}

pub struct LinuxPlatformControl<A> {
    api: A,
}

impl<A> LinuxPlatformControl<A> {
    pub fn new(api: A) -> Self {
        Self { api }
    }
}

#[async_trait]
impl<A: LinuxPlatformApi> PlatformControl for LinuxPlatformControl<A> {
    async fn persist_recovery_intent(&self, intent: RecoveryIntent) -> Result<(), DaemonError> {
        self.api.secret_service_store_recovery_intent(intent)
    }

    async fn engage_kill_switch(&self) -> Result<(), DaemonError> {
        self.api.nft_apply_atomic_fail_closed_table()
    }

    async fn verify_kill_switch(&self) -> Result<bool, DaemonError> {
        self.api.nft_verify_effective_fail_closed_table()
    }

    async fn disengage_kill_switch(&self) -> Result<(), DaemonError> {
        self.api.nft_remove_table_after_teardown()
    }

    async fn start_packet_tunnel(&self) -> Result<(), DaemonError> {
        self.api.tun_open_configured_fd()
    }

    async fn stop_packet_tunnel(&self) -> Result<(), DaemonError> {
        self.api.tun_close_and_verify_routes()
    }

    async fn replace_split_policy(&self, rules: &[ApplicationRule]) -> Result<(), DaemonError> {
        self.api.nft_replace_application_policy(rules)
    }
}

pub enum UnixTransportPeer {
    Client {
        socket_acl_matches: bool,
        peercred_group_authorized: bool,
        executable_is_approved_desktop: bool,
        channel_binding: [u8; 32],
    },
    Server {
        peercred_uid_is_root: bool,
        executable_is_root_owned_and_fixed: bool,
        socket_is_root_owned: bool,
        channel_binding: [u8; 32],
    },
}

pub struct UnixSocketAuthenticator;

impl PeerAuthenticator for UnixSocketAuthenticator {
    type TransportPeer = UnixTransportPeer;

    fn authenticate_client(
        &self,
        peer: &Self::TransportPeer,
    ) -> Result<AuthenticatedPeer, PeerAuthenticationError> {
        match peer {
            UnixTransportPeer::Client {
                socket_acl_matches: true,
                peercred_group_authorized: true,
                executable_is_approved_desktop: true,
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
            UnixTransportPeer::Server {
                peercred_uid_is_root: true,
                executable_is_root_owned_and_fixed: true,
                socket_is_root_owned: true,
                channel_binding,
            } => Ok(AuthenticatedPeer::new(
                PeerRole::PrivilegedDaemon,
                *channel_binding,
            )),
            _ => Err(PeerAuthenticationError::NotAuthorized),
        }
    }
}
