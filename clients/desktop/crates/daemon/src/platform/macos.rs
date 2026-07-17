use onionroute_desktop_ipc::{
    AuthenticatedPeer, PeerAuthenticationError, PeerAuthenticator, PeerRole,
};

/// Evidence extracted from `NETunnelProviderSession`/Network Extension audit
/// token and SecCode designated requirement. No bundle/team string crosses IPC.
pub enum AppleTransportPeer {
    App {
        audit_token_matches_owning_app: bool,
        app_group_matches: bool,
        designated_requirement_matches: bool,
        channel_binding: [u8; 32],
    },
    Provider {
        installed_provider_matches_manager: bool,
        team_identifier_matches: bool,
        designated_requirement_matches: bool,
        channel_binding: [u8; 32],
    },
}

pub struct AppleNetworkExtensionAuthenticator;

impl PeerAuthenticator for AppleNetworkExtensionAuthenticator {
    type TransportPeer = AppleTransportPeer;

    fn authenticate_client(
        &self,
        peer: &Self::TransportPeer,
    ) -> Result<AuthenticatedPeer, PeerAuthenticationError> {
        match peer {
            AppleTransportPeer::App {
                audit_token_matches_owning_app: true,
                app_group_matches: true,
                designated_requirement_matches: true,
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
            AppleTransportPeer::Provider {
                installed_provider_matches_manager: true,
                team_identifier_matches: true,
                designated_requirement_matches: true,
                channel_binding,
            } => Ok(AuthenticatedPeer::new(
                PeerRole::PrivilegedDaemon,
                *channel_binding,
            )),
            _ => Err(PeerAuthenticationError::NotAuthorized),
        }
    }
}
