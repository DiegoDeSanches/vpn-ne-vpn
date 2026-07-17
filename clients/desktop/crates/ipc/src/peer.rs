use std::fmt;

use thiserror::Error;

/// Role derived from trusted OS process credentials, never from an IPC field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRole {
    UnprivilegedUi,
    PrivilegedDaemon,
}

/// A short-lived authorization result. It intentionally has no principal name,
/// SID, UID, path, token, or serializable representation.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    role: PeerRole,
    session_binding: [u8; 32],
}

impl AuthenticatedPeer {
    pub fn new(role: PeerRole, session_binding: [u8; 32]) -> Self {
        Self {
            role,
            session_binding,
        }
    }

    pub fn role(&self) -> PeerRole {
        self.role
    }

    /// Opaque channel binding derived by the OS adapter. It must not be logged
    /// or sent on the wire.
    pub fn session_binding(&self) -> &[u8; 32] {
        &self.session_binding
    }
}

impl fmt::Debug for AuthenticatedPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedPeer")
            .field("role", &self.role)
            .field("session_binding", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PeerAuthenticationError {
    #[error("the local peer is not authorized")]
    NotAuthorized,
    #[error("the local peer identity could not be verified")]
    VerificationUnavailable,
}

/// Implemented by Named Pipe token/ACL, Apple audit-token/code-signing, or
/// Unix SO_PEERCRED/socket-ACL adapters. Both directions are mandatory.
pub trait PeerAuthenticator: Send + Sync {
    type TransportPeer;

    fn authenticate_client(
        &self,
        peer: &Self::TransportPeer,
    ) -> Result<AuthenticatedPeer, PeerAuthenticationError>;

    fn authenticate_server(
        &self,
        peer: &Self::TransportPeer,
    ) -> Result<AuthenticatedPeer, PeerAuthenticationError>;
}
