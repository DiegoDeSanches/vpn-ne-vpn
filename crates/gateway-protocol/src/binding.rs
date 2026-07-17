use sha2::{Digest, Sha256};

use crate::wire::onionroute::common::v1::ProtocolVersion;
use crate::{ProtocolError, Result};

const AUTH_BINDING_DOMAIN: &[u8] = b"onionroute-gateway-auth-v1\0";

/// Computes the standard v1 hello transcript binding used by `Authenticate`.
/// A token scheme with proof of possession signs or MACs this 32-byte value
/// according to that independently reviewed scheme.
pub fn session_nonce_binding(
    client_nonce: &[u8],
    server_nonce: &[u8],
    ephemeral_session_id: &[u8],
    selected_version: &ProtocolVersion,
) -> Result<[u8; 32]> {
    if client_nonce.len() != 32 {
        return Err(ProtocolError::InvalidField("client_nonce"));
    }
    if server_nonce.len() != 32 {
        return Err(ProtocolError::InvalidField("server_nonce"));
    }
    if ephemeral_session_id.len() != 16 {
        return Err(ProtocolError::InvalidField("ephemeral_session_id"));
    }
    if selected_version.major == 0 {
        return Err(ProtocolError::InvalidField("selected_version"));
    }

    let mut hasher = Sha256::new();
    hasher.update(AUTH_BINDING_DOMAIN);
    hasher.update(client_nonce);
    hasher.update(server_nonce);
    hasher.update(ephemeral_session_id);
    hasher.update(selected_version.major.to_be_bytes());
    hasher.update(selected_version.minor.to_be_bytes());
    Ok(hasher.finalize().into())
}
