//! OnionRoute desktop IPC v1.
//!
//! Authentication is deliberately outside the protobuf payload. The local
//! transport must authenticate both peers using OS credentials and ACLs before
//! any frame is decoded. This crate never carries shared secrets.

mod framing;
mod peer;
mod validation;

pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/onionroute.desktop.ipc.v1.rs"));
}

pub use framing::{decode_frame, encode_frame, FrameError, MAX_FRAME_BYTES};
pub use peer::{AuthenticatedPeer, PeerAuthenticationError, PeerAuthenticator, PeerRole};
pub use validation::{validate_envelope, ValidationError, IPC_V1};
