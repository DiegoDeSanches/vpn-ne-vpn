//! OnionRoute private-gateway protocol v1.
//!
//! This crate owns only the reliable-byte-stream protocol layer: protobuf
//! framing, version negotiation, multiplexing, flow control, bounded queues and
//! reference client/server handshakes. It has no Tor, egress, billing, UI, DNS
//! resolver, or account dependency. The caller supplies an already protected
//! `AsyncRead + AsyncWrite` transport.

#![forbid(unsafe_code)]

pub mod binding;
pub mod client;
pub mod debug;
pub mod error;
pub mod flow;
pub mod framing;
pub mod limits;
pub mod negotiation;
pub mod scheduler;
pub mod server;
pub mod session;
pub mod validation;

/// Generated protobuf types. These values may contain secrets or destinations;
/// never log their derived `Debug` representation. Use [`debug::FrameSummary`].
pub mod wire {
    pub mod onionroute {
        pub mod common {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/onionroute.common.v1.rs"));
            }
        }
        pub mod gateway {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/onionroute.gateway.v1.rs"));
            }
        }
    }
}

pub use error::{ProtocolError, Result};
pub use limits::ProtocolLimits;
pub use wire::onionroute::gateway::v1 as proto;
