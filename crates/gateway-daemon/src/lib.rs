#![forbid(unsafe_code)]
//! Experimental OnionRoute private exit gateway.
//!
//! The crate deliberately owns no account or billing identity. All request-path
//! state is bounded and volatile; authentication is supplied through the
//! [`auth::AuthenticationVerifier`] interface.

pub mod acl;
pub mod auth;
pub mod config;
pub mod dns;
pub mod egress;
pub mod error;
pub mod health;
pub mod protocol;
pub mod rate_limit;
pub mod server;
pub mod session;
mod wire;

/// Prost adapter mirroring the protected protobuf v1 tags. Kept local so wire
/// types do not become an in-process `common-types` dependency.
pub use wire::onionroute;

pub use error::{GatewayError, GatewayErrorCode, GatewayResult};
