//! Experimental Enhanced-mode data plane.
//!
//! The entry side accepts only an already anonymized Tor byte stream and an
//! anonymous capability. It selects a diverse exit and forwards an opaque
//! terminal TLS session. Only the exit terminates the user gateway protocol,
//! resolves DNS, applies destination ACLs, and performs TCP egress.

#![forbid(unsafe_code)]

pub mod entry;
pub mod error;
pub mod exit;
pub mod identity;
pub mod mux;
pub mod protocol;
pub mod quota;
pub mod recovery;
pub mod route;
pub mod tls;

pub use error::{Error, ErrorCode, Result};
