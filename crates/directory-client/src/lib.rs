#![forbid(unsafe_code)]
//! Experimental reference implementation for proposed OnionRoute directory v2.
//!
//! This crate is deliberately outside the protected root workspace until
//! `docs/contract-proposals/CP-0006-directory-v2.md` is accepted. It contains no
//! networking and can verify a downloaded directory completely offline.

pub mod format;
pub mod issuer;
pub mod selection;
pub mod verification;

pub use format::*;
pub use issuer::{sign_directory, sign_trust_bundle, IssueError};
pub use selection::{select_gateway_plan, LocalFailure, SelectionError, SelectionInput};
pub use verification::{
    validate_document_semantics, verify_directory, PersistedDirectoryState, VerificationContext,
    VerificationError, VerifiedDirectory,
};

/// Maximum serialized signed envelope accepted by the reference verifier.
pub const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum number of gateway records in one document.
pub const MAX_GATEWAYS: usize = 4_096;
/// Signature domain for exact directory payload bytes.
pub const DIRECTORY_SIGNATURE_DOMAIN: &[u8] = b"onionroute-directory-v2\0";
/// Signature domain for a root-authorized trust bundle.
pub const TRUST_BUNDLE_SIGNATURE_DOMAIN: &[u8] = b"onionroute-directory-trust-v1\0";
