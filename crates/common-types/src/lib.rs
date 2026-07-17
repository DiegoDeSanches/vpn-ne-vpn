#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Platform-neutral, versioned contracts shared by OnionRoute components.
//!
//! Dependency direction is strictly inward: implementations may depend on this
//! crate, while this crate does not depend on component implementations or a
//! particular async runtime.

pub mod contracts;
pub mod error;
pub mod state;
pub mod transport;
pub mod types;
pub mod version;

#[cfg(any(test, feature = "test-utils"))]
pub mod mocks;

pub use error::{OnionError, OnionResult};
pub use version::{ContractVersion, VersionedContract, CONTRACT_V1};

