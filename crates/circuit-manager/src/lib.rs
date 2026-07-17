#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Circuit, isolation and rotation ownership for OnionRoute.
//!
//! Client-core depends on the stable common `CircuitManager` trait. The
//! concrete implementation here owns a `TorBackendExt` and never exposes its
//! C Tor or Arti implementation.

mod callbacks;
mod isolation;
mod manager;
mod rotation;

pub use callbacks::{NoopRotationObserver, RotationObserver};
pub use isolation::IsolationManager;
pub use manager::{CircuitManager, CircuitManagerConfig, IdentityResetResult, RouteState};
pub use rotation::{RotationGate, RotationScheduler, RotationSchedulerConfig};

use onionroute_common_types::error::{ErrorCode, ErrorDomain, RetryClass, SafetyImpact, Severity};
use onionroute_common_types::OnionError;

pub(crate) fn circuit_error(
    code: ErrorCode,
    severity: Severity,
    retry: RetryClass,
    safety: SafetyImpact,
    message: &'static str,
) -> OnionError {
    OnionError::new(ErrorDomain::Tor, code, severity, retry, safety, message)
}
