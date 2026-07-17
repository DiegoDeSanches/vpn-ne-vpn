#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Runtime-neutral Tor integration for OnionRoute.
//!
//! The stable client boundary remains
//! [`onionroute_common_types::contracts::v1::TorBackend`].  This crate adds a
//! managed-process extension without exposing a C Tor process, control socket,
//! or Tokio stream to client-core.

mod arti;
mod backoff;
mod control;
mod ctor;
mod health;
mod pool;
mod socks;
mod transport;
mod types;

#[cfg(feature = "test-utils")]
pub mod mock;

pub use arti::ArtiBackend;
pub use backoff::{BoundedBackoff, RetryPolicy};
pub use ctor::{CTorBackend, CTorConfig};
pub use health::{HealthObserver, TorHealthMonitor};
pub use pool::TorContextPool;
pub use types::{
    BackendHealth, BackendLifecycle, BridgeConfig, BridgeLine, ClientTransportPlugin,
    IsolationContext, IsolationScope, ProxyConfig, RotationOutcome, TorBackendExt, TorContextId,
};

pub(crate) use types::{configuration_error, tor_error};
