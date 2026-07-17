//! Privileged desktop lifecycle orchestration.
//!
//! Network processing is intentionally absent. `CoreControl` is an adapter to
//! the shared Rust core; platform code owns only OS facilities such as TUN,
//! firewall policy, secure storage, and local IPC.

mod confirmation;
mod diagnostics;
mod runtime;
mod session;

pub mod platform;

pub use confirmation::{ConfirmationError, ConfirmationStore};
pub use diagnostics::{
    DiagnosticEventCode, DiagnosticSnapshot, DiagnosticsError, DiagnosticsExporter, ExportMetadata,
};
pub use runtime::{
    CoreControl, CoreIntent, DaemonError, DaemonRuntime, PlatformControl, RecoveryIntent,
};
pub use session::{IpcSession, SessionError};
