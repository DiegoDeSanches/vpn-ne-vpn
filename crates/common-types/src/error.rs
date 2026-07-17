//! Stable internal error taxonomy shared across component boundaries.

/// Component family that originated an error.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ErrorDomain {
    /// Invalid local configuration.
    Configuration,
    /// OS or host integration.
    Platform,
    /// Fail-closed traffic controls.
    KillSwitch,
    /// Tor bootstrap or stream handling.
    Tor,
    /// Signed gateway directory.
    Directory,
    /// Capability-token acquisition or validation.
    Authentication,
    /// Private gateway session.
    Gateway,
    /// Packet and flow processing.
    Packet,
    /// Protected DNS resolution.
    Dns,
    /// Local policy evaluation.
    Policy,
    /// Protected local storage.
    Storage,
    /// Control-plane access.
    ControlPlane,
    /// Version or framing contract.
    Protocol,
    /// Failed invariant without a more specific domain.
    Internal,
}

/// Stable error code used for programmatic recovery and aggregate metrics.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ErrorCode {
    /// Configuration could not be validated.
    InvalidConfiguration,
    /// Required platform capability is absent.
    PlatformUnsupported,
    /// Kill switch could not be applied atomically.
    KillSwitchApplyFailed,
    /// Installed kill-switch state could not be proven safe.
    KillSwitchVerificationFailed,
    /// Tor did not bootstrap within its deadline.
    TorBootstrapTimeout,
    /// Tor became unavailable.
    TorUnavailable,
    /// Tor rejected an onion-service stream.
    TorStreamFailed,
    /// No cached directory exists.
    DirectoryUnavailable,
    /// Directory signature is invalid or untrusted.
    DirectorySignatureInvalid,
    /// Directory is expired or not yet valid.
    DirectoryExpired,
    /// Directory sequence indicates rollback.
    DirectoryRollback,
    /// No gateway satisfies the route constraints.
    GatewayUnavailable,
    /// Gateway TLS identity did not match the signed directory.
    GatewayIdentityMismatch,
    /// Gateway protocol negotiation found no compatible version.
    ProtocolIncompatible,
    /// A frame or message exceeded its declared bound.
    MessageTooLarge,
    /// A frame was malformed or violated sequencing rules.
    ProtocolViolation,
    /// No capability token could be acquired.
    TokenUnavailable,
    /// Capability token was rejected or expired.
    TokenRejected,
    /// Gateway session expired.
    SessionExpired,
    /// Gateway session heartbeat timed out.
    GatewayTimeout,
    /// Flow-control credit or queue capacity was exhausted.
    Backpressure,
    /// Traffic is unsupported in the current product version.
    UnsupportedTransport,
    /// Policy intentionally blocked the request.
    PolicyDenied,
    /// DNS failed inside the protected route.
    DnsResolutionFailed,
    /// System DNS was observed while protection was active.
    DnsLeakDetected,
    /// Protected storage could not be read or written.
    StorageUnavailable,
    /// Protected storage contents failed integrity checks.
    StorageCorrupt,
    /// Rotation failed while the old session remained usable.
    RotationDeferred,
    /// All protected paths are unavailable.
    ProtectedPathLost,
    /// Graceful shutdown exceeded its deadline.
    ShutdownTimeout,
    /// An internal safety invariant was violated.
    InvariantViolation,
}

/// Whether and when an operation may be retried.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RetryClass {
    /// Retrying cannot succeed without a software or configuration change.
    Never,
    /// A bounded immediate retry is safe.
    Immediate,
    /// Retry with exponential backoff and jitter.
    Backoff,
    /// Refresh the signed directory before retrying.
    AfterDirectoryRefresh,
    /// Acquire a fresh anonymous token before retrying.
    AfterTokenRefresh,
    /// Explicit user or administrator action is required.
    UserAction,
}

/// Security effect of an error.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SafetyImpact {
    /// Existing protection remains valid.
    Protected,
    /// Protection is uncertain; traffic must be blocked.
    MustBlock,
    /// Error occurred before traffic interception was attempted.
    NotApplicable,
}

/// Severity suitable for local diagnostics after redaction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Severity {
    /// Operation can continue with reduced availability.
    Warning,
    /// Current operation failed.
    Error,
    /// Safety or state invariants cannot be recovered automatically.
    Fatal,
}

/// Error safe to pass between in-process components.
///
/// `message` is static by design. Destinations, addresses, account identifiers,
/// tokens, and traffic contents must never be embedded in it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionError {
    /// Originating component family.
    pub domain: ErrorDomain,
    /// Stable programmatic code.
    pub code: ErrorCode,
    /// Operational severity.
    pub severity: Severity,
    /// Retry guidance.
    pub retry: RetryClass,
    /// Required fail-closed behavior.
    pub safety: SafetyImpact,
    /// Redacted static diagnostic.
    pub message: &'static str,
}

impl OnionError {
    /// Creates a fully classified error.
    pub const fn new(
        domain: ErrorDomain,
        code: ErrorCode,
        severity: Severity,
        retry: RetryClass,
        safety: SafetyImpact,
        message: &'static str,
    ) -> Self {
        Self {
            domain,
            code,
            severity,
            retry,
            safety,
            message,
        }
    }

    /// Returns true when traffic must remain blocked after this error.
    pub const fn requires_blocking(&self) -> bool {
        matches!(self.safety, SafetyImpact::MustBlock)
    }
}

/// Result type used by all Rust component contracts.
pub type OnionResult<T> = Result<T, OnionError>;

