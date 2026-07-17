use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use onionroute_common_types::contracts::v1::TorBackend;
use onionroute_common_types::error::{ErrorCode, ErrorDomain, RetryClass, SafetyImpact, Severity};
use onionroute_common_types::transport::BoxFuture;
use onionroute_common_types::types::{AnonymityMode, IsolationKey, TorStatus};
use onionroute_common_types::{OnionError, OnionResult};

/// Maximum number of bridge lines accepted by one managed Tor context.
pub const MAX_BRIDGES: usize = 32;
/// Maximum number of pluggable transport definitions accepted per context.
pub const MAX_TRANSPORT_PLUGINS: usize = 8;
/// Maximum bytes accepted in any isolation dimension.
pub const MAX_ISOLATION_COMPONENT_BYTES: usize = 256;

/// Coarse managed-backend lifecycle. It never includes destinations or relays.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendLifecycle {
    /// No child or embedded backend is running.
    Stopped,
    /// Local resources and the control channel are being created.
    Starting,
    /// Tor is running but has not reached 100 percent bootstrap.
    Bootstrapping,
    /// New isolated streams may be opened.
    Ready,
    /// Protection remains fail-closed while recovery is required.
    Degraded,
    /// New work is rejected while resources are released.
    Stopping,
    /// The protected path is unavailable and user traffic must remain blocked.
    FailedClosed,
}

/// Closed-schema health snapshot suitable for local orchestration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendHealth {
    /// Current managed lifecycle.
    pub lifecycle: BackendLifecycle,
    /// Bootstrap completion from zero through one hundred.
    pub bootstrap_percent: u8,
    /// Whether the backend accepts new isolated streams.
    pub accepting_streams: bool,
    /// Coarse count of currently owned streams.
    pub active_streams: usize,
    /// True means the packet path must reject new user traffic.
    pub fail_closed: bool,
}

impl BackendHealth {
    /// Returns a stopped snapshot that requires the outer path to remain blocked.
    pub const fn stopped() -> Self {
        Self {
            lifecycle: BackendLifecycle::Stopped,
            bootstrap_percent: 0,
            accepting_streams: false,
            active_streams: 0,
            fail_closed: true,
        }
    }
}

/// Inputs that define whether streams may share a Tor circuit.
///
/// Values stay local and are never copied into diagnostics or the SOCKS
/// password. The SOCKS password is a fresh random key allocated for this exact
/// scope and session epoch.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct IsolationScope {
    /// Optional process-local application classifier.
    pub application: Option<String>,
    /// User-selected anonymity profile.
    pub anonymity_profile: AnonymityMode,
    /// Optional catalog gateway classifier.
    pub gateway: Option<String>,
    /// Local policy-defined destination grouping.
    pub destination_group: String,
    /// Optional browser container classifier.
    pub browser_container: Option<String>,
}

impl fmt::Debug for IsolationScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IsolationScope([REDACTED])")
    }
}

impl IsolationScope {
    /// Validates every component against length and control-character bounds.
    pub fn validate(&self) -> OnionResult<()> {
        for value in [
            self.application.as_deref(),
            self.gateway.as_deref(),
            Some(self.destination_group.as_str()),
            self.browser_container.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if value.is_empty()
                || value.len() > MAX_ISOLATION_COMPONENT_BYTES
                || value.contains(['\r', '\n', '\0'])
            {
                return Err(configuration_error("invalid isolation scope"));
            }
        }
        Ok(())
    }
}

/// Allocated, process-local SOCKS isolation context.
#[derive(Clone, Eq, PartialEq)]
pub struct IsolationContext {
    /// Backend-owned identity epoch at allocation time.
    pub session_epoch: u64,
    /// Random key sent only as the Tor SOCKS isolation parameter.
    pub key: IsolationKey,
}

impl fmt::Debug for IsolationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IsolationContext([REDACTED])")
    }
}

/// One validated bridge descriptor.
#[derive(Clone, Eq, PartialEq)]
pub struct BridgeLine {
    /// Optional pluggable-transport name.
    pub transport: Option<String>,
    /// Bridge OR endpoint.
    pub address: SocketAddr,
    /// Optional 40-hex relay identity fingerprint.
    pub fingerprint: Option<String>,
    /// Bounded `key=value` arguments understood by the selected transport.
    pub parameters: Vec<(String, String)>,
}

impl fmt::Debug for BridgeLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BridgeLine([REDACTED])")
    }
}

/// Pluggable transport process or an already-running local proxy.
#[derive(Clone, Eq, PartialEq)]
pub enum ClientTransportPlugin {
    /// Already-running local SOCKS5 pluggable-transport proxy.
    Socks5 {
        /// Transport name referenced by bridge lines.
        name: String,
        /// Local proxy endpoint.
        endpoint: SocketAddr,
    },
    /// Child executable managed by C Tor.
    Executable {
        /// Transport name referenced by bridge lines.
        name: String,
        /// Packaged, platform-validated executable path.
        path: PathBuf,
        /// Bounded executable arguments.
        arguments: Vec<String>,
    },
}

impl fmt::Debug for ClientTransportPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientTransportPlugin([REDACTED])")
    }
}

/// Bridge configuration applied before starting a Tor context.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BridgeConfig {
    /// Whether startup must fail if no bridge is configured.
    pub required: bool,
    /// Bounded bridge descriptors.
    pub bridges: Vec<BridgeLine>,
    /// Bounded pluggable-transport definitions.
    pub transports: Vec<ClientTransportPlugin>,
}

impl BridgeConfig {
    /// Validates bounds and prevents torrc line injection.
    pub fn validate(&self) -> OnionResult<()> {
        if self.bridges.len() > MAX_BRIDGES || self.transports.len() > MAX_TRANSPORT_PLUGINS {
            return Err(configuration_error("bridge configuration exceeds limits"));
        }
        if self.required && self.bridges.is_empty() {
            return Err(configuration_error(
                "bridges are required but not configured",
            ));
        }
        for bridge in &self.bridges {
            validate_token(bridge.transport.as_deref())?;
            if let Some(fingerprint) = &bridge.fingerprint {
                if fingerprint.len() != 40
                    || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(configuration_error("invalid bridge fingerprint"));
                }
            }
            if bridge.parameters.len() > 16 {
                return Err(configuration_error("bridge parameters exceed limit"));
            }
            for (key, value) in &bridge.parameters {
                validate_plain_value(key, 64)?;
                validate_plain_value(value, 256)?;
                if key.contains('=') || value.contains(char::is_whitespace) {
                    return Err(configuration_error("invalid bridge parameter"));
                }
            }
        }
        for transport in &self.transports {
            match transport {
                ClientTransportPlugin::Socks5 { name, .. } => validate_plain_value(name, 32)?,
                ClientTransportPlugin::Executable {
                    name,
                    path,
                    arguments,
                } => {
                    validate_plain_value(name, 32)?;
                    if path.as_os_str().is_empty() || arguments.len() > 32 {
                        return Err(configuration_error("invalid transport executable"));
                    }
                    for argument in arguments {
                        validate_plain_value(argument, 512)?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Optional upstream proxy used only by Tor's OR connections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyConfig {
    /// SOCKS5 proxy for Tor OR connections.
    Socks5(SocketAddr),
    /// HTTP CONNECT proxy for Tor OR connections.
    Https(SocketAddr),
}

/// Result of a rotation request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RotationOutcome {
    /// Epoch installed for subsequent context allocations.
    pub new_epoch: u64,
    /// Streams cancelled by the transition; always zero for soft rotation.
    pub closed_streams: usize,
}

/// Opaque identifier for one independently managed Tor process/context.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct TorContextId(pub [u8; 16]);

impl fmt::Debug for TorContextId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TorContextId([REDACTED])")
    }
}

/// Managed lifecycle extension proposed for a future common contract revision.
///
/// Implementations must also implement the stable `TorBackend` v1 contract.
/// All futures are bounded by implementation configuration; no method owns an
/// unbounded retry loop.
pub trait TorBackendExt: TorBackend {
    /// Starts local backend resources without waiting for full bootstrap.
    fn start(&self) -> BoxFuture<'_, OnionResult<TorStatus>>;
    /// Stops accepting streams and releases all local resources.
    fn stop(&self) -> BoxFuture<'_, OnionResult<()>>;
    /// Returns bounded bootstrap progress.
    fn bootstrap_progress(&self) -> BoxFuture<'_, OnionResult<u8>>;
    /// Allocates or reuses a context for the complete current-epoch scope.
    fn allocate_isolation_context<'a>(
        &'a self,
        scope: &'a IsolationScope,
    ) -> BoxFuture<'a, OnionResult<IsolationContext>>;
    /// Releases context ownership and cancels its remaining managed streams.
    fn release_isolation_context<'a>(
        &'a self,
        context: &'a IsolationContext,
    ) -> BoxFuture<'a, OnionResult<()>>;
    /// Advances the epoch without cancelling existing streams.
    fn request_soft_rotation(&self) -> BoxFuture<'_, OnionResult<RotationOutcome>>;
    /// Performs rate-limited disruptive identity rotation.
    fn request_hard_rotation(&self) -> BoxFuture<'_, OnionResult<RotationOutcome>>;
    /// Returns destination-free managed health.
    fn health_status(&self) -> BoxFuture<'_, OnionResult<BackendHealth>>;
    /// Replaces stopped-state bridge configuration.
    fn configure_bridges<'a>(&'a self, config: BridgeConfig) -> BoxFuture<'a, OnionResult<()>>;
    /// Replaces stopped-state upstream proxy configuration.
    fn configure_proxy(&self, config: Option<ProxyConfig>) -> BoxFuture<'_, OnionResult<()>>;
    /// Marks existing network assumptions stale without permitting a direct fallback.
    fn network_changed(&self) -> BoxFuture<'_, OnionResult<()>>;
}

pub(crate) fn validate_plain_value(value: &str, max: usize) -> OnionResult<()> {
    if value.is_empty() || value.len() > max || value.contains(['\r', '\n', '\0', '"']) {
        return Err(configuration_error("invalid Tor configuration value"));
    }
    Ok(())
}

fn validate_token(value: Option<&str>) -> OnionResult<()> {
    if let Some(value) = value {
        validate_plain_value(value, 32)?;
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(configuration_error("invalid Tor configuration token"));
        }
    }
    Ok(())
}

pub(crate) fn configuration_error(message: &'static str) -> OnionError {
    OnionError::new(
        ErrorDomain::Configuration,
        ErrorCode::InvalidConfiguration,
        Severity::Error,
        RetryClass::Never,
        SafetyImpact::NotApplicable,
        message,
    )
}

pub(crate) fn tor_error(
    code: ErrorCode,
    severity: Severity,
    retry: RetryClass,
    safety: SafetyImpact,
    message: &'static str,
) -> OnionError {
    OnionError::new(ErrorDomain::Tor, code, severity, retry, safety, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_configuration_is_bounded_and_injection_safe() {
        let required_without_bridge = BridgeConfig {
            required: true,
            ..BridgeConfig::default()
        };
        assert!(required_without_bridge.validate().is_err());

        let injected = BridgeConfig {
            required: false,
            bridges: vec![BridgeLine {
                transport: Some("obfs4\nUseBridges 0".to_owned()),
                address: "127.0.0.1:443".parse().unwrap(),
                fingerprint: None,
                parameters: Vec::new(),
            }],
            transports: Vec::new(),
        };
        assert!(injected.validate().is_err());
    }

    #[test]
    fn sensitive_debug_values_are_redacted() {
        let scope = IsolationScope {
            application: Some("secret-app".to_owned()),
            anonymity_profile: AnonymityMode::Standard,
            gateway: Some("secret-gateway".to_owned()),
            destination_group: "secret-destination".to_owned(),
            browser_container: None,
        };
        let rendered = format!("{scope:?}");
        assert!(!rendered.contains("secret"));
    }
}
