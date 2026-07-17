//! Version 1 component contracts.
//!
//! Implementations own concurrency and resource management. Callers must obey
//! documented size limits and may not assume a specific async runtime.

use crate::transport::{BoxFuture, BoxPacketTunnel, BoxTransport};
use crate::types::{
    CapabilityToken, DirectoryRefreshReason, DnsPolicyContext, DnsQuery, DnsResponse,
    GatewayCredentials, GatewayDialRequest, GatewayPlan, GatewaySession, GatewaySessionState,
    HealthEvent,
    IsolationKey, KillSwitchLease, KillSwitchPolicy, KillSwitchStatus, OnionEndpoint,
    PacketEngineConfig, PacketEngineStatus, PacketEvent, PolicyDecision, RotationCandidate,
    RotationReason, RouteConstraints, RouteLease, SecretValue, SignedDirectoryEnvelope,
    StorageKey, TcpFlowRequest, TokenRequest, TorBootstrapConfig, TorStatus,
    VerifiedGatewayDirectory,
};
use crate::version::VersionedContract;
use crate::{OnionError, OnionResult};

/// Low-level Tor implementation boundary, initially C Tor and later Arti.
pub trait TorBackend: Send + Sync + VersionedContract {
    /// Bootstraps Tor to a usable state or returns a bounded error.
    fn bootstrap<'a>(
        &'a self,
        config: &'a TorBootstrapConfig,
    ) -> BoxFuture<'a, OnionResult<TorStatus>>;

    /// Opens an isolated stream to a v3 onion endpoint.
    fn open_onion_stream<'a>(
        &'a self,
        endpoint: &'a OnionEndpoint,
        isolation: &'a IsolationKey,
    ) -> BoxFuture<'a, OnionResult<BoxTransport>>;

    /// Opens a direct Tor exit stream for the explicitly selected Direct Tor mode.
    fn open_direct_stream<'a>(
        &'a self,
        request: &'a TcpFlowRequest,
        isolation: &'a IsolationKey,
    ) -> BoxFuture<'a, OnionResult<BoxTransport>>;

    /// Returns coarse bootstrap and availability status.
    fn status(&self) -> BoxFuture<'_, OnionResult<TorStatus>>;

    /// Stops accepting streams and shuts the backend down.
    fn shutdown(&self) -> BoxFuture<'_, OnionResult<()>>;
}

/// Owns isolated Tor route lifetimes and make-before-break rotation.
pub trait CircuitManager: Send + Sync + VersionedContract {
    /// Prepares an isolated route for a previously selected gateway plan.
    fn prepare_route<'a>(
        &'a self,
        plan: &'a GatewayPlan,
        reason: RotationReason,
    ) -> BoxFuture<'a, OnionResult<RouteLease>>;

    /// Opens the first-hop protected transport for an existing route lease.
    fn open_first_hop<'a>(
        &'a self,
        route: &'a RouteLease,
    ) -> BoxFuture<'a, OnionResult<BoxTransport>>;

    /// Prepares both a replacement route and its first-hop transport while the
    /// current route remains active.
    fn prepare_rotation<'a>(
        &'a self,
        current: &'a RouteLease,
        replacement: &'a GatewayPlan,
        reason: RotationReason,
    ) -> BoxFuture<'a, OnionResult<RotationCandidate>>;

    /// Retires a route after all attached gateway sessions have drained.
    fn retire_route<'a>(&'a self, route: &'a RouteLease) -> BoxFuture<'a, OnionResult<()>>;
}

/// Builds and owns anonymous private-gateway sessions and multiplexed streams.
pub trait GatewayConnector: Send + Sync + VersionedContract {
    /// Performs application TLS, version negotiation, and anonymous capability
    /// authentication over a prepared protected transport.
    fn connect<'a>(
        &'a self,
        transport: BoxTransport,
        request: &'a GatewayDialRequest,
        credentials: GatewayCredentials,
    ) -> BoxFuture<'a, OnionResult<GatewaySession>>;

    /// Opens a bounded TCP stream through the terminal exit gateway.
    fn open_tcp<'a>(
        &'a self,
        session: &'a GatewaySession,
        request: &'a TcpFlowRequest,
    ) -> BoxFuture<'a, OnionResult<BoxTransport>>;

    /// Exchanges one bounded DNS wire message through an active session.
    fn exchange_dns<'a>(
        &'a self,
        session: &'a GatewaySession,
        query: &'a DnsQuery,
    ) -> BoxFuture<'a, OnionResult<DnsResponse>>;

    /// Reads the authoritative session lifecycle state.
    fn session_state<'a>(
        &'a self,
        session: &'a GatewaySession,
    ) -> BoxFuture<'a, OnionResult<GatewaySessionState>>;

    /// Stops accepting new flows while allowing a bounded drain period.
    fn begin_draining<'a>(
        &'a self,
        session: &'a GatewaySession,
    ) -> BoxFuture<'a, OnionResult<()>>;

    /// Closes a drained session and releases all protocol resources.
    fn close<'a>(&'a self, session: &'a GatewaySession) -> BoxFuture<'a, OnionResult<()>>;
}

/// Converts a platform packet tunnel into bounded TCP and DNS events.
pub trait PacketEngine: Send + Sync + VersionedContract {
    /// Attaches a platform adapter and starts packet processing.
    fn start(
        &self,
        tunnel: BoxPacketTunnel,
        config: PacketEngineConfig,
    ) -> BoxFuture<'_, OnionResult<()>>;

    /// Waits for the next bounded flow event, applying queue backpressure.
    fn next_event(&self) -> BoxFuture<'_, OnionResult<PacketEvent>>;

    /// Binds a protected ordered stream to a pending local TCP flow.
    fn bind_tcp(
        &self,
        flow: crate::types::FlowId,
        stream: BoxTransport,
    ) -> BoxFuture<'_, OnionResult<()>>;

    /// Rejects a pending local flow with a stable, non-sensitive reason.
    fn reject_flow(
        &self,
        flow: crate::types::FlowId,
        error: OnionError,
    ) -> BoxFuture<'_, OnionResult<()>>;

    /// Delivers a protected DNS response to the system packet tunnel.
    fn complete_dns(&self, response: DnsResponse) -> BoxFuture<'_, OnionResult<()>>;

    /// Returns coarse queue and flow counts.
    fn status(&self) -> BoxFuture<'_, OnionResult<PacketEngineStatus>>;

    /// Rejects new flows, drains bounded buffers, and closes the packet tunnel.
    fn stop(&self) -> BoxFuture<'_, OnionResult<()>>;
}

/// Resolves DNS exclusively through a supplied protected upstream.
pub trait DnsEngine: Send + Sync + VersionedContract {
    /// Validates and resolves a DNS query without using system DNS.
    fn resolve<'a>(
        &'a self,
        query: &'a DnsQuery,
        session: &'a GatewaySession,
        gateway: &'a dyn GatewayConnector,
    ) -> BoxFuture<'a, OnionResult<DnsResponse>>;

    /// Clears cached answers during identity rotation or policy change.
    fn flush_cache(&self) -> BoxFuture<'_, OnionResult<()>>;
}

/// Evaluates local flow, DNS, split-tunnel, and route-selection policy.
pub trait PolicyEngine: Send + Sync + VersionedContract {
    /// Decides whether a TCP request is tunneled, explicitly bypassed, or blocked.
    fn evaluate_tcp<'a>(
        &'a self,
        request: &'a TcpFlowRequest,
    ) -> BoxFuture<'a, OnionResult<PolicyDecision>>;

    /// Decides whether a DNS request is protected or blocked. DNS bypass is never
    /// valid while the OnionRoute tunnel is active.
    fn evaluate_dns<'a>(
        &'a self,
        context: &'a DnsPolicyContext,
    ) -> BoxFuture<'a, OnionResult<PolicyDecision>>;

    /// Selects an ordered, role-correct plan from a verified signed directory.
    fn select_gateway_plan<'a>(
        &'a self,
        directory: &'a VerifiedGatewayDirectory,
        constraints: &'a RouteConstraints,
    ) -> BoxFuture<'a, OnionResult<GatewayPlan>>;
}

/// Installs and verifies fail-closed platform traffic controls.
pub trait KillSwitch: Send + Sync + VersionedContract {
    /// Atomically installs the requested blocking policy before Tor bootstrap.
    fn engage<'a>(
        &'a self,
        policy: &'a KillSwitchPolicy,
    ) -> BoxFuture<'a, OnionResult<KillSwitchLease>>;

    /// Independently verifies effective rules for a lease.
    fn verify<'a>(
        &'a self,
        lease: &'a KillSwitchLease,
    ) -> BoxFuture<'a, OnionResult<KillSwitchStatus>>;

    /// Forces the strongest available local block after an uncertain failure.
    fn emergency_block(&self) -> BoxFuture<'_, OnionResult<KillSwitchLease>>;

    /// Removes rules only after packet, gateway, and Tor shutdown completes.
    fn disengage<'a>(
        &'a self,
        lease: &'a KillSwitchLease,
    ) -> BoxFuture<'a, OnionResult<()>>;

    /// Inspects and safely recovers rules left by a previous process crash.
    fn recover(&self) -> BoxFuture<'_, OnionResult<KillSwitchStatus>>;
}

/// Minimal secret-storage boundary implemented with platform secure storage.
pub trait SecureStorage: Send + Sync + VersionedContract {
    /// Loads one bounded secret, returning `None` when it has never been stored.
    fn load(&self, key: StorageKey) -> BoxFuture<'_, OnionResult<Option<SecretValue>>>;

    /// Atomically replaces one bounded secret.
    fn store(
        &self,
        key: StorageKey,
        value: SecretValue,
    ) -> BoxFuture<'_, OnionResult<()>>;

    /// Deletes one secret and its recoverable temporary versions.
    fn delete(&self, key: StorageKey) -> BoxFuture<'_, OnionResult<()>>;
}

/// Fetches, verifies, caches, and rollback-protects the public gateway directory.
pub trait GatewayDirectoryProvider: Send + Sync + VersionedContract {
    /// Loads the last verified unexpired cached directory.
    fn load_cached(&self) -> BoxFuture<'_, OnionResult<Option<VerifiedGatewayDirectory>>>;

    /// Fetches a signed directory through the protected control-plane path and
    /// returns it only after signature, bounds, validity, and rollback checks.
    fn refresh(
        &self,
        reason: DirectoryRefreshReason,
    ) -> BoxFuture<'_, OnionResult<VerifiedGatewayDirectory>>;

    /// Verifies externally supplied bytes, primarily for contract tests and
    /// offline recovery. Production callers normally use `refresh`.
    fn verify<'a>(
        &'a self,
        envelope: &'a SignedDirectoryEnvelope,
    ) -> BoxFuture<'a, OnionResult<VerifiedGatewayDirectory>>;
}

/// Obtains unlinkable, short-lived gateway capabilities from the control plane.
pub trait TokenProvider: Send + Sync + VersionedContract {
    /// Acquires an unblinded token. Account authentication, when required, stays
    /// inside the provider and is never returned in the token object.
    fn acquire<'a>(
        &'a self,
        request: &'a TokenRequest,
    ) -> BoxFuture<'a, OnionResult<CapabilityToken>>;

    /// Discards cached tokens after rejection, rotation, logout, or expiry.
    fn invalidate(&self) -> BoxFuture<'_, OnionResult<()>>;
}

/// Collects only allow-listed, coarse, user-controlled health signals.
pub trait HealthReporter: Send + Sync + VersionedContract {
    /// Records one closed-schema health event locally.
    fn record(&self, event: HealthEvent) -> BoxFuture<'_, OnionResult<()>>;

    /// Flushes a bounded aggregate batch through the control plane.
    fn flush(&self) -> BoxFuture<'_, OnionResult<()>>;

    /// Purges queued health data, for example when telemetry is disabled.
    fn purge(&self) -> BoxFuture<'_, OnionResult<()>>;
}
