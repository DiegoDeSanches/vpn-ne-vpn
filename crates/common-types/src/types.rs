//! Shared value types for the versioned component contracts.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use crate::error::ErrorCode;
use crate::transport::BoxTransport;

/// Maximum accepted capability-token size.
pub const MAX_TOKEN_BYTES: usize = 4 * 1024;
/// Maximum encoded DNS message size.
pub const MAX_DNS_MESSAGE_BYTES: usize = 64 * 1024;
/// Maximum packet supplied to the packet engine, including headroom.
pub const MAX_PACKET_BYTES: usize = 128 * 1024;
/// Maximum number of gateways in a verified directory.
pub const MAX_DIRECTORY_GATEWAYS: usize = 4_096;
/// Maximum private gateways in one route.
pub const MAX_GATEWAY_HOPS: usize = 3;
/// Maximum value accepted by the secure-storage contract.
pub const MAX_SECRET_VALUE_BYTES: usize = 256 * 1024;

/// Wire-protocol version.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct ProtocolVersion {
    /// Breaking wire generation.
    pub major: u16,
    /// Additive wire revision.
    pub minor: u16,
}

impl ProtocolVersion {
    /// Creates a protocol version.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

/// Inclusive wire-version range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolVersionRange {
    /// Oldest version accepted by the peer.
    pub minimum: ProtocolVersion,
    /// Newest version accepted by the peer.
    pub maximum: ProtocolVersion,
}

impl ProtocolVersionRange {
    /// Returns the highest mutually supported version.
    pub fn negotiate(self, other: Self) -> Option<ProtocolVersion> {
        if self.minimum.major != self.maximum.major
            || other.minimum.major != other.maximum.major
            || self.minimum.major != other.minimum.major
        {
            return None;
        }
        let minimum_minor = self.minimum.minor.max(other.minimum.minor);
        let maximum_minor = self.maximum.minor.min(other.maximum.minor);
        (minimum_minor <= maximum_minor)
            .then_some(ProtocolVersion::new(self.minimum.major, maximum_minor))
    }
}

/// User-selected privacy route.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AnonymityMode {
    /// Tor to a private exit gateway.
    Standard,
    /// Tor to entry gateway, then an encrypted path to an exit gateway.
    Enhanced,
    /// Tor to entry gateway, relay gateway, and exit gateway.
    Maximum,
    /// Tor to a public Tor exit without a private gateway.
    DirectTor,
}

/// Stable catalog identifier that is not tied to a user or account.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct GatewayId(
    /// Bounded opaque catalog value.
    pub String,
);

impl fmt::Debug for GatewayId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatewayId([REDACTED])")
    }
}

/// ISO 3166-1 alpha-2 exit-country selector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CountryCode(
    /// Uppercase ASCII country code.
    pub [u8; 2],
);

/// Tor v3 onion service endpoint.
#[derive(Clone, Eq, PartialEq)]
pub struct OnionEndpoint {
    /// Fifty-six character v3 service identifier without `.onion`.
    pub service_id: String,
    /// Onion-service virtual port.
    pub port: u16,
}

impl fmt::Debug for OnionEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OnionEndpoint([REDACTED])")
    }
}

/// Gateway role in a private multihop route.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GatewayRole {
    /// First gateway contacted through Tor.
    Entry,
    /// Middle gateway that relays opaque end-to-end traffic.
    Relay,
    /// Terminal private gateway that opens Internet flows.
    Exit,
}

/// One hop selected from a verified directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayHop {
    /// Public catalog identifier.
    pub gateway_id: GatewayId,
    /// Role of this hop.
    pub role: GatewayRole,
    /// Onion endpoint used when this is the first hop.
    pub onion_endpoint: OnionEndpoint,
    /// Pinned SHA-256 hash of the gateway TLS SPKI.
    pub tls_spki_sha256: [u8; 32],
}

/// Ordered gateway route selected by client policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayPlan {
    /// Requested privacy mode.
    pub mode: AnonymityMode,
    /// Ordered entry-to-exit hop list; empty only for Direct Tor.
    pub hops: Vec<GatewayHop>,
}

/// Constraints used for gateway selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteConstraints {
    /// Desired route mode.
    pub mode: AnonymityMode,
    /// Optional exit-country requirement.
    pub exit_country: Option<CountryCode>,
    /// Required gateway feature names from the versioned registry.
    pub required_features: Vec<String>,
}

/// Per-route random isolation value with no stable device identity.
#[derive(Clone, Eq, PartialEq)]
pub struct IsolationKey(
    /// Secret random bytes scoped to one route.
    pub [u8; 32],
);

impl fmt::Debug for IsolationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IsolationKey([REDACTED])")
    }
}

/// Ephemeral local Tor route identifier.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct RouteId(
    /// Random local identifier bytes.
    pub [u8; 16],
);

impl fmt::Debug for RouteId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RouteId([REDACTED])")
    }
}

/// Prepared Tor and gateway route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteLease {
    /// Local ephemeral identifier.
    pub route_id: RouteId,
    /// Selected gateways.
    pub plan: GatewayPlan,
    /// Tor isolation key.
    pub isolation_key: IsolationKey,
    /// Absolute Unix expiry time.
    pub expires_at_unix: i64,
}

/// Why a circuit or gateway route is being replaced.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RotationReason {
    /// Explicit New Identity request.
    UserRequested,
    /// Configured maximum age reached.
    Scheduled,
    /// Health degradation crossed the threshold.
    HealthDegraded,
    /// Gateway directory invalidated the old route.
    DirectoryChanged,
    /// Token or session expiry requires replacement.
    SessionExpiring,
}

/// Tor bootstrap parameters independent of C Tor and Arti.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TorBootstrapConfig {
    /// Upper bound for bootstrap.
    pub timeout: Duration,
    /// Whether configured bridges are mandatory.
    pub bridges_required: bool,
}

/// Coarse Tor status safe for UI and health logic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TorStatus {
    /// Bootstrap completion from zero through one hundred.
    pub bootstrap_percent: u8,
    /// Whether new isolated streams may be opened.
    pub ready: bool,
}

/// Ephemeral gateway session identifier.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SessionId(
    /// Random per-handshake bytes.
    pub [u8; 16],
);

impl fmt::Debug for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionId([REDACTED])")
    }
}

/// Gateway-session lifecycle state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GatewaySessionState {
    /// Transport exists but no hello was exchanged.
    Negotiating,
    /// Protocol is selected and token proof is in progress.
    Authenticating,
    /// New TCP and DNS operations are accepted.
    Active,
    /// No new operations; existing flows may finish.
    Draining,
    /// Close handshake is in progress.
    Closing,
    /// Session ended normally.
    Closed,
    /// Token or maximum lifetime elapsed.
    Expired,
    /// Session ended due to a protocol or transport error.
    Failed,
}

/// Established anonymous gateway session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewaySession {
    /// Random session identifier assigned during handshake.
    pub session_id: SessionId,
    /// Gateway identity matched to the signed route plan and TLS pin.
    pub gateway_id: GatewayId,
    /// Role enforced for this nested session.
    pub role: GatewayRole,
    /// Negotiated gateway protocol.
    pub protocol_version: ProtocolVersion,
    /// Current lifecycle state.
    pub state: GatewaySessionState,
    /// Hard Unix expiry time.
    pub expires_at_unix: i64,
    /// Maximum simultaneous flows advertised by the gateway.
    pub max_concurrent_streams: u32,
}

/// Inputs to an anonymous gateway handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayDialRequest {
    /// Full route used to build nested protected transports.
    pub plan: GatewayPlan,
    /// Supported gateway protocol range.
    pub supported_versions: ProtocolVersionRange,
    /// Explicit optional feature names.
    pub requested_features: Vec<String>,
}

/// Short-lived anonymous capability token.
#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityToken(Vec<u8>);

impl CapabilityToken {
    /// Creates a bounded non-empty token.
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        (!bytes.is_empty() && bytes.len() <= MAX_TOKEN_BYTES).then_some(Self(bytes))
    }

    /// Borrows token bytes for one gateway authentication exchange.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// Independently issued credentials ordered exactly like a private gateway plan.
///
/// Standard has one credential, Enhanced two, Maximum three, and Direct Tor none.
/// A token is never reused between hops.
#[derive(Clone, Eq, PartialEq)]
pub struct GatewayCredentials {
    per_hop: Vec<CapabilityToken>,
}

impl GatewayCredentials {
    /// Creates a non-empty bounded credential set.
    pub fn new(per_hop: Vec<CapabilityToken>) -> Option<Self> {
        (!per_hop.is_empty() && per_hop.len() <= MAX_GATEWAY_HOPS)
            .then_some(Self { per_hop })
    }

    /// Returns the number of independently authorized private hops.
    pub fn len(&self) -> usize {
        self.per_hop.len()
    }

    /// Returns true when no hop credential exists.
    pub fn is_empty(&self) -> bool {
        self.per_hop.is_empty()
    }

    /// Consumes the wrapper and returns tokens in gateway-plan order.
    pub fn into_per_hop(self) -> Vec<CapabilityToken> {
        self.per_hop
    }
}

impl fmt::Debug for GatewayCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayCredentials")
            .field("per_hop_count", &self.len())
            .finish()
    }
}

impl fmt::Debug for CapabilityToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CapabilityToken")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// Capability-token request. Account identity remains private to its provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenRequest {
    /// Coarse capability names from a versioned registry.
    pub capabilities: Vec<String>,
    /// Desired route mode.
    pub mode: AnonymityMode,
    /// Minimum token validity required by the session.
    pub minimum_validity: Duration,
}

/// Local packet-engine flow identifier.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FlowId(
    /// Process-local monotonically allocated value.
    pub u64,
);

impl fmt::Debug for FlowId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FlowId([REDACTED])")
    }
}

/// TCP destination visible only to the terminal exit data-plane handler.
#[derive(Clone, Eq, PartialEq)]
pub enum TcpHost {
    /// IDNA ASCII hostname, bounded to 253 bytes.
    Hostname(
        /// Validated hostname value.
        String,
    ),
    /// IPv4 or IPv6 literal.
    Ip(
        /// Parsed address value.
        IpAddr,
    ),
}

impl fmt::Debug for TcpHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TcpHost([REDACTED])")
    }
}

/// Requested TCP flow.
#[derive(Clone, Eq, PartialEq)]
pub struct TcpFlowRequest {
    /// Local flow identifier.
    pub flow_id: FlowId,
    /// Destination host.
    pub host: TcpHost,
    /// Destination TCP port.
    pub port: u16,
    /// Optional local application tag used only for split-tunnel policy.
    pub application: Option<ApplicationTag>,
}

impl fmt::Debug for TcpFlowRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TcpFlowRequest([REDACTED])")
    }
}

/// Local opaque application identifier used for split tunneling.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ApplicationTag(
    /// Platform adapter supplied value, never sent to the data plane.
    pub String,
);

impl fmt::Debug for ApplicationTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApplicationTag([REDACTED])")
    }
}

/// Raw DNS query assigned a local identifier.
#[derive(Clone, Eq, PartialEq)]
pub struct DnsQuery {
    /// Local query identifier.
    pub query_id: u64,
    /// RFC-compatible DNS wire message.
    pub wire: Vec<u8>,
}

impl fmt::Debug for DnsQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DnsQuery([REDACTED])")
    }
}

/// Raw protected DNS response.
#[derive(Clone, Eq, PartialEq)]
pub struct DnsResponse {
    /// Query identifier copied from the request.
    pub query_id: u64,
    /// RFC-compatible DNS wire message.
    pub wire: Vec<u8>,
}

impl fmt::Debug for DnsResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DnsResponse([REDACTED])")
    }
}

/// Event emitted by a running packet engine.
#[derive(Debug)]
pub enum PacketEvent {
    /// A TCP flow needs policy evaluation and a protected stream.
    OpenTcp(
        /// Pending local flow.
        TcpFlowRequest,
    ),
    /// A DNS packet needs protected resolution.
    ResolveDns(
        /// Pending protected query.
        DnsQuery,
    ),
    /// UDP, QUIC, or another unsupported transport was intercepted.
    Unsupported {
        /// Local flow identifier.
        flow_id: FlowId,
        /// Stable rejection code.
        reason: ErrorCode,
    },
    /// Platform packet tunnel ended.
    TunnelClosed,
}

/// Packet-engine startup configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketEngineConfig {
    /// Maximum concurrently tracked TCP flows.
    pub max_flows: usize,
    /// Per-flow buffered byte limit.
    pub per_flow_buffer_bytes: usize,
    /// Whether all IPv6 must be rejected for the current platform policy.
    pub block_ipv6: bool,
    /// Whether QUIC detection and rejection is mandatory.
    pub block_quic: bool,
}

/// Current packet-engine status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketEngineStatus {
    /// Whether a packet tunnel is attached.
    pub running: bool,
    /// Number of live flow entries.
    pub active_flows: usize,
    /// Number of events waiting for the orchestrator.
    pub queued_events: usize,
}

/// Local policy action for one flow.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PolicyAction {
    /// Send through the protected OnionRoute path.
    Tunnel,
    /// Permit direct traffic only when an explicit split-tunnel policy allows it.
    Bypass,
    /// Reject without network access.
    Block,
}

/// Auditable policy result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    /// Selected action.
    pub action: PolicyAction,
    /// Stable policy-rule identifier, never a destination or user value.
    pub rule_id: String,
}

/// DNS policy input without exposing it to health reporting.
#[derive(Clone, Eq, PartialEq)]
pub struct DnsPolicyContext {
    /// Optional local application tag.
    pub application: Option<ApplicationTag>,
    /// DNS record type parsed from the query.
    pub record_type: u16,
}

impl fmt::Debug for DnsPolicyContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DnsPolicyContext([REDACTED])")
    }
}

/// Kill-switch rules requested by the orchestrator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KillSwitchPolicy {
    /// Allows only the platform adapter's authenticated Tor transport. The adapter,
    /// not this shared contract, resolves that transport to OS-specific identities.
    pub allow_tor_transport: bool,
    /// Whether IPv6 must be blocked rather than routed.
    pub block_ipv6: bool,
    /// Whether UDP must be blocked except packet-tunnel internals.
    pub block_udp: bool,
    /// Whether system DNS is forbidden.
    pub block_system_dns: bool,
}

/// Opaque lease proving which kill-switch generation is installed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KillSwitchLease {
    /// Monotonically increasing local generation.
    pub generation: u64,
}

/// Result of an independent kill-switch verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KillSwitchStatus {
    /// Whether fail-closed rules are installed.
    pub engaged: bool,
    /// Whether rules match the requested generation and policy.
    pub verified: bool,
    /// Installed generation when known.
    pub generation: Option<u64>,
}

/// Logical secure-storage key with no caller-defined namespace.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StorageKey {
    /// Trusted directory signing roots and rotations.
    DirectoryKeyring,
    /// Highest verified directory sequence for rollback prevention.
    DirectorySequence,
    /// Token-protocol client secret material.
    TokenSecret,
    /// Signed local configuration.
    ClientConfiguration,
}

/// Secret bytes that redact debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    /// Creates a bounded secret value owned by secure storage.
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        (bytes.len() <= MAX_SECRET_VALUE_BYTES).then_some(Self(bytes))
    }

    /// Exposes bytes only to the component that owns the corresponding key.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

/// Public directory gateway descriptor after signature and bounds validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayDescriptor {
    /// Catalog identifier.
    pub gateway_id: GatewayId,
    /// ISO country code.
    pub country: CountryCode,
    /// Allowed roles.
    pub roles: Vec<GatewayRole>,
    /// Onion-service endpoint.
    pub endpoint: OnionEndpoint,
    /// Pinned application TLS SPKI hash.
    pub tls_spki_sha256: [u8; 32],
    /// Supported gateway protocol versions.
    pub protocols: Vec<ProtocolVersion>,
    /// Coarse feature names.
    pub capabilities: Vec<String>,
}

/// Signed directory bytes as received from the control plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedDirectoryEnvelope {
    /// Envelope format generation.
    pub envelope_version: u16,
    /// Trusted signing key selector.
    pub signing_key_id: String,
    /// Exact serialized payload covered by the signature.
    pub payload: Vec<u8>,
    /// Standard signature algorithm declared by the envelope.
    pub signature_algorithm: DirectorySignatureAlgorithm,
    /// Signature bytes.
    pub signature: Vec<u8>,
}

/// Supported signed-directory signature algorithms.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DirectorySignatureAlgorithm {
    /// Ed25519 over the domain separator and exact payload bytes.
    Ed25519,
}

/// Directory accepted after signature, validity, rollback, and bounds checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedGatewayDirectory {
    /// Decoded payload format version.
    pub format_version: ProtocolVersion,
    /// Monotonic publisher sequence.
    pub sequence: u64,
    /// Issuance time.
    pub issued_at_unix: i64,
    /// Hard expiry time.
    pub valid_until_unix: i64,
    /// Bounded list of usable gateways.
    pub gateways: Vec<GatewayDescriptor>,
    /// Signing key that verified the envelope.
    pub verified_by_key_id: String,
}

/// Reason for loading a new signed directory.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DirectoryRefreshReason {
    /// No cached directory is available.
    Initial,
    /// Cached validity is approaching expiry.
    Scheduled,
    /// Gateway selection produced no viable route.
    NoGateway,
    /// A protocol response requested a newer sequence.
    ServerHint,
    /// Explicit operator diagnostic action.
    UserRequested,
}

/// Closed health-event registry; arbitrary labels and values are not accepted.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HealthMetric {
    /// Successful protected connection.
    ConnectSuccess,
    /// Failed protected connection.
    ConnectFailure,
    /// Successful route rotation.
    RotationSuccess,
    /// Deferred or failed route rotation.
    RotationFailure,
    /// Bucketed Tor bootstrap duration.
    TorBootstrapDurationBucket,
    /// Bucketed gateway round-trip time.
    GatewayRttBucket,
    /// Failure to apply or verify the kill switch.
    KillSwitchFailure,
}

/// Coarse health event without destination, identity, or per-flow fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HealthEvent {
    /// Allow-listed metric.
    pub metric: HealthMetric,
    /// Bucket or count defined by the metric registry.
    pub value: u64,
}

/// Result of preparing a replacement route before retiring the old route.
pub struct RotationCandidate {
    /// Newly prepared route.
    pub route: RouteLease,
    /// Protected first-hop transport for gateway negotiation.
    pub transport: BoxTransport,
}

impl fmt::Debug for RotationCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RotationCandidate")
            .field("route", &self.route)
            .field("transport", &"BoxTransport(..)")
            .finish()
    }
}
