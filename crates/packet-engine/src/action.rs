//! Public input and output boundary of the synchronous packet processor.

use std::net::Ipv4Addr;

use onionroute_common_types::state::ClientConnectionState;
use onionroute_common_types::types::{
    AnonymityMode, ApplicationTag, DnsQuery, FlowId, GatewayId, IsolationKey, PolicyDecision,
    TcpFlowRequest,
};

use crate::flow::TransportEndpoint;

/// Per-packet metadata supplied by the platform adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformMetadata {
    /// Opaque local application tag, when supported by the platform.
    pub application: Option<ApplicationTag>,
    /// Caller-provided monotonic time in milliseconds.
    pub monotonic_ms: u64,
}

/// Protected routing context selected outside the packet parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedRoute {
    /// Auditable local policy decision.
    pub decision: PolicyDecision,
    /// Hostname recovered from the synthetic DNS map.
    pub hostname: Option<String>,
    /// Per-route isolation key.
    pub isolation_key: IsolationKey,
    /// Selected anonymity profile.
    pub anonymity_profile: AnonymityMode,
    /// Selected terminal gateway, absent only for explicitly unsupported modes.
    pub gateway_id: Option<GatewayId>,
}

/// Complete input for processing one TUN packet.
pub struct PacketEngineInput<'a> {
    /// Complete IP packet.
    pub packet: &'a [u8],
    /// Platform-local metadata.
    pub platform: PlatformMetadata,
    /// Routing decision and protected route metadata, required for new TCP flows.
    pub route: Option<ProtectedRoute>,
    /// Current orchestrator connection state.
    pub connection_state: ClientConnectionState,
}

/// Stable local block reasons.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockReason {
    /// Packet failed checked parsing.
    MalformedPacket,
    /// IPv6 is not fully routed by this MVP.
    Ipv6Blocked,
    /// Arbitrary UDP is unsupported.
    UdpBlocked,
    /// UDP/443 QUIC is explicitly blocked.
    QuicBlocked,
    /// ICMP is not proxied by the protected stream protocol.
    IcmpUnsupported,
    /// Unknown IP transport is unsupported.
    UnsupportedTransport,
    /// Policy denied the flow.
    PolicyDenied,
    /// A bypass decision reached the TUN core and was rejected.
    DirectFallbackForbidden,
    /// No healthy protected connection is available.
    ProtectedPathUnavailable,
    /// Flow or queue capacity was exhausted.
    Backpressure,
    /// Connect deadline elapsed.
    ConnectionTimeout,
    /// Idle deadline elapsed.
    IdleTimeout,
    /// Engine cancellation or shutdown closed the flow.
    Shutdown,
    /// Protected stream failed or reset.
    DownstreamFailure,
}

/// Non-sensitive local diagnostic event identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticCode {
    /// Malformed packet was discarded.
    MalformedPacket,
    /// Duplicate SYN or already-consumed payload was acknowledged again.
    Retransmission,
    /// Out-of-order payload was not buffered.
    OutOfOrder,
    /// Flow table limit was reached.
    FlowLimit,
    /// Per-flow buffer limit was reached.
    BufferLimit,
    /// Packet referenced no known flow.
    UnknownFlow,
    /// Sleep/resume invalidated protected flows.
    ResumePathInvalid,
    /// Engine entered shutdown.
    Shutdown,
}

/// Which side of a protected stream should close.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseDirection {
    /// Stop protected writes but continue response reads.
    Write,
    /// Close both directions immediately or after both FINs.
    Both,
}

/// Where a protected DNS response must be synthesized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsResponseTarget {
    /// Response to a UDP DNS query.
    Udp {
        /// Original client endpoint.
        client: TransportEndpoint,
        /// Intercepted resolver endpoint.
        resolver: TransportEndpoint,
    },
    /// Response framed onto a locally terminated TCP/53 flow.
    Tcp {
        /// DNS TCP flow identifier.
        flow_id: FlowId,
    },
}

/// Explicit action emitted by the packet processor.
#[derive(Debug)]
pub enum EngineAction {
    /// Open an ordered stream only through the protected dispatcher.
    OpenProtectedStream {
        /// Public gateway request.
        request: TcpFlowRequest,
        /// Isolation key retained for route validation.
        isolation_key: IsolationKey,
        /// Requested anonymity mode.
        anonymity_profile: AnonymityMode,
        /// Selected gateway identifier.
        gateway_id: Option<GatewayId>,
    },
    /// Send payload to an already-open protected stream.
    ForwardPayload {
        /// Flow identifier.
        flow_id: FlowId,
        /// Owned bounded payload.
        payload: Vec<u8>,
    },
    /// Perform one protected DNS exchange or local synthetic resolution.
    ResolveDns {
        /// Bounded DNS query.
        query: DnsQuery,
        /// Local response target.
        target: DnsResponseTarget,
    },
    /// Close a protected stream direction.
    CloseProtectedStream {
        /// Flow identifier.
        flow_id: FlowId,
        /// Requested close direction.
        direction: CloseDirection,
    },
    /// Inject a synthetic packet back into the local TUN.
    SendSyntheticResponse {
        /// Complete bounded IP packet.
        packet: Vec<u8>,
    },
    /// Reject a flow without network access.
    BlockFlow {
        /// Flow ID when one was allocated.
        flow_id: Option<FlowId>,
        /// Stable rejection reason.
        reason: BlockReason,
    },
    /// Record a local-only, closed-schema diagnostic.
    RecordDiagnostic {
        /// Diagnostic identifier.
        code: DiagnosticCode,
        /// Related flow ID when known.
        flow_id: Option<FlowId>,
    },
}

pub(crate) fn endpoints(
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
) -> (TransportEndpoint, TransportEndpoint) {
    (
        TransportEndpoint {
            address: source,
            port: source_port,
        },
        TransportEndpoint {
            address: destination,
            port: destination_port,
        },
    )
}
