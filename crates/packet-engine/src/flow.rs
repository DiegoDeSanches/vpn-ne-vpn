//! Flow metadata, lifecycle state, and bounded buffer accounting.

use std::net::Ipv4Addr;

use onionroute_common_types::types::{
    AnonymityMode, ApplicationTag, FlowId, GatewayId, IsolationKey,
};

use crate::packet::TcpFlags;

/// IPv4 transport endpoint retained only in process-local flow state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TransportEndpoint {
    /// Endpoint address.
    pub address: Ipv4Addr,
    /// Endpoint port.
    pub port: u16,
}

/// Monotonic local timestamps. They are never part of remote telemetry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowTimestamps {
    /// Flow creation time in caller-provided monotonic milliseconds.
    pub created_ms: u64,
    /// Last accepted packet or protected-stream activity.
    pub last_activity_ms: u64,
    /// Time at which a protected open started, when applicable.
    pub connect_started_ms: Option<u64>,
}

/// Per-flow queue limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferLimits {
    /// Maximum bytes waiting for the protected stream.
    pub to_gateway_bytes: usize,
    /// Maximum protected bytes accepted for one local packet emission.
    pub to_application_bytes: usize,
}

/// Local TCP lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpFlowState {
    /// SYN accepted while the protected stream is being opened.
    Connecting,
    /// SYN-ACK emitted and final ACK is expected.
    SynAckSent,
    /// Both directions are open.
    Established,
    /// Application sent FIN; protected response reads remain valid.
    HalfClosedLocal,
    /// Protected peer closed; application acknowledgement/FIN remains.
    HalfClosedRemote,
    /// Both halves are closing.
    Closing,
    /// Flow was reset.
    Reset,
    /// Flow completed normally.
    Closed,
}

/// Redacted snapshot suitable for local diagnostics and tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowSnapshot {
    /// Process-local flow identifier.
    pub flow_id: FlowId,
    /// Local source endpoint.
    pub source: TransportEndpoint,
    /// Requested destination endpoint; a synthetic address may be present.
    pub destination: TransportEndpoint,
    /// Hostname recovered from synthetic DNS, when known.
    pub hostname: Option<String>,
    /// Local application identifier, when the platform supplied one.
    pub application: Option<ApplicationTag>,
    /// Per-route isolation value.
    pub isolation_key: IsolationKey,
    /// User-selected anonymity mode.
    pub anonymity_profile: AnonymityMode,
    /// Selected terminal gateway catalog identifier.
    pub gateway_id: Option<GatewayId>,
    /// Local monotonic lifecycle timestamps.
    pub timestamps: FlowTimestamps,
    /// Current TCP state.
    pub state: TcpFlowState,
    /// Configured per-flow limits.
    pub limits: BufferLimits,
    /// Bytes currently charged to the protected-stream queue.
    pub queued_to_gateway: usize,
    /// Bytes currently charged to local packet emission.
    pub queued_to_application: usize,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct FlowKey {
    pub source: TransportEndpoint,
    pub destination: TransportEndpoint,
}

pub(crate) struct FlowRecord {
    pub snapshot: FlowSnapshot,
    pub key: FlowKey,
    pub client_next: u32,
    pub server_next: u32,
    pub dns_tcp: bool,
    pub dns_buffer: Vec<u8>,
    pub outstanding_to_application: Option<OutstandingSegment>,
}

pub(crate) struct OutstandingSegment {
    pub sequence: u32,
    pub acknowledgement: u32,
    pub flags: TcpFlags,
    pub payload: Vec<u8>,
    pub sent_ms: u64,
    pub retransmissions: u8,
}
