#![forbid(unsafe_code)]
//! Bounded packet classification and local TCP proxy state for OnionRoute.
//!
//! This crate has no socket API. It turns validated TUN packets and protected
//! stream callbacks into explicit [`EngineAction`] values for client-core.

mod action;
mod engine;
mod flow;
mod metrics;
mod packet;

pub use action::{
    BlockReason, CloseDirection, DiagnosticCode, DnsResponseTarget, EngineAction,
    PacketEngineInput, PlatformMetadata, ProtectedRoute,
};
pub use engine::{EngineConfig, PacketProcessor};
pub use flow::{BufferLimits, FlowSnapshot, FlowTimestamps, TcpFlowState, TransportEndpoint};
pub use metrics::{MetricEvent, MetricsSink, NoopMetrics};
pub use packet::{
    build_tcp_packet, build_udp_packet, classify, ClassifiedPacket, IcmpPacket, IpProtocolClass,
    PacketError, TcpFlags, TcpSegment, UdpDatagram,
};
