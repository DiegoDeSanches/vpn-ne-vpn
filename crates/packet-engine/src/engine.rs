//! Bounded synchronous packet-to-action state machine.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use onionroute_common_types::error::ErrorCode;
use onionroute_common_types::state::ClientConnectionState;
use onionroute_common_types::types::{
    AnonymityMode, DnsQuery, FlowId, IsolationKey, PolicyAction, TcpFlowRequest, TcpHost,
    MAX_DNS_MESSAGE_BYTES,
};

use crate::action::{
    endpoints, BlockReason, CloseDirection, DiagnosticCode, DnsResponseTarget, EngineAction,
    PacketEngineInput,
};
use crate::flow::{
    BufferLimits, FlowKey, FlowRecord, FlowSnapshot, FlowTimestamps, OutstandingSegment,
    TcpFlowState,
};
use crate::metrics::{MetricEvent, MetricsSink};
use crate::packet::{
    build_tcp_packet, build_udp_packet, classify, ClassifiedPacket, TcpFlags, TcpSegment,
    UdpDatagram,
};

/// Resource and timeout limits for [`PacketProcessor`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EngineConfig {
    /// Maximum concurrent TCP entries.
    pub max_flows: usize,
    /// Maximum unresolved DNS operations.
    pub max_pending_dns: usize,
    /// Per-flow queue limits.
    pub buffers: BufferLimits,
    /// Protected connect deadline.
    pub connection_timeout_ms: u64,
    /// Established-flow idle deadline.
    pub idle_timeout_ms: u64,
    /// Delay before retransmitting unacknowledged protected-stream data locally.
    pub retransmit_interval_ms: u64,
    /// Maximum local retransmissions before the flow is reset.
    pub max_retransmissions: u8,
    /// Fixed local receive window, never larger than the ingress buffer limit.
    pub receive_window: u16,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_flows: 4_096,
            max_pending_dns: 256,
            buffers: BufferLimits {
                to_gateway_bytes: 256 * 1024,
                to_application_bytes: 60 * 1024,
            },
            connection_timeout_ms: 30_000,
            idle_timeout_ms: 300_000,
            retransmit_interval_ms: 1_000,
            max_retransmissions: 5,
            receive_window: 32 * 1024,
        }
    }
}

impl EngineConfig {
    fn valid(self) -> bool {
        self.max_flows > 0
            && self.max_pending_dns > 0
            && self.buffers.to_gateway_bytes > 0
            && self.buffers.to_application_bytes > 0
            && self.connection_timeout_ms > 0
            && self.idle_timeout_ms > 0
            && self.retransmit_interval_ms > 0
            && self.max_retransmissions > 0
            && self.receive_window > 0
            && usize::from(self.receive_window) <= self.buffers.to_gateway_bytes
            && self.buffers.to_application_bytes <= usize::from(u16::MAX)
    }
}

/// Packet classifier, TCP flow table, DNS interception table, and timeout coordinator.
pub struct PacketProcessor {
    config: EngineConfig,
    metrics: Arc<dyn MetricsSink>,
    flows: HashMap<FlowKey, FlowRecord>,
    ids: HashMap<FlowId, FlowKey>,
    pending_dns: HashMap<u64, DnsResponseTarget>,
    next_flow_id: u64,
    next_dns_id: u64,
    accepting: bool,
    suspended_at_ms: Option<u64>,
}

impl PacketProcessor {
    /// Creates an engine only when all resource limits are finite and consistent.
    pub fn new(config: EngineConfig, metrics: Arc<dyn MetricsSink>) -> Option<Self> {
        config.valid().then(|| Self {
            config,
            metrics,
            flows: HashMap::with_capacity(config.max_flows.min(1_024)),
            ids: HashMap::with_capacity(config.max_flows.min(1_024)),
            pending_dns: HashMap::with_capacity(config.max_pending_dns.min(256)),
            next_flow_id: 1,
            next_dns_id: 1,
            accepting: true,
            suspended_at_ms: None,
        })
    }

    /// Returns the configured hard limits.
    pub const fn config(&self) -> EngineConfig {
        self.config
    }

    /// Returns the number of live TCP flows.
    pub fn active_flows(&self) -> usize {
        self.flows.len()
    }

    /// Returns the number of unresolved DNS operations.
    pub fn pending_dns(&self) -> usize {
        self.pending_dns.len()
    }

    /// Returns process-local identifiers of all live flows.
    pub fn flow_ids(&self) -> Vec<FlowId> {
        self.ids.keys().copied().collect()
    }

    /// Returns a local flow snapshot without exposing traffic payload.
    pub fn flow(&self, flow_id: FlowId) -> Option<FlowSnapshot> {
        let key = self.ids.get(&flow_id)?;
        self.flows.get(key).map(|flow| flow.snapshot.clone())
    }

    /// Classifies and processes one complete IP packet.
    pub fn process(&mut self, input: PacketEngineInput<'_>) -> Vec<EngineAction> {
        let classified = match classify(input.packet) {
            Ok(packet) => packet,
            Err(_) => {
                self.metrics
                    .record(MetricEvent::FlowBlocked(BlockReason::MalformedPacket), None);
                return vec![
                    EngineAction::BlockFlow {
                        flow_id: None,
                        reason: BlockReason::MalformedPacket,
                    },
                    EngineAction::RecordDiagnostic {
                        code: DiagnosticCode::MalformedPacket,
                        flow_id: None,
                    },
                ];
            }
        };

        match classified {
            ClassifiedPacket::Ipv6 => self.block(None, BlockReason::Ipv6Blocked),
            ClassifiedPacket::Udp(datagram) => self.process_udp(datagram, input.connection_state),
            ClassifiedPacket::Tcp(segment) => self.process_tcp(segment, input),
            ClassifiedPacket::Icmp(_) => self.block(None, BlockReason::IcmpUnsupported),
            ClassifiedPacket::Other(_) => self.block(None, BlockReason::UnsupportedTransport),
        }
    }

    fn process_udp(
        &mut self,
        datagram: UdpDatagram<'_>,
        connection_state: ClientConnectionState,
    ) -> Vec<EngineAction> {
        if datagram.destination_port == 53 {
            if !self.accepting {
                return self.block(None, BlockReason::Shutdown);
            }
            if !protected_state(connection_state) {
                return self.block(None, BlockReason::ProtectedPathUnavailable);
            }
            if datagram.payload.is_empty()
                || datagram.payload.len() > MAX_DNS_MESSAGE_BYTES
                || self.pending_dns.len() >= self.config.max_pending_dns
            {
                return self.block(None, BlockReason::Backpressure);
            }
            let query_id = self.allocate_dns_id();
            let (client, resolver) = endpoints(
                datagram.source,
                datagram.source_port,
                datagram.destination,
                datagram.destination_port,
            );
            let target = DnsResponseTarget::Udp { client, resolver };
            self.pending_dns.insert(query_id, target);
            return vec![EngineAction::ResolveDns {
                query: DnsQuery {
                    query_id,
                    wire: datagram.payload.to_vec(),
                },
                target,
            }];
        }
        if datagram.destination_port == 443 {
            self.block(None, BlockReason::QuicBlocked)
        } else {
            self.block(None, BlockReason::UdpBlocked)
        }
    }

    fn process_tcp(
        &mut self,
        segment: TcpSegment<'_>,
        input: PacketEngineInput<'_>,
    ) -> Vec<EngineAction> {
        let (source, destination) = endpoints(
            segment.source,
            segment.source_port,
            segment.destination,
            segment.destination_port,
        );
        let key = FlowKey {
            source,
            destination,
        };

        if segment.flags.syn
            && (segment.flags.fin || segment.flags.rst || !segment.payload.is_empty())
        {
            if let Some(flow) = self.flows.get(&key) {
                return self.fail_flow(flow.snapshot.flow_id, BlockReason::MalformedPacket);
            }
            return self.reject_syn(segment, BlockReason::MalformedPacket);
        }

        if segment.flags.rst {
            return self.reset_by_key(key);
        }

        if !self.flows.contains_key(&key) {
            if !segment.flags.syn || segment.flags.ack {
                return vec![EngineAction::RecordDiagnostic {
                    code: DiagnosticCode::UnknownFlow,
                    flow_id: None,
                }];
            }
            if segment.destination_port == 53 {
                return self.open_dns_tcp(key, segment, input.platform, input.connection_state);
            }
            return self.open_tcp(key, segment, input);
        }

        if !protected_state(input.connection_state) {
            let flow_id = self
                .flows
                .get(&key)
                .expect("flow existence checked")
                .snapshot
                .flow_id;
            return self.fail_flow(flow_id, BlockReason::ProtectedPathUnavailable);
        }

        self.process_existing_tcp(key, segment, input.platform.monotonic_ms)
    }

    fn open_dns_tcp(
        &mut self,
        key: FlowKey,
        segment: TcpSegment<'_>,
        platform: crate::action::PlatformMetadata,
        connection_state: ClientConnectionState,
    ) -> Vec<EngineAction> {
        if !self.accepting {
            return self.reject_syn(segment, BlockReason::Shutdown);
        }
        if !protected_state(connection_state) {
            return self.reject_syn(segment, BlockReason::ProtectedPathUnavailable);
        }
        if self.flows.len() >= self.config.max_flows {
            return self.reject_syn(segment, BlockReason::Backpressure);
        }
        let flow_id = self.allocate_flow_id();
        let server_initial = initial_sequence(flow_id);
        let flow = FlowRecord {
            snapshot: FlowSnapshot {
                flow_id,
                source: key.source,
                destination: key.destination,
                hostname: None,
                application: platform.application,
                isolation_key: IsolationKey([0; 32]),
                anonymity_profile: AnonymityMode::Standard,
                gateway_id: None,
                timestamps: FlowTimestamps {
                    created_ms: platform.monotonic_ms,
                    last_activity_ms: platform.monotonic_ms,
                    connect_started_ms: None,
                },
                state: TcpFlowState::SynAckSent,
                limits: self.config.buffers,
                queued_to_gateway: 0,
                queued_to_application: 0,
            },
            key,
            client_next: segment.sequence.wrapping_add(1),
            server_next: server_initial.wrapping_add(1),
            dns_tcp: true,
            dns_buffer: Vec::new(),
            outstanding_to_application: None,
        };
        let response = response_from_values(
            &flow,
            server_initial,
            flow.client_next,
            TcpFlags::syn_ack(),
            self.config.receive_window,
            &[],
        );
        self.insert_flow(flow);
        vec![EngineAction::SendSyntheticResponse { packet: response }]
    }

    fn open_tcp(
        &mut self,
        key: FlowKey,
        segment: TcpSegment<'_>,
        input: PacketEngineInput<'_>,
    ) -> Vec<EngineAction> {
        if !self.accepting {
            return self.reject_syn(segment, BlockReason::Shutdown);
        }
        if !protected_state(input.connection_state) {
            return self.reject_syn(segment, BlockReason::ProtectedPathUnavailable);
        }
        let route = match input.route {
            Some(route) => route,
            None => return self.reject_syn(segment, BlockReason::PolicyDenied),
        };
        match route.decision.action {
            PolicyAction::Block => return self.reject_syn(segment, BlockReason::PolicyDenied),
            PolicyAction::Bypass => {
                return self.reject_syn(segment, BlockReason::DirectFallbackForbidden)
            }
            PolicyAction::Tunnel => {}
        }
        if self.flows.len() >= self.config.max_flows {
            self.metrics.record(MetricEvent::Backpressure, None);
            let mut actions = self.reject_syn(segment, BlockReason::Backpressure);
            actions.push(EngineAction::RecordDiagnostic {
                code: DiagnosticCode::FlowLimit,
                flow_id: None,
            });
            return actions;
        }

        let flow_id = self.allocate_flow_id();
        let request = TcpFlowRequest {
            flow_id,
            host: route
                .hostname
                .clone()
                .map(TcpHost::Hostname)
                .unwrap_or(TcpHost::Ip(IpAddr::V4(segment.destination))),
            port: segment.destination_port,
            application: input.platform.application.clone(),
        };
        let flow = FlowRecord {
            snapshot: FlowSnapshot {
                flow_id,
                source: key.source,
                destination: key.destination,
                hostname: route.hostname,
                application: input.platform.application,
                isolation_key: route.isolation_key.clone(),
                anonymity_profile: route.anonymity_profile,
                gateway_id: route.gateway_id.clone(),
                timestamps: FlowTimestamps {
                    created_ms: input.platform.monotonic_ms,
                    last_activity_ms: input.platform.monotonic_ms,
                    connect_started_ms: Some(input.platform.monotonic_ms),
                },
                state: TcpFlowState::Connecting,
                limits: self.config.buffers,
                queued_to_gateway: 0,
                queued_to_application: 0,
            },
            key,
            client_next: segment.sequence.wrapping_add(1),
            server_next: initial_sequence(flow_id).wrapping_add(1),
            dns_tcp: false,
            dns_buffer: Vec::new(),
            outstanding_to_application: None,
        };
        self.insert_flow(flow);
        vec![EngineAction::OpenProtectedStream {
            request,
            isolation_key: route.isolation_key,
            anonymity_profile: route.anonymity_profile,
            gateway_id: route.gateway_id,
        }]
    }

    fn process_existing_tcp(
        &mut self,
        key: FlowKey,
        segment: TcpSegment<'_>,
        now_ms: u64,
    ) -> Vec<EngineAction> {
        let mut actions = Vec::new();
        let mut reset_after = false;
        let mut graceful_remove = false;
        let receive_window = self.config.receive_window;
        let max_buffer = self.config.buffers.to_gateway_bytes;
        let max_pending_dns = self.config.max_pending_dns;

        let flow = self.flows.get_mut(&key).expect("flow existence checked");
        let flow_id = flow.snapshot.flow_id;
        flow.snapshot.timestamps.last_activity_ms = now_ms;

        if segment.flags.syn {
            self.metrics
                .record(MetricEvent::Retransmission, Some(flow_id));
            actions.push(EngineAction::RecordDiagnostic {
                code: DiagnosticCode::Retransmission,
                flow_id: Some(flow_id),
            });
            if flow.snapshot.state == TcpFlowState::SynAckSent {
                actions.push(EngineAction::SendSyntheticResponse {
                    packet: response_from_values(
                        flow,
                        flow.server_next.wrapping_sub(1),
                        flow.client_next,
                        TcpFlags::syn_ack(),
                        receive_window,
                        &[],
                    ),
                });
            }
            return actions;
        }

        if flow.snapshot.state == TcpFlowState::Connecting {
            return actions;
        }
        if flow.snapshot.state == TcpFlowState::SynAckSent {
            if segment.flags.ack
                && segment.acknowledgement == flow.server_next
                && segment.sequence == flow.client_next
            {
                flow.snapshot.state = TcpFlowState::Established;
                flow.snapshot.timestamps.connect_started_ms = None;
            } else {
                actions.push(EngineAction::RecordDiagnostic {
                    code: DiagnosticCode::OutOfOrder,
                    flow_id: Some(flow_id),
                });
                actions.push(EngineAction::SendSyntheticResponse {
                    packet: response_from_values(
                        flow,
                        flow.server_next.wrapping_sub(1),
                        flow.client_next,
                        TcpFlags::syn_ack(),
                        receive_window,
                        &[],
                    ),
                });
                return actions;
            }
        }

        if (!segment.payload.is_empty() || segment.flags.fin) && !segment.flags.ack {
            actions.push(EngineAction::RecordDiagnostic {
                code: DiagnosticCode::OutOfOrder,
                flow_id: Some(flow_id),
            });
            actions.push(EngineAction::SendSyntheticResponse {
                packet: response_from_values(
                    flow,
                    flow.server_next,
                    flow.client_next,
                    TcpFlags::ack(),
                    receive_window,
                    &[],
                ),
            });
            return actions;
        }

        if segment.flags.ack {
            if sequence_before(flow.server_next, segment.acknowledgement) {
                actions.push(EngineAction::BlockFlow {
                    flow_id: Some(flow_id),
                    reason: BlockReason::MalformedPacket,
                });
                actions.push(EngineAction::RecordDiagnostic {
                    code: DiagnosticCode::OutOfOrder,
                    flow_id: Some(flow_id),
                });
                reset_after = true;
            } else if segment.acknowledgement == flow.server_next
                && flow.outstanding_to_application.take().is_some()
            {
                flow.snapshot.queued_to_application = 0;
            }
        }

        if flow.snapshot.state == TcpFlowState::Closing
            && segment.flags.ack
            && segment.acknowledgement == flow.server_next
            && flow.outstanding_to_application.is_none()
            && segment.payload.is_empty()
            && !segment.flags.fin
        {
            actions.push(EngineAction::CloseProtectedStream {
                flow_id,
                direction: CloseDirection::Both,
            });
            self.remove_flow(key);
            return actions;
        }

        if !segment.payload.is_empty() && !reset_after {
            if matches!(
                flow.snapshot.state,
                TcpFlowState::HalfClosedLocal | TcpFlowState::Closing
            ) {
                actions.push(EngineAction::BlockFlow {
                    flow_id: Some(flow_id),
                    reason: BlockReason::MalformedPacket,
                });
                actions.push(EngineAction::RecordDiagnostic {
                    code: DiagnosticCode::OutOfOrder,
                    flow_id: Some(flow_id),
                });
                reset_after = true;
            } else if segment.sequence == flow.client_next {
                if flow.dns_tcp {
                    if flow.dns_buffer.len().saturating_add(segment.payload.len()) > max_buffer {
                        actions.push(EngineAction::BlockFlow {
                            flow_id: Some(flow_id),
                            reason: BlockReason::Backpressure,
                        });
                        actions.push(EngineAction::RecordDiagnostic {
                            code: DiagnosticCode::BufferLimit,
                            flow_id: Some(flow_id),
                        });
                        reset_after = true;
                    } else {
                        flow.dns_buffer.extend_from_slice(segment.payload);
                        flow.client_next =
                            flow.client_next.wrapping_add(segment.payload.len() as u32);
                        actions.push(EngineAction::SendSyntheticResponse {
                            packet: response_from_values(
                                flow,
                                flow.server_next,
                                flow.client_next,
                                TcpFlags::ack(),
                                receive_window,
                                &[],
                            ),
                        });
                    }
                } else if flow
                    .snapshot
                    .queued_to_gateway
                    .saturating_add(segment.payload.len())
                    > max_buffer
                {
                    actions.push(EngineAction::BlockFlow {
                        flow_id: Some(flow_id),
                        reason: BlockReason::Backpressure,
                    });
                    actions.push(EngineAction::RecordDiagnostic {
                        code: DiagnosticCode::BufferLimit,
                        flow_id: Some(flow_id),
                    });
                    reset_after = true;
                } else {
                    flow.snapshot.queued_to_gateway += segment.payload.len();
                    flow.client_next = flow.client_next.wrapping_add(segment.payload.len() as u32);
                    actions.push(EngineAction::ForwardPayload {
                        flow_id,
                        payload: segment.payload.to_vec(),
                    });
                }
            } else if sequence_before(segment.sequence, flow.client_next) {
                actions.push(EngineAction::RecordDiagnostic {
                    code: DiagnosticCode::Retransmission,
                    flow_id: Some(flow_id),
                });
                actions.push(EngineAction::SendSyntheticResponse {
                    packet: response_from_values(
                        flow,
                        flow.server_next,
                        flow.client_next,
                        TcpFlags::ack(),
                        receive_window,
                        &[],
                    ),
                });
            } else {
                actions.push(EngineAction::RecordDiagnostic {
                    code: DiagnosticCode::OutOfOrder,
                    flow_id: Some(flow_id),
                });
                actions.push(EngineAction::SendSyntheticResponse {
                    packet: response_from_values(
                        flow,
                        flow.server_next,
                        flow.client_next,
                        TcpFlags::ack(),
                        receive_window,
                        &[],
                    ),
                });
            }
        }

        if flow.dns_tcp && !reset_after {
            loop {
                if flow.dns_buffer.len() < 2 {
                    break;
                }
                let message_len =
                    usize::from(u16::from_be_bytes([flow.dns_buffer[0], flow.dns_buffer[1]]));
                if message_len == 0 || message_len > MAX_DNS_MESSAGE_BYTES {
                    actions.push(EngineAction::BlockFlow {
                        flow_id: Some(flow_id),
                        reason: BlockReason::MalformedPacket,
                    });
                    reset_after = true;
                    break;
                }
                if flow.dns_buffer.len() < message_len + 2 {
                    break;
                }
                if self.pending_dns.len() >= max_pending_dns {
                    actions.push(EngineAction::BlockFlow {
                        flow_id: Some(flow_id),
                        reason: BlockReason::Backpressure,
                    });
                    reset_after = true;
                    break;
                }
                let wire = flow.dns_buffer[2..message_len + 2].to_vec();
                flow.dns_buffer.drain(..message_len + 2);
                let query_id = self.next_dns_id;
                self.next_dns_id = self.next_dns_id.wrapping_add(1).max(1);
                let target = DnsResponseTarget::Tcp { flow_id };
                self.pending_dns.insert(query_id, target);
                actions.push(EngineAction::ResolveDns {
                    query: DnsQuery { query_id, wire },
                    target,
                });
            }
        }

        let fin_sequence_end = segment.sequence.wrapping_add(segment.payload.len() as u32);
        if segment.flags.fin && !reset_after && fin_sequence_end == flow.client_next {
            flow.client_next = flow.client_next.wrapping_add(1);
            let acknowledgement = response_from_values(
                flow,
                flow.server_next,
                flow.client_next,
                TcpFlags::ack(),
                receive_window,
                &[],
            );
            if flow.snapshot.state == TcpFlowState::HalfClosedRemote {
                flow.snapshot.state = TcpFlowState::Closing;
                actions.push(EngineAction::CloseProtectedStream {
                    flow_id,
                    direction: CloseDirection::Both,
                });
                if segment.payload.is_empty() {
                    actions.push(EngineAction::SendSyntheticResponse {
                        packet: acknowledgement,
                    });
                    graceful_remove = true;
                }
            } else {
                flow.snapshot.state = TcpFlowState::HalfClosedLocal;
                if !flow.dns_tcp {
                    actions.push(EngineAction::CloseProtectedStream {
                        flow_id,
                        direction: CloseDirection::Write,
                    });
                }
                if flow.dns_tcp || segment.payload.is_empty() {
                    actions.push(EngineAction::SendSyntheticResponse {
                        packet: acknowledgement,
                    });
                }
            }
        } else if segment.flags.fin
            && !reset_after
            && fin_sequence_end.wrapping_add(1) == flow.client_next
        {
            actions.push(EngineAction::RecordDiagnostic {
                code: DiagnosticCode::Retransmission,
                flow_id: Some(flow_id),
            });
            actions.push(EngineAction::SendSyntheticResponse {
                packet: response_from_values(
                    flow,
                    flow.server_next,
                    flow.client_next,
                    TcpFlags::ack(),
                    receive_window,
                    &[],
                ),
            });
        }

        if reset_after {
            let rst = response_from_values(
                flow,
                flow.server_next,
                flow.client_next,
                TcpFlags::rst_ack(),
                0,
                &[],
            );
            actions.push(EngineAction::SendSyntheticResponse { packet: rst });
            actions.push(EngineAction::CloseProtectedStream {
                flow_id,
                direction: CloseDirection::Both,
            });
        }
        if reset_after || graceful_remove {
            self.remove_flow(key);
        }
        actions
    }

    /// Marks a protected stream open and emits the delayed SYN-ACK.
    pub fn protected_stream_opened(&mut self, flow_id: FlowId, now_ms: u64) -> Vec<EngineAction> {
        let Some(key) = self.ids.get(&flow_id).copied() else {
            return vec![EngineAction::RecordDiagnostic {
                code: DiagnosticCode::UnknownFlow,
                flow_id: Some(flow_id),
            }];
        };
        let flow = self.flows.get_mut(&key).expect("id map points to flow");
        if flow.snapshot.state != TcpFlowState::Connecting {
            return Vec::new();
        }
        flow.snapshot.state = TcpFlowState::SynAckSent;
        flow.snapshot.timestamps.last_activity_ms = now_ms;
        let sequence = flow.server_next.wrapping_sub(1);
        vec![EngineAction::SendSyntheticResponse {
            packet: response_from_values(
                flow,
                sequence,
                flow.client_next,
                TcpFlags::syn_ack(),
                self.config.receive_window,
                &[],
            ),
        }]
    }

    /// Releases bytes only after the protected write succeeds and emits the cumulative ACK.
    pub fn acknowledge_forwarded(
        &mut self,
        flow_id: FlowId,
        bytes: usize,
        now_ms: u64,
    ) -> Vec<EngineAction> {
        let Some(key) = self.ids.get(&flow_id).copied() else {
            return Vec::new();
        };
        let Some(flow) = self.flows.get_mut(&key) else {
            return Vec::new();
        };
        flow.snapshot.queued_to_gateway = flow.snapshot.queued_to_gateway.saturating_sub(bytes);
        flow.snapshot.timestamps.last_activity_ms = now_ms;
        let packet = response_from_values(
            flow,
            flow.server_next,
            flow.client_next,
            TcpFlags::ack(),
            self.config.receive_window,
            &[],
        );
        let remove_after = flow.snapshot.state == TcpFlowState::Closing
            && flow.outstanding_to_application.is_none();
        if remove_after {
            self.remove_flow(key);
        }
        vec![EngineAction::SendSyntheticResponse { packet }]
    }

    /// Returns the bounded number of protected bytes that may be read without loss.
    ///
    /// A zero value means client-core must wait for an application ACK or handshake
    /// completion instead of reading and dropping bytes from the ordered stream.
    pub fn protected_read_capacity(&self, flow_id: FlowId) -> usize {
        let Some(key) = self.ids.get(&flow_id) else {
            return 0;
        };
        let Some(flow) = self.flows.get(key) else {
            return 0;
        };
        if flow.outstanding_to_application.is_none()
            && matches!(
                flow.snapshot.state,
                TcpFlowState::Established | TcpFlowState::HalfClosedLocal
            )
        {
            flow.snapshot.limits.to_application_bytes
        } else {
            0
        }
    }

    /// Converts protected-stream bytes to one bounded local TCP segment.
    pub fn protected_payload(
        &mut self,
        flow_id: FlowId,
        payload: &[u8],
        now_ms: u64,
    ) -> Vec<EngineAction> {
        let Some(key) = self.ids.get(&flow_id).copied() else {
            return vec![EngineAction::RecordDiagnostic {
                code: DiagnosticCode::UnknownFlow,
                flow_id: Some(flow_id),
            }];
        };
        if payload.is_empty() {
            return Vec::new();
        }
        let can_accept = self.flows.get(&key).is_some_and(|flow| {
            payload.len() <= flow.snapshot.limits.to_application_bytes
                && flow.outstanding_to_application.is_none()
                && matches!(
                    flow.snapshot.state,
                    TcpFlowState::Established | TcpFlowState::HalfClosedLocal
                )
        });
        if !can_accept {
            return self.fail_flow(flow_id, BlockReason::Backpressure);
        }
        let flow = self.flows.get_mut(&key).expect("id map points to flow");
        flow.snapshot.timestamps.last_activity_ms = now_ms;
        flow.snapshot.queued_to_application = payload.len();
        let sequence = flow.server_next;
        let acknowledgement = flow.client_next;
        let flags = TcpFlags {
            psh: true,
            ..TcpFlags::ack()
        };
        flow.server_next = flow.server_next.wrapping_add(payload.len() as u32);
        let packet = response_from_values(
            flow,
            sequence,
            acknowledgement,
            flags,
            self.config.receive_window,
            payload,
        );
        flow.outstanding_to_application = Some(OutstandingSegment {
            sequence,
            acknowledgement,
            flags,
            payload: payload.to_vec(),
            sent_ms: now_ms,
            retransmissions: 0,
        });
        vec![EngineAction::SendSyntheticResponse { packet }]
    }

    /// Emits FIN after an orderly protected peer close.
    pub fn protected_stream_closed(&mut self, flow_id: FlowId, now_ms: u64) -> Vec<EngineAction> {
        let Some(key) = self.ids.get(&flow_id).copied() else {
            return Vec::new();
        };
        let valid = self.flows.get(&key).is_some_and(|flow| {
            flow.outstanding_to_application.is_none()
                && matches!(
                    flow.snapshot.state,
                    TcpFlowState::Established | TcpFlowState::HalfClosedLocal
                )
        });
        if !valid {
            return self.fail_flow(flow_id, BlockReason::DownstreamFailure);
        }
        let flow = self.flows.get_mut(&key).expect("id map points to flow");
        flow.snapshot.timestamps.last_activity_ms = now_ms;
        flow.snapshot.state = if flow.snapshot.state == TcpFlowState::HalfClosedLocal {
            TcpFlowState::Closing
        } else {
            TcpFlowState::HalfClosedRemote
        };
        let sequence = flow.server_next;
        let acknowledgement = flow.client_next;
        let flags = TcpFlags::fin_ack();
        flow.server_next = flow.server_next.wrapping_add(1);
        let packet = response_from_values(
            flow,
            sequence,
            acknowledgement,
            flags,
            self.config.receive_window,
            &[],
        );
        flow.outstanding_to_application = Some(OutstandingSegment {
            sequence,
            acknowledgement,
            flags,
            payload: Vec::new(),
            sent_ms: now_ms,
            retransmissions: 0,
        });
        vec![EngineAction::SendSyntheticResponse { packet }]
    }

    /// Fails a protected stream and resets its local flow without fallback.
    pub fn fail_flow(&mut self, flow_id: FlowId, reason: BlockReason) -> Vec<EngineAction> {
        let Some(key) = self.ids.get(&flow_id).copied() else {
            return Vec::new();
        };
        let flow = self.flows.get(&key).expect("id map points to flow");
        let packet = response_from_values(
            flow,
            flow.server_next,
            flow.client_next,
            TcpFlags::rst_ack(),
            0,
            &[],
        );
        self.remove_flow(key);
        self.metrics
            .record(MetricEvent::FlowBlocked(reason), Some(flow_id));
        vec![
            EngineAction::SendSyntheticResponse { packet },
            EngineAction::BlockFlow {
                flow_id: Some(flow_id),
                reason,
            },
            EngineAction::CloseProtectedStream {
                flow_id,
                direction: CloseDirection::Both,
            },
        ]
    }

    /// Completes one intercepted DNS operation with a bounded DNS wire response.
    pub fn complete_dns(&mut self, query_id: u64, wire: &[u8], now_ms: u64) -> Vec<EngineAction> {
        let Some(target) = self.pending_dns.remove(&query_id) else {
            return Vec::new();
        };
        if wire.is_empty() || wire.len() > MAX_DNS_MESSAGE_BYTES {
            return match target {
                DnsResponseTarget::Tcp { flow_id } => {
                    self.fail_flow(flow_id, BlockReason::DownstreamFailure)
                }
                DnsResponseTarget::Udp { .. } => self.block(None, BlockReason::DownstreamFailure),
            };
        }
        match target {
            DnsResponseTarget::Udp { client, resolver } => {
                if wire.len() > 65_507 {
                    return self.block(None, BlockReason::Backpressure);
                }
                vec![EngineAction::SendSyntheticResponse {
                    packet: build_udp_packet(
                        resolver.address,
                        client.address,
                        resolver.port,
                        client.port,
                        wire,
                    ),
                }]
            }
            DnsResponseTarget::Tcp { flow_id } => {
                let Some(key) = self.ids.get(&flow_id).copied() else {
                    return Vec::new();
                };
                let mut framed = Vec::with_capacity(wire.len() + 2);
                framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
                framed.extend_from_slice(wire);
                let can_accept = self.flows.get(&key).is_some_and(|flow| {
                    framed.len() <= flow.snapshot.limits.to_application_bytes
                        && flow.outstanding_to_application.is_none()
                        && matches!(
                            flow.snapshot.state,
                            TcpFlowState::Established | TcpFlowState::HalfClosedLocal
                        )
                });
                if !can_accept {
                    return self.fail_flow(flow_id, BlockReason::Backpressure);
                }
                let flow = self.flows.get_mut(&key).expect("id map points to flow");
                flow.snapshot.timestamps.last_activity_ms = now_ms;
                flow.snapshot.queued_to_application = framed.len();
                let sequence = flow.server_next;
                let acknowledgement = flow.client_next;
                let flags = TcpFlags {
                    psh: true,
                    ..TcpFlags::ack()
                };
                flow.server_next = flow.server_next.wrapping_add(framed.len() as u32);
                let packet = response_from_values(
                    flow,
                    sequence,
                    acknowledgement,
                    flags,
                    self.config.receive_window,
                    &framed,
                );
                flow.outstanding_to_application = Some(OutstandingSegment {
                    sequence,
                    acknowledgement,
                    flags,
                    payload: framed,
                    sent_ms: now_ms,
                    retransmissions: 0,
                });
                vec![EngineAction::SendSyntheticResponse { packet }]
            }
        }
    }

    /// Expires connect and idle deadlines.
    pub fn tick(&mut self, now_ms: u64) -> Vec<EngineAction> {
        if self.suspended_at_ms.is_some() {
            return Vec::new();
        }
        let mut expired = Vec::new();
        let mut retransmissions = Vec::new();
        for flow in self.flows.values_mut() {
            let timestamps = flow.snapshot.timestamps;
            if matches!(
                flow.snapshot.state,
                TcpFlowState::Connecting | TcpFlowState::SynAckSent
            ) && now_ms.saturating_sub(
                timestamps
                    .connect_started_ms
                    .unwrap_or(timestamps.created_ms),
            ) >= self.config.connection_timeout_ms
            {
                expired.push((flow.snapshot.flow_id, BlockReason::ConnectionTimeout));
            } else if now_ms.saturating_sub(timestamps.last_activity_ms)
                >= self.config.idle_timeout_ms
            {
                expired.push((flow.snapshot.flow_id, BlockReason::IdleTimeout));
            } else if let Some(outstanding) = &mut flow.outstanding_to_application {
                if now_ms.saturating_sub(outstanding.sent_ms) >= self.config.retransmit_interval_ms
                {
                    if outstanding.retransmissions >= self.config.max_retransmissions {
                        expired.push((flow.snapshot.flow_id, BlockReason::IdleTimeout));
                    } else {
                        outstanding.retransmissions += 1;
                        outstanding.sent_ms = now_ms;
                        let segment = (
                            outstanding.sequence,
                            outstanding.acknowledgement,
                            outstanding.flags,
                            outstanding.payload.clone(),
                        );
                        let packet = response_from_values(
                            flow,
                            segment.0,
                            segment.1,
                            segment.2,
                            self.config.receive_window,
                            &segment.3,
                        );
                        retransmissions.push((flow.snapshot.flow_id, packet));
                    }
                }
            }
        }
        let mut actions = Vec::new();
        for (flow_id, packet) in retransmissions {
            self.metrics
                .record(MetricEvent::Retransmission, Some(flow_id));
            actions.push(EngineAction::RecordDiagnostic {
                code: DiagnosticCode::Retransmission,
                flow_id: Some(flow_id),
            });
            actions.push(EngineAction::SendSyntheticResponse { packet });
        }
        for (flow_id, reason) in expired {
            actions.extend(self.fail_flow(flow_id, reason));
        }
        actions
    }

    /// Freezes monotonic deadlines before platform sleep.
    pub fn suspend(&mut self, now_ms: u64) {
        if self.suspended_at_ms.is_none() {
            self.suspended_at_ms = Some(now_ms);
        }
    }

    /// Resumes deadlines only if the orchestrator independently proved the path healthy.
    /// Otherwise every flow is reset fail-closed.
    pub fn resume(&mut self, now_ms: u64, protected_path_healthy: bool) -> Vec<EngineAction> {
        let Some(suspended_at) = self.suspended_at_ms.take() else {
            return Vec::new();
        };
        if !protected_path_healthy {
            let ids: Vec<FlowId> = self.ids.keys().copied().collect();
            let mut actions = vec![EngineAction::RecordDiagnostic {
                code: DiagnosticCode::ResumePathInvalid,
                flow_id: None,
            }];
            for flow_id in ids {
                actions.extend(self.fail_flow(flow_id, BlockReason::ProtectedPathUnavailable));
            }
            return actions;
        }
        let slept = now_ms.saturating_sub(suspended_at);
        for flow in self.flows.values_mut() {
            flow.snapshot.timestamps.created_ms =
                flow.snapshot.timestamps.created_ms.saturating_add(slept);
            flow.snapshot.timestamps.last_activity_ms = flow
                .snapshot
                .timestamps
                .last_activity_ms
                .saturating_add(slept);
            if let Some(started) = &mut flow.snapshot.timestamps.connect_started_ms {
                *started = started.saturating_add(slept);
            }
        }
        Vec::new()
    }

    /// Cancels new work and resets all flows. The platform kill switch must remain engaged.
    pub fn shutdown(&mut self) -> Vec<EngineAction> {
        self.accepting = false;
        self.pending_dns.clear();
        let ids: Vec<FlowId> = self.ids.keys().copied().collect();
        let mut actions = vec![EngineAction::RecordDiagnostic {
            code: DiagnosticCode::Shutdown,
            flow_id: None,
        }];
        for flow_id in ids {
            actions.extend(self.fail_flow(flow_id, BlockReason::Shutdown));
        }
        actions
    }

    /// Resets every protected flow for a downstream path failure.
    pub fn fail_all(&mut self, reason: BlockReason) -> Vec<EngineAction> {
        self.pending_dns.clear();
        let ids: Vec<FlowId> = self.ids.keys().copied().collect();
        let mut actions = Vec::new();
        for flow_id in ids {
            actions.extend(self.fail_flow(flow_id, reason));
        }
        actions
    }

    fn reject_syn(&mut self, segment: TcpSegment<'_>, reason: BlockReason) -> Vec<EngineAction> {
        let acknowledgement = segment.sequence.wrapping_add(1);
        let packet = build_tcp_packet(
            segment.destination,
            segment.source,
            segment.destination_port,
            segment.source_port,
            0,
            acknowledgement,
            TcpFlags::rst_ack(),
            0,
            &[],
        );
        let mut actions = self.block(None, reason);
        actions.insert(0, EngineAction::SendSyntheticResponse { packet });
        actions
    }

    fn reset_by_key(&mut self, key: FlowKey) -> Vec<EngineAction> {
        let Some(flow) = self.flows.get(&key) else {
            return Vec::new();
        };
        let flow_id = flow.snapshot.flow_id;
        self.remove_flow(key);
        vec![EngineAction::CloseProtectedStream {
            flow_id,
            direction: CloseDirection::Both,
        }]
    }

    fn block(&self, flow_id: Option<FlowId>, reason: BlockReason) -> Vec<EngineAction> {
        self.metrics
            .record(MetricEvent::FlowBlocked(reason), flow_id);
        vec![EngineAction::BlockFlow { flow_id, reason }]
    }

    fn insert_flow(&mut self, flow: FlowRecord) {
        let flow_id = flow.snapshot.flow_id;
        let key = flow.key;
        self.ids.insert(flow_id, key);
        self.flows.insert(key, flow);
        self.metrics.record(MetricEvent::FlowOpened, Some(flow_id));
    }

    fn remove_flow(&mut self, key: FlowKey) {
        if let Some(flow) = self.flows.remove(&key) {
            let flow_id = flow.snapshot.flow_id;
            self.ids.remove(&flow_id);
            self.pending_dns.retain(|_, target| {
                !matches!(target, DnsResponseTarget::Tcp { flow_id: pending } if *pending == flow_id)
            });
            self.metrics.record(MetricEvent::FlowClosed, Some(flow_id));
        }
    }

    fn allocate_flow_id(&mut self) -> FlowId {
        let id = FlowId(self.next_flow_id);
        self.next_flow_id = self.next_flow_id.wrapping_add(1).max(1);
        id
    }

    fn allocate_dns_id(&mut self) -> u64 {
        let id = self.next_dns_id;
        self.next_dns_id = self.next_dns_id.wrapping_add(1).max(1);
        id
    }
}

fn protected_state(state: ClientConnectionState) -> bool {
    matches!(
        state,
        ClientConnectionState::Connected
            | ClientConnectionState::Rotating
            | ClientConnectionState::Degraded
    )
}

fn initial_sequence(flow_id: FlowId) -> u32 {
    0xa50f_0000u32 ^ (flow_id.0 as u32).wrapping_mul(0x9e37_79b9)
}

fn sequence_before(left: u32, right: u32) -> bool {
    (left.wrapping_sub(right) as i32) < 0
}

fn response_from_values(
    flow: &FlowRecord,
    sequence: u32,
    acknowledgement: u32,
    flags: TcpFlags,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    build_tcp_packet(
        flow.key.destination.address,
        flow.key.source.address,
        flow.key.destination.port,
        flow.key.source.port,
        sequence,
        acknowledgement,
        flags,
        window,
        payload,
    )
}

#[allow(dead_code)]
fn _stable_error_mapping(reason: BlockReason) -> ErrorCode {
    match reason {
        BlockReason::MalformedPacket => ErrorCode::ProtocolViolation,
        BlockReason::Backpressure => ErrorCode::Backpressure,
        BlockReason::PolicyDenied | BlockReason::DirectFallbackForbidden => ErrorCode::PolicyDenied,
        BlockReason::ProtectedPathUnavailable | BlockReason::DownstreamFailure => {
            ErrorCode::ProtectedPathLost
        }
        _ => ErrorCode::UnsupportedTransport,
    }
}
