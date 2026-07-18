//! High-level packet, policy, DNS, dispatcher and lifecycle coordination.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;

use onionroute_common_types::contracts::v1::PolicyEngine;
use onionroute_common_types::error::{ErrorCode, ErrorDomain, RetryClass, SafetyImpact, Severity};
use onionroute_common_types::state::ClientConnectionState;
use onionroute_common_types::types::{
    AnonymityMode, ApplicationTag, DnsPolicyContext, FlowId, GatewayId, GatewaySession,
    IsolationKey, PolicyAction, TcpFlowRequest, TcpHost,
};
use onionroute_common_types::{OnionError, OnionResult};
use onionroute_dns_engine::SyntheticDnsEngine;
use onionroute_packet_engine::{
    classify, BlockReason, CloseDirection, DiagnosticCode, EngineAction, PacketEngineInput,
    PacketProcessor, PlatformMetadata, ProtectedRoute,
};

use crate::dispatcher::{ConnectionDispatcher, DispatcherCancellation};

/// Already-selected route metadata. Circuit selection remains outside client-core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveRoute {
    /// Random route isolation value.
    pub isolation_key: IsolationKey,
    /// User-selected anonymity mode.
    pub anonymity_profile: AnonymityMode,
    /// Terminal private gateway identifier.
    pub gateway_id: Option<GatewayId>,
}

/// Closed-schema local diagnostic retained only on device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalDiagnostic {
    /// Stable diagnostic code.
    pub code: DiagnosticCode,
    /// Process-local flow identifier, never exported remotely.
    pub flow_id: Option<FlowId>,
}

/// Result of one core operation.
#[derive(Default, Debug)]
pub struct CoreOutput {
    /// Synthetic IP packets to send back to the platform TUN.
    pub packets: Vec<Vec<u8>>,
    /// Local-only block results.
    pub blocked: Vec<(Option<FlowId>, BlockReason)>,
    /// Local-only closed-schema diagnostics.
    pub diagnostics: Vec<LocalDiagnostic>,
}

/// OnionRoute packet core with no UI or direct-network dependency.
pub struct ClientCore {
    packet: PacketProcessor,
    dns: Arc<SyntheticDnsEngine>,
    policy: Arc<dyn PolicyEngine>,
    dispatcher: ConnectionDispatcher,
    route: ActiveRoute,
}

impl ClientCore {
    /// Creates a core around an externally prepared gateway session and route.
    pub fn new(
        packet: PacketProcessor,
        dns: Arc<SyntheticDnsEngine>,
        policy: Arc<dyn PolicyEngine>,
        dispatcher: ConnectionDispatcher,
        route: ActiveRoute,
    ) -> Self {
        Self {
            packet,
            dns,
            policy,
            dispatcher,
            route,
        }
    }

    /// Processes one TUN packet through policy and the protected dispatcher.
    pub async fn handle_packet(
        &mut self,
        packet: &[u8],
        platform: PlatformMetadata,
        connection_state: ClientConnectionState,
    ) -> CoreOutput {
        let route = self.route_for_packet(packet, &platform).await;
        let actions = self.packet.process(PacketEngineInput {
            packet,
            platform: platform.clone(),
            route,
            connection_state,
        });
        self.execute(actions, platform.monotonic_ms, platform.application)
            .await
    }

    async fn route_for_packet(
        &self,
        packet: &[u8],
        platform: &PlatformMetadata,
    ) -> Option<ProtectedRoute> {
        let segment = match classify(packet).ok()? {
            onionroute_packet_engine::ClassifiedPacket::Tcp(segment)
                if segment.flags.syn && !segment.flags.ack && segment.destination_port != 53 =>
            {
                segment
            }
            _ => return None,
        };
        let hostname = self.dns.lookup_hostname(segment.destination);
        let request = TcpFlowRequest {
            flow_id: FlowId(0),
            host: hostname
                .clone()
                .map(TcpHost::Hostname)
                .unwrap_or(TcpHost::Ip(IpAddr::V4(segment.destination))),
            port: segment.destination_port,
            application: platform.application.clone(),
        };
        let decision = self.policy.evaluate_tcp(&request).await.ok()?;
        Some(ProtectedRoute {
            decision,
            hostname,
            isolation_key: self.route.isolation_key.clone(),
            anonymity_profile: self.route.anonymity_profile,
            gateway_id: self.route.gateway_id.clone(),
        })
    }

    async fn execute(
        &mut self,
        actions: Vec<EngineAction>,
        now_ms: u64,
        application: Option<ApplicationTag>,
    ) -> CoreOutput {
        let mut output = CoreOutput::default();
        let mut queue: VecDeque<EngineAction> = actions.into();
        while let Some(action) = queue.pop_front() {
            match action {
                EngineAction::OpenProtectedStream { request, .. } => {
                    let flow_id = request.flow_id;
                    match self.dispatcher.open(&request).await {
                        Ok(()) => {
                            queue.extend(self.packet.protected_stream_opened(flow_id, now_ms))
                        }
                        Err(_) => {
                            queue.clear();
                            queue.extend(
                                self.packet
                                    .fail_flow(flow_id, BlockReason::DownstreamFailure),
                            );
                        }
                    }
                }
                EngineAction::ForwardPayload { flow_id, payload } => {
                    match self.dispatcher.write_all(flow_id, &payload).await {
                        Ok(()) => queue.extend(self.packet.acknowledge_forwarded(
                            flow_id,
                            payload.len(),
                            now_ms,
                        )),
                        Err(_) => {
                            queue.clear();
                            queue.extend(
                                self.packet
                                    .fail_flow(flow_id, BlockReason::DownstreamFailure),
                            );
                        }
                    }
                }
                EngineAction::ResolveDns { query, .. } => {
                    let response = match SyntheticDnsEngine::parse_query(&query.wire) {
                        Ok(question) => {
                            let context = DnsPolicyContext {
                                application: application.clone(),
                                record_type: question.record_type,
                            };
                            match self.policy.evaluate_dns(&context).await {
                                Ok(decision) if decision.action == PolicyAction::Tunnel => self
                                    .dispatcher
                                    .resolve_dns(self.dns.as_ref(), &query)
                                    .await
                                    .map(|response| response.wire)
                                    .unwrap_or_else(|_| SyntheticDnsEngine::servfail(&query.wire)),
                                _ => SyntheticDnsEngine::servfail(&query.wire),
                            }
                        }
                        Err(_) => SyntheticDnsEngine::servfail(&query.wire),
                    };
                    queue.extend(self.packet.complete_dns(query.query_id, &response, now_ms));
                }
                EngineAction::CloseProtectedStream {
                    flow_id,
                    direction: CloseDirection::Write,
                } => {
                    if self.dispatcher.mark_write_closed(flow_id).is_err() {
                        queue.clear();
                        queue.extend(
                            self.packet
                                .fail_flow(flow_id, BlockReason::DownstreamFailure),
                        );
                    }
                }
                EngineAction::CloseProtectedStream {
                    flow_id,
                    direction: CloseDirection::Both,
                } => {
                    let _ = self.dispatcher.close(flow_id).await;
                }
                EngineAction::SendSyntheticResponse { packet } => output.packets.push(packet),
                EngineAction::BlockFlow { flow_id, reason } => {
                    output.blocked.push((flow_id, reason))
                }
                EngineAction::RecordDiagnostic { code, flow_id } => {
                    output.diagnostics.push(LocalDiagnostic { code, flow_id });
                }
            }
        }
        output
    }

    /// Pumps one protected read for a flow and emits local TCP data or FIN.
    pub async fn pump_flow(&mut self, flow_id: FlowId, now_ms: u64) -> CoreOutput {
        let capacity = self.packet.protected_read_capacity(flow_id);
        if capacity == 0 {
            return CoreOutput::default();
        }
        let actions = match self.dispatcher.read_once_limited(flow_id, capacity).await {
            Ok(Some(payload)) => self.packet.protected_payload(flow_id, &payload, now_ms),
            Ok(None) => self.packet.protected_stream_closed(flow_id, now_ms),
            Err(_) => self
                .packet
                .fail_flow(flow_id, BlockReason::DownstreamFailure),
        };
        self.execute(actions, now_ms, None).await
    }

    /// Applies connection and idle deadlines.
    pub async fn tick(&mut self, now_ms: u64) -> CoreOutput {
        let actions = self.packet.tick(now_ms);
        self.execute(actions, now_ms, None).await
    }

    /// Freezes flow deadlines before platform sleep.
    pub fn suspend(&mut self, now_ms: u64) {
        self.packet.suspend(now_ms);
    }

    /// Resumes or resets every flow depending on independently supplied path health.
    pub async fn resume(&mut self, now_ms: u64, protected_path_healthy: bool) -> CoreOutput {
        let actions = self.packet.resume(now_ms, protected_path_healthy);
        self.execute(actions, now_ms, None).await
    }

    /// Fails all flows immediately after a Tor/gateway/session loss.
    pub async fn protected_path_lost(&mut self, now_ms: u64) -> CoreOutput {
        let actions = self.packet.fail_all(BlockReason::ProtectedPathUnavailable);
        let output = self.execute(actions, now_ms, None).await;
        let _ = self.dispatcher.close_all().await;
        output
    }

    /// Installs a replacement gateway session after old flows were failed closed.
    pub async fn reconnect(
        &mut self,
        session: GatewaySession,
        route: ActiveRoute,
        now_ms: u64,
    ) -> OnionResult<CoreOutput> {
        let output = self.protected_path_lost(now_ms).await;
        self.dispatcher.replace_session(session).await?;
        self.route = route;
        Ok(output)
    }

    /// Clears synthetic hostname mappings for manual Identity Reset.
    pub fn identity_reset(&self) {
        self.dns.identity_reset();
    }

    /// Returns a signal that can cancel pending gateway I/O from another task.
    pub fn cancellation_handle(&self) -> DispatcherCancellation {
        self.dispatcher.cancellation_handle()
    }

    /// Rejects new work, resets flows, and closes all protected streams.
    pub async fn shutdown(&mut self, now_ms: u64) -> CoreOutput {
        let actions = self.packet.shutdown();
        let output = self.execute(actions, now_ms, None).await;
        let _ = self.dispatcher.close_all().await;
        output
    }

    /// Returns the live local flow count.
    pub fn active_flows(&self) -> usize {
        self.packet.active_flows()
    }

    /// Returns process-local flow identifiers for the owning bounded I/O pump.
    pub fn active_flow_ids(&self) -> Vec<FlowId> {
        self.packet.flow_ids()
    }
}

pub(crate) fn core_error(code: ErrorCode, message: &'static str) -> OnionError {
    OnionError::new(
        ErrorDomain::Packet,
        code,
        Severity::Error,
        RetryClass::Never,
        SafetyImpact::MustBlock,
        message,
    )
}
