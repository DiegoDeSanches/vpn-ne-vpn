use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::flow::FlowController;
use crate::framing::{read_frame, write_frame};
use crate::limits::{ProtocolLimits, MAX_DATA_PAYLOAD};
use crate::negotiation::{
    validate_capabilities, FLOW_CONTROL_V1, RESOLVE_DOMAIN_V1, SESSION_ROTATION_V1, TCP_CONNECT_V1,
};
use crate::proto::gateway_frame::Body;
use crate::proto::{
    CloseCode, CloseStream, Data, ErrorCode, GatewayFrame, GoAway, HalfClose, OpenTcpStream,
    ResolveDomain, ResolveResult, TcpStreamOpened, TcpStreamRejected, WindowUpdate,
};
use crate::scheduler::{FairScheduler, OutboundItem};
use crate::validation::{validate_frame, validate_stream_id};
use crate::wire::onionroute::common::v1::ProtocolVersion;
use crate::{ProtocolError, Result};

const FRAME_ACCOUNTING_OVERHEAD: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRole {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionPhase {
    AwaitingServerHello,
    AwaitingClientHello,
    AwaitingAuthentication,
    AwaitingAuthenticationResult,
    Active,
    Draining,
    Closed,
}

pub(crate) struct NegotiatedParameters {
    pub selected_version: ProtocolVersion,
    pub session_id: Vec<u8>,
    pub maximum_frame_size: usize,
    pub peer_connection_receive_window: u32,
    pub local_connection_receive_window: u32,
    pub maximum_concurrent_streams: usize,
    pub enabled_capabilities: BTreeSet<String>,
    pub idle_stream_timeout: Duration,
    pub next_phase: SessionPhase,
}

/// Async protocol state machine over an arbitrary reliable ordered byte stream.
/// The caller drives reads and writes explicitly, so its own bounded channels
/// naturally propagate backpressure to packet/TCP producers.
pub struct Session<T> {
    transport: T,
    local_role: PeerRole,
    phase: SessionPhase,
    limits: ProtocolLimits,
    maximum_frame_size: usize,
    outbound_version: ProtocolVersion,
    selected_version: Option<ProtocolVersion>,
    session_id: Vec<u8>,
    next_send_sequence: u64,
    next_receive_sequence: u64,
    enabled_critical_extensions: BTreeSet<u32>,
    enabled_capabilities: BTreeSet<String>,
    scheduler: FairScheduler,
    flow: Option<FlowController>,
    local_resolves: BTreeSet<u64>,
    remote_resolves: BTreeSet<u64>,
    maximum_seen_local_query_id: u64,
    maximum_seen_remote_query_id: u64,
}

impl<T> Session<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new_client(
        transport: T,
        limits: ProtocolLimits,
        initial_version: ProtocolVersion,
    ) -> Result<Self> {
        Self::new(
            transport,
            PeerRole::Client,
            SessionPhase::AwaitingServerHello,
            limits,
            initial_version,
        )
    }

    pub fn new_server(
        transport: T,
        limits: ProtocolLimits,
        initial_version: ProtocolVersion,
    ) -> Result<Self> {
        Self::new(
            transport,
            PeerRole::Server,
            SessionPhase::AwaitingClientHello,
            limits,
            initial_version,
        )
    }

    fn new(
        transport: T,
        local_role: PeerRole,
        phase: SessionPhase,
        limits: ProtocolLimits,
        initial_version: ProtocolVersion,
    ) -> Result<Self> {
        limits.validate()?;
        if initial_version.major == 0 {
            return Err(ProtocolError::InvalidField("initial_version"));
        }
        let scheduler = FairScheduler::new(
            limits.maximum_queued_bytes,
            limits.maximum_queued_bytes_per_stream,
            limits.maximum_control_frames,
        )?;
        Ok(Self {
            transport,
            local_role,
            phase,
            maximum_frame_size: limits.maximum_frame_size,
            limits,
            outbound_version: initial_version,
            selected_version: None,
            session_id: Vec::new(),
            next_send_sequence: 1,
            next_receive_sequence: 1,
            enabled_critical_extensions: BTreeSet::new(),
            enabled_capabilities: BTreeSet::new(),
            scheduler,
            flow: None,
            local_resolves: BTreeSet::new(),
            remote_resolves: BTreeSet::new(),
            maximum_seen_local_query_id: 0,
            maximum_seen_remote_query_id: 0,
        })
    }

    pub fn phase(&self) -> SessionPhase {
        self.phase
    }

    pub fn selected_version(&self) -> Option<&ProtocolVersion> {
        self.selected_version.as_ref()
    }

    pub fn queued_bytes(&self) -> usize {
        self.scheduler.queued_bytes()
    }

    pub fn flow_controller(&self) -> Option<&FlowController> {
        self.flow.as_ref()
    }

    pub fn into_inner(self) -> T {
        self.transport
    }

    pub(crate) fn configure_negotiated(&mut self, parameters: NegotiatedParameters) -> Result<()> {
        if parameters.selected_version.major == 0 || parameters.session_id.len() != 16 {
            return Err(ProtocolError::InvalidSession);
        }
        if parameters.maximum_frame_size == 0
            || parameters.maximum_frame_size > self.limits.maximum_frame_size
        {
            return Err(ProtocolError::InvalidField("negotiated_frame_size"));
        }
        let flow = FlowController::new(
            parameters.peer_connection_receive_window,
            parameters.local_connection_receive_window,
            parameters
                .maximum_concurrent_streams
                .min(self.limits.maximum_concurrent_streams),
        )?;
        let capabilities: Vec<String> = parameters.enabled_capabilities.iter().cloned().collect();
        validate_capabilities(&capabilities)?;
        if parameters.idle_stream_timeout.is_zero() {
            return Err(ProtocolError::InvalidField("idle_stream_timeout"));
        }
        self.outbound_version = parameters.selected_version.clone();
        self.selected_version = Some(parameters.selected_version);
        self.session_id = parameters.session_id;
        self.maximum_frame_size = parameters.maximum_frame_size;
        self.enabled_capabilities = parameters.enabled_capabilities;
        self.limits.idle_stream_timeout = parameters.idle_stream_timeout;
        self.flow = Some(flow);
        self.phase = parameters.next_phase;
        Ok(())
    }

    pub(crate) fn mark_active(&mut self) -> Result<()> {
        match self.phase {
            SessionPhase::AwaitingAuthentication | SessionPhase::AwaitingAuthenticationResult => {
                self.phase = SessionPhase::Active;
                Ok(())
            }
            _ => Err(ProtocolError::ProtocolViolation(
                "invalid active transition",
            )),
        }
    }

    pub(crate) fn set_granted_capabilities(&mut self, granted: &[String]) -> Result<()> {
        validate_capabilities(granted)?;
        let granted_set: BTreeSet<String> = granted.iter().cloned().collect();
        if granted_set.len() != granted.len()
            || granted_set
                .iter()
                .any(|capability| !self.enabled_capabilities.contains(capability))
        {
            return Err(ProtocolError::ProtocolViolation(
                "authentication granted an unnegotiated capability",
            ));
        }
        self.enabled_capabilities = granted_set;
        Ok(())
    }

    pub(crate) fn queue_handshake(&mut self, body: Body) -> Result<()> {
        match self.phase {
            SessionPhase::AwaitingServerHello
            | SessionPhase::AwaitingClientHello
            | SessionPhase::AwaitingAuthentication
            | SessionPhase::AwaitingAuthenticationResult => self.queue_control_body(body),
            _ => Err(ProtocolError::ProtocolViolation(
                "handshake already complete",
            )),
        }
    }

    pub fn open_tcp(&mut self, message: OpenTcpStream) -> Result<()> {
        self.require_active_client()?;
        self.require_capability(TCP_CONNECT_V1)?;
        let size = accounted_body_size(&Body::OpenTcpStream(message.clone()))?;
        self.scheduler.can_enqueue_control(size)?;
        self.flow_mut()?
            .open_local(message.stream_id, message.initial_receive_window)?;
        self.scheduler.enqueue_control(OutboundItem {
            body: Body::OpenTcpStream(message),
            accounted_bytes: size,
        })
    }

    pub fn accept_tcp(&mut self, stream_id: u64, initial_receive_window: u32) -> Result<()> {
        self.require_active_server()?;
        self.require_capability(TCP_CONNECT_V1)?;
        let body = Body::TcpStreamOpened(TcpStreamOpened {
            stream_id,
            initial_receive_window,
        });
        let size = accounted_body_size(&body)?;
        self.scheduler.can_enqueue_control(size)?;
        self.flow_mut()?
            .accept_remote_open(stream_id, initial_receive_window)?;
        self.scheduler.enqueue_control(OutboundItem {
            body,
            accounted_bytes: size,
        })
    }

    pub fn reject_tcp(&mut self, message: TcpStreamRejected) -> Result<()> {
        self.require_active_server()?;
        self.require_capability(TCP_CONNECT_V1)?;
        let size = accounted_body_size(&Body::TcpStreamRejected(message.clone()))?;
        self.scheduler.can_enqueue_control(size)?;
        self.flow_mut()?.reject_or_close(message.stream_id)?;
        self.scheduler.enqueue_control(OutboundItem {
            body: Body::TcpStreamRejected(message),
            accounted_bytes: size,
        })
    }

    /// Queues at most one DATA frame and returns the consumed prefix length.
    /// Callers retry the remainder after receiving WindowUpdate/backpressure.
    pub fn try_queue_data(&mut self, stream_id: u64, payload: &[u8]) -> Result<usize> {
        self.require_active_or_draining()?;
        self.require_capability(TCP_CONNECT_V1)?;
        validate_stream_id(stream_id)?;
        if payload.is_empty() {
            return Err(ProtocolError::InvalidField("data_payload"));
        }
        let consumed = payload.len().min(MAX_DATA_PAYLOAD);
        let body = Body::Data(Data {
            stream_id,
            payload: payload[..consumed].to_vec(),
        });
        let accounted = accounted_body_size(&body)?;
        self.scheduler.can_enqueue_stream(stream_id, accounted)?;
        self.flow_mut()?.debit_send(stream_id, consumed)?;
        self.scheduler.enqueue_stream(
            stream_id,
            OutboundItem {
                body,
                accounted_bytes: accounted,
            },
        )?;
        Ok(consumed)
    }

    pub fn grant_receive_credit(&mut self, stream_id: u64, credit: u32) -> Result<()> {
        self.require_active_or_draining()?;
        self.require_capability(FLOW_CONTROL_V1)?;
        let body = Body::WindowUpdate(WindowUpdate { stream_id, credit });
        let size = accounted_body_size(&body)?;
        self.scheduler.can_enqueue_control(size)?;
        self.flow_mut()?.grant_receive_credit(stream_id, credit)?;
        self.scheduler.enqueue_control(OutboundItem {
            body,
            accounted_bytes: size,
        })
    }

    pub fn half_close(&mut self, stream_id: u64) -> Result<()> {
        self.require_active_or_draining()?;
        self.require_capability(TCP_CONNECT_V1)?;
        let body = Body::HalfClose(HalfClose { stream_id });
        let size = accounted_body_size(&body)?;
        self.scheduler.can_enqueue_control(size)?;
        self.flow_mut()?.local_half_close(stream_id)?;
        self.scheduler.enqueue_control(OutboundItem {
            body,
            accounted_bytes: size,
        })
    }

    pub fn close_stream(&mut self, stream_id: u64, code: CloseCode) -> Result<()> {
        self.require_active_or_draining()?;
        self.require_capability(TCP_CONNECT_V1)?;
        if code == CloseCode::Unspecified {
            return Err(ProtocolError::InvalidField("close_code"));
        }
        let body = Body::CloseStream(CloseStream {
            stream_id,
            code: code as i32,
        });
        let size = accounted_body_size(&body)?;
        self.scheduler.can_enqueue_control(size)?;
        self.flow_mut()?.reject_or_close(stream_id)?;
        self.scheduler.cancel_stream(stream_id);
        self.scheduler.enqueue_control(OutboundItem {
            body,
            accounted_bytes: size,
        })
    }

    pub fn resolve(&mut self, message: ResolveDomain) -> Result<()> {
        self.require_active_client()?;
        self.require_capability(RESOLVE_DOMAIN_V1)?;
        if message.query_id <= self.maximum_seen_local_query_id
            || self.local_resolves.len() >= self.limits.maximum_outstanding_resolves
        {
            return Err(ProtocolError::InvalidStreamId);
        }
        let body = Body::ResolveDomain(message.clone());
        let size = accounted_body_size(&body)?;
        self.scheduler.can_enqueue_control(size)?;
        self.maximum_seen_local_query_id = message.query_id;
        self.local_resolves.insert(message.query_id);
        self.scheduler.enqueue_control(OutboundItem {
            body,
            accounted_bytes: size,
        })
    }

    pub fn resolve_result(&mut self, message: ResolveResult) -> Result<()> {
        self.require_active_server()?;
        self.require_capability(RESOLVE_DOMAIN_V1)?;
        if !self.remote_resolves.contains(&message.query_id) {
            return Err(ProtocolError::InvalidStreamId);
        }
        let body = Body::ResolveResult(message.clone());
        let size = accounted_body_size(&body)?;
        self.scheduler.can_enqueue_control(size)?;
        self.remote_resolves.remove(&message.query_id);
        self.scheduler.enqueue_control(OutboundItem {
            body,
            accounted_bytes: size,
        })
    }

    pub fn queue_control(&mut self, body: Body) -> Result<()> {
        self.require_active_or_draining()?;
        match body {
            Body::RotateSession(_) | Body::SessionRotated(_) => {
                self.require_capability(SESSION_ROTATION_V1)?;
                self.queue_control_body(body)
            }
            Body::Ping(_) | Body::Pong(_) | Body::Error(_) => self.queue_control_body(body),
            _ => Err(ProtocolError::ProtocolViolation(
                "message requires a typed session method",
            )),
        }
    }

    pub fn begin_go_away(&mut self, message: GoAway) -> Result<()> {
        self.require_active_or_draining()?;
        let body = Body::GoAway(message);
        self.queue_control_body(body)?;
        self.phase = SessionPhase::Draining;
        Ok(())
    }

    pub fn expire_idle_streams(&mut self, now: Instant) -> Result<Vec<u64>> {
        let expired = self
            .flow
            .as_ref()
            .map(|flow| flow.expire_idle(now, self.limits.idle_stream_timeout))
            .unwrap_or_default();
        for stream_id in &expired {
            self.close_stream(*stream_id, CloseCode::Timeout)?;
        }
        Ok(expired)
    }

    pub async fn flush_one(&mut self) -> Result<bool> {
        if self.phase == SessionPhase::Closed {
            return Err(ProtocolError::Closed);
        }
        let result = self.flush_one_inner().await;
        if result.is_err() {
            self.phase = SessionPhase::Closed;
        }
        result
    }

    async fn flush_one_inner(&mut self) -> Result<bool> {
        let Some(item) = self.scheduler.pop_next() else {
            return Ok(false);
        };
        let sequence = self.next_send_sequence;
        self.next_send_sequence = self
            .next_send_sequence
            .checked_add(1)
            .ok_or(ProtocolError::IntegerOverflow)?;
        let frame = GatewayFrame {
            sequence,
            version: Some(self.outbound_version.clone()),
            critical_extension_ids: Vec::new(),
            session_id: self.session_id.clone(),
            body: Some(item.body),
        };
        validate_frame(&frame, &self.enabled_critical_extensions)?;
        write_frame(&mut self.transport, &frame, self.maximum_frame_size).await?;
        Ok(true)
    }

    pub async fn flush_all(&mut self) -> Result<()> {
        while self.flush_one().await? {}
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Body> {
        let result = self.receive_inner().await;
        if result.is_err() {
            self.phase = SessionPhase::Closed;
        }
        result
    }

    async fn receive_inner(&mut self) -> Result<Body> {
        if self.phase == SessionPhase::Closed {
            return Err(ProtocolError::Closed);
        }
        let frame = read_frame(&mut self.transport, self.maximum_frame_size).await?;
        validate_frame(&frame, &self.enabled_critical_extensions)?;
        if frame.sequence != self.next_receive_sequence {
            self.phase = SessionPhase::Closed;
            return Err(ProtocolError::InvalidSequence);
        }
        self.next_receive_sequence = self
            .next_receive_sequence
            .checked_add(1)
            .ok_or(ProtocolError::IntegerOverflow)?;
        self.validate_frame_context(&frame)?;
        let body = frame.body.ok_or(ProtocolError::MissingBody)?;
        self.apply_inbound(&body)?;
        Ok(body)
    }

    fn validate_frame_context(&mut self, frame: &GatewayFrame) -> Result<()> {
        match self.phase {
            SessionPhase::AwaitingClientHello => match frame.body.as_ref() {
                Some(Body::ClientHello(hello))
                    if frame.session_id.is_empty()
                        && hello
                            .supported_versions
                            .as_ref()
                            .and_then(|range| range.maximum.as_ref())
                            == frame.version.as_ref() => {}
                _ => return Err(ProtocolError::InvalidSession),
            },
            SessionPhase::AwaitingServerHello => match frame.body.as_ref() {
                Some(Body::ServerHello(hello))
                    if frame.session_id == hello.ephemeral_session_id
                        && hello.selected_version.as_ref() == frame.version.as_ref() => {}
                Some(Body::Error(_)) | Some(Body::GoAway(_)) if frame.session_id.is_empty() => {}
                _ => return Err(ProtocolError::InvalidSession),
            },
            SessionPhase::AwaitingAuthentication
            | SessionPhase::AwaitingAuthenticationResult
            | SessionPhase::Active
            | SessionPhase::Draining => {
                if frame.session_id != self.session_id {
                    return Err(ProtocolError::InvalidSession);
                }
                let selected = self
                    .selected_version
                    .as_ref()
                    .ok_or(ProtocolError::InvalidSession)?;
                if frame.version.as_ref() != Some(selected) {
                    return Err(ProtocolError::ProtocolViolation(
                        "version changed after negotiation",
                    ));
                }
            }
            SessionPhase::Closed => return Err(ProtocolError::Closed),
        }
        Ok(())
    }

    fn apply_inbound(&mut self, body: &Body) -> Result<()> {
        match self.phase {
            SessionPhase::AwaitingClientHello => match body {
                Body::ClientHello(_) => Ok(()),
                _ => Err(ProtocolError::ProtocolViolation("expected ClientHello")),
            },
            SessionPhase::AwaitingServerHello => match body {
                Body::ServerHello(_) | Body::Error(_) | Body::GoAway(_) => Ok(()),
                _ => Err(ProtocolError::ProtocolViolation("expected ServerHello")),
            },
            SessionPhase::AwaitingAuthentication => match body {
                Body::Authenticate(_) | Body::Error(_) | Body::GoAway(_) => Ok(()),
                _ => Err(ProtocolError::ProtocolViolation("expected Authenticate")),
            },
            SessionPhase::AwaitingAuthenticationResult => match body {
                Body::AuthenticationResult(_) | Body::Error(_) | Body::GoAway(_) => Ok(()),
                _ => Err(ProtocolError::ProtocolViolation(
                    "expected AuthenticationResult",
                )),
            },
            SessionPhase::Active | SessionPhase::Draining => self.apply_active_inbound(body),
            SessionPhase::Closed => Err(ProtocolError::Closed),
        }
    }

    fn apply_active_inbound(&mut self, body: &Body) -> Result<()> {
        match body {
            Body::OpenTcpStream(message) => {
                self.require_capability(TCP_CONNECT_V1)?;
                if self.local_role != PeerRole::Server || self.phase == SessionPhase::Draining {
                    return Err(ProtocolError::ProtocolViolation("new stream not permitted"));
                }
                self.flow_mut()?
                    .receive_open(message.stream_id, message.initial_receive_window)
            }
            Body::TcpStreamOpened(message) => {
                self.require_capability(TCP_CONNECT_V1)?;
                if self.local_role != PeerRole::Client {
                    return Err(ProtocolError::ProtocolViolation("unexpected stream opened"));
                }
                self.flow_mut()?
                    .confirm_local_open(message.stream_id, message.initial_receive_window)
            }
            Body::TcpStreamRejected(message) => {
                self.require_capability(TCP_CONNECT_V1)?;
                if self.local_role != PeerRole::Client {
                    return Err(ProtocolError::ProtocolViolation(
                        "unexpected stream rejected",
                    ));
                }
                self.flow_mut()?.reject_or_close(message.stream_id)
            }
            Body::Data(message) => {
                self.require_capability(TCP_CONNECT_V1)?;
                self.flow_mut()?
                    .debit_receive(message.stream_id, message.payload.len())
            }
            Body::WindowUpdate(message) => {
                self.require_capability(FLOW_CONTROL_V1)?;
                self.flow_mut()?
                    .receive_window_update(message.stream_id, message.credit)
            }
            Body::HalfClose(message) => {
                self.require_capability(TCP_CONNECT_V1)?;
                self.flow_mut()?.receive_half_close(message.stream_id)
            }
            Body::CloseStream(message) => {
                self.require_capability(TCP_CONNECT_V1)?;
                self.scheduler.cancel_stream(message.stream_id);
                self.flow_mut()?.reject_or_close(message.stream_id)
            }
            Body::ResolveDomain(message) => {
                self.require_capability(RESOLVE_DOMAIN_V1)?;
                if self.local_role != PeerRole::Server || self.phase == SessionPhase::Draining {
                    return Err(ProtocolError::ProtocolViolation("resolve not permitted"));
                }
                if message.query_id <= self.maximum_seen_remote_query_id
                    || self.remote_resolves.len() >= self.limits.maximum_outstanding_resolves
                {
                    return Err(ProtocolError::InvalidStreamId);
                }
                self.maximum_seen_remote_query_id = message.query_id;
                self.remote_resolves.insert(message.query_id);
                Ok(())
            }
            Body::ResolveResult(message) => {
                self.require_capability(RESOLVE_DOMAIN_V1)?;
                if self.local_role != PeerRole::Client
                    || !self.local_resolves.remove(&message.query_id)
                {
                    return Err(ProtocolError::InvalidStreamId);
                }
                Ok(())
            }
            Body::GoAway(_) => {
                self.phase = SessionPhase::Draining;
                Ok(())
            }
            Body::Error(message) if message.fatal => {
                self.phase = SessionPhase::Closed;
                Ok(())
            }
            Body::ClientHello(_)
            | Body::ServerHello(_)
            | Body::Authenticate(_)
            | Body::AuthenticationResult(_) => Err(ProtocolError::ProtocolViolation(
                "handshake message after authentication",
            )),
            Body::RotateSession(_) | Body::SessionRotated(_) => {
                self.require_capability(SESSION_ROTATION_V1)
            }
            Body::Ping(_) | Body::Pong(_) | Body::Error(_) => Ok(()),
        }
    }

    fn queue_control_body(&mut self, body: Body) -> Result<()> {
        let size = accounted_body_size(&body)?;
        self.scheduler.enqueue_control(OutboundItem {
            body,
            accounted_bytes: size,
        })
    }

    fn flow_mut(&mut self) -> Result<&mut FlowController> {
        self.flow.as_mut().ok_or(ProtocolError::InvalidSession)
    }

    fn require_active_client(&self) -> Result<()> {
        if self.phase != SessionPhase::Active || self.local_role != PeerRole::Client {
            return Err(ProtocolError::Closed);
        }
        Ok(())
    }

    fn require_active_server(&self) -> Result<()> {
        if self.phase != SessionPhase::Active || self.local_role != PeerRole::Server {
            return Err(ProtocolError::Closed);
        }
        Ok(())
    }

    fn require_active_or_draining(&self) -> Result<()> {
        if !matches!(self.phase, SessionPhase::Active | SessionPhase::Draining) {
            return Err(ProtocolError::Closed);
        }
        Ok(())
    }

    fn require_capability(&self, capability: &str) -> Result<()> {
        if !self.enabled_capabilities.contains(capability) {
            return Err(ProtocolError::ProtocolViolation(
                "capability was not negotiated and granted",
            ));
        }
        Ok(())
    }
}

fn accounted_body_size(body: &Body) -> Result<usize> {
    let frame = GatewayFrame {
        sequence: u64::MAX,
        version: Some(ProtocolVersion {
            major: u32::MAX,
            minor: u32::MAX,
        }),
        critical_extension_ids: Vec::new(),
        session_id: vec![0; 16],
        body: Some(body.clone()),
    };
    validate_frame(&frame, &BTreeSet::new())?;
    frame
        .encoded_len()
        .checked_add(FRAME_ACCOUNTING_OVERHEAD)
        .ok_or(ProtocolError::IntegerOverflow)
}

pub fn graceful_go_away(last_accepted_stream_id: u64, drain_timeout_ms: u32) -> GoAway {
    GoAway {
        last_accepted_stream_id,
        code: ErrorCode::Unspecified as i32,
        drain_timeout_ms,
    }
}
