//! Gateway protobuf v1 session server and bounded TCP stream multiplexer.

use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;

use crate::acl::Destination;
use crate::auth::{AuthenticationRequest, AuthenticationVerifier};
use crate::config::LimitConfig;
use crate::dns::DnsResolver;
use crate::egress::{BoxedIo, OpenedEgress, TcpEgressConnector};
use crate::health::{Metric, Metrics, PrivacyEventBuffer, PrivacyEventKind};
use crate::onionroute::common::v1::{ProtocolVersion, UnixTimestamp};
use crate::onionroute::gateway::v1::gateway_frame::Body;
use crate::onionroute::gateway::v1::{
    destination, AuthenticateResponse, Data, DnsResponse, GatewayFrame, HalfClose, OpenTcpResponse,
    Pong, ResetStream, ServerHello, SessionRole, WindowUpdate,
};
use crate::session::{SessionLease, SessionManager, StreamLease};
use crate::{GatewayError, GatewayErrorCode, GatewayResult};

const PROTOCOL_MAJOR: u32 = 1;
const PROTOCOL_MINOR: u32 = 0;
const SUPPORTED_FEATURES: &[&str] = &["tcp-connect-v1", "dns-wire-v1", "flow-control-v1"];

#[derive(Clone)]
pub struct ProtocolHandler {
    gateway_id: Arc<str>,
    limits: LimitConfig,
    verifier: Arc<dyn AuthenticationVerifier>,
    sessions: SessionManager,
    egress: TcpEgressConnector,
    resolver: Arc<dyn DnsResolver>,
    metrics: Arc<Metrics>,
    events: Arc<PrivacyEventBuffer>,
}

impl ProtocolHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        gateway_id: String,
        limits: LimitConfig,
        verifier: Arc<dyn AuthenticationVerifier>,
        sessions: SessionManager,
        egress: TcpEgressConnector,
        resolver: Arc<dyn DnsResolver>,
        metrics: Arc<Metrics>,
        events: Arc<PrivacyEventBuffer>,
    ) -> Self {
        Self {
            gateway_id: Arc::from(gateway_id),
            limits,
            verifier,
            sessions,
            egress,
            resolver,
            metrics,
            events,
        }
    }

    pub async fn serve_io<T>(&self, io: T) -> GatewayResult<()>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut client_reader, mut client_writer) = tokio::io::split(io);
        let (session_id, mut client_sequence, mut server_sequence) = self
            .handshake(&mut client_reader, &mut client_writer)
            .await?;
        let session = match self
            .authenticate(
                &mut client_reader,
                &mut client_writer,
                &session_id,
                &mut client_sequence,
                &mut server_sequence,
            )
            .await?
        {
            Some(session) => Arc::new(session),
            None => return Ok(()),
        };

        self.run_session(
            &mut client_reader,
            &mut client_writer,
            session_id,
            client_sequence,
            server_sequence,
            session,
        )
        .await
    }

    async fn handshake<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
    ) -> GatewayResult<(Vec<u8>, u64, u64)>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let frame = tokio::time::timeout(
            self.limits.handshake_timeout(),
            read_frame(reader, self.limits.max_frame_bytes),
        )
        .await
        .map_err(|_| GatewayErrorCode::Timeout)??
        .ok_or(GatewayErrorCode::ProtocolViolation)?;
        validate_envelope(&frame, 1, &[])?;
        let hello = match frame.body {
            Some(Body::ClientHello(hello)) => hello,
            _ => return Err(GatewayErrorCode::ProtocolViolation.into()),
        };
        validate_client_hello(&hello)?;

        let mut session_id = vec![0u8; 16];
        let mut server_nonce = vec![0u8; 16];
        getrandom::getrandom(&mut session_id).map_err(|_| GatewayErrorCode::Internal)?;
        getrandom::getrandom(&mut server_nonce).map_err(|_| GatewayErrorCode::Internal)?;
        let response = GatewayFrame {
            version: Some(version()),
            session_id: session_id.clone(),
            sequence: 1,
            body: Some(Body::ServerHello(ServerHello {
                selected_version: Some(version()),
                server_nonce,
                ephemeral_session_id: session_id.clone(),
                enabled_features: SUPPORTED_FEATURES
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                initial_stream_window: self.limits.initial_stream_window as u32,
                max_concurrent_streams: self.limits.max_streams_per_session as u32,
                session_ttl_seconds: self.limits.session_ttl_seconds as u32,
                gateway_id: self.gateway_id.to_string(),
                session_role: SessionRole::Exit as i32,
            })),
        };
        write_frame(writer, &response, self.limits.max_frame_bytes).await?;
        Ok((session_id, 2, 2))
    }

    async fn authenticate<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        session_id: &[u8],
        client_sequence: &mut u64,
        server_sequence: &mut u64,
    ) -> GatewayResult<Option<SessionLease>>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let frame = tokio::time::timeout(
            self.limits.handshake_timeout(),
            read_frame(reader, self.limits.max_frame_bytes),
        )
        .await
        .map_err(|_| GatewayErrorCode::Timeout)??
        .ok_or(GatewayErrorCode::ProtocolViolation)?;
        validate_envelope(&frame, *client_sequence, session_id)?;
        *client_sequence = client_sequence
            .checked_add(1)
            .ok_or(GatewayErrorCode::ProtocolViolation)?;
        let auth = match frame.body {
            Some(Body::AuthenticateRequest(auth)) => auth,
            _ => return Err(GatewayErrorCode::ProtocolViolation.into()),
        };
        if auth.capability_token.is_empty()
            || auth.capability_token.len() > self.limits.max_token_bytes
            || auth.proof_of_possession.len() > self.limits.max_proof_bytes
        {
            return self
                .write_auth_rejection(
                    writer,
                    session_id,
                    server_sequence,
                    GatewayErrorCode::TokenRejected.into(),
                )
                .await
                .map(|_| None);
        }

        let verification = tokio::time::timeout(
            self.limits.auth_timeout(),
            self.verifier.verify(AuthenticationRequest {
                capability_token: &auth.capability_token,
                proof_of_possession: &auth.proof_of_possession,
                now: SystemTime::now(),
            }),
        )
        .await;
        let grant = match verification {
            Ok(Ok(grant)) => grant,
            Ok(Err(error)) => {
                self.write_auth_rejection(writer, session_id, server_sequence, error)
                    .await?;
                return Ok(None);
            }
            Err(_) => {
                self.write_auth_rejection(
                    writer,
                    session_id,
                    server_sequence,
                    GatewayErrorCode::AuthenticationUnavailable.into(),
                )
                .await?;
                return Ok(None);
            }
        };
        let session = match self.sessions.register(&auth.capability_token, grant) {
            Ok(session) => session,
            Err(error) => {
                self.write_auth_rejection(writer, session_id, server_sequence, error)
                    .await?;
                return Ok(None);
            }
        };
        if !session.has_capability("tcp-connect-v1") && !session.has_capability("dns-wire-v1") {
            drop(session);
            self.write_auth_rejection(
                writer,
                session_id,
                server_sequence,
                GatewayErrorCode::TokenRejected.into(),
            )
            .await?;
            return Ok(None);
        }
        let expires_at = unix_timestamp(session.expires_at())?;
        let response = GatewayFrame {
            version: Some(version()),
            session_id: session_id.to_vec(),
            sequence: *server_sequence,
            body: Some(Body::AuthenticateResponse(AuthenticateResponse {
                accepted: true,
                expires_at: Some(expires_at),
                granted_capabilities: session.capabilities().to_vec(),
                error: None,
            })),
        };
        write_frame(writer, &response, self.limits.max_frame_bytes).await?;
        *server_sequence = server_sequence
            .checked_add(1)
            .ok_or(GatewayErrorCode::ProtocolViolation)?;
        self.metrics.increment(Metric::AcceptedSessions);
        Ok(Some(session))
    }

    async fn write_auth_rejection<W>(
        &self,
        writer: &mut W,
        session_id: &[u8],
        server_sequence: &mut u64,
        error: GatewayError,
    ) -> GatewayResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        self.metrics.increment(Metric::RejectedAuthentication);
        let _ = self
            .events
            .record(PrivacyEventKind::AuthenticationRejected, None);
        let response = GatewayFrame {
            version: Some(version()),
            session_id: session_id.to_vec(),
            sequence: *server_sequence,
            body: Some(Body::AuthenticateResponse(AuthenticateResponse {
                accepted: false,
                expires_at: None,
                granted_capabilities: Vec::new(),
                error: Some(error.to_status(random_correlation_id()?)),
            })),
        };
        write_frame(writer, &response, self.limits.max_frame_bytes).await?;
        *server_sequence = server_sequence.saturating_add(1);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_session<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        session_id: Vec<u8>,
        mut client_sequence: u64,
        mut server_sequence: u64,
        session: Arc<SessionLease>,
    ) -> GatewayResult<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let (event_tx, mut event_rx) = mpsc::channel(self.limits.outbound_event_queue);
        let mut streams: HashMap<u64, ActiveStream> = HashMap::new();
        let mut pending = HashSet::new();
        let mut highest_stream_id = 0u64;
        let expires_after = session
            .expires_at()
            .duration_since(SystemTime::now())
            .map_err(|_| GatewayErrorCode::SessionExpired)?;
        let expiry = tokio::time::sleep(expires_after);
        tokio::pin!(expiry);

        let result = loop {
            let idle = tokio::time::sleep(self.limits.io_timeout());
            tokio::pin!(idle);
            tokio::select! {
                _ = &mut expiry => break Err(GatewayErrorCode::SessionExpired.into()),
                _ = &mut idle => break Err(GatewayErrorCode::Timeout.into()),
                frame = read_frame(reader, self.limits.max_frame_bytes) => {
                    let Some(frame) = frame? else { break Ok(()) };
                    if let Err(error) = validate_envelope(&frame, client_sequence, &session_id) {
                        break Err(error);
                    }
                    client_sequence = client_sequence
                        .checked_add(1)
                        .ok_or(GatewayErrorCode::ProtocolViolation)?;
                    if let Err(error) = self.handle_client_frame(
                        frame,
                        writer,
                        &session_id,
                        &mut server_sequence,
                        &session,
                        &mut streams,
                        &mut pending,
                        &mut highest_stream_id,
                        event_tx.clone(),
                    ).await {
                        break Err(error);
                    }
                }
                event = event_rx.recv() => {
                    let Some(event) = event else { break Err(GatewayErrorCode::Internal.into()) };
                    if let Err(error) = self.handle_stream_event(
                        event,
                        writer,
                        &session_id,
                        &mut server_sequence,
                        &session,
                        &mut streams,
                        &mut pending,
                        event_tx.clone(),
                    ).await {
                        break Err(error);
                    }
                }
            }
        };

        for (_, stream) in streams.drain() {
            stream.reader_task.abort();
        }
        if let Err(error) = result {
            if matches!(
                error.code,
                GatewayErrorCode::ProtocolViolation
                    | GatewayErrorCode::MessageTooLarge
                    | GatewayErrorCode::ProtocolIncompatible
            ) {
                self.metrics.increment(Metric::ProtocolViolations);
                let _ = self
                    .events
                    .record(PrivacyEventKind::ProtocolRejected, Some(session.handle()));
            }
            let error_frame = GatewayFrame {
                version: Some(version()),
                session_id,
                sequence: server_sequence,
                body: Some(Body::Error(error.to_status(random_correlation_id()?))),
            };
            let _ = write_frame(writer, &error_frame, self.limits.max_frame_bytes).await;
            return Err(error);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_client_frame<W>(
        &self,
        frame: GatewayFrame,
        writer: &mut W,
        session_id: &[u8],
        server_sequence: &mut u64,
        session: &Arc<SessionLease>,
        streams: &mut HashMap<u64, ActiveStream>,
        pending: &mut HashSet<u64>,
        highest_stream_id: &mut u64,
        event_tx: mpsc::Sender<StreamEvent>,
    ) -> GatewayResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        match frame.body.ok_or(GatewayErrorCode::ProtocolViolation)? {
            Body::OpenTcpRequest(request) => {
                if request.stream_id == 0
                    || request.stream_id % 2 == 0
                    || request.stream_id <= *highest_stream_id
                    || request.port == 0
                    || request.port > u32::from(u16::MAX)
                    || request.initial_window == 0
                    || request.initial_window as usize > self.limits.max_stream_window
                    || streams.len().saturating_add(pending.len())
                        >= self.limits.max_streams_per_session
                {
                    return Err(GatewayErrorCode::ProtocolViolation.into());
                }
                let destination = decode_destination(request.destination)?;
                *highest_stream_id = request.stream_id;
                if !session.has_capability("tcp-connect-v1") {
                    self.metrics.increment(Metric::PolicyViolations);
                    let _ = self
                        .events
                        .record(PrivacyEventKind::PolicyRejected, Some(session.handle()));
                    self.send_body(
                        writer,
                        session_id,
                        server_sequence,
                        Body::OpenTcpResponse(OpenTcpResponse {
                            stream_id: request.stream_id,
                            opened: false,
                            error: Some(
                                GatewayError::new(GatewayErrorCode::PolicyDenied)
                                    .to_status(random_correlation_id()?),
                            ),
                        }),
                    )
                    .await?;
                    return Ok(());
                }
                pending.insert(request.stream_id);
                let egress = self.egress.clone();
                let session = session.clone();
                let stream_id = request.stream_id;
                let initial_window = request.initial_window as usize;
                tokio::spawn(async move {
                    let result = egress
                        .open(&session, destination, request.port as u16)
                        .await;
                    let _ = event_tx
                        .send(StreamEvent::Opened {
                            stream_id,
                            initial_window,
                            result,
                        })
                        .await;
                });
            }
            Body::Data(data) => {
                if data.payload.is_empty() || data.payload.len() > self.limits.max_data_bytes {
                    return Err(GatewayErrorCode::MessageTooLarge.into());
                }
                let remove = {
                    let stream = streams
                        .get_mut(&data.stream_id)
                        .ok_or(GatewayErrorCode::ProtocolViolation)?;
                    if stream.local_closed || data.payload.len() > stream.inbound_credit {
                        return Err(GatewayErrorCode::ProtocolViolation.into());
                    }
                    session.acquire_bandwidth(data.payload.len()).await?;
                    stream.inbound_credit -= data.payload.len();
                    let write_result = tokio::time::timeout(
                        self.limits.io_timeout(),
                        stream.writer.write_all(&data.payload),
                    )
                    .await;
                    let failed = !matches!(write_result, Ok(Ok(())));
                    if !failed {
                        stream.inbound_credit = stream
                            .inbound_credit
                            .checked_add(data.payload.len())
                            .ok_or(GatewayErrorCode::ProtocolViolation)?;
                    }
                    failed
                };
                if remove {
                    if let Some(stream) = streams.remove(&data.stream_id) {
                        stream.reader_task.abort();
                    }
                    self.send_reset(
                        writer,
                        session_id,
                        server_sequence,
                        data.stream_id,
                        GatewayErrorCode::EgressFailure.into(),
                    )
                    .await?;
                } else {
                    self.metrics
                        .add(Metric::BytesClientToEgress, data.payload.len() as u64);
                    self.send_body(
                        writer,
                        session_id,
                        server_sequence,
                        Body::WindowUpdate(WindowUpdate {
                            stream_id: data.stream_id,
                            credit: data.payload.len() as u32,
                        }),
                    )
                    .await?;
                }
            }
            Body::WindowUpdate(update) => {
                if update.credit == 0 {
                    return Err(GatewayErrorCode::ProtocolViolation.into());
                }
                let stream = streams
                    .get(&update.stream_id)
                    .ok_or(GatewayErrorCode::ProtocolViolation)?;
                stream.outbound_credit.grant(update.credit as usize)?;
            }
            Body::HalfClose(close) => {
                let remove = {
                    let stream = streams
                        .get_mut(&close.stream_id)
                        .ok_or(GatewayErrorCode::ProtocolViolation)?;
                    if stream.local_closed {
                        return Err(GatewayErrorCode::ProtocolViolation.into());
                    }
                    tokio::time::timeout(self.limits.io_timeout(), stream.writer.shutdown())
                        .await
                        .map_err(|_| GatewayErrorCode::Timeout)?
                        .map_err(|_| GatewayErrorCode::EgressFailure)?;
                    stream.local_closed = true;
                    stream.remote_closed
                };
                if remove {
                    if let Some(stream) = streams.remove(&close.stream_id) {
                        stream.reader_task.abort();
                    }
                    self.metrics.increment(Metric::ClosedStreams);
                }
            }
            Body::ResetStream(reset) => {
                let stream = streams
                    .remove(&reset.stream_id)
                    .ok_or(GatewayErrorCode::ProtocolViolation)?;
                stream.reader_task.abort();
                self.metrics.increment(Metric::ClosedStreams);
            }
            Body::DnsQuery(query) => {
                if !session.has_capability("dns-wire-v1") {
                    return Err(GatewayErrorCode::PolicyDenied.into());
                }
                if query.wire_query.is_empty() || query.wire_query.len() > 64 * 1024 {
                    return Err(GatewayErrorCode::MessageTooLarge.into());
                }
                let wire_response = self.resolver.exchange_wire(&query.wire_query).await?;
                self.send_body(
                    writer,
                    session_id,
                    server_sequence,
                    Body::DnsResponse(DnsResponse {
                        query_id: query.query_id,
                        wire_response,
                    }),
                )
                .await?;
            }
            Body::Ping(ping) => {
                if !(16..=32).contains(&ping.nonce.len()) {
                    return Err(GatewayErrorCode::ProtocolViolation.into());
                }
                self.send_body(
                    writer,
                    session_id,
                    server_sequence,
                    Body::Pong(Pong { nonce: ping.nonce }),
                )
                .await?;
            }
            Body::GoAway(_) => return Err(GatewayErrorCode::SessionExpired.into()),
            _ => return Err(GatewayErrorCode::ProtocolViolation.into()),
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_stream_event<W>(
        &self,
        event: StreamEvent,
        writer: &mut W,
        session_id: &[u8],
        server_sequence: &mut u64,
        session: &Arc<SessionLease>,
        streams: &mut HashMap<u64, ActiveStream>,
        pending: &mut HashSet<u64>,
        event_tx: mpsc::Sender<StreamEvent>,
    ) -> GatewayResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        match event {
            StreamEvent::Opened {
                stream_id,
                initial_window,
                result,
            } => {
                if !pending.remove(&stream_id) {
                    return Ok(());
                }
                match result {
                    Ok(opened) => {
                        let active = self.start_stream(
                            stream_id,
                            initial_window,
                            opened,
                            session.clone(),
                            event_tx,
                        );
                        streams.insert(stream_id, active);
                        self.send_body(
                            writer,
                            session_id,
                            server_sequence,
                            Body::OpenTcpResponse(OpenTcpResponse {
                                stream_id,
                                opened: true,
                                error: None,
                            }),
                        )
                        .await?;
                    }
                    Err(error) => {
                        self.send_body(
                            writer,
                            session_id,
                            server_sequence,
                            Body::OpenTcpResponse(OpenTcpResponse {
                                stream_id,
                                opened: false,
                                error: Some(error.to_status(random_correlation_id()?)),
                            }),
                        )
                        .await?;
                    }
                }
            }
            StreamEvent::Data { stream_id, payload } => {
                if !streams.contains_key(&stream_id) {
                    return Ok(());
                }
                self.metrics
                    .add(Metric::BytesEgressToClient, payload.len() as u64);
                self.send_body(
                    writer,
                    session_id,
                    server_sequence,
                    Body::Data(Data { stream_id, payload }),
                )
                .await?;
            }
            StreamEvent::HalfClosed { stream_id } => {
                let Some(stream) = streams.get_mut(&stream_id) else {
                    return Ok(());
                };
                stream.remote_closed = true;
                let remove = stream.local_closed;
                self.send_body(
                    writer,
                    session_id,
                    server_sequence,
                    Body::HalfClose(HalfClose { stream_id }),
                )
                .await?;
                if remove {
                    if let Some(stream) = streams.remove(&stream_id) {
                        stream.reader_task.abort();
                    }
                    self.metrics.increment(Metric::ClosedStreams);
                }
            }
            StreamEvent::Failed { stream_id, error } => {
                let Some(stream) = streams.remove(&stream_id) else {
                    return Ok(());
                };
                stream.reader_task.abort();
                self.send_reset(writer, session_id, server_sequence, stream_id, error)
                    .await?;
                self.metrics.increment(Metric::ClosedStreams);
            }
        }
        Ok(())
    }

    fn start_stream(
        &self,
        stream_id: u64,
        initial_window: usize,
        opened: OpenedEgress,
        session: Arc<SessionLease>,
        event_tx: mpsc::Sender<StreamEvent>,
    ) -> ActiveStream {
        let (reader, writer) = tokio::io::split(opened.io);
        let outbound_credit = Arc::new(FlowCredit::new(
            initial_window,
            self.limits.max_stream_window,
        ));
        let reader_credit = outbound_credit.clone();
        let max_data = self.limits.max_data_bytes;
        let io_timeout = self.limits.io_timeout();
        let reader_task = tokio::spawn(async move {
            pump_egress_reader(
                stream_id,
                reader,
                reader_credit,
                max_data,
                io_timeout,
                session,
                event_tx,
            )
            .await;
        });
        ActiveStream {
            writer,
            _permit: opened.permit,
            reader_task,
            outbound_credit,
            inbound_credit: self.limits.initial_stream_window,
            local_closed: false,
            remote_closed: false,
        }
    }

    async fn send_reset<W>(
        &self,
        writer: &mut W,
        session_id: &[u8],
        sequence: &mut u64,
        stream_id: u64,
        error: GatewayError,
    ) -> GatewayResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        self.send_body(
            writer,
            session_id,
            sequence,
            Body::ResetStream(ResetStream {
                stream_id,
                reason: Some(error.to_status(random_correlation_id()?)),
            }),
        )
        .await
    }

    async fn send_body<W>(
        &self,
        writer: &mut W,
        session_id: &[u8],
        sequence: &mut u64,
        body: Body,
    ) -> GatewayResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        let frame = GatewayFrame {
            version: Some(version()),
            session_id: session_id.to_vec(),
            sequence: *sequence,
            body: Some(body),
        };
        tokio::time::timeout(
            self.limits.io_timeout(),
            write_frame(writer, &frame, self.limits.max_frame_bytes),
        )
        .await
        .map_err(|_| GatewayErrorCode::Timeout)??;
        *sequence = sequence
            .checked_add(1)
            .ok_or(GatewayErrorCode::ProtocolViolation)?;
        Ok(())
    }
}

struct ActiveStream {
    writer: WriteHalf<BoxedIo>,
    _permit: StreamLease,
    reader_task: JoinHandle<()>,
    outbound_credit: Arc<FlowCredit>,
    inbound_credit: usize,
    local_closed: bool,
    remote_closed: bool,
}

enum StreamEvent {
    Opened {
        stream_id: u64,
        initial_window: usize,
        result: GatewayResult<OpenedEgress>,
    },
    Data {
        stream_id: u64,
        payload: Vec<u8>,
    },
    HalfClosed {
        stream_id: u64,
    },
    Failed {
        stream_id: u64,
        error: GatewayError,
    },
}

struct FlowCredit {
    semaphore: Arc<Semaphore>,
    outstanding: AtomicUsize,
    maximum: usize,
}

impl FlowCredit {
    fn new(initial: usize, maximum: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(initial)),
            outstanding: AtomicUsize::new(initial),
            maximum,
        }
    }

    fn grant(&self, amount: usize) -> GatewayResult<()> {
        self.outstanding
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(amount)
                    .filter(|next| *next <= self.maximum)
            })
            .map_err(|_| GatewayErrorCode::ProtocolViolation)?;
        self.semaphore.add_permits(amount);
        Ok(())
    }

    async fn acquire(&self, maximum: usize) -> GatewayResult<usize> {
        let available = self.semaphore.available_permits();
        let amount = available.max(1).min(maximum);
        let permits = self
            .semaphore
            .clone()
            .acquire_many_owned(amount as u32)
            .await
            .map_err(|_| GatewayErrorCode::SessionExpired)?;
        permits.forget();
        self.outstanding.fetch_sub(amount, Ordering::AcqRel);
        Ok(amount)
    }

    fn restore(&self, amount: usize) {
        if amount > 0 {
            self.outstanding.fetch_add(amount, Ordering::AcqRel);
            self.semaphore.add_permits(amount);
        }
    }
}

async fn pump_egress_reader(
    stream_id: u64,
    mut reader: ReadHalf<BoxedIo>,
    flow: Arc<FlowCredit>,
    max_data: usize,
    io_timeout: Duration,
    session: Arc<SessionLease>,
    event_tx: mpsc::Sender<StreamEvent>,
) {
    loop {
        let reserved = match flow.acquire(max_data).await {
            Ok(value) => value,
            Err(_) => return,
        };
        let mut buffer = vec![0u8; reserved];
        let read = tokio::time::timeout(io_timeout, reader.read(&mut buffer)).await;
        let received = match read {
            Ok(Ok(0)) => {
                flow.restore(reserved);
                let _ = event_tx.send(StreamEvent::HalfClosed { stream_id }).await;
                return;
            }
            Ok(Ok(received)) => received,
            Ok(Err(_)) => {
                let _ = event_tx
                    .send(StreamEvent::Failed {
                        stream_id,
                        error: GatewayErrorCode::EgressFailure.into(),
                    })
                    .await;
                return;
            }
            Err(_) => {
                let _ = event_tx
                    .send(StreamEvent::Failed {
                        stream_id,
                        error: GatewayErrorCode::Timeout.into(),
                    })
                    .await;
                return;
            }
        };
        flow.restore(reserved - received);
        buffer.truncate(received);
        if let Err(error) = session.acquire_bandwidth(received).await {
            let _ = event_tx
                .send(StreamEvent::Failed { stream_id, error })
                .await;
            return;
        }
        if event_tx
            .send(StreamEvent::Data {
                stream_id,
                payload: buffer,
            })
            .await
            .is_err()
        {
            return;
        }
    }
}

fn validate_client_hello(hello: &crate::onionroute::gateway::v1::ClientHello) -> GatewayResult<()> {
    let range = hello
        .supported_versions
        .as_ref()
        .ok_or(GatewayErrorCode::ProtocolIncompatible)?;
    let minimum = range
        .minimum
        .as_ref()
        .ok_or(GatewayErrorCode::ProtocolIncompatible)?;
    let maximum = range
        .maximum
        .as_ref()
        .ok_or(GatewayErrorCode::ProtocolIncompatible)?;
    if minimum.major != PROTOCOL_MAJOR
        || maximum.major != PROTOCOL_MAJOR
        || minimum.minor > PROTOCOL_MINOR
        || minimum.minor > maximum.minor
        || !(16..=32).contains(&hello.client_nonce.len())
        || hello.requested_features.len() > 32
        || hello
            .requested_features
            .iter()
            .any(|feature| feature.is_empty() || feature.len() > 64 || !feature.is_ascii())
    {
        return Err(GatewayErrorCode::ProtocolIncompatible.into());
    }
    for required in hello
        .requested_features
        .iter()
        .filter_map(|feature| feature.strip_prefix("required:"))
    {
        if !SUPPORTED_FEATURES.contains(&required) {
            return Err(GatewayErrorCode::ProtocolIncompatible.into());
        }
    }
    if !matches!(hello.route_mode, 1..=3) {
        return Err(GatewayErrorCode::ProtocolViolation.into());
    }
    Ok(())
}

fn validate_envelope(
    frame: &GatewayFrame,
    expected_sequence: u64,
    session_id: &[u8],
) -> GatewayResult<()> {
    let version = frame
        .version
        .as_ref()
        .ok_or(GatewayErrorCode::ProtocolViolation)?;
    if version.major != PROTOCOL_MAJOR
        || version.minor != PROTOCOL_MINOR
        || frame.sequence != expected_sequence
        || frame.session_id != session_id
    {
        return Err(GatewayErrorCode::ProtocolViolation.into());
    }
    Ok(())
}

fn decode_destination(
    destination: Option<crate::onionroute::gateway::v1::Destination>,
) -> GatewayResult<Destination> {
    let value = destination
        .and_then(|destination| destination.value)
        .ok_or(GatewayErrorCode::ProtocolViolation)?;
    match value {
        destination::Value::Hostname(hostname) => Ok(Destination::Hostname(hostname)),
        destination::Value::IpAddress(bytes) => match bytes.len() {
            4 => Ok(Destination::Ip(std::net::IpAddr::from([
                bytes[0], bytes[1], bytes[2], bytes[3],
            ]))),
            16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&bytes);
                Ok(Destination::Ip(std::net::IpAddr::from(octets)))
            }
            _ => Err(GatewayErrorCode::ProtocolViolation.into()),
        },
    }
}

fn version() -> ProtocolVersion {
    ProtocolVersion {
        major: PROTOCOL_MAJOR,
        minor: PROTOCOL_MINOR,
    }
}

fn unix_timestamp(time: SystemTime) -> GatewayResult<UnixTimestamp> {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GatewayErrorCode::TokenRejected)?
        .as_secs();
    Ok(UnixTimestamp {
        seconds: i64::try_from(seconds).map_err(|_| GatewayErrorCode::TokenRejected)?,
    })
}

fn random_correlation_id() -> GatewayResult<[u8; 16]> {
    let mut value = [0u8; 16];
    getrandom::getrandom(&mut value).map_err(|_| GatewayErrorCode::Internal)?;
    Ok(value)
}

pub async fn read_frame<R>(
    reader: &mut R,
    max_frame_bytes: usize,
) -> GatewayResult<Option<GatewayFrame>>
where
    R: AsyncRead + Unpin,
{
    let first = match reader.read_u8().await {
        Ok(byte) => byte,
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(_) => return Err(GatewayErrorCode::ProtocolViolation.into()),
    };
    let mut length = u64::from(first & 0x7f);
    let mut shift = 7u32;
    let mut byte = first;
    let mut prefix_bytes = 1usize;
    for _ in 1..5 {
        if byte & 0x80 == 0 {
            break;
        }
        byte = reader
            .read_u8()
            .await
            .map_err(|_| GatewayErrorCode::ProtocolViolation)?;
        prefix_bytes += 1;
        length |= u64::from(byte & 0x7f) << shift;
        shift += 7;
    }
    if byte & 0x80 != 0 || length == 0 || length > max_frame_bytes as u64 {
        return Err(GatewayErrorCode::MessageTooLarge.into());
    }
    let canonical_prefix_bytes = if length < (1 << 7) {
        1
    } else if length < (1 << 14) {
        2
    } else if length < (1 << 21) {
        3
    } else if length < (1 << 28) {
        4
    } else {
        5
    };
    if prefix_bytes != canonical_prefix_bytes {
        return Err(GatewayErrorCode::ProtocolViolation.into());
    }
    let mut encoded = vec![0u8; length as usize];
    reader
        .read_exact(&mut encoded)
        .await
        .map_err(|_| GatewayErrorCode::ProtocolViolation)?;
    GatewayFrame::decode(encoded.as_slice())
        .map(Some)
        .map_err(|_| GatewayErrorCode::ProtocolViolation.into())
}

pub async fn write_frame<W>(
    writer: &mut W,
    frame: &GatewayFrame,
    max_frame_bytes: usize,
) -> GatewayResult<()>
where
    W: AsyncWrite + Unpin,
{
    if frame.encoded_len() == 0 || frame.encoded_len() > max_frame_bytes {
        return Err(GatewayErrorCode::MessageTooLarge.into());
    }
    let mut encoded = Vec::with_capacity(frame.encoded_len() + 5);
    frame
        .encode_length_delimited(&mut encoded)
        .map_err(|_| GatewayErrorCode::Internal)?;
    writer
        .write_all(&encoded)
        .await
        .map_err(|_| GatewayErrorCode::ProtocolViolation)?;
    writer
        .flush()
        .await
        .map_err(|_| GatewayErrorCode::ProtocolViolation)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_allocation() {
        let mut input = &[0x81, 0x80, 0x04][..]; // 65,537 in protobuf varint.
        assert_eq!(
            read_frame(&mut input, 64 * 1024).await.unwrap_err().code,
            GatewayErrorCode::MessageTooLarge
        );
    }

    #[tokio::test]
    async fn truncated_frame_is_rejected() {
        let mut input = &[0x05, 0x08][..];
        assert_eq!(
            read_frame(&mut input, 64 * 1024).await.unwrap_err().code,
            GatewayErrorCode::ProtocolViolation
        );
    }

    #[tokio::test]
    async fn noncanonical_varint_prefix_is_rejected() {
        let mut input = &[0x81, 0x00, 0x00][..];
        assert_eq!(
            read_frame(&mut input, 64 * 1024).await.unwrap_err().code,
            GatewayErrorCode::ProtocolViolation
        );
    }

    #[tokio::test]
    async fn slow_client_partial_frame_is_bounded_by_caller_deadline() {
        let (mut client, mut server) = tokio::io::duplex(16);
        client.write_all(&[0x7f]).await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(10),
            read_frame(&mut server, 64 * 1024),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn flow_credit_blocks_reader_until_window_update() {
        let credit = Arc::new(FlowCredit::new(0, 32));
        let waiting = {
            let credit = credit.clone();
            tokio::spawn(async move { credit.acquire(16).await.unwrap() })
        };
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        credit.grant(8).unwrap();
        assert_eq!(waiting.await.unwrap(), 1);
    }

    #[test]
    fn sequence_and_session_are_strict() {
        let frame = GatewayFrame {
            version: Some(version()),
            session_id: vec![1; 16],
            sequence: 2,
            body: Some(Body::GoAway(crate::onionroute::gateway::v1::GoAway {
                last_accepted_stream_id: 0,
                reason: None,
            })),
        };
        assert!(validate_envelope(&frame, 2, &[1; 16]).is_ok());
        assert!(validate_envelope(&frame, 1, &[1; 16]).is_err());
        assert!(validate_envelope(&frame, 2, &[2; 16]).is_err());
    }
}
