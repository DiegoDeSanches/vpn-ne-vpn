//! Versioned, bounded inter-gateway protocol over an authenticated TLS stream.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use onionroute_gateway_protocol::flow::FlowController;
use onionroute_gateway_protocol::limits::{
    ABSOLUTE_MAX_FRAME_SIZE, MAX_CONNECTION_WINDOW, MAX_DATA_PAYLOAD, MAX_STREAM_WINDOW,
};
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::identity::PeerIdentity;
use crate::route::{GatewayRole, ProtocolVersion};
use crate::tls::AuthenticatedTls;
use crate::{ErrorCode, Result};

const MAX_SERVICE_ID: usize = 128;
const NONCE_SIZE: usize = 32;
const CONNECTION_ID_SIZE: usize = 16;
const BINDING_SIZE: usize = 32;
const MAX_CLOCK_SKEW: Duration = Duration::from_secs(60);
const MAX_REPLAY_ENTRIES: usize = 16_384;
const DEFAULT_REPLAY_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Clone, PartialEq, Message)]
pub struct InterGatewayFrame {
    #[prost(uint64, tag = "1")]
    pub sequence: u64,
    #[prost(message, optional, tag = "2")]
    pub version: Option<WireVersion>,
    #[prost(bytes = "vec", tag = "3")]
    pub connection_id: Vec<u8>,
    #[prost(
        oneof = "inter_gateway_frame::Body",
        tags = "10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22"
    )]
    pub body: Option<inter_gateway_frame::Body>,
}

pub mod inter_gateway_frame {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "10")]
        ClientHello(super::ClientHello),
        #[prost(message, tag = "11")]
        ServerHello(super::ServerHello),
        #[prost(message, tag = "12")]
        Finished(super::Finished),
        #[prost(message, tag = "13")]
        OpenSession(super::OpenSession),
        #[prost(message, tag = "14")]
        SessionOpened(super::SessionOpened),
        #[prost(message, tag = "15")]
        SessionRejected(super::SessionRejected),
        #[prost(message, tag = "16")]
        Data(super::Data),
        #[prost(message, tag = "17")]
        WindowUpdate(super::WindowUpdate),
        #[prost(message, tag = "18")]
        HalfClose(super::HalfClose),
        #[prost(message, tag = "19")]
        CloseSession(super::CloseSession),
        #[prost(message, tag = "20")]
        Ping(super::Ping),
        #[prost(message, tag = "21")]
        Pong(super::Pong),
        #[prost(message, tag = "22")]
        GoAway(super::GoAway),
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct WireVersion {
    #[prost(uint32, tag = "1")]
    pub major: u32,
    #[prost(uint32, tag = "2")]
    pub minor: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct ClientHello {
    #[prost(string, tag = "1")]
    pub service_id: String,
    #[prost(enumeration = "WireRole", tag = "2")]
    pub role: i32,
    #[prost(message, optional, tag = "3")]
    pub minimum_version: Option<WireVersion>,
    #[prost(message, optional, tag = "4")]
    pub maximum_version: Option<WireVersion>,
    #[prost(bytes = "vec", tag = "5")]
    pub nonce: Vec<u8>,
    #[prost(int64, tag = "6")]
    pub unix_seconds: i64,
    #[prost(uint32, tag = "7")]
    pub initial_connection_receive_window: u32,
    #[prost(uint32, tag = "8")]
    pub initial_session_receive_window: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct ServerHello {
    #[prost(string, tag = "1")]
    pub service_id: String,
    #[prost(enumeration = "WireRole", tag = "2")]
    pub role: i32,
    #[prost(message, optional, tag = "3")]
    pub selected_version: Option<WireVersion>,
    #[prost(bytes = "vec", tag = "4")]
    pub echoed_client_nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub server_nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub connection_id: Vec<u8>,
    #[prost(uint32, tag = "7")]
    pub maximum_concurrent_sessions: u32,
    #[prost(uint32, tag = "8")]
    pub initial_connection_receive_window: u32,
    #[prost(uint32, tag = "9")]
    pub initial_session_receive_window: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct Finished {
    #[prost(bytes = "vec", tag = "1")]
    pub exporter_binding: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct OpenSession {
    #[prost(uint64, tag = "1")]
    pub session_id: u64,
    #[prost(message, optional, tag = "2")]
    pub terminal_protocol_version: Option<WireVersion>,
    #[prost(uint32, tag = "3")]
    pub initial_receive_window: u32,
    #[prost(int64, tag = "4")]
    pub expires_at_unix_seconds: i64,
}

#[derive(Clone, PartialEq, Message)]
pub struct SessionOpened {
    #[prost(uint64, tag = "1")]
    pub session_id: u64,
    #[prost(uint32, tag = "2")]
    pub initial_receive_window: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct SessionRejected {
    #[prost(uint64, tag = "1")]
    pub session_id: u64,
    #[prost(enumeration = "RejectCode", tag = "2")]
    pub code: i32,
}

#[derive(Clone, PartialEq, Message)]
pub struct Data {
    #[prost(uint64, tag = "1")]
    pub session_id: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub payload: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct WindowUpdate {
    #[prost(uint64, tag = "1")]
    pub session_id: u64,
    #[prost(uint32, tag = "2")]
    pub credit: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct HalfClose {
    #[prost(uint64, tag = "1")]
    pub session_id: u64,
}

#[derive(Clone, PartialEq, Message)]
pub struct CloseSession {
    #[prost(uint64, tag = "1")]
    pub session_id: u64,
    #[prost(enumeration = "CloseCode", tag = "2")]
    pub code: i32,
}

#[derive(Clone, PartialEq, Message)]
pub struct Ping {
    #[prost(bytes = "vec", tag = "1")]
    pub nonce: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Pong {
    #[prost(bytes = "vec", tag = "1")]
    pub nonce: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GoAway {
    #[prost(uint64, tag = "1")]
    pub last_accepted_session_id: u64,
    #[prost(uint32, tag = "2")]
    pub drain_timeout_ms: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ::prost::Enumeration)]
#[repr(i32)]
pub enum WireRole {
    Unspecified = 0,
    Entry = 1,
    Exit = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ::prost::Enumeration)]
#[repr(i32)]
pub enum RejectCode {
    Unspecified = 0,
    Policy = 1,
    ResourceExhausted = 2,
    Draining = 3,
    Revoked = 4,
    Incompatible = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ::prost::Enumeration)]
#[repr(i32)]
pub enum CloseCode {
    Unspecified = 0,
    Finished = 1,
    Cancelled = 2,
    Timeout = 3,
    Protocol = 4,
    Revoked = 5,
}

#[derive(Clone, Debug)]
pub struct ProtocolLimits {
    pub maximum_frame_size: usize,
    pub maximum_concurrent_sessions: usize,
    pub initial_connection_window: u32,
    pub initial_session_window: u32,
    pub handshake_timeout: Duration,
    pub maximum_session_ttl: Duration,
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            maximum_frame_size: ABSOLUTE_MAX_FRAME_SIZE,
            maximum_concurrent_sessions: 512,
            initial_connection_window: 4 * 1024 * 1024,
            initial_session_window: 256 * 1024,
            handshake_timeout: Duration::from_secs(10),
            maximum_session_ttl: Duration::from_secs(60 * 60),
        }
    }
}

impl ProtocolLimits {
    pub fn validate(&self) -> Result<()> {
        if self.maximum_frame_size == 0
            || self.maximum_frame_size > ABSOLUTE_MAX_FRAME_SIZE
            || self.maximum_concurrent_sessions == 0
            || self.maximum_concurrent_sessions > 4096
            || self.initial_connection_window == 0
            || u64::from(self.initial_connection_window) > MAX_CONNECTION_WINDOW
            || self.initial_session_window == 0
            || u64::from(self.initial_session_window) > MAX_STREAM_WINDOW
            || self.handshake_timeout.is_zero()
            || self.maximum_session_ttl.is_zero()
            || self.maximum_session_ttl > Duration::from_secs(24 * 60 * 60)
        {
            return Err(ErrorCode::InvalidConfiguration.into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct HandshakeConfig {
    pub minimum_version: ProtocolVersion,
    pub maximum_version: ProtocolVersion,
    pub limits: ProtocolLimits,
}

impl HandshakeConfig {
    pub fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        if self.minimum_version.major == 0
            || self.minimum_version.major != self.maximum_version.major
            || self.minimum_version > self.maximum_version
        {
            return Err(ErrorCode::InvalidConfiguration.into());
        }
        Ok(())
    }
}

/// Bounded replay cache for client application-handshake nonces. TLS 0-RTT and
/// resumption are disabled separately; the TLS exporter also binds Finished to
/// this exact connection.
pub struct ReplayCache {
    entries: Mutex<HashMap<(String, [u8; NONCE_SIZE]), Instant>>,
    ttl: Duration,
    maximum_entries: usize,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl: DEFAULT_REPLAY_TTL,
            maximum_entries: MAX_REPLAY_ENTRIES,
        }
    }
}

impl ReplayCache {
    pub fn check_and_insert(&self, service_id: &str, nonce: &[u8]) -> Result<()> {
        let nonce: [u8; NONCE_SIZE] = nonce.try_into().map_err(|_| ErrorCode::ProtocolViolation)?;
        let now = Instant::now();
        let mut entries = self.entries.lock().map_err(|_| ErrorCode::Internal)?;
        entries.retain(|_, inserted| now.duration_since(*inserted) <= self.ttl);
        let key = (service_id.to_owned(), nonce);
        if entries.contains_key(&key) {
            return Err(ErrorCode::ReplayDetected.into());
        }
        if entries.len() >= self.maximum_entries {
            return Err(ErrorCode::ResourceExhausted.into());
        }
        entries.insert(key, now);
        Ok(())
    }
}

pub struct ProtocolConnection<T> {
    transport: T,
    local_role: GatewayRole,
    peer: PeerIdentity,
    version: ProtocolVersion,
    connection_id: [u8; CONNECTION_ID_SIZE],
    next_send_sequence: u64,
    next_receive_sequence: u64,
    limits: ProtocolLimits,
    flow: FlowController,
    local_draining: bool,
    peer_draining: bool,
}

impl<T> ProtocolConnection<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn peer(&self) -> &PeerIdentity {
        &self.peer
    }

    pub fn version(&self) -> ProtocolVersion {
        self.version
    }

    pub fn is_draining(&self) -> bool {
        self.local_draining || self.peer_draining
    }

    pub fn flow(&self) -> &FlowController {
        &self.flow
    }

    pub fn into_inner(self) -> T {
        self.transport
    }

    pub async fn open_session(&mut self, request: OpenSession) -> Result<()> {
        if self.local_role != GatewayRole::Entry || self.is_draining() {
            return Err(ErrorCode::Draining.into());
        }
        validate_open_session(&request, &self.limits)?;
        self.flow
            .open_local(request.session_id, request.initial_receive_window)?;
        self.send(inter_gateway_frame::Body::OpenSession(request))
            .await
    }

    pub async fn accept_session(&mut self, session_id: u64) -> Result<()> {
        if self.local_role != GatewayRole::Exit || self.local_draining {
            return Err(ErrorCode::Draining.into());
        }
        self.flow
            .accept_remote_open(session_id, self.limits.initial_session_window)?;
        self.send(inter_gateway_frame::Body::SessionOpened(SessionOpened {
            session_id,
            initial_receive_window: self.limits.initial_session_window,
        }))
        .await
    }

    pub async fn reject_session(&mut self, session_id: u64, code: RejectCode) -> Result<()> {
        if self.local_role != GatewayRole::Exit || code == RejectCode::Unspecified {
            return Err(ErrorCode::ProtocolViolation.into());
        }
        self.flow.reject_or_close(session_id)?;
        self.send(inter_gateway_frame::Body::SessionRejected(
            SessionRejected {
                session_id,
                code: code as i32,
            },
        ))
        .await
    }

    /// Writes one bounded DATA frame. `Backpressure` means the caller must stop
    /// reading its upstream session until WindowUpdate arrives.
    pub async fn send_data(&mut self, session_id: u64, payload: &[u8]) -> Result<usize> {
        if payload.is_empty() {
            return Err(ErrorCode::ProtocolViolation.into());
        }
        let consumed = payload.len().min(MAX_DATA_PAYLOAD);
        self.flow.debit_send(session_id, consumed)?;
        self.send(inter_gateway_frame::Body::Data(Data {
            session_id,
            payload: payload[..consumed].to_vec(),
        }))
        .await?;
        Ok(consumed)
    }

    pub async fn grant_receive_credit(&mut self, session_id: u64, credit: u32) -> Result<()> {
        self.flow.grant_receive_credit(session_id, credit)?;
        self.send(inter_gateway_frame::Body::WindowUpdate(WindowUpdate {
            session_id,
            credit,
        }))
        .await
    }

    pub async fn half_close(&mut self, session_id: u64) -> Result<()> {
        self.flow.local_half_close(session_id)?;
        self.send(inter_gateway_frame::Body::HalfClose(HalfClose {
            session_id,
        }))
        .await
    }

    pub async fn close_session(&mut self, session_id: u64, code: CloseCode) -> Result<()> {
        if code == CloseCode::Unspecified {
            return Err(ErrorCode::ProtocolViolation.into());
        }
        self.flow.reject_or_close(session_id)?;
        self.send(inter_gateway_frame::Body::CloseSession(CloseSession {
            session_id,
            code: code as i32,
        }))
        .await
    }

    pub async fn begin_draining(&mut self, timeout: Duration) -> Result<()> {
        let timeout_ms =
            u32::try_from(timeout.as_millis()).map_err(|_| ErrorCode::InvalidConfiguration)?;
        if timeout_ms == 0 || timeout_ms > 30_000 {
            return Err(ErrorCode::InvalidConfiguration.into());
        }
        self.local_draining = true;
        self.send(inter_gateway_frame::Body::GoAway(GoAway {
            last_accepted_session_id: self.flow.maximum_seen_stream_id(),
            drain_timeout_ms: timeout_ms,
        }))
        .await
    }

    pub async fn next_event(&mut self) -> Result<inter_gateway_frame::Body> {
        let frame = read_frame(&mut self.transport, self.limits.maximum_frame_size).await?;
        validate_active_envelope(
            &frame,
            self.next_receive_sequence,
            self.version,
            &self.connection_id,
        )?;
        self.next_receive_sequence = self
            .next_receive_sequence
            .checked_add(1)
            .ok_or(ErrorCode::ProtocolViolation)?;
        let body = frame.body.ok_or(ErrorCode::ProtocolViolation)?;
        match &body {
            inter_gateway_frame::Body::OpenSession(request) => {
                if self.local_role != GatewayRole::Exit || self.local_draining {
                    return Err(ErrorCode::ProtocolViolation.into());
                }
                validate_open_session(request, &self.limits)?;
                self.flow
                    .receive_open(request.session_id, request.initial_receive_window)?;
            }
            inter_gateway_frame::Body::SessionOpened(opened) => {
                if self.local_role != GatewayRole::Entry {
                    return Err(ErrorCode::ProtocolViolation.into());
                }
                self.flow
                    .confirm_local_open(opened.session_id, opened.initial_receive_window)?;
            }
            inter_gateway_frame::Body::SessionRejected(rejected) => {
                if self.local_role != GatewayRole::Entry
                    || RejectCode::try_from(rejected.code)
                        .ok()
                        .filter(|code| *code != RejectCode::Unspecified)
                        .is_none()
                {
                    return Err(ErrorCode::ProtocolViolation.into());
                }
                self.flow.reject_or_close(rejected.session_id)?;
            }
            inter_gateway_frame::Body::Data(data) => {
                if data.payload.is_empty() || data.payload.len() > MAX_DATA_PAYLOAD {
                    return Err(ErrorCode::ProtocolViolation.into());
                }
                self.flow
                    .debit_receive(data.session_id, data.payload.len())?;
            }
            inter_gateway_frame::Body::WindowUpdate(update) => {
                self.flow
                    .receive_window_update(update.session_id, update.credit)?;
            }
            inter_gateway_frame::Body::HalfClose(close) => {
                self.flow.receive_half_close(close.session_id)?;
            }
            inter_gateway_frame::Body::CloseSession(close) => {
                if CloseCode::try_from(close.code)
                    .ok()
                    .filter(|code| *code != CloseCode::Unspecified)
                    .is_none()
                {
                    return Err(ErrorCode::ProtocolViolation.into());
                }
                self.flow.reject_or_close(close.session_id)?;
            }
            inter_gateway_frame::Body::Ping(ping) => validate_ping(&ping.nonce)?,
            inter_gateway_frame::Body::Pong(pong) => validate_ping(&pong.nonce)?,
            inter_gateway_frame::Body::GoAway(go_away) => {
                if go_away.drain_timeout_ms == 0 || go_away.drain_timeout_ms > 30_000 {
                    return Err(ErrorCode::ProtocolViolation.into());
                }
                self.peer_draining = true;
            }
            inter_gateway_frame::Body::ClientHello(_)
            | inter_gateway_frame::Body::ServerHello(_)
            | inter_gateway_frame::Body::Finished(_) => {
                return Err(ErrorCode::ProtocolViolation.into())
            }
        }
        Ok(body)
    }

    async fn send(&mut self, body: inter_gateway_frame::Body) -> Result<()> {
        let frame = InterGatewayFrame {
            sequence: self.next_send_sequence,
            version: Some(self.version.into()),
            connection_id: self.connection_id.to_vec(),
            body: Some(body),
        };
        validate_frame(&frame, false, &self.limits)?;
        write_frame(&mut self.transport, &frame, self.limits.maximum_frame_size).await?;
        self.next_send_sequence = self
            .next_send_sequence
            .checked_add(1)
            .ok_or(ErrorCode::ProtocolViolation)?;
        Ok(())
    }
}

pub async fn connect_entry<T>(
    mut tls: AuthenticatedTls<T>,
    local_identity: &PeerIdentity,
    config: HandshakeConfig,
) -> Result<ProtocolConnection<AuthenticatedTls<T>>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    config.validate()?;
    validate_handshake_identity(local_identity, GatewayRole::Entry)?;
    validate_handshake_identity(tls.peer(), GatewayRole::Exit)?;
    let peer = tls.peer().clone();
    let channel_binding = *tls.channel_binding();
    tokio::time::timeout(config.limits.handshake_timeout, async {
        let client_nonce = random_array::<NONCE_SIZE>()?;
        let hello = ClientHello {
            service_id: local_identity.service_id.clone(),
            role: WireRole::Entry as i32,
            minimum_version: Some(config.minimum_version.into()),
            maximum_version: Some(config.maximum_version.into()),
            nonce: client_nonce.to_vec(),
            unix_seconds: unix_now()?,
            initial_connection_receive_window: config.limits.initial_connection_window,
            initial_session_receive_window: config.limits.initial_session_window,
        };
        write_frame(
            &mut tls,
            &InterGatewayFrame {
                sequence: 1,
                version: Some(config.maximum_version.into()),
                connection_id: Vec::new(),
                body: Some(inter_gateway_frame::Body::ClientHello(hello.clone())),
            },
            config.limits.maximum_frame_size,
        )
        .await?;

        let frame = read_frame(&mut tls, config.limits.maximum_frame_size).await?;
        if frame.sequence != 1 || frame.connection_id.len() != CONNECTION_ID_SIZE {
            return Err(ErrorCode::ProtocolViolation.into());
        }
        let server = match frame.body {
            Some(inter_gateway_frame::Body::ServerHello(server)) => server,
            _ => return Err(ErrorCode::ProtocolViolation.into()),
        };
        validate_server_hello(&server, &peer, &hello, &config)?;
        let version = version_from_wire(
            server
                .selected_version
                .as_ref()
                .ok_or(ErrorCode::ProtocolViolation)?,
        )?;
        if frame.version.as_ref().map(version_from_wire).transpose()? != Some(version)
            || frame.connection_id != server.connection_id
        {
            return Err(ErrorCode::ProtocolViolation.into());
        }
        let connection_id: [u8; CONNECTION_ID_SIZE] = server
            .connection_id
            .as_slice()
            .try_into()
            .map_err(|_| ErrorCode::ProtocolViolation)?;
        let server_nonce: [u8; NONCE_SIZE] = server
            .server_nonce
            .as_slice()
            .try_into()
            .map_err(|_| ErrorCode::ProtocolViolation)?;

        let server_finished = read_frame(&mut tls, config.limits.maximum_frame_size).await?;
        let expected_server = finished_binding(
            &channel_binding,
            &client_nonce,
            &server_nonce,
            &connection_id,
            version,
            local_identity,
            &peer,
            b"server",
        );
        validate_finished_frame(
            &server_finished,
            2,
            version,
            &connection_id,
            &expected_server,
        )?;

        let client_finished = finished_binding(
            &channel_binding,
            &client_nonce,
            &server_nonce,
            &connection_id,
            version,
            local_identity,
            &peer,
            b"client",
        );
        write_frame(
            &mut tls,
            &InterGatewayFrame {
                sequence: 2,
                version: Some(version.into()),
                connection_id: connection_id.to_vec(),
                body: Some(inter_gateway_frame::Body::Finished(Finished {
                    exporter_binding: client_finished.to_vec(),
                })),
            },
            config.limits.maximum_frame_size,
        )
        .await?;

        let flow = FlowController::new(
            server.initial_connection_receive_window,
            config.limits.initial_connection_window,
            config
                .limits
                .maximum_concurrent_sessions
                .min(server.maximum_concurrent_sessions as usize),
        )?;
        Ok(ProtocolConnection {
            transport: tls,
            local_role: GatewayRole::Entry,
            peer,
            version,
            connection_id,
            next_send_sequence: 3,
            next_receive_sequence: 3,
            limits: config.limits,
            flow,
            local_draining: false,
            peer_draining: false,
        })
    })
    .await
    .map_err(|_| ErrorCode::Timeout)?
}

pub async fn accept_exit<T>(
    mut tls: AuthenticatedTls<T>,
    local_identity: &PeerIdentity,
    config: HandshakeConfig,
    replay_cache: &ReplayCache,
) -> Result<ProtocolConnection<AuthenticatedTls<T>>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    config.validate()?;
    validate_handshake_identity(local_identity, GatewayRole::Exit)?;
    validate_handshake_identity(tls.peer(), GatewayRole::Entry)?;
    let peer = tls.peer().clone();
    let channel_binding = *tls.channel_binding();
    tokio::time::timeout(config.limits.handshake_timeout, async {
        let frame = read_frame(&mut tls, config.limits.maximum_frame_size).await?;
        if frame.sequence != 1 || !frame.connection_id.is_empty() {
            return Err(ErrorCode::ProtocolViolation.into());
        }
        let hello = match frame.body {
            Some(inter_gateway_frame::Body::ClientHello(hello)) => hello,
            _ => return Err(ErrorCode::ProtocolViolation.into()),
        };
        validate_client_hello(&hello, &peer, &config)?;
        replay_cache.check_and_insert(&peer.service_id, &hello.nonce)?;
        let client_nonce: [u8; NONCE_SIZE] = hello
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| ErrorCode::ProtocolViolation)?;
        let selected = select_version(&hello, &config)?;
        let server_nonce = random_array::<NONCE_SIZE>()?;
        let connection_id = random_array::<CONNECTION_ID_SIZE>()?;
        let server = ServerHello {
            service_id: local_identity.service_id.clone(),
            role: WireRole::Exit as i32,
            selected_version: Some(selected.into()),
            echoed_client_nonce: client_nonce.to_vec(),
            server_nonce: server_nonce.to_vec(),
            connection_id: connection_id.to_vec(),
            maximum_concurrent_sessions: config.limits.maximum_concurrent_sessions as u32,
            initial_connection_receive_window: config.limits.initial_connection_window,
            initial_session_receive_window: config.limits.initial_session_window,
        };
        write_frame(
            &mut tls,
            &InterGatewayFrame {
                sequence: 1,
                version: Some(selected.into()),
                connection_id: connection_id.to_vec(),
                body: Some(inter_gateway_frame::Body::ServerHello(server)),
            },
            config.limits.maximum_frame_size,
        )
        .await?;
        let server_finished = finished_binding(
            &channel_binding,
            &client_nonce,
            &server_nonce,
            &connection_id,
            selected,
            &peer,
            local_identity,
            b"server",
        );
        write_frame(
            &mut tls,
            &InterGatewayFrame {
                sequence: 2,
                version: Some(selected.into()),
                connection_id: connection_id.to_vec(),
                body: Some(inter_gateway_frame::Body::Finished(Finished {
                    exporter_binding: server_finished.to_vec(),
                })),
            },
            config.limits.maximum_frame_size,
        )
        .await?;
        let client_finished = read_frame(&mut tls, config.limits.maximum_frame_size).await?;
        let expected_client = finished_binding(
            &channel_binding,
            &client_nonce,
            &server_nonce,
            &connection_id,
            selected,
            &peer,
            local_identity,
            b"client",
        );
        validate_finished_frame(
            &client_finished,
            2,
            selected,
            &connection_id,
            &expected_client,
        )?;
        let flow = FlowController::new(
            hello.initial_connection_receive_window,
            config.limits.initial_connection_window,
            config.limits.maximum_concurrent_sessions,
        )?;
        Ok(ProtocolConnection {
            transport: tls,
            local_role: GatewayRole::Exit,
            peer,
            version: selected,
            connection_id,
            next_send_sequence: 3,
            next_receive_sequence: 3,
            limits: config.limits,
            flow,
            local_draining: false,
            peer_draining: false,
        })
    })
    .await
    .map_err(|_| ErrorCode::Timeout)?
}

impl From<ProtocolVersion> for WireVersion {
    fn from(value: ProtocolVersion) -> Self {
        Self {
            major: u32::from(value.major),
            minor: u32::from(value.minor),
        }
    }
}

pub fn encode_frame(frame: &InterGatewayFrame, maximum: usize) -> Result<Vec<u8>> {
    if maximum == 0 || maximum > ABSOLUTE_MAX_FRAME_SIZE {
        return Err(ErrorCode::InvalidConfiguration.into());
    }
    let length = frame.encoded_len();
    if length == 0 || length > maximum {
        return Err(ErrorCode::ProtocolViolation.into());
    }
    let mut output = Vec::with_capacity(length.saturating_add(5));
    encode_u32_varint(
        u32::try_from(length).map_err(|_| ErrorCode::ProtocolViolation)?,
        &mut output,
    );
    frame.encode(&mut output)?;
    Ok(output)
}

pub async fn write_frame<W>(writer: &mut W, frame: &InterGatewayFrame, maximum: usize) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let encoded = encode_frame(frame, maximum)?;
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame<R>(reader: &mut R, maximum: usize) -> Result<InterGatewayFrame>
where
    R: AsyncRead + Unpin,
{
    if maximum == 0 || maximum > ABSOLUTE_MAX_FRAME_SIZE {
        return Err(ErrorCode::InvalidConfiguration.into());
    }
    let mut prefix = [0u8; 5];
    let mut used = 0usize;
    loop {
        if used == prefix.len() {
            return Err(ErrorCode::ProtocolViolation.into());
        }
        reader.read_exact(&mut prefix[used..used + 1]).await?;
        let byte = prefix[used];
        used += 1;
        if byte & 0x80 == 0 {
            break;
        }
    }
    let length = decode_canonical_u32_varint(&prefix[..used])? as usize;
    if length == 0 || length > maximum {
        return Err(ErrorCode::ProtocolViolation.into());
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).await?;
    decode_frame_bytes(&body, maximum)
}

/// Decodes one protobuf body after the length prefix has been removed. Kept
/// public for fuzzing and capture-free conformance tests.
pub fn decode_frame_bytes(body: &[u8], maximum: usize) -> Result<InterGatewayFrame> {
    if body.is_empty() || body.len() > maximum || maximum == 0 || maximum > ABSOLUTE_MAX_FRAME_SIZE
    {
        return Err(ErrorCode::ProtocolViolation.into());
    }
    let frame = InterGatewayFrame::decode(body)?;
    if frame.body.is_none() {
        return Err(ErrorCode::ProtocolViolation.into());
    }
    Ok(frame)
}

fn validate_frame(
    frame: &InterGatewayFrame,
    handshake: bool,
    limits: &ProtocolLimits,
) -> Result<()> {
    if frame.sequence == 0 || frame.version.is_none() || frame.body.is_none() {
        return Err(ErrorCode::ProtocolViolation.into());
    }
    if handshake {
        if frame.connection_id.len() > CONNECTION_ID_SIZE {
            return Err(ErrorCode::ProtocolViolation.into());
        }
    } else if frame.connection_id.len() != CONNECTION_ID_SIZE {
        return Err(ErrorCode::ProtocolViolation.into());
    }
    if frame.encoded_len() > limits.maximum_frame_size {
        return Err(ErrorCode::ProtocolViolation.into());
    }
    Ok(())
}

fn validate_active_envelope(
    frame: &InterGatewayFrame,
    sequence: u64,
    version: ProtocolVersion,
    connection_id: &[u8; CONNECTION_ID_SIZE],
) -> Result<()> {
    if frame.sequence != sequence
        || frame.connection_id != connection_id
        || frame.version.as_ref().map(version_from_wire).transpose()? != Some(version)
    {
        return Err(ErrorCode::ProtocolViolation.into());
    }
    Ok(())
}

fn validate_handshake_identity(identity: &PeerIdentity, role: GatewayRole) -> Result<()> {
    if identity.role != role
        || identity.purpose != crate::identity::IdentityPurpose::InterGatewayDataPlane
    {
        return Err(ErrorCode::WrongRole.into());
    }
    Ok(())
}

fn validate_client_hello(
    hello: &ClientHello,
    peer: &PeerIdentity,
    config: &HandshakeConfig,
) -> Result<()> {
    if hello.service_id != peer.service_id
        || hello.role != WireRole::Entry as i32
        || hello.nonce.len() != NONCE_SIZE
        || hello.initial_connection_receive_window == 0
        || u64::from(hello.initial_connection_receive_window) > MAX_CONNECTION_WINDOW
        || hello.initial_session_receive_window == 0
        || u64::from(hello.initial_session_receive_window) > MAX_STREAM_WINDOW
    {
        return Err(ErrorCode::ProtocolViolation.into());
    }
    validate_service_id(&hello.service_id)?;
    let sent = UNIX_EPOCH
        .checked_add(Duration::from_secs(
            u64::try_from(hello.unix_seconds).map_err(|_| ErrorCode::ProtocolViolation)?,
        ))
        .ok_or(ErrorCode::ProtocolViolation)?;
    let skew = SystemTime::now()
        .duration_since(sent)
        .or_else(|_| sent.duration_since(SystemTime::now()))
        .map_err(|_| ErrorCode::ProtocolViolation)?;
    if skew > MAX_CLOCK_SKEW {
        return Err(ErrorCode::ReplayDetected.into());
    }
    select_version(hello, config).map(|_| ())
}

fn validate_server_hello(
    server: &ServerHello,
    peer: &PeerIdentity,
    client: &ClientHello,
    config: &HandshakeConfig,
) -> Result<()> {
    let selected = version_from_wire(
        server
            .selected_version
            .as_ref()
            .ok_or(ErrorCode::ProtocolViolation)?,
    )?;
    if server.service_id != peer.service_id
        || server.role != WireRole::Exit as i32
        || server.echoed_client_nonce != client.nonce
        || server.server_nonce.len() != NONCE_SIZE
        || server.connection_id.len() != CONNECTION_ID_SIZE
        || selected < config.minimum_version
        || selected > config.maximum_version
        || selected != config.maximum_version
        || server.maximum_concurrent_sessions == 0
        || server.initial_connection_receive_window == 0
        || u64::from(server.initial_connection_receive_window) > MAX_CONNECTION_WINDOW
        || server.initial_session_receive_window == 0
        || u64::from(server.initial_session_receive_window) > MAX_STREAM_WINDOW
    {
        return Err(ErrorCode::ProtocolViolation.into());
    }
    validate_service_id(&server.service_id)
}

fn validate_finished_frame(
    frame: &InterGatewayFrame,
    sequence: u64,
    version: ProtocolVersion,
    connection_id: &[u8; CONNECTION_ID_SIZE],
    expected: &[u8; BINDING_SIZE],
) -> Result<()> {
    validate_active_envelope(frame, sequence, version, connection_id)?;
    let finished = match frame.body.as_ref() {
        Some(inter_gateway_frame::Body::Finished(finished)) => finished,
        _ => return Err(ErrorCode::ProtocolViolation.into()),
    };
    if finished.exporter_binding.as_slice() != expected {
        return Err(ErrorCode::ReplayDetected.into());
    }
    Ok(())
}

fn validate_open_session(request: &OpenSession, limits: &ProtocolLimits) -> Result<()> {
    if request.session_id == 0
        || request.session_id & 1 == 0
        || request.initial_receive_window == 0
        || u64::from(request.initial_receive_window) > MAX_STREAM_WINDOW
        || request.expires_at_unix_seconds <= unix_now()?
        || request.expires_at_unix_seconds
            > unix_now()?.saturating_add(
                i64::try_from(limits.maximum_session_ttl.as_secs())
                    .map_err(|_| ErrorCode::ProtocolViolation)?,
            )
    {
        return Err(ErrorCode::ProtocolViolation.into());
    }
    let version = request
        .terminal_protocol_version
        .as_ref()
        .ok_or(ErrorCode::ProtocolViolation)?;
    if version.major == 0
        || version.major > u32::from(u16::MAX)
        || version.minor > u32::from(u16::MAX)
    {
        return Err(ErrorCode::ProtocolViolation.into());
    }
    Ok(())
}

fn validate_service_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_SERVICE_ID
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ErrorCode::ProtocolViolation.into());
    }
    Ok(())
}

fn validate_ping(nonce: &[u8]) -> Result<()> {
    if !(8..=32).contains(&nonce.len()) {
        return Err(ErrorCode::ProtocolViolation.into());
    }
    Ok(())
}

fn select_version(hello: &ClientHello, config: &HandshakeConfig) -> Result<ProtocolVersion> {
    let minimum = version_from_wire(
        hello
            .minimum_version
            .as_ref()
            .ok_or(ErrorCode::ProtocolViolation)?,
    )?;
    let maximum = version_from_wire(
        hello
            .maximum_version
            .as_ref()
            .ok_or(ErrorCode::ProtocolViolation)?,
    )?;
    if minimum.major != maximum.major
        || minimum.major != config.minimum_version.major
        || minimum > maximum
    {
        return Err(ErrorCode::ProtocolIncompatible.into());
    }
    let lower = minimum.max(config.minimum_version);
    let upper = maximum.min(config.maximum_version);
    if lower > upper {
        return Err(ErrorCode::ProtocolIncompatible.into());
    }
    Ok(upper)
}

fn version_from_wire(version: &WireVersion) -> Result<ProtocolVersion> {
    Ok(ProtocolVersion {
        major: u16::try_from(version.major).map_err(|_| ErrorCode::ProtocolViolation)?,
        minor: u16::try_from(version.minor).map_err(|_| ErrorCode::ProtocolViolation)?,
    })
}

fn finished_binding(
    channel_binding: &[u8; BINDING_SIZE],
    client_nonce: &[u8; NONCE_SIZE],
    server_nonce: &[u8; NONCE_SIZE],
    connection_id: &[u8; CONNECTION_ID_SIZE],
    version: ProtocolVersion,
    entry: &PeerIdentity,
    exit: &PeerIdentity,
    direction: &[u8],
) -> [u8; BINDING_SIZE] {
    let mut digest = Sha256::new();
    digest.update(b"onionroute-inter-gateway-finished-v1\0");
    digest.update(channel_binding);
    digest.update(client_nonce);
    digest.update(server_nonce);
    digest.update(connection_id);
    digest.update(version.major.to_be_bytes());
    digest.update(version.minor.to_be_bytes());
    digest.update((entry.service_id.len() as u16).to_be_bytes());
    digest.update(entry.service_id.as_bytes());
    digest.update((exit.service_id.len() as u16).to_be_bytes());
    digest.update(exit.service_id.as_bytes());
    digest.update(direction);
    digest.finalize().into()
}

fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut value = [0u8; N];
    getrandom::getrandom(&mut value).map_err(|_| ErrorCode::Internal)?;
    Ok(value)
}

fn unix_now() -> Result<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ErrorCode::Internal)?
            .as_secs(),
    )
    .map_err(|_| ErrorCode::Internal.into())
}

fn encode_u32_varint(mut value: u32, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn decode_canonical_u32_varint(bytes: &[u8]) -> Result<u32> {
    if bytes.is_empty() || bytes.len() > 5 {
        return Err(ErrorCode::ProtocolViolation.into());
    }
    let mut value = 0u32;
    for (index, byte) in bytes.iter().copied().enumerate() {
        let bits = u32::from(byte & 0x7f);
        if index == 4 && bits > 0x0f {
            return Err(ErrorCode::ProtocolViolation.into());
        }
        value |= bits << (index * 7);
        if byte & 0x80 == 0 {
            if index + 1 != bytes.len() {
                return Err(ErrorCode::ProtocolViolation.into());
            }
            let minimum = if index == 0 { 0 } else { 1u32 << (index * 7) };
            if value < minimum {
                return Err(ErrorCode::ProtocolViolation.into());
            }
            return Ok(value);
        }
    }
    Err(ErrorCode::ProtocolViolation.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_cache_rejects_duplicate_nonce() {
        let cache = ReplayCache::default();
        let nonce = [7u8; NONCE_SIZE];
        cache.check_and_insert("entry-a", &nonce).unwrap();
        assert_eq!(
            cache.check_and_insert("entry-a", &nonce).unwrap_err().code,
            ErrorCode::ReplayDetected
        );
        cache.check_and_insert("entry-b", &nonce).unwrap();
    }

    #[test]
    fn non_canonical_prefix_is_rejected() {
        assert!(decode_canonical_u32_varint(&[0x81, 0x00]).is_err());
    }
}
