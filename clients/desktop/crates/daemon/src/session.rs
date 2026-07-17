use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use onionroute_desktop_ipc::{
    v1::{
        envelope, event, request, response, CriticalAction, DiagnosticsExportReady, Envelope,
        ErrorCode, Event, EventTopic, PeerAuthMethod, ProtocolVersion, Request, Response,
        ResponseStatus, RotationKind, ServerHello, TunnelPhase,
    },
    validate_envelope, AuthenticatedPeer, PeerRole, IPC_V1,
};
use thiserror::Error;

use crate::{
    ConfirmationError, ConfirmationStore, CoreControl, DaemonError, DaemonRuntime,
    DiagnosticSnapshot, DiagnosticsExporter, PlatformControl,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("local IPC peer is not an authenticated UI")]
    NotAuthorized,
    #[error("local IPC sequence or handshake is invalid")]
    Protocol,
    #[error("local IPC event window is full")]
    Backpressure,
    #[error("secure random generation is unavailable")]
    RandomUnavailable,
}

/// State for one already OS-authenticated IPC connection. Reconnect creates a
/// new session; daemon/core lifecycle state remains in `DaemonRuntime`.
pub struct IpcSession<P: PlatformControl, C: CoreControl> {
    _peer: AuthenticatedPeer,
    auth_method: PeerAuthMethod,
    runtime: Arc<DaemonRuntime<P, C>>,
    diagnostics: DiagnosticsExporter,
    confirmations: ConfirmationStore,
    hello_complete: bool,
    last_client_sequence: u64,
    next_server_sequence: u64,
    next_event_sequence: u64,
    event_window: usize,
    topics: HashSet<i32>,
    unacknowledged_events: VecDeque<u64>,
}

impl<P: PlatformControl, C: CoreControl> IpcSession<P, C> {
    pub fn new(
        peer: AuthenticatedPeer,
        auth_method: PeerAuthMethod,
        runtime: Arc<DaemonRuntime<P, C>>,
        diagnostics: DiagnosticsExporter,
    ) -> Result<Self, SessionError> {
        if peer.role() != PeerRole::UnprivilegedUi || auth_method == PeerAuthMethod::Unspecified {
            return Err(SessionError::NotAuthorized);
        }
        Ok(Self {
            _peer: peer,
            auth_method,
            runtime,
            diagnostics,
            confirmations: ConfirmationStore::default(),
            hello_complete: false,
            last_client_sequence: 0,
            next_server_sequence: 0,
            next_event_sequence: 0,
            event_window: 1,
            topics: HashSet::new(),
            unacknowledged_events: VecDeque::new(),
        })
    }

    pub async fn handle(
        &mut self,
        incoming: Envelope,
        monotonic_now: Instant,
        wall_now: SystemTime,
    ) -> Result<Envelope, SessionError> {
        validate_envelope(&incoming).map_err(|_| SessionError::Protocol)?;
        if incoming.sequence != self.last_client_sequence.saturating_add(1) {
            return Err(SessionError::Protocol);
        }
        self.last_client_sequence = incoming.sequence;
        let request_id = incoming.request_id;
        match incoming.body.ok_or(SessionError::Protocol)? {
            envelope::Body::ClientHello(hello) if !self.hello_complete => {
                self.hello_complete = true;
                self.event_window = hello.event_window as usize;
                self.topics.extend(hello.requested_topics);
                let mut nonce = vec![0_u8; 32];
                let mut session_id = vec![0_u8; 16];
                getrandom::getrandom(&mut nonce).map_err(|_| SessionError::RandomUnavailable)?;
                getrandom::getrandom(&mut session_id)
                    .map_err(|_| SessionError::RandomUnavailable)?;
                self.reply(
                    request_id,
                    envelope::Body::ServerHello(ServerHello {
                        selected_version: Some(IPC_V1),
                        process_nonce: nonce,
                        session_id,
                        peer_auth_method: self.auth_method as i32,
                        event_window: self.event_window as u32,
                    }),
                )
            }
            envelope::Body::Request(request) if self.hello_complete => {
                let response = self.handle_request(request, monotonic_now, wall_now).await;
                self.reply(request_id, envelope::Body::Response(response))
            }
            _ => Err(SessionError::Protocol),
        }
    }

    pub async fn state_event(&mut self) -> Result<Option<Envelope>, SessionError> {
        if !self.topics.contains(&(EventTopic::TunnelState as i32)) {
            return Ok(None);
        }
        if self.unacknowledged_events.len() >= self.event_window {
            return Err(SessionError::Backpressure);
        }
        self.next_event_sequence = self
            .next_event_sequence
            .checked_add(1)
            .ok_or(SessionError::Protocol)?;
        let event_sequence = self.next_event_sequence;
        self.unacknowledged_events.push_back(event_sequence);
        let mut request_id = vec![0_u8; 16];
        getrandom::getrandom(&mut request_id).map_err(|_| SessionError::RandomUnavailable)?;
        let event = Event {
            topic: EventTopic::TunnelState as i32,
            event_sequence,
            payload: Some(event::Payload::StateChanged(self.runtime.snapshot().await)),
        };
        self.reply(request_id, envelope::Body::Event(event))
            .map(Some)
    }

    async fn handle_request(
        &mut self,
        request: Request,
        monotonic_now: Instant,
        wall_now: SystemTime,
    ) -> Response {
        let Some(command) = request.command.as_ref() else {
            return rejected(ErrorCode::InvalidRequest);
        };
        if let Some(action) = critical_action(command) {
            match self.confirm(&request, action, monotonic_now) {
                Ok(Some(response)) => return response,
                Ok(None) => {}
                Err(_) => return rejected(ErrorCode::ConfirmationExpired),
            }
        }

        match command {
            request::Command::GetState(_) => ok_state(self.runtime.snapshot().await),
            request::Command::Connect(_) => result(self.runtime.connect().await),
            request::Command::Disconnect(value) => {
                result(self.runtime.disconnect(value.keep_kill_switch).await)
            }
            request::Command::SetKillSwitch(value) => {
                result(self.runtime.set_kill_switch_enabled(value.enabled).await)
            }
            request::Command::SetCountry(_)
            | request::Command::SetAnonymityMode(_)
            | request::Command::Rotate(_)
            | request::Command::UpdateSplitTunneling(_)
            | request::Command::UpdateSettings(_) => {
                result(self.runtime.apply_non_lifecycle_request(command).await)
            }
            request::Command::ExportDiagnostics(value) => self
                .export_diagnostics(wall_now, value.retention_hours)
                .await
                .unwrap_or_else(|_| rejected(ErrorCode::InternalRedacted)),
            request::Command::Subscribe(value) => {
                self.topics.clear();
                self.topics.extend(value.topics.iter().copied());
                self.event_window = value.event_window as usize;
                self.unacknowledged_events.clear();
                ok()
            }
            request::Command::AcknowledgeEvents(value) => {
                while self
                    .unacknowledged_events
                    .front()
                    .is_some_and(|sequence| *sequence <= value.through_sequence)
                {
                    self.unacknowledged_events.pop_front();
                }
                ok()
            }
        }
    }

    fn confirm(
        &mut self,
        request: &Request,
        action: CriticalAction,
        now: Instant,
    ) -> Result<Option<Response>, ConfirmationError> {
        if request.confirmation_id.is_empty() {
            let id = self.confirmations.issue(action, now)?;
            return Ok(Some(Response {
                status: ResponseStatus::ConfirmationRequired as i32,
                error_code: ErrorCode::Unspecified as i32,
                support_code: String::new(),
                payload: Some(response::Payload::Confirmation(
                    onionroute_desktop_ipc::v1::ConfirmationRequired {
                        action: action as i32,
                        confirmation_id: id.to_vec(),
                        expires_in_seconds: 60,
                    },
                )),
            }));
        }
        self.confirmations
            .consume(&request.confirmation_id, action, now)?;
        Ok(None)
    }

    async fn export_diagnostics(
        &self,
        wall_now: SystemTime,
        retention_hours: u32,
    ) -> Result<Response, crate::DiagnosticsError> {
        let state = self.runtime.snapshot().await;
        let phase = TunnelPhase::try_from(state.phase).unwrap_or(TunnelPhase::Blocked);
        let bucket = match state.tor_bootstrap_percent {
            0..=12 => 0,
            13..=37 => 25,
            38..=62 => 50,
            63..=87 => 75,
            _ => 100,
        };
        let metadata = self.diagnostics.export(
            DiagnosticSnapshot {
                app_version: env!("CARGO_PKG_VERSION").into(),
                daemon_version: env!("CARGO_PKG_VERSION").into(),
                os_family: std::env::consts::OS.into(),
                tunnel_phase: format!("{phase:?}").to_ascii_lowercase(),
                tor_bootstrap_bucket: bucket,
                gateway_status: format!("{:?}", state.gateway_status).to_ascii_lowercase(),
                latency_bucket: format!("{:?}", state.latency_bucket).to_ascii_lowercase(),
                kill_switch_state: format!("{:?}", state.kill_switch).to_ascii_lowercase(),
                blocked_leak_count: state.blocked_leak_count,
                events: Vec::new(),
            },
            wall_now,
            Duration::from_secs(u64::from(retention_hours) * 60 * 60),
        )?;
        let expires_at = metadata
            .expires_at
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or_default();
        Ok(Response {
            status: ResponseStatus::Ok as i32,
            error_code: ErrorCode::Unspecified as i32,
            support_code: String::new(),
            payload: Some(response::Payload::DiagnosticsExport(
                DiagnosticsExportReady {
                    export_id: metadata.export_id.to_vec(),
                    file_name: metadata.file_name,
                    expires_at_unix_seconds: expires_at,
                    sha256: metadata.sha256.to_vec(),
                },
            )),
        })
    }

    fn reply(
        &mut self,
        request_id: Vec<u8>,
        body: envelope::Body,
    ) -> Result<Envelope, SessionError> {
        self.next_server_sequence = self
            .next_server_sequence
            .checked_add(1)
            .ok_or(SessionError::Protocol)?;
        Ok(Envelope {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            request_id,
            sequence: self.next_server_sequence,
            body: Some(body),
        })
    }
}

fn critical_action(command: &request::Command) -> Option<CriticalAction> {
    match command {
        request::Command::Disconnect(value) if !value.keep_kill_switch => {
            Some(CriticalAction::DisconnectAndUnblock)
        }
        request::Command::SetKillSwitch(value) if !value.enabled => {
            Some(CriticalAction::DisableKillSwitch)
        }
        request::Command::Rotate(value)
            if RotationKind::try_from(value.kind).ok() == Some(RotationKind::HardNewIdentity) =>
        {
            Some(CriticalAction::HardRotation)
        }
        request::Command::UpdateSplitTunneling(_) => Some(CriticalAction::ReplaceSplitTunnelPolicy),
        _ => None,
    }
}

fn ok() -> Response {
    Response {
        status: ResponseStatus::Ok as i32,
        error_code: ErrorCode::Unspecified as i32,
        support_code: String::new(),
        payload: None,
    }
}

fn ok_state(state: onionroute_desktop_ipc::v1::StateSnapshot) -> Response {
    Response {
        payload: Some(response::Payload::State(state)),
        ..ok()
    }
}

fn rejected(code: ErrorCode) -> Response {
    Response {
        status: ResponseStatus::Rejected as i32,
        error_code: code as i32,
        support_code: String::new(),
        payload: None,
    }
}

fn result(result: Result<(), DaemonError>) -> Response {
    match result {
        Ok(()) => ok(),
        Err(DaemonError::KillSwitchNotVerified) => rejected(ErrorCode::KillSwitchFailed),
        Err(DaemonError::InvalidRequest) => rejected(ErrorCode::InvalidRequest),
        Err(DaemonError::Core | DaemonError::Platform) => rejected(ErrorCode::InternalRedacted),
    }
}
