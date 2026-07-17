//! EXPERIMENTAL Windows console host.
//!
//! This binary is intentionally separate from the production Windows Service
//! contract. It exercises authenticated, bounded IPC and an app-scoped Direct
//! Tor lifecycle. `Connected` is emitted only while this process owns the fixed
//! loopback proxy and a nonce-bound local route proof has been verified.

use std::{
    collections::{HashSet, VecDeque},
    env,
    ffi::{c_void, OsStr, OsString},
    fs, io, mem,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    ptr,
    time::Instant,
};

use async_trait::async_trait;
use onionroute_desktop_daemon::ConfirmationStore;
use onionroute_desktop_ipc::{
    decode_frame, encode_frame,
    v1::{
        envelope, event, request, response, AnonymityMode, ClientHello, CriticalAction, Envelope,
        ErrorCode, Event, EventTopic, GatewayStatus, KillSwitchState, LatencyBucket,
        PeerAuthMethod, ProtocolVersion, Request, Response, ResponseStatus, RotationKind,
        RouteRole, ServerHello, StateSnapshot, TunnelPhase,
    },
    AuthenticatedPeer, FrameError, PeerRole, IPC_V1, MAX_FRAME_BYTES,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
    sync::watch,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, HANDLE},
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        EqualSid, GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    },
    System::{
        Pipes::GetNamedPipeClientProcessId,
        Threading::{
            GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

use crate::prototype_route::{ManagedPrototypeRoute, PrototypeRoute, PrototypeRouteError};
use onionroute_desktop_daemon::platform::windows::{
    CONTROL_PIPE, CONTROL_PIPE_SDDL, MAX_PIPE_INSTANCES,
};

const HELP: &str = "OnionRoute experimental Windows daemon\n\
Usage:\n  onionroute-desktop-daemon.exe --experimental-console [--ui-exe ABSOLUTE_PATH]\n\
\nThis host is app-scoped and development-only. It does not install WFP filters,\n\
create Wintun, or provide a system VPN.\n";

#[derive(Debug, Error)]
pub(crate) enum HostError {
    #[error("invalid experimental daemon arguments")]
    Usage,
    #[error("local IPC I/O failed")]
    Io(#[from] io::Error),
    #[error("local IPC frame was rejected")]
    Frame(#[from] FrameError),
    #[error("local IPC peer was not authorized")]
    NotAuthorized,
    #[error("local IPC session violated the protocol")]
    Protocol,
    #[error("secure random generation is unavailable")]
    RandomUnavailable,
}

pub(crate) async fn run() -> Result<(), HostError> {
    let Some(config) = Config::from_args(env::args_os())? else {
        print!("{HELP}");
        return Ok(());
    };
    eprintln!(
        "EXPERIMENTAL: app-scoped Direct Tor control host; no system tunnel or kill switch is installed."
    );
    eprintln!("Application proxy: 127.0.0.1:19080; local Tor SOCKS: 127.0.0.1:19050.");

    let route = ManagedPrototypeRoute::new();
    let mut runtime = PrototypeRuntime::new(route);
    let (_shutdown_sender, shutdown_receiver) = watch::channel(false);
    let mut server = Box::pin(serve_named_pipe(
        &config.expected_ui_image,
        &mut runtime,
        shutdown_receiver,
    ));
    let mut ctrl_c = Box::pin(tokio::signal::ctrl_c());

    tokio::select! {
        result = &mut server => result,
        signal = &mut ctrl_c => {
            signal?;
            // Dropping the server future closes the pipe. The app-scoped route
            // is then explicitly stopped before process exit.
            drop(server);
            runtime.shutdown().await;
            Ok(())
        }
    }
}

struct Config {
    expected_ui_image: PathBuf,
}

impl Config {
    fn from_args(args: impl IntoIterator<Item = OsString>) -> Result<Option<Self>, HostError> {
        let mut args = args.into_iter();
        let executable = args.next().ok_or(HostError::Usage)?;
        let mut experimental = false;
        let mut help = false;
        let mut expected_ui_image = None;
        while let Some(argument) = args.next() {
            match argument.to_str() {
                Some("--experimental-console") => experimental = true,
                Some("--help") | Some("-h") => help = true,
                Some("--ui-exe") => {
                    if expected_ui_image.is_some() {
                        return Err(HostError::Usage);
                    }
                    expected_ui_image = Some(PathBuf::from(args.next().ok_or(HostError::Usage)?));
                }
                _ => return Err(HostError::Usage),
            }
        }
        if help {
            return Ok(None);
        }
        if !experimental {
            return Err(HostError::Usage);
        }
        let executable = absolute_existing_path(Path::new(&executable))?;
        let default_ui = executable
            .parent()
            .ok_or(HostError::Usage)?
            .join("OnionRoute.App.exe");
        let expected_ui_image =
            absolute_existing_path(expected_ui_image.as_deref().unwrap_or(default_ui.as_path()))?;
        Ok(Some(Self { expected_ui_image }))
    }
}

struct PrototypeRuntime<R> {
    route: R,
    state: StateSnapshot,
}

impl<R: PrototypeRoute> PrototypeRuntime<R> {
    fn new(route: R) -> Self {
        Self {
            route,
            state: StateSnapshot {
                phase: TunnelPhase::Disconnected as i32,
                exit_country_code: String::new(),
                anonymity_mode: AnonymityMode::DirectTor as i32,
                tor_bootstrap_percent: 0,
                gateway_status: GatewayStatus::NotApplicable as i32,
                latency_bucket: LatencyBucket::NotAvailable as i32,
                kill_switch: KillSwitchState::Disabled as i32,
                blocked_leak_count: 0,
                udp_blocked: false,
                route_roles: Vec::new(),
                state_revision: 1,
            },
        }
    }

    fn snapshot(&self) -> StateSnapshot {
        self.state.clone()
    }

    fn transition(&mut self, phase: TunnelPhase, bootstrap: u32) {
        self.state.phase = phase as i32;
        self.state.tor_bootstrap_percent = bootstrap;
        self.state.anonymity_mode = AnonymityMode::DirectTor as i32;
        self.state.gateway_status = GatewayStatus::NotApplicable as i32;
        self.state.kill_switch = KillSwitchState::Disabled as i32;
        self.state.udp_blocked = false;
        self.state.state_revision = self.state.state_revision.saturating_add(1);
    }

    fn connected(&mut self) {
        self.transition(TunnelPhase::Connected, 100);
        self.state.route_roles = vec![RouteRole::Tor as i32];
    }

    fn disconnected(&mut self) {
        self.transition(TunnelPhase::Disconnected, 0);
        self.state.route_roles.clear();
    }

    fn blocked(&mut self) {
        self.transition(TunnelPhase::Blocked, 0);
        self.state.route_roles.clear();
    }

    async fn shutdown(&mut self) {
        if self.route.stop().await.is_ok() {
            self.disconnected();
        } else {
            self.blocked();
        }
    }
}

async fn serve_named_pipe<R: PrototypeRoute>(
    expected_ui_image: &Path,
    runtime: &mut PrototypeRuntime<R>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), HostError> {
    debug_assert!(MAX_PIPE_INSTANCES >= 1);
    let mut descriptor = OwnedSecurityDescriptor::from_sddl(CONTROL_PIPE_SDDL)?;
    let mut attributes = descriptor.attributes();
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .max_instances(1)
        .reject_remote_clients(true);
    let mut pipe = unsafe {
        options.create_with_security_attributes_raw(
            CONTROL_PIPE,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )?
    };

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            connected = pipe.connect() => connected?,
        }
        match authenticate_client(&pipe, expected_ui_image) {
            Ok(peer) => {
                let session_result =
                    serve_authenticated_stream(&mut pipe, peer, runtime, shutdown.clone()).await;
                if let Err(error) = session_result {
                    eprintln!("Experimental IPC session closed: {error}");
                }
            }
            Err(_) => eprintln!("Rejected an unauthorized local IPC client."),
        }
        pipe.disconnect()?;
        if *shutdown.borrow() {
            return Ok(());
        }
    }
}

async fn serve_authenticated_stream<S, R>(
    stream: &mut S,
    peer: AuthenticatedPeer,
    runtime: &mut PrototypeRuntime<R>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), HostError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: PrototypeRoute,
{
    let mut session = PrototypeSession::new(peer)?;
    loop {
        let incoming = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            }
            incoming = read_envelope(stream) => incoming?,
        };
        let Some(incoming) = incoming else {
            return Ok(());
        };
        session.accept_sequence(&incoming)?;
        let request_id = incoming.request_id;
        match incoming.body.ok_or(HostError::Protocol)? {
            envelope::Body::ClientHello(hello) if !session.hello_complete => {
                let response = session.accept_hello(request_id, hello)?;
                write_envelope(stream, &response).await?;
                session.publish_state(stream, runtime.snapshot()).await?;
            }
            envelope::Body::Request(request) if session.hello_complete => {
                let response = handle_request(&mut session, stream, runtime, request).await?;
                let response = session.reply(request_id, envelope::Body::Response(response))?;
                write_envelope(stream, &response).await?;
            }
            _ => return Err(HostError::Protocol),
        }
    }
}

async fn handle_request<S, R>(
    session: &mut PrototypeSession,
    stream: &mut S,
    runtime: &mut PrototypeRuntime<R>,
    request: Request,
) -> Result<Response, HostError>
where
    S: AsyncWrite + Unpin,
    R: PrototypeRoute,
{
    let Some(command) = request.command.as_ref() else {
        return Ok(rejected(ErrorCode::InvalidRequest));
    };
    if let Some(action) = critical_action(command) {
        if request.confirmation_id.is_empty() {
            let id = session
                .confirmations
                .issue(action, Instant::now())
                .map_err(|_| HostError::Protocol)?;
            return Ok(Response {
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
            });
        }
        if session
            .confirmations
            .consume(&request.confirmation_id, action, Instant::now())
            .is_err()
        {
            return Ok(rejected(ErrorCode::ConfirmationExpired));
        }
    }

    match command {
        request::Command::GetState(_) => Ok(ok_state(runtime.snapshot())),
        request::Command::Connect(_) => {
            if TunnelPhase::try_from(runtime.state.phase).ok() == Some(TunnelPhase::Connected)
                && runtime.route.is_active().await
            {
                return Ok(ok());
            }
            runtime.transition(TunnelPhase::Preparing, 0);
            session.publish_state(stream, runtime.snapshot()).await?;
            runtime.transition(TunnelPhase::BootstrappingTor, 25);
            session.publish_state(stream, runtime.snapshot()).await?;
            runtime.transition(TunnelPhase::ConnectingGateway, 75);
            session.publish_state(stream, runtime.snapshot()).await?;

            let started = runtime.route.start().await.is_ok() && runtime.route.is_active().await;
            if started {
                runtime.connected();
                let response = ok();
                session.publish_state(stream, runtime.snapshot()).await?;
                Ok(response)
            } else {
                let _ = runtime.route.stop().await;
                runtime.blocked();
                let response = rejected(ErrorCode::TorBootstrapFailed);
                session.publish_state(stream, runtime.snapshot()).await?;
                Ok(response)
            }
        }
        request::Command::Disconnect(_) => {
            runtime.transition(TunnelPhase::Disconnecting, 0);
            session.publish_state(stream, runtime.snapshot()).await?;
            let response = if runtime.route.stop().await.is_ok() {
                runtime.disconnected();
                ok()
            } else {
                runtime.blocked();
                rejected(ErrorCode::InternalRedacted)
            };
            session.publish_state(stream, runtime.snapshot()).await?;
            Ok(response)
        }
        request::Command::Rotate(_) => {
            // This prototype does not own a Tor control port. Rejecting the
            // request preserves the established route instead of pretending a
            // new identity was created or tearing down a healthy proxy.
            Ok(rejected(ErrorCode::InvalidRequest))
        }
        request::Command::SetAnonymityMode(value)
            if AnonymityMode::try_from(value.mode).ok() == Some(AnonymityMode::DirectTor) =>
        {
            Ok(ok())
        }
        request::Command::SetKillSwitch(value) if !value.enabled => Ok(ok()),
        request::Command::Subscribe(value) => {
            session.topics.clear();
            session.topics.extend(value.topics.iter().copied());
            session.event_window = value.event_window as usize;
            session.unacknowledged_events.clear();
            Ok(ok())
        }
        request::Command::AcknowledgeEvents(value) => {
            while session
                .unacknowledged_events
                .front()
                .is_some_and(|sequence| *sequence <= value.through_sequence)
            {
                session.unacknowledged_events.pop_front();
            }
            Ok(ok())
        }
        _ => Ok(rejected(ErrorCode::InvalidRequest)),
    }
}

struct PrototypeSession {
    hello_complete: bool,
    last_client_sequence: u64,
    next_server_sequence: u64,
    next_event_sequence: u64,
    event_window: usize,
    topics: HashSet<i32>,
    unacknowledged_events: VecDeque<u64>,
    confirmations: ConfirmationStore,
}

impl PrototypeSession {
    fn new(peer: AuthenticatedPeer) -> Result<Self, HostError> {
        if peer.role() != PeerRole::UnprivilegedUi {
            return Err(HostError::NotAuthorized);
        }
        Ok(Self {
            hello_complete: false,
            last_client_sequence: 0,
            next_server_sequence: 0,
            next_event_sequence: 0,
            event_window: 1,
            topics: HashSet::new(),
            unacknowledged_events: VecDeque::new(),
            confirmations: ConfirmationStore::default(),
        })
    }

    fn accept_sequence(&mut self, envelope: &Envelope) -> Result<(), HostError> {
        if envelope.sequence != self.last_client_sequence.saturating_add(1) {
            return Err(HostError::Protocol);
        }
        self.last_client_sequence = envelope.sequence;
        Ok(())
    }

    fn accept_hello(
        &mut self,
        request_id: Vec<u8>,
        hello: ClientHello,
    ) -> Result<Envelope, HostError> {
        self.hello_complete = true;
        self.event_window = hello.event_window as usize;
        self.topics.extend(hello.requested_topics);
        let mut process_nonce = vec![0_u8; 32];
        let mut session_id = vec![0_u8; 16];
        getrandom::getrandom(&mut process_nonce).map_err(|_| HostError::RandomUnavailable)?;
        getrandom::getrandom(&mut session_id).map_err(|_| HostError::RandomUnavailable)?;
        self.reply(
            request_id,
            envelope::Body::ServerHello(ServerHello {
                selected_version: Some(IPC_V1),
                process_nonce,
                session_id,
                peer_auth_method: PeerAuthMethod::WindowsTokenAndAcl as i32,
                event_window: self.event_window as u32,
            }),
        )
    }

    async fn publish_state<S: AsyncWrite + Unpin>(
        &mut self,
        stream: &mut S,
        state: StateSnapshot,
    ) -> Result<(), HostError> {
        if !self.topics.contains(&(EventTopic::TunnelState as i32)) {
            return Ok(());
        }
        if self.unacknowledged_events.len() >= self.event_window {
            return Err(HostError::Protocol);
        }
        self.next_event_sequence = self
            .next_event_sequence
            .checked_add(1)
            .ok_or(HostError::Protocol)?;
        let event_sequence = self.next_event_sequence;
        self.unacknowledged_events.push_back(event_sequence);
        let mut request_id = vec![0_u8; 16];
        getrandom::getrandom(&mut request_id).map_err(|_| HostError::RandomUnavailable)?;
        let envelope = self.reply(
            request_id,
            envelope::Body::Event(Event {
                topic: EventTopic::TunnelState as i32,
                event_sequence,
                payload: Some(event::Payload::StateChanged(state)),
            }),
        )?;
        write_envelope(stream, &envelope).await
    }

    fn reply(&mut self, request_id: Vec<u8>, body: envelope::Body) -> Result<Envelope, HostError> {
        self.next_server_sequence = self
            .next_server_sequence
            .checked_add(1)
            .ok_or(HostError::Protocol)?;
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

fn ok_state(state: StateSnapshot) -> Response {
    Response {
        payload: Some(response::Payload::State(state)),
        ..ok()
    }
}

fn rejected(error: ErrorCode) -> Response {
    Response {
        status: ResponseStatus::Rejected as i32,
        error_code: error as i32,
        support_code: String::new(),
        payload: None,
    }
}

async fn read_envelope<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Option<Envelope>, HostError> {
    let mut prefix = [0_u8; 4];
    match stream.read_exact(&mut prefix).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(HostError::Protocol);
    }
    let mut frame = vec![0_u8; 4 + length];
    frame[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut frame[4..]).await?;
    decode_frame(&frame).map(Some).map_err(Into::into)
}

async fn write_envelope<S: AsyncWrite + Unpin>(
    stream: &mut S,
    envelope: &Envelope,
) -> Result<(), HostError> {
    let frame = encode_frame(envelope)?;
    stream.write_all(&frame).await?;
    stream.flush().await?;
    Ok(())
}

struct OwnedSecurityDescriptor(*mut c_void);

impl OwnedSecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, io::Error> {
        let wide: Vec<u16> = OsStr::new(sddl).encode_wide().chain(Some(0)).collect();
        let mut descriptor = ptr::null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if converted == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }

    fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn authenticate_client(
    pipe: &NamedPipeServer,
    expected_ui_image: &Path,
) -> Result<AuthenticatedPeer, HostError> {
    let pipe_handle = pipe.as_raw_handle().cast::<c_void>();
    let mut process_id = 0_u32;
    if unsafe { GetNamedPipeClientProcessId(pipe_handle, &mut process_id) } == 0 || process_id == 0
    {
        return Err(HostError::NotAuthorized);
    }
    let process = OwnedHandle::open_process(process_id)?;
    let actual_image = query_process_image(process.0)?;
    if normalized_existing_path(&actual_image)? != normalized_existing_path(expected_ui_image)? {
        return Err(HostError::NotAuthorized);
    }

    let client_token = OwnedHandle::open_token(process.0)?;
    let current_token = OwnedHandle::open_token(unsafe { GetCurrentProcess() })?;
    let client_identity = TokenIdentity::read(client_token.0)?;
    let current_identity = TokenIdentity::read(current_token.0)?;
    if unsafe { EqualSid(client_identity.sid(), current_identity.sid()) } == 0 {
        return Err(HostError::NotAuthorized);
    }

    let mut verified_process_id = 0_u32;
    if unsafe { GetNamedPipeClientProcessId(pipe_handle, &mut verified_process_id) } == 0
        || verified_process_id != process_id
    {
        return Err(HostError::NotAuthorized);
    }
    let mut random = [0_u8; 32];
    getrandom::getrandom(&mut random).map_err(|_| HostError::RandomUnavailable)?;
    let mut digest = Sha256::new();
    digest.update(random);
    digest.update(process_id.to_le_bytes());
    digest.update(normalized_existing_path(&actual_image)?.as_bytes());
    let binding: [u8; 32] = digest.finalize().into();
    Ok(AuthenticatedPeer::new(PeerRole::UnprivilegedUi, binding))
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn open_process(process_id: u32) -> Result<Self, HostError> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        if handle.is_null() {
            return Err(HostError::NotAuthorized);
        }
        Ok(Self(handle))
    }

    fn open_token(process: HANDLE) -> Result<Self, HostError> {
        let mut token = ptr::null_mut();
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 || token.is_null() {
            return Err(HostError::NotAuthorized);
        }
        Ok(Self(token))
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct TokenIdentity {
    storage: Vec<usize>,
}

impl TokenIdentity {
    fn read(token: HANDLE) -> Result<Self, HostError> {
        let mut required = 0_u32;
        unsafe {
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut required);
        }
        if required == 0 || required as usize > 64 * 1024 {
            return Err(HostError::NotAuthorized);
        }
        let words = (required as usize).div_ceil(mem::size_of::<usize>());
        let mut storage = vec![0_usize; words];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                storage.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(HostError::NotAuthorized);
        }
        Ok(Self { storage })
    }

    fn sid(&self) -> *mut c_void {
        unsafe { (*(self.storage.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }
}

fn query_process_image(process: HANDLE) -> Result<PathBuf, HostError> {
    let mut buffer = vec![0_u16; 32_768];
    let mut length = buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) } == 0
        || length == 0
    {
        return Err(HostError::NotAuthorized);
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

fn absolute_existing_path(path: &Path) -> Result<PathBuf, HostError> {
    if !path.is_absolute() {
        return Err(HostError::Usage);
    }
    fs::canonicalize(path).map_err(|_| HostError::Usage)
}

fn normalized_existing_path(path: &Path) -> Result<String, HostError> {
    let canonical = fs::canonicalize(path).map_err(|_| HostError::NotAuthorized)?;
    let value = canonical.to_string_lossy().replace('/', "\\");
    let value = value
        .strip_prefix(r"\\?\UNC\")
        .map(|tail| format!(r"\\{tail}"))
        .or_else(|| value.strip_prefix(r"\\?\").map(str::to_owned))
        .unwrap_or(value);
    Ok(value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use onionroute_desktop_ipc::v1::{
        envelope, event, request, ClientHello, ConnectRequest, ProtocolVersionRange, Request,
    };
    use tokio::io::{duplex, DuplexStream};

    use super::*;

    struct HarnessRoute {
        succeeds: bool,
        active: bool,
    }

    #[async_trait]
    impl PrototypeRoute for HarnessRoute {
        async fn start(&mut self) -> Result<(), PrototypeRouteError> {
            self.active = self.succeeds;
            if self.succeeds {
                Ok(())
            } else {
                Err(PrototypeRouteError::Unavailable)
            }
        }

        async fn stop(&mut self) -> Result<(), PrototypeRouteError> {
            self.active = false;
            Ok(())
        }

        async fn is_active(&self) -> bool {
            self.active
        }
    }

    fn hello() -> Envelope {
        Envelope {
            version: Some(IPC_V1),
            request_id: vec![1; 16],
            sequence: 1,
            body: Some(envelope::Body::ClientHello(ClientHello {
                supported_versions: Some(ProtocolVersionRange {
                    minimum: Some(IPC_V1),
                    maximum: Some(IPC_V1),
                }),
                process_nonce: vec![2; 32],
                requested_topics: vec![EventTopic::TunnelState as i32],
                event_window: 16,
            })),
        }
    }

    fn connect() -> Envelope {
        Envelope {
            version: Some(IPC_V1),
            request_id: vec![3; 16],
            sequence: 2,
            body: Some(envelope::Body::Request(Request {
                confirmation_id: Vec::new(),
                command: Some(request::Command::Connect(ConnectRequest {})),
            })),
        }
    }

    async fn send(stream: &mut DuplexStream, envelope: &Envelope) {
        write_envelope(stream, envelope).await.unwrap();
    }

    async fn receive(stream: &mut DuplexStream) -> Envelope {
        read_envelope(stream).await.unwrap().unwrap()
    }

    fn state_from_event(envelope: Envelope) -> StateSnapshot {
        let envelope::Body::Event(event) = envelope.body.unwrap() else {
            panic!("state event expected")
        };
        let event::Payload::StateChanged(state) = event.payload.unwrap() else {
            panic!("state payload expected")
        };
        state
    }

    #[tokio::test]
    async fn harness_route_can_connect_only_after_active_check_and_stays_direct_tor() {
        let (mut client, mut server) = duplex(128 * 1024);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut runtime = PrototypeRuntime::new(HarnessRoute {
                succeeds: true,
                active: false,
            });
            serve_authenticated_stream(
                &mut server,
                AuthenticatedPeer::new(PeerRole::UnprivilegedUi, [4; 32]),
                &mut runtime,
                shutdown_rx,
            )
            .await
            .unwrap();
            runtime
        });

        send(&mut client, &hello()).await;
        assert!(matches!(
            receive(&mut client).await.body,
            Some(envelope::Body::ServerHello(_))
        ));
        let initial = state_from_event(receive(&mut client).await);
        assert_eq!(
            TunnelPhase::try_from(initial.phase).unwrap(),
            TunnelPhase::Disconnected
        );

        send(&mut client, &connect()).await;
        for phase in [
            TunnelPhase::Preparing,
            TunnelPhase::BootstrappingTor,
            TunnelPhase::ConnectingGateway,
        ] {
            let state = state_from_event(receive(&mut client).await);
            assert_eq!(TunnelPhase::try_from(state.phase).unwrap(), phase);
            assert_eq!(
                AnonymityMode::try_from(state.anonymity_mode).unwrap(),
                AnonymityMode::DirectTor
            );
            assert_eq!(
                KillSwitchState::try_from(state.kill_switch).unwrap(),
                KillSwitchState::Disabled
            );
            assert_eq!(
                GatewayStatus::try_from(state.gateway_status).unwrap(),
                GatewayStatus::NotApplicable
            );
            assert!(!state.udp_blocked);
        }
        let connected = state_from_event(receive(&mut client).await);
        assert_eq!(
            TunnelPhase::try_from(connected.phase).unwrap(),
            TunnelPhase::Connected
        );
        let response = receive(&mut client).await;
        let envelope::Body::Response(response) = response.body.unwrap() else {
            panic!("response expected")
        };
        assert_eq!(
            ResponseStatus::try_from(response.status).unwrap(),
            ResponseStatus::Ok
        );
        drop(client);
        let runtime = task.await.unwrap();
        assert!(runtime.route.active);
    }

    #[tokio::test]
    async fn unavailable_route_finishes_blocked_and_never_connected() {
        let (mut client, mut server) = duplex(128 * 1024);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut runtime = PrototypeRuntime::new(HarnessRoute {
                succeeds: false,
                active: false,
            });
            serve_authenticated_stream(
                &mut server,
                AuthenticatedPeer::new(PeerRole::UnprivilegedUi, [5; 32]),
                &mut runtime,
                shutdown_rx,
            )
            .await
            .unwrap();
            runtime
        });

        send(&mut client, &hello()).await;
        receive(&mut client).await;
        receive(&mut client).await;
        send(&mut client, &connect()).await;
        for _ in 0..3 {
            receive(&mut client).await;
        }
        let blocked = state_from_event(receive(&mut client).await);
        assert_eq!(
            TunnelPhase::try_from(blocked.phase).unwrap(),
            TunnelPhase::Blocked
        );
        assert_eq!(
            KillSwitchState::try_from(blocked.kill_switch).unwrap(),
            KillSwitchState::Disabled
        );
        let response = receive(&mut client).await;
        let envelope::Body::Response(response) = response.body.unwrap() else {
            panic!("response expected")
        };
        assert_eq!(
            ResponseStatus::try_from(response.status).unwrap(),
            ResponseStatus::Rejected
        );
        assert_eq!(
            ErrorCode::try_from(response.error_code).unwrap(),
            ErrorCode::TorBootstrapFailed
        );
        drop(client);
        assert_eq!(
            TunnelPhase::try_from(task.await.unwrap().state.phase).unwrap(),
            TunnelPhase::Blocked
        );
    }
}
