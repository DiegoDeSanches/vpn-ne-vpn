use std::{
    sync::{Arc, Mutex},
    time::{Instant, SystemTime},
};

use async_trait::async_trait;
use onionroute_desktop_daemon::{
    CoreControl, CoreIntent, DaemonError, DaemonRuntime, DiagnosticsExporter, IpcSession,
    PlatformControl, RecoveryIntent, SessionError,
};
use onionroute_desktop_ipc::{
    v1::{
        envelope, request, response, ApplicationRule, ClientHello, CriticalAction, Envelope,
        EventTopic, PeerAuthMethod, ProtocolVersion, ProtocolVersionRange, Request, ResponseStatus,
        RotateRequest, RotationKind,
    },
    AuthenticatedPeer, PeerRole, IPC_V1,
};

#[derive(Default)]
struct Platform;

#[async_trait]
impl PlatformControl for Platform {
    async fn persist_recovery_intent(&self, _: RecoveryIntent) -> Result<(), DaemonError> {
        Ok(())
    }
    async fn engage_kill_switch(&self) -> Result<(), DaemonError> {
        Ok(())
    }
    async fn verify_kill_switch(&self) -> Result<bool, DaemonError> {
        Ok(true)
    }
    async fn disengage_kill_switch(&self) -> Result<(), DaemonError> {
        Ok(())
    }
    async fn start_packet_tunnel(&self) -> Result<(), DaemonError> {
        Ok(())
    }
    async fn stop_packet_tunnel(&self) -> Result<(), DaemonError> {
        Ok(())
    }
    async fn replace_split_policy(&self, _: &[ApplicationRule]) -> Result<(), DaemonError> {
        Ok(())
    }
}

#[derive(Default)]
struct Core {
    intents: Mutex<Vec<CoreIntent>>,
}

#[async_trait]
impl CoreControl for Core {
    async fn start(&self) -> Result<(), DaemonError> {
        Ok(())
    }
    async fn stop(&self) -> Result<(), DaemonError> {
        Ok(())
    }
    async fn apply(&self, intent: CoreIntent) -> Result<(), DaemonError> {
        self.intents.lock().unwrap().push(intent);
        Ok(())
    }
}

fn hello(sequence: u64, window: u32) -> Envelope {
    Envelope {
        version: Some(IPC_V1),
        request_id: vec![1; 16],
        sequence,
        body: Some(envelope::Body::ClientHello(ClientHello {
            supported_versions: Some(ProtocolVersionRange {
                minimum: Some(IPC_V1),
                maximum: Some(IPC_V1),
            }),
            process_nonce: vec![2; 32],
            requested_topics: vec![EventTopic::TunnelState as i32],
            event_window: window,
        })),
    }
}

fn command(sequence: u64, request: Request) -> Envelope {
    Envelope {
        version: Some(ProtocolVersion { major: 1, minor: 0 }),
        request_id: vec![sequence as u8; 16],
        sequence,
        body: Some(envelope::Body::Request(request)),
    }
}

fn session(core: Arc<Core>, directory: &std::path::Path) -> IpcSession<Platform, Core> {
    IpcSession::new(
        AuthenticatedPeer::new(PeerRole::UnprivilegedUi, [7; 32]),
        PeerAuthMethod::WindowsTokenAndAcl,
        Arc::new(DaemonRuntime::new(Arc::new(Platform), core)),
        DiagnosticsExporter::new(directory),
    )
    .unwrap()
}

#[tokio::test]
async fn hard_rotation_challenge_is_single_use_and_precedes_core_action() {
    let directory = tempfile::tempdir().unwrap();
    let core = Arc::new(Core::default());
    let mut session = session(core.clone(), directory.path());
    let now = Instant::now();
    session
        .handle(hello(1, 4), now, SystemTime::now())
        .await
        .unwrap();
    let rotation = request::Command::Rotate(RotateRequest {
        kind: RotationKind::HardNewIdentity as i32,
    });
    let first = session
        .handle(
            command(
                2,
                Request {
                    confirmation_id: Vec::new(),
                    command: Some(rotation.clone()),
                },
            ),
            now,
            SystemTime::now(),
        )
        .await
        .unwrap();
    assert!(core.intents.lock().unwrap().is_empty());
    let envelope::Body::Response(first) = first.body.unwrap() else {
        panic!("response expected")
    };
    assert_eq!(
        ResponseStatus::try_from(first.status).unwrap(),
        ResponseStatus::ConfirmationRequired
    );
    let response::Payload::Confirmation(challenge) = first.payload.unwrap() else {
        panic!("confirmation expected")
    };
    assert_eq!(
        CriticalAction::try_from(challenge.action).unwrap(),
        CriticalAction::HardRotation
    );

    let confirmed = Request {
        confirmation_id: challenge.confirmation_id.clone(),
        command: Some(rotation.clone()),
    };
    let second = session
        .handle(command(3, confirmed), now, SystemTime::now())
        .await
        .unwrap();
    let envelope::Body::Response(second) = second.body.unwrap() else {
        panic!("response expected")
    };
    assert_eq!(
        ResponseStatus::try_from(second.status).unwrap(),
        ResponseStatus::Ok
    );
    assert_eq!(
        core.intents.lock().unwrap().as_slice(),
        &[CoreIntent::HardRotation]
    );

    let replay = session
        .handle(
            command(
                4,
                Request {
                    confirmation_id: challenge.confirmation_id,
                    command: Some(rotation),
                },
            ),
            now,
            SystemTime::now(),
        )
        .await
        .unwrap();
    let envelope::Body::Response(replay) = replay.body.unwrap() else {
        panic!("response expected")
    };
    assert_eq!(
        ResponseStatus::try_from(replay.status).unwrap(),
        ResponseStatus::Rejected
    );
}

#[tokio::test]
async fn sequence_replay_and_event_window_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let mut session = session(Arc::new(Core::default()), directory.path());
    let now = Instant::now();
    session
        .handle(hello(1, 1), now, SystemTime::now())
        .await
        .unwrap();
    assert!(session.state_event().await.unwrap().is_some());
    assert_eq!(session.state_event().await, Err(SessionError::Backpressure));
    assert_eq!(
        session.handle(hello(1, 1), now, SystemTime::now()).await,
        Err(SessionError::Protocol)
    );
}

#[test]
fn daemon_session_refuses_the_wrong_os_authenticated_role() {
    let directory = tempfile::tempdir().unwrap();
    let result = IpcSession::new(
        AuthenticatedPeer::new(PeerRole::PrivilegedDaemon, [9; 32]),
        PeerAuthMethod::UnixPeercredAndAcl,
        Arc::new(DaemonRuntime::new(
            Arc::new(Platform),
            Arc::new(Core::default()),
        )),
        DiagnosticsExporter::new(directory.path()),
    );
    assert_eq!(result.err(), Some(SessionError::NotAuthorized));
}
