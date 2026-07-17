use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::binding::session_nonce_binding;
use crate::limits::{ProtocolLimits, MAX_SESSION_TTL_SECONDS};
use crate::negotiation::{
    negotiate_capabilities, select_version, version_range, FLOW_CONTROL_V1, TCP_CONNECT_V1,
};
use crate::proto::gateway_frame::Body;
use crate::proto::{
    AuthenticationResult, Error, ErrorCode, ResolveResult, ServerHello, TcpStreamRejected,
};
use crate::session::{NegotiatedParameters, Session, SessionPhase};
use crate::wire::onionroute::common::v1::{ProtocolVersionRange, RetryHint};
use crate::{ProtocolError, Result};

pub type VerificationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AuthenticationDecision>> + Send + 'a>>;

/// Implemented by the anonymous capability-token crate. It receives only the
/// bounded token material and session binding, never an account context.
pub trait AuthenticationVerifier: Send {
    fn verify<'a>(
        &'a mut self,
        anonymous_capability_token: &'a [u8],
        proof_of_possession: &'a [u8],
        session_binding: &'a [u8; 32],
    ) -> VerificationFuture<'a>;
}

pub struct AuthenticationDecision {
    pub accepted: bool,
    pub expires_at_unix_seconds: i64,
    pub granted_capabilities: Vec<String>,
}

impl AuthenticationDecision {
    pub fn reject() -> Self {
        Self {
            accepted: false,
            expires_at_unix_seconds: 0,
            granted_capabilities: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct ServerConfig {
    pub supported_versions: ProtocolVersionRange,
    pub supported_capabilities: BTreeSet<String>,
    pub session_ttl_seconds: u32,
    pub limits: ProtocolLimits,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            supported_versions: version_range(1, 0, 0),
            supported_capabilities: BTreeSet::from([
                TCP_CONNECT_V1.to_owned(),
                FLOW_CONTROL_V1.to_owned(),
            ]),
            session_ttl_seconds: 3_600,
            limits: ProtocolLimits::default(),
        }
    }
}

pub struct ServerReference<T> {
    session: Session<T>,
    granted_capabilities: Vec<String>,
}

impl<T> ServerReference<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn accept<V>(transport: T, config: ServerConfig, verifier: V) -> Result<Self>
    where
        V: AuthenticationVerifier,
    {
        let timeout = config.limits.handshake_timeout;
        tokio::time::timeout(timeout, Self::accept_inner(transport, config, verifier))
            .await
            .map_err(|_| ProtocolError::HandshakeTimeout)?
    }

    async fn accept_inner<V>(transport: T, config: ServerConfig, mut verifier: V) -> Result<Self>
    where
        V: AuthenticationVerifier,
    {
        config.limits.validate()?;
        if config.session_ttl_seconds == 0 || config.session_ttl_seconds > MAX_SESSION_TTL_SECONDS {
            return Err(ProtocolError::InvalidField("session_ttl_seconds"));
        }
        let initial_version = config
            .supported_versions
            .maximum
            .clone()
            .ok_or(ProtocolError::InvalidField("maximum_version"))?;
        let mut session = Session::new_server(transport, config.limits.clone(), initial_version)?;
        let client_hello = match session.receive().await? {
            Body::ClientHello(hello) => hello,
            _ => return Err(ProtocolError::ProtocolViolation("expected ClientHello")),
        };
        let client_range = client_hello
            .supported_versions
            .as_ref()
            .ok_or(ProtocolError::InvalidField("client_supported_versions"))?;
        let selected = match select_version(client_range, &config.supported_versions) {
            Ok(selected) => selected,
            Err(error) => {
                send_incompatible(&mut session).await?;
                return Err(error);
            }
        };
        let enabled_capabilities = match negotiate_capabilities(
            &client_hello.client_capabilities,
            &config.supported_capabilities,
        ) {
            Ok(enabled) => enabled,
            Err(error) => {
                send_incompatible(&mut session).await?;
                return Err(error);
            }
        };

        let mut server_nonce = [0u8; 32];
        let mut session_id = [0u8; 16];
        getrandom::getrandom(&mut server_nonce).map_err(|_| ProtocolError::EntropyUnavailable)?;
        getrandom::getrandom(&mut session_id).map_err(|_| ProtocolError::EntropyUnavailable)?;
        let maximum_frame_size = config
            .limits
            .maximum_frame_size
            .min(client_hello.maximum_frame_size as usize);
        let idle_timeout_ms = u32::try_from(config.limits.idle_stream_timeout.as_millis())
            .map_err(|_| ProtocolError::InvalidField("idle_stream_timeout"))?;
        let server_hello = ServerHello {
            supported_versions: Some(config.supported_versions.clone()),
            selected_version: Some(selected.clone()),
            enabled_capabilities: enabled_capabilities.clone(),
            echoed_client_nonce: client_hello.session_nonce.clone(),
            server_nonce: server_nonce.to_vec(),
            ephemeral_session_id: session_id.to_vec(),
            maximum_frame_size: maximum_frame_size as u32,
            maximum_concurrent_streams: config.limits.maximum_concurrent_streams as u32,
            initial_connection_receive_window: config.limits.initial_connection_window,
            initial_stream_receive_window: config.limits.initial_stream_window,
            idle_stream_timeout_ms: idle_timeout_ms,
            session_ttl_seconds: config.session_ttl_seconds,
        };
        session.configure_negotiated(NegotiatedParameters {
            selected_version: selected.clone(),
            session_id: session_id.to_vec(),
            maximum_frame_size,
            peer_connection_receive_window: client_hello.initial_connection_receive_window,
            local_connection_receive_window: server_hello.initial_connection_receive_window,
            maximum_concurrent_streams: config.limits.maximum_concurrent_streams,
            enabled_capabilities: enabled_capabilities.iter().cloned().collect(),
            idle_stream_timeout: config.limits.idle_stream_timeout,
            next_phase: SessionPhase::AwaitingAuthentication,
        })?;
        session.queue_handshake(Body::ServerHello(server_hello.clone()))?;
        session.flush_all().await?;

        let authenticate = match session.receive().await? {
            Body::Authenticate(authenticate) => authenticate,
            _ => return Err(ProtocolError::ProtocolViolation("expected Authenticate")),
        };
        let expected_binding = session_nonce_binding(
            &client_hello.session_nonce,
            &server_nonce,
            &session_id,
            &selected,
        )?;
        if authenticate.session_nonce_binding != expected_binding {
            send_authentication_result(&mut session, AuthenticationDecision::reject()).await?;
            return Err(ProtocolError::AuthenticationRejected);
        }
        let decision = verifier
            .verify(
                &authenticate.anonymous_capability_token,
                &authenticate.proof_of_possession,
                &expected_binding,
            )
            .await?;
        if decision.accepted {
            crate::negotiation::verify_enabled_capabilities(
                &enabled_capabilities,
                &decision.granted_capabilities,
            )?;
            if decision.expires_at_unix_seconds <= 0 {
                return Err(ProtocolError::InvalidField("authentication_expiry"));
            }
        }
        let granted = decision.granted_capabilities.clone();
        let accepted = decision.accepted;
        send_authentication_result(&mut session, decision).await?;
        if !accepted {
            return Err(ProtocolError::AuthenticationRejected);
        }
        session.set_granted_capabilities(&granted)?;
        session.mark_active()?;
        Ok(Self {
            session,
            granted_capabilities: granted,
        })
    }

    pub fn granted_capabilities(&self) -> &[String] {
        &self.granted_capabilities
    }

    pub fn session(&self) -> &Session<T> {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut Session<T> {
        &mut self.session
    }

    pub fn accept_tcp(&mut self, stream_id: u64, initial_receive_window: u32) -> Result<()> {
        self.session.accept_tcp(stream_id, initial_receive_window)
    }

    pub fn reject_tcp(&mut self, rejection: TcpStreamRejected) -> Result<()> {
        self.session.reject_tcp(rejection)
    }

    pub fn resolve_result(&mut self, result: ResolveResult) -> Result<()> {
        self.session.resolve_result(result)
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.session.flush_all().await
    }

    pub async fn next_event(&mut self) -> Result<Body> {
        self.session.receive().await
    }
}

async fn send_incompatible<T>(session: &mut Session<T>) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut correlation_id = [0u8; 16];
    getrandom::getrandom(&mut correlation_id).map_err(|_| ProtocolError::EntropyUnavailable)?;
    session.queue_handshake(Body::Error(Error {
        code: ErrorCode::ProtocolIncompatible as i32,
        retry_hint: RetryHint::Never as i32,
        fatal: true,
        stream_id: 0,
        retry_after_ms: 0,
        correlation_id: correlation_id.to_vec(),
    }))?;
    session.flush_all().await
}

async fn send_authentication_result<T>(
    session: &mut Session<T>,
    decision: AuthenticationDecision,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    session.queue_handshake(Body::AuthenticationResult(AuthenticationResult {
        accepted: decision.accepted,
        error_code: if decision.accepted {
            ErrorCode::Unspecified as i32
        } else {
            ErrorCode::AuthenticationFailed as i32
        },
        granted_capabilities: decision.granted_capabilities,
        expires_at_unix_seconds: decision.expires_at_unix_seconds,
    }))?;
    session.flush_all().await
}
