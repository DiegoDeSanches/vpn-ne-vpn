use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::binding::session_nonce_binding;
use crate::limits::ProtocolLimits;
use crate::negotiation::{
    verify_enabled_capabilities, verify_server_selection, version_range, FLOW_CONTROL_V1,
    TCP_CONNECT_V1,
};
use crate::proto::gateway_frame::Body;
use crate::proto::{
    AnonymityMode, Authenticate, ClientHello, ErrorCode, OpenTcpStream, ResolveDomain,
};
use crate::session::{NegotiatedParameters, Session, SessionPhase};
use crate::validation::validate_client_hello;
use crate::wire::onionroute::common::v1::ProtocolVersionRange;
use crate::{ProtocolError, Result};

pub type AuthenticationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AuthenticationMaterial>> + Send + 'a>>;

/// Opaque output of the separately reviewed anonymous-token implementation.
/// This type intentionally contains no account identifier.
pub struct AuthenticationMaterial {
    pub anonymous_capability_token: Vec<u8>,
    pub proof_of_possession: Vec<u8>,
}

pub trait ClientAuthenticator: Send {
    fn authentication_material<'a>(
        &'a mut self,
        session_binding: &'a [u8; 32],
    ) -> AuthenticationFuture<'a>;
}

/// Reference client hello policy. The session nonce is always generated inside
/// `connect` and cannot accidentally be reused by this config object.
#[derive(Clone)]
pub struct ClientConfig {
    pub supported_versions: ProtocolVersionRange,
    pub capabilities: Vec<String>,
    pub anonymity_mode: AnonymityMode,
    pub desired_country: String,
    pub limits: ProtocolLimits,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            supported_versions: version_range(1, 0, 0),
            capabilities: vec![
                format!("required:{TCP_CONNECT_V1}"),
                format!("required:{FLOW_CONTROL_V1}"),
            ],
            anonymity_mode: AnonymityMode::Standard,
            desired_country: String::new(),
            limits: ProtocolLimits::default(),
        }
    }
}

pub struct ClientReference<T> {
    session: Session<T>,
    granted_capabilities: Vec<String>,
}

impl<T> ClientReference<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn connect<A>(transport: T, config: ClientConfig, authenticator: A) -> Result<Self>
    where
        A: ClientAuthenticator,
    {
        let timeout = config.limits.handshake_timeout;
        tokio::time::timeout(
            timeout,
            Self::connect_inner(transport, config, authenticator),
        )
        .await
        .map_err(|_| ProtocolError::HandshakeTimeout)?
    }

    async fn connect_inner<A>(
        transport: T,
        config: ClientConfig,
        mut authenticator: A,
    ) -> Result<Self>
    where
        A: ClientAuthenticator,
    {
        config.limits.validate()?;
        let range = config.supported_versions.clone();
        let initial_version = range
            .maximum
            .clone()
            .ok_or(ProtocolError::InvalidField("maximum_version"))?;
        let mut client_nonce = [0u8; 32];
        getrandom::getrandom(&mut client_nonce).map_err(|_| ProtocolError::EntropyUnavailable)?;
        let hello = ClientHello {
            supported_versions: Some(range.clone()),
            client_capabilities: config.capabilities.clone(),
            anonymity_mode: config.anonymity_mode as i32,
            desired_country: config.desired_country,
            session_nonce: client_nonce.to_vec(),
            maximum_frame_size: config.limits.maximum_frame_size as u32,
            initial_connection_receive_window: config.limits.initial_connection_window,
            initial_stream_receive_window: config.limits.initial_stream_window,
        };
        validate_client_hello(&hello)?;

        let mut session = Session::new_client(transport, config.limits.clone(), initial_version)?;
        session.queue_handshake(Body::ClientHello(hello.clone()))?;
        session.flush_all().await?;

        let server_hello = match session.receive().await? {
            Body::ServerHello(hello) => hello,
            Body::Error(error) if error.code == ErrorCode::ProtocolIncompatible as i32 => {
                return Err(ProtocolError::IncompatibleVersion)
            }
            Body::Error(_) | Body::GoAway(_) => {
                return Err(ProtocolError::ProtocolViolation("hello rejected"))
            }
            _ => return Err(ProtocolError::ProtocolViolation("expected ServerHello")),
        };
        if server_hello.echoed_client_nonce != client_nonce {
            return Err(ProtocolError::InvalidSession);
        }
        let server_range = server_hello
            .supported_versions
            .as_ref()
            .ok_or(ProtocolError::InvalidField("server_supported_versions"))?;
        let selected = server_hello
            .selected_version
            .clone()
            .ok_or(ProtocolError::InvalidField("selected_version"))?;
        verify_server_selection(&range, server_range, &selected)?;
        verify_enabled_capabilities(&config.capabilities, &server_hello.enabled_capabilities)?;

        let negotiated_frame_size = config
            .limits
            .maximum_frame_size
            .min(server_hello.maximum_frame_size as usize);
        session.configure_negotiated(NegotiatedParameters {
            selected_version: selected.clone(),
            session_id: server_hello.ephemeral_session_id.clone(),
            maximum_frame_size: negotiated_frame_size,
            peer_connection_receive_window: server_hello.initial_connection_receive_window,
            local_connection_receive_window: hello.initial_connection_receive_window,
            maximum_concurrent_streams: server_hello.maximum_concurrent_streams as usize,
            enabled_capabilities: server_hello.enabled_capabilities.iter().cloned().collect(),
            idle_stream_timeout: config.limits.idle_stream_timeout.min(Duration::from_millis(
                u64::from(server_hello.idle_stream_timeout_ms),
            )),
            next_phase: SessionPhase::AwaitingAuthenticationResult,
        })?;
        let binding = session_nonce_binding(
            &hello.session_nonce,
            &server_hello.server_nonce,
            &server_hello.ephemeral_session_id,
            &selected,
        )?;
        let material = authenticator.authentication_material(&binding).await?;
        session.queue_handshake(Body::Authenticate(Authenticate {
            anonymous_capability_token: material.anonymous_capability_token,
            proof_of_possession: material.proof_of_possession,
            session_nonce_binding: binding.to_vec(),
        }))?;
        session.flush_all().await?;

        let result = match session.receive().await? {
            Body::AuthenticationResult(result) => result,
            Body::Error(_) | Body::GoAway(_) => return Err(ProtocolError::AuthenticationRejected),
            _ => {
                return Err(ProtocolError::ProtocolViolation(
                    "expected AuthenticationResult",
                ))
            }
        };
        if !result.accepted {
            return Err(ProtocolError::AuthenticationRejected);
        }
        verify_enabled_capabilities(
            &server_hello.enabled_capabilities,
            &result.granted_capabilities,
        )?;
        session.set_granted_capabilities(&result.granted_capabilities)?;
        session.mark_active()?;
        Ok(Self {
            session,
            granted_capabilities: result.granted_capabilities,
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

    pub fn open_tcp(&mut self, request: OpenTcpStream) -> Result<()> {
        self.session.open_tcp(request)
    }

    pub fn resolve(&mut self, request: ResolveDomain) -> Result<()> {
        self.session.resolve(request)
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.session.flush_all().await
    }

    pub async fn next_event(&mut self) -> Result<Body> {
        self.session.receive().await
    }
}
