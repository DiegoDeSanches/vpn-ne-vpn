//! Entry gateway orchestration over an already accepted Tor session.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::route::{
    select_enhanced_route, EnhancedRoute, GatewayDescriptor, RecentFailure, RoutePolicy,
};
use crate::{ErrorCode, Result};

pub trait RelayIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> RelayIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
pub type BoxedRelayIo = Pin<Box<dyn RelayIo>>;

/// The wrapper deliberately contains no SocketAddr/source IP. The onion-service
/// listener must discard that information before constructing this value.
pub struct TorSession<T> {
    io: T,
}

impl<T> TorSession<T> {
    pub fn from_anonymized_io(io: T) -> Self {
        Self { io }
    }
}

pub struct AnonymousCredential<'a> {
    pub token: &'a [u8],
    pub proof_of_possession: &'a [u8],
    pub session_binding: &'a [u8; 32],
}

#[derive(Clone, Debug)]
pub struct AnonymousGrant {
    pub expires_at: SystemTime,
    pub enhanced_allowed: bool,
    pub maximum_relay_bytes: u64,
}

#[async_trait]
pub trait AnonymousCredentialVerifier: Send + Sync + 'static {
    async fn verify(&self, credential: AnonymousCredential<'_>) -> Result<AnonymousGrant>;
}

#[async_trait]
pub trait RelaySessionFactory: Send + Sync + 'static {
    /// Opens one logical session on a bounded mTLS inter-gateway connection.
    /// Implementations own a `ConnectionPoolLimiter`, reuse only authenticated
    /// `ProtocolConnection`s, and call `ProtocolConnection::open_session`;
    /// direct TCP to an Internet destination is outside this interface.
    async fn open_relay(
        &self,
        route: &EnhancedRoute,
        expires_at: SystemTime,
    ) -> Result<BoxedRelayIo>;
}

pub struct EntrySessionRequest<'a, T> {
    pub tor_session: TorSession<T>,
    pub credential: AnonymousCredential<'a>,
    pub route_policy: RoutePolicy,
    pub recent_failures: &'a [RecentFailure],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntrySessionOutcome {
    pub route: EnhancedRoute,
    pub bytes_client_to_exit: u64,
    pub bytes_exit_to_client: u64,
}

#[derive(Clone)]
pub struct EntryGateway<V, R> {
    descriptor: GatewayDescriptor,
    exits: Arc<Vec<GatewayDescriptor>>,
    verifier: Arc<V>,
    relays: Arc<R>,
    verification_timeout: Duration,
}

impl<V, R> EntryGateway<V, R>
where
    V: AnonymousCredentialVerifier,
    R: RelaySessionFactory,
{
    pub fn new(
        descriptor: GatewayDescriptor,
        exits: Vec<GatewayDescriptor>,
        verifier: Arc<V>,
        relays: Arc<R>,
        verification_timeout: Duration,
    ) -> Result<Self> {
        if descriptor.role != crate::route::GatewayRole::Entry
            || exits.is_empty()
            || verification_timeout.is_zero()
        {
            return Err(ErrorCode::InvalidConfiguration.into());
        }
        Ok(Self {
            descriptor,
            exits: Arc::new(exits),
            verifier,
            relays,
            verification_timeout,
        })
    }

    /// Verifies the entry-scoped anonymous credential, selects a diverse exit,
    /// and pumps opaque terminal TLS bytes. `copy_bidirectional` plus protocol
    /// windows propagates backpressure in both directions.
    pub async fn serve<T>(&self, request: EntrySessionRequest<'_, T>) -> Result<EntrySessionOutcome>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if request.credential.token.is_empty()
            || request.credential.token.len() > 4096
            || request.credential.proof_of_possession.len() > 4096
        {
            return Err(ErrorCode::AuthenticationRejected.into());
        }
        let grant = tokio::time::timeout(
            self.verification_timeout,
            self.verifier.verify(request.credential),
        )
        .await
        .map_err(|_| ErrorCode::Timeout)??;
        if !grant.enhanced_allowed
            || grant.maximum_relay_bytes == 0
            || grant.expires_at <= SystemTime::now()
        {
            return Err(ErrorCode::AuthenticationRejected.into());
        }

        let route = select_enhanced_route(
            &self.descriptor,
            self.exits.as_slice(),
            &request.route_policy,
            request.recent_failures,
        )?;
        let relay = self.relays.open_relay(&route, grant.expires_at).await?;
        let tor = request.tor_session.io;
        let remaining = Arc::new(AtomicU64::new(grant.maximum_relay_bytes));
        let (mut tor_reader, tor_writer) = tokio::io::split(tor);
        let (mut relay_reader, relay_writer) = tokio::io::split(relay);
        let mut to_exit = QuotaWriter::new(relay_writer, remaining.clone());
        let mut to_client = QuotaWriter::new(tor_writer, remaining.clone());
        let copied = tokio::try_join!(
            tokio::io::copy(&mut tor_reader, &mut to_exit),
            tokio::io::copy(&mut relay_reader, &mut to_client),
        );
        let (client_to_exit, exit_to_client) = match copied {
            Ok(counts) => counts,
            Err(_) if remaining.load(Ordering::Acquire) == 0 => {
                return Err(ErrorCode::ResourceExhausted.into())
            }
            Err(_) => return Err(ErrorCode::TransportFailure.into()),
        };
        Ok(EntrySessionOutcome {
            route,
            bytes_client_to_exit: client_to_exit,
            bytes_exit_to_client: exit_to_client,
        })
    }
}

struct QuotaWriter<W> {
    inner: W,
    remaining: Arc<AtomicU64>,
}

impl<W> QuotaWriter<W> {
    fn new(inner: W, remaining: Arc<AtomicU64>) -> Self {
        Self { inner, remaining }
    }
}

impl<W> AsyncWrite for QuotaWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let reserved = loop {
            let remaining = self.remaining.load(Ordering::Acquire);
            if remaining == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "relay byte quota exhausted",
                )));
            }
            let wanted = remaining.min(buffer.len() as u64);
            if self
                .remaining
                .compare_exchange(
                    remaining,
                    remaining - wanted,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                break wanted as usize;
            }
        };
        match Pin::new(&mut self.inner).poll_write(context, &buffer[..reserved]) {
            Poll::Pending => {
                self.remaining.fetch_add(reserved as u64, Ordering::AcqRel);
                Poll::Pending
            }
            Poll::Ready(Ok(written)) => {
                self.remaining
                    .fetch_add((reserved - written) as u64, Ordering::AcqRel);
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => {
                self.remaining.fetch_add(reserved as u64, Ordering::AcqRel);
                Poll::Ready(Err(error))
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}
