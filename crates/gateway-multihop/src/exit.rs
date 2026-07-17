//! Exit-side authorization and independently policy-checked DNS/TCP egress.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::identity::{IdentityPurpose, PeerIdentity, TrustBundle};
use crate::quota::{EntryConnectionPermit, EntryQuotaManager};
use crate::route::GatewayRole;
use crate::{ErrorCode, Result};

pub trait SessionIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> SessionIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
pub type BoxedSessionIo = Pin<Box<dyn SessionIo>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataPlaneOperation {
    OpenRelaySession,
    RelayBytes,
    Management,
    ControlPlane,
}

/// Role-scoped mTLS identities are data-plane-only. There is deliberately no
/// grant path from an entry certificate to management/control-plane operations.
pub fn authorize_operation(peer: &PeerIdentity, operation: DataPlaneOperation) -> Result<()> {
    if peer.role != GatewayRole::Entry
        || peer.purpose != IdentityPurpose::InterGatewayDataPlane
        || !matches!(
            operation,
            DataPlaneOperation::OpenRelaySession | DataPlaneOperation::RelayBytes
        )
    {
        return Err(ErrorCode::PolicyDenied.into());
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Destination {
    Hostname(String),
    Ip(IpAddr),
}

#[derive(Clone)]
pub struct DefaultExitAcl {
    blocked_ports: Arc<HashSet<u16>>,
    management_networks: Arc<Vec<(IpAddr, u8)>>,
}

impl DefaultExitAcl {
    pub fn new(
        blocked_ports: HashSet<u16>,
        management_networks: Vec<(IpAddr, u8)>,
    ) -> Result<Self> {
        if management_networks.len() > 256
            || management_networks
                .iter()
                .any(|(address, prefix)| match address {
                    IpAddr::V4(_) => *prefix > 32,
                    IpAddr::V6(_) => *prefix > 128,
                })
        {
            return Err(ErrorCode::InvalidConfiguration.into());
        }
        Ok(Self {
            blocked_ports: Arc::new(blocked_ports),
            management_networks: Arc::new(management_networks),
        })
    }

    pub fn check_requested(&self, destination: &Destination, port: u16) -> Result<()> {
        if port == 0
            || port == 25
            || port == 9051
            || port == 9151
            || (6881..=6889).contains(&port)
            || self.blocked_ports.contains(&port)
        {
            return Err(ErrorCode::PolicyDenied.into());
        }
        match destination {
            Destination::Hostname(hostname) => validate_public_hostname(hostname),
            Destination::Ip(address) => self.check_resolved(*address),
        }
    }

    /// Called for every DNS result and again immediately before dial.
    pub fn check_resolved(&self, address: IpAddr) -> Result<()> {
        if is_non_public(address)
            || self
                .management_networks
                .iter()
                .any(|network| contains(*network, address))
        {
            return Err(ErrorCode::PolicyDenied.into());
        }
        Ok(())
    }
}

#[async_trait]
pub trait ExitResolver: Send + Sync + 'static {
    /// Must use the exit's protected resolver. System/client DNS is not an
    /// implementation of this interface.
    async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>>;
}

#[async_trait]
pub trait ExitDialer: Send + Sync + 'static {
    async fn connect(&self, address: SocketAddr) -> Result<BoxedSessionIo>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TokioTcpDialer;

#[async_trait]
impl ExitDialer for TokioTcpDialer {
    async fn connect(&self, address: SocketAddr) -> Result<BoxedSessionIo> {
        let stream = TcpStream::connect(address)
            .await
            .map_err(|_| ErrorCode::TransportFailure)?;
        stream
            .set_nodelay(true)
            .map_err(|_| ErrorCode::TransportFailure)?;
        Ok(Box::pin(stream))
    }
}

#[derive(Clone)]
pub struct ExitEgressAdapter<R, D> {
    acl: DefaultExitAcl,
    resolver: Arc<R>,
    dialer: Arc<D>,
    connect_timeout: Duration,
}

impl<R, D> ExitEgressAdapter<R, D>
where
    R: ExitResolver,
    D: ExitDialer,
{
    pub fn new(
        acl: DefaultExitAcl,
        resolver: Arc<R>,
        dialer: Arc<D>,
        connect_timeout: Duration,
    ) -> Result<Self> {
        if connect_timeout.is_zero() || connect_timeout > Duration::from_secs(120) {
            return Err(ErrorCode::InvalidConfiguration.into());
        }
        Ok(Self {
            acl,
            resolver,
            dialer,
            connect_timeout,
        })
    }

    /// The destination is never trusted because it arrived from entry. The exit
    /// performs hostname/port policy, DNS, every-address policy, and a final
    /// pre-dial policy check itself.
    pub async fn open_tcp(&self, destination: Destination, port: u16) -> Result<BoxedSessionIo> {
        self.acl.check_requested(&destination, port)?;
        let addresses = match destination {
            Destination::Hostname(hostname) => {
                let addresses = self.resolver.resolve(&hostname).await?;
                if addresses.is_empty() || addresses.len() > 16 {
                    return Err(ErrorCode::PolicyDenied.into());
                }
                addresses
            }
            Destination::Ip(address) => vec![address],
        };

        let mut saw_transport_failure = false;
        for address in addresses {
            self.acl.check_resolved(address)?;
            // Re-check immediately before dialing to keep the policy ordering
            // explicit even when a future resolver adapter changes.
            self.acl.check_resolved(address)?;
            match tokio::time::timeout(
                self.connect_timeout,
                self.dialer.connect(SocketAddr::new(address, port)),
            )
            .await
            {
                Ok(Ok(io)) => return Ok(io),
                Ok(Err(_)) | Err(_) => saw_transport_failure = true,
            }
        }
        Err(if saw_transport_failure {
            ErrorCode::TransportFailure
        } else {
            ErrorCode::PolicyDenied
        }
        .into())
    }
}

pub struct TerminalContext {
    /// Public entry service ID, used only for quotas/revocation. No user/account
    /// or source IP is carried.
    pub entry_service_id: String,
}

#[async_trait]
pub trait TerminalSessionHandler: Send + Sync + 'static {
    /// Implementations terminate the separate client-to-exit TLS identity,
    /// verify an exit-scoped anonymous credential, and route all OpenTcp/DNS
    /// requests through `ExitEgressAdapter`.
    async fn serve_terminal(&self, context: TerminalContext, io: BoxedSessionIo) -> Result<()>;
}

#[derive(Clone)]
pub struct ExitGatewayAdapter<H> {
    trust: TrustBundle,
    quotas: EntryQuotaManager,
    handler: Arc<H>,
}

/// Admission for one authenticated entry-to-exit TLS connection. Holding the
/// value keeps the per-entry connection quota charged.
pub struct AuthorizedEntryConnection {
    peer: PeerIdentity,
    _permit: EntryConnectionPermit,
}

impl AuthorizedEntryConnection {
    pub fn peer(&self) -> &PeerIdentity {
        &self.peer
    }
}

impl<H> ExitGatewayAdapter<H>
where
    H: TerminalSessionHandler,
{
    pub fn new(trust: TrustBundle, quotas: EntryQuotaManager, handler: Arc<H>) -> Self {
        Self {
            trust,
            quotas,
            handler,
        }
    }

    pub fn admit_connection(&self, peer: PeerIdentity) -> Result<AuthorizedEntryConnection> {
        self.trust.ensure_active(&peer, SystemTime::now())?;
        authorize_operation(&peer, DataPlaneOperation::OpenRelaySession)?;
        let permit = self.quotas.acquire_connection(&peer)?;
        Ok(AuthorizedEntryConnection {
            peer,
            _permit: permit,
        })
    }

    pub fn charge_relay_bytes(
        &self,
        connection: &AuthorizedEntryConnection,
        bytes: usize,
    ) -> Result<()> {
        self.trust
            .ensure_active(connection.peer(), SystemTime::now())?;
        authorize_operation(connection.peer(), DataPlaneOperation::RelayBytes)?;
        self.quotas.charge_bytes(connection.peer(), bytes)
    }

    pub async fn serve_relay(
        &self,
        connection: &AuthorizedEntryConnection,
        io: BoxedSessionIo,
    ) -> Result<()> {
        self.trust
            .ensure_active(connection.peer(), SystemTime::now())?;
        authorize_operation(connection.peer(), DataPlaneOperation::OpenRelaySession)?;
        let _session_permit = self.quotas.acquire_session(connection.peer())?;
        self.handler
            .serve_terminal(
                TerminalContext {
                    entry_service_id: connection.peer.service_id.clone(),
                },
                io,
            )
            .await
    }
}

fn validate_public_hostname(hostname: &str) -> Result<()> {
    let value = hostname.strip_suffix('.').unwrap_or(hostname);
    if value.is_empty() || value.len() > 253 || !value.is_ascii() || value.parse::<IpAddr>().is_ok()
    {
        return Err(ErrorCode::PolicyDenied.into());
    }
    let lower = value.to_ascii_lowercase();
    if ["localhost", "local", "internal", "home.arpa", "onion"]
        .iter()
        .any(|blocked| lower == *blocked || lower.ends_with(&format!(".{blocked}")))
        || lower == "metadata.google.internal"
    {
        return Err(ErrorCode::PolicyDenied.into());
    }
    for label in lower.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ErrorCode::PolicyDenied.into());
        }
    }
    Ok(())
}

fn contains(network: (IpAddr, u8), address: IpAddr) -> bool {
    match (network, address) {
        ((IpAddr::V4(base), prefix), IpAddr::V4(candidate)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(base) & mask == u32::from(candidate) & mask
        }
        ((IpAddr::V6(base), prefix), IpAddr::V6(candidate)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(base) & mask == u128::from(candidate) & mask
        }
        _ => false,
    }
}

fn is_non_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_non_public_v4(address),
        IpAddr::V6(address) => is_non_public_v6(address),
    }
}

fn is_non_public_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && (b == 0 || b == 168))
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
        || address.is_unspecified()
        || address.is_broadcast()
}

fn is_non_public_v6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] & 0xe000) != 0x2000
        || (segments[0] == 0x0064 && segments[1] == 0xff9b)
        || segments[0] == 0x2002
        || (segments[0] == 0x2001 && segments[1] == 0)
        || address.to_ipv4().map(is_non_public_v4).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_acl_blocks_management_and_ssrf_targets() {
        let acl = DefaultExitAcl::new(HashSet::new(), vec![("203.0.113.0".parse().unwrap(), 24)])
            .unwrap();
        for address in ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1"] {
            assert_eq!(
                acl.check_resolved(address.parse().unwrap())
                    .unwrap_err()
                    .code,
                ErrorCode::PolicyDenied
            );
        }
        assert!(acl.check_resolved("1.1.1.1".parse().unwrap()).is_ok());
        assert!(acl
            .check_requested(&Destination::Hostname("example.com".into()), 443)
            .is_ok());
        assert!(acl
            .check_requested(
                &Destination::Hostname("metadata.google.internal".into()),
                443
            )
            .is_err());
    }
}
