//! Policy-checked TCP egress connector.

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::acl::{AclEngine, Destination};
use crate::dns::DnsResolver;
use crate::health::{Metric, Metrics, PrivacyEventBuffer, PrivacyEventKind};
use crate::rate_limit::CircuitBreaker;
use crate::session::{SessionLease, StreamLease};
use crate::{GatewayError, GatewayErrorCode, GatewayResult};

pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedIo = Pin<Box<dyn AsyncIo>>;

#[async_trait]
pub trait EgressDialer: Send + Sync + 'static {
    async fn connect(&self, address: SocketAddr) -> GatewayResult<BoxedIo>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TokioEgressDialer;

#[async_trait]
impl EgressDialer for TokioEgressDialer {
    async fn connect(&self, address: SocketAddr) -> GatewayResult<BoxedIo> {
        let stream = TcpStream::connect(address)
            .await
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::AddrNotAvailable => {
                    GatewayErrorCode::EgressInfrastructureFailure
                }
                _ => GatewayErrorCode::EgressFailure,
            })?;
        stream
            .set_nodelay(true)
            .map_err(|_| GatewayErrorCode::EgressInfrastructureFailure)?;
        Ok(Box::pin(stream))
    }
}

pub struct OpenedEgress {
    pub io: BoxedIo,
    pub permit: StreamLease,
}

/// Executes the normative OpenTcpStream order: session/tariff, hostname/port,
/// DNS, every resolved IP, direct-IP TCP connect, then protocol-level flow and
/// bandwidth control.
#[derive(Clone)]
pub struct TcpEgressConnector {
    acl: AclEngine,
    resolver: Arc<dyn DnsResolver>,
    dialer: Arc<dyn EgressDialer>,
    circuit: Arc<CircuitBreaker>,
    metrics: Arc<Metrics>,
    events: Arc<PrivacyEventBuffer>,
    connect_timeout: std::time::Duration,
}

impl TcpEgressConnector {
    pub fn new(
        acl: AclEngine,
        resolver: Arc<dyn DnsResolver>,
        dialer: Arc<dyn EgressDialer>,
        circuit: Arc<CircuitBreaker>,
        metrics: Arc<Metrics>,
        events: Arc<PrivacyEventBuffer>,
        connect_timeout: std::time::Duration,
    ) -> Self {
        Self {
            acl,
            resolver,
            dialer,
            circuit,
            metrics,
            events,
            connect_timeout,
        }
    }

    pub async fn open(
        &self,
        session: &SessionLease,
        destination: Destination,
        port: u16,
    ) -> GatewayResult<OpenedEgress> {
        session.ensure_active()?;
        if let Err(error) = self.acl.check_destination(&destination, port) {
            self.metrics.increment(Metric::PolicyViolations);
            let _ = self
                .events
                .record(PrivacyEventKind::PolicyRejected, Some(session.handle()));
            return Err(error);
        }

        // The plaintext exists only in this stack-local buffer. The session
        // manager stores a keyed, short-lived digest for scan detection.
        let mut scan_material = Vec::with_capacity(260);
        match &destination {
            Destination::Hostname(hostname) => scan_material.extend_from_slice(hostname.as_bytes()),
            Destination::Ip(address) => match address {
                IpAddr::V4(address) => scan_material.extend_from_slice(&address.octets()),
                IpAddr::V6(address) => scan_material.extend_from_slice(&address.octets()),
            },
        }
        scan_material.extend_from_slice(&port.to_be_bytes());
        let permit = match session.reserve_stream(&scan_material) {
            Ok(permit) => permit,
            Err(error) => {
                match error.code {
                    GatewayErrorCode::Draining => {
                        self.metrics.increment(Metric::DrainingRejections)
                    }
                    GatewayErrorCode::PolicyDenied => {
                        self.metrics.increment(Metric::PolicyViolations)
                    }
                    _ => self.metrics.increment(Metric::RateLimitViolations),
                }
                return Err(error);
            }
        };
        self.circuit.before_connect().map_err(|error| {
            self.metrics.increment(Metric::CircuitOpen);
            error
        })?;

        let addresses = match &destination {
            Destination::Hostname(hostname) => {
                match self.resolver.resolve_for_connect(hostname).await {
                    Ok(resolution) => resolution.addresses,
                    Err(error) => {
                        self.metrics.increment(Metric::DnsFailures);
                        let _ = self
                            .events
                            .record(PrivacyEventKind::DnsUnavailable, Some(session.handle()));
                        return Err(error);
                    }
                }
            }
            Destination::Ip(address) => vec![*address],
        };

        let mut last_error = GatewayError::new(GatewayErrorCode::EgressFailure);
        let mut infrastructure_failure = false;
        for address in addresses {
            // Repeat the post-resolution policy check immediately before each
            // dial. No hostname is ever passed to the OS connector.
            if let Err(error) = self.acl.check_ip(address) {
                self.metrics.increment(Metric::PolicyViolations);
                let _ = self
                    .events
                    .record(PrivacyEventKind::PolicyRejected, Some(session.handle()));
                return Err(error);
            }
            match tokio::time::timeout(
                self.connect_timeout,
                self.dialer.connect(SocketAddr::new(address, port)),
            )
            .await
            {
                Ok(Ok(io)) => {
                    self.circuit.record_success();
                    self.metrics.increment(Metric::OpenedStreams);
                    return Ok(OpenedEgress { io, permit });
                }
                Ok(Err(error)) => {
                    infrastructure_failure |=
                        error.code == GatewayErrorCode::EgressInfrastructureFailure;
                    last_error = error;
                }
                Err(_) => last_error = GatewayErrorCode::Timeout.into(),
            }
        }
        if infrastructure_failure {
            self.circuit.record_failure();
        }
        self.metrics.increment(Metric::EgressFailures);
        let _ = self
            .events
            .record(PrivacyEventKind::EgressUnavailable, Some(session.handle()));
        Err(last_error)
    }
}
