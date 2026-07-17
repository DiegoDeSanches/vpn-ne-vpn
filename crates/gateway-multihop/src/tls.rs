//! TLS 1.3-only mTLS boundary for entry-to-exit transport.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;

use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::identity::{IdentityPurpose, IdentityStore, PeerIdentity, TrustBundle};
use crate::route::GatewayRole;
use crate::{ErrorCode, Result};

const ALPN: &[u8] = b"onionroute-inter-gateway/1";
const EXPORTER_LABEL: &[u8] = b"EXPORTER-OnionRoute-InterGateway-v1";

/// An authenticated TLS stream plus an ephemeral exporter binding. The binding
/// is used only by the application handshake and must never be logged.
pub struct AuthenticatedTls<T> {
    io: T,
    peer: PeerIdentity,
    channel_binding: [u8; 32],
}

impl<T> AuthenticatedTls<T> {
    pub fn peer(&self) -> &PeerIdentity {
        &self.peer
    }

    pub(crate) fn channel_binding(&self) -> &[u8; 32] {
        &self.channel_binding
    }

    pub fn into_inner(self) -> T {
        self.io
    }
}

impl<T> AsyncRead for AuthenticatedTls<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(context, buffer)
    }
}

impl<T> AsyncWrite for AuthenticatedTls<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(context)
    }
}

#[derive(Clone)]
pub struct EntryTlsConnector {
    identity: IdentityStore,
    exits: TrustBundle,
}

impl EntryTlsConnector {
    pub fn new(identity: IdentityStore, exits: TrustBundle) -> Result<Self> {
        let descriptor = identity.snapshot(SystemTime::now())?;
        if descriptor.descriptor().role != GatewayRole::Entry
            || descriptor.descriptor().purpose != IdentityPurpose::InterGatewayDataPlane
        {
            return Err(ErrorCode::WrongRole.into());
        }
        Ok(Self { identity, exits })
    }

    pub async fn connect<T>(
        &self,
        io: T,
        server_name: ServerName<'static>,
        expected_exit_id: &str,
    ) -> Result<AuthenticatedTls<tokio_rustls::client::TlsStream<T>>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let now = SystemTime::now();
        let identity = self.identity.snapshot(now)?;
        let roots = root_store(self.exits.roots())?;
        let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_client_auth_cert(identity.certificate_chain(), identity.private_key())
            .map_err(|_| ErrorCode::InvalidIdentity)?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.enable_early_data = false;
        config.resumption = Resumption::disabled();

        let stream = TlsConnector::from(Arc::new(config))
            .connect(server_name, io)
            .await
            .map_err(|_| ErrorCode::InvalidIdentity)?;
        let connection = stream.get_ref().1;
        ensure_tls_parameters(connection.protocol_version(), connection.alpn_protocol())?;
        let leaf = connection
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or(ErrorCode::InvalidIdentity)?;
        let peer = self.exits.authorize_leaf(
            leaf,
            GatewayRole::Exit,
            IdentityPurpose::InterGatewayDataPlane,
            Some(expected_exit_id),
            SystemTime::now(),
        )?;
        let mut channel_binding = [0u8; 32];
        connection
            .export_keying_material(&mut channel_binding, EXPORTER_LABEL, None)
            .map_err(|_| ErrorCode::InvalidIdentity)?;
        Ok(AuthenticatedTls {
            io: stream,
            peer,
            channel_binding,
        })
    }
}

#[derive(Clone)]
pub struct ExitTlsAcceptor {
    identity: IdentityStore,
    entries: TrustBundle,
}

impl ExitTlsAcceptor {
    pub fn new(identity: IdentityStore, entries: TrustBundle) -> Result<Self> {
        let descriptor = identity.snapshot(SystemTime::now())?;
        if descriptor.descriptor().role != GatewayRole::Exit
            || descriptor.descriptor().purpose != IdentityPurpose::InterGatewayDataPlane
        {
            return Err(ErrorCode::WrongRole.into());
        }
        Ok(Self { identity, entries })
    }

    pub async fn accept<T>(
        &self,
        io: T,
    ) -> Result<AuthenticatedTls<tokio_rustls::server::TlsStream<T>>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let now = SystemTime::now();
        let identity = self.identity.snapshot(now)?;
        let roots = root_store(self.entries.roots())?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|_| ErrorCode::InvalidConfiguration)?;
        let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(identity.certificate_chain(), identity.private_key())
            .map_err(|_| ErrorCode::InvalidIdentity)?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.max_early_data_size = 0;
        config.send_half_rtt_data = false;
        config.send_tls13_tickets = 0;

        let stream = TlsAcceptor::from(Arc::new(config))
            .accept(io)
            .await
            .map_err(|_| ErrorCode::InvalidIdentity)?;
        let connection = stream.get_ref().1;
        ensure_tls_parameters(connection.protocol_version(), connection.alpn_protocol())?;
        let leaf = connection
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or(ErrorCode::InvalidIdentity)?;
        let peer = self.entries.authorize_leaf(
            leaf,
            GatewayRole::Entry,
            IdentityPurpose::InterGatewayDataPlane,
            None,
            SystemTime::now(),
        )?;
        let mut channel_binding = [0u8; 32];
        connection
            .export_keying_material(&mut channel_binding, EXPORTER_LABEL, None)
            .map_err(|_| ErrorCode::InvalidIdentity)?;
        Ok(AuthenticatedTls {
            io: stream,
            peer,
            channel_binding,
        })
    }
}

fn root_store(
    certificates: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate.clone())
            .map_err(|_| ErrorCode::InvalidConfiguration)?;
    }
    if roots.is_empty() {
        return Err(ErrorCode::InvalidConfiguration.into());
    }
    Ok(roots)
}

fn ensure_tls_parameters(
    version: Option<rustls::ProtocolVersion>,
    alpn: Option<&[u8]>,
) -> Result<()> {
    if version != Some(rustls::ProtocolVersion::TLSv1_3) || alpn != Some(ALPN) {
        return Err(ErrorCode::ProtocolIncompatible.into());
    }
    Ok(())
}
