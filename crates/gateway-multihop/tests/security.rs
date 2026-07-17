use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use onionroute_gateway_multihop::exit::{
    authorize_operation, DataPlaneOperation, DefaultExitAcl, Destination, ExitDialer,
    ExitEgressAdapter, ExitResolver,
};
use onionroute_gateway_multihop::identity::{
    certificate_fingerprint, IdentityMaterial, IdentityPurpose, IdentityStore, PeerIdentity,
    TrustBundle,
};
use onionroute_gateway_multihop::protocol::{
    accept_exit, connect_entry, inter_gateway_frame, HandshakeConfig, OpenSession, ReplayCache,
    WireVersion,
};
use onionroute_gateway_multihop::route::{GatewayRole, ProtocolVersion};
use onionroute_gateway_multihop::tls::{EntryTlsConnector, ExitTlsAcceptor};
use onionroute_gateway_multihop::{ErrorCode, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use time::OffsetDateTime;

struct TestPki {
    entry_store: IdentityStore,
    exit_store: IdentityStore,
    entry_trust: TrustBundle,
    exit_trust: TrustBundle,
    entry_peer: PeerIdentity,
    exit_peer: PeerIdentity,
}

fn test_pki() -> TestPki {
    let (entry_ca, entry_ca_key) = ca("entry-data-plane-ca");
    let (exit_ca, exit_ca_key) = ca("exit-data-plane-ca");
    let (entry_cert, entry_key) = leaf(
        "entry-a.test",
        ExtendedKeyUsagePurpose::ClientAuth,
        &entry_ca,
        &entry_ca_key,
    );
    let (exit_cert, exit_key) = leaf(
        "exit-a.test",
        ExtendedKeyUsagePurpose::ServerAuth,
        &exit_ca,
        &exit_ca_key,
    );
    let now = SystemTime::now();
    let entry_peer = peer(
        "entry-a",
        GatewayRole::Entry,
        certificate_fingerprint(entry_cert.der()),
        now,
    );
    let exit_peer = peer(
        "exit-a",
        GatewayRole::Exit,
        certificate_fingerprint(exit_cert.der()),
        now,
    );
    let entry_material = IdentityMaterial::new(
        entry_peer.clone(),
        vec![entry_cert.der().clone()],
        PrivatePkcs8KeyDer::from(entry_key.serialize_der()).into(),
        now,
    )
    .unwrap();
    let exit_material = IdentityMaterial::new(
        exit_peer.clone(),
        vec![exit_cert.der().clone()],
        PrivatePkcs8KeyDer::from(exit_key.serialize_der()).into(),
        now,
    )
    .unwrap();
    TestPki {
        entry_store: IdentityStore::new(entry_material).unwrap(),
        exit_store: IdentityStore::new(exit_material).unwrap(),
        entry_trust: TrustBundle::new(vec![entry_ca.der().clone()], vec![entry_peer.clone()], now)
            .unwrap(),
        exit_trust: TrustBundle::new(vec![exit_ca.der().clone()], vec![exit_peer.clone()], now)
            .unwrap(),
        entry_peer,
        exit_peer,
    }
}

fn ca(common_name: &str) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params.not_before = OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_after = OffsetDateTime::now_utc() + time::Duration::days(7);
    let key = KeyPair::generate().unwrap();
    (params.self_signed(&key).unwrap(), key)
}

fn leaf(
    dns_name: &str,
    usage: ExtendedKeyUsagePurpose,
    issuer: &Certificate,
    issuer_key: &KeyPair,
) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec![dns_name.to_owned()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, dns_name);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![usage];
    params.not_before = OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_after = OffsetDateTime::now_utc() + time::Duration::hours(4);
    let key = KeyPair::generate().unwrap();
    (params.signed_by(&key, issuer, issuer_key).unwrap(), key)
}

fn peer(
    service_id: &str,
    role: GatewayRole,
    certificate_sha256: [u8; 32],
    now: SystemTime,
) -> PeerIdentity {
    PeerIdentity {
        service_id: service_id.into(),
        role,
        purpose: IdentityPurpose::InterGatewayDataPlane,
        certificate_sha256,
        valid_from: now - Duration::from_secs(60),
        valid_until: now + Duration::from_secs(3 * 60 * 60),
    }
}

#[tokio::test]
async fn tls13_mtls_and_exporter_bound_handshake_carry_opaque_sessions() {
    let pki = test_pki();
    let connector = EntryTlsConnector::new(pki.entry_store, pki.exit_trust).unwrap();
    let acceptor = ExitTlsAcceptor::new(pki.exit_store, pki.entry_trust).unwrap();
    let (entry_io, exit_io) = tokio::io::duplex(256 * 1024);
    let server_name = ServerName::try_from("exit-a.test").unwrap().to_owned();
    let (entry_tls, exit_tls) = tokio::join!(
        connector.connect(entry_io, server_name, "exit-a"),
        acceptor.accept(exit_io),
    );
    let entry_tls = entry_tls.unwrap();
    let exit_tls = exit_tls.unwrap();
    assert_eq!(entry_tls.peer().service_id, "exit-a");
    assert_eq!(exit_tls.peer().service_id, "entry-a");

    let config = HandshakeConfig {
        minimum_version: ProtocolVersion { major: 1, minor: 0 },
        maximum_version: ProtocolVersion { major: 1, minor: 0 },
        limits: Default::default(),
    };
    let replay = ReplayCache::default();
    let (entry, exit) = tokio::join!(
        connect_entry(entry_tls, &pki.entry_peer, config.clone()),
        accept_exit(exit_tls, &pki.exit_peer, config, &replay),
    );
    let mut entry = entry.unwrap();
    let mut exit = exit.unwrap();
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    entry
        .open_session(OpenSession {
            session_id: 1,
            terminal_protocol_version: Some(WireVersion { major: 1, minor: 0 }),
            initial_receive_window: 64 * 1024,
            expires_at_unix_seconds: expires as i64,
        })
        .await
        .unwrap();
    assert!(matches!(
        exit.next_event().await.unwrap(),
        inter_gateway_frame::Body::OpenSession(_)
    ));
    exit.accept_session(1).await.unwrap();
    assert!(matches!(
        entry.next_event().await.unwrap(),
        inter_gateway_frame::Body::SessionOpened(_)
    ));
    entry.send_data(1, b"opaque-terminal-tls").await.unwrap();
    match exit.next_event().await.unwrap() {
        inter_gateway_frame::Body::Data(data) => {
            assert_eq!(data.payload, b"opaque-terminal-tls");
        }
        _ => panic!("unexpected event"),
    }
}

#[test]
fn entry_certificate_has_no_management_or_control_authority() {
    let pki = test_pki();
    assert!(authorize_operation(&pki.entry_peer, DataPlaneOperation::RelayBytes).is_ok());
    assert_eq!(
        authorize_operation(&pki.entry_peer, DataPlaneOperation::Management)
            .unwrap_err()
            .code,
        ErrorCode::PolicyDenied
    );
    assert_eq!(
        authorize_operation(&pki.entry_peer, DataPlaneOperation::ControlPlane)
            .unwrap_err()
            .code,
        ErrorCode::PolicyDenied
    );
}

#[test]
fn emergency_revocation_is_checked_on_existing_peer_identity() {
    let pki = test_pki();
    pki.entry_trust.emergency_revoke_service("entry-a").unwrap();
    assert_eq!(
        pki.entry_trust
            .ensure_active(&pki.entry_peer, SystemTime::now())
            .unwrap_err()
            .code,
        ErrorCode::Revoked
    );
}

struct FixedResolver(Vec<IpAddr>);

#[async_trait]
impl ExitResolver for FixedResolver {
    async fn resolve(&self, _: &str) -> Result<Vec<IpAddr>> {
        Ok(self.0.clone())
    }
}

struct RecordingDialer {
    calls: Mutex<Vec<SocketAddr>>,
}

#[async_trait]
impl ExitDialer for RecordingDialer {
    async fn connect(
        &self,
        address: SocketAddr,
    ) -> Result<onionroute_gateway_multihop::exit::BoxedSessionIo> {
        self.calls.lock().unwrap().push(address);
        let (io, _) = tokio::io::duplex(1024);
        Ok(Box::pin(io))
    }
}

#[tokio::test]
async fn exit_rejects_private_dns_result_before_any_dial() {
    let dialer = Arc::new(RecordingDialer {
        calls: Mutex::new(Vec::new()),
    });
    let adapter = ExitEgressAdapter::new(
        DefaultExitAcl::new(HashSet::new(), Vec::new()).unwrap(),
        Arc::new(FixedResolver(vec!["127.0.0.1".parse().unwrap()])),
        dialer.clone(),
        Duration::from_secs(1),
    )
    .unwrap();
    let error = adapter
        .open_tcp(Destination::Hostname("example.com".into()), 443)
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::PolicyDenied);
    assert!(dialer.calls.lock().unwrap().is_empty());
}
