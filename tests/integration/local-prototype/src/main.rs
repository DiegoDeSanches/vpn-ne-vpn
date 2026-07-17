#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::File;
use std::io::{BufReader, Error as IoError, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use onionroute_gateway_daemon::acl::AclEngine;
use onionroute_gateway_daemon::auth::{
    AuthenticationGrant, AuthenticationRequest, AuthenticationVerifier, TokenLimits,
};
use onionroute_gateway_daemon::config::GatewayConfig;
use onionroute_gateway_daemon::dns::{DnsResolver, Resolution};
use onionroute_gateway_daemon::egress::{
    BoxedIo, EgressDialer, TcpEgressConnector, TokioEgressDialer,
};
use onionroute_gateway_daemon::health::{Metrics, PrivacyEventBuffer};
use onionroute_gateway_daemon::onionroute::common::v1::{
    ProtocolVersion, ProtocolVersionRange,
};
use onionroute_gateway_daemon::onionroute::gateway::v1::destination;
use onionroute_gateway_daemon::onionroute::gateway::v1::gateway_frame::Body;
use onionroute_gateway_daemon::onionroute::gateway::v1::{
    AuthenticateRequest, ClientHello, Data, Destination, GatewayFrame, HalfClose, OpenTcpRequest,
    RouteMode, WindowUpdate,
};
use onionroute_gateway_daemon::protocol::{read_frame, write_frame, ProtocolHandler};
use onionroute_gateway_daemon::rate_limit::CircuitBreaker;
use onionroute_gateway_daemon::server::{bind_management, serve_management, GatewayServer};
use onionroute_gateway_daemon::session::SessionManager;
use onionroute_gateway_daemon::{GatewayErrorCode, GatewayResult};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio_rustls::TlsConnector;

const GATEWAY_ID: &str = "local-prototype-gateway";
const FIXTURE_HOSTNAME: &str = "fixture.onionroute.test";
const FIXTURE_IP: Ipv4Addr = Ipv4Addr::new(192, 175, 48, 10);
const FIXTURE_PORT: u16 = 18_080;
const ONION_TLS_PORT: u16 = 443;
const GATEWAY_LISTENER: &str = "127.0.0.1:18443";
const MANAGEMENT_LISTENER: &str = "127.0.0.1:19090";
const DEFAULT_SOCKS: &str = "127.0.0.1:19050";
const TLS_SERVER_NAME: &str = "onionroute-local.invalid";
const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_HTTP_BYTES: usize = 16 * 1024;
const ROUTE_PROOF_SCHEMA: &str = "onionroute.local-prototype.route-proof.v1";

type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("local-prototype failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> AppResult<()> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let command = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| invalid("expected serve, origin, probe, or healthcheck"))?;
    match command.as_str() {
        "serve" => {
            let runtime = path_argument(arguments.next(), "runtime directory")?;
            serve_gateway(&runtime).await
        }
        "origin" => serve_origin().await,
        "probe" => {
            let runtime = path_argument(arguments.next(), "runtime directory")?;
            let socks = arguments
                .next()
                .and_then(|value| value.into_string().ok())
                .unwrap_or_else(|| DEFAULT_SOCKS.to_owned())
                .parse()?;
            run_probe(&runtime, socks).await
        }
        "probe-server" => {
            let runtime = path_argument(arguments.next(), "runtime directory")?;
            let listener = socket_argument(arguments.next(), "probe listener")?;
            let socks = socket_argument(arguments.next(), "SOCKS endpoint")?;
            serve_probe_api(runtime, listener, socks).await
        }
        "healthcheck" => {
            let target = arguments
                .next()
                .and_then(|value| value.into_string().ok())
                .ok_or_else(|| invalid("expected gateway or origin healthcheck target"))?;
            healthcheck(&target).await
        }
        _ => Err(invalid("unknown command")),
    }
}

fn path_argument(value: Option<std::ffi::OsString>, label: &str) -> AppResult<PathBuf> {
    value.map(PathBuf::from).ok_or_else(|| invalid(label))
}

fn socket_argument(value: Option<std::ffi::OsString>, label: &str) -> AppResult<SocketAddr> {
    value
        .and_then(|item| item.into_string().ok())
        .ok_or_else(|| invalid(label))?
        .parse()
        .map_err(Into::into)
}

fn invalid(message: &str) -> Box<dyn Error + Send + Sync> {
    Box::new(IoError::new(ErrorKind::InvalidInput, message.to_owned()))
}

#[derive(Clone)]
struct LocalTokenVerifier {
    expected: Arc<[u8]>,
}

#[async_trait]
impl AuthenticationVerifier for LocalTokenVerifier {
    async fn verify(
        &self,
        request: AuthenticationRequest<'_>,
    ) -> GatewayResult<AuthenticationGrant> {
        if !request.proof_of_possession.is_empty()
            || request.capability_token.ct_eq(&self.expected).unwrap_u8() != 1
        {
            return Err(GatewayErrorCode::TokenRejected.into());
        }
        let expires_at = request
            .now
            .checked_add(Duration::from_secs(600))
            .ok_or(GatewayErrorCode::TokenRejected)?;
        Ok(AuthenticationGrant {
            expires_at,
            capabilities: vec!["tcp-connect-v1".to_owned()],
            limits: TokenLimits {
                max_sessions: 1,
                max_concurrent_streams: 1,
                connections_per_second: 1,
                connection_burst: 1,
                bytes_per_second: 256 * 1024,
                bandwidth_burst_bytes: 256 * 1024,
                total_bytes: 1024 * 1024,
            },
        })
    }
}

#[derive(Clone, Copy)]
struct FixtureResolver;

#[async_trait]
impl DnsResolver for FixtureResolver {
    async fn resolve_for_connect(&self, hostname: &str) -> GatewayResult<Resolution> {
        if hostname != FIXTURE_HOSTNAME {
            return Err(GatewayErrorCode::PolicyDenied.into());
        }
        Ok(Resolution {
            addresses: vec![IpAddr::V4(FIXTURE_IP)],
            cname_depth: 0,
            response_bytes: 0,
        })
    }

    async fn exchange_wire(&self, _query: &[u8]) -> GatewayResult<Vec<u8>> {
        Err(GatewayErrorCode::PolicyDenied.into())
    }
}

#[derive(Clone, Copy)]
struct FixtureOnlyDialer;

#[async_trait]
impl EgressDialer for FixtureOnlyDialer {
    async fn connect(&self, address: SocketAddr) -> GatewayResult<BoxedIo> {
        if address != SocketAddr::new(IpAddr::V4(FIXTURE_IP), FIXTURE_PORT) {
            return Err(GatewayErrorCode::PolicyDenied.into());
        }
        TokioEgressDialer.connect(address).await
    }
}

async fn serve_gateway(runtime: &Path) -> AppResult<()> {
    let token = read_trimmed(&runtime.join("capability-token"))?;
    if token.len() != 64 || !token.iter().all(u8::is_ascii_hexdigit) {
        return Err(invalid("invalid runtime capability token"));
    }

    let mut config = GatewayConfig::default();
    config.gateway_id = GATEWAY_ID.to_owned();
    config.onion_listener = GATEWAY_LISTENER.parse()?;
    config.management_listener = MANAGEMENT_LISTENER.parse()?;
    config.tls.certificate_chain = runtime.join("tls/server.crt");
    config.tls.private_key = runtime.join("tls/server.key");
    // GatewayConfig requires an explicit DNS boundary. The local resolver below
    // never calls this placeholder and only maps the single fixture hostname.
    config.dns.upstreams = vec!["127.0.0.1:9".parse()?];
    config.privacy_events.enabled = false;
    config.limits.max_connections = 8;
    config.limits.max_sessions = 4;
    config.limits.max_token_states = 8;
    config.limits.max_sessions_per_token = 1;
    config.limits.max_streams_global = 4;
    config.limits.max_streams_per_session = 1;
    config.limits.max_streams_per_token = 1;
    config.limits.connection_rate_per_second = 1;
    config.limits.connection_rate_burst = 1;
    config.limits.outbound_event_queue = 16;
    config.limits.session_ttl_seconds = 600;
    config.limits.io_timeout_ms = 30_000;
    config.drain_grace_seconds = 3;
    config.validate()?;

    let acl = AclEngine::new(config.acl.clone());
    let resolver: Arc<dyn DnsResolver> = Arc::new(FixtureResolver);
    let sessions = SessionManager::new(config.limits.clone())?;
    let metrics = Arc::new(Metrics::default());
    let events = Arc::new(PrivacyEventBuffer::new(
        config.privacy_events.clone(),
        config.gateway_id.clone(),
    ));
    let circuit = Arc::new(CircuitBreaker::new(
        config.limits.circuit_failure_threshold,
        Duration::from_secs(config.limits.circuit_cooldown_seconds),
    ));
    let egress = TcpEgressConnector::new(
        acl,
        resolver.clone(),
        Arc::new(FixtureOnlyDialer),
        circuit.clone(),
        metrics.clone(),
        events.clone(),
        config.limits.connect_timeout(),
    );
    let protocol = ProtocolHandler::new(
        config.gateway_id.clone(),
        config.limits.clone(),
        Arc::new(LocalTokenVerifier {
            expected: Arc::from(token),
        }),
        sessions.clone(),
        egress,
        resolver,
        metrics.clone(),
        events.clone(),
    );
    let server = GatewayServer::new(config.clone(), protocol, sessions.clone(), events);
    let management_listener = bind_management(config.management_listener)?;
    let management = tokio::spawn(serve_management(
        management_listener,
        metrics,
        sessions,
        circuit,
    ));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let gateway = tokio::spawn(server.run(shutdown_rx));
    tokio::select! {
        result = gateway => result??,
        result = management => result??,
    }
    Ok(())
}

async fn serve_origin() -> AppResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, FIXTURE_PORT)).await?;
    let permits = Arc::new(Semaphore::new(16));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            let _ = handle_origin(stream).await;
        });
    }
}

async fn handle_origin(mut stream: TcpStream) -> AppResult<()> {
    let mut request = vec![0u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut request)).await??;
    request.truncate(read);
    let request = std::str::from_utf8(&request)?;
    if !request.contains("\r\n\r\n") {
        return Err(invalid("incomplete fixture request"));
    }
    let first_line = request.lines().next().ok_or_else(|| invalid("missing request"))?;
    let prefix = "GET /route-proof?challenge=";
    let suffix = " HTTP/1.1";
    let challenge = first_line
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .ok_or_else(|| invalid("invalid fixture request"))?;
    if challenge.len() != 64
        || !challenge
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid("invalid fixture challenge"));
    }
    let body = serde_json::to_vec(&OriginProof {
        fixture: "onionroute-controlled-http-v1",
        challenge,
    })?;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-OnionRoute-Fixture: v1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await?;
    Ok(())
}

#[derive(Serialize)]
struct OriginProof<'a> {
    fixture: &'static str,
    challenge: &'a str,
}

#[derive(Deserialize)]
struct OriginProofOwned {
    fixture: String,
    challenge: String,
}

#[derive(Serialize)]
struct RouteProof {
    schema: &'static str,
    ok: bool,
    transport: &'static str,
    gateway_id: String,
    onion_service: String,
    destination: String,
    fixture: &'static str,
    response_sha256: String,
    server_certificate_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DaemonProbeRequest {
    nonce: String,
}

#[derive(Serialize)]
struct DaemonProbeResponse {
    schema: &'static str,
    ok: bool,
    nonce_sha256: String,
    route_proof_sha256: String,
    transport: &'static str,
    gateway_id: &'static str,
}

#[derive(Serialize)]
struct RuntimeInfo {
    schema: &'static str,
    gateway_id: &'static str,
    onion_service: String,
    socks_endpoint: &'static str,
    probe_endpoint: &'static str,
    probe_schema: &'static str,
    tls_server_name: &'static str,
    server_certificate_sha256: String,
}

#[derive(Serialize)]
struct ApiFailure {
    schema: &'static str,
    ok: bool,
    code: &'static str,
}

async fn run_probe(runtime: &Path, socks_address: SocketAddr) -> AppResult<()> {
    let proof = perform_probe(runtime, socks_address, None).await?;
    let encoded = serde_json::to_vec(&proof)?;
    std::fs::write(runtime.join("route-proof.json"), &encoded)?;
    println!("{}", String::from_utf8(encoded)?);
    Ok(())
}

async fn perform_probe(
    runtime: &Path,
    socks_address: SocketAddr,
    supplied_challenge: Option<String>,
) -> AppResult<RouteProof> {
    let token = read_trimmed(&runtime.join("capability-token"))?;
    let onion = String::from_utf8(read_trimmed(&runtime.join("onion-service/hostname"))?)?;
    validate_v3_onion(&onion)?;
    let (tls_config, certificate_sha256) = load_client_tls(&runtime.join("tls/server.crt"))?;

    let deadline = Instant::now() + Duration::from_secs(180);
    let tcp = loop {
        match socks_connect(socks_address, &onion, ONION_TLS_PORT).await {
            Ok(stream) => break stream,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(error) => return Err(error),
        }
    };

    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = ServerName::try_from(TLS_SERVER_NAME)?.to_owned();
    let mut transport = tokio::time::timeout(
        Duration::from_secs(20),
        connector.connect(server_name, tcp),
    )
    .await??;
    if transport.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return Err(invalid("gateway did not negotiate TLS 1.3"));
    }

    let version = ProtocolVersion { major: 1, minor: 0 };
    let mut client_nonce = vec![0u8; 16];
    getrandom::getrandom(&mut client_nonce).map_err(|_| invalid("entropy unavailable"))?;
    write_frame(
        &mut transport,
        &GatewayFrame {
            version: Some(version.clone()),
            session_id: Vec::new(),
            sequence: 1,
            body: Some(Body::ClientHello(ClientHello {
                supported_versions: Some(ProtocolVersionRange {
                    minimum: Some(version.clone()),
                    maximum: Some(version.clone()),
                }),
                client_nonce,
                route_mode: RouteMode::Standard as i32,
                requested_features: vec!["required:tcp-connect-v1".to_owned()],
            })),
        },
        MAX_FRAME_BYTES,
    )
    .await?;
    let hello_frame = next_initial_server_frame(&mut transport).await?;
    let envelope_session_id = hello_frame.session_id.clone();
    let hello = match hello_frame.body {
        Some(Body::ServerHello(hello)) => hello,
        _ => return Err(invalid("expected ServerHello")),
    };
    if hello.gateway_id != GATEWAY_ID
        || hello.ephemeral_session_id.len() != 16
        || hello.ephemeral_session_id != envelope_session_id
        || !hello.enabled_features.iter().any(|value| value == "tcp-connect-v1")
    {
        return Err(invalid("invalid ServerHello"));
    }
    let session_id = hello.ephemeral_session_id;

    write_frame(
        &mut transport,
        &GatewayFrame {
            version: Some(version.clone()),
            session_id: session_id.clone(),
            sequence: 2,
            body: Some(Body::AuthenticateRequest(AuthenticateRequest {
                capability_token: token,
                proof_of_possession: Vec::new(),
            })),
        },
        MAX_FRAME_BYTES,
    )
    .await?;
    let auth_frame = next_server_frame(&mut transport, 2, &session_id).await?;
    match auth_frame.body {
        Some(Body::AuthenticateResponse(response)) if response.accepted => {}
        _ => return Err(invalid("local capability authentication rejected")),
    }

    write_frame(
        &mut transport,
        &GatewayFrame {
            version: Some(version.clone()),
            session_id: session_id.clone(),
            sequence: 3,
            body: Some(Body::OpenTcpRequest(OpenTcpRequest {
                stream_id: 1,
                destination: Some(Destination {
                    value: Some(destination::Value::Hostname(FIXTURE_HOSTNAME.to_owned())),
                }),
                port: u32::from(FIXTURE_PORT),
                initial_window: 64 * 1024,
            })),
        },
        MAX_FRAME_BYTES,
    )
    .await?;
    let opened = next_server_frame(&mut transport, 3, &session_id).await?;
    match opened.body {
        Some(Body::OpenTcpResponse(response)) if response.opened && response.stream_id == 1 => {}
        _ => return Err(invalid("controlled fixture stream rejected")),
    }

    let challenge = match supplied_challenge {
        Some(value) => {
            validate_challenge(&value)?;
            value
        }
        None => {
            let mut value = [0u8; 32];
            getrandom::getrandom(&mut value).map_err(|_| invalid("entropy unavailable"))?;
            lowercase_hex(&value)
        }
    };
    let request = format!(
        "GET /route-proof?challenge={challenge} HTTP/1.1\r\nHost: {FIXTURE_HOSTNAME}\r\nConnection: close\r\n\r\n"
    );
    write_frame(
        &mut transport,
        &GatewayFrame {
            version: Some(version.clone()),
            session_id: session_id.clone(),
            sequence: 4,
            body: Some(Body::Data(Data {
                stream_id: 1,
                payload: request.into_bytes(),
            })),
        },
        MAX_FRAME_BYTES,
    )
    .await?;
    write_frame(
        &mut transport,
        &GatewayFrame {
            version: Some(version.clone()),
            session_id: session_id.clone(),
            sequence: 5,
            body: Some(Body::HalfClose(HalfClose { stream_id: 1 })),
        },
        MAX_FRAME_BYTES,
    )
    .await?;

    let mut response_bytes = Vec::new();
    let mut expected_server_sequence = 4;
    let mut next_client_sequence = 6;
    loop {
        let frame = tokio::time::timeout(
            Duration::from_secs(30),
            next_server_frame(&mut transport, expected_server_sequence, &session_id),
        )
        .await??;
        expected_server_sequence += 1;
        match frame.body {
            Some(Body::Data(data)) if data.stream_id == 1 => {
                if response_bytes.len().saturating_add(data.payload.len()) > MAX_HTTP_BYTES {
                    return Err(invalid("fixture response exceeds bound"));
                }
                let credit = u32::try_from(data.payload.len())?;
                response_bytes.extend_from_slice(&data.payload);
                write_frame(
                    &mut transport,
                    &GatewayFrame {
                        version: Some(version.clone()),
                        session_id: session_id.clone(),
                        sequence: next_client_sequence,
                        body: Some(Body::WindowUpdate(WindowUpdate {
                            stream_id: 1,
                            credit,
                        })),
                    },
                    MAX_FRAME_BYTES,
                )
                .await?;
                next_client_sequence = next_client_sequence
                    .checked_add(1)
                    .ok_or_else(|| invalid("client sequence exhausted"))?;
            }
            Some(Body::WindowUpdate(update)) if update.stream_id == 1 => {}
            Some(Body::HalfClose(close)) if close.stream_id == 1 => break,
            Some(Body::ResetStream(_)) | Some(Body::Error(_)) => {
                return Err(invalid("gateway reset controlled stream"))
            }
            _ => return Err(invalid("unexpected gateway frame")),
        }
    }
    verify_origin_response(&response_bytes, &challenge)?;

    Ok(RouteProof {
        schema: ROUTE_PROOF_SCHEMA,
        ok: true,
        transport: "socks5+tor-v3-onion+tls1.3+gateway-v1-adapter",
        gateway_id: hello.gateway_id,
        onion_service: onion,
        destination: format!("{FIXTURE_HOSTNAME}:{FIXTURE_PORT}"),
        fixture: "onionroute-controlled-http-v1",
        response_sha256: lowercase_hex(&Sha256::digest(&response_bytes)),
        server_certificate_sha256: certificate_sha256,
    })
}

fn validate_challenge(value: &str) -> AppResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid("challenge must be 64 lowercase hexadecimal characters"));
    }
    Ok(())
}

async fn serve_probe_api(
    runtime: PathBuf,
    listener_address: SocketAddr,
    socks_address: SocketAddr,
) -> AppResult<()> {
    if !listener_address.ip().is_unspecified() && !listener_address.ip().is_loopback() {
        return Err(invalid("probe listener must be container-local"));
    }
    let listener = TcpListener::bind(listener_address).await?;
    let permit = Arc::new(Semaphore::new(1));
    loop {
        let (stream, _) = listener.accept().await?;
        let runtime = runtime.clone();
        let socks = socks_address;
        let permit = permit.clone();
        tokio::spawn(async move {
            let Ok(_permit) = permit.try_acquire_owned() else {
                let _ = write_api_failure(stream, "503 Service Unavailable", "probe_busy").await;
                return;
            };
            let _ = handle_probe_api(stream, &runtime, socks).await;
        });
    }
}

async fn handle_probe_api(
    mut stream: TcpStream,
    runtime: &Path,
    socks_address: SocketAddr,
) -> AppResult<()> {
    let request = read_bounded_http_request(&mut stream).await?;
    let boundary = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| invalid("missing HTTP header boundary"))?;
    let headers = std::str::from_utf8(&request[..boundary])?;
    let first_line = headers.lines().next().ok_or_else(|| invalid("missing HTTP request"))?;
    match first_line {
        "GET /v1/runtime HTTP/1.1" => {
            let info = runtime_info(runtime)?;
            write_json_response(&mut stream, "200 OK", &info).await
        }
        "POST /v1/probe HTTP/1.1" => {
            let body = &request[boundary + 4..];
            let request: DaemonProbeRequest = match serde_json::from_slice(body) {
                Ok(value) => value,
                Err(_) => {
                    return write_api_failure(
                        stream,
                        "400 Bad Request",
                        "invalid_probe_request",
                    )
                    .await
                }
            };
            if validate_challenge(&request.nonce).is_err() {
                return write_api_failure(
                    stream,
                    "400 Bad Request",
                    "invalid_probe_request",
                )
                .await;
            }
            let proof = match perform_probe(runtime, socks_address, Some(request.nonce.clone())).await {
                Ok(value) => value,
                Err(_) => {
                    return write_api_failure(
                        stream,
                        "503 Service Unavailable",
                        "route_unavailable",
                    )
                    .await
                }
            };
            let encoded_proof = serde_json::to_vec(&proof)?;
            std::fs::write(runtime.join("route-proof.json"), &encoded_proof)?;
            let response = DaemonProbeResponse {
                schema: "onionroute.local-prototype.daemon-probe.v1",
                ok: true,
                nonce_sha256: lowercase_hex(&Sha256::digest(request.nonce.as_bytes())),
                route_proof_sha256: lowercase_hex(&Sha256::digest(&encoded_proof)),
                transport: "socks5+tor-v3-onion+tls1.3+gateway-v1-adapter",
                gateway_id: GATEWAY_ID,
            };
            write_json_response(&mut stream, "200 OK", &response).await
        }
        _ => write_api_failure(stream, "404 Not Found", "not_found").await,
    }
}

fn runtime_info(runtime: &Path) -> AppResult<RuntimeInfo> {
    let onion = String::from_utf8(read_trimmed(&runtime.join("onion-service/hostname"))?)?;
    validate_v3_onion(&onion)?;
    let (_, certificate_sha256) = load_client_tls(&runtime.join("tls/server.crt"))?;
    Ok(RuntimeInfo {
        schema: "onionroute.local-prototype.runtime.v1",
        gateway_id: GATEWAY_ID,
        onion_service: onion,
        socks_endpoint: "127.0.0.1:19050",
        probe_endpoint: "http://127.0.0.1:19091/v1/probe",
        probe_schema: "onionroute.local-prototype.daemon-probe.v1",
        tls_server_name: TLS_SERVER_NAME,
        server_certificate_sha256: certificate_sha256,
    })
}

async fn read_bounded_http_request(stream: &mut TcpStream) -> AppResult<Vec<u8>> {
    const MAX_REQUEST_BYTES: usize = 2048;
    let mut request = Vec::with_capacity(1024);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if request.len() >= MAX_REQUEST_BYTES {
            return Err(invalid("probe API request too large"));
        }
        let mut buffer = [0u8; 512];
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(invalid("probe API request timeout"));
        }
        let read = tokio::time::timeout(remaining, stream.read(&mut buffer)).await??;
        if read == 0 {
            return Err(invalid("probe API request ended early"));
        }
        request.extend_from_slice(&buffer[..read]);
        let Some(boundary) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let headers = std::str::from_utf8(&request[..boundary])?;
        let mut content_length = 0usize;
        for line in headers.lines().skip(1) {
            if let Some(value) = line.strip_prefix("Content-Length:") {
                content_length = value.trim().parse()?;
            } else if line.to_ascii_lowercase().starts_with("content-length:") {
                return Err(invalid("Content-Length must use canonical casing"));
            }
        }
        if content_length > 256 {
            return Err(invalid("probe API body too large"));
        }
        let expected = boundary
            .checked_add(4)
            .and_then(|value| value.checked_add(content_length))
            .ok_or_else(|| invalid("probe API request length overflow"))?;
        if request.len() < expected {
            continue;
        }
        if request.len() != expected {
            return Err(invalid("probe API request has trailing bytes"));
        }
        return Ok(request);
    }
}

async fn write_api_failure(
    mut stream: TcpStream,
    status: &str,
    code: &'static str,
) -> AppResult<()> {
    write_json_response(
        &mut stream,
        status,
        &ApiFailure {
            schema: "onionroute.local-prototype.error.v1",
            ok: false,
            code,
        },
    )
    .await
}

async fn write_json_response<T: Serialize>(
    stream: &mut TcpStream,
    status: &str,
    body: &T,
) -> AppResult<()> {
    let body = serde_json::to_vec(body)?;
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn next_server_frame<T>(
    transport: &mut T,
    expected_sequence: u64,
    expected_session: &[u8],
) -> AppResult<GatewayFrame>
where
    T: tokio::io::AsyncRead + Unpin,
{
    let frame = read_frame(transport, MAX_FRAME_BYTES)
        .await?
        .ok_or_else(|| invalid("gateway closed session"))?;
    let version = frame
        .version
        .as_ref()
        .ok_or_else(|| invalid("gateway omitted version"))?;
    if version.major != 1
        || version.minor != 0
        || frame.sequence != expected_sequence
        || frame.session_id != expected_session
    {
        return Err(invalid("invalid gateway envelope"));
    }
    Ok(frame)
}

async fn next_initial_server_frame<T>(transport: &mut T) -> AppResult<GatewayFrame>
where
    T: tokio::io::AsyncRead + Unpin,
{
    let frame = read_frame(transport, MAX_FRAME_BYTES)
        .await?
        .ok_or_else(|| invalid("gateway closed during handshake"))?;
    let version = frame
        .version
        .as_ref()
        .ok_or_else(|| invalid("gateway omitted version"))?;
    if version.major != 1
        || version.minor != 0
        || frame.sequence != 1
        || frame.session_id.len() != 16
    {
        return Err(invalid("invalid initial gateway envelope"));
    }
    Ok(frame)
}

fn verify_origin_response(response: &[u8], expected_challenge: &str) -> AppResult<()> {
    let boundary = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| invalid("fixture returned invalid HTTP"))?;
    let headers = std::str::from_utf8(&response[..boundary])?;
    if !headers.starts_with("HTTP/1.1 200 OK\r\n")
        || !headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("X-OnionRoute-Fixture: v1"))
    {
        return Err(invalid("fixture marker missing"));
    }
    let body: OriginProofOwned = serde_json::from_slice(&response[boundary + 4..])?;
    if body.fixture != "onionroute-controlled-http-v1" || body.challenge != expected_challenge {
        return Err(invalid("fixture challenge mismatch"));
    }
    Ok(())
}

fn load_client_tls(certificate_path: &Path) -> AppResult<(ClientConfig, String)> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut reader = BufReader::new(File::open(certificate_path)?);
    let certificates = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    let first = certificates
        .first()
        .ok_or_else(|| invalid("missing local TLS certificate"))?;
    let fingerprint = lowercase_hex(&Sha256::digest(first.as_ref()));
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate)?;
    }
    let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok((config, fingerprint))
}

async fn socks_connect(address: SocketAddr, host: &str, port: u16) -> AppResult<TcpStream> {
    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(address)).await??;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 0] {
        return Err(invalid("SOCKS5 authentication negotiation failed"));
    }
    let host_bytes = host.as_bytes();
    let host_len = u8::try_from(host_bytes.len())?;
    let mut request = Vec::with_capacity(host_bytes.len() + 7);
    request.extend_from_slice(&[5, 1, 0, 3, host_len]);
    request.extend_from_slice(host_bytes);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 5 || response[1] != 0 || response[2] != 0 {
        return Err(invalid("Tor SOCKS5 onion connection failed"));
    }
    let address_bytes = match response[3] {
        1 => 4,
        3 => usize::from(stream.read_u8().await?),
        4 => 16,
        _ => return Err(invalid("invalid SOCKS5 address type")),
    };
    let mut ignored = vec![0u8; address_bytes + 2];
    stream.read_exact(&mut ignored).await?;
    Ok(stream)
}

fn validate_v3_onion(hostname: &str) -> AppResult<()> {
    let label = hostname
        .strip_suffix(".onion")
        .ok_or_else(|| invalid("runtime hostname is not an onion service"))?;
    if label.len() != 56
        || !label
            .bytes()
            .all(|value| value.is_ascii_lowercase() || (b'2'..=b'7').contains(&value))
    {
        return Err(invalid("runtime hostname is not Tor v3"));
    }
    Ok(())
}

fn read_trimmed(path: &Path) -> AppResult<Vec<u8>> {
    let mut value = std::fs::read(path)?;
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value.pop();
    }
    if value.is_empty() {
        return Err(invalid("empty runtime file"));
    }
    Ok(value)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

async fn healthcheck(target: &str) -> AppResult<()> {
    let (address, request, marker) = match target {
        "gateway" => (
            MANAGEMENT_LISTENER,
            "GET /healthz HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n".to_owned(),
            "200 OK",
        ),
        "origin" => (
            "127.0.0.1:18080",
            format!(
                "GET /route-proof?challenge={} HTTP/1.1\r\nHost: {FIXTURE_HOSTNAME}\r\nConnection: close\r\n\r\n",
                "0".repeat(64)
            ),
            "X-OnionRoute-Fixture: v1",
        ),
        "probe-api" => (
            "127.0.0.1:19091",
            "GET /v1/runtime HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n".to_owned(),
            "onionroute.local-prototype.runtime.v1",
        ),
        _ => return Err(invalid("unknown healthcheck target")),
    };
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(request.as_bytes()).await?;
    stream.shutdown().await?;
    let mut response = vec![0u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut response)).await??;
    if !String::from_utf8_lossy(&response[..read]).contains(marker) {
        return Err(invalid("healthcheck marker missing"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolver_allows_only_controlled_fixture() {
        let error = match FixtureResolver.resolve_for_connect("example.com").await {
            Ok(_) => panic!("unexpected resolution"),
            Err(error) => error,
        };
        assert_eq!(error.code, GatewayErrorCode::PolicyDenied);
        let resolution = FixtureResolver
            .resolve_for_connect(FIXTURE_HOSTNAME)
            .await
            .unwrap();
        assert_eq!(resolution.addresses, vec![IpAddr::V4(FIXTURE_IP)]);
    }

    #[tokio::test]
    async fn verifier_rejects_wrong_token_and_proof() {
        let verifier = LocalTokenVerifier {
            expected: Arc::from(b"expected".as_slice()),
        };
        for (token, proof) in [
            (b"wrong".as_slice(), b"".as_slice()),
            (b"expected".as_slice(), b"unexpected".as_slice()),
        ] {
            let error = verifier
                .verify(AuthenticationRequest {
                    capability_token: token,
                    proof_of_possession: proof,
                    now: SystemTime::now(),
                })
                .await
                .unwrap_err();
            assert_eq!(error.code, GatewayErrorCode::TokenRejected);
        }
    }

    #[test]
    fn route_proof_requires_echoed_challenge() {
        let challenge = "a".repeat(64);
        let response = format!(
            "HTTP/1.1 200 OK\r\nX-OnionRoute-Fixture: v1\r\n\r\n{{\"fixture\":\"onionroute-controlled-http-v1\",\"challenge\":\"{challenge}\"}}"
        );
        verify_origin_response(response.as_bytes(), &challenge).unwrap();
        assert!(verify_origin_response(response.as_bytes(), &"b".repeat(64)).is_err());
    }

    #[test]
    fn onion_validation_is_v3_only() {
        assert!(validate_v3_onion(&format!("{}.onion", "a".repeat(56))).is_ok());
        assert!(validate_v3_onion("abcdefghijklmnop.onion").is_err());
        assert!(validate_v3_onion(&format!("{}.example", "a".repeat(56))).is_err());
    }
}
