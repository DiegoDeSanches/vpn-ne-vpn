use onionroute_gateway_protocol::client::{
    AuthenticationFuture, AuthenticationMaterial, ClientAuthenticator, ClientConfig,
    ClientReference,
};
use onionroute_gateway_protocol::negotiation::{FLOW_CONTROL_V1, TCP_CONNECT_V1};
use onionroute_gateway_protocol::proto::destination::Value;
use onionroute_gateway_protocol::proto::gateway_frame::Body;
use onionroute_gateway_protocol::proto::{
    AddressFamily, Destination, OpenTcpStream, ResolveDomain,
};
use onionroute_gateway_protocol::server::{
    AuthenticationDecision, AuthenticationVerifier, ServerConfig, ServerReference,
    VerificationFuture,
};
use onionroute_gateway_protocol::{ProtocolError, Result};

struct TestClientAuth;

impl ClientAuthenticator for TestClientAuth {
    fn authentication_material<'a>(
        &'a mut self,
        _session_binding: &'a [u8; 32],
    ) -> AuthenticationFuture<'a> {
        Box::pin(async {
            Ok(AuthenticationMaterial {
                anonymous_capability_token: b"anonymous-test-token".to_vec(),
                proof_of_possession: Vec::new(),
            })
        })
    }
}

struct TestVerifier;

impl AuthenticationVerifier for TestVerifier {
    fn verify<'a>(
        &'a mut self,
        token: &'a [u8],
        _proof: &'a [u8],
        _session_binding: &'a [u8; 32],
    ) -> VerificationFuture<'a> {
        Box::pin(async move {
            if token != b"anonymous-test-token" {
                return Ok(AuthenticationDecision::reject());
            }
            Ok(AuthenticationDecision {
                accepted: true,
                expires_at_unix_seconds: 4_102_444_800,
                granted_capabilities: vec![FLOW_CONTROL_V1.to_owned(), TCP_CONNECT_V1.to_owned()],
            })
        })
    }
}

#[tokio::test]
async fn client_server_handshake_open_and_data_conform() {
    let (client_io, server_io) = tokio::io::duplex(1 << 20);

    let server = async move {
        let mut server =
            ServerReference::accept(server_io, ServerConfig::default(), TestVerifier).await?;
        let request = match server.next_event().await? {
            Body::OpenTcpStream(request) => request,
            _ => return Err(ProtocolError::ProtocolViolation("expected open")),
        };
        server.accept_tcp(request.stream_id, 4096)?;
        server.flush().await?;
        match server.next_event().await? {
            Body::Data(data) if data.payload == b"hello" => Ok(()),
            _ => Err(ProtocolError::ProtocolViolation("expected data")),
        }
    };

    let client = async move {
        let mut client =
            ClientReference::connect(client_io, ClientConfig::default(), TestClientAuth).await?;
        assert!(matches!(
            client.resolve(ResolveDomain {
                query_id: 1,
                hostname: "example.com".to_owned(),
                address_family: AddressFamily::Any as i32,
                timeout_ms: 10_000,
            }),
            Err(ProtocolError::ProtocolViolation(_))
        ));
        client.open_tcp(OpenTcpStream {
            stream_id: 1,
            destination: Some(Destination {
                value: Some(Value::Hostname("example.com".to_owned())),
            }),
            destination_port: 443,
            timeout_ms: 10_000,
            policy_flags: 0,
            initial_receive_window: 4096,
        })?;
        client.flush().await?;
        match client.next_event().await? {
            Body::TcpStreamOpened(opened) if opened.stream_id == 1 => {}
            _ => return Err(ProtocolError::ProtocolViolation("expected opened")),
        }
        assert_eq!(client.session_mut().try_queue_data(1, b"hello")?, 5);
        client.flush().await
    };

    let (server_result, client_result): (Result<()>, Result<()>) = tokio::join!(server, client);
    server_result.unwrap();
    client_result.unwrap();
}

#[tokio::test]
async fn incompatible_client_receives_explicit_error() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let client_config = ClientConfig {
        supported_versions: onionroute_gateway_protocol::negotiation::version_range(2, 0, 0),
        ..ClientConfig::default()
    };

    let server = ServerReference::accept(server_io, ServerConfig::default(), TestVerifier);
    let client = ClientReference::connect(client_io, client_config, TestClientAuth);
    let (server_result, client_result) = tokio::join!(server, client);
    assert!(matches!(
        server_result,
        Err(ProtocolError::IncompatibleVersion)
    ));
    assert!(matches!(
        client_result,
        Err(ProtocolError::IncompatibleVersion)
    ));
}
