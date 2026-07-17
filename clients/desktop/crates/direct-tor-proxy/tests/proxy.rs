use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use onionroute_direct_tor_proxy::{
    DirectTorProxy, ProxyConfig, ProxyLimits, TorSocksEndpoint, UpstreamAuthentication,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(Debug, Eq, PartialEq)]
enum ObservedDestination {
    Domain(Vec<u8>, u16),
    Ipv4([u8; 4], u16),
}

#[derive(Clone)]
struct ExpectedAuthentication {
    username: Vec<u8>,
    password: Vec<u8>,
}

struct MockTor {
    address: SocketAddr,
    observed: mpsc::UnboundedReceiver<ObservedDestination>,
    connections: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl MockTor {
    async fn start(authentication: Option<ExpectedAuthentication>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (observed_tx, observed) = mpsc::unbounded_channel();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let tx = observed_tx.clone();
                let expected = authentication.clone();
                tokio::spawn(async move {
                    let _ = handle_mock_tor(stream, expected, tx).await;
                });
            }
        });
        Self {
            address,
            observed,
            connections,
            task,
        }
    }

    fn authentication(&self, expected: Option<ExpectedAuthentication>) -> UpstreamAuthentication {
        match expected {
            Some(expected) => UpstreamAuthentication::UsernamePassword {
                username: expected.username,
                password: expected.password,
            },
            None => UpstreamAuthentication::None,
        }
    }
}

impl Drop for MockTor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle_mock_tor(
    mut stream: TcpStream,
    expected: Option<ExpectedAuthentication>,
    observed: mpsc::UnboundedSender<ObservedDestination>,
) -> std::io::Result<()> {
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 5 || greeting[1] == 0 {
        return Ok(());
    }
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await?;
    match expected {
        Some(expected) => {
            if !methods.contains(&2) {
                stream.write_all(&[5, 0xff]).await?;
                return Ok(());
            }
            stream.write_all(&[5, 2]).await?;
            let mut auth_header = [0_u8; 2];
            stream.read_exact(&mut auth_header).await?;
            if auth_header[0] != 1 {
                return Ok(());
            }
            let mut username = vec![0_u8; usize::from(auth_header[1])];
            stream.read_exact(&mut username).await?;
            let password_len = stream.read_u8().await?;
            let mut password = vec![0_u8; usize::from(password_len)];
            stream.read_exact(&mut password).await?;
            if username != expected.username || password != expected.password {
                stream.write_all(&[1, 1]).await?;
                return Ok(());
            }
            stream.write_all(&[1, 0]).await?;
        }
        None => {
            if !methods.contains(&0) {
                stream.write_all(&[5, 0xff]).await?;
                return Ok(());
            }
            stream.write_all(&[5, 0]).await?;
        }
    }

    let mut request = [0_u8; 4];
    stream.read_exact(&mut request).await?;
    if request[..3] != [5, 1, 0] {
        return Ok(());
    }
    let destination = match request[3] {
        1 => {
            let mut address = [0_u8; 4];
            stream.read_exact(&mut address).await?;
            let port = stream.read_u16().await?;
            ObservedDestination::Ipv4(address, port)
        }
        3 => {
            let length = stream.read_u8().await?;
            let mut domain = vec![0_u8; usize::from(length)];
            stream.read_exact(&mut domain).await?;
            let port = stream.read_u16().await?;
            ObservedDestination::Domain(domain, port)
        }
        _ => return Ok(()),
    };
    let _ = observed.send(destination);
    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;

    let mut buffer = [0_u8; 1_024];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        stream.write_all(&buffer[..read]).await?;
    }
}

async fn start_proxy(
    mock: &MockTor,
    authentication: UpstreamAuthentication,
    limits: ProxyLimits,
) -> DirectTorProxy {
    let endpoint = TorSocksEndpoint::new(mock.address, authentication).unwrap();
    let mut config = ProxyConfig::new(0, endpoint);
    config.limits = limits;
    DirectTorProxy::start(config).await.unwrap()
}

async fn negotiate_client(address: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut response = [0_u8; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [5, 0]);
    stream
}

async fn send_request(stream: &mut TcpStream, request: &[u8]) -> u8 {
    stream.write_all(request).await.unwrap();
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], 5);
    let address_length = match header[3] {
        1 => 4,
        4 => 16,
        3 => usize::from(stream.read_u8().await.unwrap()),
        other => panic!("unexpected reply address type {other}"),
    };
    let mut ignored = vec![0_u8; address_length + 2];
    stream.read_exact(&mut ignored).await.unwrap();
    header[1]
}

fn domain_request(command: u8, domain: &[u8], port: u16) -> Vec<u8> {
    let mut request = vec![5, command, 0, 3, domain.len() as u8];
    request.extend_from_slice(domain);
    request.extend_from_slice(&port.to_be_bytes());
    request
}

fn ipv4_request(command: u8, address: [u8; 4], port: u16) -> Vec<u8> {
    let mut request = vec![5, command, 0, 1];
    request.extend_from_slice(&address);
    request.extend_from_slice(&port.to_be_bytes());
    request
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unresolved_domain_is_forwarded_unchanged_and_data_round_trips() {
    let mut mock = MockTor::start(None).await;
    let proxy = start_proxy(&mock, UpstreamAuthentication::None, ProxyLimits::default()).await;
    let mut client = negotiate_client(proxy.local_address()).await;
    let domain = b"never-resolve-this.invalid";
    assert_eq!(
        send_request(&mut client, &domain_request(1, domain, 443)).await,
        0
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), mock.observed.recv())
            .await
            .unwrap()
            .unwrap(),
        ObservedDestination::Domain(domain.to_vec(), 443)
    );
    client.write_all(b"round-trip").await.unwrap();
    let mut echoed = [0_u8; 10];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"round-trip");
    drop(client);
    proxy.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv4_and_tor_isolation_credentials_are_forwarded() {
    let expected = ExpectedAuthentication {
        username: b"<torS0X>0".to_vec(),
        password: b"identity-secret".to_vec(),
    };
    let mut mock = MockTor::start(Some(expected.clone())).await;
    let authentication = mock.authentication(Some(expected));
    let proxy = start_proxy(&mock, authentication, ProxyLimits::default()).await;
    let mut client = negotiate_client(proxy.local_address()).await;
    assert_eq!(
        send_request(&mut client, &ipv4_request(1, [203, 0, 113, 7], 80)).await,
        0
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), mock.observed.recv())
            .await
            .unwrap()
            .unwrap(),
        ObservedDestination::Ipv4([203, 0, 113, 7], 80)
    );
    drop(client);
    proxy.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bind_udp_ipv6_and_smtp_are_rejected_before_tor() {
    let mock = MockTor::start(None).await;
    let proxy = start_proxy(&mock, UpstreamAuthentication::None, ProxyLimits::default()).await;

    for command in [2, 3] {
        let mut client = negotiate_client(proxy.local_address()).await;
        assert_eq!(
            send_request(&mut client, &ipv4_request(command, [192, 0, 2, 1], 443)).await,
            7
        );
    }

    let mut ipv6 = negotiate_client(proxy.local_address()).await;
    let mut request = vec![5, 1, 0, 4];
    request.extend_from_slice(&[0_u8; 16]);
    request.extend_from_slice(&443_u16.to_be_bytes());
    assert_eq!(send_request(&mut ipv6, &request).await, 8);

    let mut smtp = negotiate_client(proxy.local_address()).await;
    assert_eq!(
        send_request(&mut smtp, &domain_request(1, b"mail.example", 25)).await,
        2
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(mock.connections.load(Ordering::SeqCst), 0);
    proxy.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_domain_and_greeting_are_bounded_before_tor() {
    let mock = MockTor::start(None).await;
    let limits = ProxyLimits {
        max_domain_bytes: 8,
        max_frame_bytes: 32,
        ..ProxyLimits::default()
    };
    let proxy = start_proxy(&mock, UpstreamAuthentication::None, limits).await;

    let mut domain = negotiate_client(proxy.local_address()).await;
    assert_eq!(
        send_request(&mut domain, &domain_request(1, b"ninechars", 443)).await,
        8
    );

    let mut greeting = TcpStream::connect(proxy.local_address()).await.unwrap();
    let mut oversized = vec![5, 40];
    oversized.extend_from_slice(&[0; 40]);
    greeting.write_all(&oversized).await.unwrap();
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(1), greeting.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
    assert_eq!(mock.connections.load(Ordering::SeqCst), 0);
    proxy.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_limit_and_slow_handshake_deadline_are_enforced() {
    let mock = MockTor::start(None).await;
    let limits = ProxyLimits {
        max_clients: 1,
        listen_backlog: 4,
        client_handshake_timeout: Duration::from_millis(120),
        ..ProxyLimits::default()
    };
    let proxy = start_proxy(&mock, UpstreamAuthentication::None, limits).await;

    let mut slow = TcpStream::connect(proxy.local_address()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(40)).await;
    let mut excess = TcpStream::connect(proxy.local_address()).await.unwrap();
    let _ = excess.write_all(&[5, 1, 0]).await;
    let mut response = [0_u8; 2];
    let excess_read = tokio::time::timeout(Duration::from_secs(1), excess.read(&mut response))
        .await
        .unwrap();
    assert!(matches!(excess_read, Ok(0) | Err(_)));

    let mut byte = [0_u8; 1];
    let slow_read = tokio::time::timeout(Duration::from_secs(1), slow.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(slow_read, Ok(0) | Err(_)));
    assert_eq!(mock.connections.load(Ordering::SeqCst), 0);
    proxy.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_tor_never_falls_back_to_the_destination() {
    let trap = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let trap_address = trap.local_addr().unwrap();
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_tor = unused.local_addr().unwrap();
    drop(unused);

    let tor = TorSocksEndpoint::new(unavailable_tor, UpstreamAuthentication::None).unwrap();
    let proxy = DirectTorProxy::start(ProxyConfig::new(0, tor))
        .await
        .unwrap();
    let mut client = negotiate_client(proxy.local_address()).await;
    let reply = send_request(
        &mut client,
        &ipv4_request(1, Ipv4Addr::LOCALHOST.octets(), trap_address.port()),
    )
    .await;
    assert_ne!(reply, 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), trap.accept())
            .await
            .is_err()
    );
    proxy.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_shutdown_closes_active_sessions() {
    let mut mock = MockTor::start(None).await;
    let proxy = start_proxy(&mock, UpstreamAuthentication::None, ProxyLimits::default()).await;
    let mut client = negotiate_client(proxy.local_address()).await;
    assert_eq!(
        send_request(&mut client, &domain_request(1, b"example.invalid", 443)).await,
        0
    );
    tokio::time::timeout(Duration::from_secs(1), mock.observed.recv())
        .await
        .unwrap()
        .unwrap();
    proxy.shutdown().await.unwrap();
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
}

#[test]
fn source_has_one_outbound_connect_and_no_resolver_or_destination_fallback() {
    let source = include_str!("../src/protocol.rs");
    assert_eq!(source.matches("TcpStream::connect(").count(), 1);
    assert!(source.contains("TcpStream::connect(tor.address())"));
    assert!(!source.contains("lookup_host"));
    assert!(!source.contains("ToSocketAddrs"));
}
