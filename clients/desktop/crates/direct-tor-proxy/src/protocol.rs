use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{ProxyLimits, TorSocksEndpoint, UpstreamAuthentication};

const SOCKS_VERSION: u8 = 5;
const AUTH_VERSION: u8 = 1;
const METHOD_NONE: u8 = 0;
const METHOD_USERNAME_PASSWORD: u8 = 2;
const METHOD_UNACCEPTABLE: u8 = 0xff;
const COMMAND_CONNECT: u8 = 1;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 3;
const ADDRESS_IPV6: u8 = 4;
const REPLY_SUCCESS: u8 = 0;
const REPLY_GENERAL_FAILURE: u8 = 1;
const REPLY_POLICY_DENIED: u8 = 2;
const REPLY_COMMAND_UNSUPPORTED: u8 = 7;
const REPLY_ADDRESS_UNSUPPORTED: u8 = 8;

enum DestinationAddress {
    Ipv4([u8; 4]),
    Domain(Vec<u8>),
}

struct Destination {
    address: DestinationAddress,
    port: u16,
}

pub(crate) async fn serve_client(
    mut client: TcpStream,
    tor: TorSocksEndpoint,
    limits: ProxyLimits,
) {
    let destination = match tokio::time::timeout(
        limits.client_handshake_timeout,
        accept_client_request(&mut client, limits),
    )
    .await
    {
        Ok(Ok(destination)) => destination,
        Ok(Err(_)) | Err(_) => return,
    };

    let mut upstream = match tokio::time::timeout(
        limits.upstream_connect_timeout,
        connect_only_to_tor(&tor, &destination, limits),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(reply)) => {
            let _ = send_reply(&mut client, reply).await;
            return;
        }
        Err(_) => {
            let _ = send_reply(&mut client, REPLY_GENERAL_FAILURE).await;
            return;
        }
    };

    if send_reply(&mut client, REPLY_SUCCESS).await.is_err() {
        return;
    }

    let _ = tokio::time::timeout(
        limits.max_stream_lifetime,
        tokio::io::copy_bidirectional_with_sizes(
            &mut client,
            &mut upstream,
            limits.relay_buffer_bytes,
            limits.relay_buffer_bytes,
        ),
    )
    .await;
}

async fn accept_client_request(
    client: &mut TcpStream,
    limits: ProxyLimits,
) -> Result<Destination, ()> {
    let mut greeting = [0_u8; 2];
    read_exact(client, &mut greeting).await?;
    let method_count = usize::from(greeting[1]);
    if greeting[0] != SOCKS_VERSION
        || method_count == 0
        || 2usize.saturating_add(method_count) > limits.max_frame_bytes
    {
        return Err(());
    }
    let mut methods = vec![0_u8; method_count];
    read_exact(client, &mut methods).await?;
    if !methods.contains(&METHOD_NONE) {
        let _ = client
            .write_all(&[SOCKS_VERSION, METHOD_UNACCEPTABLE])
            .await;
        return Err(());
    }
    client
        .write_all(&[SOCKS_VERSION, METHOD_NONE])
        .await
        .map_err(|_| ())?;

    let mut header = [0_u8; 4];
    read_exact(client, &mut header).await?;
    if header[0] != SOCKS_VERSION || header[2] != 0 {
        let _ = send_reply(client, REPLY_GENERAL_FAILURE).await;
        return Err(());
    }
    let mut accounted = 4usize;
    let mut address_rejected = false;
    let destination = match header[3] {
        ADDRESS_IPV4 => {
            let mut address = [0_u8; 4];
            read_exact(client, &mut address).await?;
            accounted += address.len();
            Some(DestinationAddress::Ipv4(address))
        }
        ADDRESS_DOMAIN => {
            let mut length = [0_u8; 1];
            read_exact(client, &mut length).await?;
            let length = usize::from(length[0]);
            accounted += 1;
            let mut domain = vec![0_u8; length];
            read_exact(client, &mut domain).await?;
            accounted += domain.len();
            if length == 0
                || length > limits.max_domain_bytes
                || accounted.saturating_add(2) > limits.max_frame_bytes
                || !valid_domain(&domain)
            {
                address_rejected = true;
                None
            } else {
                Some(DestinationAddress::Domain(domain))
            }
        }
        ADDRESS_IPV6 => {
            let mut ignored = [0_u8; 16];
            read_exact(client, &mut ignored).await?;
            accounted += ignored.len();
            address_rejected = true;
            None
        }
        _ => {
            let _ = send_reply(client, REPLY_ADDRESS_UNSUPPORTED).await;
            return Err(());
        }
    };

    let mut port = [0_u8; 2];
    read_exact(client, &mut port).await?;
    accounted += port.len();
    if header[1] != COMMAND_CONNECT {
        let _ = send_reply(client, REPLY_COMMAND_UNSUPPORTED).await;
        return Err(());
    }
    if address_rejected {
        let _ = send_reply(client, REPLY_ADDRESS_UNSUPPORTED).await;
        return Err(());
    }
    if accounted > limits.max_frame_bytes {
        let _ = send_reply(client, REPLY_GENERAL_FAILURE).await;
        return Err(());
    }
    let port = u16::from_be_bytes(port);
    if port == 0 || port == 25 {
        let _ = send_reply(client, REPLY_POLICY_DENIED).await;
        return Err(());
    }

    Ok(Destination {
        address: destination.ok_or(())?,
        port,
    })
}

async fn connect_only_to_tor(
    tor: &TorSocksEndpoint,
    destination: &Destination,
    limits: ProxyLimits,
) -> Result<TcpStream, u8> {
    // This is the sole outbound connect in the crate. Configuration validation
    // guarantees that its target is a loopback Tor SOCKS listener; destination
    // bytes are sent only inside the subsequent SOCKS request.
    let mut stream = TcpStream::connect(tor.address())
        .await
        .map_err(|_| REPLY_GENERAL_FAILURE)?;
    let _ = stream.set_nodelay(true);
    authenticate_to_tor(&mut stream, tor.authentication()).await?;

    let address_bytes = match &destination.address {
        DestinationAddress::Ipv4(_) => 1 + 4,
        DestinationAddress::Domain(domain) => 2 + domain.len(),
    };
    if 3usize.saturating_add(address_bytes).saturating_add(2) > limits.max_frame_bytes {
        return Err(REPLY_GENERAL_FAILURE);
    }
    let mut request = Vec::with_capacity(3 + address_bytes + 2);
    request.extend_from_slice(&[SOCKS_VERSION, COMMAND_CONNECT, 0]);
    match &destination.address {
        DestinationAddress::Ipv4(address) => {
            request.push(ADDRESS_IPV4);
            request.extend_from_slice(address);
        }
        DestinationAddress::Domain(domain) => {
            request.extend_from_slice(&[ADDRESS_DOMAIN, domain.len() as u8]);
            request.extend_from_slice(domain);
        }
    }
    request.extend_from_slice(&destination.port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|_| REPLY_GENERAL_FAILURE)?;

    let mut response = [0_u8; 4];
    read_exact_reply(&mut stream, &mut response).await?;
    if response[0] != SOCKS_VERSION || response[2] != 0 {
        return Err(REPLY_GENERAL_FAILURE);
    }
    consume_bound_address(&mut stream, response[3], limits).await?;
    if response[1] != REPLY_SUCCESS {
        return Err(if response[1] <= REPLY_ADDRESS_UNSUPPORTED {
            response[1]
        } else {
            REPLY_GENERAL_FAILURE
        });
    }
    Ok(stream)
}

async fn authenticate_to_tor(
    stream: &mut TcpStream,
    authentication: &UpstreamAuthentication,
) -> Result<(), u8> {
    let method = match authentication {
        UpstreamAuthentication::None => METHOD_NONE,
        UpstreamAuthentication::UsernamePassword { .. } => METHOD_USERNAME_PASSWORD,
    };
    stream
        .write_all(&[SOCKS_VERSION, 1, method])
        .await
        .map_err(|_| REPLY_GENERAL_FAILURE)?;
    let mut selection = [0_u8; 2];
    read_exact_reply(stream, &mut selection).await?;
    if selection != [SOCKS_VERSION, method] {
        return Err(REPLY_GENERAL_FAILURE);
    }
    if let UpstreamAuthentication::UsernamePassword { username, password } = authentication {
        let mut request = Vec::with_capacity(3 + username.len() + password.len());
        request.extend_from_slice(&[AUTH_VERSION, username.len() as u8]);
        request.extend_from_slice(username);
        request.push(password.len() as u8);
        request.extend_from_slice(password);
        stream
            .write_all(&request)
            .await
            .map_err(|_| REPLY_GENERAL_FAILURE)?;
        let mut response = [0_u8; 2];
        read_exact_reply(stream, &mut response).await?;
        if response != [AUTH_VERSION, 0] {
            return Err(REPLY_GENERAL_FAILURE);
        }
    }
    Ok(())
}

async fn consume_bound_address(
    stream: &mut TcpStream,
    address_type: u8,
    limits: ProxyLimits,
) -> Result<(), u8> {
    let (address_bytes, address_prefix_bytes) = match address_type {
        ADDRESS_IPV4 => (4, 0),
        ADDRESS_IPV6 => (16, 0),
        ADDRESS_DOMAIN => {
            let mut length = [0_u8; 1];
            read_exact_reply(stream, &mut length).await?;
            (usize::from(length[0]), 1)
        }
        _ => return Err(REPLY_GENERAL_FAILURE),
    };
    if address_bytes == 0
        || 4usize
            .saturating_add(address_prefix_bytes)
            .saturating_add(address_bytes)
            .saturating_add(2)
            > limits.max_frame_bytes
    {
        return Err(REPLY_GENERAL_FAILURE);
    }
    let mut ignored = vec![0_u8; address_bytes + 2];
    read_exact_reply(stream, &mut ignored).await
}

async fn send_reply(stream: &mut TcpStream, reply: u8) -> std::io::Result<()> {
    stream
        .write_all(&[SOCKS_VERSION, reply, 0, ADDRESS_IPV4, 0, 0, 0, 0, 0, 0])
        .await
}

async fn read_exact(stream: &mut TcpStream, bytes: &mut [u8]) -> Result<(), ()> {
    stream.read_exact(bytes).await.map(|_| ()).map_err(|_| ())
}

async fn read_exact_reply(stream: &mut TcpStream, bytes: &mut [u8]) -> Result<(), u8> {
    stream
        .read_exact(bytes)
        .await
        .map(|_| ())
        .map_err(|_| REPLY_GENERAL_FAILURE)
}

fn valid_domain(domain: &[u8]) -> bool {
    if domain.is_empty() || !domain.is_ascii() {
        return false;
    }
    domain.split(|byte| *byte == b'.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.first() != Some(&b'-')
            && label.last() != Some(&b'-')
            && label
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_ascii_bounded_labels() {
        assert!(valid_domain(b"example.com"));
        assert!(valid_domain(b"test-service.onion"));
        assert!(!valid_domain(b""));
        assert!(!valid_domain(b"bad..example"));
        assert!(!valid_domain(b"-bad.example"));
        assert!(!valid_domain(&[0xff, b'.', b'a']));
    }
}
