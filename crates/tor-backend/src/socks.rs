use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use onionroute_common_types::error::{ErrorCode, RetryClass, SafetyImpact, Severity};
use onionroute_common_types::types::{IsolationKey, TcpHost};
use onionroute_common_types::OnionResult;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::tor_error;

const SOCKS_USERNAME: &[u8] = b"<torS0X>0";

pub(crate) async fn connect(
    proxy: SocketAddr,
    host: &TcpHost,
    port: u16,
    isolation: &IsolationKey,
    timeout: Duration,
) -> OnionResult<TcpStream> {
    if port == 0 {
        return Err(stream_error("Tor stream destination is invalid"));
    }
    tokio::time::timeout(timeout, connect_inner(proxy, host, port, isolation))
        .await
        .map_err(|_| stream_error("Tor SOCKS handshake timed out"))?
}

async fn connect_inner(
    proxy: SocketAddr,
    host: &TcpHost,
    port: u16,
    isolation: &IsolationKey,
) -> OnionResult<TcpStream> {
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(|_| stream_error("Tor SOCKS connection failed"))?;
    stream
        .write_all(&[5, 1, 2])
        .await
        .map_err(|_| stream_error("Tor SOCKS negotiation failed"))?;
    let mut method = [0_u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .map_err(|_| stream_error("Tor SOCKS negotiation failed"))?;
    if method != [5, 2] {
        return Err(stream_error("Tor refused SOCKS authentication isolation"));
    }

    let password = hex::encode(isolation.0);
    let mut authentication = Vec::with_capacity(3 + SOCKS_USERNAME.len() + password.len());
    authentication.extend_from_slice(&[1, SOCKS_USERNAME.len() as u8]);
    authentication.extend_from_slice(SOCKS_USERNAME);
    authentication.push(password.len() as u8);
    authentication.extend_from_slice(password.as_bytes());
    stream
        .write_all(&authentication)
        .await
        .map_err(|_| stream_error("Tor SOCKS authentication failed"))?;
    let mut auth_reply = [0_u8; 2];
    stream
        .read_exact(&mut auth_reply)
        .await
        .map_err(|_| stream_error("Tor SOCKS authentication failed"))?;
    if auth_reply != [1, 0] {
        return Err(stream_error("Tor SOCKS authentication was rejected"));
    }

    let mut request = Vec::with_capacity(4 + 255 + 2);
    request.extend_from_slice(&[5, 1, 0]);
    match host {
        TcpHost::Hostname(hostname) => {
            if hostname.is_empty()
                || hostname.len() > 253
                || hostname.contains(['\r', '\n', '\0'])
                || !hostname.is_ascii()
            {
                return Err(stream_error("Tor stream destination is invalid"));
            }
            request.push(3);
            request.push(hostname.len() as u8);
            request.extend_from_slice(hostname.as_bytes());
        }
        TcpHost::Ip(IpAddr::V4(address)) => {
            request.push(1);
            request.extend_from_slice(&address.octets());
        }
        TcpHost::Ip(IpAddr::V6(address)) => {
            request.push(4);
            request.extend_from_slice(&address.octets());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|_| stream_error("Tor SOCKS connect request failed"))?;

    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| stream_error("Tor SOCKS connect reply failed"))?;
    if header[0] != 5 || header[1] != 0 || header[2] != 0 {
        return Err(stream_error("Tor stream could not be opened"));
    }
    let address_len = match header[3] {
        1 => 4,
        4 => 16,
        3 => usize::from(
            stream
                .read_u8()
                .await
                .map_err(|_| stream_error("Tor SOCKS reply is malformed"))?,
        ),
        _ => return Err(stream_error("Tor SOCKS reply is malformed")),
    };
    let mut ignored = vec![0_u8; address_len + 2];
    stream
        .read_exact(&mut ignored)
        .await
        .map_err(|_| stream_error("Tor SOCKS reply is malformed"))?;
    Ok(stream)
}

pub(crate) fn onion_host(service_id: &str) -> OnionResult<TcpHost> {
    if service_id.len() != 56
        || !service_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
    {
        return Err(stream_error("invalid Tor v3 onion endpoint"));
    }
    Ok(TcpHost::Hostname(format!("{service_id}.onion")))
}

fn stream_error(message: &'static str) -> onionroute_common_types::OnionError {
    tor_error(
        ErrorCode::TorStreamFailed,
        Severity::Error,
        RetryClass::Backoff,
        SafetyImpact::Protected,
        message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onion_validation_does_not_echo_input() {
        let error = onion_host("not-an-onion").unwrap_err();
        assert!(!error.message.contains("not-an-onion"));
    }
}
