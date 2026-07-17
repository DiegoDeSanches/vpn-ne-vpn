use std::io;
#[cfg(not(unix))]
use std::net::SocketAddr;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufStream, ReadBuf};
#[cfg(not(unix))]
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;

use onionroute_common_types::error::{ErrorCode, RetryClass, SafetyImpact, Severity};
use onionroute_common_types::OnionResult;

use crate::tor_error;

const MAX_CONTROL_LINE: usize = 8 * 1024;
const MAX_CONTROL_REPLY: usize = 64 * 1024;
const SAFECOOKIE_SERVER_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
const SAFECOOKIE_CLIENT_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

#[derive(Clone, Debug)]
pub(crate) enum ControlEndpoint {
    #[cfg(not(unix))]
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

enum ControlSocket {
    #[cfg(not(unix))]
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl AsyncRead for ControlSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(not(unix))]
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buffer),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_read(cx, buffer),
        }
    }
}

impl AsyncWrite for ControlSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            #[cfg(not(unix))]
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buffer),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_write(cx, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(not(unix))]
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(not(unix))]
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub(crate) struct ControlClient {
    stream: BufStream<ControlSocket>,
    command_timeout: Duration,
}

impl ControlClient {
    pub(crate) async fn connect_and_authenticate(
        endpoint: &ControlEndpoint,
        cookie_file: &Path,
        timeout: Duration,
    ) -> OnionResult<Self> {
        let socket = tokio::time::timeout(timeout, async {
            match endpoint {
                #[cfg(not(unix))]
                ControlEndpoint::Tcp(address) => {
                    TcpStream::connect(address).await.map(ControlSocket::Tcp)
                }
                #[cfg(unix)]
                ControlEndpoint::Unix(path) => {
                    UnixStream::connect(path).await.map(ControlSocket::Unix)
                }
            }
        })
        .await
        .map_err(|_| control_unavailable("Tor control connection timed out"))?
        .map_err(|_| control_unavailable("Tor control connection failed"))?;

        let mut client = Self {
            stream: BufStream::new(socket),
            command_timeout: timeout,
        };
        let protocol = client.command("PROTOCOLINFO 1").await?;
        if !protocol
            .iter()
            .any(|line| line.contains("AUTH METHODS=") && line.contains("SAFECOOKIE"))
        {
            return Err(control_security_error("Tor SAFECOOKIE is unavailable"));
        }

        let cookie = tokio::fs::read(cookie_file)
            .await
            .map_err(|_| control_security_error("Tor control cookie is unavailable"))?;
        if cookie.len() != 32 {
            return Err(control_security_error(
                "Tor control cookie has invalid length",
            ));
        }
        let mut client_nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut client_nonce);
        let challenge = client
            .command(&format!(
                "AUTHCHALLENGE SAFECOOKIE {}",
                hex::encode_upper(client_nonce)
            ))
            .await?;
        let challenge_line = challenge
            .iter()
            .find(|line| line.contains("AUTHCHALLENGE"))
            .ok_or_else(|| control_security_error("Tor SAFECOOKIE response is malformed"))?;
        let server_hash = parse_hex_field(challenge_line, "SERVERHASH=")?;
        let server_nonce = parse_hex_field(challenge_line, "SERVERNONCE=")?;
        if server_hash.len() != 32 || server_nonce.len() != 32 {
            return Err(control_security_error(
                "Tor SAFECOOKIE response has invalid length",
            ));
        }

        let expected =
            safe_cookie_hmac(SAFECOOKIE_SERVER_KEY, &cookie, &client_nonce, &server_nonce)?;
        if expected.as_slice().ct_eq(&server_hash).unwrap_u8() != 1 {
            return Err(control_security_error("Tor SAFECOOKIE server proof failed"));
        }
        let client_hash =
            safe_cookie_hmac(SAFECOOKIE_CLIENT_KEY, &cookie, &client_nonce, &server_nonce)?;
        client
            .command(&format!("AUTHENTICATE {}", hex::encode_upper(client_hash)))
            .await?;
        client.command("TAKEOWNERSHIP").await?;
        Ok(client)
    }

    pub(crate) async fn command(&mut self, command: &str) -> OnionResult<Vec<String>> {
        tokio::time::timeout(self.command_timeout, self.command_inner(command))
            .await
            .map_err(|_| control_unavailable("Tor control command timed out"))?
    }

    async fn command_inner(&mut self, command: &str) -> OnionResult<Vec<String>> {
        if command.contains(['\r', '\n', '\0']) || command.len() > MAX_CONTROL_LINE {
            return Err(control_security_error("invalid Tor control command"));
        }
        self.stream
            .write_all(command.as_bytes())
            .await
            .map_err(|_| control_unavailable("Tor control write failed"))?;
        self.stream
            .write_all(b"\r\n")
            .await
            .map_err(|_| control_unavailable("Tor control write failed"))?;
        self.stream
            .flush()
            .await
            .map_err(|_| control_unavailable("Tor control flush failed"))?;

        let mut lines = Vec::new();
        let mut total = 0_usize;
        loop {
            let mut bytes = Vec::new();
            let count = self
                .stream
                .read_until(b'\n', &mut bytes)
                .await
                .map_err(|_| control_unavailable("Tor control read failed"))?;
            if count == 0 || count > MAX_CONTROL_LINE {
                return Err(control_security_error("Tor control reply is malformed"));
            }
            total = total.saturating_add(count);
            if total > MAX_CONTROL_REPLY {
                return Err(control_security_error("Tor control reply exceeds limit"));
            }
            if bytes.ends_with(b"\n") {
                bytes.pop();
            }
            if bytes.ends_with(b"\r") {
                bytes.pop();
            }
            let line = String::from_utf8(bytes)
                .map_err(|_| control_security_error("Tor control reply is not UTF-8"))?;
            if line.len() < 4 || !line[..3].bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(control_security_error("Tor control reply is malformed"));
            }
            let code = line[..3].parse::<u16>().unwrap_or(0);
            let separator = line.as_bytes()[3];
            lines.push(line);
            if separator == b' ' {
                if code != 250 {
                    return Err(control_unavailable("Tor control command was rejected"));
                }
                return Ok(lines);
            }
            if separator != b'-' {
                return Err(control_security_error(
                    "unsupported Tor control reply framing",
                ));
            }
        }
    }
}

fn safe_cookie_hmac(
    key: &[u8],
    cookie: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> OnionResult<Vec<u8>> {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| control_security_error("Tor SAFECOOKIE HMAC initialization failed"))?;
    hmac.update(cookie);
    hmac.update(client_nonce);
    hmac.update(server_nonce);
    Ok(hmac.finalize().into_bytes().to_vec())
}

fn parse_hex_field(line: &str, name: &str) -> OnionResult<Vec<u8>> {
    let value = line
        .split_ascii_whitespace()
        .find_map(|part| part.strip_prefix(name))
        .ok_or_else(|| control_security_error("Tor SAFECOOKIE response is incomplete"))?;
    hex::decode(value).map_err(|_| control_security_error("Tor SAFECOOKIE response is malformed"))
}

fn control_unavailable(message: &'static str) -> onionroute_common_types::OnionError {
    tor_error(
        ErrorCode::TorUnavailable,
        Severity::Error,
        RetryClass::Backoff,
        SafetyImpact::Protected,
        message,
    )
}

fn control_security_error(message: &'static str) -> onionroute_common_types::OnionError {
    tor_error(
        ErrorCode::TorUnavailable,
        Severity::Fatal,
        RetryClass::Never,
        SafetyImpact::MustBlock,
        message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_cookie_vector_is_stable() {
        let cookie = [1_u8; 32];
        let client = [2_u8; 32];
        let server = [3_u8; 32];
        let result = safe_cookie_hmac(SAFECOOKIE_CLIENT_KEY, &cookie, &client, &server).unwrap();
        assert_eq!(result.len(), 32);
        assert_ne!(
            result,
            safe_cookie_hmac(SAFECOOKIE_SERVER_KEY, &cookie, &client, &server).unwrap()
        );
    }
}
