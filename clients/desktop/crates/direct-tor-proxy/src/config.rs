use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::ProxyError;

const MAX_CLIENT_LIMIT: usize = 4_096;
const MAX_LISTEN_BACKLOG: u32 = 4_096;
const MAX_FRAME_LIMIT: usize = 4_096;
const MAX_DOMAIN_LIMIT: usize = 253;
const MAX_RELAY_BUFFER: usize = 64 * 1024;
const MAX_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_STREAM_LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Authentication offered only to the already-running local Tor SOCKS port.
///
/// Username/password values are deliberately redacted from `Debug` output.
#[derive(Clone, Eq, PartialEq)]
pub enum UpstreamAuthentication {
    /// Offer SOCKS5 no-authentication to Tor.
    None,
    /// Offer RFC 1929 username/password authentication. Tor can use these
    /// opaque values as an `IsolateSOCKSAuth` circuit-isolation key.
    UsernamePassword {
        /// Opaque username, between 1 and 255 bytes.
        username: Vec<u8>,
        /// Opaque password, between 1 and 255 bytes.
        password: Vec<u8>,
    },
}

impl fmt::Debug for UpstreamAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("None"),
            Self::UsernamePassword { .. } => formatter.write_str("UsernamePassword([REDACTED])"),
        }
    }
}

impl UpstreamAuthentication {
    fn validate(&self) -> Result<(), ProxyError> {
        match self {
            Self::None => Ok(()),
            Self::UsernamePassword { username, password }
                if !username.is_empty()
                    && username.len() <= u8::MAX as usize
                    && !password.is_empty()
                    && password.len() <= u8::MAX as usize =>
            {
                Ok(())
            }
            Self::UsernamePassword { .. } => Err(ProxyError::InvalidConfiguration(
                "upstream SOCKS credentials must contain 1..255 bytes",
            )),
        }
    }
}

/// A validated local Tor SOCKS endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TorSocksEndpoint {
    address: SocketAddr,
    authentication: UpstreamAuthentication,
}

impl TorSocksEndpoint {
    /// Creates an endpoint only when it is loopback. The proxy never connects
    /// to a remotely supplied upstream SOCKS service.
    pub fn new(
        address: SocketAddr,
        authentication: UpstreamAuthentication,
    ) -> Result<Self, ProxyError> {
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(ProxyError::InvalidConfiguration(
                "Tor SOCKS endpoint must be a non-zero loopback address",
            ));
        }
        authentication.validate()?;
        Ok(Self {
            address,
            authentication,
        })
    }

    /// Returns the loopback Tor listener address.
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Returns the redacted authentication configuration.
    pub const fn authentication(&self) -> &UpstreamAuthentication {
        &self.authentication
    }
}

/// Hard resource and time limits for the proxy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyLimits {
    /// Maximum accepted client sessions, including incomplete handshakes.
    pub max_clients: usize,
    /// Kernel listen backlog. This is independent of `max_clients`.
    pub listen_backlog: u32,
    /// Maximum bytes accepted in one SOCKS greeting or request.
    pub max_frame_bytes: usize,
    /// Maximum accepted domain length. The protocol maximum is 253 bytes.
    pub max_domain_bytes: usize,
    /// Maximum fixed buffer allocated per relay direction.
    pub relay_buffer_bytes: usize,
    /// Complete inbound greeting/request deadline.
    pub client_handshake_timeout: Duration,
    /// Complete Tor connect and SOCKS handshake deadline.
    pub upstream_connect_timeout: Duration,
    /// Absolute upper bound for a connected proxied stream.
    pub max_stream_lifetime: Duration,
}

impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            max_clients: 128,
            listen_backlog: 128,
            max_frame_bytes: 512,
            max_domain_bytes: MAX_DOMAIN_LIMIT,
            relay_buffer_bytes: 16 * 1024,
            client_handshake_timeout: Duration::from_secs(10),
            upstream_connect_timeout: Duration::from_secs(60),
            max_stream_lifetime: Duration::from_secs(24 * 60 * 60),
        }
    }
}

impl ProxyLimits {
    pub(crate) fn validate(self) -> Result<(), ProxyError> {
        if self.max_clients == 0 || self.max_clients > MAX_CLIENT_LIMIT {
            return Err(ProxyError::InvalidConfiguration(
                "max_clients is outside the supported range",
            ));
        }
        if self.listen_backlog == 0 || self.listen_backlog > MAX_LISTEN_BACKLOG {
            return Err(ProxyError::InvalidConfiguration(
                "listen_backlog is outside the supported range",
            ));
        }
        if self.max_frame_bytes < 7 || self.max_frame_bytes > MAX_FRAME_LIMIT {
            return Err(ProxyError::InvalidConfiguration(
                "max_frame_bytes is outside the supported range",
            ));
        }
        if self.max_domain_bytes == 0 || self.max_domain_bytes > MAX_DOMAIN_LIMIT {
            return Err(ProxyError::InvalidConfiguration(
                "max_domain_bytes is outside the supported range",
            ));
        }
        if self.relay_buffer_bytes == 0 || self.relay_buffer_bytes > MAX_RELAY_BUFFER {
            return Err(ProxyError::InvalidConfiguration(
                "relay_buffer_bytes is outside the supported range",
            ));
        }
        if self.client_handshake_timeout.is_zero()
            || self.client_handshake_timeout > MAX_HANDSHAKE_TIMEOUT
        {
            return Err(ProxyError::InvalidConfiguration(
                "client_handshake_timeout is outside the supported range",
            ));
        }
        if self.upstream_connect_timeout.is_zero()
            || self.upstream_connect_timeout > MAX_UPSTREAM_TIMEOUT
        {
            return Err(ProxyError::InvalidConfiguration(
                "upstream_connect_timeout is outside the supported range",
            ));
        }
        if self.max_stream_lifetime.is_zero() || self.max_stream_lifetime > MAX_STREAM_LIFETIME {
            return Err(ProxyError::InvalidConfiguration(
                "max_stream_lifetime is outside the supported range",
            ));
        }
        Ok(())
    }
}

/// Complete daemon-facing startup configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyConfig {
    /// Listener address. Only the exact IPv4 loopback address is accepted; port
    /// zero requests an ephemeral port.
    pub listen_address: SocketAddr,
    /// Already-running local Tor SOCKS endpoint.
    pub tor: TorSocksEndpoint,
    /// Resource and deadline limits.
    pub limits: ProxyLimits,
}

impl ProxyConfig {
    /// Creates a configuration with default hard limits.
    pub fn new(listen_port: u16, tor: TorSocksEndpoint) -> Self {
        Self {
            listen_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port),
            tor,
            limits: ProxyLimits::default(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ProxyError> {
        if self.listen_address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err(ProxyError::InvalidConfiguration(
                "proxy listener must be exactly 127.0.0.1",
            ));
        }
        self.tor.authentication.validate()?;
        if !self.tor.address.ip().is_loopback() || self.tor.address.port() == 0 {
            return Err(ProxyError::InvalidConfiguration(
                "Tor SOCKS endpoint must be a non-zero loopback address",
            ));
        }
        self.limits.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> TorSocksEndpoint {
        TorSocksEndpoint::new(
            "127.0.0.1:9050".parse().unwrap(),
            UpstreamAuthentication::None,
        )
        .unwrap()
    }

    #[test]
    fn listener_and_upstream_are_restricted_to_loopback() {
        assert!(TorSocksEndpoint::new(
            "192.0.2.10:9050".parse().unwrap(),
            UpstreamAuthentication::None
        )
        .is_err());
        let mut config = ProxyConfig::new(0, endpoint());
        config.listen_address = "0.0.0.0:0".parse().unwrap();
        assert!(config.validate().is_err());
        config.listen_address = "[::1]:0".parse().unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn credentials_are_bounded_and_redacted() {
        let auth = UpstreamAuthentication::UsernamePassword {
            username: b"isolation".to_vec(),
            password: b"secret-value".to_vec(),
        };
        assert_eq!(format!("{auth:?}"), "UsernamePassword([REDACTED])");
        let invalid = UpstreamAuthentication::UsernamePassword {
            username: Vec::new(),
            password: vec![1],
        };
        assert!(TorSocksEndpoint::new("127.0.0.1:9050".parse().unwrap(), invalid).is_err());
    }

    #[test]
    fn every_limit_is_validated() {
        let limits = ProxyLimits {
            max_clients: 0,
            ..ProxyLimits::default()
        };
        assert!(limits.validate().is_err());
        let limits = ProxyLimits {
            max_domain_bytes: 254,
            ..ProxyLimits::default()
        };
        assert!(limits.validate().is_err());
        let limits = ProxyLimits {
            client_handshake_timeout: Duration::ZERO,
            ..ProxyLimits::default()
        };
        assert!(limits.validate().is_err());
    }
}
