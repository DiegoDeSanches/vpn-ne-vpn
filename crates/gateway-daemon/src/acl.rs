//! Destination policy with hostname pre-check and resolved-address post-check.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

use ipnet::IpNet;

use crate::config::AclConfig;
use crate::{GatewayErrorCode, GatewayResult};

#[derive(Clone, Eq, PartialEq)]
pub enum Destination {
    Hostname(String),
    Ip(IpAddr),
}

#[derive(Clone, Default)]
struct EmergencyRules {
    networks: Vec<IpNet>,
    hostname_suffixes: Vec<String>,
}

/// Fail-closed policy engine. Emergency rules can only add denials.
#[derive(Clone)]
pub struct AclEngine {
    config: Arc<AclConfig>,
    emergency: Arc<RwLock<EmergencyRules>>,
}

impl AclEngine {
    pub fn new(config: AclConfig) -> Self {
        let emergency = EmergencyRules {
            networks: config.emergency_deny_networks.clone(),
            hostname_suffixes: config
                .emergency_deny_host_suffixes
                .iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
        };
        Self {
            config: Arc::new(config),
            emergency: Arc::new(RwLock::new(emergency)),
        }
    }

    pub fn replace_emergency_denies(
        &self,
        networks: Vec<IpNet>,
        hostname_suffixes: Vec<String>,
    ) -> GatewayResult<()> {
        if networks.len() > 256
            || hostname_suffixes.len() > 256
            || hostname_suffixes
                .iter()
                .any(|value| value.is_empty() || value.len() > 253 || !value.is_ascii())
        {
            return Err(GatewayErrorCode::PolicyDenied.into());
        }
        let mut rules = self
            .emergency
            .write()
            .map_err(|_| GatewayErrorCode::Internal)?;
        rules.networks = networks;
        rules.hostname_suffixes = hostname_suffixes
            .into_iter()
            .map(|value| value.to_ascii_lowercase())
            .collect();
        Ok(())
    }

    pub fn check_destination(&self, destination: &Destination, port: u16) -> GatewayResult<()> {
        self.check_port(port)?;
        match destination {
            Destination::Hostname(hostname) => {
                let canonical = canonical_hostname(hostname)?;
                if forbidden_hostname(&canonical) || self.emergency_hostname_denied(&canonical)? {
                    return Err(GatewayErrorCode::PolicyDenied.into());
                }
                Ok(())
            }
            Destination::Ip(address) => self.check_ip(*address),
        }
    }

    pub fn check_port(&self, port: u16) -> GatewayResult<()> {
        if port == 0
            || port == 25
            || port == 9051
            || port == 9151
            || (6881..=6889).contains(&port)
            || self.config.blocked_ports.contains(&port)
        {
            return Err(GatewayErrorCode::PolicyDenied.into());
        }
        Ok(())
    }

    /// Must be called for every address returned by DNS and again immediately
    /// before dialing it.
    pub fn check_ip(&self, address: IpAddr) -> GatewayResult<()> {
        if is_non_public(address)
            || self.config.cloud_metadata_ips.contains(&address)
            || self
                .config
                .management_networks
                .iter()
                .any(|network| network.contains(&address))
        {
            return Err(GatewayErrorCode::PolicyDenied.into());
        }
        let emergency = self
            .emergency
            .read()
            .map_err(|_| GatewayErrorCode::Internal)?;
        if emergency
            .networks
            .iter()
            .any(|network| network.contains(&address))
        {
            return Err(GatewayErrorCode::PolicyDenied.into());
        }
        Ok(())
    }

    fn emergency_hostname_denied(&self, hostname: &str) -> GatewayResult<bool> {
        let emergency = self
            .emergency
            .read()
            .map_err(|_| GatewayErrorCode::Internal)?;
        Ok(emergency
            .hostname_suffixes
            .iter()
            .any(|suffix| hostname == suffix || hostname.ends_with(&format!(".{suffix}"))))
    }
}

pub fn canonical_hostname(hostname: &str) -> GatewayResult<String> {
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    if hostname.is_empty() || hostname.len() > 253 || !hostname.is_ascii() {
        return Err(GatewayErrorCode::PolicyDenied.into());
    }
    if hostname.parse::<IpAddr>().is_ok() {
        return Err(GatewayErrorCode::PolicyDenied.into());
    }
    for label in hostname.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(GatewayErrorCode::PolicyDenied.into());
        }
    }
    Ok(hostname.to_ascii_lowercase())
}

fn forbidden_hostname(hostname: &str) -> bool {
    const EXACT: &[&str] = &[
        "localhost",
        "metadata",
        "metadata.google.internal",
        "instance-data",
        "kubernetes.default",
        "local",
        "internal",
        "home.arpa",
        "onion",
    ];
    const SUFFIXES: &[&str] = &[".localhost", ".local", ".internal", ".home.arpa", ".onion"];
    EXACT.contains(&hostname) || SUFFIXES.iter().any(|suffix| hostname.ends_with(suffix))
}

fn is_non_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_non_public_v4(address),
        IpAddr::V6(address) => is_non_public_v6(address),
    }
}

fn is_non_public_v4(address: Ipv4Addr) -> bool {
    let [a, b, _, _] = address.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0)
        || (a == 192 && b == 168)
        || (a == 192 && b == 88 && address.octets()[2] == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && address.octets()[2] == 100)
        || (a == 203 && b == 0 && address.octets()[2] == 113)
        || a >= 224
        || address.is_unspecified()
        || address.is_broadcast()
}

fn is_non_public_v6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] & 0xe000) != 0x2000
        || (segments[0] == 0x0064 && segments[1] == 0xff9b)
        || segments[0] == 0x2002
        || (segments[0] == 0x2001 && segments[1] == 0)
        || address.to_ipv4().is_some_and(is_non_public_v4)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl() -> AclEngine {
        AclEngine::new(AclConfig::default())
    }

    #[test]
    fn blocks_ssrf_ranges_and_metadata() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.1.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.100.100.200",
            "168.63.129.16",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert_eq!(
                acl().check_ip(address.parse().unwrap()).unwrap_err().code,
                GatewayErrorCode::PolicyDenied,
                "{address}"
            );
        }
        assert!(acl().check_ip("1.1.1.1".parse().unwrap()).is_ok());
        assert!(acl()
            .check_ip("2606:4700:4700::1111".parse().unwrap())
            .is_ok());
    }

    #[test]
    fn blocks_hostname_and_admin_ports() {
        assert!(acl()
            .check_destination(
                &Destination::Hostname("metadata.google.internal".into()),
                443
            )
            .is_err());
        assert!(acl()
            .check_destination(&Destination::Hostname("example.com".into()), 25)
            .is_err());
        assert!(acl()
            .check_destination(&Destination::Hostname("example.com".into()), 22)
            .is_err());
        assert!(acl()
            .check_destination(&Destination::Hostname("example.com".into()), 443)
            .is_ok());
    }
}
