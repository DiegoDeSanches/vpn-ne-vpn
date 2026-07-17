//! Explicit-upstream DNS with bounded wire parsing and connect-time revalidation.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::acl::{canonical_hostname, AclEngine};
use crate::config::DnsConfig;
use crate::{GatewayErrorCode, GatewayResult};

const DNS_HEADER_BYTES: usize = 12;
const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

#[derive(Clone, Eq, PartialEq)]
pub struct Resolution {
    pub addresses: Vec<IpAddr>,
    pub cname_depth: usize,
    pub response_bytes: usize,
}

#[async_trait]
pub trait DnsResolver: Send + Sync + 'static {
    /// Resolves twice when configured, validates every returned address, and
    /// returns only addresses from the final lookup. The connector dials these
    /// IPs directly, never the hostname.
    async fn resolve_for_connect(&self, hostname: &str) -> GatewayResult<Resolution>;

    /// Handles the bounded v1 DNS-wire feature. The response is checked for
    /// internal addresses and CNAME abuse before it is returned to the client.
    async fn exchange_wire(&self, query: &[u8]) -> GatewayResult<Vec<u8>>;
}

#[async_trait]
pub trait DnsTransport: Send + Sync + 'static {
    async fn exchange(
        &self,
        upstream: SocketAddr,
        query: &[u8],
        max_response_bytes: usize,
        timeout: Duration,
    ) -> GatewayResult<Vec<u8>>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UdpTcpDnsTransport;

#[async_trait]
impl DnsTransport for UdpTcpDnsTransport {
    async fn exchange(
        &self,
        upstream: SocketAddr,
        query: &[u8],
        max_response_bytes: usize,
        timeout: Duration,
    ) -> GatewayResult<Vec<u8>> {
        let bind_address = if upstream.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = tokio::time::timeout(timeout, UdpSocket::bind(bind_address))
            .await
            .map_err(|_| GatewayErrorCode::Timeout)?
            .map_err(|_| GatewayErrorCode::DnsFailure)?;
        tokio::time::timeout(timeout, socket.connect(upstream))
            .await
            .map_err(|_| GatewayErrorCode::Timeout)?
            .map_err(|_| GatewayErrorCode::DnsFailure)?;
        tokio::time::timeout(timeout, socket.send(query))
            .await
            .map_err(|_| GatewayErrorCode::Timeout)?
            .map_err(|_| GatewayErrorCode::DnsFailure)?;

        let mut response = vec![0u8; max_response_bytes.saturating_add(1)];
        let received = tokio::time::timeout(timeout, socket.recv(&mut response))
            .await
            .map_err(|_| GatewayErrorCode::Timeout)?
            .map_err(|_| GatewayErrorCode::DnsFailure)?;
        if received > max_response_bytes || received < DNS_HEADER_BYTES {
            return Err(GatewayErrorCode::MessageTooLarge.into());
        }
        response.truncate(received);
        if u16::from_be_bytes([response[2], response[3]]) & 0x0200 == 0 {
            return Ok(response);
        }

        exchange_tcp(upstream, query, max_response_bytes, timeout).await
    }
}

async fn exchange_tcp(
    upstream: SocketAddr,
    query: &[u8],
    max_response_bytes: usize,
    timeout: Duration,
) -> GatewayResult<Vec<u8>> {
    let query_len = u16::try_from(query.len()).map_err(|_| GatewayErrorCode::MessageTooLarge)?;
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(upstream))
        .await
        .map_err(|_| GatewayErrorCode::Timeout)?
        .map_err(|_| GatewayErrorCode::DnsFailure)?;
    tokio::time::timeout(timeout, async {
        stream.write_all(&query_len.to_be_bytes()).await?;
        stream.write_all(query).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| GatewayErrorCode::Timeout)?
    .map_err(|_| GatewayErrorCode::DnsFailure)?;

    let response_len = tokio::time::timeout(timeout, stream.read_u16())
        .await
        .map_err(|_| GatewayErrorCode::Timeout)?
        .map_err(|_| GatewayErrorCode::DnsFailure)? as usize;
    if response_len < DNS_HEADER_BYTES || response_len > max_response_bytes {
        return Err(GatewayErrorCode::MessageTooLarge.into());
    }
    let mut response = vec![0u8; response_len];
    tokio::time::timeout(timeout, stream.read_exact(&mut response))
        .await
        .map_err(|_| GatewayErrorCode::Timeout)?
        .map_err(|_| GatewayErrorCode::DnsFailure)?;
    Ok(response)
}

/// DNS resolver that does not use the host's implicit resolver configuration.
pub struct WireDnsResolver<T> {
    config: DnsConfig,
    acl: AclEngine,
    transport: Arc<T>,
    upstream_cursor: AtomicUsize,
}

impl<T> WireDnsResolver<T>
where
    T: DnsTransport,
{
    pub fn new(config: DnsConfig, acl: AclEngine, transport: T) -> GatewayResult<Self> {
        if config.upstreams.is_empty() {
            return Err(GatewayErrorCode::InvalidConfiguration.into());
        }
        Ok(Self {
            config,
            acl,
            transport: Arc::new(transport),
            upstream_cursor: AtomicUsize::new(0),
        })
    }

    async fn lookup(&self, hostname: &str) -> GatewayResult<Resolution> {
        let mut addresses = Vec::new();
        let mut response_bytes = 0usize;
        let mut cname_depth = 0usize;
        for record_type in [TYPE_A, TYPE_AAAA] {
            let result = self.lookup_type(hostname, record_type).await?;
            response_bytes = response_bytes
                .checked_add(result.response_bytes)
                .ok_or(GatewayErrorCode::MessageTooLarge)?;
            cname_depth = cname_depth.max(result.cname_depth);
            addresses.extend(result.addresses);
        }
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() || addresses.len() > self.config.max_addresses {
            return Err(GatewayErrorCode::DnsFailure.into());
        }
        Ok(Resolution {
            addresses,
            cname_depth,
            response_bytes,
        })
    }

    async fn lookup_type(&self, hostname: &str, record_type: u16) -> GatewayResult<Resolution> {
        let mut current = hostname.to_owned();
        let mut visited = HashSet::new();
        let mut total_depth = 0usize;
        let mut response_bytes = 0usize;
        loop {
            if !visited.insert(current.clone()) || total_depth > self.config.max_cname_depth {
                return Err(GatewayErrorCode::DnsFailure.into());
            }
            let id = random_id()?;
            let query = build_query(id, &current, record_type)?;
            let response = self.exchange(&query).await?;
            response_bytes = response_bytes
                .checked_add(response.len())
                .ok_or(GatewayErrorCode::MessageTooLarge)?;
            let parsed = parse_response(&response, id, &current, self.config.max_records)?;
            total_depth = total_depth
                .checked_add(parsed.cname_depth)
                .ok_or(GatewayErrorCode::DnsFailure)?;
            if total_depth > self.config.max_cname_depth {
                return Err(GatewayErrorCode::DnsFailure.into());
            }
            if !parsed.addresses.is_empty() {
                return Ok(Resolution {
                    addresses: parsed.addresses,
                    cname_depth: total_depth,
                    response_bytes,
                });
            }
            if parsed.terminal_name == current {
                return Ok(Resolution {
                    addresses: Vec::new(),
                    cname_depth: total_depth,
                    response_bytes,
                });
            }
            current = parsed.terminal_name;
        }
    }

    async fn exchange(&self, query: &[u8]) -> GatewayResult<Vec<u8>> {
        let index =
            self.upstream_cursor.fetch_add(1, Ordering::Relaxed) % self.config.upstreams.len();
        self.transport
            .exchange(
                self.config.upstreams[index],
                query,
                self.config.max_response_bytes,
                self.config.timeout(),
            )
            .await
    }

    fn validate_resolution(&self, resolution: &Resolution) -> GatewayResult<()> {
        if resolution.addresses.is_empty()
            || resolution.addresses.len() > self.config.max_addresses
            || resolution.cname_depth > self.config.max_cname_depth
            || resolution.response_bytes > self.config.max_response_bytes * 4
        {
            return Err(GatewayErrorCode::DnsFailure.into());
        }
        for address in &resolution.addresses {
            self.acl
                .check_ip(*address)
                .map_err(|_| GatewayErrorCode::DnsRebinding)?;
        }
        Ok(())
    }
}

#[async_trait]
impl<T> DnsResolver for WireDnsResolver<T>
where
    T: DnsTransport,
{
    async fn resolve_for_connect(&self, hostname: &str) -> GatewayResult<Resolution> {
        let hostname = canonical_hostname(hostname)?;
        let first = self.lookup(&hostname).await?;
        self.validate_resolution(&first)?;
        if !self.config.revalidate {
            return Ok(first);
        }

        // The second answer is checked independently and is the only one used
        // for direct-IP connect. Public load-balancer changes are allowed, while
        // a public-to-private rebind fails closed.
        let second = self.lookup(&hostname).await?;
        self.validate_resolution(&second)?;
        Ok(second)
    }

    async fn exchange_wire(&self, query: &[u8]) -> GatewayResult<Vec<u8>> {
        let question = validate_client_query(query, self.config.max_response_bytes)?;
        let response = self.exchange(query).await?;
        let parsed = parse_response(
            &response,
            question.id,
            &question.name,
            self.config.max_records,
        )?;
        if parsed.cname_depth > self.config.max_cname_depth {
            return Err(GatewayErrorCode::DnsFailure.into());
        }
        for address in parsed.all_addresses {
            self.acl
                .check_ip(address)
                .map_err(|_| GatewayErrorCode::DnsRebinding)?;
        }
        Ok(response)
    }
}

fn random_id() -> GatewayResult<u16> {
    let mut bytes = [0u8; 2];
    getrandom::getrandom(&mut bytes).map_err(|_| GatewayErrorCode::Internal)?;
    Ok(u16::from_be_bytes(bytes))
}

fn build_query(id: u16, hostname: &str, record_type: u16) -> GatewayResult<Vec<u8>> {
    let mut query = Vec::with_capacity(512);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&[0u8; 6]);
    encode_name(hostname, &mut query)?;
    query.extend_from_slice(&record_type.to_be_bytes());
    query.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(query)
}

fn encode_name(hostname: &str, output: &mut Vec<u8>) -> GatewayResult<()> {
    for label in hostname.split('.') {
        let length = u8::try_from(label.len()).map_err(|_| GatewayErrorCode::DnsFailure)?;
        if length == 0 || length > 63 {
            return Err(GatewayErrorCode::DnsFailure.into());
        }
        output.push(length);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    Ok(())
}

#[derive(Debug)]
struct ClientQuestion {
    id: u16,
    name: String,
}

fn validate_client_query(query: &[u8], max_bytes: usize) -> GatewayResult<ClientQuestion> {
    if query.len() < DNS_HEADER_BYTES || query.len() > max_bytes {
        return Err(GatewayErrorCode::MessageTooLarge.into());
    }
    let flags = read_u16(query, 2)?;
    let questions = read_u16(query, 4)?;
    let answers = read_u16(query, 6)?;
    let authorities = read_u16(query, 8)?;
    let additional = read_u16(query, 10)?;
    if flags & 0x8000 != 0 || questions != 1 || answers != 0 || authorities != 0 || additional != 0
    {
        // EDNS is rejected in v1, which also prevents ECS forwarding.
        return Err(GatewayErrorCode::ProtocolViolation.into());
    }
    let (name, cursor) = read_name(query, DNS_HEADER_BYTES)?;
    if cursor + 4 != query.len() {
        return Err(GatewayErrorCode::ProtocolViolation.into());
    }
    let _ = canonical_hostname(&name)?;
    Ok(ClientQuestion {
        id: read_u16(query, 0)?,
        name,
    })
}

#[derive(Clone, Debug)]
enum AnswerData {
    Address(IpAddr),
    Cname(String),
    Other,
}

#[derive(Clone, Debug)]
struct AnswerRecord {
    owner: String,
    data: AnswerData,
}

#[derive(Debug)]
struct ParsedResponse {
    addresses: Vec<IpAddr>,
    all_addresses: Vec<IpAddr>,
    terminal_name: String,
    cname_depth: usize,
}

fn parse_response(
    wire: &[u8],
    expected_id: u16,
    expected_name: &str,
    max_records: usize,
) -> GatewayResult<ParsedResponse> {
    if wire.len() < DNS_HEADER_BYTES || read_u16(wire, 0)? != expected_id {
        return Err(GatewayErrorCode::DnsFailure.into());
    }
    let flags = read_u16(wire, 2)?;
    let qdcount = usize::from(read_u16(wire, 4)?);
    let ancount = usize::from(read_u16(wire, 6)?);
    let nscount = usize::from(read_u16(wire, 8)?);
    let arcount = usize::from(read_u16(wire, 10)?);
    let total_records = ancount
        .checked_add(nscount)
        .and_then(|value| value.checked_add(arcount))
        .ok_or(GatewayErrorCode::DnsFailure)?;
    if flags & 0x8000 == 0 || flags & 0x000f != 0 || qdcount != 1 || total_records > max_records {
        return Err(GatewayErrorCode::DnsFailure.into());
    }

    let (question_name, mut cursor) = read_name(wire, DNS_HEADER_BYTES)?;
    if question_name != expected_name || cursor + 4 > wire.len() {
        return Err(GatewayErrorCode::DnsFailure.into());
    }
    cursor += 4;

    let mut answers = Vec::with_capacity(ancount);
    let mut all_addresses = Vec::new();
    for index in 0..total_records {
        let (owner, name_end) = read_name(wire, cursor)?;
        cursor = name_end;
        if cursor + 10 > wire.len() {
            return Err(GatewayErrorCode::DnsFailure.into());
        }
        let record_type = read_u16(wire, cursor)?;
        let class = read_u16(wire, cursor + 2)?;
        let data_length = usize::from(read_u16(wire, cursor + 8)?);
        cursor += 10;
        let data_end = cursor
            .checked_add(data_length)
            .ok_or(GatewayErrorCode::DnsFailure)?;
        if data_end > wire.len() {
            return Err(GatewayErrorCode::DnsFailure.into());
        }
        let data = if class == CLASS_IN && record_type == TYPE_A && data_length == 4 {
            let address = IpAddr::V4(Ipv4Addr::new(
                wire[cursor],
                wire[cursor + 1],
                wire[cursor + 2],
                wire[cursor + 3],
            ));
            all_addresses.push(address);
            AnswerData::Address(address)
        } else if class == CLASS_IN && record_type == TYPE_AAAA && data_length == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&wire[cursor..data_end]);
            let address = IpAddr::V6(Ipv6Addr::from(octets));
            all_addresses.push(address);
            AnswerData::Address(address)
        } else if class == CLASS_IN && record_type == TYPE_CNAME {
            let (target, consumed) = read_name(wire, cursor)?;
            if consumed != data_end {
                return Err(GatewayErrorCode::DnsFailure.into());
            }
            AnswerData::Cname(target)
        } else {
            AnswerData::Other
        };
        if index < ancount {
            answers.push(AnswerRecord { owner, data });
        }
        cursor = data_end;
    }
    if cursor != wire.len() {
        return Err(GatewayErrorCode::DnsFailure.into());
    }

    let mut current = expected_name.to_owned();
    let mut visited = HashSet::new();
    let mut depth = 0usize;
    loop {
        if !visited.insert(current.clone()) {
            return Err(GatewayErrorCode::DnsFailure.into());
        }
        let addresses: Vec<IpAddr> = answers
            .iter()
            .filter(|record| record.owner == current)
            .filter_map(|record| match record.data {
                AnswerData::Address(address) => Some(address),
                _ => None,
            })
            .collect();
        if !addresses.is_empty() {
            return Ok(ParsedResponse {
                addresses,
                all_addresses,
                terminal_name: current,
                cname_depth: depth,
            });
        }
        let aliases: Vec<&String> = answers
            .iter()
            .filter(|record| record.owner == current)
            .filter_map(|record| match &record.data {
                AnswerData::Cname(target) => Some(target),
                _ => None,
            })
            .collect();
        if aliases.is_empty() {
            return Ok(ParsedResponse {
                addresses: Vec::new(),
                all_addresses,
                terminal_name: current,
                cname_depth: depth,
            });
        }
        if aliases.len() != 1 {
            return Err(GatewayErrorCode::DnsFailure.into());
        }
        current.clone_from(aliases[0]);
        depth = depth.checked_add(1).ok_or(GatewayErrorCode::DnsFailure)?;
        if depth > 16 {
            return Err(GatewayErrorCode::DnsFailure.into());
        }
    }
}

fn read_name(wire: &[u8], start: usize) -> GatewayResult<(String, usize)> {
    let mut cursor = start;
    let mut consumed_end = None;
    let mut labels = Vec::new();
    let mut visited = HashSet::new();
    let mut expanded = 0usize;
    for _ in 0..=16 {
        if !visited.insert(cursor) {
            return Err(GatewayErrorCode::DnsFailure.into());
        }
        let length = *wire.get(cursor).ok_or(GatewayErrorCode::DnsFailure)?;
        if length & 0xc0 == 0xc0 {
            let second = *wire.get(cursor + 1).ok_or(GatewayErrorCode::DnsFailure)?;
            let target = usize::from((u16::from(length & 0x3f) << 8) | u16::from(second));
            if target >= wire.len() {
                return Err(GatewayErrorCode::DnsFailure.into());
            }
            consumed_end.get_or_insert(cursor + 2);
            cursor = target;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(GatewayErrorCode::DnsFailure.into());
        }
        cursor += 1;
        if length == 0 {
            if labels.is_empty() || expanded > 253 {
                return Err(GatewayErrorCode::DnsFailure.into());
            }
            return Ok((labels.join("."), consumed_end.unwrap_or(cursor)));
        }
        let length = usize::from(length);
        let end = cursor
            .checked_add(length)
            .ok_or(GatewayErrorCode::DnsFailure)?;
        let label = wire.get(cursor..end).ok_or(GatewayErrorCode::DnsFailure)?;
        if length > 63
            || !label
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            || label.first() == Some(&b'-')
            || label.last() == Some(&b'-')
        {
            return Err(GatewayErrorCode::DnsFailure.into());
        }
        labels.push(
            std::str::from_utf8(label)
                .map_err(|_| GatewayErrorCode::DnsFailure)?
                .to_ascii_lowercase(),
        );
        expanded = expanded
            .checked_add(length + usize::from(labels.len() > 1))
            .ok_or(GatewayErrorCode::DnsFailure)?;
        cursor = end;
    }
    Err(GatewayErrorCode::DnsFailure.into())
}

fn read_u16(wire: &[u8], offset: usize) -> GatewayResult<u16> {
    let bytes = wire
        .get(offset..offset + 2)
        .ok_or(GatewayErrorCode::DnsFailure)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AclConfig;
    use std::sync::Mutex;

    struct SequenceTransport {
        addresses: Mutex<Vec<Ipv4Addr>>,
    }

    struct CnameTransport {
        targets: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl DnsTransport for CnameTransport {
        async fn exchange(
            &self,
            _upstream: SocketAddr,
            query: &[u8],
            _max_response_bytes: usize,
            _timeout: Duration,
        ) -> GatewayResult<Vec<u8>> {
            let target = self.targets.lock().unwrap().remove(0);
            Ok(cname_response(query, &target))
        }
    }

    #[async_trait]
    impl DnsTransport for SequenceTransport {
        async fn exchange(
            &self,
            _upstream: SocketAddr,
            query: &[u8],
            _max_response_bytes: usize,
            _timeout: Duration,
        ) -> GatewayResult<Vec<u8>> {
            let address = self.addresses.lock().unwrap().remove(0);
            Ok(a_response(query, address))
        }
    }

    fn a_response(query: &[u8], address: Ipv4Addr) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0u8; 4]);
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&TYPE_A.to_be_bytes());
        response.extend_from_slice(&CLASS_IN.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&address.octets());
        response
    }

    fn cname_response(query: &[u8], target: &str) -> Vec<u8> {
        let mut encoded_target = Vec::new();
        encode_name(target, &mut encoded_target).unwrap();
        let mut response = Vec::new();
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0u8; 4]);
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&TYPE_CNAME.to_be_bytes());
        response.extend_from_slice(&CLASS_IN.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&(encoded_target.len() as u16).to_be_bytes());
        response.extend_from_slice(&encoded_target);
        response
    }

    fn config() -> DnsConfig {
        DnsConfig {
            upstreams: vec!["127.0.0.1:53".parse().unwrap()],
            ..DnsConfig::default()
        }
    }

    #[tokio::test]
    async fn dns_rebinding_to_private_address_is_blocked() {
        // A and AAAA are queried for each pass. This mock returns an A-shaped
        // record for both types; the parser still validates the actual RDATA.
        let transport = SequenceTransport {
            addresses: Mutex::new(vec![
                Ipv4Addr::new(1, 1, 1, 1),
                Ipv4Addr::new(1, 1, 1, 1),
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 1),
            ]),
        };
        let resolver =
            WireDnsResolver::new(config(), AclEngine::new(AclConfig::default()), transport)
                .unwrap();
        let error = resolver
            .resolve_for_connect("example.com")
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, GatewayErrorCode::DnsRebinding);
    }

    #[tokio::test]
    async fn cname_chain_limit_is_enforced() {
        let mut dns_config = config();
        dns_config.max_cname_depth = 1;
        let transport = CnameTransport {
            targets: Mutex::new(vec!["b.example".into(), "c.example".into()]),
        };
        let resolver =
            WireDnsResolver::new(dns_config, AclEngine::new(AclConfig::default()), transport)
                .unwrap();
        let error = resolver
            .resolve_for_connect("a.example")
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, GatewayErrorCode::DnsFailure);
    }

    #[test]
    fn compression_pointer_loop_is_rejected() {
        let mut wire = vec![0u8; 14];
        wire[12] = 0xc0;
        wire[13] = 0x0c;
        assert!(read_name(&wire, 12).is_err());
    }
}
