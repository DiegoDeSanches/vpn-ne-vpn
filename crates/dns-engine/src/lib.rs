#![forbid(unsafe_code)]
//! Protected DNS handling and bounded synthetic IPv4-to-hostname mapping.
//!
//! The crate deliberately exposes no system resolver or socket API. A/AAAA
//! queries are answered locally for transparent hostname preservation; every
//! other accepted query is passed only to an explicit `GatewayConnector`.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use onionroute_common_types::contracts::v1::{DnsEngine, GatewayConnector};
use onionroute_common_types::error::{ErrorCode, ErrorDomain, RetryClass, SafetyImpact, Severity};
use onionroute_common_types::transport::BoxFuture;
use onionroute_common_types::types::{
    DnsQuery, DnsResponse, GatewaySession, MAX_DNS_MESSAGE_BYTES,
};
use onionroute_common_types::version::{ContractVersion, VersionedContract, CONTRACT_V1};
use onionroute_common_types::{OnionError, OnionResult};

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const OPTION_ECS: u16 = 8;
const SYNTHETIC_FIRST: u32 = 0xc612_0001; // 198.18.0.1
const SYNTHETIC_LAST: u32 = 0xc613_fffe; // 198.19.255.254

/// Synthetic DNS configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyntheticDnsConfig {
    /// Maximum hostname mappings retained for one identity.
    pub max_entries: usize,
    /// Short synthetic answer TTL; values above 60 seconds are rejected.
    pub ttl: Duration,
}

impl Default for SyntheticDnsConfig {
    fn default() -> Self {
        Self {
            max_entries: 4_096,
            ttl: Duration::from_secs(30),
        }
    }
}

impl SyntheticDnsConfig {
    fn valid(self) -> bool {
        self.max_entries > 0
            && self.max_entries <= (SYNTHETIC_LAST - SYNTHETIC_FIRST + 1) as usize
            && !self.ttl.is_zero()
            && self.ttl <= Duration::from_secs(60)
    }
}

/// Parsed, validated DNS question.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQuestion {
    /// Lower-case ASCII hostname without a trailing dot.
    pub hostname: String,
    /// DNS record type.
    pub record_type: u16,
    /// DNS record class, normally IN (1).
    pub record_class: u16,
    question_end: usize,
}

#[derive(Clone)]
struct Mapping {
    address: Ipv4Addr,
    expires_at: Instant,
}

struct Cache {
    by_name: HashMap<String, Mapping>,
    by_ip: HashMap<Ipv4Addr, String>,
    lru: VecDeque<String>,
    next_address: u32,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            by_name: HashMap::new(),
            by_ip: HashMap::new(),
            lru: VecDeque::new(),
            next_address: SYNTHETIC_FIRST,
        }
    }
}

/// Bounded synthetic DNS engine scoped to one OnionRoute identity.
pub struct SyntheticDnsEngine {
    config: SyntheticDnsConfig,
    cache: Mutex<Cache>,
}

impl SyntheticDnsEngine {
    /// Creates an engine only for a finite cache and short TTL.
    pub fn new(config: SyntheticDnsConfig) -> Option<Self> {
        config.valid().then(|| Self {
            config,
            cache: Mutex::new(Cache::default()),
        })
    }

    /// Parses one bounded DNS query and rejects EDNS Client Subnet.
    pub fn parse_query(wire: &[u8]) -> OnionResult<DnsQuestion> {
        parse_query(wire)
    }

    /// Looks up a non-expired hostname for a synthetic IPv4 address.
    pub fn lookup_hostname(&self, address: Ipv4Addr) -> Option<String> {
        let now = Instant::now();
        let mut cache = self.cache.lock().expect("DNS cache mutex poisoned");
        purge_expired(&mut cache, now);
        let hostname = cache.by_ip.get(&address)?.clone();
        touch(&mut cache.lru, &hostname);
        Some(hostname)
    }

    /// Returns the current mapping count for local status and bounds tests.
    pub fn cache_len(&self) -> usize {
        self.cache
            .lock()
            .expect("DNS cache mutex poisoned")
            .by_name
            .len()
    }

    /// Clears all hostname and address state during Identity Reset.
    pub fn identity_reset(&self) {
        *self.cache.lock().expect("DNS cache mutex poisoned") = Cache::default();
    }

    /// Builds a bounded SERVFAIL response without consulting another resolver.
    pub fn servfail(query: &[u8]) -> Vec<u8> {
        error_response(query, 2)
    }

    fn synthetic_response(
        &self,
        query: &DnsQuery,
        question: &DnsQuestion,
    ) -> OnionResult<DnsResponse> {
        if question.record_class != 1 {
            return Ok(DnsResponse {
                query_id: query.query_id,
                wire: error_response(&query.wire, 5),
            });
        }
        if question.record_type == TYPE_AAAA {
            return Ok(DnsResponse {
                query_id: query.query_id,
                wire: empty_success_response(&query.wire, question.question_end),
            });
        }
        let address = self.get_or_allocate(&question.hostname)?;
        Ok(DnsResponse {
            query_id: query.query_id,
            wire: a_response(
                &query.wire,
                question.question_end,
                address,
                self.config.ttl.as_secs() as u32,
            ),
        })
    }

    fn get_or_allocate(&self, hostname: &str) -> OnionResult<Ipv4Addr> {
        let now = Instant::now();
        let mut cache = self.cache.lock().expect("DNS cache mutex poisoned");
        purge_expired(&mut cache, now);
        if let Some(mapping) = cache.by_name.get(hostname).cloned() {
            touch(&mut cache.lru, hostname);
            return Ok(mapping.address);
        }
        while cache.by_name.len() >= self.config.max_entries {
            let Some(oldest) = cache.lru.pop_front() else {
                break;
            };
            if let Some(mapping) = cache.by_name.remove(&oldest) {
                cache.by_ip.remove(&mapping.address);
            }
        }
        let address = allocate_address(&mut cache).ok_or_else(|| {
            dns_error(
                ErrorCode::Backpressure,
                RetryClass::Backoff,
                "synthetic DNS address pool is exhausted",
            )
        })?;
        let mapping = Mapping {
            address,
            expires_at: now + self.config.ttl,
        };
        cache.by_ip.insert(address, hostname.to_owned());
        cache.by_name.insert(hostname.to_owned(), mapping);
        touch(&mut cache.lru, hostname);
        Ok(address)
    }
}

impl VersionedContract for SyntheticDnsEngine {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl DnsEngine for SyntheticDnsEngine {
    fn resolve<'a>(
        &'a self,
        query: &'a DnsQuery,
        session: &'a GatewaySession,
        gateway: &'a dyn GatewayConnector,
    ) -> BoxFuture<'a, OnionResult<DnsResponse>> {
        Box::pin(async move {
            let question = parse_query(&query.wire)?;
            if matches!(question.record_type, TYPE_A | TYPE_AAAA) {
                return self.synthetic_response(query, &question);
            }
            let response = gateway.exchange_dns(session, query).await?;
            validate_response(query, &response)?;
            Ok(response)
        })
    }

    fn flush_cache(&self) -> BoxFuture<'_, OnionResult<()>> {
        self.identity_reset();
        Box::pin(async { Ok(()) })
    }
}

fn parse_query(wire: &[u8]) -> OnionResult<DnsQuestion> {
    if wire.len() < 12 || wire.len() > MAX_DNS_MESSAGE_BYTES {
        return Err(malformed("DNS query size is invalid"));
    }
    let flags = u16::from_be_bytes([wire[2], wire[3]]);
    if flags & 0x8000 != 0 {
        return Err(malformed("DNS query has response flag"));
    }
    if flags & 0x7800 != 0 {
        return Err(malformed("DNS opcode is unsupported"));
    }
    if flags & 0x0240 != 0 {
        return Err(malformed(
            "truncated or reserved DNS query flags are invalid",
        ));
    }
    let questions = u16::from_be_bytes([wire[4], wire[5]]);
    if questions != 1 {
        return Err(malformed("DNS query must contain one question"));
    }
    let (hostname, name_end) = read_name(wire, 12)?;
    if name_end + 4 > wire.len() {
        return Err(malformed("DNS question is truncated"));
    }
    let record_type = u16::from_be_bytes([wire[name_end], wire[name_end + 1]]);
    let record_class = u16::from_be_bytes([wire[name_end + 2], wire[name_end + 3]]);
    let question_end = name_end + 4;
    reject_ecs(wire, question_end)?;
    Ok(DnsQuestion {
        hostname,
        record_type,
        record_class,
        question_end,
    })
}

fn read_name(wire: &[u8], start: usize) -> OnionResult<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut consumed_end = None;
    let mut jumps = 0usize;
    let mut expanded_len = 0usize;
    loop {
        let length = *wire
            .get(cursor)
            .ok_or_else(|| malformed("DNS name is truncated"))?;
        if length & 0xc0 == 0xc0 {
            let second = *wire
                .get(cursor + 1)
                .ok_or_else(|| malformed("DNS pointer is truncated"))?;
            let offset = usize::from((u16::from(length & 0x3f) << 8) | u16::from(second));
            if offset >= wire.len() || jumps >= 16 {
                return Err(malformed("DNS compression pointer is invalid"));
            }
            consumed_end.get_or_insert(cursor + 2);
            cursor = offset;
            jumps += 1;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(malformed("DNS label encoding is invalid"));
        }
        cursor += 1;
        if length == 0 {
            let end = consumed_end.unwrap_or(cursor);
            if labels.is_empty() || expanded_len > 253 {
                return Err(malformed("DNS hostname length is invalid"));
            }
            return Ok((labels.join("."), end));
        }
        let length = usize::from(length);
        if length > 63 || cursor + length > wire.len() {
            return Err(malformed("DNS label length is invalid"));
        }
        let label = &wire[cursor..cursor + length];
        if !label
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            || label.first() == Some(&b'-')
            || label.last() == Some(&b'-')
        {
            return Err(malformed("DNS hostname contains unsupported characters"));
        }
        let text =
            std::str::from_utf8(label).map_err(|_| malformed("DNS hostname is not ASCII"))?;
        labels.push(text.to_ascii_lowercase());
        expanded_len = expanded_len.saturating_add(length + usize::from(!labels.is_empty()));
        cursor += length;
    }
}

fn skip_name(wire: &[u8], start: usize) -> OnionResult<usize> {
    let mut cursor = start;
    let mut labels = 0usize;
    loop {
        let length = *wire
            .get(cursor)
            .ok_or_else(|| malformed("DNS record name is truncated"))?;
        if length & 0xc0 == 0xc0 {
            if wire.get(cursor + 1).is_none() {
                return Err(malformed("DNS record pointer is truncated"));
            }
            return Ok(cursor + 2);
        }
        if length & 0xc0 != 0 || labels >= 128 {
            return Err(malformed("DNS record name is invalid"));
        }
        cursor += 1;
        if length == 0 {
            return Ok(cursor);
        }
        cursor = cursor
            .checked_add(usize::from(length))
            .ok_or_else(|| malformed("DNS name overflow"))?;
        if cursor > wire.len() {
            return Err(malformed("DNS record name is truncated"));
        }
        labels += 1;
    }
}

fn reject_ecs(wire: &[u8], mut cursor: usize) -> OnionResult<()> {
    let answers = usize::from(u16::from_be_bytes([wire[6], wire[7]]));
    let authorities = usize::from(u16::from_be_bytes([wire[8], wire[9]]));
    let additional = usize::from(u16::from_be_bytes([wire[10], wire[11]]));
    let total = answers
        .saturating_add(authorities)
        .saturating_add(additional);
    if total > 128 {
        return Err(malformed("DNS record count exceeds limit"));
    }
    for _ in 0..total {
        cursor = skip_name(wire, cursor)?;
        if cursor + 10 > wire.len() {
            return Err(malformed("DNS resource record is truncated"));
        }
        let record_type = u16::from_be_bytes([wire[cursor], wire[cursor + 1]]);
        let rdlen = usize::from(u16::from_be_bytes([wire[cursor + 8], wire[cursor + 9]]));
        cursor += 10;
        let end = cursor
            .checked_add(rdlen)
            .ok_or_else(|| malformed("DNS record length overflow"))?;
        if end > wire.len() {
            return Err(malformed("DNS resource data is truncated"));
        }
        if record_type == TYPE_OPT {
            let mut option = cursor;
            while option < end {
                if option + 4 > end {
                    return Err(malformed("EDNS option is truncated"));
                }
                let code = u16::from_be_bytes([wire[option], wire[option + 1]]);
                let length = usize::from(u16::from_be_bytes([wire[option + 2], wire[option + 3]]));
                option += 4;
                if option + length > end {
                    return Err(malformed("EDNS option length is invalid"));
                }
                if code == OPTION_ECS {
                    return Err(dns_error(
                        ErrorCode::PolicyDenied,
                        RetryClass::Never,
                        "EDNS Client Subnet is forbidden",
                    ));
                }
                option += length;
            }
        }
        cursor = end;
    }
    if cursor != wire.len() {
        return Err(malformed("DNS query contains trailing bytes"));
    }
    Ok(())
}

fn a_response(query: &[u8], question_end: usize, address: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let mut response = response_header(query, 1);
    response.extend_from_slice(&query[12..question_end]);
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&TYPE_A.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&ttl.to_be_bytes());
    response.extend_from_slice(&4u16.to_be_bytes());
    response.extend_from_slice(&address.octets());
    response
}

fn empty_success_response(query: &[u8], question_end: usize) -> Vec<u8> {
    let mut response = response_header(query, 0);
    response.extend_from_slice(&query[12..question_end]);
    response
}

fn response_header(query: &[u8], answers: u16) -> Vec<u8> {
    let request_flags = u16::from_be_bytes([query[2], query[3]]);
    let flags = 0x8080 | (request_flags & 0x0100);
    let mut response = Vec::with_capacity(64);
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&answers.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response
}

fn error_response(query: &[u8], rcode: u16) -> Vec<u8> {
    let id = if query.len() >= 2 {
        &query[..2]
    } else {
        &[0, 0]
    };
    let request_flags = if query.len() >= 4 {
        u16::from_be_bytes([query[2], query[3]])
    } else {
        0
    };
    let flags = 0x8080 | (request_flags & 0x0100) | (rcode & 0x0f);
    let mut response = Vec::with_capacity(12);
    response.extend_from_slice(id);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&[0; 8]);
    response
}

fn validate_response(query: &DnsQuery, response: &DnsResponse) -> OnionResult<()> {
    if response.query_id != query.query_id
        || response.wire.len() < 12
        || response.wire.len() > MAX_DNS_MESSAGE_BYTES
        || response.wire[..2] != query.wire[..2]
        || response.wire[2] & 0x80 == 0
    {
        return Err(dns_error(
            ErrorCode::DnsResolutionFailed,
            RetryClass::Backoff,
            "protected DNS response is invalid",
        ));
    }
    let expected = parse_query(&query.wire)?;
    let flags = u16::from_be_bytes([response.wire[2], response.wire[3]]);
    let questions = u16::from_be_bytes([response.wire[4], response.wire[5]]);
    if flags & 0x7800 != 0 || questions != 1 {
        return Err(dns_error(
            ErrorCode::DnsResolutionFailed,
            RetryClass::Backoff,
            "protected DNS response header is invalid",
        ));
    }
    let (hostname, name_end) = read_name(&response.wire, 12)?;
    if name_end + 4 > response.wire.len() {
        return Err(dns_error(
            ErrorCode::DnsResolutionFailed,
            RetryClass::Backoff,
            "protected DNS response question is truncated",
        ));
    }
    let record_type = u16::from_be_bytes([response.wire[name_end], response.wire[name_end + 1]]);
    let record_class =
        u16::from_be_bytes([response.wire[name_end + 2], response.wire[name_end + 3]]);
    if hostname != expected.hostname
        || record_type != expected.record_type
        || record_class != expected.record_class
    {
        return Err(dns_error(
            ErrorCode::DnsResolutionFailed,
            RetryClass::Backoff,
            "protected DNS response question does not match the query",
        ));
    }
    reject_ecs(&response.wire, name_end + 4)?;
    Ok(())
}

fn purge_expired(cache: &mut Cache, now: Instant) {
    let expired: Vec<String> = cache
        .by_name
        .iter()
        .filter(|(_, mapping)| mapping.expires_at <= now)
        .map(|(name, _)| name.clone())
        .collect();
    for name in expired {
        if let Some(mapping) = cache.by_name.remove(&name) {
            cache.by_ip.remove(&mapping.address);
        }
        cache.lru.retain(|entry| entry != &name);
    }
}

fn allocate_address(cache: &mut Cache) -> Option<Ipv4Addr> {
    let pool_size = SYNTHETIC_LAST - SYNTHETIC_FIRST + 1;
    for _ in 0..pool_size {
        let raw = cache.next_address;
        cache.next_address = if raw >= SYNTHETIC_LAST {
            SYNTHETIC_FIRST
        } else {
            raw + 1
        };
        let address = Ipv4Addr::from(raw);
        let last = address.octets()[3];
        if last != 0 && last != 255 && !cache.by_ip.contains_key(&address) {
            return Some(address);
        }
    }
    None
}

fn touch(lru: &mut VecDeque<String>, hostname: &str) {
    lru.retain(|entry| entry != hostname);
    lru.push_back(hostname.to_owned());
}

fn malformed(message: &'static str) -> OnionError {
    dns_error(ErrorCode::ProtocolViolation, RetryClass::Never, message)
}

fn dns_error(code: ErrorCode, retry: RetryClass, message: &'static str) -> OnionError {
    OnionError::new(
        ErrorDomain::Dns,
        code,
        Severity::Error,
        retry,
        SafetyImpact::Protected,
        message,
    )
}
