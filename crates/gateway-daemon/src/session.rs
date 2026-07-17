//! Anonymous session, per-token quotas, scan detection, and draining state.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use ring::hmac;

use crate::auth::{AuthenticationGrant, TokenLimits};
use crate::config::LimitConfig;
use crate::rate_limit::{BandwidthLimiter, TokenBucket};
use crate::{GatewayErrorCode, GatewayResult};

struct ScanWindow {
    started_at: Instant,
    destinations: HashSet<[u8; 16]>,
}

struct TokenState {
    expires_at: SystemTime,
    max_sessions: usize,
    max_streams: usize,
    sessions: AtomicUsize,
    streams: AtomicUsize,
    connection_rate: TokenBucket,
    bandwidth: BandwidthLimiter,
    scan: Mutex<ScanWindow>,
}

struct SessionManagerInner {
    limits: LimitConfig,
    hash_key: [u8; 32],
    tokens: Mutex<HashMap<[u8; 32], Arc<TokenState>>>,
    sessions: AtomicUsize,
    streams: AtomicUsize,
    draining: AtomicBool,
}

/// Creates and accounts short-lived data-plane sessions.
#[derive(Clone)]
pub struct SessionManager {
    inner: Arc<SessionManagerInner>,
}

impl SessionManager {
    pub fn new(limits: LimitConfig) -> GatewayResult<Self> {
        let mut hash_key = [0u8; 32];
        getrandom::getrandom(&mut hash_key).map_err(|_| GatewayErrorCode::Internal)?;
        Ok(Self {
            inner: Arc::new(SessionManagerInner {
                limits,
                hash_key,
                tokens: Mutex::new(HashMap::new()),
                sessions: AtomicUsize::new(0),
                streams: AtomicUsize::new(0),
                draining: AtomicBool::new(false),
            }),
        })
    }

    pub fn register(
        &self,
        capability_token: &[u8],
        grant: AuthenticationGrant,
    ) -> GatewayResult<SessionLease> {
        if self.is_draining() {
            return Err(GatewayErrorCode::Draining.into());
        }
        let now = SystemTime::now();
        if capability_token.is_empty() || grant.expires_at <= now {
            return Err(GatewayErrorCode::TokenRejected.into());
        }
        validate_grant(&grant)?;
        increment_bounded(&self.inner.sessions, self.inner.limits.max_sessions)?;

        let token_tag = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, &self.inner.hash_key),
            capability_token,
        );
        let mut token_key = [0u8; 32];
        token_key.copy_from_slice(token_tag.as_ref());
        let token_state = {
            let mut tokens = self
                .inner
                .tokens
                .lock()
                .map_err(|_| GatewayErrorCode::Internal)?;
            purge_token_map(&mut tokens);
            if !tokens.contains_key(&token_key)
                && tokens.len() >= self.inner.limits.max_token_states
            {
                self.inner.sessions.fetch_sub(1, Ordering::AcqRel);
                return Err(GatewayErrorCode::ResourceExhausted.into());
            }
            tokens
                .entry(token_key)
                .or_insert_with(|| Arc::new(self.create_token_state(&grant)))
                .clone()
        };
        if token_state.expires_at <= now {
            self.inner.sessions.fetch_sub(1, Ordering::AcqRel);
            return Err(GatewayErrorCode::TokenRejected.into());
        }
        if increment_bounded(&token_state.sessions, token_state.max_sessions).is_err() {
            self.inner.sessions.fetch_sub(1, Ordering::AcqRel);
            return Err(GatewayErrorCode::ResourceExhausted.into());
        }

        let mut handle = [0u8; 8];
        if getrandom::getrandom(&mut handle).is_err() {
            token_state.sessions.fetch_sub(1, Ordering::AcqRel);
            self.inner.sessions.fetch_sub(1, Ordering::AcqRel);
            return Err(GatewayErrorCode::Internal.into());
        }
        let maximum_session_expiry = now
            .checked_add(Duration::from_secs(self.inner.limits.session_ttl_seconds))
            .ok_or(GatewayErrorCode::Internal)?;
        Ok(SessionLease {
            manager: self.inner.clone(),
            token_key,
            token: token_state,
            handle,
            expires_at: grant.expires_at.min(maximum_session_expiry),
            capabilities: grant.capabilities,
            streams: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn create_token_state(&self, grant: &AuthenticationGrant) -> TokenState {
        let effective = effective_limits(grant.limits, &self.inner.limits);
        TokenState {
            expires_at: grant.expires_at,
            max_sessions: effective.max_sessions,
            max_streams: effective.max_concurrent_streams,
            sessions: AtomicUsize::new(0),
            streams: AtomicUsize::new(0),
            connection_rate: TokenBucket::new(
                u64::from(effective.connections_per_second),
                u64::from(effective.connection_burst),
            ),
            bandwidth: BandwidthLimiter::new(
                effective.bytes_per_second,
                effective.bandwidth_burst_bytes,
                effective.total_bytes,
                self.inner.limits.io_timeout(),
            ),
            scan: Mutex::new(ScanWindow {
                started_at: Instant::now(),
                destinations: HashSet::new(),
            }),
        }
    }

    pub fn set_draining(&self, draining: bool) {
        self.inner.draining.store(draining, Ordering::Release);
    }

    pub fn is_draining(&self) -> bool {
        self.inner.draining.load(Ordering::Acquire)
    }

    pub fn active_sessions(&self) -> usize {
        self.inner.sessions.load(Ordering::Acquire)
    }

    pub fn active_streams(&self) -> usize {
        self.inner.streams.load(Ordering::Acquire)
    }

    pub fn purge_expired(&self) -> GatewayResult<()> {
        let mut tokens = self
            .inner
            .tokens
            .lock()
            .map_err(|_| GatewayErrorCode::Internal)?;
        purge_token_map(&mut tokens);
        Ok(())
    }
}

fn validate_grant(grant: &AuthenticationGrant) -> GatewayResult<()> {
    let limits = grant.limits;
    if grant.capabilities.is_empty()
        || grant.capabilities.len() > 32
        || grant
            .capabilities
            .iter()
            .any(|value| value.is_empty() || value.len() > 64 || !value.is_ascii())
        || limits.max_sessions == 0
        || limits.max_concurrent_streams == 0
        || limits.connections_per_second == 0
        || limits.connection_burst == 0
        || limits.bytes_per_second == 0
        || limits.bandwidth_burst_bytes == 0
        || limits.total_bytes == 0
    {
        return Err(GatewayErrorCode::TokenRejected.into());
    }
    Ok(())
}

fn effective_limits(token: TokenLimits, server: &LimitConfig) -> TokenLimits {
    TokenLimits {
        max_sessions: token.max_sessions.min(server.max_sessions_per_token),
        max_concurrent_streams: token
            .max_concurrent_streams
            .min(server.max_streams_per_token),
        connections_per_second: token
            .connections_per_second
            .min(server.connection_rate_per_second),
        connection_burst: token.connection_burst.min(server.connection_rate_burst),
        bytes_per_second: token
            .bytes_per_second
            .min(server.bandwidth_bytes_per_second),
        bandwidth_burst_bytes: token
            .bandwidth_burst_bytes
            .min(server.bandwidth_burst_bytes),
        total_bytes: token.total_bytes.min(server.token_byte_quota),
    }
}

fn purge_token_map(tokens: &mut HashMap<[u8; 32], Arc<TokenState>>) {
    let now = SystemTime::now();
    tokens.retain(|_, token| {
        token.expires_at > now
            || token.sessions.load(Ordering::Acquire) > 0
            || token.streams.load(Ordering::Acquire) > 0
    });
}

fn increment_bounded(counter: &AtomicUsize, maximum: usize) -> GatewayResult<()> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(1).filter(|next| *next <= maximum)
        })
        .map(|_| ())
        .map_err(|_| GatewayErrorCode::ResourceExhausted.into())
}

/// A short-lived authenticated session. Its random handle is suitable only for
/// TTL-limited local privacy events.
pub struct SessionLease {
    manager: Arc<SessionManagerInner>,
    token_key: [u8; 32],
    token: Arc<TokenState>,
    handle: [u8; 8],
    expires_at: SystemTime,
    capabilities: Vec<String>,
    streams: Arc<AtomicUsize>,
}

impl SessionLease {
    pub fn handle(&self) -> [u8; 8] {
        self.handle
    }

    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities
            .iter()
            .any(|granted| granted == capability)
    }

    pub fn ensure_active(&self) -> GatewayResult<()> {
        if self.expires_at <= SystemTime::now() || self.token.expires_at <= SystemTime::now() {
            return Err(GatewayErrorCode::SessionExpired.into());
        }
        Ok(())
    }

    pub fn reserve_stream(&self, destination_material: &[u8]) -> GatewayResult<StreamLease> {
        self.ensure_active()?;
        if self.manager.draining.load(Ordering::Acquire) {
            return Err(GatewayErrorCode::Draining.into());
        }
        self.token.connection_rate.try_take(1)?;
        self.observe_destination(destination_material)?;

        increment_bounded(&self.streams, self.manager.limits.max_streams_per_session)?;
        if increment_bounded(&self.token.streams, self.token.max_streams).is_err() {
            self.streams.fetch_sub(1, Ordering::AcqRel);
            return Err(GatewayErrorCode::ResourceExhausted.into());
        }
        if increment_bounded(
            &self.manager.streams,
            self.manager.limits.max_streams_global,
        )
        .is_err()
        {
            self.token.streams.fetch_sub(1, Ordering::AcqRel);
            self.streams.fetch_sub(1, Ordering::AcqRel);
            return Err(GatewayErrorCode::ResourceExhausted.into());
        }
        Ok(StreamLease {
            manager: self.manager.clone(),
            token: self.token.clone(),
            session_streams: self.streams.clone(),
        })
    }

    fn observe_destination(&self, destination_material: &[u8]) -> GatewayResult<()> {
        let mut material = Vec::with_capacity(self.token_key.len() + destination_material.len());
        material.extend_from_slice(&self.token_key);
        material.extend_from_slice(destination_material);
        let digest = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, &self.manager.hash_key),
            &material,
        );
        let mut short = [0u8; 16];
        short.copy_from_slice(&digest.as_ref()[..16]);

        let mut scan = self
            .token
            .scan
            .lock()
            .map_err(|_| GatewayErrorCode::Internal)?;
        let window = Duration::from_secs(self.manager.limits.scan_window_seconds);
        if scan.started_at.elapsed() >= window {
            scan.started_at = Instant::now();
            scan.destinations.clear();
        }
        scan.destinations.insert(short);
        if scan.destinations.len() > self.manager.limits.scan_distinct_destination_limit {
            return Err(GatewayErrorCode::PolicyDenied.into());
        }
        Ok(())
    }

    pub async fn acquire_bandwidth(&self, bytes: usize) -> GatewayResult<()> {
        self.ensure_active()?;
        self.token.bandwidth.acquire(bytes).await
    }
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        self.token.sessions.fetch_sub(1, Ordering::AcqRel);
        self.manager.sessions.fetch_sub(1, Ordering::AcqRel);
    }
}

/// RAII accounting for a stream.
pub struct StreamLease {
    manager: Arc<SessionManagerInner>,
    token: Arc<TokenState>,
    session_streams: Arc<AtomicUsize>,
}

impl Drop for StreamLease {
    fn drop(&mut self) {
        self.session_streams.fetch_sub(1, Ordering::AcqRel);
        self.token.streams.fetch_sub(1, Ordering::AcqRel);
        self.manager.streams.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(expires_at: SystemTime) -> AuthenticationGrant {
        AuthenticationGrant {
            expires_at,
            capabilities: vec!["tcp-connect-v1".into()],
            limits: TokenLimits {
                max_sessions: 1,
                max_concurrent_streams: 1,
                connections_per_second: 10,
                connection_burst: 10,
                bytes_per_second: 1_000_000,
                bandwidth_burst_bytes: 1_000_000,
                total_bytes: 10_000_000,
            },
        }
    }

    #[test]
    fn token_expiration_fails_closed() {
        let manager = SessionManager::new(LimitConfig::default()).unwrap();
        let error = manager
            .register(b"opaque", grant(SystemTime::UNIX_EPOCH))
            .err()
            .unwrap();
        assert_eq!(error.code, GatewayErrorCode::TokenRejected);
    }

    #[test]
    fn draining_rejects_new_work_without_dropping_existing_stream() {
        let manager = SessionManager::new(LimitConfig::default()).unwrap();
        let session = manager
            .register(
                b"opaque",
                grant(SystemTime::now() + Duration::from_secs(60)),
            )
            .unwrap();
        let stream = session.reserve_stream(b"first").unwrap();
        manager.set_draining(true);
        assert_eq!(
            session.reserve_stream(b"second").err().unwrap().code,
            GatewayErrorCode::Draining
        );
        assert_eq!(manager.active_streams(), 1);
        drop(stream);
        assert_eq!(manager.active_streams(), 0);
    }

    #[test]
    fn session_ttl_is_clamped_by_server_policy() {
        let limits = LimitConfig {
            session_ttl_seconds: 5,
            ..LimitConfig::default()
        };
        let manager = SessionManager::new(limits).unwrap();
        let session = manager
            .register(
                b"opaque",
                grant(SystemTime::now() + Duration::from_secs(3_600)),
            )
            .unwrap();
        assert!(session.expires_at() <= SystemTime::now() + Duration::from_secs(6));
    }

    #[test]
    fn distinct_destination_scan_limit_is_enforced() {
        let limits = LimitConfig {
            scan_distinct_destination_limit: 2,
            ..LimitConfig::default()
        };
        let manager = SessionManager::new(limits).unwrap();
        let mut token_grant = grant(SystemTime::now() + Duration::from_secs(60));
        token_grant.limits.max_concurrent_streams = 8;
        let session = manager.register(b"opaque", token_grant).unwrap();
        let first = session.reserve_stream(b"one").unwrap();
        let second = session.reserve_stream(b"two").unwrap();
        assert_eq!(
            session.reserve_stream(b"three").err().unwrap().code,
            GatewayErrorCode::PolicyDenied
        );
        drop((first, second));
    }

    #[test]
    fn token_state_table_is_bounded() {
        let limits = LimitConfig {
            max_connections: 2,
            max_sessions: 2,
            max_token_states: 2,
            ..LimitConfig::default()
        };
        let manager = SessionManager::new(limits).unwrap();
        let expiry = SystemTime::now() + Duration::from_secs(60);
        drop(manager.register(b"token-one", grant(expiry)).unwrap());
        drop(manager.register(b"token-two", grant(expiry)).unwrap());
        assert_eq!(
            manager
                .register(b"token-three", grant(expiry))
                .err()
                .unwrap()
                .code,
            GatewayErrorCode::ResourceExhausted
        );
    }
}
