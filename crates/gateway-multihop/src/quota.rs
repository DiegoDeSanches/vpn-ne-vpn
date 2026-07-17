//! Per-entry data-plane quotas and drain admission.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::identity::PeerIdentity;
use crate::{ErrorCode, Result};

#[derive(Clone, Debug)]
pub struct EntryQuotaLimits {
    pub maximum_entries: usize,
    pub maximum_connections_per_entry: usize,
    pub maximum_sessions_per_entry: usize,
    pub bytes_per_second: u64,
    pub burst_bytes: u64,
}

impl Default for EntryQuotaLimits {
    fn default() -> Self {
        Self {
            maximum_entries: 1_024,
            maximum_connections_per_entry: 8,
            maximum_sessions_per_entry: 2_048,
            bytes_per_second: 100 * 1024 * 1024,
            burst_bytes: 20 * 1024 * 1024,
        }
    }
}

struct EntryState {
    connections: usize,
    sessions: usize,
    available_bytes: u64,
    last_refill: Instant,
}

struct Inner {
    limits: EntryQuotaLimits,
    entries: Mutex<HashMap<String, EntryState>>,
    draining: AtomicBool,
}

#[derive(Clone)]
pub struct EntryQuotaManager {
    inner: Arc<Inner>,
}

impl EntryQuotaManager {
    pub fn new(limits: EntryQuotaLimits) -> Result<Self> {
        if limits.maximum_entries == 0
            || limits.maximum_connections_per_entry == 0
            || limits.maximum_sessions_per_entry == 0
            || limits.bytes_per_second == 0
            || limits.burst_bytes == 0
        {
            return Err(ErrorCode::InvalidConfiguration.into());
        }
        Ok(Self {
            inner: Arc::new(Inner {
                limits,
                entries: Mutex::new(HashMap::new()),
                draining: AtomicBool::new(false),
            }),
        })
    }

    pub fn set_draining(&self, draining: bool) {
        self.inner.draining.store(draining, Ordering::Release);
    }

    pub fn is_draining(&self) -> bool {
        self.inner.draining.load(Ordering::Acquire)
    }

    pub fn acquire_connection(&self, peer: &PeerIdentity) -> Result<EntryConnectionPermit> {
        if self.is_draining() {
            return Err(ErrorCode::Draining.into());
        }
        let mut entries = self.inner.entries.lock().map_err(|_| ErrorCode::Internal)?;
        if !entries.contains_key(&peer.service_id)
            && entries.len() >= self.inner.limits.maximum_entries
        {
            return Err(ErrorCode::ResourceExhausted.into());
        }
        let state = entries
            .entry(peer.service_id.clone())
            .or_insert(EntryState {
                connections: 0,
                sessions: 0,
                available_bytes: self.inner.limits.burst_bytes,
                last_refill: Instant::now(),
            });
        if state.connections >= self.inner.limits.maximum_connections_per_entry {
            return Err(ErrorCode::ResourceExhausted.into());
        }
        state.connections += 1;
        Ok(EntryConnectionPermit {
            manager: self.clone(),
            service_id: peer.service_id.clone(),
        })
    }

    pub fn acquire_session(&self, peer: &PeerIdentity) -> Result<EntrySessionPermit> {
        if self.is_draining() {
            return Err(ErrorCode::Draining.into());
        }
        let mut entries = self.inner.entries.lock().map_err(|_| ErrorCode::Internal)?;
        let state = entries
            .get_mut(&peer.service_id)
            .ok_or(ErrorCode::AuthenticationRejected)?;
        if state.sessions >= self.inner.limits.maximum_sessions_per_entry {
            return Err(ErrorCode::ResourceExhausted.into());
        }
        state.sessions += 1;
        Ok(EntrySessionPermit {
            manager: self.clone(),
            service_id: peer.service_id.clone(),
        })
    }

    pub fn charge_bytes(&self, peer: &PeerIdentity, bytes: usize) -> Result<()> {
        let requested = u64::try_from(bytes).map_err(|_| ErrorCode::ResourceExhausted)?;
        let mut entries = self.inner.entries.lock().map_err(|_| ErrorCode::Internal)?;
        let state = entries
            .get_mut(&peer.service_id)
            .ok_or(ErrorCode::AuthenticationRejected)?;
        refill(state, &self.inner.limits);
        if requested > state.available_bytes {
            return Err(ErrorCode::Backpressure.into());
        }
        state.available_bytes -= requested;
        Ok(())
    }

    fn release(&self, service_id: &str, connection: bool) {
        if let Ok(mut entries) = self.inner.entries.lock() {
            if let Some(state) = entries.get_mut(service_id) {
                if connection {
                    state.connections = state.connections.saturating_sub(1);
                } else {
                    state.sessions = state.sessions.saturating_sub(1);
                }
                if state.connections == 0 && state.sessions == 0 {
                    entries.remove(service_id);
                }
            }
        }
    }
}

fn refill(state: &mut EntryState, limits: &EntryQuotaLimits) {
    let elapsed = state.last_refill.elapsed();
    if elapsed < Duration::from_millis(10) {
        return;
    }
    let nanos = elapsed.as_nanos();
    let added = (u128::from(limits.bytes_per_second) * nanos / 1_000_000_000)
        .min(u128::from(u64::MAX)) as u64;
    state.available_bytes = state
        .available_bytes
        .saturating_add(added)
        .min(limits.burst_bytes);
    state.last_refill = Instant::now();
}

pub struct EntryConnectionPermit {
    manager: EntryQuotaManager,
    service_id: String,
}

impl Drop for EntryConnectionPermit {
    fn drop(&mut self) {
        self.manager.release(&self.service_id, true);
    }
}

pub struct EntrySessionPermit {
    manager: EntryQuotaManager,
    service_id: String,
}

impl Drop for EntrySessionPermit {
    fn drop(&mut self) {
        self.manager.release(&self.service_id, false);
    }
}
