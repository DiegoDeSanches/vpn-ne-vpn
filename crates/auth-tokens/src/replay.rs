use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;

use crate::{SessionLease, TokenId, TokenStoreError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenReservation {
    pub token_id: TokenId,
    pub session_id: [u8; 32],
    pub now: i64,
    pub expires_at: i64,
    pub max_active_sessions: u16,
}

/// Replay/state boundary. A production multi-gateway implementation MUST make
/// `reserve` linearizable for a token ID and MUST fail closed when quorum/state
/// is unavailable. This store belongs to the anonymous data plane, not billing.
#[async_trait]
pub trait TokenStore: Send + Sync + 'static {
    async fn reserve(&self, reservation: TokenReservation)
        -> Result<SessionLease, TokenStoreError>;
    async fn release(&self, lease: SessionLease) -> Result<(), TokenStoreError>;
}

#[derive(Default)]
pub struct InMemoryTokenStore {
    entries: Mutex<HashMap<TokenId, TokenSessions>>,
}

struct TokenSessions {
    expires_at: i64,
    sessions: HashSet<[u8; 32]>,
}

#[async_trait]
impl TokenStore for InMemoryTokenStore {
    async fn reserve(
        &self,
        reservation: TokenReservation,
    ) -> Result<SessionLease, TokenStoreError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| TokenStoreError::Unavailable)?;
        entries.retain(|_, state| state.expires_at > reservation.now);

        let state = entries
            .entry(reservation.token_id)
            .or_insert_with(|| TokenSessions {
                expires_at: reservation.expires_at,
                sessions: HashSet::new(),
            });
        state.expires_at = state.expires_at.min(reservation.expires_at);
        if state.sessions.contains(&reservation.session_id) {
            return Err(TokenStoreError::AlreadyReserved);
        }
        if state.sessions.len() >= usize::from(reservation.max_active_sessions) {
            return Err(TokenStoreError::LimitReached);
        }
        state.sessions.insert(reservation.session_id);
        Ok(SessionLease {
            token_id: reservation.token_id,
            session_id: reservation.session_id,
        })
    }

    async fn release(&self, lease: SessionLease) -> Result<(), TokenStoreError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| TokenStoreError::Unavailable)?;
        if let Some(state) = entries.get_mut(&lease.token_id) {
            state.sessions.remove(&lease.session_id);
            if state.sessions.is_empty() {
                entries.remove(&lease.token_id);
            }
        }
        Ok(())
    }
}
