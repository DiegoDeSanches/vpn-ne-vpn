use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use onionroute_desktop_ipc::v1::CriticalAction;
use thiserror::Error;

const CONFIRMATION_TTL: Duration = Duration::from_secs(60);
const MAX_PENDING_CONFIRMATIONS: usize = 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfirmationError {
    #[error("confirmation challenge is missing, expired, or does not match")]
    Invalid,
    #[error("secure random generation is unavailable")]
    RandomUnavailable,
    #[error("too many confirmation challenges are pending")]
    Backpressure,
}

/// Per-authenticated-session, bounded and single-use confirmation challenges.
pub struct ConfirmationStore {
    pending: HashMap<[u8; 16], (CriticalAction, Instant)>,
}

impl Default for ConfirmationStore {
    fn default() -> Self {
        Self {
            pending: HashMap::with_capacity(MAX_PENDING_CONFIRMATIONS),
        }
    }
}

impl ConfirmationStore {
    pub fn issue(
        &mut self,
        action: CriticalAction,
        now: Instant,
    ) -> Result<[u8; 16], ConfirmationError> {
        self.prune(now);
        if self.pending.len() >= MAX_PENDING_CONFIRMATIONS {
            return Err(ConfirmationError::Backpressure);
        }
        for _ in 0..4 {
            let mut id = [0_u8; 16];
            getrandom::getrandom(&mut id).map_err(|_| ConfirmationError::RandomUnavailable)?;
            if id != [0; 16] && !self.pending.contains_key(&id) {
                self.pending.insert(id, (action, now + CONFIRMATION_TTL));
                return Ok(id);
            }
        }
        Err(ConfirmationError::RandomUnavailable)
    }

    pub fn consume(
        &mut self,
        id: &[u8],
        action: CriticalAction,
        now: Instant,
    ) -> Result<(), ConfirmationError> {
        if id.len() != 16 {
            return Err(ConfirmationError::Invalid);
        }
        let mut key = [0_u8; 16];
        key.copy_from_slice(id);
        let Some((stored_action, expires)) = self.pending.remove(&key) else {
            return Err(ConfirmationError::Invalid);
        };
        if stored_action != action || expires < now {
            return Err(ConfirmationError::Invalid);
        }
        Ok(())
    }

    pub fn prune(&mut self, now: Instant) {
        self.pending.retain(|_, (_, expires)| *expires >= now);
    }
}
