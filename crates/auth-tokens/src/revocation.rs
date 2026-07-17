use std::collections::HashSet;
use std::sync::RwLock;

use crate::{RevocationUpdateError, TokenId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationStatus {
    Active,
    Revoked,
    SnapshotStale,
}

/// Locally cached, signed revocation material. The verifier does not perform a
/// synchronous control-plane lookup during authentication.
pub trait RevocationProvider: Send + Sync + 'static {
    fn status(&self, key_id: &str, token_id: TokenId, now: i64) -> RevocationStatus;
}

#[derive(Clone, Debug)]
pub struct RevocationSnapshot {
    pub valid_until: i64,
    pub revoked_key_ids: HashSet<String>,
    pub revoked_token_ids: HashSet<TokenId>,
}

impl RevocationSnapshot {
    pub fn empty(valid_until: i64) -> Self {
        Self {
            valid_until,
            revoked_key_ids: HashSet::new(),
            revoked_token_ids: HashSet::new(),
        }
    }
}

pub struct InMemoryRevocationProvider {
    snapshot: RwLock<RevocationSnapshot>,
}

impl InMemoryRevocationProvider {
    pub fn new(snapshot: RevocationSnapshot) -> Self {
        Self {
            snapshot: RwLock::new(snapshot),
        }
    }

    pub fn replace(&self, snapshot: RevocationSnapshot) -> Result<(), RevocationUpdateError> {
        *self
            .snapshot
            .write()
            .map_err(|_| RevocationUpdateError::LockUnavailable)? = snapshot;
        Ok(())
    }
}

impl RevocationProvider for InMemoryRevocationProvider {
    fn status(&self, key_id: &str, token_id: TokenId, now: i64) -> RevocationStatus {
        let Ok(snapshot) = self.snapshot.read() else {
            return RevocationStatus::SnapshotStale;
        };
        if now > snapshot.valid_until {
            return RevocationStatus::SnapshotStale;
        }
        if snapshot.revoked_key_ids.contains(key_id)
            || snapshot.revoked_token_ids.contains(&token_id)
        {
            RevocationStatus::Revoked
        } else {
            RevocationStatus::Active
        }
    }
}
