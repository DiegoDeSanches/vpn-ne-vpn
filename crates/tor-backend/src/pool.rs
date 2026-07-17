use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use onionroute_common_types::error::{ErrorCode, RetryClass, SafetyImpact, Severity};
use onionroute_common_types::OnionResult;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::{tor_error, TorBackendExt, TorContextId};

/// Bounded registry of independently managed Tor processes/contexts.
pub struct TorContextPool {
    maximum: usize,
    contexts: RwLock<HashMap<TorContextId, Arc<dyn TorBackendExt>>>,
}

impl TorContextPool {
    /// Creates a pool limited to at most 32 independent processes.
    pub fn new(maximum: usize) -> OnionResult<Self> {
        if maximum == 0 || maximum > 32 {
            return Err(crate::configuration_error("invalid Tor context pool limit"));
        }
        Ok(Self {
            maximum,
            contexts: RwLock::new(HashMap::new()),
        })
    }

    /// Inserts a backend under a fresh process-local opaque identifier.
    pub fn insert(&self, backend: Arc<dyn TorBackendExt>) -> OnionResult<TorContextId> {
        let mut contexts = self.contexts.write().map_err(|_| pool_invariant())?;
        if contexts.len() >= self.maximum {
            return Err(tor_error(
                ErrorCode::Backpressure,
                Severity::Error,
                RetryClass::Backoff,
                SafetyImpact::Protected,
                "Tor context pool is full",
            ));
        }
        for _ in 0..8 {
            let mut bytes = [0_u8; 16];
            OsRng.fill_bytes(&mut bytes);
            let id = TorContextId(bytes);
            if let Entry::Vacant(entry) = contexts.entry(id) {
                entry.insert(Arc::clone(&backend));
                return Ok(id);
            }
        }
        Err(pool_invariant())
    }

    /// Returns a cloned backend handle without changing ownership.
    pub fn get(&self, id: TorContextId) -> OnionResult<Option<Arc<dyn TorBackendExt>>> {
        Ok(self
            .contexts
            .read()
            .map_err(|_| pool_invariant())?
            .get(&id)
            .cloned())
    }

    /// Removes and returns a backend; the caller remains responsible for stopping it.
    pub fn remove(&self, id: TorContextId) -> OnionResult<Option<Arc<dyn TorBackendExt>>> {
        Ok(self
            .contexts
            .write()
            .map_err(|_| pool_invariant())?
            .remove(&id))
    }

    /// Returns the current number of registered contexts.
    pub fn len(&self) -> OnionResult<usize> {
        Ok(self.contexts.read().map_err(|_| pool_invariant())?.len())
    }

    /// Returns true when no contexts are registered.
    pub fn is_empty(&self) -> OnionResult<bool> {
        Ok(self.len()? == 0)
    }

    /// Stops every registered context once and returns the first error only
    /// after all contexts received a stop request.
    pub async fn shutdown_all(&self) -> OnionResult<()> {
        let contexts: Vec<_> = self
            .contexts
            .read()
            .map_err(|_| pool_invariant())?
            .values()
            .cloned()
            .collect();
        let mut first_error = None;
        for backend in contexts {
            if let Err(error) = backend.stop().await {
                first_error.get_or_insert(error);
            }
        }
        self.contexts.write().map_err(|_| pool_invariant())?.clear();
        first_error.map_or(Ok(()), Err)
    }
}

fn pool_invariant() -> onionroute_common_types::OnionError {
    tor_error(
        ErrorCode::InvariantViolation,
        Severity::Fatal,
        RetryClass::Never,
        SafetyImpact::MustBlock,
        "Tor context pool invariant failed",
    )
}
