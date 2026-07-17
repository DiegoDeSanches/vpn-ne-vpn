use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use onionroute_common_types::error::{ErrorCode, RetryClass, SafetyImpact, Severity};
use onionroute_common_types::OnionResult;
use onionroute_tor_backend::{IsolationContext, IsolationScope, TorBackendExt};

use crate::circuit_error;

const COLLISION_RETRY_LIMIT: usize = 8;

#[derive(Default)]
struct Registry {
    by_scope: HashMap<(u64, IsolationScope), IsolationContext>,
    key_owners: HashMap<[u8; 32], (u64, IsolationScope)>,
}

/// Owns the complete isolation tuple and rejects key reuse across tuples.
pub struct IsolationManager {
    backend: Arc<dyn TorBackendExt>,
    epoch: AtomicU64,
    registry: Mutex<Registry>,
}

impl IsolationManager {
    /// Creates an empty epoch-zero registry over one managed backend.
    pub fn new(backend: Arc<dyn TorBackendExt>) -> Self {
        Self {
            backend,
            epoch: AtomicU64::new(0),
            registry: Mutex::new(Registry::default()),
        }
    }

    /// Returns the epoch assigned to subsequent allocations.
    pub fn current_epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// Allocates or reuses a collision-checked current-epoch context.
    pub async fn allocate(&self, scope: IsolationScope) -> OnionResult<IsolationContext> {
        scope.validate()?;
        let epoch = self.current_epoch();
        if let Some(context) = self
            .registry
            .lock()
            .map_err(|_| isolation_invariant())?
            .by_scope
            .get(&(epoch, scope.clone()))
            .cloned()
        {
            return Ok(context);
        }

        for _ in 0..COLLISION_RETRY_LIMIT {
            let context = self.backend.allocate_isolation_context(&scope).await?;
            if context.session_epoch != epoch {
                self.backend.release_isolation_context(&context).await?;
                return Err(isolation_invariant());
            }
            let collision = {
                let mut registry = self.registry.lock().map_err(|_| isolation_invariant())?;
                let owner = (epoch, scope.clone());
                if let Some(existing_owner) = registry.key_owners.get(&context.key.0) {
                    if existing_owner == &owner {
                        return Ok(registry.by_scope.get(&owner).cloned().unwrap_or(context));
                    }
                    true
                } else {
                    registry.key_owners.insert(context.key.0, owner.clone());
                    registry.by_scope.insert(owner, context.clone());
                    return Ok(context);
                }
            };
            if collision {
                self.backend.release_isolation_context(&context).await?;
                continue;
            }
        }
        Err(isolation_invariant())
    }

    /// Releases local and backend ownership of one context.
    pub async fn release(&self, context: &IsolationContext) -> OnionResult<()> {
        {
            let mut registry = self.registry.lock().map_err(|_| isolation_invariant())?;
            if let Some(owner) = registry.key_owners.remove(&context.key.0) {
                registry.by_scope.remove(&owner);
            }
        }
        self.backend.release_isolation_context(context).await
    }

    /// Installs the epoch returned by the backend. Old entries remain so live
    /// soft-rotation streams keep their cancellation tokens and circuits.
    pub fn install_soft_epoch(&self, new_epoch: u64) -> OnionResult<()> {
        let current = self.current_epoch();
        if new_epoch <= current {
            return Err(isolation_invariant());
        }
        self.epoch.store(new_epoch, Ordering::Release);
        Ok(())
    }

    /// Clears local ownership after the backend has cancelled all old contexts.
    pub fn install_hard_epoch(&self, new_epoch: u64) -> OnionResult<()> {
        self.install_soft_epoch(new_epoch)?;
        let mut registry = self.registry.lock().map_err(|_| isolation_invariant())?;
        registry.by_scope.clear();
        registry.key_owners.clear();
        Ok(())
    }

    /// Returns the number of locally owned contexts across live epochs.
    pub fn context_count(&self) -> OnionResult<usize> {
        Ok(self
            .registry
            .lock()
            .map_err(|_| isolation_invariant())?
            .by_scope
            .len())
    }
}

fn isolation_invariant() -> onionroute_common_types::OnionError {
    circuit_error(
        ErrorCode::InvariantViolation,
        Severity::Fatal,
        RetryClass::Never,
        SafetyImpact::MustBlock,
        "Tor isolation ownership invariant failed",
    )
}
