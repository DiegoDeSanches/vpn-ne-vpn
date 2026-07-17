use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;

use crate::{AccountRef, BillingAdapterError, BillingEntitlement};

/// Minimal billing boundary. A real payment provider adapter maps its private
/// subscription state into this coarse entitlement and exposes nothing to the
/// anonymous issuer or gateway.
#[async_trait]
pub trait BillingEntitlementProvider: Send + Sync + 'static {
    async fn entitlement_for(
        &self,
        account: &AccountRef,
        now: i64,
    ) -> Result<BillingEntitlement, BillingAdapterError>;
}

#[derive(Default)]
pub struct MockBillingAdapter {
    state: RwLock<MockBillingState>,
}

#[derive(Default)]
struct MockBillingState {
    available: bool,
    entitlements: HashMap<AccountRef, BillingEntitlement>,
}

impl MockBillingAdapter {
    pub fn new_available() -> Self {
        Self {
            state: RwLock::new(MockBillingState {
                available: true,
                entitlements: HashMap::new(),
            }),
        }
    }

    pub fn set_entitlement(
        &self,
        account: AccountRef,
        entitlement: BillingEntitlement,
    ) -> Result<(), BillingAdapterError> {
        self.state
            .write()
            .map_err(|_| BillingAdapterError::Unavailable)?
            .entitlements
            .insert(account, entitlement);
        Ok(())
    }

    pub fn set_available(&self, available: bool) -> Result<(), BillingAdapterError> {
        self.state
            .write()
            .map_err(|_| BillingAdapterError::Unavailable)?
            .available = available;
        Ok(())
    }
}

#[async_trait]
impl BillingEntitlementProvider for MockBillingAdapter {
    async fn entitlement_for(
        &self,
        account: &AccountRef,
        _now: i64,
    ) -> Result<BillingEntitlement, BillingAdapterError> {
        let state = self
            .state
            .read()
            .map_err(|_| BillingAdapterError::Unavailable)?;
        if !state.available {
            return Err(BillingAdapterError::Unavailable);
        }
        state
            .entitlements
            .get(account)
            .copied()
            .ok_or(BillingAdapterError::NotFound)
    }
}
