use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use onionroute_auth_tokens::DeviceSlotClass;

use crate::{AccountRef, DeviceSlotError, InstallationRef};

#[derive(Clone, Copy, Debug)]
pub struct DeviceSlotAuthorization(());

/// Control-plane-only persistent installation accounting. Neither the
/// installation reference nor account reference appears in a capability token.
#[async_trait]
pub trait DeviceSlotManager: Send + Sync + 'static {
    async fn authorize_slot(
        &self,
        account: &AccountRef,
        installation: InstallationRef,
        class: DeviceSlotClass,
    ) -> Result<DeviceSlotAuthorization, DeviceSlotError>;

    async fn release_slot(
        &self,
        account: &AccountRef,
        installation: InstallationRef,
    ) -> Result<(), DeviceSlotError>;
}

#[derive(Default)]
pub struct InMemoryDeviceSlotManager {
    slots: Mutex<HashMap<AccountRef, HashSet<InstallationRef>>>,
}

#[async_trait]
impl DeviceSlotManager for InMemoryDeviceSlotManager {
    async fn authorize_slot(
        &self,
        account: &AccountRef,
        installation: InstallationRef,
        class: DeviceSlotClass,
    ) -> Result<DeviceSlotAuthorization, DeviceSlotError> {
        let mut slots = self
            .slots
            .lock()
            .map_err(|_| DeviceSlotError::Unavailable)?;
        let installations = slots.entry(account.clone()).or_default();
        if !installations.contains(&installation) && installations.len() >= class.slot_limit() {
            return Err(DeviceSlotError::LimitReached);
        }
        installations.insert(installation);
        Ok(DeviceSlotAuthorization(()))
    }

    async fn release_slot(
        &self,
        account: &AccountRef,
        installation: InstallationRef,
    ) -> Result<(), DeviceSlotError> {
        let mut slots = self
            .slots
            .lock()
            .map_err(|_| DeviceSlotError::Unavailable)?;
        if let Some(installations) = slots.get_mut(account) {
            installations.remove(&installation);
            if installations.is_empty() {
                slots.remove(account);
            }
        }
        Ok(())
    }
}
