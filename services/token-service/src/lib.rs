//! Account-plane entitlement and device-slot orchestration.
//!
//! Identity-bearing types stop at this crate. The injected
//! [`onionroute_auth_tokens::TokenIssuer`] receives only a canonical policy,
//! bucketed validity window and an ephemeral PoP public key.

mod billing;
mod device_slots;
mod error;
mod service;
mod types;

pub use billing::{BillingEntitlementProvider, MockBillingAdapter};
pub use device_slots::{DeviceSlotManager, InMemoryDeviceSlotManager};
pub use error::{BillingAdapterError, DeviceSlotError, TokenServiceError};
pub use service::TokenService;
pub use types::{
    AccountRef, AuthenticatedAccountContext, BillingEntitlement, EntitlementStatus,
    InstallationRef, MintTokenBatchRequest, MintTokenBatchResponse,
};

pub const MAX_TOKEN_BATCH_SIZE: usize = 8;
