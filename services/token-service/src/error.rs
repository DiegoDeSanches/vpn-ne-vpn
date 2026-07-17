use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BillingAdapterError {
    #[error("billing entitlement provider is unavailable")]
    Unavailable,
    #[error("billing entitlement does not exist")]
    NotFound,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DeviceSlotError {
    #[error("device slot limit was reached")]
    LimitReached,
    #[error("device slot store is unavailable")]
    Unavailable,
}

/// Coarse response errors: none includes an account, payment, token, or device
/// identifier and callers must not enrich them with those values in logs.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TokenServiceError {
    #[error("token batch request is invalid")]
    InvalidRequest,
    #[error("entitlement service is unavailable")]
    EntitlementUnavailable,
    #[error("account is not entitled to receive tokens")]
    NotEntitled,
    #[error("entitlement ends before the next standard token window")]
    EntitlementEndsBeforeTokenWindow,
    #[error("device slot limit was reached")]
    DeviceSlotLimitReached,
    #[error("device slot service is unavailable")]
    DeviceSlotServiceUnavailable,
    #[error("anonymous credential issuer is unavailable")]
    IssuerUnavailable,
}
