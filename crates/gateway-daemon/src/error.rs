//! Redacted gateway error taxonomy.

use crate::onionroute::common::v1::{ErrorCategory, ErrorStatus, RetryHint};

/// Stable gateway-local errors. Variants intentionally carry no destination,
/// token, account, address, payload, or persistent session data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayErrorCode {
    InvalidConfiguration,
    MessageTooLarge,
    ProtocolViolation,
    ProtocolIncompatible,
    AuthenticationUnavailable,
    TokenRejected,
    SessionExpired,
    PolicyDenied,
    DnsFailure,
    DnsRebinding,
    ResourceExhausted,
    RateLimited,
    BandwidthExhausted,
    CircuitOpen,
    Draining,
    EgressFailure,
    EgressInfrastructureFailure,
    Timeout,
    Internal,
}

impl GatewayErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "invalid_configuration",
            Self::MessageTooLarge => "message_too_large",
            Self::ProtocolViolation => "protocol_violation",
            Self::ProtocolIncompatible => "protocol_incompatible",
            Self::AuthenticationUnavailable => "authentication_unavailable",
            Self::TokenRejected => "token_rejected",
            Self::SessionExpired => "session_expired",
            Self::PolicyDenied => "policy_denied",
            Self::DnsFailure => "dns_failure",
            Self::DnsRebinding => "dns_rebinding",
            Self::ResourceExhausted => "resource_exhausted",
            Self::RateLimited => "rate_limited",
            Self::BandwidthExhausted => "bandwidth_exhausted",
            Self::CircuitOpen => "circuit_open",
            Self::Draining => "gateway_draining",
            Self::EgressFailure => "egress_failure",
            Self::EgressInfrastructureFailure => "egress_infrastructure_failure",
            Self::Timeout => "timeout",
            Self::Internal => "internal",
        }
    }
}

/// An error safe to aggregate or return across the data-plane boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{code:?}")]
pub struct GatewayError {
    pub code: GatewayErrorCode,
}

impl GatewayError {
    pub const fn new(code: GatewayErrorCode) -> Self {
        Self { code }
    }

    pub fn to_status(self, correlation_id: [u8; 16]) -> ErrorStatus {
        let (category, retry_hint) = match self.code {
            GatewayErrorCode::MessageTooLarge | GatewayErrorCode::ProtocolViolation => {
                (ErrorCategory::Protocol, RetryHint::Never)
            }
            GatewayErrorCode::ProtocolIncompatible => {
                (ErrorCategory::Unsupported, RetryHint::Never)
            }
            GatewayErrorCode::AuthenticationUnavailable => {
                (ErrorCategory::Unavailable, RetryHint::Backoff)
            }
            GatewayErrorCode::TokenRejected | GatewayErrorCode::SessionExpired => {
                (ErrorCategory::Authentication, RetryHint::AfterTokenRefresh)
            }
            GatewayErrorCode::PolicyDenied | GatewayErrorCode::DnsRebinding => {
                (ErrorCategory::Policy, RetryHint::Never)
            }
            GatewayErrorCode::DnsFailure
            | GatewayErrorCode::EgressFailure
            | GatewayErrorCode::EgressInfrastructureFailure
            | GatewayErrorCode::Timeout
            | GatewayErrorCode::CircuitOpen
            | GatewayErrorCode::Draining => (ErrorCategory::Unavailable, RetryHint::Backoff),
            GatewayErrorCode::ResourceExhausted
            | GatewayErrorCode::RateLimited
            | GatewayErrorCode::BandwidthExhausted => {
                (ErrorCategory::ResourceExhausted, RetryHint::Backoff)
            }
            GatewayErrorCode::InvalidConfiguration | GatewayErrorCode::Internal => {
                (ErrorCategory::Internal, RetryHint::Never)
            }
        };
        ErrorStatus {
            code: self.code.as_str().to_owned(),
            category: category as i32,
            retry_hint: retry_hint as i32,
            correlation_id: correlation_id.to_vec(),
        }
    }
}

impl From<GatewayErrorCode> for GatewayError {
    fn from(code: GatewayErrorCode) -> Self {
        Self::new(code)
    }
}

pub type GatewayResult<T> = Result<T, GatewayError>;
