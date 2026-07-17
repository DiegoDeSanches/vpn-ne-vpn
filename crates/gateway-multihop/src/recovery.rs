//! Make-before-break route recovery with no clearnet fallback state.

use std::time::Duration;

use crate::route::{
    select_enhanced_route, EnhancedRoute, GatewayDescriptor, RecentFailure, RoutePolicy,
};
use crate::{ErrorCode, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureClass {
    Transport,
    CertificateRevoked,
    ProtocolIncompatible,
    ExitDraining,
    Policy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    ReconnectEnhanced {
        route: EnhancedRoute,
        after: Duration,
    },
    Block,
}

#[derive(Clone, Debug)]
pub struct FailClosedRecovery {
    pub initial_backoff: Duration,
    pub maximum_backoff: Duration,
    consecutive_failures: u8,
}

impl Default for FailClosedRecovery {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_millis(250),
            maximum_backoff: Duration::from_secs(30),
            consecutive_failures: 0,
        }
    }
}

impl FailClosedRecovery {
    pub fn on_success(&mut self) {
        self.consecutive_failures = 0;
    }

    pub fn recover(
        &mut self,
        class: FailureClass,
        entry: &GatewayDescriptor,
        exits: &[GatewayDescriptor],
        policy: &RoutePolicy,
        failures: &[RecentFailure],
    ) -> Result<RecoveryAction> {
        if self.initial_backoff.is_zero()
            || self.maximum_backoff < self.initial_backoff
            || class == FailureClass::Policy
        {
            return Ok(RecoveryAction::Block);
        }
        self.consecutive_failures = self.consecutive_failures.saturating_add(1).min(16);
        let route = match select_enhanced_route(entry, exits, policy, failures) {
            Ok(route) => route,
            Err(error)
                if matches!(
                    error.code,
                    ErrorCode::PolicyDenied | ErrorCode::ProtocolIncompatible
                ) =>
            {
                return Ok(RecoveryAction::Block)
            }
            Err(error) => return Err(error),
        };
        let exponent = u32::from(self.consecutive_failures.saturating_sub(1).min(10));
        let multiplier = 1u32.checked_shl(exponent).unwrap_or(u32::MAX);
        let after = self
            .initial_backoff
            .checked_mul(multiplier)
            .unwrap_or(self.maximum_backoff)
            .min(self.maximum_backoff);
        Ok(RecoveryAction::ReconnectEnhanced { route, after })
    }
}
