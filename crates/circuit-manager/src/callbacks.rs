use onionroute_common_types::transport::BoxFuture;
use onionroute_common_types::types::RotationReason;
use onionroute_common_types::OnionResult;

/// Client-core callbacks required by disruptive identity transitions.
///
/// Implementations must be idempotent. No callback may enable clearnet
/// fallback or disengage the kill switch.
pub trait RotationObserver: Send + Sync {
    /// Notifies client-core before any active stream is closed.
    fn hard_rotation_started(&self, reason: RotationReason) -> BoxFuture<'_, OnionResult<()>>;
    /// Closes every active client/gateway stream and waits for completion.
    fn close_active_streams(&self) -> BoxFuture<'_, OnionResult<()>>;
    /// Clears protected DNS mappings after a manual identity reset.
    fn flush_dns_state(&self) -> BoxFuture<'_, OnionResult<()>>;
    /// Revokes the temporary private-gateway session after identity reset.
    fn revoke_temporary_gateway_session(&self) -> BoxFuture<'_, OnionResult<()>>;
    /// Clears other bounded transient identity state.
    fn clear_transient_state(&self) -> BoxFuture<'_, OnionResult<()>>;
}

#[derive(Default)]
/// Observer that acknowledges every callback without side effects.
pub struct NoopRotationObserver;

impl RotationObserver for NoopRotationObserver {
    fn hard_rotation_started(&self, _reason: RotationReason) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async { Ok(()) })
    }

    fn close_active_streams(&self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async { Ok(()) })
    }

    fn flush_dns_state(&self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async { Ok(()) })
    }

    fn revoke_temporary_gateway_session(&self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async { Ok(()) })
    }

    fn clear_transient_state(&self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async { Ok(()) })
    }
}
