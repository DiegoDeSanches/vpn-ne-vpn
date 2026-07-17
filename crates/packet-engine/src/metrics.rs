//! Closed-schema, local metrics boundary.

use onionroute_common_types::types::FlowId;

use crate::action::BlockReason;

/// Allow-listed metric event without addresses, hostnames, application IDs, or traffic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricEvent {
    /// A flow entry was allocated.
    FlowOpened,
    /// A flow entry was released.
    FlowClosed,
    /// A packet or flow was blocked.
    FlowBlocked(BlockReason),
    /// A duplicate segment was observed.
    Retransmission,
    /// Queue capacity was exhausted.
    Backpressure,
}

/// Local metrics interface. Implementations must not attach destination labels.
pub trait MetricsSink: Send + Sync {
    /// Records one closed-schema event. `flow_id` is process-local and must not be exported.
    fn record(&self, event: MetricEvent, flow_id: Option<FlowId>);
}

/// Metrics sink used when local diagnostics are disabled.
#[derive(Default)]
pub struct NoopMetrics;

impl MetricsSink for NoopMetrics {
    fn record(&self, _event: MetricEvent, _flow_id: Option<FlowId>) {}
}
