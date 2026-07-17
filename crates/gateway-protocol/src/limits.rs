use std::time::Duration;

use crate::{ProtocolError, Result};

pub const ABSOLUTE_MAX_FRAME_SIZE: usize = 64 * 1024;
pub const MIN_NEGOTIABLE_FRAME_SIZE: usize = 1024;
pub const MAX_DATA_PAYLOAD: usize = 32 * 1024;
pub const MAX_CAPABILITY_TOKEN: usize = 4 * 1024;
pub const MAX_PROOF_OF_POSSESSION: usize = 4 * 1024;
pub const MAX_CAPABILITIES: usize = 32;
pub const MAX_CAPABILITY_NAME: usize = 64;
pub const MAX_HOSTNAME: usize = 253;
pub const MAX_RESOLVE_ADDRESSES: usize = 16;
pub const MAX_CONCURRENT_STREAMS: usize = 4096;
pub const MAX_STREAM_WINDOW: u64 = 4 * 1024 * 1024;
pub const MAX_CONNECTION_WINDOW: u64 = 16 * 1024 * 1024;
pub const MAX_TIMEOUT_MS: u32 = 120_000;
pub const MAX_SESSION_TTL_SECONDS: u32 = 86_400;
pub const MAX_DRAIN_TIMEOUT_MS: u32 = 30_000;

/// Local hard limits. Negotiated peer limits can only reduce these values.
#[derive(Clone, Debug)]
pub struct ProtocolLimits {
    pub maximum_frame_size: usize,
    pub maximum_concurrent_streams: usize,
    pub initial_connection_window: u32,
    pub initial_stream_window: u32,
    pub maximum_queued_bytes: usize,
    pub maximum_queued_bytes_per_stream: usize,
    pub maximum_control_frames: usize,
    pub maximum_outstanding_resolves: usize,
    pub handshake_timeout: Duration,
    pub idle_stream_timeout: Duration,
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            maximum_frame_size: ABSOLUTE_MAX_FRAME_SIZE,
            maximum_concurrent_streams: 512,
            initial_connection_window: 4 * 1024 * 1024,
            initial_stream_window: 256 * 1024,
            maximum_queued_bytes: 8 * 1024 * 1024,
            maximum_queued_bytes_per_stream: 256 * 1024,
            maximum_control_frames: 256,
            maximum_outstanding_resolves: 128,
            handshake_timeout: Duration::from_secs(30),
            idle_stream_timeout: Duration::from_secs(120),
        }
    }
}

impl ProtocolLimits {
    pub fn validate(&self) -> Result<()> {
        if !(MIN_NEGOTIABLE_FRAME_SIZE..=ABSOLUTE_MAX_FRAME_SIZE).contains(&self.maximum_frame_size)
        {
            return Err(ProtocolError::InvalidField("maximum_frame_size"));
        }
        if !(1..=MAX_CONCURRENT_STREAMS).contains(&self.maximum_concurrent_streams) {
            return Err(ProtocolError::InvalidField("maximum_concurrent_streams"));
        }
        if self.initial_connection_window == 0
            || u64::from(self.initial_connection_window) > MAX_CONNECTION_WINDOW
        {
            return Err(ProtocolError::InvalidField("initial_connection_window"));
        }
        if self.initial_stream_window == 0
            || u64::from(self.initial_stream_window) > MAX_STREAM_WINDOW
        {
            return Err(ProtocolError::InvalidField("initial_stream_window"));
        }
        if self.maximum_queued_bytes == 0
            || self.maximum_queued_bytes_per_stream == 0
            || self.maximum_queued_bytes_per_stream > self.maximum_queued_bytes
            || self.maximum_control_frames == 0
            || self.maximum_outstanding_resolves == 0
        {
            return Err(ProtocolError::InvalidField("queue_limits"));
        }
        if self.handshake_timeout.is_zero() || self.idle_stream_timeout.is_zero() {
            return Err(ProtocolError::InvalidField("timeouts"));
        }
        Ok(())
    }
}
