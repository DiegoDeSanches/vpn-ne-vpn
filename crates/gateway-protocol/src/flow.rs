use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::limits::{MAX_CONNECTION_WINDOW, MAX_STREAM_WINDOW};
use crate::validation::validate_stream_id;
use crate::{ProtocolError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamPhase {
    OpeningLocal,
    OpeningRemote,
    Open,
}

#[derive(Clone, Debug)]
pub struct StreamState {
    phase: StreamPhase,
    send_window: u64,
    receive_window: u64,
    local_half_closed: bool,
    remote_half_closed: bool,
    last_activity: Instant,
}

impl StreamState {
    pub fn phase(&self) -> StreamPhase {
        self.phase
    }

    pub fn send_window(&self) -> u64 {
        self.send_window
    }

    pub fn receive_window(&self) -> u64 {
        self.receive_window
    }

    pub fn local_half_closed(&self) -> bool {
        self.local_half_closed
    }

    pub fn remote_half_closed(&self) -> bool {
        self.remote_half_closed
    }
}

/// Credit ledger for both connection and per-stream windows. All arithmetic is
/// checked and bounded; this type never stores user payload bytes.
#[derive(Debug)]
pub struct FlowController {
    connection_send_window: u64,
    connection_receive_window: u64,
    maximum_concurrent_streams: usize,
    maximum_seen_stream_id: u64,
    streams: BTreeMap<u64, StreamState>,
}

impl FlowController {
    pub fn new(
        peer_connection_receive_window: u32,
        local_connection_receive_window: u32,
        maximum_concurrent_streams: usize,
    ) -> Result<Self> {
        if peer_connection_receive_window == 0
            || local_connection_receive_window == 0
            || u64::from(peer_connection_receive_window) > MAX_CONNECTION_WINDOW
            || u64::from(local_connection_receive_window) > MAX_CONNECTION_WINDOW
            || maximum_concurrent_streams == 0
        {
            return Err(ProtocolError::InvalidField("flow_controller_limits"));
        }
        Ok(Self {
            connection_send_window: u64::from(peer_connection_receive_window),
            connection_receive_window: u64::from(local_connection_receive_window),
            maximum_concurrent_streams,
            maximum_seen_stream_id: 0,
            streams: BTreeMap::new(),
        })
    }

    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    pub fn maximum_seen_stream_id(&self) -> u64 {
        self.maximum_seen_stream_id
    }

    pub fn stream(&self, stream_id: u64) -> Option<&StreamState> {
        self.streams.get(&stream_id)
    }

    pub fn open_local(&mut self, stream_id: u64, local_receive_window: u32) -> Result<()> {
        self.insert_new_stream(
            stream_id,
            StreamPhase::OpeningLocal,
            0,
            local_receive_window,
        )
    }

    pub fn receive_open(&mut self, stream_id: u64, peer_receive_window: u32) -> Result<()> {
        self.insert_new_stream(
            stream_id,
            StreamPhase::OpeningRemote,
            peer_receive_window,
            0,
        )
    }

    pub fn confirm_local_open(&mut self, stream_id: u64, peer_receive_window: u32) -> Result<()> {
        validate_window(peer_receive_window)?;
        let stream = self.stream_mut(stream_id)?;
        if stream.phase != StreamPhase::OpeningLocal {
            return Err(ProtocolError::ProtocolViolation(
                "unexpected stream-open response",
            ));
        }
        stream.phase = StreamPhase::Open;
        stream.send_window = u64::from(peer_receive_window);
        stream.last_activity = Instant::now();
        Ok(())
    }

    pub fn accept_remote_open(&mut self, stream_id: u64, local_receive_window: u32) -> Result<()> {
        validate_window(local_receive_window)?;
        let stream = self.stream_mut(stream_id)?;
        if stream.phase != StreamPhase::OpeningRemote {
            return Err(ProtocolError::ProtocolViolation(
                "unexpected stream acceptance",
            ));
        }
        stream.phase = StreamPhase::Open;
        stream.receive_window = u64::from(local_receive_window);
        stream.last_activity = Instant::now();
        Ok(())
    }

    pub fn reject_or_close(&mut self, stream_id: u64) -> Result<()> {
        validate_stream_id(stream_id)?;
        self.streams
            .remove(&stream_id)
            .ok_or(ProtocolError::InvalidStreamId)?;
        Ok(())
    }

    pub fn debit_send(&mut self, stream_id: u64, bytes: usize) -> Result<()> {
        let amount = u64::try_from(bytes).map_err(|_| ProtocolError::IntegerOverflow)?;
        if amount == 0 {
            return Err(ProtocolError::InvalidField("data_length"));
        }
        if self.connection_send_window < amount {
            return Err(ProtocolError::Backpressure);
        }
        {
            let stream = self.stream_mut(stream_id)?;
            if stream.phase != StreamPhase::Open || stream.local_half_closed {
                return Err(ProtocolError::Closed);
            }
            if stream.send_window < amount {
                return Err(ProtocolError::Backpressure);
            }
            stream.send_window -= amount;
            stream.last_activity = Instant::now();
        }
        self.connection_send_window -= amount;
        Ok(())
    }

    pub fn debit_receive(&mut self, stream_id: u64, bytes: usize) -> Result<()> {
        let amount = u64::try_from(bytes).map_err(|_| ProtocolError::IntegerOverflow)?;
        let invalid_stream = match self.streams.get(&stream_id) {
            Some(stream) => {
                stream.phase != StreamPhase::Open
                    || stream.remote_half_closed
                    || stream.receive_window < amount
            }
            None => true,
        };
        if amount == 0 || self.connection_receive_window < amount || invalid_stream {
            return Err(ProtocolError::FlowControlViolation);
        }
        {
            let stream = self.stream_mut(stream_id)?;
            stream.receive_window -= amount;
            stream.last_activity = Instant::now();
        }
        self.connection_receive_window -= amount;
        Ok(())
    }

    /// Applies peer-granted send credit from an inbound WindowUpdate.
    pub fn receive_window_update(&mut self, stream_id: u64, credit: u32) -> Result<()> {
        if credit == 0 {
            return Err(ProtocolError::FlowControlViolation);
        }
        if stream_id == 0 {
            self.connection_send_window = checked_credit_add(
                self.connection_send_window,
                u64::from(credit),
                MAX_CONNECTION_WINDOW,
            )?;
        } else {
            let stream = self.stream_mut(stream_id)?;
            stream.send_window =
                checked_credit_add(stream.send_window, u64::from(credit), MAX_STREAM_WINDOW)?;
            stream.last_activity = Instant::now();
        }
        Ok(())
    }

    /// Restores local receive credit before sending a WindowUpdate. Call only
    /// after the application has consumed the corresponding bytes.
    pub fn grant_receive_credit(&mut self, stream_id: u64, credit: u32) -> Result<()> {
        if credit == 0 {
            return Err(ProtocolError::InvalidField("window_credit"));
        }
        if stream_id == 0 {
            self.connection_receive_window = checked_credit_add(
                self.connection_receive_window,
                u64::from(credit),
                MAX_CONNECTION_WINDOW,
            )?;
        } else {
            let stream = self.stream_mut(stream_id)?;
            stream.receive_window =
                checked_credit_add(stream.receive_window, u64::from(credit), MAX_STREAM_WINDOW)?;
            stream.last_activity = Instant::now();
        }
        Ok(())
    }

    pub fn local_half_close(&mut self, stream_id: u64) -> Result<()> {
        let stream = self.stream_mut(stream_id)?;
        if stream.phase != StreamPhase::Open || stream.local_half_closed {
            return Err(ProtocolError::Closed);
        }
        stream.local_half_closed = true;
        stream.last_activity = Instant::now();
        Ok(())
    }

    pub fn receive_half_close(&mut self, stream_id: u64) -> Result<()> {
        let stream = self.stream_mut(stream_id)?;
        if stream.phase != StreamPhase::Open || stream.remote_half_closed {
            return Err(ProtocolError::ProtocolViolation(
                "duplicate remote half-close",
            ));
        }
        stream.remote_half_closed = true;
        stream.last_activity = Instant::now();
        Ok(())
    }

    pub fn expire_idle(&self, now: Instant, timeout: Duration) -> Vec<u64> {
        self.streams
            .iter()
            .filter_map(|(stream_id, stream)| {
                now.checked_duration_since(stream.last_activity)
                    .filter(|elapsed| *elapsed >= timeout)
                    .map(|_| *stream_id)
            })
            .collect()
    }

    fn insert_new_stream(
        &mut self,
        stream_id: u64,
        phase: StreamPhase,
        send_window: u32,
        receive_window: u32,
    ) -> Result<()> {
        validate_stream_id(stream_id)?;
        if stream_id <= self.maximum_seen_stream_id || self.streams.contains_key(&stream_id) {
            return Err(ProtocolError::InvalidStreamId);
        }
        if self.streams.len() >= self.maximum_concurrent_streams {
            return Err(ProtocolError::StreamLimit);
        }
        if send_window != 0 {
            validate_window(send_window)?;
        }
        if receive_window != 0 {
            validate_window(receive_window)?;
        }
        self.maximum_seen_stream_id = stream_id;
        self.streams.insert(
            stream_id,
            StreamState {
                phase,
                send_window: u64::from(send_window),
                receive_window: u64::from(receive_window),
                local_half_closed: false,
                remote_half_closed: false,
                last_activity: Instant::now(),
            },
        );
        Ok(())
    }

    fn stream_mut(&mut self, stream_id: u64) -> Result<&mut StreamState> {
        validate_stream_id(stream_id)?;
        self.streams
            .get_mut(&stream_id)
            .ok_or(ProtocolError::InvalidStreamId)
    }
}

fn validate_window(window: u32) -> Result<()> {
    if window == 0 || u64::from(window) > MAX_STREAM_WINDOW {
        return Err(ProtocolError::InvalidField("stream_window"));
    }
    Ok(())
}

fn checked_credit_add(current: u64, credit: u64, maximum: u64) -> Result<u64> {
    let updated = current
        .checked_add(credit)
        .ok_or(ProtocolError::IntegerOverflow)?;
    if updated > maximum {
        return Err(ProtocolError::FlowControlViolation);
    }
    Ok(updated)
}
