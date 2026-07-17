use std::collections::{BTreeMap, VecDeque};

use crate::proto::gateway_frame::Body;
use crate::{ProtocolError, Result};

const MAX_CONTROL_BURST: usize = 8;

#[derive(Debug)]
pub(crate) struct OutboundItem {
    pub body: Body,
    pub accounted_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Data, Ping};

    fn data(stream_id: u64, marker: u8) -> OutboundItem {
        OutboundItem {
            body: Body::Data(Data {
                stream_id,
                payload: vec![marker],
            }),
            accounted_bytes: 1,
        }
    }

    #[test]
    fn streams_are_round_robin_and_control_cannot_starve_data() {
        let mut scheduler = FairScheduler::new(1024, 512, 64).unwrap();
        scheduler.enqueue_stream(1, data(1, 1)).unwrap();
        scheduler.enqueue_stream(1, data(1, 2)).unwrap();
        scheduler.enqueue_stream(3, data(3, 3)).unwrap();
        for _ in 0..16 {
            scheduler
                .enqueue_control(OutboundItem {
                    body: Body::Ping(Ping { nonce: vec![0; 8] }),
                    accounted_bytes: 1,
                })
                .unwrap();
        }

        for _ in 0..8 {
            assert!(matches!(scheduler.pop_next().unwrap().body, Body::Ping(_)));
        }
        assert!(matches!(
            scheduler.pop_next().unwrap().body,
            Body::Data(Data { stream_id: 1, .. })
        ));
        for _ in 0..8 {
            assert!(matches!(scheduler.pop_next().unwrap().body, Body::Ping(_)));
        }
        assert!(matches!(
            scheduler.pop_next().unwrap().body,
            Body::Data(Data { stream_id: 3, .. })
        ));
    }
}

/// Bounded scheduler with a small control burst and one-frame deficit-free
/// round-robin across data streams. It cannot remove wire-level HOL from the
/// single transport, but a busy stream cannot monopolize the user scheduler.
#[derive(Debug)]
pub(crate) struct FairScheduler {
    control: VecDeque<OutboundItem>,
    streams: BTreeMap<u64, VecDeque<OutboundItem>>,
    per_stream_bytes: BTreeMap<u64, usize>,
    active: VecDeque<u64>,
    queued_bytes: usize,
    maximum_queued_bytes: usize,
    maximum_queued_bytes_per_stream: usize,
    maximum_control_frames: usize,
    control_burst: usize,
}

impl FairScheduler {
    pub fn new(
        maximum_queued_bytes: usize,
        maximum_queued_bytes_per_stream: usize,
        maximum_control_frames: usize,
    ) -> Result<Self> {
        if maximum_queued_bytes == 0
            || maximum_queued_bytes_per_stream == 0
            || maximum_queued_bytes_per_stream > maximum_queued_bytes
            || maximum_control_frames == 0
        {
            return Err(ProtocolError::InvalidField("scheduler_limits"));
        }
        Ok(Self {
            control: VecDeque::new(),
            streams: BTreeMap::new(),
            per_stream_bytes: BTreeMap::new(),
            active: VecDeque::new(),
            queued_bytes: 0,
            maximum_queued_bytes,
            maximum_queued_bytes_per_stream,
            maximum_control_frames,
            control_burst: 0,
        })
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    pub fn can_enqueue_control(&self, bytes: usize) -> Result<()> {
        if self.control.len() >= self.maximum_control_frames {
            return Err(ProtocolError::Backpressure);
        }
        self.reserve_global(bytes)
    }

    pub fn can_enqueue_stream(&self, stream_id: u64, bytes: usize) -> Result<()> {
        self.reserve_global(bytes)?;
        let current = self.per_stream_bytes.get(&stream_id).copied().unwrap_or(0);
        let updated = current
            .checked_add(bytes)
            .ok_or(ProtocolError::IntegerOverflow)?;
        if updated > self.maximum_queued_bytes_per_stream {
            return Err(ProtocolError::Backpressure);
        }
        Ok(())
    }

    pub fn enqueue_control(&mut self, item: OutboundItem) -> Result<()> {
        self.can_enqueue_control(item.accounted_bytes)?;
        self.queued_bytes += item.accounted_bytes;
        self.control.push_back(item);
        Ok(())
    }

    pub fn enqueue_stream(&mut self, stream_id: u64, item: OutboundItem) -> Result<()> {
        self.can_enqueue_stream(stream_id, item.accounted_bytes)?;
        let current = self.per_stream_bytes.get(&stream_id).copied().unwrap_or(0);
        let updated = current + item.accounted_bytes;

        let queue = self.streams.entry(stream_id).or_default();
        if queue.is_empty() {
            self.active.push_back(stream_id);
        }
        queue.push_back(item);
        self.per_stream_bytes.insert(stream_id, updated);
        self.queued_bytes = self
            .queued_bytes
            .checked_add(queue.back().expect("just pushed").accounted_bytes)
            .ok_or(ProtocolError::IntegerOverflow)?;
        Ok(())
    }

    pub fn pop_next(&mut self) -> Option<OutboundItem> {
        if !self.control.is_empty()
            && (self.control_burst < MAX_CONTROL_BURST || self.active.is_empty())
        {
            self.control_burst += 1;
            let item = self.control.pop_front()?;
            self.queued_bytes = self.queued_bytes.saturating_sub(item.accounted_bytes);
            return Some(item);
        }

        if let Some(stream_id) = self.active.pop_front() {
            let (item, remains_active) = {
                let queue = self.streams.get_mut(&stream_id)?;
                let item = queue.pop_front()?;
                (item, !queue.is_empty())
            };
            self.control_burst = 0;
            self.queued_bytes = self.queued_bytes.saturating_sub(item.accounted_bytes);
            let current = self.per_stream_bytes.get(&stream_id).copied().unwrap_or(0);
            let updated = current.saturating_sub(item.accounted_bytes);
            if remains_active {
                self.active.push_back(stream_id);
                self.per_stream_bytes.insert(stream_id, updated);
            } else {
                self.streams.remove(&stream_id);
                self.per_stream_bytes.remove(&stream_id);
            }
            return Some(item);
        }

        let item = self.control.pop_front()?;
        self.queued_bytes = self.queued_bytes.saturating_sub(item.accounted_bytes);
        Some(item)
    }

    pub fn cancel_stream(&mut self, stream_id: u64) {
        if let Some(queue) = self.streams.remove(&stream_id) {
            let removed = queue
                .iter()
                .fold(0usize, |sum, item| sum.saturating_add(item.accounted_bytes));
            self.queued_bytes = self.queued_bytes.saturating_sub(removed);
        }
        self.per_stream_bytes.remove(&stream_id);
        self.active.retain(|candidate| *candidate != stream_id);
    }

    fn reserve_global(&self, bytes: usize) -> Result<()> {
        let updated = self
            .queued_bytes
            .checked_add(bytes)
            .ok_or(ProtocolError::IntegerOverflow)?;
        if updated > self.maximum_queued_bytes {
            return Err(ProtocolError::Backpressure);
        }
        Ok(())
    }
}
