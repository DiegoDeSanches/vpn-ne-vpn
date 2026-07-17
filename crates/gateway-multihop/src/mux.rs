//! Bounded fair scheduling and connection-pool admission for the relay multiplexer.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{ErrorCode, Result};

const CONTROL_BURST: usize = 8;
const ACCOUNTING_OVERHEAD: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundCommand {
    Open { session_id: u64, encoded: Vec<u8> },
    Data { session_id: u64, payload: Vec<u8> },
    Control { encoded: Vec<u8> },
}

impl OutboundCommand {
    fn session_id(&self) -> Option<u64> {
        match self {
            Self::Open { session_id, .. } | Self::Data { session_id, .. } => Some(*session_id),
            Self::Control { .. } => None,
        }
    }

    fn accounted_bytes(&self) -> Result<usize> {
        let payload = match self {
            Self::Open { encoded, .. } | Self::Control { encoded } => encoded.len(),
            Self::Data { payload, .. } => payload.len(),
        };
        payload
            .checked_add(ACCOUNTING_OVERHEAD)
            .ok_or(ErrorCode::ResourceExhausted.into())
    }
}

/// One-frame round-robin across logical sessions, with a bounded control burst.
/// Saturation returns `Backpressure`; it never grows the queue.
pub struct FairMuxQueue {
    control: VecDeque<OutboundCommand>,
    sessions: BTreeMap<u64, VecDeque<OutboundCommand>>,
    active: VecDeque<u64>,
    per_session_bytes: BTreeMap<u64, usize>,
    queued_bytes: usize,
    maximum_bytes: usize,
    maximum_per_session_bytes: usize,
    maximum_control_frames: usize,
    control_burst: usize,
}

impl FairMuxQueue {
    pub fn new(
        maximum_bytes: usize,
        maximum_per_session_bytes: usize,
        maximum_control_frames: usize,
    ) -> Result<Self> {
        if maximum_bytes == 0
            || maximum_per_session_bytes == 0
            || maximum_per_session_bytes > maximum_bytes
            || maximum_control_frames == 0
        {
            return Err(ErrorCode::InvalidConfiguration.into());
        }
        Ok(Self {
            control: VecDeque::new(),
            sessions: BTreeMap::new(),
            active: VecDeque::new(),
            per_session_bytes: BTreeMap::new(),
            queued_bytes: 0,
            maximum_bytes,
            maximum_per_session_bytes,
            maximum_control_frames,
            control_burst: 0,
        })
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    pub fn try_push(&mut self, command: OutboundCommand) -> Result<()> {
        let bytes = command.accounted_bytes()?;
        let total = self
            .queued_bytes
            .checked_add(bytes)
            .ok_or(ErrorCode::ResourceExhausted)?;
        if total > self.maximum_bytes {
            return Err(ErrorCode::Backpressure.into());
        }
        match command.session_id() {
            None => {
                if self.control.len() >= self.maximum_control_frames {
                    return Err(ErrorCode::Backpressure.into());
                }
                self.control.push_back(command);
            }
            Some(session_id) => {
                if session_id == 0 || session_id & 1 == 0 {
                    return Err(ErrorCode::ProtocolViolation.into());
                }
                let current = self
                    .per_session_bytes
                    .get(&session_id)
                    .copied()
                    .unwrap_or(0);
                let updated = current
                    .checked_add(bytes)
                    .ok_or(ErrorCode::ResourceExhausted)?;
                if updated > self.maximum_per_session_bytes {
                    return Err(ErrorCode::Backpressure.into());
                }
                let queue = self.sessions.entry(session_id).or_default();
                if queue.is_empty() {
                    self.active.push_back(session_id);
                }
                queue.push_back(command);
                self.per_session_bytes.insert(session_id, updated);
            }
        }
        self.queued_bytes = total;
        Ok(())
    }

    pub fn pop_next(&mut self) -> Option<OutboundCommand> {
        if !self.control.is_empty()
            && (self.control_burst < CONTROL_BURST || self.active.is_empty())
        {
            self.control_burst += 1;
            let command = self.control.pop_front()?;
            self.queued_bytes = self
                .queued_bytes
                .saturating_sub(command.accounted_bytes().unwrap_or(0));
            return Some(command);
        }
        if let Some(session_id) = self.active.pop_front() {
            let (command, remains) = {
                let queue = self.sessions.get_mut(&session_id)?;
                let command = queue.pop_front()?;
                (command, !queue.is_empty())
            };
            let bytes = command.accounted_bytes().unwrap_or(0);
            self.queued_bytes = self.queued_bytes.saturating_sub(bytes);
            let updated = self
                .per_session_bytes
                .get(&session_id)
                .copied()
                .unwrap_or(0)
                .saturating_sub(bytes);
            if remains {
                self.active.push_back(session_id);
                self.per_session_bytes.insert(session_id, updated);
            } else {
                self.sessions.remove(&session_id);
                self.per_session_bytes.remove(&session_id);
            }
            self.control_burst = 0;
            return Some(command);
        }
        let command = self.control.pop_front()?;
        self.queued_bytes = self
            .queued_bytes
            .saturating_sub(command.accounted_bytes().unwrap_or(0));
        Some(command)
    }

    pub fn cancel_session(&mut self, session_id: u64) {
        if let Some(queue) = self.sessions.remove(&session_id) {
            let removed = queue.iter().fold(0usize, |total, command| {
                total.saturating_add(command.accounted_bytes().unwrap_or(0))
            });
            self.queued_bytes = self.queued_bytes.saturating_sub(removed);
        }
        self.per_session_bytes.remove(&session_id);
        self.active.retain(|candidate| *candidate != session_id);
    }
}

#[derive(Clone, Debug)]
pub struct PoolLimits {
    pub maximum_total_connections: usize,
    pub maximum_connections_per_exit: usize,
}

#[derive(Clone)]
pub struct ConnectionPoolLimiter {
    total: Arc<Semaphore>,
    per_exit: Arc<Mutex<HashMap<String, usize>>>,
    limits: PoolLimits,
}

impl ConnectionPoolLimiter {
    pub fn new(limits: PoolLimits) -> Result<Self> {
        if limits.maximum_total_connections == 0
            || limits.maximum_connections_per_exit == 0
            || limits.maximum_connections_per_exit > limits.maximum_total_connections
        {
            return Err(ErrorCode::InvalidConfiguration.into());
        }
        Ok(Self {
            total: Arc::new(Semaphore::new(limits.maximum_total_connections)),
            per_exit: Arc::new(Mutex::new(HashMap::new())),
            limits,
        })
    }

    pub fn try_acquire(&self, exit_id: &str) -> Result<ConnectionPoolPermit> {
        if exit_id.is_empty() || exit_id.len() > 128 {
            return Err(ErrorCode::InvalidConfiguration.into());
        }
        let permit = self
            .total
            .clone()
            .try_acquire_owned()
            .map_err(|_| ErrorCode::ResourceExhausted)?;
        let mut per_exit = self.per_exit.lock().map_err(|_| ErrorCode::Internal)?;
        let current = per_exit.get(exit_id).copied().unwrap_or(0);
        if current >= self.limits.maximum_connections_per_exit {
            drop(permit);
            return Err(ErrorCode::ResourceExhausted.into());
        }
        per_exit.insert(exit_id.to_owned(), current + 1);
        Ok(ConnectionPoolPermit {
            _total: permit,
            exit_id: exit_id.to_owned(),
            per_exit: self.per_exit.clone(),
        })
    }
}

pub struct ConnectionPoolPermit {
    _total: OwnedSemaphorePermit,
    exit_id: String,
    per_exit: Arc<Mutex<HashMap<String, usize>>>,
}

impl Drop for ConnectionPoolPermit {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.per_exit.lock() {
            if let Some(current) = counts.get_mut(&self.exit_id) {
                *current = current.saturating_sub(1);
                if *current == 0 {
                    counts.remove(&self.exit_id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturated_queue_backpressures_and_round_robins() {
        let mut queue = FairMuxQueue::new(2_000, 1_000, 16).unwrap();
        queue
            .try_push(OutboundCommand::Data {
                session_id: 1,
                payload: vec![1; 100],
            })
            .unwrap();
        queue
            .try_push(OutboundCommand::Data {
                session_id: 3,
                payload: vec![3; 100],
            })
            .unwrap();
        assert!(matches!(
            queue.pop_next(),
            Some(OutboundCommand::Data { session_id: 1, .. })
        ));
        assert!(matches!(
            queue.pop_next(),
            Some(OutboundCommand::Data { session_id: 3, .. })
        ));
        assert_eq!(queue.queued_bytes(), 0);
    }

    #[test]
    fn pool_is_bounded_per_exit() {
        let pool = ConnectionPoolLimiter::new(PoolLimits {
            maximum_total_connections: 2,
            maximum_connections_per_exit: 1,
        })
        .unwrap();
        let first = pool.try_acquire("exit-a").unwrap();
        assert_eq!(
            pool.try_acquire("exit-a").err().unwrap().code,
            ErrorCode::ResourceExhausted
        );
        drop(first);
        pool.try_acquire("exit-a").unwrap();
    }
}
