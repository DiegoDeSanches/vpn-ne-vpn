use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use onionroute_common_types::types::AnonymityMode;
use onionroute_common_types::OnionResult;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::circuit_error;
use onionroute_common_types::error::{ErrorCode, RetryClass, SafetyImpact, Severity};

/// Local anti-stampede limits shared by all scheduled Tor contexts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RotationSchedulerConfig {
    /// Minimum gap between two accepted local rotations.
    pub minimum_spacing: Duration,
    /// Sliding window used for the context-fleet limit.
    pub fleet_window: Duration,
    /// Maximum accepted rotations inside the sliding window.
    pub maximum_in_window: usize,
}

impl Default for RotationSchedulerConfig {
    fn default() -> Self {
        Self {
            minimum_spacing: Duration::from_secs(5),
            fleet_window: Duration::from_secs(60),
            maximum_in_window: 4,
        }
    }
}

impl RotationSchedulerConfig {
    fn validate(self) -> OnionResult<Self> {
        if self.minimum_spacing.is_zero()
            || self.minimum_spacing > Duration::from_secs(60)
            || self.fleet_window < self.minimum_spacing
            || self.fleet_window > Duration::from_secs(10 * 60)
            || self.maximum_in_window == 0
            || self.maximum_in_window > 32
        {
            return Err(circuit_error(
                ErrorCode::InvalidConfiguration,
                Severity::Error,
                RetryClass::Never,
                SafetyImpact::NotApplicable,
                "invalid rotation scheduler configuration",
            ));
        }
        Ok(self)
    }
}

/// Sliding-window limiter that prevents local Tor contexts rotating together.
pub struct RotationGate {
    config: RotationSchedulerConfig,
    accepted: VecDeque<Instant>,
}

impl RotationGate {
    /// Creates an empty sliding-window gate.
    pub fn new(config: RotationSchedulerConfig) -> OnionResult<Self> {
        Ok(Self {
            config: config.validate()?,
            accepted: VecDeque::new(),
        })
    }

    /// Records and accepts a rotation only when spacing/window limits allow it.
    pub fn try_acquire(&mut self, now: Instant) -> bool {
        while self
            .accepted
            .front()
            .map(|timestamp| now.saturating_duration_since(*timestamp) >= self.config.fleet_window)
            .unwrap_or(false)
        {
            self.accepted.pop_front();
        }
        if self
            .accepted
            .back()
            .map(|timestamp| {
                now.saturating_duration_since(*timestamp) < self.config.minimum_spacing
            })
            .unwrap_or(false)
            || self.accepted.len() >= self.config.maximum_in_window
        {
            return false;
        }
        self.accepted.push_back(now);
        true
    }
}

/// Full-window jitter scheduler for automatic soft rotations.
pub struct RotationScheduler {
    rng: Mutex<StdRng>,
    gate: Mutex<RotationGate>,
}

impl RotationScheduler {
    /// Creates a cryptographically randomized full-window scheduler.
    pub fn new(config: RotationSchedulerConfig) -> OnionResult<Self> {
        Ok(Self {
            rng: Mutex::new(StdRng::from_entropy()),
            gate: Mutex::new(RotationGate::new(config)?),
        })
    }

    #[cfg(any(test, feature = "test-utils"))]
    /// Creates a deterministic scheduler for tests only.
    pub fn with_seed(config: RotationSchedulerConfig, seed: u64) -> OnionResult<Self> {
        Ok(Self {
            rng: Mutex::new(StdRng::seed_from_u64(seed)),
            gate: Mutex::new(RotationGate::new(config)?),
        })
    }

    /// Returns a uniformly jittered delay inside the profile's entire allowed window.
    pub fn next_delay(&self, profile: AnonymityMode) -> OnionResult<Duration> {
        let (minimum_minutes, maximum_minutes) = match profile {
            AnonymityMode::Standard | AnonymityMode::DirectTor => (15_u64, 30_u64),
            AnonymityMode::Enhanced => (10, 20),
            AnonymityMode::Maximum => (5, 15),
        };
        let minimum = Duration::from_secs(minimum_minutes * 60);
        let maximum = Duration::from_secs(maximum_minutes * 60);
        let range_ms = maximum.as_millis() as u64 - minimum.as_millis() as u64;
        let jitter_ms = self
            .rng
            .lock()
            .map_err(|_| rotation_invariant())?
            .gen_range(0..=range_ms);
        Ok(minimum + Duration::from_millis(jitter_ms))
    }

    /// Applies the shared anti-stampede gate to one due rotation.
    pub fn try_acquire(&self, now: Instant) -> OnionResult<bool> {
        Ok(self
            .gate
            .lock()
            .map_err(|_| rotation_invariant())?
            .try_acquire(now))
    }
}

fn rotation_invariant() -> onionroute_common_types::OnionError {
    circuit_error(
        ErrorCode::InvariantViolation,
        Severity::Fatal,
        RetryClass::Never,
        SafetyImpact::MustBlock,
        "rotation scheduler invariant failed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_intervals_stay_inside_required_windows() {
        let scheduler = RotationScheduler::with_seed(Default::default(), 7).unwrap();
        for _ in 0..100 {
            let standard = scheduler.next_delay(AnonymityMode::Standard).unwrap();
            assert!(
                (Duration::from_secs(15 * 60)..=Duration::from_secs(30 * 60)).contains(&standard)
            );
            let enhanced = scheduler.next_delay(AnonymityMode::Enhanced).unwrap();
            assert!(
                (Duration::from_secs(10 * 60)..=Duration::from_secs(20 * 60)).contains(&enhanced)
            );
            let maximum = scheduler.next_delay(AnonymityMode::Maximum).unwrap();
            assert!((Duration::from_secs(5 * 60)..=Duration::from_secs(15 * 60)).contains(&maximum));
        }
    }

    #[test]
    fn gate_prevents_mass_rotation() {
        let mut gate = RotationGate::new(RotationSchedulerConfig::default()).unwrap();
        let now = Instant::now();
        assert!(gate.try_acquire(now));
        assert!(!gate.try_acquire(now + Duration::from_secs(1)));
    }
}
