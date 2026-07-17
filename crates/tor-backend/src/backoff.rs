use std::time::Duration;

use rand::{CryptoRng, Rng};

use crate::configuration_error;
use onionroute_common_types::OnionResult;

/// Validated finite retry policy with full jitter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// Total number of attempts, including the first zero-jitter delay.
    pub max_attempts: u8,
    /// Initial exponential-backoff cap.
    pub initial_delay: Duration,
    /// Hard upper bound for every generated delay.
    pub max_delay: Duration,
}

impl RetryPolicy {
    /// Rejects zero, unbounded, inverted, or excessively long policies.
    pub fn validate(self) -> OnionResult<Self> {
        if self.max_attempts == 0
            || self.max_attempts > 64
            || self.initial_delay.is_zero()
            || self.initial_delay > self.max_delay
            || self.max_delay > Duration::from_secs(60)
        {
            return Err(configuration_error("invalid bounded retry policy"));
        }
        Ok(self)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 64,
            initial_delay: Duration::from_millis(25),
            max_delay: Duration::from_secs(2),
        }
    }
}

/// State for one retry operation. Exhaustion is explicit and terminal.
pub struct BoundedBackoff<R> {
    policy: RetryPolicy,
    rng: R,
    attempts: u8,
}

impl<R: Rng + CryptoRng> BoundedBackoff<R> {
    /// Creates finite backoff state using the supplied cryptographic RNG.
    pub fn new(policy: RetryPolicy, rng: R) -> OnionResult<Self> {
        Ok(Self {
            policy: policy.validate()?,
            rng,
            attempts: 0,
        })
    }

    /// Returns the next full-jitter delay, or `None` after exhaustion.
    pub fn next_delay(&mut self) -> Option<Duration> {
        if self.attempts >= self.policy.max_attempts {
            return None;
        }
        let exponent = u32::from(self.attempts.min(20));
        self.attempts += 1;
        let cap_ms = self
            .policy
            .initial_delay
            .as_millis()
            .saturating_mul(1_u128 << exponent)
            .min(self.policy.max_delay.as_millis())
            .max(1) as u64;
        Some(Duration::from_millis(self.rng.gen_range(0..=cap_ms)))
    }

    /// Returns how many delays have already been issued.
    pub const fn attempts(&self) -> u8 {
        self.attempts
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn exhaustion_is_bounded() {
        let policy = RetryPolicy {
            max_attempts: 3,
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(20),
        };
        let mut backoff = BoundedBackoff::new(policy, StdRng::seed_from_u64(7)).unwrap();
        assert!(backoff.next_delay().unwrap() <= Duration::from_millis(10));
        assert!(backoff.next_delay().unwrap() <= Duration::from_millis(20));
        assert!(backoff.next_delay().unwrap() <= Duration::from_millis(20));
        assert_eq!(backoff.next_delay(), None);
    }
}
