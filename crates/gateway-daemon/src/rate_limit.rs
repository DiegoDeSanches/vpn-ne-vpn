//! Bounded token buckets and the egress failure circuit breaker.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::{GatewayErrorCode, GatewayResult};

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    updated_at: Instant,
}

/// A lock-protected token bucket suitable for short critical sections.
#[derive(Debug)]
pub struct TokenBucket {
    rate_per_second: f64,
    capacity: f64,
    state: Mutex<BucketState>,
}

impl TokenBucket {
    pub fn new(rate_per_second: u64, capacity: u64) -> Self {
        let now = Instant::now();
        Self {
            rate_per_second: rate_per_second as f64,
            capacity: capacity as f64,
            state: Mutex::new(BucketState {
                tokens: capacity as f64,
                updated_at: now,
            }),
        }
    }

    pub fn try_take(&self, amount: u64) -> GatewayResult<()> {
        let mut state = self.state.lock().map_err(|_| GatewayErrorCode::Internal)?;
        refill(&mut state, self.rate_per_second, self.capacity);
        if amount as f64 > state.tokens {
            return Err(GatewayErrorCode::RateLimited.into());
        }
        state.tokens -= amount as f64;
        Ok(())
    }

    fn reserve_delay(&self, amount: u64) -> GatewayResult<Duration> {
        let mut state = self.state.lock().map_err(|_| GatewayErrorCode::Internal)?;
        refill(&mut state, self.rate_per_second, self.capacity);
        let after = state.tokens - amount as f64;
        state.tokens = after;
        if after >= 0.0 {
            Ok(Duration::ZERO)
        } else {
            Ok(Duration::from_secs_f64((-after) / self.rate_per_second))
        }
    }
}

fn refill(state: &mut BucketState, rate: f64, capacity: f64) {
    let now = Instant::now();
    let elapsed = now
        .saturating_duration_since(state.updated_at)
        .as_secs_f64();
    state.tokens = (state.tokens + elapsed * rate).min(capacity);
    state.updated_at = now;
}

/// Per-token bandwidth limiter. Reservations create backpressure; the total
/// quota is a hard limit and never refills during a token lifetime.
#[derive(Debug)]
pub struct BandwidthLimiter {
    bucket: TokenBucket,
    used: AtomicU64,
    total_limit: u64,
    max_wait: Duration,
}

impl BandwidthLimiter {
    pub fn new(rate: u64, burst: u64, total_limit: u64, max_wait: Duration) -> Self {
        Self {
            bucket: TokenBucket::new(rate, burst),
            used: AtomicU64::new(0),
            total_limit,
            max_wait,
        }
    }

    pub async fn acquire(&self, amount: usize) -> GatewayResult<()> {
        let amount = u64::try_from(amount).map_err(|_| GatewayErrorCode::BandwidthExhausted)?;
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(amount)
                    .filter(|next| *next <= self.total_limit)
            })
            .map_err(|_| GatewayErrorCode::BandwidthExhausted)?;
        let delay = self.bucket.reserve_delay(amount)?;
        if delay > self.max_wait {
            return Err(GatewayErrorCode::BandwidthExhausted.into());
        }
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        Ok(())
    }

    pub fn used_bytes(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
struct BreakerState {
    open_until: Option<Instant>,
}

/// Global egress circuit breaker. Only connection failures affect it; policy,
/// authentication, and DNS denials do not.
#[derive(Debug)]
pub struct CircuitBreaker {
    failures: AtomicU32,
    threshold: u32,
    cooldown: Duration,
    state: Mutex<BreakerState>,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, cooldown: Duration) -> Self {
        Self {
            failures: AtomicU32::new(0),
            threshold,
            cooldown,
            state: Mutex::new(BreakerState { open_until: None }),
        }
    }

    pub fn before_connect(&self) -> GatewayResult<()> {
        let mut state = self.state.lock().map_err(|_| GatewayErrorCode::Internal)?;
        if let Some(deadline) = state.open_until {
            if Instant::now() < deadline {
                return Err(GatewayErrorCode::CircuitOpen.into());
            }
            state.open_until = None;
            self.failures.store(0, Ordering::Release);
        }
        Ok(())
    }

    pub fn record_success(&self) {
        self.failures.store(0, Ordering::Release);
    }

    pub fn record_failure(&self) {
        let failures = self
            .failures
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        if failures >= self.threshold {
            if let Ok(mut state) = self.state.lock() {
                state.open_until = Some(Instant::now() + self.cooldown);
            }
        }
    }

    pub fn is_open(&self) -> bool {
        self.before_connect().is_err()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_bucket_is_bounded() {
        let bucket = TokenBucket::new(1, 2);
        assert!(bucket.try_take(1).is_ok());
        assert!(bucket.try_take(1).is_ok());
        assert_eq!(
            bucket.try_take(1).unwrap_err().code,
            GatewayErrorCode::RateLimited
        );
    }

    #[test]
    fn circuit_opens_at_threshold() {
        let breaker = CircuitBreaker::new(2, Duration::from_secs(60));
        breaker.record_failure();
        assert!(breaker.before_connect().is_ok());
        breaker.record_failure();
        assert_eq!(
            breaker.before_connect().unwrap_err().code,
            GatewayErrorCode::CircuitOpen
        );
    }
}
