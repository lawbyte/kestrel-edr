//! Exponential reconnect backoff with full jitter (1 s → 5 min).

use rand::Rng;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    max: Duration,
    attempt: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff::new(Duration::from_secs(1), Duration::from_secs(300))
    }
}

impl Backoff {
    pub fn new(base: Duration, max: Duration) -> Backoff {
        Backoff {
            base,
            max,
            attempt: 0,
        }
    }

    /// Upper bound of the next delay (before jitter).
    pub fn ceiling(&self) -> Duration {
        let exp = self.attempt.min(20);
        self.base.saturating_mul(1u32 << exp).min(self.max)
    }

    /// Next delay: uniformly random in `[ceiling/2, ceiling]` ("equal jitter"),
    /// so reconnect storms spread out but never collapse to ~0.
    pub fn next_delay(&mut self) -> Duration {
        let c = self.ceiling();
        self.attempt = self.attempt.saturating_add(1);
        let lo = c / 2;
        let span = (c - lo).as_millis() as u64;
        lo + Duration::from_millis(if span == 0 {
            0
        } else {
            rand::thread_rng().gen_range(0..=span)
        })
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_and_caps() {
        let mut b = Backoff::default();
        let mut prev_ceiling = Duration::ZERO;
        for i in 0..30 {
            let c = b.ceiling();
            let d = b.next_delay();
            assert!(
                d <= c && d >= c / 2,
                "attempt {i}: {d:?} not in [{:?},{c:?}]",
                c / 2
            );
            assert!(c >= prev_ceiling);
            assert!(c <= Duration::from_secs(300));
            prev_ceiling = c;
        }
        assert_eq!(b.ceiling(), Duration::from_secs(300));
        b.reset();
        assert_eq!(b.ceiling(), Duration::from_secs(1));
        let d = b.next_delay();
        assert!(d >= Duration::from_millis(500) && d <= Duration::from_secs(1));
    }

    #[test]
    fn jitter_varies() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            let mut b = Backoff::default();
            for _ in 0..8 {
                b.next_delay();
            }
            seen.insert(b.next_delay());
        }
        assert!(seen.len() > 1);
    }
}
