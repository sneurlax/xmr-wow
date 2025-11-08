//! Native platform implementations of abstractions.

use crate::abstractions::TimeProvider;
use std::time::{SystemTime, UNIX_EPOCH};
pub struct SystemTimeProvider;

impl SystemTimeProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SystemTimeProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeProvider for SystemTimeProvider {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| {
                // If system time is before UNIX epoch, return 0
                // This is safer than panicking and allows the system to continue
                std::time::Duration::from_secs(0)
            })
            .as_secs()
    }

    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| {
                // If system time is before UNIX epoch, return 0
                // This is safer than panicking and allows the system to continue
                std::time::Duration::from_secs(0)
            })
            .as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_time_provider() {
        let provider = SystemTimeProvider::new();
        let now = provider.now();
        let now_ms = provider.now_ms();

        assert!(now > 1_600_000_000);
        assert!(now < 2_000_000_000);
        assert!(now_ms > now * 1000);
        assert!(now_ms < (now + 1) * 1000);
    }

    #[test]
    fn test_system_time_provider_default() {
        let provider = SystemTimeProvider::default();
        let now = provider.now();
        assert!(now > 0);
    }

    #[test]
    fn test_system_time_provider_consistency() {
        let provider = SystemTimeProvider::new();
        let now1 = provider.now();
        let now2 = provider.now();

        // Second call should be equal or slightly later
        assert!(now2 >= now1);
        // Should be within 1 second
        assert!(now2 - now1 < 2);
    }

    #[test]
    fn test_system_time_provider_millisecond_precision() {
        let provider = SystemTimeProvider::new();
        let now_sec = provider.now();
        let now_ms = provider.now_ms();

        // Milliseconds should be roughly 1000x seconds
        let expected_ms = now_sec * 1000;
        // Allow 1 second of variance for test execution time
        assert!(now_ms >= expected_ms);
        assert!(now_ms <= expected_ms + 1000);
    }

    #[test]
    fn test_system_time_provider_multiple_instances() {
        let provider1 = SystemTimeProvider::new();
        let provider2 = SystemTimeProvider::new();

        let time1 = provider1.now();
        let time2 = provider2.now();

        // Both should return similar times (within 1 second)
        assert!((time1 as i64 - time2 as i64).abs() < 2);
    }
}
