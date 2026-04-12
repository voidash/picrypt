//! Platform-specific functionality: sleep detection and post-sleep recovery.
//!
//! Each platform module exports a `watch_for_sleep` function that spawns a
//! background task. When the system is about to sleep (or has just woken),
//! it sends a message on the provided channel so the daemon can dismount.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use tokio::sync::mpsc;

/// Events detected by platform-specific monitors.
#[derive(Debug)]
pub enum PlatformEvent {
    /// System is about to sleep — dismount immediately.
    SleepImminent,
    /// System just woke from sleep — verify server reachability.
    WokeFromSleep,
}

/// Start platform-specific sleep detection.
/// Returns a receiver that emits [`PlatformEvent`]s.
/// On unsupported platforms, returns a receiver that never fires.
pub fn start_sleep_monitor() -> mpsc::Receiver<PlatformEvent> {
    let (tx, rx) = mpsc::channel(8);

    #[cfg(target_os = "macos")]
    {
        macos::start(tx);
    }

    #[cfg(target_os = "linux")]
    {
        linux::start(tx);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _tx = tx; // Suppress unused warning.
        tracing::warn!("sleep detection not implemented for this platform");
    }

    rx
}

/// Detect if the system was recently asleep by checking for wall-clock jumps.
/// Call this periodically (e.g., every heartbeat). If the wall clock advanced
/// significantly more than the expected interval, the system was likely asleep.
pub struct WallClockMonitor {
    last_check: std::time::Instant,
    last_wall: chrono::DateTime<chrono::Utc>,
}

impl Default for WallClockMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl WallClockMonitor {
    pub fn new() -> Self {
        Self {
            last_check: std::time::Instant::now(),
            last_wall: chrono::Utc::now(),
        }
    }

    /// Check if the system was asleep. Returns the estimated sleep duration
    /// if a significant time jump was detected (> 2x expected interval).
    pub fn check(&mut self, expected_interval_secs: u64) -> Option<std::time::Duration> {
        let now_instant = std::time::Instant::now();
        let now_wall = chrono::Utc::now();

        let monotonic_elapsed = now_instant.duration_since(self.last_check);
        let wall_elapsed = (now_wall - self.last_wall)
            .to_std()
            .unwrap_or(std::time::Duration::ZERO);

        self.last_check = now_instant;
        self.last_wall = now_wall;

        // If wall clock advanced much more than monotonic clock,
        // the system was likely suspended.
        let threshold = std::time::Duration::from_secs(expected_interval_secs * 2);
        if wall_elapsed > threshold && wall_elapsed > monotonic_elapsed + threshold {
            let sleep_duration = wall_elapsed.saturating_sub(monotonic_elapsed);
            tracing::warn!(
                "detected possible system sleep: wall={:.1}s mono={:.1}s gap={:.1}s",
                wall_elapsed.as_secs_f64(),
                monotonic_elapsed.as_secs_f64(),
                sleep_duration.as_secs_f64()
            );
            Some(sleep_duration)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wall_clock_monitor_no_false_positive() {
        let mut monitor = WallClockMonitor::new();

        // Two sequential checks with a generous expected interval should NOT
        // report a sleep event — no actual wall-clock jump can happen here.
        let result1 = monitor.check(30);
        let result2 = monitor.check(30);

        assert!(
            result1.is_none(),
            "first check should not detect sleep, got: {result1:?}"
        );
        assert!(
            result2.is_none(),
            "second check should not detect sleep, got: {result2:?}"
        );
    }
}
