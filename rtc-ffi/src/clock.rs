//! Time across the boundary.
//!
//! The caller passes the time as monotonic nanoseconds (`uint64_t now_ns`) on an origin of its
//! own choosing: a virtual clock starting at 0, `CLOCK_MONOTONIC`, `performance.now() * 1e6`.
//! It must never go backwards for one peer connection. `Instant` is opaque, so the library maps
//! nanoseconds onto one process-wide anchor instant taken once (`anchor + now_ns`), and maps
//! the engine's deadlines back the same way; the conversion is exact both ways and reads no
//! clock after the anchor.
//!
//! The engine takes wall-clock time (NTP timestamps of RTCP sender reports, statistics
//! timestamps) from the system clock itself, paired with the caller's monotonic time
//! (`rtc_shared::time::SystemInstant`); no engine entry point takes a wall-clock reading, so
//! this interface has none either.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

fn anchor() -> Instant {
    static ANCHOR: OnceLock<Instant> = OnceLock::new();
    // The one clock read of the sans-I/O layer: an origin for the caller's nanoseconds.
    let anchor = ANCHOR.get_or_init(Instant::now);
    *anchor
}

/// The instant `now_ns` nanoseconds after the anchor.
pub fn instant(now_ns: u64) -> Instant {
    anchor() + Duration::from_nanos(now_ns)
}

/// Nanoseconds from the anchor to `at` (0 for an instant before it).
pub fn nanos(at: Instant) -> u64 {
    u64::try_from(at.saturating_duration_since(anchor()).as_nanos()).unwrap_or(u64::MAX)
}

/// The current time in the nanoseconds of [`instant`]: the driven layer's clock, which owns
/// its sockets and so reads the time like any driver.
#[cfg(feature = "driver")]
pub(crate) fn now_ns() -> u64 {
    nanos(Instant::now())
}
