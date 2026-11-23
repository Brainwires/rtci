//! Monotonic, Unix and NTP time.
//!
//! Protocol logic measures time with a monotonic [`Instant`](std::time::Instant), which cannot go
//! backwards but has no absolute meaning. RTCP timestamps need the opposite: wall-clock time in
//! NTP format. [`SystemInstant`](crate::time::SystemInstant) captures both once, so either can be derived from the other later
//! without re-reading a clock that may have been adjusted in between.
use std::ops::Add;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A monotonic [`Instant`] paired with the wall-clock time it was taken at.
///
/// Sans-I/O protocol code measures time with a monotonic [`Instant`], but RTCP timestamps
/// and NTP fields need wall-clock time. Capturing both once lets either be derived from the
/// other later without re-reading the (non-monotonic) system clock.
pub struct SystemInstant {
    instant: Instant,
    duration_since_unix_epoch: Duration,
}

impl SystemInstant {
    /// Captures the current monotonic instant together with the current wall-clock time.
    pub fn now(now: Instant) -> Self {
        Self {
            instant: now,
            duration_since_unix_epoch: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0)),
        }
    }

    /// The process's one wall-clock anchor, taken at the first call (with `now` as its
    /// monotonic half) and the same for every later caller.
    ///
    /// RTCP fields that compare NTP times written by different parts of an endpoint use it:
    /// RFC 8888 section 3.1 derives the report timestamp "from the same clock used to generate
    /// the NTP timestamp field in RTCP SR packets", and RFC 3550 section 6.4.1 has every
    /// sender report of a participant on one wallclock. Each taking its own
    /// [`now`](Self::now) at a different moment would pair a different wall-clock reading with
    /// each anchor instant: under a clock the caller drives (virtual time) the two differ by
    /// however far that clock ran ahead of the machine's.
    pub fn shared(now: Instant) -> Self {
        static SHARED: OnceLock<SystemInstant> = OnceLock::new();
        *SHARED.get_or_init(|| Self::now(now))
    }

    /// Pairs a monotonic instant with the wall-clock time the caller says it corresponds to.
    ///
    /// Reads no clock: for a time derived from another [`SystemInstant`] (an earlier or later
    /// instant on the same anchor) or carried by a protocol field (an RTCP sender report's NTP
    /// timestamp).
    pub fn at(instant: Instant, duration_since_unix_epoch: Duration) -> Self {
        Self {
            instant,
            duration_since_unix_epoch,
        }
    }

    /// Only used for deserialization
    pub fn from_epoch(duration_since_unix_epoch: Duration) -> Self {
        let system_now = SystemTime::now(); // Exemption: wall-clock is correct here to deserialization only
        let instant_now = Instant::now(); // Exemption: Instant-now is correct here to deserialization only

        let duration_since_approx = system_now
            .duration_since(UNIX_EPOCH + duration_since_unix_epoch)
            .unwrap_or_else(|_| Duration::from_secs(0));

        let instant = instant_now - duration_since_approx;

        Self {
            instant,
            duration_since_unix_epoch,
        }
    }

    /// Converts a Unix-epoch duration back into the monotonic [`Instant`] it corresponds to.
    pub fn instant(&self, duration_since_unix_epoch: Duration) -> Instant {
        self.instant + duration_since_unix_epoch - self.duration_since_unix_epoch
    }

    /// The wall-clock time, as a duration since the Unix epoch, captured at construction.
    pub fn duration_since_unix_epoch(&self) -> Duration {
        self.duration_since_unix_epoch
    }

    /// Converts the monotonic `now` into wall-clock time as a duration since the Unix epoch.
    /// An instant before the anchor's maps to as much before its wall-clock time (saturating
    /// at the Unix epoch).
    pub fn unix(&self, now: Instant) -> Duration {
        match now.checked_duration_since(self.instant) {
            Some(after) => after.add(self.duration_since_unix_epoch),
            None => self
                .duration_since_unix_epoch
                .saturating_sub(self.instant.duration_since(now)),
        }
    }

    /// Converts the monotonic `now` into a 64-bit NTP timestamp, as RTCP Sender Reports carry.
    pub fn ntp(&self, now: Instant) -> u64 {
        SystemInstant::unix2ntp(self.unix(now))
    }

    /// Converts a Unix-epoch duration into a 64-bit NTP timestamp.
    ///
    /// The result is seconds since the NTP epoch (1900-01-01) in the high 32 bits and a binary
    /// fraction of a second in the low 32.
    pub fn unix2ntp(duration_since_unix_epoch: Duration) -> u64 {
        let u = duration_since_unix_epoch.as_nanos() as u64;

        let mut s = u / 1_000_000_000;
        s += 0x83AA7E80; //offset in seconds between unix epoch and ntp epoch
        let mut f = u % 1_000_000_000;
        f <<= 32;
        f /= 1_000_000_000;
        s <<= 32;

        s | f
    }

    /// Converts a 64-bit NTP timestamp into a duration since the Unix epoch.
    ///
    /// The inverse of [`Self::unix2ntp`].
    pub fn ntp2unix(ntp: u64) -> Duration {
        let mut s = ntp >> 32;
        let mut f = ntp & 0xFFFFFFFF;
        f *= 1_000_000_000;
        f >>= 32;
        s -= 0x83AA7E80;
        let u = s * 1_000_000_000 + f;

        /*let duration_since_unix_epoch =*/
        Duration::new(u / 1_000_000_000, (u % 1_000_000_000) as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An instant before the anchor is as far before its wall-clock time; it used to stop at
    /// the anchor's.
    #[test]
    fn an_instant_before_the_anchor_maps_to_an_earlier_wall_clock_time() {
        let at = Instant::now() + Duration::from_secs(10);
        let anchor = SystemInstant::at(at, Duration::from_secs(1_000));
        assert_eq!(
            Duration::from_secs(997),
            anchor.unix(at - Duration::from_secs(3))
        );
        assert_eq!(
            Duration::from_secs(1_002),
            anchor.unix(at + Duration::from_secs(2))
        );
    }

    /// Every caller of `shared` gets the one anchor, whatever instant it passes.
    #[test]
    fn the_shared_anchor_is_one_for_every_caller() {
        let now = Instant::now();
        let first = SystemInstant::shared(now);
        let second = SystemInstant::shared(now + Duration::from_secs(60));
        assert_eq!(first, second);
        assert_eq!(first.ntp(now), second.ntp(now));
    }
}
