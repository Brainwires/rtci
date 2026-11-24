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

/// Whether the NTP timestamp `ntp` falls where a positive leap second could make it
/// ambiguous: the last second of the last day of a month (UTC) or the second after it.
///
/// RFC 7164 section 5: "generating or using NTP timestamps during the entire last second of a
/// day on which a positive leap second has been scheduled SHOULD be avoided. Note that the
/// period to be avoided has a real-time duration of two seconds"; section 5.1: senders and
/// receivers "MAY assume that a positive leap second occurs at the end of the last day of
/// every month". On a clock that does not bear the leap second (this one counts seconds
/// uniformly) those two seconds read 23:59:59 and 00:00:00. Timestamps of the NTP era that
/// starts in 2036 are taken as such.
pub fn near_leap_second(ntp: u64) -> bool {
    const NTP_TO_UNIX: u64 = 0x83AA_7E80;
    const DAY: u64 = 86_400;
    let mut seconds = ntp >> 32;
    if seconds < NTP_TO_UNIX {
        // Era 1 (from 2036-02-07): the seconds field wrapped.
        seconds += 1 << 32;
    }
    let unix = seconds - NTP_TO_UNIX;
    let (day, second_of_day) = (unix / DAY, unix % DAY);
    match second_of_day {
        // 23:59:59 on the last day of a month: the next day is the first.
        86_399 => day_of_month(day + 1) == 1,
        // 00:00:00 on the first day of a month: where the leap second's real time falls.
        0 => day_of_month(day) == 1,
        _ => false,
    }
}

/// The day of the month (1 to 31) of the civil (proleptic Gregorian) date `days` days after
/// 1970-01-01 (H. Hinnant's `civil_from_days`).
fn day_of_month(days: u64) -> u64 {
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    day_of_year - (153 * month_index + 2) / 5 + 1
}

#[cfg(test)]
mod tests {

    /// The NTP timestamp of `unix` seconds (and `millis`) after the Unix epoch.
    fn ntp_at(unix: u64, millis: u64) -> u64 {
        SystemInstant::unix2ntp(Duration::from_millis(unix * 1000 + millis))
    }

    /// RFC 7164 sections 5 and 5.1: the last second of the last day of every month and the
    /// second after it, and nothing else; month lengths and leap years as the calendar has
    /// them.
    #[test]
    fn the_two_seconds_around_the_end_of_every_month_are_near_a_leap_second() {
        // 2016-12-31 23:59:59, a day that had one; 2026-11-30 and 2026-12-31 23:59:59.
        for unix in [1_483_228_799u64, 1_796_083_199, 1_798_761_599] {
            assert!(near_leap_second(ntp_at(unix, 0)), "{unix}");
            assert!(near_leap_second(ntp_at(unix, 999)), "{unix}");
            assert!(near_leap_second(ntp_at(unix + 1, 500)), "{unix} + 1");
            assert!(!near_leap_second(ntp_at(unix - 1, 999)), "{unix} - 1");
            assert!(!near_leap_second(ntp_at(unix + 2, 0)), "{unix} + 2");
        }
        // February: the 29th in a leap year, the 28th otherwise.
        assert!(near_leap_second(ntp_at(1_709_251_199, 0))); // 2024-02-29 23:59:59
        assert!(!near_leap_second(ntp_at(1_709_164_799, 0))); // 2024-02-28 23:59:59
        assert!(near_leap_second(ntp_at(1_740_787_199, 0))); // 2025-02-28 23:59:59
        // Mid-month, mid-day.
        assert!(!near_leap_second(ntp_at(1_795_521_600, 0))); // 2026-11-24 12:00:00
        // NTP era 1: 2036-02-29 23:59:59.
        assert!(near_leap_second(ntp_at(2_087_942_399, 0)));
    }
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
