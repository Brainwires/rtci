//! Datagram Packetization Layer Path MTU Discovery (DPLPMTUD, RFC 8899) for an association.
//!
//! RFC 8261 section 4 and RFC 8831 section 5: SCTP over DTLS discovers the path MTU without
//! ICMP. RFC 8899 section 6.2 is the method: a probe is an SCTP packet of exactly the size to
//! try, a HEARTBEAT chunk followed by a PAD chunk (RFC 4820) that fills it up, and the
//! HEARTBEAT ACK confirms that the size crosses the path. Probes carry no user data, so a lost
//! one costs nothing to repair; they are neither congestion nor flow controlled and do not
//! count against the path (RFC 8899 section 3, items 4, 7 and 8; section 6.2.1.2).
//!
//! This module is the state machine of RFC 8899 section 5.2 (DISABLED, BASE, SEARCHING,
//! SEARCH_COMPLETE, ERROR) in SCTP packet bytes: the sizes are what the association hands the
//! layer below, so the headers under SCTP (DTLS record, UDP, IP, TURN framing) are the
//! caller's to subtract from an IP-layer MTU. The association sends the probes, routes their
//! acknowledgements here and applies the PLPMTU this machine settles on.
//!
//! Black holes. SCTP is an acknowledged packetization layer, so it runs no
//! CONFIRMATION_TIMER in SEARCH_COMPLETE (section 6.2.3.3, a MUST NOT); a path that stops
//! carrying the current size shows as data that is not acknowledged. Two retransmission
//! timeouts in a row without the cumulative TSN moving, while the PLPMTU is above the base,
//! are taken as that indication (section 4.3, the third method): the PLPMTU falls back to
//! BASE_PLPMTU, which is confirmed, and the search starts again from there.

use std::time::{Duration, Instant};

/// Smallest step the search takes: probing for less is not worth a probe (RFC 8899 section
/// 5.3.2, "maximize the gain in PLPMTU from each search step").
const SEARCH_STEP: u32 = 16;

/// Retransmission timeouts in a row, without progress, that indicate a black hole.
pub(crate) const BLACK_HOLE_TIMEOUTS: u32 = 2;

/// The probe: an SCTP common header (12 bytes), a HEARTBEAT chunk with one Heartbeat Info
/// parameter of 20 bytes (4 + 4 + 20 = 28 bytes) and the PAD chunk's own header (4 bytes).
/// The smallest probe is this, with no padding at all.
pub(crate) const PROBE_OVERHEAD: u32 = 12 + 28 + 4;

/// The phase of the discovery (RFC 8899 section 5.2).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PathMtuState {
    /// Not started: the association is not established, or discovery is off.
    Disabled,
    /// Confirming that BASE_PLPMTU crosses the path.
    Base,
    /// Probing for a larger PLPMTU.
    Searching,
    /// The search is over; the PLPMTU stays until the raise timer or a black hole.
    SearchComplete,
    /// BASE_PLPMTU was not confirmed: the PLPMTU is MIN_PLPMTU and BASE_PLPMTU is probed
    /// until it is.
    Error,
}

/// Settings of the path MTU discovery (RFC 8899 sections 5.1.1 and 5.1.2), in SCTP packet
/// bytes (common header and chunks).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PathMtuDiscoveryConfig {
    max_path_mtu: u32,
    min_path_mtu: u32,
    probe_timeout: Duration,
    raise_interval: Duration,
    max_probes: u32,
}

impl Default for PathMtuDiscoveryConfig {
    /// MAX_PLPMTU 1452 (a 1500-byte IPv6 packet less the IPv6 and UDP headers; over DTLS the
    /// record overhead comes off too, and a transport that knows it says so with
    /// [`with_max_path_mtu`](Self::with_max_path_mtu)); MIN_PLPMTU the smallest packet that
    /// carries DATA; PROBE_TIMER 16 s (section 5.1.1: at least 1 s, and it "SHOULD be larger
    /// than 15 seconds"); PMTU_RAISE_TIMER 600 s; MAX_PROBES 3.
    fn default() -> Self {
        Self {
            max_path_mtu: 1452,
            min_path_mtu: crate::config::MIN_DATA_PACKET_MTU,
            probe_timeout: Duration::from_secs(16),
            raise_interval: Duration::from_secs(600),
            max_probes: 3,
        }
    }
}

impl PathMtuDiscoveryConfig {
    /// MAX_PLPMTU: the largest SCTP packet the search tries (the local interface MTU less
    /// what lies under SCTP).
    pub fn with_max_path_mtu(mut self, value: u32) -> Self {
        self.max_path_mtu = value;
        self
    }

    /// MAX_PLPMTU, see [`with_max_path_mtu`](Self::with_max_path_mtu).
    pub fn max_path_mtu(&self) -> u32 {
        self.max_path_mtu
    }

    /// MIN_PLPMTU: the PLPMTU used while BASE_PLPMTU is not confirmed (the ERROR state).
    /// Raised to the smallest packet that carries DATA.
    pub fn with_min_path_mtu(mut self, value: u32) -> Self {
        self.min_path_mtu = value.max(crate::config::MIN_DATA_PACKET_MTU);
        self
    }

    /// MIN_PLPMTU, see [`with_min_path_mtu`](Self::with_min_path_mtu).
    pub fn min_path_mtu(&self) -> u32 {
        self.min_path_mtu
    }

    /// PROBE_TIMER: how long a probe waits for its acknowledgement. Raised to 1 s (RFC 8899
    /// section 5.1.1: it "MUST NOT be smaller than 1 second").
    pub fn with_probe_timeout(mut self, value: Duration) -> Self {
        self.probe_timeout = value.max(Duration::from_secs(1));
        self
    }

    /// PROBE_TIMER, see [`with_probe_timeout`](Self::with_probe_timeout).
    pub fn probe_timeout(&self) -> Duration {
        self.probe_timeout
    }

    /// PMTU_RAISE_TIMER: how long a completed search is trusted before the next one.
    pub fn with_raise_interval(mut self, value: Duration) -> Self {
        self.raise_interval = value;
        self
    }

    /// PMTU_RAISE_TIMER, see [`with_raise_interval`](Self::with_raise_interval).
    pub fn raise_interval(&self) -> Duration {
        self.raise_interval
    }

    /// MAX_PROBES: unacknowledged probes in a row, of any size, after which a phase ends.
    /// At least 1.
    pub fn with_max_probes(mut self, value: u32) -> Self {
        self.max_probes = value.max(1);
        self
    }

    /// MAX_PROBES, see [`with_max_probes`](Self::with_max_probes).
    pub fn max_probes(&self) -> u32 {
        self.max_probes
    }
}

/// The discovery of one association's path.
#[derive(Debug, Clone)]
pub(crate) struct PathMtuDiscovery {
    config: PathMtuDiscoveryConfig,
    state: PathMtuState,
    /// BASE_PLPMTU: the size the path is assumed to carry (RFC 8831 section 5's initial MTU).
    base: u32,
    /// PLPMTU: the largest size confirmed (or assumed, in BASE and ERROR).
    plpmtu: u32,
    /// PROBED_SIZE.
    probed_size: u32,
    /// PROBE_COUNT: probes in a row that went unacknowledged.
    probe_count: u32,
    /// The smallest size this search found not to cross the path; above MAX_PLPMTU while
    /// none failed.
    failed_size: u32,
    /// A probe is due.
    send_due: bool,
    /// The probe in flight: its nonce, size and deadline.
    outstanding: Option<(u64, u32, Instant)>,
    /// When the next search starts (PMTU_RAISE_TIMER), in SEARCH_COMPLETE.
    raise_at: Option<Instant>,
    /// Retransmission timeouts in a row without progress (the black hole indication).
    stalled_timeouts: u32,
}

impl PathMtuDiscovery {
    pub(crate) fn new(config: PathMtuDiscoveryConfig, base: u32) -> Self {
        Self {
            config,
            state: PathMtuState::Disabled,
            base,
            plpmtu: base,
            probed_size: base,
            probe_count: 0,
            failed_size: u32::MAX,
            send_due: false,
            outstanding: None,
            raise_at: None,
            stalled_timeouts: 0,
        }
    }

    pub(crate) fn state(&self) -> PathMtuState {
        self.state
    }

    pub(crate) fn config(&self) -> &PathMtuDiscoveryConfig {
        &self.config
    }

    /// BASE_PLPMTU.
    pub(crate) fn base(&self) -> u32 {
        self.base
    }

    /// The largest size the search tries: MAX_PLPMTU, never below BASE_PLPMTU.
    fn max(&self) -> u32 {
        round_down(self.config.max_path_mtu).max(self.base)
    }

    /// Starts over from DISABLED with `base` as BASE_PLPMTU (a new path, or a new base the
    /// transport learned). The next [`start`](Self::start) enters BASE.
    pub(crate) fn reset(&mut self, base: u32) {
        *self = Self::new(self.config, base);
    }

    /// Sets MAX_PLPMTU. A PLPMTU above it comes down to it; the search goes on below it.
    /// Returns the new PLPMTU when it changed.
    pub(crate) fn set_max_path_mtu(&mut self, max: u32) -> Option<u32> {
        self.config.max_path_mtu = max;
        if self.state == PathMtuState::SearchComplete && self.plpmtu < self.max() {
            // A larger MAX_PLPMTU is worth a search now rather than at the raise timer.
            self.enter_searching();
        }
        if self.plpmtu > self.max() {
            self.plpmtu = self.max();
            return Some(self.plpmtu);
        }
        None
    }

    /// The association is established (RFC 8899 section 6.2.3.1: "A sender can enter the
    /// BASE state as soon as SCTP connectivity has been confirmed"). Nothing in another state.
    pub(crate) fn start(&mut self) {
        if self.state == PathMtuState::Disabled {
            self.enter_base();
        }
    }

    fn enter_base(&mut self) {
        self.state = PathMtuState::Base;
        self.plpmtu = self.base;
        self.probed_size = self.base;
        self.probe_count = 0;
        self.failed_size = u32::MAX;
        self.outstanding = None;
        self.raise_at = None;
        self.send_due = true;
    }

    fn enter_searching(&mut self) {
        self.state = PathMtuState::Searching;
        self.probe_count = 0;
        self.failed_size = u32::MAX;
        self.outstanding = None;
        self.raise_at = None;
        match self.next_size() {
            Some(size) => {
                self.probed_size = size;
                self.send_due = true;
            }
            None => self.enter_search_complete_without_timer(),
        }
    }

    fn enter_search_complete_without_timer(&mut self) {
        self.state = PathMtuState::SearchComplete;
        self.outstanding = None;
        self.send_due = false;
    }

    fn enter_search_complete(&mut self, now: Instant) {
        self.enter_search_complete_without_timer();
        self.raise_at = Some(now + self.config.raise_interval);
    }

    /// The next size to probe in SEARCHING: MAX_PLPMTU first (the largest gain, section
    /// 5.3.2), then halfway between the PLPMTU and the smallest size that failed. `None` when
    /// what is left is less than a step.
    fn next_size(&self) -> Option<u32> {
        let max = self.max();
        if self.plpmtu >= max {
            return None;
        }
        let high = self.failed_size.min(max.saturating_add(4));
        if high <= self.plpmtu.saturating_add(SEARCH_STEP) {
            return None;
        }
        if self.failed_size > max {
            return Some(max);
        }
        let mid = round_down(self.plpmtu + (high - self.plpmtu) / 2);
        (mid > self.plpmtu).then_some(mid)
    }

    /// The size of the probe to send now, if one is due. The caller sends it and reports it
    /// with [`probe_sent`](Self::probe_sent).
    pub(crate) fn poll_probe(&self) -> Option<u32> {
        if !self.send_due || self.outstanding.is_some() {
            return None;
        }
        match self.state {
            PathMtuState::Base | PathMtuState::Searching | PathMtuState::Error => {
                Some(self.probed_size.max(PROBE_OVERHEAD))
            }
            PathMtuState::Disabled | PathMtuState::SearchComplete => None,
        }
    }

    pub(crate) fn probe_sent(&mut self, nonce: u64, size: u32, now: Instant) {
        self.send_due = false;
        self.outstanding = Some((nonce, size, now + self.config.probe_timeout));
    }

    /// The probe whose HEARTBEAT ACK carried `nonce` crossed the path. Returns the new
    /// PLPMTU when it changed; `None` for a nonce that is not the outstanding probe's (a late
    /// or duplicated acknowledgement, RFC 8899 section 3: robust to delay and duplication).
    pub(crate) fn on_probe_ack(&mut self, nonce: u64, now: Instant) -> Option<u32> {
        let (expected, size, _) = self.outstanding?;
        if expected != nonce {
            return None;
        }
        self.outstanding = None;
        self.probe_count = 0;
        let before = self.plpmtu;
        match self.state {
            PathMtuState::Base | PathMtuState::Error => {
                self.plpmtu = size;
                self.enter_searching();
            }
            PathMtuState::Searching => {
                self.plpmtu = size;
                match self.next_size() {
                    Some(next) => {
                        self.probed_size = next;
                        self.send_due = true;
                    }
                    None => self.enter_search_complete(now),
                }
            }
            PathMtuState::Disabled | PathMtuState::SearchComplete => {}
        }
        (self.plpmtu != before).then_some(self.plpmtu)
    }

    /// When [`on_timeout`](Self::on_timeout) is next due.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        match (self.outstanding.map(|(_, _, at)| at), self.raise_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Runs the PROBE_TIMER and the PMTU_RAISE_TIMER. Returns the new PLPMTU when it changed.
    pub(crate) fn on_timeout(&mut self, now: Instant) -> Option<u32> {
        let before = self.plpmtu;
        if let Some((_, size, at)) = self.outstanding
            && now >= at
        {
            // The probe failed: it is discounted, not taken as congestion or as a path
            // failure (section 3 item 7, section 6.2.1.2).
            self.outstanding = None;
            self.probe_count += 1;
            let exhausted = self.probe_count >= self.config.max_probes;
            match self.state {
                PathMtuState::Base if exhausted => {
                    // BASE_PLPMTU does not cross the path: MIN_PLPMTU until it does.
                    self.state = PathMtuState::Error;
                    self.plpmtu = self.config.min_path_mtu.min(self.base);
                    self.probe_count = 0;
                    self.send_due = true;
                }
                PathMtuState::Base | PathMtuState::Error => self.send_due = true,
                PathMtuState::Searching => {
                    self.failed_size = self.failed_size.min(size);
                    if exhausted {
                        self.enter_search_complete(now);
                    } else {
                        match self.next_size() {
                            Some(next) => {
                                self.probed_size = next;
                                self.send_due = true;
                            }
                            None => self.enter_search_complete(now),
                        }
                    }
                }
                PathMtuState::Disabled | PathMtuState::SearchComplete => {}
            }
        }
        if self.state == PathMtuState::SearchComplete && self.raise_at.is_some_and(|at| now >= at) {
            self.enter_searching();
        }
        (self.plpmtu != before).then_some(self.plpmtu)
    }

    /// A retransmission timeout fired with nothing acknowledged since the last one. Returns
    /// the new PLPMTU when this is taken as a black hole (section 4.3): the path no longer
    /// carries the PLPMTU, which falls back to BASE_PLPMTU, to be confirmed by a probe.
    pub(crate) fn on_retransmission_timeout(&mut self) -> Option<u32> {
        if !matches!(
            self.state,
            PathMtuState::Searching | PathMtuState::SearchComplete
        ) || self.plpmtu <= self.base
        {
            self.stalled_timeouts = 0;
            return None;
        }
        self.stalled_timeouts += 1;
        if self.stalled_timeouts < BLACK_HOLE_TIMEOUTS {
            return None;
        }
        self.stalled_timeouts = 0;
        self.enter_base();
        Some(self.plpmtu)
    }

    /// The cumulative TSN moved: data crosses the path at the PLPMTU.
    pub(crate) fn on_progress(&mut self) {
        self.stalled_timeouts = 0;
    }
}

/// Probes are a whole number of 4-byte words (the PAD chunk then needs no padding of its own).
fn round_down(size: u32) -> u32 {
    size & !3
}

#[cfg(test)]
mod test {
    use super::*;

    fn acked(d: &mut PathMtuDiscovery, now: Instant) -> Option<u32> {
        let size = d.poll_probe()?;
        d.probe_sent(7, size, now);
        d.on_probe_ack(7, now);
        Some(size)
    }

    /// The search climbs from BASE_PLPMTU to the largest size the path takes, by halves,
    /// with MAX_PLPMTU tried first; MAX_PROBES failures in a row end it.
    #[test]
    fn the_search_finds_the_largest_size_below_the_first_failure() {
        let now = Instant::now();
        let config = PathMtuDiscoveryConfig::default().with_max_path_mtu(1400);
        let mut d = PathMtuDiscovery::new(config, 1100);
        assert_eq!(d.poll_probe(), None, "nothing before the association is up");
        d.start();
        assert_eq!(acked(&mut d, now), Some(1100), "BASE_PLPMTU first");
        assert_eq!(d.state(), PathMtuState::Searching);
        let path = 1300;
        let mut t = now;
        let mut probes = Vec::new();
        while let Some(size) = d.poll_probe() {
            probes.push(size);
            d.probe_sent(size as u64, size, t);
            if size <= path {
                d.on_probe_ack(size as u64, t);
            } else {
                t += config.probe_timeout();
                d.on_timeout(t);
            }
        }
        assert_eq!(probes[0], 1400, "MAX_PLPMTU first: {probes:?}");
        assert_eq!(d.state(), PathMtuState::SearchComplete, "{probes:?}");
        assert!(
            d.plpmtu <= path && d.plpmtu > path - SEARCH_STEP,
            "{} for a path of {path}: {probes:?}",
            d.plpmtu
        );
    }
}
