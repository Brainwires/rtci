//! ECN initiation and failure detection for an RTP stream whose feedback is RFC 8888.
//!
//! RFC 8888 section 7: "When using ECN with RTP, the guidelines in Section 7.2 of [RFC6679]
//! MUST be followed to initiate the use of ECN in an RTP session", section 7.3's ongoing use
//! likewise, and "the guidance in Section 7.4 of [RFC6679] related to detecting failures MUST
//! be followed, with the exception that the necessary information is retrieved from the RTCP
//! Congestion Control Feedback Packets".
//!
//! [`EcnValidation`] is that sender-side procedure for one stream, sans-I/O: it is told of each
//! packet sent ([`EcnValidation::on_send`], which answers whether the packet goes out ECT) and
//! of each RFC 8888 report about one ([`EcnValidation::on_report`]).
//!
//! * **Initiation** (RFC 6679 section 7.2.1, the in-band method every implementation MUST
//!   have): "an RTP sender SHALL mark a small fraction of its RTP traffic as ECT", "a minimum
//!   of two packets with ECT markings per RTCP reporting interval" is RECOMMENDED, and it
//!   "SHOULD NOT mark all RTP packets". Here one packet in [`PROBE_SPACING`], and one at least
//!   every [`PROBE_INTERVAL`], never two in a row. On a unicast transport the initiation "MAY
//!   [be treated] as provisionally successful if it receives [a report] indicating successful
//!   receipt of the ECT-marked packets, with no negative indications": [`CONFIRMATIONS`]
//!   probes reported received ECT (or CE) and none reported Not-ECT. It "is considered to have
//!   failed" when the feedback shows the receiver "should have received multiple (>3)
//!   ECT-marked RTP packets" and none arrived marked: here more than three probes reported
//!   lost while none was reported received, or a probe reported received Not-ECT.
//! * **Ongoing use** (section 7.3.1): after success the sender "SHOULD mark all the RTP data
//!   packets it sends as ECT".
//! * **Failures** (section 7.4): a path that clears the ECN field ("the ratio [...] has become
//!   all not-ECT, or has substantially changed towards not-ECT", section 7.4.2) stops the
//!   marking: more than a quarter of a window of [`WINDOW`] reported ECT packets arrived
//!   Not-ECT. "A sender that detects high packet loss rates for ECT-marked packets SHOULD
//!   immediately switch to sending packets as not-ECT to determine if the losses are
//!   potentially due to the ECT markings. If the losses disappear when the ECT-marking is
//!   discontinued, the RTP sender should go back to initiation procedures": half a window lost
//!   switches to Not-ECT for a window; if the loss falls under a quarter the stream initiates
//!   again, else (the loss is the path's, not ECN's) it resumes marking. After a failed
//!   initiation the sender "periodically [retries] the ECN initiation" (the first option of
//!   section 7.4.1) every [`DEFAULT_RETRY_AFTER`], and "if multiple initiations have been successful, but
//!   the following full usage of ECN has resulted in the fallback procedures, then disabling
//!   of the ECN support is RECOMMENDED": the second such fallback ends ECN for the stream.
//!
//! RTCP is never marked (section 7.2: "SHALL NOT ECT mark their RTCP traffic"); that is the
//! caller's part, as is choosing the codepoint (ECT(1) for L4S, RFC 9331).

use rtcp::transport_feedbacks::cc_feedback_report::Ecn;
use rtcp::transport_feedbacks::ecn_feedback::EcnCounters;
use std::time::{Duration, Instant};

/// During initiation one packet in this many is a probe sent ECT.
pub const PROBE_SPACING: u32 = 10;
/// During initiation a probe is sent at least this often (given an unmarked packet since the
/// last one): two per RTCP reporting interval at the shortest regular interval RFC 3550
/// section 6.2 allows a reduced-minimum sender (360 / session kbit/s seconds) is met for any
/// session above 720 kbit/s by the spacing, and below by this.
pub const PROBE_INTERVAL: Duration = Duration::from_millis(500);
/// Probes reported received with an ECN-capable marking that make the initiation succeed.
pub const CONFIRMATIONS: u32 = 2;
/// Probes reported lost, none received, that make the initiation fail (RFC 6679 section 7.2.1:
/// "multiple (>3)").
pub const PROBES_LOST_TO_FAIL: u32 = 4;
/// Reported packets the failure checks of ongoing use are made over.
pub const WINDOW: u32 = 32;
/// How long after a failed initiation the next one starts (RFC 6679 section 7.4.1 option 1).
pub const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(60);
/// Fallbacks from ongoing use, each confirmed as ECN's doing, after which ECN stays off.
pub const FALLBACKS_TO_DISABLE: u32 = 2;

/// Sent packets remembered, by sequence number, to match reports with how each was sent.
const HISTORY: usize = 2048;

/// Where a stream is in RFC 6679's procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnState {
    /// Section 7.2.1: a fraction of the packets are probes sent ECT.
    Initiating,
    /// Section 7.3.1: every packet is sent ECT.
    Active,
    /// Section 7.4.1: ECT-marked packets were lost at a high rate; packets go out Not-ECT to
    /// see whether the loss goes with the marking.
    Fallback,
    /// The path does not carry ECN; nothing is marked until `retry_at`.
    Failed {
        /// When the next initiation starts.
        retry_at: Instant,
    },
    /// ECN is off for the stream for good (section 7.4.1).
    Disabled,
}

/// How a stream starts using ECN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EcnInitiation {
    /// RFC 6679 section 7.2.1: probes, then every packet once feedback confirmed them (the
    /// method every implementation MUST have).
    #[default]
    RtpAndRtcp,
    /// RFC 6679 section 7.2.3, leap of faith: every packet is sent ECT from the first, as
    /// browsers that implement L4S do. Failure detection (section 7.4) still applies. The RFC
    /// allows it only for sessions that accept its limitations (the first packets may be lost
    /// on a path that drops ECT traffic).
    LeapOfFaith,
}

#[derive(Debug, Clone, Copy, Default)]
struct Sent {
    sequence_number: u16,
    /// Whether this slot describes a packet at all.
    known: bool,
    marked: bool,
    /// Reported so far: received (true), lost (false), not yet (`None`).
    reported: Option<bool>,
}

/// Counts over one window of reported packets.
#[derive(Debug, Clone, Copy, Default)]
struct Window {
    reported: u32,
    lost: u32,
    bleached: u32,
}

/// RFC 6679 sections 7.2-7.4 for one RTP stream, fed from RFC 8888 reports. See the module
/// documentation.
#[derive(Debug, Clone)]
pub struct EcnValidation {
    state: EcnState,
    retry_after: Duration,
    since_probe: u32,
    last_probe: Option<Instant>,
    history: Box<[Sent]>,
    probes_confirmed: u32,
    probes_lost: u32,
    window: Window,
    /// The loss of the window that sent the stream into [`EcnState::Fallback`].
    fallback_from: u32,
    fallbacks: u32,
    /// The last RFC 6679 counters reported, with the extended highest sequence number they
    /// relate to ([`EcnValidation::on_counters`]).
    last_counters: Option<(u32, EcnCounters)>,
}

impl Default for EcnValidation {
    fn default() -> Self {
        Self::new(EcnInitiation::default())
    }
}

impl EcnValidation {
    /// A stream about to send its first packet with ECN negotiated.
    pub fn new(initiation: EcnInitiation) -> Self {
        Self {
            state: match initiation {
                EcnInitiation::RtpAndRtcp => EcnState::Initiating,
                EcnInitiation::LeapOfFaith => EcnState::Active,
            },
            retry_after: DEFAULT_RETRY_AFTER,
            since_probe: PROBE_SPACING,
            last_probe: None,
            history: vec![Sent::default(); HISTORY].into_boxed_slice(),
            probes_confirmed: 0,
            probes_lost: 0,
            window: Window::default(),
            fallback_from: 0,
            fallbacks: 0,
            last_counters: None,
        }
    }

    /// How long after a failed initiation the next one starts ([`DEFAULT_RETRY_AFTER`]).
    pub fn with_retry_after(mut self, retry_after: Duration) -> Self {
        self.retry_after = retry_after;
        self
    }

    /// Where the stream is in the procedure.
    pub fn state(&self) -> EcnState {
        self.state
    }

    /// Whether a packet of the stream that is not one of its own numbered packets (an RTX
    /// retransmission, say) goes out ECT: only in ongoing use, so probes are the stream's own
    /// packets, whose reports name them.
    pub fn marks_all(&self) -> bool {
        self.state == EcnState::Active
    }

    /// Whether the packet `sequence_number` was sent ECT, as far as the history still knows.
    pub fn was_marked(&self, sequence_number: u16) -> bool {
        let slot = &self.history[usize::from(sequence_number) % HISTORY];
        slot.known && slot.sequence_number == sequence_number && slot.marked
    }

    /// A packet of the stream is sent at `now`: whether it goes out ECT.
    pub fn on_send(&mut self, now: Instant, sequence_number: u16) -> bool {
        if let EcnState::Failed { retry_at } = self.state
            && now >= retry_at
        {
            self.initiate();
        }
        let marked = match self.state {
            EcnState::Initiating => {
                let due = self.since_probe + 1 >= PROBE_SPACING
                    || (self.since_probe >= 1
                        && self
                            .last_probe
                            .is_none_or(|at| now.saturating_duration_since(at) >= PROBE_INTERVAL));
                if due {
                    self.since_probe = 0;
                    self.last_probe = Some(now);
                } else {
                    self.since_probe += 1;
                }
                due
            }
            EcnState::Active => true,
            EcnState::Fallback | EcnState::Failed { .. } | EcnState::Disabled => false,
        };
        self.history[usize::from(sequence_number) % HISTORY] = Sent {
            sequence_number,
            known: true,
            marked,
            reported: None,
        };
        marked
    }

    /// An RFC 8888 report about the packet `sequence_number` arrived at `now`: whether it was
    /// received, and if so the ECN field it arrived with.
    pub fn on_report(&mut self, now: Instant, sequence_number: u16, received: bool, ecn: Ecn) {
        let slot = &mut self.history[usize::from(sequence_number) % HISTORY];
        if !slot.known || slot.sequence_number != sequence_number {
            return;
        }
        // Each packet counts once; a loss reported and then undone by a later report (the
        // packet was late) is taken back.
        let undo_loss = match slot.reported {
            Some(true) => return,
            Some(false) if !received => return,
            Some(false) => true,
            None => false,
        };
        slot.reported = Some(received);
        let marked = slot.marked;
        let ecn_capable = matches!(ecn, Ecn::Ect0 | Ecn::Ect1 | Ecn::Ce);

        match self.state {
            EcnState::Initiating if marked => {
                if undo_loss {
                    self.probes_lost = self.probes_lost.saturating_sub(1);
                }
                if !received {
                    self.probes_lost += 1;
                } else if ecn_capable {
                    self.probes_confirmed += 1;
                } else {
                    // A negative indication: the path cleared the ECN field.
                    self.fail(now, "an ECT probe arrived Not-ECT");
                    return;
                }
                if self.probes_confirmed == 0 && self.probes_lost >= PROBES_LOST_TO_FAIL {
                    self.fail(now, "no ECT probe arrived");
                } else if self.probes_confirmed >= CONFIRMATIONS {
                    self.state = EcnState::Active;
                    self.window = Window::default();
                }
            }
            EcnState::Active if marked => {
                self.count(undo_loss, received, !ecn_capable);
                if self.window.bleached * 4 > WINDOW {
                    self.fail(now, "the path clears the ECN field");
                } else if self.window.lost * 2 >= WINDOW {
                    log::debug!("ECN: high loss of ECT packets; sending Not-ECT to compare");
                    self.state = EcnState::Fallback;
                    self.fallback_from = self.window.lost;
                    self.window = Window::default();
                } else if self.window.reported >= WINDOW {
                    self.window = Window::default();
                }
            }
            EcnState::Fallback if !marked => {
                self.count(undo_loss, received, false);
                if self.window.reported >= WINDOW {
                    if self.window.lost * 4 < WINDOW && self.window.lost * 2 < self.fallback_from {
                        // The loss went with the marking.
                        self.fallbacks += 1;
                        if self.fallbacks >= FALLBACKS_TO_DISABLE {
                            log::warn!("ECN: ECT packets were lost again; ECN off for the stream");
                            self.state = EcnState::Disabled;
                        } else {
                            log::warn!("ECN: ECT packets were lost; initiating again");
                            self.initiate();
                        }
                    } else {
                        // Not-ECT packets were lost as much: the path's loss, not ECN's.
                        self.state = EcnState::Active;
                        self.window = Window::default();
                    }
                }
            }
            _ => {}
        }
    }

    /// An RFC 6679 report about the stream arrived at `now`: the receiver's cumulative ECN
    /// counters (an RTCP ECN Feedback packet, section 5.1, or an XR ECN Summary Report,
    /// section 5.2) and the extended highest sequence number they relate to (the feedback
    /// packet's, or the reception report's in the same compound packet). The procedure is the
    /// one [`on_report`](Self::on_report) runs, on what changed since the last report: the
    /// packets sent up to the new highest sequence number, how many went out ECT, and how many
    /// the receiver counted ECT or CE, not-ECT, lost and duplicated (section 7.4.2).
    ///
    /// * Initiating: ECT or CE counts confirm probes; not-ECT counts beyond the unmarked
    ///   packets sent (and the duplicates) are a negative indication; more than three probes
    ///   sent with no ECT counted is a failure (section 7.2.1).
    /// * Ongoing use: each packet sent ECT is reported; the not-ECT count beyond duplicates is
    ///   bleaching, the lost count is loss; the thresholds are those of per-packet reports.
    pub fn on_counters(&mut self, now: Instant, extended_highest: u32, counters: EcnCounters) {
        let (previous_highest, previous) = match self.last_counters {
            Some(last) => last,
            None => (
                extended_highest.wrapping_sub(self.known_since(extended_highest)),
                EcnCounters::default(),
            ),
        };
        // An older report than the last one says nothing new.
        let span = extended_highest.wrapping_sub(previous_highest);
        if span > 0x8000_0000 {
            return;
        }
        self.last_counters = Some((extended_highest, counters));
        if span == 0 && counters == previous {
            return;
        }
        let ect = u64::from(counters.ect0.wrapping_sub(previous.ect0))
            + u64::from(counters.ect1.wrapping_sub(previous.ect1))
            + u64::from(counters.ce.wrapping_sub(previous.ce));
        let not_ect = u64::from(counters.not_ect.wrapping_sub(previous.not_ect));
        let duplicates = u64::from(counters.duplicates.wrapping_sub(previous.duplicates));
        // The loss counter may fall (late packets) between reports.
        let lost = i64::from(counters.lost.wrapping_sub(previous.lost) as i16).max(0) as u64;

        // What went out in (previous_highest, extended_highest], as far as the history knows.
        let (mut marked, mut unmarked) = (0u64, 0u64);
        let first = previous_highest.wrapping_add(1);
        for offset in 0..span.min(HISTORY as u32) {
            let sequence_number = first.wrapping_add(offset) as u16;
            let slot = &self.history[usize::from(sequence_number) % HISTORY];
            if slot.known && slot.sequence_number == sequence_number {
                if slot.marked {
                    marked += 1;
                } else {
                    unmarked += 1;
                }
            }
        }
        let bleached = not_ect.saturating_sub(unmarked + duplicates);

        match self.state {
            EcnState::Initiating => {
                if bleached > 0 && marked > 0 {
                    self.fail(now, "ECT probes were counted Not-ECT");
                    return;
                }
                self.probes_confirmed += ect.min(u64::from(u32::MAX)) as u32;
                if ect == 0 {
                    self.probes_lost += marked as u32;
                }
                if self.probes_confirmed == 0 && self.probes_lost >= PROBES_LOST_TO_FAIL {
                    self.fail(now, "no ECT probe arrived");
                } else if self.probes_confirmed >= CONFIRMATIONS && bleached == 0 {
                    self.state = EcnState::Active;
                    self.window = Window::default();
                }
            }
            EcnState::Active => {
                self.window.reported += marked as u32;
                self.window.lost += lost.min(marked) as u32;
                self.window.bleached += bleached.min(marked) as u32;
                if self.window.bleached * 4 > WINDOW {
                    self.fail(now, "the path clears the ECN field");
                } else if self.window.lost * 2 >= WINDOW {
                    log::debug!("ECN: high loss of ECT packets; sending Not-ECT to compare");
                    self.state = EcnState::Fallback;
                    self.fallback_from = self.window.lost;
                    self.window = Window::default();
                } else if self.window.reported >= WINDOW {
                    self.window = Window::default();
                }
            }
            EcnState::Fallback => {
                self.window.reported += unmarked as u32;
                self.window.lost += lost.min(unmarked) as u32;
                if self.window.reported >= WINDOW {
                    if self.window.lost * 4 < WINDOW && self.window.lost * 2 < self.fallback_from {
                        self.fallbacks += 1;
                        if self.fallbacks >= FALLBACKS_TO_DISABLE {
                            log::warn!("ECN: ECT packets were lost again; ECN off for the stream");
                            self.state = EcnState::Disabled;
                        } else {
                            log::warn!("ECN: ECT packets were lost; initiating again");
                            self.initiate();
                        }
                    } else {
                        self.state = EcnState::Active;
                        self.window = Window::default();
                    }
                }
            }
            EcnState::Failed { .. } | EcnState::Disabled => {}
        }
    }

    /// How many sequence numbers before `extended_highest` the history holds sent packets
    /// for: the span the first RFC 6679 report covers.
    fn known_since(&self, extended_highest: u32) -> u32 {
        let mut span = 0u32;
        while span < HISTORY as u32 {
            let sequence_number = extended_highest.wrapping_sub(span) as u16;
            let slot = &self.history[usize::from(sequence_number) % HISTORY];
            if !(slot.known && slot.sequence_number == sequence_number) {
                break;
            }
            span += 1;
        }
        span
    }

    fn count(&mut self, undo_loss: bool, received: bool, bleached: bool) {
        if undo_loss {
            self.window.lost = self.window.lost.saturating_sub(1);
        } else {
            self.window.reported += 1;
        }
        if !received {
            self.window.lost += 1;
        } else if bleached {
            self.window.bleached += 1;
        }
    }

    fn initiate(&mut self) {
        self.state = EcnState::Initiating;
        self.since_probe = PROBE_SPACING;
        self.last_probe = None;
        self.probes_confirmed = 0;
        self.probes_lost = 0;
        self.window = Window::default();
    }

    fn fail(&mut self, now: Instant, why: &str) {
        // RFC 6679 section 7.2.1: "they should log these to enable follow up".
        log::warn!("ECN: {why}; packets go out Not-ECT");
        self.state = EcnState::Failed {
            retry_at: now + self.retry_after,
        };
        self.window = Window::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6679 counters for `marked` probes and the unmarked rest of `first..=last`, as a
    /// receiver on a path that `ect_arrives` (or clears the field) counts them.
    fn counters_for(
        sent: &[u16],
        marked: &[u16],
        ect_arrives: bool,
        lost: u16,
        base: EcnCounters,
    ) -> EcnCounters {
        let marked_count = marked.len() as u32;
        let unmarked = (sent.len() - marked.len()) as u16;
        let mut c = base;
        if ect_arrives {
            c.ect1 += marked_count - u32::from(lost.min(marked_count as u16));
            c.not_ect += unmarked;
        } else {
            c.not_ect += unmarked + marked_count as u16 - lost;
        }
        c.lost += lost;
        c
    }

    /// RFC 6679 7.2.1 with the counters of section 5: probes counted ECT by the receiver's
    /// ECN Feedback / XR ECN Summary Reports make the initiation succeed, and every packet is
    /// then sent ECT (section 7.3.1).
    #[test]
    fn counted_ect_probes_complete_the_initiation() {
        let mut v = EcnValidation::default();
        let mut at = Instant::now();
        let sent: Vec<u16> = (0..40).collect();
        let marked = send(&mut v, &mut at, 0, 40);
        assert!(
            marked.len() >= 2 && marked.len() < 40,
            "probes only: {marked:?}"
        );
        let c = counters_for(&sent, &marked, true, 0, EcnCounters::default());
        v.on_counters(at, 39, c);
        assert_eq!(v.state(), EcnState::Active);
        assert_eq!(
            send(&mut v, &mut at, 40, 10).len(),
            10,
            "all marked once active"
        );
    }

    /// Section 7.2.1: a path that clears the field (probes counted not-ECT) fails the
    /// initiation; section 7.4.1: it is retried later.
    #[test]
    fn probes_counted_not_ect_fail_the_initiation() {
        let mut v = EcnValidation::default().with_retry_after(Duration::from_secs(10));
        let mut at = Instant::now();
        let sent: Vec<u16> = (0..40).collect();
        let marked = send(&mut v, &mut at, 0, 40);
        let c = counters_for(&sent, &marked, false, 0, EcnCounters::default());
        v.on_counters(at, 39, c);
        assert!(
            matches!(v.state(), EcnState::Failed { .. }),
            "{:?}",
            v.state()
        );
        assert!(
            send(&mut v, &mut at, 40, 20).is_empty(),
            "nothing marked after the failure"
        );
        at += Duration::from_secs(11);
        assert!(
            !send(&mut v, &mut at, 60, 20).is_empty(),
            "probing again after the retry time"
        );
    }

    /// Section 7.4.2, ongoing use: once every packet goes out ECT, a receiver counting them
    /// not-ECT means the path clears the field, and marking stops.
    #[test]
    fn bleaching_counted_in_ongoing_use_stops_the_marking() {
        let mut v = EcnValidation::new(EcnInitiation::LeapOfFaith);
        let mut at = Instant::now();
        let sent: Vec<u16> = (0..40).collect();
        let marked = send(&mut v, &mut at, 0, 40);
        assert_eq!(marked.len(), 40);
        let c = counters_for(&sent, &marked, false, 0, EcnCounters::default());
        v.on_counters(at, 39, c);
        assert!(
            matches!(v.state(), EcnState::Failed { .. }),
            "{:?}",
            v.state()
        );
    }

    /// Section 7.4.1: high loss of ECT packets switches to not-ECT to compare.
    #[test]
    fn counted_loss_of_ect_packets_falls_back_to_not_ect() {
        let mut v = EcnValidation::new(EcnInitiation::LeapOfFaith);
        let mut at = Instant::now();
        let sent: Vec<u16> = (0..40).collect();
        let marked = send(&mut v, &mut at, 0, 40);
        let c = counters_for(&sent, &marked, true, 20, EcnCounters::default());
        v.on_counters(at, 39, c);
        assert_eq!(v.state(), EcnState::Fallback);
        assert!(send(&mut v, &mut at, 40, 10).is_empty());
    }

    /// Sends `count` packets 20 ms apart from `first`; returns which were marked.
    fn send(v: &mut EcnValidation, at: &mut Instant, first: u16, count: u16) -> Vec<u16> {
        let mut marked = vec![];
        for n in 0..count {
            let seq = first.wrapping_add(n);
            if v.on_send(*at, seq) {
                marked.push(seq);
            }
            *at += Duration::from_millis(20);
        }
        marked
    }

    /// Reports `first..first + count`: `path(seq, marked)` says how each arrived.
    fn report(
        v: &mut EcnValidation,
        at: Instant,
        first: u16,
        count: u16,
        path: impl Fn(u16, bool) -> Option<Ecn>,
    ) {
        for n in 0..count {
            let seq = first.wrapping_add(n);
            let marked = v.was_marked(seq);
            match path(seq, marked) {
                Some(ecn) => v.on_report(at, seq, true, ecn),
                None => v.on_report(at, seq, false, Ecn::NotEct),
            }
        }
    }

    fn carries_ecn(_: u16, marked: bool) -> Option<Ecn> {
        Some(if marked { Ecn::Ect1 } else { Ecn::NotEct })
    }

    #[test]
    fn initiation_marks_a_small_fraction_never_all() {
        let mut v = EcnValidation::default();
        let mut at = Instant::now();
        let marked = send(&mut v, &mut at, 0, 100);
        assert!(marked.len() >= 4, "probes: {marked:?}");
        assert!(marked.len() <= 100 / 4, "a small fraction: {marked:?}");
        assert!(
            marked.windows(2).all(|w| w[1] - w[0] >= 2),
            "never two in a row: {marked:?}"
        );
        assert_eq!(v.state(), EcnState::Initiating);
    }

    #[test]
    fn a_slow_stream_still_probes_twice_a_second() {
        let mut v = EcnValidation::default();
        let mut at = Instant::now();
        let mut marked = 0;
        // Five packets a second for two seconds.
        for seq in 0..10u16 {
            marked += u32::from(v.on_send(at, seq));
            at += Duration::from_millis(200);
        }
        assert!(marked >= 4, "{marked} probes in two seconds");
        assert!(marked < 10);
    }

    #[test]
    fn confirmed_probes_make_every_packet_ect() {
        let mut v = EcnValidation::default();
        let mut at = Instant::now();
        send(&mut v, &mut at, 0, 40);
        report(&mut v, at, 0, 40, carries_ecn);
        assert_eq!(v.state(), EcnState::Active);
        assert_eq!(send(&mut v, &mut at, 40, 20).len(), 20);
        assert!(v.marks_all());
    }

    #[test]
    fn a_ce_marked_probe_confirms_ecn_too() {
        let mut v = EcnValidation::default();
        let mut at = Instant::now();
        send(&mut v, &mut at, 0, 40);
        report(&mut v, at, 0, 40, |_, m| {
            Some(if m { Ecn::Ce } else { Ecn::NotEct })
        });
        assert_eq!(v.state(), EcnState::Active);
    }

    #[test]
    fn a_bleached_probe_fails_the_initiation_and_a_retry_follows() {
        let mut v = EcnValidation::default().with_retry_after(Duration::from_secs(10));
        let mut at = Instant::now();
        send(&mut v, &mut at, 0, 40);
        report(&mut v, at, 0, 40, |_, _| Some(Ecn::NotEct));
        assert!(
            matches!(v.state(), EcnState::Failed { .. }),
            "{:?}",
            v.state()
        );
        assert!(send(&mut v, &mut at, 40, 100).is_empty(), "nothing marked");
        at += Duration::from_secs(10);
        assert!(
            !send(&mut v, &mut at, 140, 20).is_empty(),
            "initiating again"
        );
        assert_eq!(v.state(), EcnState::Initiating);
    }

    #[test]
    fn a_path_that_drops_ect_packets_fails_the_initiation() {
        let mut v = EcnValidation::default();
        let mut at = Instant::now();
        let probes = send(&mut v, &mut at, 0, 60);
        assert!(probes.len() >= 4);
        report(&mut v, at, 0, 60, |_, m| (!m).then_some(Ecn::NotEct));
        assert!(
            matches!(v.state(), EcnState::Failed { .. }),
            "{:?}",
            v.state()
        );
    }

    #[test]
    fn three_lost_probes_are_not_yet_a_failure() {
        let mut v = EcnValidation::default();
        let mut at = Instant::now();
        let probes = send(&mut v, &mut at, 0, 60);
        let lost: Vec<u16> = probes[..3].to_vec();
        report(&mut v, at, 0, 60, |s, m| {
            if lost.contains(&s) {
                None
            } else {
                carries_ecn(s, m)
            }
        });
        assert_eq!(v.state(), EcnState::Active, "the fourth probe arrived ECT");
    }

    #[test]
    fn a_late_packet_reported_lost_then_received_is_not_a_loss() {
        let mut v = EcnValidation::default();
        let mut at = Instant::now();
        let probes = send(&mut v, &mut at, 0, 60);
        for &p in &probes {
            v.on_report(at, p, false, Ecn::NotEct);
            v.on_report(at, p, true, Ecn::Ect1);
            // A repeat of either report changes nothing.
            v.on_report(at, p, true, Ecn::Ect1);
            v.on_report(at, p, false, Ecn::NotEct);
        }
        assert_eq!(v.state(), EcnState::Active);
    }

    #[test]
    fn bleaching_during_use_stops_the_marking() {
        let mut v = EcnValidation::new(EcnInitiation::LeapOfFaith);
        let mut at = Instant::now();
        assert_eq!(
            send(&mut v, &mut at, 0, 32).len(),
            32,
            "leap of faith marks all"
        );
        // A few bleached packets are not a failure.
        report(&mut v, at, 0, 32, |s, _| {
            Some(if s % 16 == 0 { Ecn::NotEct } else { Ecn::Ect1 })
        });
        assert_eq!(v.state(), EcnState::Active);
        send(&mut v, &mut at, 32, 32);
        report(&mut v, at, 32, 32, |_, _| Some(Ecn::NotEct));
        assert!(
            matches!(v.state(), EcnState::Failed { .. }),
            "{:?}",
            v.state()
        );
        assert!(send(&mut v, &mut at, 64, 50).is_empty());
    }

    #[test]
    fn loss_that_goes_with_the_marking_initiates_again_then_disables() {
        let mut v = EcnValidation::new(EcnInitiation::LeapOfFaith);
        let mut at = Instant::now();
        let mut seq = 0u16;
        for round in 0..FALLBACKS_TO_DISABLE {
            // In use: ECT packets are dropped.
            if round > 0 {
                // Initiate again: probes go through, so the stream is back in use.
                let n = 40;
                send(&mut v, &mut at, seq, n);
                report(&mut v, at, seq, n, carries_ecn);
                seq += n;
            }
            assert_eq!(v.state(), EcnState::Active, "round {round}");
            send(&mut v, &mut at, seq, 32);
            report(&mut v, at, seq, 32, |_, m| (!m).then_some(Ecn::NotEct));
            seq += 32;
            assert_eq!(v.state(), EcnState::Fallback, "round {round}");
            assert!(
                send(&mut v, &mut at, seq, 32).is_empty(),
                "Not-ECT while comparing"
            );
            report(&mut v, at, seq, 32, |_, m| (!m).then_some(Ecn::NotEct));
            seq += 32;
        }
        assert_eq!(v.state(), EcnState::Disabled);
        at += DEFAULT_RETRY_AFTER * 2;
        assert!(
            send(&mut v, &mut at, seq, 40).is_empty(),
            "disabled for good"
        );
    }

    #[test]
    fn loss_that_stays_without_the_marking_resumes_it() {
        let mut v = EcnValidation::new(EcnInitiation::LeapOfFaith);
        let mut at = Instant::now();
        send(&mut v, &mut at, 0, 32);
        report(&mut v, at, 0, 32, |s, _| (s % 2 == 0).then_some(Ecn::Ect1));
        assert_eq!(v.state(), EcnState::Fallback);
        send(&mut v, &mut at, 32, 32);
        report(&mut v, at, 32, 32, |s, _| {
            (s % 2 == 0).then_some(Ecn::NotEct)
        });
        assert_eq!(v.state(), EcnState::Active, "congestion, not ECN");
    }

    /// A fixed corpus of arbitrary send / report sequences (sequence numbers that jump, wrap,
    /// repeat; reports out of order, duplicated, for unknown packets): nothing panics, a stream
    /// that is initiating never marks two packets in a row nor more than a quarter of them,
    /// and one that is disabled never marks again.
    #[test]
    fn arbitrary_send_and_report_sequences_keep_the_invariants() {
        let mut state = 0x0EC0_0001u32;
        let mut next = move || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state >> 8
        };
        for _ in 0..400 {
            let mut v = if next() % 2 == 0 {
                EcnValidation::default()
            } else {
                EcnValidation::new(EcnInitiation::LeapOfFaith)
            }
            .with_retry_after(Duration::from_millis(u64::from(next() % 3000)));
            let mut at = Instant::now();
            let mut seq = next() as u16;
            let mut sent: Vec<u16> = vec![];
            let mut run_marked = 0u32;
            let mut initiating = (0u32, 0u32);
            for _ in 0..600 {
                at += Duration::from_millis(u64::from(next() % 60));
                match next() % 10 {
                    0..=5 => {
                        seq = match next() % 20 {
                            0 => seq.wrapping_add(next() as u16),
                            1 => seq,
                            _ => seq.wrapping_add(1),
                        };
                        let was = v.state();
                        let marked = v.on_send(at, seq);
                        sent.push(seq);
                        if was == EcnState::Disabled {
                            assert!(!marked, "a disabled stream marks nothing");
                        }
                        if v.state() == EcnState::Initiating && was == EcnState::Initiating {
                            initiating.0 += 1;
                            initiating.1 += u32::from(marked);
                            run_marked = if marked { run_marked + 1 } else { 0 };
                            assert!(run_marked <= 1, "two probes in a row");
                        } else {
                            run_marked = 0;
                        }
                    }
                    _ => {
                        let target = if sent.is_empty() || next() % 8 == 0 {
                            next() as u16
                        } else {
                            sent[(next() as usize) % sent.len()]
                        };
                        let ecn = match next() % 4 {
                            0 => Ecn::NotEct,
                            1 => Ecn::Ect1,
                            2 => Ecn::Ect0,
                            _ => Ecn::Ce,
                        };
                        v.on_report(at, target, next() % 5 != 0, ecn);
                    }
                }
            }
            if initiating.0 >= 40 {
                assert!(
                    initiating.1 * 4 <= initiating.0 + 4,
                    "a small fraction while initiating: {initiating:?}"
                );
            }
        }
    }
}
