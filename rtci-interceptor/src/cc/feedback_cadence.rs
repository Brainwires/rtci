//! How often congestion control feedback is generated: a share of the media it reports on.

use crate::rtcp_session::{RtcpBandwidth, RtcpSessionControl};
use crate::{Packet, TaggedPacket};
use shared::marshal::MarshalSize;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// The share of the media it reports on that congestion control feedback may take: the 5%
/// RFC 3550 section 6.2 recommends for RTCP.
pub(crate) const FEEDBACK_SHARE: f64 = 0.05;
/// The window the received media bit rate is measured over.
const RATE_WINDOW: Duration = Duration::from_secs(2);
const RATE_BUCKET: Duration = Duration::from_millis(250);
/// The report that leads the minimal compound RTCP packet a feedback packet travels in without
/// reduced-size RTCP (RFC 4585 section 3.1): an RR without report blocks, or an SR without
/// them from an endpoint that sends media.
const RR_OCTETS: f64 = 8.0;
const SR_OCTETS: f64 = 28.0;
/// The CNAME assumed until the session's is seen: RFC 7022's 96 random bits in Base64.
const DEFAULT_CNAME_OCTETS: usize = 16;
/// How long after this endpoint's last RTP packet its RTCP leads with an SR: RFC 3550 section
/// 6.3.8's two report intervals, taken at the five-second minimum.
const SENDER_HORIZON: Duration = Duration::from_secs(10);
/// UDP over IPv4, which RFC 3550 section 6.2 counts in the size of an RTCP packet.
const LOWER_LAYER_OCTETS: f64 = 28.0;
/// The size assumed for a feedback packet before one has been built.
const INITIAL_FEEDBACK_OCTETS: f64 = 40.0;
/// The shortest interval the cadence goes to, however much media there is.
pub(crate) const MIN_ADAPTIVE_INTERVAL: Duration = Duration::from_millis(50);
/// The longest interval the cadence stretches to while media flows: a sender's estimator
/// works as well with a report every 50 ms as every 250 ms, and markedly worse with one a
/// second (`gcc_feedback_rate.rs`); libwebrtc holds its transport feedback to the same range.
pub(crate) const MAX_ADAPTIVE_INTERVAL: Duration = Duration::from_millis(250);

/// The interval between two feedback packets of a generator (TWCC or RFC 8888).
///
/// Congestion control feedback is sized to what it reports on, not to the rest of RTCP: the
/// interval in which [`FEEDBACK_SHARE`] of the media received holds one feedback packet
/// (with its lower layers, and the minimal compound packet around it unless reduced-size RTCP
/// was negotiated), held within [`MIN_ADAPTIVE_INTERVAL`] and [`MAX_ADAPTIVE_INTERVAL`]. RFC
/// 8888 section 3.1 asks that the reporting interval be chosen by the bandwidth it may use
/// and sized for the congestion controller's needs; the RTCP session sends the packets as
/// they come (`RtcpSessionBuilder::with_immediate_congestion_feedback`). `b=RR` (RFC 3556),
/// when negotiated, is the share instead.
pub(crate) struct FeedbackCadence {
    /// The fixed interval, when not adaptive.
    floor: Duration,
    adaptive: bool,
    /// The share of the media received the feedback may take ([`FEEDBACK_SHARE`] unless set).
    share: f64,
    /// The longest adaptive interval ([`MAX_ADAPTIVE_INTERVAL`] unless set).
    max_interval: Duration,
    /// `b=` lines of the session, as the RTCP session is told them.
    negotiated: RtcpBandwidth,
    /// Whether reduced-size RTCP was negotiated (RFC 5506): a report can leave on its own.
    reduced_size: bool,
    buckets: VecDeque<(Instant, u64)>,
    first_media: Option<Instant>,
    /// A running mean of the size of the feedback built, RTCP octets.
    feedback_octets: f64,
    /// The octets SRTCP adds to every RTCP packet (`RtcpSessionControl::SrtcpOverhead`).
    srtcp_octets: f64,
    /// The length of the session's CNAME (`RtcpSessionControl::Cname`), for the SDES of a
    /// minimal compound packet.
    cname_octets: usize,
    /// When this endpoint last sent RTP: its compound packets then lead with an SR.
    last_sent: Option<Instant>,
}

impl FeedbackCadence {
    pub(crate) fn new(floor: Duration, adaptive: bool) -> Self {
        Self {
            floor,
            adaptive,
            share: FEEDBACK_SHARE,
            max_interval: MAX_ADAPTIVE_INTERVAL,
            negotiated: RtcpBandwidth::default(),
            reduced_size: false,
            buckets: VecDeque::new(),
            first_media: None,
            feedback_octets: INITIAL_FEEDBACK_OCTETS,
            srtcp_octets: 0.0,
            cname_octets: DEFAULT_CNAME_OCTETS,
            last_sent: None,
        }
    }

    /// The share of the media received the feedback may take, and the longest adaptive
    /// interval (`TwccReceiverBuilder::with_feedback_share`, `with_max_adaptive_interval`).
    pub(crate) fn with_limits(mut self, share: f64, max_interval: Duration) -> Self {
        self.share = share.clamp(0.001, 1.0);
        self.max_interval = max_interval.max(MIN_ADAPTIVE_INTERVAL);
        self
    }

    /// Whether no interval was configured at all: the generator is off.
    pub(crate) fn is_off(&self) -> bool {
        self.floor.is_zero()
    }

    /// An RTP packet arrived: the media the feedback reports on.
    pub(crate) fn on_packet(&mut self, message: &TaggedPacket) {
        let Packet::Rtp(packet) = &message.message.packet else {
            return;
        };
        let now = message.now;
        let octets = packet.marshal_size() as u64;
        self.first_media.get_or_insert(now);
        match self.buckets.back_mut() {
            Some((start, sum)) if now.saturating_duration_since(*start) < RATE_BUCKET => {
                *sum += octets;
            }
            _ => self.buckets.push_back((now, octets)),
        }
        while self
            .buckets
            .front()
            .is_some_and(|(start, _)| now.saturating_duration_since(*start) > RATE_WINDOW)
        {
            self.buckets.pop_front();
        }
    }

    /// Something written towards the wire: what the session is told about its bandwidth,
    /// packet form, SRTCP and CNAME is read on its way past, and this endpoint's own RTP tells
    /// whether its compound packets lead with an SR.
    pub(crate) fn on_write(&mut self, message: &TaggedPacket) {
        if let Packet::Rtp(_) = &message.message.packet {
            self.last_sent = Some(message.now);
        }
        match message.message.custom::<RtcpSessionControl>() {
            Some(RtcpSessionControl::Bandwidth(bandwidth)) => self.negotiated = *bandwidth,
            Some(RtcpSessionControl::ReducedSize(reduced_size)) => {
                self.reduced_size = *reduced_size;
            }
            Some(RtcpSessionControl::SrtcpOverhead(octets)) => self.srtcp_octets = *octets as f64,
            Some(RtcpSessionControl::Cname(cname)) => self.cname_octets = cname.len(),
            _ => {}
        }
    }

    /// The octets around a feedback packet on the wire as of `now`: SRTCP and the lower layers
    /// always, and without reduced-size RTCP the minimal compound packet's report and SDES
    /// (RFC 4585 section 3.1: one SR or RR without report blocks, an SDES with the CNAME).
    fn wrapping_octets(&self, now: Instant) -> f64 {
        let compound = if self.reduced_size {
            0.0
        } else {
            let sending = self
                .last_sent
                .is_some_and(|at| now.saturating_duration_since(at) <= SENDER_HORIZON);
            let report = if sending { SR_OCTETS } else { RR_OCTETS };
            // Header, SSRC, the CNAME item (type, length, text) and a terminating null, padded
            // to 32 bits.
            let chunk = (4 + 2 + self.cname_octets + 1).div_ceil(4) * 4;
            report + (4 + chunk) as f64
        };
        self.srtcp_octets + LOWER_LAYER_OCTETS + compound
    }

    /// A feedback packet of `octets` was built.
    pub(crate) fn on_feedback(&mut self, octets: usize) {
        self.feedback_octets += (octets as f64 - self.feedback_octets) / 8.0;
    }

    fn media_bits_per_second(&self, now: Instant) -> f64 {
        let Some(first) = self.first_media else {
            return 0.0;
        };
        let octets: u64 = self
            .buckets
            .iter()
            .filter(|(start, _)| now.saturating_duration_since(*start) <= RATE_WINDOW)
            .map(|(_, sum)| *sum)
            .sum();
        let span = now
            .saturating_duration_since(first)
            .min(RATE_WINDOW)
            .as_secs_f64()
            .max(RATE_BUCKET.as_secs_f64());
        octets as f64 * 8.0 / span
    }

    /// The interval to the next feedback packet, as of `now`.
    pub(crate) fn interval(&self, now: Instant) -> Duration {
        if !self.adaptive || self.floor.is_zero() {
            return self.floor;
        }
        let share = match self.negotiated.rr {
            Some(rr) => rr as f64,
            None => self.share * self.media_bits_per_second(now),
        };
        if share <= 0.0 {
            return self.max_interval;
        }
        let packet_octets = self.feedback_octets + self.wrapping_octets(now);
        Duration::from_secs_f64(packet_octets * 8.0 / share)
            .clamp(MIN_ADAPTIVE_INTERVAL, self.max_interval)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AttributedPacket;
    use shared::TransportContext;

    fn media(now: Instant, octets: usize) -> TaggedPacket {
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    ..Default::default()
                },
                payload: vec![0u8; octets - 12].into(),
            })),
        }
    }

    /// `bits_per_second` of media received for three seconds.
    fn after_media(cadence: &mut FeedbackCadence, bits_per_second: f64) -> Instant {
        let epoch = Instant::now();
        let octets = 500usize;
        let spacing = Duration::from_secs_f64(octets as f64 * 8.0 / bits_per_second);
        let mut at = Duration::ZERO;
        while at < Duration::from_secs(3) {
            cadence.on_packet(&media(epoch + at, octets));
            at += spacing;
        }
        epoch + Duration::from_secs(3)
    }

    /// At 64 kbit/s of media 5% is 3.2 kbit/s, and a 40-octet report in a minimal compound
    /// packet (an RR, an SDES with a 16-character CNAME: 36 octets) with its lower layers is
    /// 104 octets: one every 0.26 s, held to 250 ms.
    #[test]
    fn the_interval_holds_the_feedback_in_five_percent_of_the_media() {
        let mut cadence = FeedbackCadence::new(Duration::from_millis(100), true);
        let now = after_media(&mut cadence, 64_000.0);
        let interval = cadence.interval(now).as_secs_f64();
        assert!((0.22..=0.25).contains(&interval), "{interval}");
    }

    /// With much media the interval stops at 50 ms; with little, at 250 ms.
    #[test]
    fn the_interval_is_held_between_50_and_250_ms() {
        let mut fast = FeedbackCadence::new(Duration::from_millis(100), true);
        let now = after_media(&mut fast, 5_000_000.0);
        assert_eq!(MIN_ADAPTIVE_INTERVAL, fast.interval(now));
        let mut slow = FeedbackCadence::new(Duration::from_millis(100), true);
        let now = after_media(&mut slow, 16_000.0);
        assert_eq!(MAX_ADAPTIVE_INTERVAL, slow.interval(now));
        let idle = FeedbackCadence::new(Duration::from_millis(100), true);
        assert_eq!(MAX_ADAPTIVE_INTERVAL, idle.interval(Instant::now()));
    }

    /// Reduced-size RTCP (RFC 5506) takes the report without the compound packet around it,
    /// and the interval shortens with it.
    #[test]
    fn reduced_size_rtcp_shortens_the_interval() {
        let mut compound = FeedbackCadence::new(Duration::from_millis(50), true);
        let now = after_media(&mut compound, 100_000.0);
        let mut reduced = FeedbackCadence::new(Duration::from_millis(50), true);
        let then = after_media(&mut reduced, 100_000.0);
        reduced.on_write(&RtcpSessionControl::ReducedSize(true).into_packet(then));
        assert!(reduced.interval(then) < compound.interval(now).mul_f64(0.8));
    }

    /// `b=RR` (RFC 3556) replaces the 5%.
    #[test]
    fn negotiated_receiver_rtcp_bandwidth_sets_the_interval() {
        let mut cadence = FeedbackCadence::new(Duration::from_millis(50), true);
        let now = after_media(&mut cadence, 64_000.0);
        let before = cadence.interval(now);
        cadence.on_write(
            &RtcpSessionControl::Bandwidth(RtcpBandwidth {
                session: None,
                rs: Some(8_000),
                rr: Some(24_000),
            })
            .into_packet(now),
        );
        let after = cadence.interval(now);
        assert!(after < before.mul_f64(0.5), "{before:?} -> {after:?}");
    }

    /// Media this endpoint sends is not what the feedback reports on.
    #[test]
    fn media_sent_does_not_count() {
        let mut cadence = FeedbackCadence::new(Duration::from_millis(100), true);
        let now = Instant::now();
        for n in 0..1_000u64 {
            cadence.on_write(&media(now + Duration::from_millis(n), 1_200));
        }
        assert_eq!(
            MAX_ADAPTIVE_INTERVAL,
            cadence.interval(now + Duration::from_secs(1))
        );
    }

    /// A smaller share and a longer ceiling (the `Performance` profile's 2.5% and 500 ms):
    /// at 32 kbit/s of media a 40-octet report with its lower layers (68 octets) fits 2.5%
    /// once every 0.68 s, held to 500 ms; the default holds it to 250 ms.
    #[test]
    fn a_smaller_share_lengthens_the_interval_up_to_its_ceiling() {
        let mut cadence = FeedbackCadence::new(Duration::from_millis(100), true)
            .with_limits(0.025, Duration::from_millis(500));
        let now = after_media(&mut cadence, 32_000.0);
        cadence.on_write(&RtcpSessionControl::ReducedSize(true).into_packet(now));
        assert_eq!(Duration::from_millis(500), cadence.interval(now));
        let mut default = FeedbackCadence::new(Duration::from_millis(100), true);
        let then = after_media(&mut default, 32_000.0);
        assert_eq!(MAX_ADAPTIVE_INTERVAL, default.interval(then));
        // At 300 kbit/s the share, not the ceiling, sets it: 68 * 8 / 7500 = 72 ms.
        let mut faster = FeedbackCadence::new(Duration::from_millis(100), true)
            .with_limits(0.025, Duration::from_millis(500));
        let now = after_media(&mut faster, 300_000.0);
        faster.on_write(&RtcpSessionControl::ReducedSize(true).into_packet(now));
        let interval = faster.interval(now).as_secs_f64();
        assert!((0.065..=0.08).contains(&interval), "{interval}");
    }

    /// What wraps a feedback packet on the wire is counted as the session builds it: SRTCP's
    /// fields (`RtcpSessionControl::SrtcpOverhead`), and without reduced-size RTCP an SR rather
    /// than an RR once this endpoint sends media, and the session's CNAME. At 200 kbit/s of
    /// media (10 kbit/s for feedback) a 40-octet reduced-size report with its lower layers is
    /// 68 octets, 54 ms apart; with SRTCP's 14 octets it is 82, 66 ms apart.
    #[test]
    fn srtcp_and_the_compound_packet_around_the_feedback_are_counted() {
        let mut plain = FeedbackCadence::new(Duration::from_millis(100), true);
        let now = after_media(&mut plain, 200_000.0);
        plain.on_write(&RtcpSessionControl::ReducedSize(true).into_packet(now));
        let plain = plain.interval(now).as_secs_f64();
        assert!((0.050..=0.058).contains(&plain), "{plain}");

        let mut srtcp = FeedbackCadence::new(Duration::from_millis(100), true);
        let now = after_media(&mut srtcp, 200_000.0);
        srtcp.on_write(&RtcpSessionControl::ReducedSize(true).into_packet(now));
        srtcp.on_write(&RtcpSessionControl::SrtcpOverhead(14).into_packet(now));
        let with_srtcp = srtcp.interval(now).as_secs_f64();
        assert!((0.062..=0.070).contains(&with_srtcp), "{with_srtcp}");

        // Without reduced-size RTCP: an RR and a 16-character CNAME (36 octets) for a
        // receive-only endpoint, 104 octets in all, 83 ms; an SR and a 24-character CNAME
        // (28 + 36) for one that sends media, 132 octets, 106 ms.
        let mut receiving = FeedbackCadence::new(Duration::from_millis(100), true);
        let now = after_media(&mut receiving, 200_000.0);
        let receiving = receiving.interval(now).as_secs_f64();
        assert!((0.080..=0.087).contains(&receiving), "{receiving}");
        let mut sending = FeedbackCadence::new(Duration::from_millis(100), true);
        let now = after_media(&mut sending, 200_000.0);
        sending.on_write(&RtcpSessionControl::Cname("a".repeat(24)).into_packet(now));
        sending.on_write(&media(now, 1_200));
        let sending = sending.interval(now).as_secs_f64();
        assert!((0.105..=0.113).contains(&sending), "{sending}");
    }

    /// The fixed setting ignores all of it.
    #[test]
    fn a_fixed_interval_stays_fixed() {
        let mut cadence = FeedbackCadence::new(Duration::from_millis(100), false);
        let now = after_media(&mut cadence, 64_000.0);
        assert_eq!(Duration::from_millis(100), cadence.interval(now));
    }
}
