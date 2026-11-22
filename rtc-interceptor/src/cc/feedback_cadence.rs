//! How often congestion control feedback is generated, given the RTCP bandwidth it has to fit.

use crate::rtcp_session::{RtcpBandwidth, RtcpSessionControl, nominal_session_bandwidth};
use crate::stream_info::StreamInfo;
use crate::{Packet, TaggedPacket};
use shared::marshal::MarshalSize;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// RFC 3550 section 6.2: the recommended share of the session bandwidth for RTCP.
const RTCP_FRACTION: f64 = 0.05;
/// The window the media bit rate is measured over, as the RTCP session does when no session
/// bandwidth was signalled.
const RATE_WINDOW: Duration = Duration::from_secs(2);
const RATE_BUCKET: Duration = Duration::from_millis(250);
/// What goes out with a feedback packet in the minimal compound RTCP packet early feedback
/// travels in (RFC 4585 section 3.1): a receiver report and an SDES with a short CNAME.
const COMPOUND_OCTETS: f64 = 28.0;
/// UDP over IPv4, which RFC 3550 section 6.2 counts in the size of an RTCP packet.
const LOWER_LAYER_OCTETS: f64 = 28.0;
/// The size assumed for a feedback packet before one has been built.
const INITIAL_FEEDBACK_OCTETS: f64 = 40.0;
/// The longest interval the cadence stretches to. A congestion controller hears from the
/// receiver at least this often however little RTCP bandwidth there is (`Gcc` converges as
/// fast with a report every 500 ms as with one every 50 ms, and markedly slower beyond); the
/// RTCP session still decides when the packet may leave.
pub(crate) const MAX_ADAPTIVE_INTERVAL: Duration = Duration::from_millis(400);

/// The interval between two feedback packets of a generator (TWCC or RFC 8888).
///
/// The RTCP session keeps all RTCP of the endpoint inside the RTCP bandwidth (RFC 3550
/// section 6.2; RFC 4585 section 3.5), so a generator that builds a report every 100 ms hands
/// the session more than it may send whenever a tenth of a second of RTCP bandwidth does not
/// hold one report: the reports queue, the queue has an end, and what the sender finally
/// hears is late or missing. "The RTCP reporting interval SHOULD be chosen" by what the
/// bandwidth allows (RFC 8888 sections 3.1 and 4; draft-holmer-rmcat-transport-wide-cc-
/// extensions-01 section 3: "with low uplink bandwidth feedback may be sent less often").
///
/// So the interval is the one in which the RTCP bandwidth of one of two members holds one
/// RTCP packet with one report in it, by the arithmetic of RFC 3550 section 6.3.1, and never
/// shorter than the configured interval: one report then rides every packet the session may
/// send, and each covers everything since the one before.
pub(crate) struct FeedbackCadence {
    /// The shortest interval: the configured one.
    floor: Duration,
    adaptive: bool,
    /// `b=` lines of the session, as the RTCP session is told them.
    negotiated: RtcpBandwidth,
    /// Whether reduced-size RTCP was negotiated (RFC 5506): a report can leave on its own.
    reduced_size: bool,
    buckets: VecDeque<(Instant, u64)>,
    first_media: Option<Instant>,
    /// A running mean of the size of the feedback built, RTCP octets.
    feedback_octets: f64,
    /// The media of the streams bound, by SSRC: whether each is video (else audio).
    streams: std::collections::HashMap<u32, bool>,
}

impl FeedbackCadence {
    pub(crate) fn new(floor: Duration, adaptive: bool) -> Self {
        Self {
            floor,
            adaptive,
            negotiated: RtcpBandwidth::default(),
            reduced_size: false,
            buckets: VecDeque::new(),
            first_media: None,
            feedback_octets: INITIAL_FEEDBACK_OCTETS,
            streams: std::collections::HashMap::new(),
        }
    }

    /// A stream of the session was bound (either direction): its media counts towards the
    /// nominal session bandwidth, as it does in the RTCP session.
    pub(crate) fn on_bind(&mut self, info: &StreamInfo) {
        let mime = info.mime_type.to_ascii_lowercase();
        if mime.starts_with("video/") {
            self.streams.insert(info.ssrc, true);
        } else if mime.starts_with("audio/") {
            self.streams.insert(info.ssrc, false);
        }
    }

    /// A stream was unbound.
    pub(crate) fn on_unbind(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);
    }

    /// Whether no interval was configured at all: the generator is off.
    pub(crate) fn is_off(&self) -> bool {
        self.floor.is_zero()
    }

    /// An RTP packet of the session passed, in either direction.
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

    /// Something written towards the wire: what the session is told about its bandwidth and
    /// packet form is read on its way past.
    pub(crate) fn on_write(&mut self, message: &TaggedPacket) {
        match message.message.custom::<RtcpSessionControl>() {
            Some(RtcpSessionControl::Bandwidth(bandwidth)) => self.negotiated = *bandwidth,
            Some(RtcpSessionControl::ReducedSize(reduced_size)) => {
                self.reduced_size = *reduced_size;
            }
            _ => self.on_packet(message),
        }
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

    /// The RTCP bandwidth of the whole session, bits per second.
    fn rtcp_bits_per_second(&self, now: Instant) -> f64 {
        let session = match self.negotiated.session {
            Some(session) => session as f64,
            None => self
                .media_bits_per_second(now)
                .max(nominal_session_bandwidth(
                    self.streams.values().any(|video| *video),
                    self.streams.values().any(|video| !*video),
                )),
        };
        match (self.negotiated.rs, self.negotiated.rr) {
            (None, None) => session * RTCP_FRACTION,
            // RFC 3556: a modifier that is absent keeps its default share of the 5%.
            (rs, rr) => {
                rs.map_or(session * RTCP_FRACTION * 0.25, |rs| rs as f64)
                    + rr.map_or(session * RTCP_FRACTION * 0.75, |rr| rr as f64)
            }
        }
    }

    /// The interval to the next feedback packet, as of `now`.
    pub(crate) fn interval(&self, now: Instant) -> Duration {
        if !self.adaptive || self.floor.is_zero() {
            return self.floor;
        }
        let rtcp_bits = self.rtcp_bits_per_second(now);
        if rtcp_bits <= 0.0 {
            return MAX_ADAPTIVE_INTERVAL.max(self.floor);
        }
        let packet_octets = self.feedback_octets
            + LOWER_LAYER_OCTETS
            + if self.reduced_size {
                0.0
            } else {
                COMPOUND_OCTETS
            };
        // Two members share the RTCP bandwidth alike (RFC 3550 section 6.3.1): the interval
        // in which this one's half holds one packet.
        let seconds = packet_octets * 8.0 * 2.0 / rtcp_bits;
        Duration::from_secs_f64(seconds.min(MAX_ADAPTIVE_INTERVAL.as_secs_f64()))
            .max(self.floor)
            .min(MAX_ADAPTIVE_INTERVAL.max(self.floor))
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

    /// `bits_per_second` of media for three seconds.
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

    /// RFC 3550 section 6.2 and 6.3.1: at 100 kbit/s of media the RTCP bandwidth is 5 kbit/s,
    /// half of it this member's, and a minimal compound packet with one 40-octet report is 96
    /// octets with its lower layers: one fits every 0.31 s, not every 0.1 s.
    #[test]
    fn the_interval_is_what_the_rtcp_bandwidth_holds_one_report_in() {
        let mut cadence = FeedbackCadence::new(Duration::from_millis(100), true);
        let now = after_media(&mut cadence, 100_000.0);
        let interval = cadence.interval(now).as_secs_f64();
        assert!((0.28..=0.34).contains(&interval), "{interval}");
    }

    /// With bandwidth to spare the configured interval rules: feedback is never generated
    /// more often than asked for.
    #[test]
    fn the_configured_interval_is_the_shortest() {
        let mut cadence = FeedbackCadence::new(Duration::from_millis(100), true);
        let now = after_media(&mut cadence, 2_000_000.0);
        assert_eq!(Duration::from_millis(100), cadence.interval(now));
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

    /// `b=RS` / `b=RR` (RFC 3556) replace the 5%, here as there.
    #[test]
    fn negotiated_rtcp_bandwidth_sets_the_interval() {
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
        assert!(after < before.mul_f64(0.2), "{before:?} -> {after:?}");
    }

    /// The fixed setting ignores all of it.
    #[test]
    fn a_fixed_interval_stays_fixed() {
        let mut cadence = FeedbackCadence::new(Duration::from_millis(100), false);
        let now = after_media(&mut cadence, 64_000.0);
        assert_eq!(Duration::from_millis(100), cadence.interval(now));
    }

    /// However little bandwidth there is, the interval stops at its bound.
    #[test]
    fn the_interval_is_bounded() {
        let mut cadence = FeedbackCadence::new(Duration::from_millis(100), true);
        cadence.on_write(
            &RtcpSessionControl::Bandwidth(RtcpBandwidth {
                session: Some(8_000),
                rs: None,
                rr: None,
            })
            .into_packet(Instant::now()),
        );
        assert_eq!(MAX_ADAPTIVE_INTERVAL, cadence.interval(Instant::now()));
    }
}
