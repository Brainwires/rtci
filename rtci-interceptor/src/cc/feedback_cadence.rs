//! How often congestion control feedback is generated.

use crate::rtcp_session::{RtcpBandwidth, RtcpBandwidthShare, RtcpSessionControl};
use crate::stream_info::StreamInfo;
use crate::{Packet, TaggedPacket};
use shared::marshal::MarshalSize;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// The share of the rate it is sized to that congestion control feedback may take: the 5%
/// RFC 3550 section 6.2 recommends for RTCP.
pub(crate) const FEEDBACK_SHARE: f64 = 0.05;
/// The window the received media bit rate is measured over.
const RATE_WINDOW: Duration = Duration::from_secs(2);
const RATE_BUCKET: Duration = Duration::from_millis(250);
/// What goes out with a feedback packet in the minimal compound RTCP packet it travels in
/// without reduced-size RTCP (RFC 4585 section 3.1): a receiver report and an SDES with a
/// short CNAME.
const COMPOUND_OCTETS: f64 = 28.0;
/// UDP over IPv4, which RFC 3550 section 6.2 counts in the size of an RTCP packet.
const LOWER_LAYER_OCTETS: f64 = 28.0;
/// The size assumed for a feedback packet before one has been built.
const INITIAL_FEEDBACK_OCTETS: f64 = 40.0;
/// The shortest interval the rate-sized cadences go to, however high the rate.
pub(crate) const MIN_ADAPTIVE_INTERVAL: Duration = Duration::from_millis(50);
/// The longest interval the rate-sized cadences stretch to while media flows: a sender's
/// estimator works as well with a report every 50 ms as every 250 ms, and markedly worse with
/// one a second (`gcc_feedback_rate.rs`); libwebrtc holds its transport feedback to the same
/// range.
pub(crate) const MAX_ADAPTIVE_INTERVAL: Duration = Duration::from_millis(250);
/// draft-ietf-rmcat-gcc-02 section 3: "at least once every 30 ms if audio-only or
/// multi-stream".
pub const PER_FRAME_INTERVAL: Duration = Duration::from_millis(30);
/// draft-ietf-rmcat-gcc-02 section 3: "If the feedback overhead needs to be limited this
/// interval can be increased to 100 ms".
pub const PER_FRAME_MAX_INTERVAL: Duration = Duration::from_millis(100);
/// libwebrtc `transport_sequence_number_feedback_generator.cc`: `kDefaultInterval`, the
/// interval until a send estimate is known.
const SEND_ESTIMATE_DEFAULT_INTERVAL: Duration = Duration::from_millis(100);
/// libwebrtc `OnSendBandwidthEstimateChanged`: `kTwccReportSize`, "Ipv4(20B) + UDP(8B) +
/// SRTP(10B) + AverageTwccReport(30B)", the size its interval is computed with.
const SEND_ESTIMATE_REPORT_OCTETS: f64 = 68.0;

/// When a congestion control feedback generator (transport-wide feedback, RFC 8888) builds
/// its next report, while its interval is not fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionFeedbackCadence {
    /// The drafts' cadence (the default). draft-ietf-rmcat-gcc-02 section 3: "The RECOMMENDED
    /// feedback interval is once per received video frame or at least once every 30 ms if
    /// audio-only or multi-stream. If the feedback overhead needs to be limited this interval
    /// can be increased to 100 ms"; draft-holmer-rmcat-transport-wide-cc-extensions-01
    /// section 3: "It is recommended that a feedback message is sent for every frame
    /// received, but in cases of low uplink bandwidth it is acceptable to send them less
    /// frequently".
    ///
    /// A session whose only reported stream is one video stream is reported when a frame of
    /// it ends (the RTP marker), and after [`PER_FRAME_MAX_INTERVAL`] without one; any other
    /// session (audio alone, audio beside video, several streams) every
    /// [`PER_FRAME_INTERVAL`]. The overhead "needs to be limited" when the feedback would
    /// take more than the RTCP bandwidth gives this endpoint (RFC 4585 section 3.2: "FB
    /// messages are part of the RTCP control streams and thus subject to the RTCP bandwidth
    /// constraints"; RFC 3550 section 6.2: 5% of the session bandwidth, shared equally by the
    /// members): the interval is then the time in which this endpoint's share of the RTCP
    /// bandwidth ([`RtcpBandwidthShare`], from the RTCP session) holds one feedback packet,
    /// up to [`PER_FRAME_MAX_INTERVAL`] and no longer.
    #[default]
    PerFrame,
    /// libwebrtc's cadence (the `Chrome` behaviour profile): the interval in which 5% of the
    /// endpoint's own send estimate holds one 68-octet report, between 50 and 250 ms; 100 ms
    /// until an estimate is known
    /// (`modules/remote_bitrate_estimator/transport_sequence_number_feedback_generator.cc`,
    /// `OnSendBandwidthEstimateChanged`, fed from `call/call.cc` `OnTargetTransferRate`). The
    /// estimate is the congestion controller's ([`SendEstimate`](crate::SendEstimate)); the
    /// share and the ceiling are the generator's (`with_feedback_share`,
    /// `with_max_adaptive_interval`).
    SendEstimate,
    /// The interval in which a share of the media RECEIVED holds one feedback packet, between
    /// 50 ms and the generator's ceiling (the `Performance` behaviour profile, with 2.5% and
    /// 500 ms). No specification has this form: it is tuning.
    ReceivedMedia,
}

/// The interval between two feedback packets of a generator (TWCC or RFC 8888): fixed, or
/// one of the forms of [`CongestionFeedbackCadence`].
pub(crate) struct FeedbackCadence {
    /// The fixed interval, when not adaptive.
    floor: Duration,
    adaptive: bool,
    form: CongestionFeedbackCadence,
    /// The share of the rate the feedback may take ([`FEEDBACK_SHARE`] unless set).
    share: f64,
    /// The longest rate-sized interval ([`MAX_ADAPTIVE_INTERVAL`] unless set).
    max_interval: Duration,
    /// `b=` lines of the session, as the RTCP session is told them.
    negotiated: RtcpBandwidth,
    /// Whether reduced-size RTCP was negotiated (RFC 5506): a report can leave on its own.
    reduced_size: bool,
    buckets: VecDeque<(Instant, u64)>,
    first_media: Option<Instant>,
    /// A running mean of the size of the feedback built, RTCP octets.
    feedback_octets: f64,
    /// The congestion controller's estimate for this endpoint's sending, bits per second.
    send_estimate: Option<f64>,
    /// This endpoint's share of the RTCP bandwidth, bits per second.
    rtcp_share: Option<f64>,
    /// The reported media streams by SSRC: whether each is video.
    streams: HashMap<u32, bool>,
    /// When feedback was last built.
    last_feedback: Option<Instant>,
}

impl FeedbackCadence {
    pub(crate) fn new(floor: Duration, adaptive: bool) -> Self {
        Self {
            floor,
            adaptive,
            form: CongestionFeedbackCadence::default(),
            share: FEEDBACK_SHARE,
            max_interval: MAX_ADAPTIVE_INTERVAL,
            negotiated: RtcpBandwidth::default(),
            reduced_size: false,
            buckets: VecDeque::new(),
            first_media: None,
            feedback_octets: INITIAL_FEEDBACK_OCTETS,
            send_estimate: None,
            rtcp_share: None,
            streams: HashMap::new(),
            last_feedback: None,
        }
    }

    /// The form the interval takes while it is not fixed.
    pub(crate) fn with_form(mut self, form: CongestionFeedbackCadence) -> Self {
        self.form = form;
        self
    }

    /// A remote media stream the generator reports on was bound.
    pub(crate) fn bind_remote(&mut self, info: &StreamInfo) {
        let video = info.mime_type.to_ascii_lowercase().starts_with("video/");
        self.streams.insert(info.ssrc, video);
    }

    /// It was unbound.
    pub(crate) fn unbind_remote(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);
    }

    /// draft-ietf-rmcat-gcc-02 section 3: whether the session is one video stream (reported
    /// per frame) rather than "audio-only or multi-stream".
    fn single_video_stream(&self) -> bool {
        self.streams.len() == 1 && self.streams.values().all(|video| *video)
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

    /// Something arrived. An RTP packet is the media the feedback reports on; what the RTCP
    /// session and the congestion controller say on their way application-ward is read off
    /// any packet. Returns whether a report is due now: with
    /// [`CongestionFeedbackCadence::PerFrame`], the packet ended a frame of a session's only
    /// video stream and the last report is at least the stretched interval ago.
    pub(crate) fn on_packet(&mut self, message: &TaggedPacket) -> bool {
        if let Some(share) = message.message.custom::<RtcpBandwidthShare>() {
            self.rtcp_share = Some(share.bits_per_second);
        }
        if let Some(estimate) = message.message.custom::<crate::SendEstimate>() {
            self.send_estimate = Some(estimate.bits_per_second);
        }
        let Packet::Rtp(packet) = &message.message.packet else {
            return false;
        };
        let now = message.now;
        let frame_ended =
            packet.header.marker && self.streams.get(&packet.header.ssrc).copied() == Some(true);
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
        self.adaptive
            && !self.floor.is_zero()
            && self.form == CongestionFeedbackCadence::PerFrame
            && frame_ended
            && self.single_video_stream()
            && self.last_feedback.is_none_or(|last| {
                now.saturating_duration_since(last) >= self.share_interval().unwrap_or_default()
            })
    }

    /// Feedback was built at `now` (or there was nothing to report then).
    pub(crate) fn reported(&mut self, now: Instant) {
        self.last_feedback = Some(now);
    }

    /// A feedback packet with what travels with it, octets on the wire.
    fn packet_octets(&self) -> f64 {
        self.feedback_octets
            + LOWER_LAYER_OCTETS
            + if self.reduced_size {
                0.0
            } else {
                COMPOUND_OCTETS
            }
    }

    /// The interval in which this endpoint's share of the RTCP bandwidth holds one feedback
    /// packet, no longer than [`PER_FRAME_MAX_INTERVAL`]; `None` while the session has not
    /// said what the share is.
    fn share_interval(&self) -> Option<Duration> {
        let share = self.rtcp_share?;
        if share <= 0.0 {
            return Some(PER_FRAME_MAX_INTERVAL);
        }
        let seconds = self.packet_octets() * 8.0 / share;
        Some(Duration::from_secs_f64(
            seconds.min(PER_FRAME_MAX_INTERVAL.as_secs_f64()),
        ))
    }

    /// Something written towards the wire: what the session is told about its bandwidth and
    /// packet form is read on its way past.
    pub(crate) fn on_write(&mut self, message: &TaggedPacket) {
        match message.message.custom::<RtcpSessionControl>() {
            Some(RtcpSessionControl::Bandwidth(bandwidth)) => self.negotiated = *bandwidth,
            Some(RtcpSessionControl::ReducedSize(reduced_size)) => {
                self.reduced_size = *reduced_size;
            }
            _ => {}
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

    /// The interval to the next feedback packet, as of `now`.
    pub(crate) fn interval(&self, now: Instant) -> Duration {
        if !self.adaptive || self.floor.is_zero() {
            return self.floor;
        }
        match self.form {
            CongestionFeedbackCadence::PerFrame => {
                // One video stream: a frame's end brings the report; this is the wait for a
                // frame that does not end. Otherwise "at least once every 30 ms".
                let base = if self.single_video_stream() {
                    PER_FRAME_MAX_INTERVAL
                } else {
                    PER_FRAME_INTERVAL
                };
                base.max(self.share_interval().unwrap_or_default())
            }
            CongestionFeedbackCadence::SendEstimate => {
                let Some(estimate) = self.send_estimate else {
                    return SEND_ESTIMATE_DEFAULT_INTERVAL;
                };
                let share = self.share * estimate;
                if share <= 0.0 {
                    return self.max_interval;
                }
                Duration::from_secs_f64(
                    (SEND_ESTIMATE_REPORT_OCTETS * 8.0 / share)
                        .min(self.max_interval.as_secs_f64()),
                )
                .clamp(MIN_ADAPTIVE_INTERVAL, self.max_interval)
            }
            CongestionFeedbackCadence::ReceivedMedia => {
                let share = match self.negotiated.rr {
                    Some(rr) => rr as f64,
                    None => self.share * self.media_bits_per_second(now),
                };
                if share <= 0.0 {
                    return self.max_interval;
                }
                Duration::from_secs_f64(
                    (self.packet_octets() * 8.0 / share).min(self.max_interval.as_secs_f64()),
                )
                .clamp(MIN_ADAPTIVE_INTERVAL, self.max_interval)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Attribute, AttributedPacket};
    use shared::TransportContext;
    use std::sync::Arc;

    /// The received-media form (the `Performance` profile's).
    fn received_media(floor: Duration, adaptive: bool) -> FeedbackCadence {
        FeedbackCadence::new(floor, adaptive).with_form(CongestionFeedbackCadence::ReceivedMedia)
    }

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
    /// packet with its lower layers is 96 octets: one every 0.24 s.
    #[test]
    fn the_interval_holds_the_feedback_in_five_percent_of_the_media() {
        let mut cadence = received_media(Duration::from_millis(100), true);
        let now = after_media(&mut cadence, 64_000.0);
        let interval = cadence.interval(now).as_secs_f64();
        assert!((0.22..=0.25).contains(&interval), "{interval}");
    }

    /// With much media the interval stops at 50 ms; with little, at 250 ms.
    #[test]
    fn the_interval_is_held_between_50_and_250_ms() {
        let mut fast = received_media(Duration::from_millis(100), true);
        let now = after_media(&mut fast, 5_000_000.0);
        assert_eq!(MIN_ADAPTIVE_INTERVAL, fast.interval(now));
        let mut slow = received_media(Duration::from_millis(100), true);
        let now = after_media(&mut slow, 16_000.0);
        assert_eq!(MAX_ADAPTIVE_INTERVAL, slow.interval(now));
        let idle = received_media(Duration::from_millis(100), true);
        assert_eq!(MAX_ADAPTIVE_INTERVAL, idle.interval(Instant::now()));
    }

    /// Reduced-size RTCP (RFC 5506) takes the report without the compound packet around it,
    /// and the interval shortens with it.
    #[test]
    fn reduced_size_rtcp_shortens_the_interval() {
        let mut compound = received_media(Duration::from_millis(50), true);
        let now = after_media(&mut compound, 100_000.0);
        let mut reduced = received_media(Duration::from_millis(50), true);
        let then = after_media(&mut reduced, 100_000.0);
        reduced.on_write(&RtcpSessionControl::ReducedSize(true).into_packet(then));
        assert!(reduced.interval(then) < compound.interval(now).mul_f64(0.8));
    }

    /// `b=RR` (RFC 3556) replaces the 5%.
    #[test]
    fn negotiated_receiver_rtcp_bandwidth_sets_the_interval() {
        let mut cadence = received_media(Duration::from_millis(50), true);
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
        let mut cadence = received_media(Duration::from_millis(100), true);
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
        let mut cadence = received_media(Duration::from_millis(100), true)
            .with_limits(0.025, Duration::from_millis(500));
        let now = after_media(&mut cadence, 32_000.0);
        cadence.on_write(&RtcpSessionControl::ReducedSize(true).into_packet(now));
        assert_eq!(Duration::from_millis(500), cadence.interval(now));
        let mut default = received_media(Duration::from_millis(100), true);
        let then = after_media(&mut default, 32_000.0);
        assert_eq!(MAX_ADAPTIVE_INTERVAL, default.interval(then));
        // At 300 kbit/s the share, not the ceiling, sets it: 68 * 8 / 7500 = 72 ms.
        let mut faster = received_media(Duration::from_millis(100), true)
            .with_limits(0.025, Duration::from_millis(500));
        let now = after_media(&mut faster, 300_000.0);
        faster.on_write(&RtcpSessionControl::ReducedSize(true).into_packet(now));
        let interval = faster.interval(now).as_secs_f64();
        assert!((0.065..=0.08).contains(&interval), "{interval}");
    }

    fn stream(ssrc: u32, mime_type: &str) -> StreamInfo {
        StreamInfo {
            ssrc,
            mime_type: mime_type.to_owned(),
            ..Default::default()
        }
    }

    fn packet(now: Instant, ssrc: u32, marker: bool) -> TaggedPacket {
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    ssrc,
                    marker,
                    ..Default::default()
                },
                payload: vec![0u8; 100].into(),
            })),
        }
    }

    /// What the RTCP session and the congestion controller attach on the way up.
    fn carrier<T: Send + Sync + 'static>(now: Instant, value: T) -> TaggedPacket {
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![]))
                .with(Attribute::Custom(Arc::new(value))),
        }
    }

    /// draft-ietf-rmcat-gcc-02 section 3: "once per received video frame". A session of one
    /// video stream is reported when a frame ends (the marker), and after 100 ms without.
    #[test]
    fn one_video_stream_is_reported_when_a_frame_ends() {
        let mut cadence = FeedbackCadence::new(Duration::from_millis(100), true);
        cadence.bind_remote(&stream(1, "video/VP8"));
        let now = Instant::now();
        assert!(!cadence.on_packet(&packet(now, 1, false)));
        assert!(cadence.on_packet(&packet(now, 1, true)), "the frame ended");
        // A packet of another SSRC (the stream's RTX, say) ends no frame of it.
        assert!(!cadence.on_packet(&packet(now, 2, true)));
        assert_eq!(PER_FRAME_MAX_INTERVAL, cadence.interval(now));
    }

    /// "or at least once every 30 ms if audio-only or multi-stream".
    #[test]
    fn audio_only_and_several_streams_are_reported_every_30_ms() {
        let now = Instant::now();
        let mut audio = FeedbackCadence::new(Duration::from_millis(100), true);
        audio.bind_remote(&stream(1, "audio/opus"));
        assert_eq!(PER_FRAME_INTERVAL, audio.interval(now));
        assert!(
            !audio.on_packet(&packet(now, 1, true)),
            "a talk spurt's marker"
        );

        let mut both = FeedbackCadence::new(Duration::from_millis(100), true);
        both.bind_remote(&stream(1, "audio/opus"));
        both.bind_remote(&stream(2, "video/VP8"));
        assert_eq!(PER_FRAME_INTERVAL, both.interval(now));
        assert!(
            !both.on_packet(&packet(now, 2, true)),
            "the timer reports it"
        );
        // The audio stream ends: one video stream is left, reported per frame.
        both.unbind_remote(&stream(1, "audio/opus"));
        assert!(both.on_packet(&packet(now, 2, true)));
    }

    /// "If the feedback overhead needs to be limited this interval can be increased to 100
    /// ms": where this endpoint's share of the RTCP bandwidth does not hold a feedback packet
    /// (40 octets, 96 with the minimal compound packet and lower layers) every 30 ms, the
    /// interval is the time in which it holds one, 100 ms at most.
    #[test]
    fn the_interval_grows_to_100_ms_where_the_rtcp_bandwidth_does_not_hold_it() {
        let now = Instant::now();
        let mut cadence = FeedbackCadence::new(Duration::from_millis(100), true);
        cadence.bind_remote(&stream(1, "audio/opus"));
        let share = |bits_per_second: f64| carrier(now, RtcpBandwidthShare { bits_per_second });
        // 96 octets every 30 ms are 25.6 kbit/s: a share of 100 kbit/s holds them.
        cadence.on_packet(&share(100_000.0));
        assert_eq!(PER_FRAME_INTERVAL, cadence.interval(now));
        // 15.36 kbit/s hold one every 50 ms.
        cadence.on_packet(&share(15_360.0));
        assert_eq!(Duration::from_millis(50), cadence.interval(now));
        // 3.8 kbit/s (an audio call's) would hold one every 202 ms: 100 ms, the draft's most.
        cadence.on_packet(&share(3_800.0));
        assert_eq!(PER_FRAME_MAX_INTERVAL, cadence.interval(now));
        cadence.on_packet(&share(0.0));
        assert_eq!(PER_FRAME_MAX_INTERVAL, cadence.interval(now));

        // One video stream: a frame that ends sooner after the last report than the share
        // holds is left to the next one.
        let mut video = FeedbackCadence::new(Duration::from_millis(100), true);
        video.bind_remote(&stream(1, "video/VP8"));
        video.on_packet(&share(15_360.0));
        video.reported(now);
        let at = |ms: u64| now + Duration::from_millis(ms);
        assert!(!video.on_packet(&packet(at(33), 1, true)));
        assert!(video.on_packet(&packet(at(66), 1, true)));
    }

    /// libwebrtc `OnSendBandwidthEstimateChanged`: 100 ms until an estimate is known, then the
    /// time in which 5% of the send estimate holds 68 octets, between 50 and 250 ms.
    #[test]
    fn the_send_estimate_form_is_libwebrtcs_interval() {
        let now = Instant::now();
        let mut cadence = FeedbackCadence::new(Duration::from_millis(100), true)
            .with_form(CongestionFeedbackCadence::SendEstimate);
        cadence.bind_remote(&stream(1, "video/VP8"));
        assert_eq!(Duration::from_millis(100), cadence.interval(now));
        assert!(
            !cadence.on_packet(&packet(now, 1, true)),
            "no per-frame report"
        );
        let estimate = |bits_per_second: f64| carrier(now, crate::SendEstimate { bits_per_second });
        cadence.on_packet(&estimate(1_000_000.0));
        assert_eq!(MIN_ADAPTIVE_INTERVAL, cadence.interval(now));
        // 68 * 8 / (0.05 * 100 000) = 108.8 ms.
        cadence.on_packet(&estimate(100_000.0));
        assert_eq!(Duration::from_micros(108_800), cadence.interval(now));
        cadence.on_packet(&estimate(20_000.0));
        assert_eq!(MAX_ADAPTIVE_INTERVAL, cadence.interval(now));
        // The media received does not move it.
        let now = after_media(&mut cadence, 5_000_000.0);
        assert_eq!(MAX_ADAPTIVE_INTERVAL, cadence.interval(now));
    }

    /// The fixed setting ignores all of it.
    #[test]
    fn a_fixed_interval_stays_fixed() {
        let mut cadence = received_media(Duration::from_millis(100), false);
        let now = after_media(&mut cadence, 64_000.0);
        assert_eq!(Duration::from_millis(100), cadence.interval(now));
    }
}
