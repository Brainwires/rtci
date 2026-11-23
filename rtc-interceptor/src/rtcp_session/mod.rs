//! The RTCP session of an endpoint: who it is, when it speaks and what a packet looks like.
//!
//! See [`RtcpSessionInterceptor`].

pub(crate) mod identity;
pub(crate) mod scheduler;

use crate::report::receiver_stream::ReceiverStream;
use crate::report::sender_stream::SenderStream;
use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Interceptor, Packet, TaggedPacket};
use identity::{RtcpRandom, ThreadRandom, choose_ssrc, generate_cname};
use rtcp::extended_report::{
    DLRRReport, DLRRReportBlock, ExtendedReport, ReceiverReferenceTimeReportBlock,
};
use rtcp::goodbye::Goodbye;
use rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtcp::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate;
use rtcp::payload_feedbacks::slice_loss_indication::SliceLossIndication;
use rtcp::receiver_report::ReceiverReport;
use rtcp::reception_report::ReceptionReport;
use rtcp::sender_report::SenderReport;
use rtcp::source_description::{
    SdesType, SourceDescription, SourceDescriptionChunk, SourceDescriptionItem,
};
use rtcp::transport_feedbacks::cc_feedback_report::CcFeedbackReport;
use rtcp::transport_feedbacks::rapid_resynchronization_request::RapidResynchronizationRequest;
use rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
use rtcp::transport_feedbacks::transport_layer_nack::{
    TransportLayerNack, nack_pairs_from_sequence_numbers,
};
use sansio::Protocol;
use scheduler::{
    BYE_BACKOFF_MEMBERS, IntervalInput, LOWER_LAYER_OVERHEAD, RTCP_BW_FRACTION, RTCP_MIN_TIME,
    RTCP_SENDER_BW_FRACTION, RegularDecision, TIMEOUT_MULTIPLIER, Timing, after,
    deterministic_interval, randomized_interval, reduced_minimum, regular_decision,
    seconds_between, update_avg_rtcp_size,
};
use shared::TransportContext;
use shared::error::Error;
use shared::marshal::MarshalSize;
use shared::time::SystemInstant;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The session bandwidth assumed while none is configured and no media has been measured:
/// one audio stream.
pub const RTCP_SESSION_MIN_BANDWIDTH: u64 = 64_000;
/// The session bandwidth assumed for video at the start, while no `b=` line gave one and the
/// media has not yet had its two seconds to be measured: 1 Mbit/s, a camera stream at
/// standard definition.
///
/// RFC 3550 section 6.2 takes the RTCP bandwidth as a share of the session bandwidth, which
/// it lets "a session management application" supply; without one the session measures the
/// media, both ways, over the last two seconds (64 kbit/s at least). Before there is anything
/// to measure, this start-up value (with [`RTCP_SESSION_NOMINAL_AUDIO_BANDWIDTH`] for audio)
/// stands in, so the first reports are not held to an idle session's share. Congestion
/// control feedback does not depend on it: it follows the media it reports on
/// ([`RtcpSessionBuilder::with_immediate_congestion_feedback`]).
pub const RTCP_SESSION_NOMINAL_VIDEO_BANDWIDTH: u64 = 1_000_000;
/// The session bandwidth assumed for audio while none was signalled: 64 kbit/s, an Opus
/// stream at its high end for speech and the floor the session has always had.
pub const RTCP_SESSION_NOMINAL_AUDIO_BANDWIDTH: u64 = RTCP_SESSION_MIN_BANDWIDTH;

/// The nominal session bandwidth of a session that carries video and / or audio, bits per
/// second (see [`RTCP_SESSION_NOMINAL_VIDEO_BANDWIDTH`]).
pub(crate) fn nominal_session_bandwidth(video: bool, audio: bool) -> f64 {
    let mut nominal = 0;
    if video {
        nominal += RTCP_SESSION_NOMINAL_VIDEO_BANDWIDTH;
    }
    if audio {
        nominal += RTCP_SESSION_NOMINAL_AUDIO_BANDWIDTH;
    }
    nominal.max(RTCP_SESSION_MIN_BANDWIDTH) as f64
}

/// The default of [`RtcpSessionBuilder::with_t_rr_interval`].
pub const RTCP_SESSION_DEFAULT_T_RR_INTERVAL: Duration = Duration::from_secs(1);
/// The default of [`RtcpSessionBuilder::with_mtu`]: the size a compound RTCP packet is kept
/// under, SRTCP and lower layers not counted.
pub const RTCP_SESSION_DEFAULT_MTU: usize = 1200;

/// The most sources the member table holds; RTCP from further unknown SSRCs is not counted.
const MAX_MEMBERS: usize = 1024;
/// The most feedback and other packets held for the next compound packet.
const MAX_PENDING: usize = 64;
/// The most receiver reference times held for answering at once.
const MAX_REFERENCE_TIMES: usize = 64;
/// The most timer expiries worked through in one call: a session left alone for long catches
/// up to here and starts over from the present.
const MAX_CATCH_UP: usize = 4096;
/// The window the media bitrate is measured over when no session bandwidth is configured.
const RATE_WINDOW: Duration = Duration::from_secs(2);
/// The size of one bucket of that window.
const RATE_BUCKET: Duration = Duration::from_millis(250);
/// RFC 5506 4.2.2: a feedback packet larger than this goes out compound, not reduced-size.
const REDUCED_SIZE_MAX: usize = 400;
/// RFC 5506 4.2.1: this many reduced-size NACK packets in a row with none of the packets
/// they asked for arriving, and the session falls back to compound packets.
const REDUCED_SIZE_UNANSWERED_LIMIT: u32 = 8;
/// The most report blocks one SR or RR carries (RFC 3550 6.4.1: RC is five bits).
const MAX_REPORT_BLOCKS: usize = 31;

/// The fraction lost (in 1/256: about 10%) from which a stream's report goes before the round
/// robin when not every report fits (RFC 8083 section 4.3).
const HIGH_LOSS_FRACTION: u8 = 26;
/// The least interval the session computes, in seconds. RTP/AVPF has no minimum for a
/// point-to-point session (RFC 4585 3.5.1), so with enough bandwidth the calculated interval
/// tends to nothing; a timer cannot.
const MIN_INTERVAL: f64 = 0.005;

/// The RTP profile whose RTCP timing rules apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RtcpProfile {
    /// RTP/AVP and RTP/SAVP (RFC 3551): a five second minimum interval, no early feedback.
    Avp,
    /// RTP/AVPF and RTP/SAVPF (RFC 4585): early feedback, `T_rr_interval`. What WebRTC uses.
    #[default]
    Avpf,
}

/// The bandwidth figures a session description gives for RTCP, all in bits per second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtcpBandwidth {
    /// The session bandwidth (`b=TIAS`, or `b=AS` times 1000). RTCP gets 5% of it unless
    /// `rs` and `rr` say otherwise. `None`: the media bitrate measured over the last two
    /// seconds, with a start-up value before that ([`RTCP_SESSION_NOMINAL_VIDEO_BANDWIDTH`]).
    pub session: Option<u64>,
    /// `b=RS` (RFC 3556): the RTCP bandwidth of the senders.
    pub rs: Option<u64>,
    /// `b=RR` (RFC 3556): the RTCP bandwidth of the receivers.
    pub rr: Option<u64>,
}

/// What an application (or the peer connection) tells the session while it runs.
///
/// It travels as an [`Attribute::Custom`] on an empty RTCP packet written into the chain
/// ([`RtcpSessionControl::into_packet`]); the session takes it off the belt.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RtcpSessionControl {
    /// The transport is up: the session joins now, without waiting for a first packet.
    Start,
    /// The CNAME of this endpoint, the one its session description announces.
    Cname(String),
    /// The negotiated bandwidth (`b=` lines).
    Bandwidth(RtcpBandwidth),
    /// Whether reduced-size RTCP (`a=rtcp-rsize`, RFC 5506) was negotiated.
    ReducedSize(bool),
    /// The octets SRTCP adds to every compound packet: the E flag and SRTCP index, the
    /// authentication tag and the MKI. RFC 3711 section 3.4: they are part of the packet size
    /// avg_rtcp_size is computed from, the initial estimate included. Give it before
    /// [`Self::Start`]; 0 (the default) for plain RTCP.
    SrtcpOverhead(usize),
    /// The negotiated `trr-int` (RFC 4585 4.2), the minimum interval between regular reports.
    TrrInt(Duration),
    /// The negotiation has no `trr-int` (any more): the interval the session was built with
    /// ([`RtcpSessionBuilder::with_t_rr_interval`]) applies again.
    TrrIntCleared,
    /// The endpoint leaves the session: every local SSRC says BYE.
    Leave,
    /// What identifies the local stream `ssrc` beyond the CNAME: the identification-tag of
    /// its m= section (RFC 9143 section 15.1, SDES `MID`), its RtpStreamId (RFC 8852 section
    /// 3.1) and, for a redundancy stream (RTX, FEC), the RepairedRtpStreamId of the stream it
    /// repairs (section 3.2). Each given value is an item of the SSRC's SDES chunk in every
    /// compound packet: RFC 9143 section 15 wants the MID "in the first few RTCP packets after
    /// joining the session and ... regularly thereafter". All `None` forgets the SSRC's items;
    /// the items of an SSRC that is no longer bound go when the next ones are given.
    StreamIdentifiers {
        /// The local SSRC.
        ssrc: u32,
        /// The m= section's `a=mid`.
        mid: Option<String>,
        /// The RtpStreamId (the encoding's rid).
        rid: Option<String>,
        /// The RepairedRtpStreamId (the rid of the stream a redundancy stream repairs).
        repaired_rid: Option<String>,
    },
}

impl RtcpSessionControl {
    /// The packet that carries this to the session when written into the chain at `now`.
    pub fn into_packet(self, now: Instant) -> TaggedPacket {
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![]))
                .with(Attribute::Custom(Arc::new(self))),
        }
    }
}

/// What the session tells the rest of the chain and the peer connection.
///
/// It travels application-ward as an [`Attribute::Custom`] on an empty RTCP packet; read it
/// with [`AttributedPacket::custom`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RtcpSessionEvent {
    /// RFC 3550 8.2: a packet arrived from another source that uses `ssrc`, one of this
    /// endpoint's own. `replacement` is an SSRC no known source uses, for the stream to move
    /// to; a reporting SSRC the session chose itself has already moved.
    SsrcCollision {
        /// The local SSRC another source uses too.
        ssrc: u32,
        /// An unused SSRC to replace it with.
        replacement: u32,
    },
    /// RFC 3550 6.5.1: the remote source `ssrc` named its CNAME (or changed it).
    RemoteCname {
        /// The remote SSRC.
        ssrc: u32,
        /// Its canonical name.
        cname: String,
    },
    /// RFC 3550 6.3.5: nothing was heard from the remote source for five report intervals.
    SourceTimedOut {
        /// The remote SSRC.
        ssrc: u32,
    },
    /// RFC 3550 6.4.1: the round-trip time to the receiver that reported on the local `ssrc`.
    RoundTripTime {
        /// The local SSRC the report block was about.
        ssrc: u32,
        /// The round trip.
        rtt: Duration,
    },
}

/// Builder for [`RtcpSessionInterceptor`].
///
/// ```
/// use rtc_interceptor::{Registry, RtcpSessionBuilder, Slot};
///
/// let chain = Registry::new()
///     .with(Slot::RtcpSession, RtcpSessionBuilder::new().build())
///     .build();
/// # let _ = chain;
/// ```
pub struct RtcpSessionBuilder {
    profile: RtcpProfile,
    t_rr_interval: Duration,
    bandwidth: RtcpBandwidth,
    rtcp_fraction: f64,
    reduced_minimum: bool,
    reduced_size: bool,
    mtu: usize,
    cname: Option<String>,
    point_to_point: Option<bool>,
    report_from_every_ssrc: bool,
    immediate_congestion_feedback: bool,
    random: Box<dyn RtcpRandom>,
}

impl Default for RtcpSessionBuilder {
    fn default() -> Self {
        Self {
            profile: RtcpProfile::default(),
            t_rr_interval: RTCP_SESSION_DEFAULT_T_RR_INTERVAL,
            bandwidth: RtcpBandwidth::default(),
            rtcp_fraction: RTCP_BW_FRACTION,
            reduced_minimum: false,
            reduced_size: false,
            mtu: RTCP_SESSION_DEFAULT_MTU,
            cname: None,
            point_to_point: None,
            report_from_every_ssrc: false,
            immediate_congestion_feedback: true,
            random: Box::new(ThreadRandom),
        }
    }
}

impl RtcpSessionBuilder {
    /// A builder with the defaults: RTP/AVPF timing, a `T_rr_interval` of one second, RTCP at
    /// 5% of the measured media bitrate (a start-up value before it is measured), compound
    /// packets only, congestion control feedback sent as it is built.
    pub fn new() -> Self {
        Self::default()
    }

    /// The profile whose timing rules apply. Default: [`RtcpProfile::Avpf`].
    pub fn with_profile(mut self, profile: RtcpProfile) -> Self {
        self.profile = profile;
        self
    }

    /// `T_rr_interval` (RFC 4585 3.4): the minimum interval between regular (full compound)
    /// reports under RTP/AVPF. Feedback is not held by it.
    ///
    /// RFC 4585 4.2 makes the value zero when `trr-int` is not negotiated, which lets regular
    /// reports use the whole RTCP bandwidth: a report every few tens of milliseconds beside a
    /// video stream. The default here is one second (what this engine sent before, and what
    /// browsers send); a negotiated `trr-int` ([`RtcpSessionControl::TrrInt`]) replaces it,
    /// and zero gives the RFC's default.
    pub fn with_t_rr_interval(mut self, t_rr_interval: Duration) -> Self {
        self.t_rr_interval = t_rr_interval;
        self
    }

    /// The bandwidth the session description gives (`b=AS` / `b=TIAS`, `b=RS`, `b=RR`).
    /// Default: none, so the media bitrate is measured and RTCP gets 5% of it.
    pub fn with_bandwidth(mut self, bandwidth: RtcpBandwidth) -> Self {
        self.bandwidth = bandwidth;
        self
    }

    /// The share of the session bandwidth RTCP uses when `b=RS` / `b=RR` do not say. Default:
    /// 0.05, the value RFC 3550 6.2 recommends.
    pub fn with_rtcp_fraction(mut self, fraction: f64) -> Self {
        self.rtcp_fraction = fraction.clamp(0.0, 1.0);
        self
    }

    /// Under RTP/AVP, use the reduced minimum interval of RFC 3550 6.2 (360 divided by the
    /// session bandwidth in kbit/s) instead of five seconds.
    pub fn with_reduced_minimum(mut self, reduced_minimum: bool) -> Self {
        self.reduced_minimum = reduced_minimum;
        self
    }

    /// Whether reduced-size RTCP (RFC 5506) was negotiated. Default: no, every packet is a
    /// compound packet.
    pub fn with_reduced_size(mut self, reduced_size: bool) -> Self {
        self.reduced_size = reduced_size;
        self
    }

    /// The size compound packets are kept under (RFC 3550 6.1). Default:
    /// [`RTCP_SESSION_DEFAULT_MTU`].
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu.max(128);
        self
    }

    /// The CNAME to use. Default: one generated as RFC 7022 section 4.2 describes.
    pub fn with_cname(mut self, cname: impl Into<String>) -> Self {
        self.cname = Some(cname.into());
        self
    }

    /// Says whether the session is point to point instead of leaving it to the count of
    /// remote CNAMEs (RFC 8108 5.4.2: "unless signaling indicates").
    pub fn with_point_to_point(mut self, point_to_point: bool) -> Self {
        self.point_to_point = Some(point_to_point);
        self
    }

    /// RFC 8108 5.1 to the letter: every local SSRC carries a report block for every remote
    /// SSRC. Default: off, the blocks are carried once, by the first local media SSRC (what
    /// browsers do, and what RFC 8861 reporting groups exist to allow).
    pub fn with_report_from_every_ssrc(mut self, every: bool) -> Self {
        self.report_from_every_ssrc = every;
        self
    }

    /// Whether congestion control feedback (transport-wide feedback, RFC 8888 reports) leaves
    /// as soon as its generator writes it (the default), or waits its turn under RFC 4585
    /// section 3.5.2 like other feedback: at most one Early packet per regular interval.
    ///
    /// The generators size their own cadence to 5% of the media they report on, between 50
    /// and 250 ms (`TwccReceiverBuilder::with_adaptive_interval`): congestion control feedback
    /// is the sender's congestion signal and is not held to the RTCP bandwidth the regular
    /// reports share, as libwebrtc and the browsers send it. It goes as a reduced-size packet
    /// where `a=rtcp-rsize` was negotiated, else in a minimal compound packet, and does not
    /// move the regular reports' timing. `false` is RFC 4585 as written: at low media rates
    /// the session then sends feedback a few times a second, with gaps a sender's estimator
    /// does not climb through.
    pub fn with_immediate_congestion_feedback(mut self, immediate: bool) -> Self {
        self.immediate_congestion_feedback = immediate;
        self
    }

    /// The source of the session's random numbers; a test supplies one that repeats.
    pub fn with_random(mut self, random: impl RtcpRandom + 'static) -> Self {
        self.random = Box::new(random);
        self
    }

    /// Builds the interceptor.
    pub fn build(mut self) -> RtcpSessionInterceptor {
        let cname = self
            .cname
            .take()
            .unwrap_or_else(|| generate_cname(self.random.as_mut()));
        RtcpSessionInterceptor {
            profile: self.profile,
            t_rr_interval: self.t_rr_interval.as_secs_f64(),
            configured_t_rr_interval: self.t_rr_interval.as_secs_f64(),
            bandwidth: self.bandwidth,
            rtcp_fraction: self.rtcp_fraction,
            reduced_minimum: self.reduced_minimum,
            reduced_size: self.reduced_size,
            mtu: self.mtu,
            cname,
            point_to_point: self.point_to_point,
            report_from_every_ssrc: self.report_from_every_ssrc,
            random: self.random,

            started: false,
            left: false,
            locals: Vec::new(),
            departing: Vec::new(),
            remotes: HashMap::new(),
            remote_order: Vec::new(),
            report_cursor: 0,
            members: HashMap::new(),
            pmembers: 0,
            avg_rtcp_size: 0.0,
            srtcp_overhead: 0,
            rate: RateWindow::default(),
            immediate_congestion_feedback: self.immediate_congestion_feedback,
            outside_budget: false,
            pending: Vec::new(),
            early_at: None,
            compound_sent: false,
            reference_times: HashMap::new(),
            wall_clock: None,
            reduced_size_failed: false,
            unanswered_reduced_nacks: 0,
            awaited: None,
            collided: HashSet::new(),
            said_bye: HashMap::new(),
            identifiers: HashMap::new(),
            bye: None,
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Audio,
    Video,
    Other,
}

impl Kind {
    fn of(mime_type: &str) -> Self {
        let mime_type = mime_type.to_ascii_lowercase();
        if mime_type.starts_with("audio/") {
            Kind::Audio
        } else if mime_type.starts_with("video/") {
            Kind::Video
        } else {
            Kind::Other
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// The SSRC of a media stream this endpoint is set up to send.
    Media,
    /// An RTX or FEC SSRC: a participant once it has sent.
    Repair,
    /// The SSRC the session chose to report from while the endpoint has no media SSRC.
    Reporter,
}

/// One of this endpoint's SSRCs.
struct Local {
    ssrc: u32,
    kind: Kind,
    role: Role,
    stream: SenderStream,
    /// `None` until the SSRC takes part and the session has started.
    timing: Option<Timing>,
    last_rtp: Option<Instant>,
    rtp_sent: bool,
    rtcp_sent: bool,
    /// The compact NTP timestamps of the last sender reports and when each was sent, for the
    /// round-trip time (RFC 3550 6.4.1).
    sent_reports: VecDeque<(u32, Instant)>,
}

impl Local {
    fn new(ssrc: u32, kind: Kind, role: Role, clock_rate: u32) -> Self {
        Self {
            ssrc,
            kind,
            role,
            stream: SenderStream::new(ssrc, clock_rate, false),
            timing: None,
            last_rtp: None,
            rtp_sent: false,
            rtcp_sent: false,
            sent_reports: VecDeque::new(),
        }
    }

    /// Whether the SSRC is a participant of the session: a repair SSRC is one from its first
    /// packet on.
    fn participates(&self) -> bool {
        self.role != Role::Repair || self.rtp_sent
    }
}

/// A remote stream bound for reception.
struct Remote {
    stream: ReceiverStream,
    kind: Kind,
    /// Whether receiver reference times (RFC 3611 4.4) were negotiated for it.
    rrtr: bool,
    /// The source said BYE or timed out: it is not reported on until it is heard again.
    gone: bool,
}

/// A source in the member table (RFC 3550 6.2.1).
struct Member {
    last_heard: Instant,
    last_rtp: Option<Instant>,
    cname: Option<String>,
}

/// RFC 3550 6.3.7: a BYE waiting its turn in a session of more than fifty members.
struct ByeBackoff {
    packets: Vec<Box<dyn rtcp::Packet>>,
    size: f64,
    tp: Instant,
    tn: Instant,
    /// The BYE packets counted so far, this one included.
    members: usize,
}

/// The media bitrate of the last seconds, for a session whose bandwidth nobody stated.
#[derive(Default)]
struct RateWindow {
    buckets: VecDeque<(Instant, u64)>,
    first: Option<Instant>,
}

impl RateWindow {
    fn add(&mut self, now: Instant, octets: usize) {
        self.first.get_or_insert(now);
        match self.buckets.back_mut() {
            Some((start, sum)) if now.saturating_duration_since(*start) < RATE_BUCKET => {
                *sum += octets as u64;
            }
            _ => self.buckets.push_back((now, octets as u64)),
        }
        while self
            .buckets
            .front()
            .is_some_and(|(start, _)| now.saturating_duration_since(*start) > RATE_WINDOW)
        {
            self.buckets.pop_front();
        }
    }

    fn bits_per_second(&self, now: Instant) -> f64 {
        let Some(first) = self.first else {
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
            .clamp(RATE_BUCKET, RATE_WINDOW);
        octets as f64 * 8.0 / span.as_secs_f64()
    }
}

/// How a compound packet is put together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// A regular report: every due SSRC's SR or RR with the report blocks, SDES, XR.
    Full,
    /// RFC 4585 3.1: the minimal compound packet that carries feedback: one SR or RR without
    /// report blocks, SDES, the feedback.
    Minimal,
}

/// The RTCP session of an endpoint (RFC 3550 section 6, RFC 4585 section 3, RFC 8108).
///
/// One interceptor, closest to the wire, is the endpoint's whole RTCP voice:
///
/// - **Identity.** One CNAME for every local SSRC (RFC 7022: 96 random bits, Base64), given
///   or generated. Reports and feedback come from the local media SSRCs; an endpoint with
///   none reports from one SSRC the session chooses (never zero, never one in use). Every
///   feedback packet the interceptors above or the application write leaves with the packet
///   sender SSRC of this endpoint (RFC 8108 5.4.1), whatever they filled in.
/// - **Reports.** A sender report for every SSRC that sent RTP in the last two intervals, RTX
///   and FEC SSRCs included; a receiver report otherwise (RFC 3550 6.4). Reception report
///   blocks for the remote streams (RFC 3550 Appendix A.3), an SDES CNAME for every reporting
///   SSRC, XR receiver reference time and DLRR blocks (RFC 3611).
/// - **Timing.** The interval of RFC 3550 6.3 from the member and sender counts, the average
///   packet size and the RTCP bandwidth, randomised, with timer reconsideration and reverse
///   reconsideration; the early feedback rules of RFC 4585 3.5 and `T_rr_interval`; one timer
///   per local SSRC, aggregated into one compound packet (RFC 8108 5.3).
/// - **Packets.** Everything leaves as a compound packet (SR or RR first, then SDES) unless
///   reduced-size RTCP was negotiated (RFC 5506), kept under the MTU.
/// - **Membership.** Sources heard in RTP and RTCP, their CNAMEs, BYE, the timeout after five
///   intervals, sender status over two; BYE for a local SSRC that stops and for all of them
///   when the endpoint leaves; a collision with one of the endpoint's own SSRCs.
///
/// It replaces [`SenderReportInterceptor`](crate::SenderReportInterceptor) and
/// [`ReceiverReportInterceptor`](crate::ReceiverReportInterceptor), which report on fixed
/// timers: a sender or receiver report those (or the application) write is dropped here, the
/// session's own stand for it.
///
/// # Where it goes
///
/// [`Slot::RtcpSession`](crate::Slot::RtcpSession), wire-ward of everything: it counts what
/// leaves (retransmissions and FEC included) and what arrives, and every RTCP packet the
/// chain writes passes it last.
///
/// # Inputs and outputs
///
/// What a session description negotiates is handed in with the builder or, while running,
/// as an [`RtcpSessionControl`]. What the session learns leaves as an [`RtcpSessionEvent`].
pub struct RtcpSessionInterceptor {
    profile: RtcpProfile,
    /// Seconds.
    t_rr_interval: f64,
    /// Seconds: the builder's, which [`RtcpSessionControl::TrrIntCleared`] goes back to.
    configured_t_rr_interval: f64,
    bandwidth: RtcpBandwidth,
    rtcp_fraction: f64,
    reduced_minimum: bool,
    reduced_size: bool,
    mtu: usize,
    cname: String,
    point_to_point: Option<bool>,
    report_from_every_ssrc: bool,
    random: Box<dyn RtcpRandom>,

    started: bool,
    left: bool,
    /// In the order they were bound.
    locals: Vec<Local>,
    /// Local SSRCs unbound since the chain was last driven: each says BYE unless bound again.
    departing: Vec<Local>,
    /// The SDES items of a local SSRC after its CNAME ([`RtcpSessionControl::StreamIdentifiers`]).
    identifiers: HashMap<u32, Vec<SourceDescriptionItem>>,
    remotes: HashMap<u32, Remote>,
    /// The bound remote SSRCs in the order they were bound, for the round robin of report
    /// blocks.
    remote_order: Vec<u32>,
    report_cursor: usize,
    /// The remote members of the session.
    members: HashMap<u32, Member>,
    pmembers: usize,
    avg_rtcp_size: f64,
    /// What SRTCP adds to each compound packet ([`RtcpSessionControl::SrtcpOverhead`]).
    srtcp_overhead: usize,
    rate: RateWindow,
    /// Whether congestion control feedback leaves as soon as it is written.
    immediate_congestion_feedback: bool,
    /// Set while a packet is sent outside the RTCP bandwidth's timing (immediate congestion
    /// feedback): it does not move the average packet size the regular interval rests on.
    outside_budget: bool,
    /// Feedback and other packets waiting for a compound packet.
    pending: Vec<Box<dyn rtcp::Packet>>,
    /// RFC 4585 3.5.2: when the scheduled Early packet goes.
    early_at: Option<Instant>,
    /// Whether a compound packet has been sent (RFC 5506 4: none reduced-size before).
    compound_sent: bool,
    /// The receiver reference times received and not yet answered, by sender SSRC.
    reference_times: HashMap<u32, (u32, Instant)>,
    wall_clock: Option<SystemInstant>,
    reduced_size_failed: bool,
    unanswered_reduced_nacks: u32,
    /// The packets the last reduced-size NACK asked for.
    awaited: Option<(u32, Vec<u16>)>,
    /// Local media SSRCs a collision was reported for.
    collided: HashSet<u32>,
    /// Sources that said BYE and when (RFC 3550 6.2.1: the entry is kept, marked, for a
    /// while, so that a packet that was overtaken by the BYE does not bring the source back).
    said_bye: HashMap<u32, Instant>,
    bye: Option<ByeBackoff>,

    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

fn boxed<P: rtcp::Packet + 'static>(packet: P) -> Box<dyn rtcp::Packet> {
    Box::new(packet)
}

/// The size of `packets` on the wire, lower layers included.
fn wire_size(packets: &[Box<dyn rtcp::Packet>]) -> usize {
    LOWER_LAYER_OVERHEAD + packets.iter().map(|p| p.marshal_size()).sum::<usize>()
}

/// The number of SSRCs reporting in a compound packet (RFC 8108 5.3.1): the distinct sources
/// of its SR and RR packets, one for a packet without any.
fn reporting_ssrcs(packets: &[Box<dyn rtcp::Packet>]) -> usize {
    let mut sources: Vec<u32> = packets
        .iter()
        .filter_map(|packet| {
            let any = packet.as_any();
            any.downcast_ref::<SenderReport>()
                .map(|sr| sr.ssrc)
                .or_else(|| any.downcast_ref::<ReceiverReport>().map(|rr| rr.ssrc))
        })
        .collect();
    sources.sort_unstable();
    sources.dedup();
    sources.len().max(1)
}

/// The packet sender SSRC of a feedback or report packet, and the media SSRC a feedback
/// message is about.
fn sender_and_media(packet: &dyn rtcp::Packet) -> (Option<u32>, Option<u32>) {
    let any = packet.as_any();
    if let Some(p) = any.downcast_ref::<TransportLayerNack>() {
        (Some(p.sender_ssrc), Some(p.media_ssrc))
    } else if let Some(p) = any.downcast_ref::<PictureLossIndication>() {
        (Some(p.sender_ssrc), Some(p.media_ssrc))
    } else if let Some(p) = any.downcast_ref::<FullIntraRequest>() {
        (Some(p.sender_ssrc), p.fir.first().map(|entry| entry.ssrc))
    } else if let Some(p) = any.downcast_ref::<SliceLossIndication>() {
        (Some(p.sender_ssrc), Some(p.media_ssrc))
    } else if let Some(p) = any.downcast_ref::<ReceiverEstimatedMaximumBitrate>() {
        (Some(p.sender_ssrc), p.ssrcs.first().copied())
    } else if let Some(p) = any.downcast_ref::<TransportLayerCc>() {
        (Some(p.sender_ssrc), Some(p.media_ssrc))
    } else if let Some(p) = any.downcast_ref::<CcFeedbackReport>() {
        (Some(p.sender_ssrc), None)
    } else if let Some(p) = any.downcast_ref::<RapidResynchronizationRequest>() {
        (Some(p.sender_ssrc), Some(p.media_ssrc))
    } else if let Some(p) = any.downcast_ref::<ExtendedReport>() {
        (Some(p.sender_ssrc), None)
    } else if let Some(p) = any.downcast_ref::<SenderReport>() {
        (Some(p.ssrc), None)
    } else if let Some(p) = any.downcast_ref::<ReceiverReport>() {
        (Some(p.ssrc), None)
    } else {
        (None, None)
    }
}

/// `packet` with `ssrc` as its packet sender, for the types that name one.
fn with_sender(packet: Box<dyn rtcp::Packet>, ssrc: u32) -> Box<dyn rtcp::Packet> {
    macro_rules! rewrite {
        ($($ty:ty),*) => {
            $(if let Some(p) = packet.as_any().downcast_ref::<$ty>() {
                let mut p = p.clone();
                p.sender_ssrc = ssrc;
                return Box::new(p);
            })*
        };
    }
    rewrite!(
        TransportLayerNack,
        PictureLossIndication,
        FullIntraRequest,
        SliceLossIndication,
        ReceiverEstimatedMaximumBitrate,
        TransportLayerCc,
        CcFeedbackReport,
        RapidResynchronizationRequest,
        ExtendedReport
    );
    packet
}

/// RFC 5506 4.2.1: whether the delivery of `packet` shows in what the peer does next (a
/// retransmission, a key frame, a sender that goes on raising its rate), so it may travel
/// reduced-size on its own.
///
/// Congestion control feedback is of that kind: RFC 8888 section 3.1 has it sent "in a
/// non-compound RTCP packet if supported by the session participants", and a sender whose
/// feedback does not arrive cuts its rate (RFC 8888 section 5), which the receiver sees.
/// Without the report and SDES around it the feedback is half the size, and at low media
/// rates twice as many fit the RTCP bandwidth.
fn delivery_shows(packet: &dyn rtcp::Packet) -> bool {
    let any = packet.as_any();
    any.is::<TransportLayerNack>()
        || any.is::<PictureLossIndication>()
        || any.is::<FullIntraRequest>()
        || any.is::<TransportLayerCc>()
        || any.is::<CcFeedbackReport>()
}

impl RtcpSessionInterceptor {
    /// The CNAME this endpoint's SSRCs are described with.
    pub fn cname(&self) -> &str {
        &self.cname
    }

    fn unit(&mut self) -> f64 {
        self.random.unit()
    }

    fn emit(&mut self, now: Instant, event: RtcpSessionEvent) {
        self.read_queue.push_back(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![]))
                .with(Attribute::Custom(Arc::new(event))),
        });
    }

    fn send(&mut self, now: Instant, packets: Vec<Box<dyn rtcp::Packet>>) {
        if packets.is_empty() {
            return;
        }
        // RFC 3550 6.3.6 with RFC 8108 5.3.1: the average takes the size per reporting SSRC.
        if !self.outside_budget {
            let size = (wire_size(&packets) + self.srtcp_overhead) as f64
                / reporting_ssrcs(&packets) as f64;
            self.avg_rtcp_size = update_avg_rtcp_size(self.avg_rtcp_size, size);
        }
        self.write_queue.push_back(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(packets)),
        });
    }

    // ---- who is in the session -------------------------------------------------------

    fn local_index(&self, ssrc: u32) -> Option<usize> {
        self.locals.iter().position(|local| local.ssrc == ssrc)
    }

    fn ssrc_in_use(&self, ssrc: u32) -> bool {
        self.local_index(ssrc).is_some()
            || self.departing.iter().any(|local| local.ssrc == ssrc)
            || self.members.contains_key(&ssrc)
            || self.remotes.contains_key(&ssrc)
    }

    /// The local SSRC that carries the reception report blocks: the first media SSRC, or the
    /// session's own reporting SSRC.
    fn reporter(&self) -> Option<usize> {
        self.locals
            .iter()
            .position(|local| local.role == Role::Media)
            .or_else(|| {
                self.locals
                    .iter()
                    .position(|local| local.role == Role::Reporter)
            })
    }

    /// The local SSRC feedback about `media_ssrc` is sent from (RFC 8108 5.4.1): a media SSRC
    /// of the same kind as the stream when there is one, the reporter otherwise.
    fn feedback_source(&self, media_ssrc: Option<u32>) -> Option<usize> {
        let kind = media_ssrc
            .and_then(|ssrc| self.remotes.get(&ssrc))
            .map(|remote| remote.kind);
        kind.and_then(|kind| {
            self.locals
                .iter()
                .position(|local| local.role == Role::Media && local.kind == kind)
        })
        .or_else(|| self.reporter())
    }

    /// Keeps the session's own reporting SSRC while the endpoint has no media SSRC, and
    /// retires it when it has one (RFC 8108 6.2: with a BYE).
    fn sync_reporter(&mut self) {
        let has_media = self.locals.iter().any(|local| local.role == Role::Media);
        let reporter = self
            .locals
            .iter()
            .position(|local| local.role == Role::Reporter);
        match (has_media, reporter) {
            (true, Some(index)) => {
                let local = self.locals.remove(index);
                self.departing.push(local);
            }
            (false, None) if !self.left => {
                let mut random = std::mem::replace(&mut self.random, Box::new(ThreadRandom));
                let ssrc = choose_ssrc(random.as_mut(), |ssrc| self.ssrc_in_use(ssrc));
                self.random = random;
                self.locals
                    .push(Local::new(ssrc, Kind::Other, Role::Reporter, 90_000));
            }
            _ => {}
        }
    }

    fn member_count(&self) -> usize {
        self.members.len() + self.locals.iter().filter(|l| l.participates()).count()
    }

    /// RFC 8108 5.4.2: point to point unless the remote sources name more than one CNAME.
    fn is_point_to_point(&self) -> bool {
        if let Some(point_to_point) = self.point_to_point {
            return point_to_point;
        }
        let mut cnames = self.members.values().filter_map(|m| m.cname.as_deref());
        match cnames.next() {
            Some(first) => cnames.all(|cname| cname == first),
            None => true,
        }
    }

    // ---- bandwidth and intervals -----------------------------------------------------

    fn session_bandwidth(&self, now: Instant) -> f64 {
        match self.bandwidth.session {
            Some(session) => session as f64,
            None => {
                // RFC 3550 6.2 lets the session bandwidth be "supplied by a session
                // management application"; without one it is the media measured both ways
                // over the last seconds. (A congestion controller's target is not used: an
                // application-limited sender's target is many times what it sends.)
                let measured = self.rate.bits_per_second(now);
                // The nominal figure stands only until the media has had its window to be
                // measured: a start-up value, not the session bandwidth.
                let starting = self
                    .rate
                    .first
                    .is_none_or(|first| now.saturating_duration_since(first) < RATE_WINDOW);
                let measured = if starting {
                    measured.max(self.nominal_bandwidth())
                } else {
                    measured
                };
                measured.max(RTCP_SESSION_MIN_BANDWIDTH as f64)
            }
        }
    }

    /// The nominal session bandwidth of the media bound, when no `b=` line gave one.
    fn nominal_bandwidth(&self) -> f64 {
        let kinds = self
            .locals
            .iter()
            .filter(|local| local.role == Role::Media)
            .map(|local| local.kind)
            .chain(self.remotes.values().map(|remote| remote.kind));
        let (mut video, mut audio) = (false, false);
        for kind in kinds {
            match kind {
                Kind::Video => video = true,
                Kind::Audio => audio = true,
                Kind::Other => {}
            }
        }
        nominal_session_bandwidth(video, audio)
    }

    /// The RTCP bandwidth in octets per second and the senders' share of it.
    fn rtcp_bandwidth(&self, now: Instant) -> (f64, f64) {
        let session = self.session_bandwidth(now);
        // RFC 3556: a modifier that is absent keeps its default share of the 5%.
        let default_rs = session * self.rtcp_fraction * RTCP_SENDER_BW_FRACTION;
        let default_rr = session * self.rtcp_fraction * (1.0 - RTCP_SENDER_BW_FRACTION);
        match (self.bandwidth.rs, self.bandwidth.rr) {
            (None, None) => (session * self.rtcp_fraction / 8.0, RTCP_SENDER_BW_FRACTION),
            (rs, rr) => {
                let rs = rs.map_or(default_rs, |rs| rs as f64);
                let rr = rr.map_or(default_rr, |rr| rr as f64);
                let total = rs + rr;
                if total <= 0.0 {
                    (0.0, RTCP_SENDER_BW_FRACTION)
                } else {
                    (total / 8.0, rs / total)
                }
            }
        }
    }

    /// The minimum interval in force for a local SSRC.
    fn t_min(&self, now: Instant, initial: bool) -> f64 {
        match self.profile {
            RtcpProfile::Avp => {
                if self.reduced_minimum {
                    reduced_minimum(self.session_bandwidth(now))
                } else {
                    RTCP_MIN_TIME
                }
            }
            // RFC 4585 3.5.1 and 3.5.3: zero for a point-to-point session, one second for the
            // first packet of a multiparty one, zero after it.
            RtcpProfile::Avpf => {
                if initial && !self.is_point_to_point() {
                    1.0
                } else {
                    0.0
                }
            }
        }
    }

    /// RFC 3550 6.3.8: whether the local SSRC sent RTP within the last two report intervals.
    fn we_sent(&self, index: usize, now: Instant) -> bool {
        let horizon = 2.0 * self.report_interval(now);
        self.locals[index]
            .last_rtp
            .is_some_and(|last| now.saturating_duration_since(last).as_secs_f64() <= horizon)
    }

    /// The interval reports are made at, for the sender status of RFC 3550 6.3.5 and 6.3.8
    /// ("within the last two RTCP report intervals"): the interval at which the members
    /// share the RTCP bandwidth, no less than the profile's minimum, and under RTP/AVPF no
    /// less than `T_rr_interval`, inside which regular reports are suppressed.
    fn report_interval(&self, now: Instant) -> f64 {
        let (rtcp_bw, _) = self.rtcp_bandwidth(now);
        let shared = if rtcp_bw > 0.0 {
            self.avg_rtcp_size * self.member_count().max(1) as f64 / rtcp_bw
        } else {
            RTCP_MIN_TIME
        };
        let floor = match self.profile {
            RtcpProfile::Avp => self.t_min(now, false),
            RtcpProfile::Avpf => self.t_rr_interval,
        };
        shared.max(floor).max(MIN_INTERVAL)
    }

    fn sender_count(&self, now: Instant) -> usize {
        let horizon = 2.0 * self.report_interval(now);
        let sent_lately = |last_rtp: Option<Instant>| {
            last_rtp
                .is_some_and(|last| now.saturating_duration_since(last).as_secs_f64() <= horizon)
        };
        self.members
            .values()
            .filter(|member| sent_lately(member.last_rtp))
            .count()
            + self
                .locals
                .iter()
                .filter(|local| local.participates() && sent_lately(local.last_rtp))
                .count()
    }

    /// The input of the interval computation of RFC 3550 6.3.1.
    fn interval_input(
        &self,
        now: Instant,
        we_sent: bool,
        initial: bool,
        senders: usize,
    ) -> IntervalInput {
        let (rtcp_bw, sender_fraction) = self.rtcp_bandwidth(now);
        IntervalInput {
            members: self.member_count().max(1),
            senders,
            rtcp_bw,
            sender_fraction,
            we_sent,
            avg_rtcp_size: self.avg_rtcp_size,
            t_min: self.t_min(now, initial),
            initial,
        }
    }

    /// The calculated interval T of a local SSRC, randomised (RFC 3550 6.3.1).
    fn interval(&mut self, index: usize, now: Instant) -> f64 {
        let we_sent = self.we_sent(index, now);
        let initial = self.locals[index]
            .timing
            .is_none_or(|timing| timing.initial);
        let senders = self.sender_count(now);
        let td = deterministic_interval(&self.interval_input(now, we_sent, initial, senders));
        let random = self.unit();
        randomized_interval(td, random).max(MIN_INTERVAL)
    }

    // ---- joining ---------------------------------------------------------------------

    /// Joins the session if it has not, and gives every participating SSRC its timer.
    fn sync(&mut self, now: Instant) {
        if self.left {
            return;
        }
        self.sync_reporter();
        if !self.started {
            self.started = true;
            // RFC 3550 6.3.2: avg_rtcp_size starts at the probable size of the first packet:
            // a report, an SDES with the CNAME, and a block for each stream bound so far.
            // RFC 3711 section 3.4: with the SRTCP fields.
            self.avg_rtcp_size = (LOWER_LAYER_OVERHEAD
                + 8
                + 12
                + self.cname.len()
                + 24 * self.remotes.len().min(MAX_REPORT_BLOCKS)
                + self.srtcp_overhead) as f64;
            self.pmembers = self.member_count().max(1);
        }
        for index in 0..self.locals.len() {
            if self.locals[index].timing.is_none() && self.locals[index].participates() {
                let t = self.interval(index, now);
                self.locals[index].timing = Some(Timing::new(now, t));
            }
        }
        self.flush_departing(now);
    }

    // ---- the member table ------------------------------------------------------------

    fn heard(&mut self, now: Instant, ssrc: u32, rtp: bool) {
        if let Some(&left_at) = self.said_bye.get(&ssrc) {
            // RFC 3550 6.2.1: a straggler behind the BYE; the source stays gone for two
            // report intervals.
            if now.saturating_duration_since(left_at).as_secs_f64()
                <= 2.0 * self.report_interval(now)
            {
                return;
            }
            self.said_bye.remove(&ssrc);
        }
        if let Some(member) = self.members.get_mut(&ssrc) {
            member.last_heard = now;
            if rtp {
                member.last_rtp = Some(now);
            }
        } else if self.members.len() < MAX_MEMBERS {
            self.members.insert(
                ssrc,
                Member {
                    last_heard: now,
                    last_rtp: rtp.then_some(now),
                    cname: None,
                },
            );
        }
        if let Some(remote) = self.remotes.get_mut(&ssrc) {
            remote.gone = false;
        }
    }

    /// RFC 3550 6.3.4: the membership fell; the timers shrink with it.
    fn reverse_reconsider(&mut self, now: Instant) {
        let members = self.member_count().max(1);
        if members < self.pmembers {
            let pmembers = self.pmembers;
            for local in &mut self.locals {
                if let Some(timing) = local.timing.as_mut() {
                    timing.reverse_reconsider(now, members, pmembers);
                }
            }
            self.pmembers = members;
        }
    }

    fn remove_member(&mut self, ssrc: u32) -> bool {
        if let Some(remote) = self.remotes.get_mut(&ssrc) {
            remote.gone = true;
        }
        self.reference_times.remove(&ssrc);
        self.members.remove(&ssrc).is_some()
    }

    /// RFC 3550 6.3.5 with RFC 8108 7.1.4: a member not heard for five deterministic
    /// intervals (computed for a receiver, with a minimum of five seconds) is timed out.
    fn time_out_members(&mut self, now: Instant) {
        let mut input = self.interval_input(now, false, false, self.sender_count(now));
        input.t_min = RTCP_MIN_TIME;
        let timeout = TIMEOUT_MULTIPLIER * deterministic_interval(&input);
        if !timeout.is_finite() {
            return;
        }
        let silent: Vec<u32> = self
            .members
            .iter()
            .filter(|(_, member)| {
                now.saturating_duration_since(member.last_heard)
                    .as_secs_f64()
                    > timeout
            })
            .map(|(ssrc, _)| *ssrc)
            .collect();
        let linger = 2.0 * self.report_interval(now);
        self.said_bye
            .retain(|_, left_at| now.saturating_duration_since(*left_at).as_secs_f64() <= linger);
        if silent.is_empty() {
            return;
        }
        for ssrc in silent {
            self.remove_member(ssrc);
            self.emit(now, RtcpSessionEvent::SourceTimedOut { ssrc });
        }
        self.reverse_reconsider(now);
    }

    /// RFC 3550 8.2: a packet from another source carries one of this endpoint's SSRCs.
    fn collision(&mut self, now: Instant, ssrc: u32) {
        let Some(index) = self.local_index(ssrc) else {
            return;
        };
        let mut random = std::mem::replace(&mut self.random, Box::new(ThreadRandom));
        let replacement = choose_ssrc(random.as_mut(), |candidate| self.ssrc_in_use(candidate));
        self.random = random;

        if self.locals[index].role == Role::Reporter {
            // The session's own SSRC: say BYE with the old identifier and take the new one.
            let old = self.locals.remove(index);
            self.departing.push(old);
            self.locals
                .push(Local::new(replacement, Kind::Other, Role::Reporter, 90_000));
            self.emit(now, RtcpSessionEvent::SsrcCollision { ssrc, replacement });
            self.sync(now);
        } else if self.collided.insert(ssrc) {
            // A stream's SSRC is the sender's to change: it is told, and the BYE for the old
            // SSRC leaves when the stream is unbound.
            self.emit(now, RtcpSessionEvent::SsrcCollision { ssrc, replacement });
        }
    }

    // ---- what arrives ----------------------------------------------------------------

    /// Whether the packet goes on to the rest of the chain.
    fn observe_rtp(&mut self, now: Instant, message: &AttributedPacket) -> bool {
        let Packet::Rtp(packet) = &message.packet else {
            return true;
        };
        let header = &packet.header;
        // The stream the packet arrived on: the RTX stream for a retransmission that was
        // de-encapsulated before the chain.
        let (arrival_ssrc, arrival_sequence_number) = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::Retransmitted {
                    ssrc,
                    sequence_number,
                } => Some((*ssrc, *sequence_number)),
                _ => None,
            })
            .unwrap_or((header.ssrc, header.sequence_number));

        // RFC 3550 8.2: our own SSRC from the network is a collision, or our own packet
        // looped back; either way it is not a remote stream's.
        if self.local_index(arrival_ssrc).is_some() {
            self.collision(now, arrival_ssrc);
            return false;
        }

        self.rate
            .add(now, header.marshal_size() + packet.payload.len());
        self.heard(now, arrival_ssrc, true);
        for &csrc in &header.csrc {
            self.heard(now, csrc, false);
        }

        if let Some(remote) = self.remotes.get_mut(&arrival_ssrc) {
            if arrival_ssrc == header.ssrc {
                remote.stream.process_rtp(now, packet);
            } else {
                let mut arrived = rtp::Packet {
                    header: rtp::header::Header {
                        ssrc: arrival_ssrc,
                        sequence_number: arrival_sequence_number,
                        timestamp: header.timestamp,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                arrived.header.version = 2;
                remote.stream.process_rtp(now, &arrived);
            }
        } else if arrival_ssrc != header.ssrc
            && let Some(remote) = self.remotes.get_mut(&header.ssrc)
        {
            // A retransmission whose RTX stream is not bound counts where it is delivered.
            remote.stream.process_rtp(now, packet);
        }

        // RFC 5506 4.2.1: a packet a reduced-size NACK asked for arrived, so they get through.
        if let Some((ssrc, sequence_numbers)) = &self.awaited
            && *ssrc == header.ssrc
            && sequence_numbers.contains(&header.sequence_number)
        {
            self.awaited = None;
            self.unanswered_reduced_nacks = 0;
        }
        true
    }

    fn observe_report_blocks(&mut self, now: Instant, reports: &[ReceptionReport]) {
        for report in reports {
            if report.last_sender_report == 0 {
                continue;
            }
            let Some(index) = self.local_index(report.ssrc) else {
                continue;
            };
            let Some(&(_, sent)) = self.locals[index]
                .sent_reports
                .iter()
                .find(|(compact_ntp, _)| *compact_ntp == report.last_sender_report)
            else {
                continue;
            };
            // RFC 3550 6.4.1: the round trip is the time since the report was sent less the
            // delay the receiver held it for (DLSR, in 1/65536 s).
            let elapsed = now.saturating_duration_since(sent).as_secs_f64();
            let rtt = (elapsed - f64::from(report.delay) / 65536.0).max(0.0);
            self.emit(
                now,
                RtcpSessionEvent::RoundTripTime {
                    ssrc: report.ssrc,
                    rtt: Duration::from_secs_f64(rtt),
                },
            );
        }
    }

    fn observe_rtcp(&mut self, now: Instant, packets: &[Box<dyn rtcp::Packet>]) {
        if packets.is_empty() {
            return;
        }
        // RFC 3711 section 3.4: the SRTCP fields count, though they are gone by now.
        let size =
            (wire_size(packets) + self.srtcp_overhead) as f64 / reporting_ssrcs(packets) as f64;
        let mut goodbyes = 0;

        for packet in packets {
            let any = packet.as_any();
            if let Some(goodbye) = any.downcast_ref::<Goodbye>() {
                goodbyes += 1;
                for &source in &goodbye.sources {
                    self.remove_member(source);
                    if self.said_bye.len() < MAX_MEMBERS {
                        self.said_bye.insert(source, now);
                    }
                }
                continue;
            }
            if let Some(sdes) = any.downcast_ref::<SourceDescription>() {
                for chunk in &sdes.chunks {
                    if self.local_index(chunk.source).is_some() {
                        continue;
                    }
                    self.heard(now, chunk.source, false);
                    let cname = chunk
                        .items
                        .iter()
                        .find(|item| item.sdes_type == SdesType::SdesCname)
                        .map(|item| String::from_utf8_lossy(&item.text).into_owned());
                    if let Some(cname) = cname
                        && let Some(member) = self.members.get_mut(&chunk.source)
                        && member.cname.as_deref() != Some(cname.as_str())
                    {
                        member.cname = Some(cname.clone());
                        self.emit(
                            now,
                            RtcpSessionEvent::RemoteCname {
                                ssrc: chunk.source,
                                cname,
                            },
                        );
                    }
                }
                continue;
            }

            let (sender, _) = sender_and_media(packet.as_ref());
            if let Some(sender) = sender {
                if self.local_index(sender).is_some() {
                    // RFC 3550 8.2: RTCP from another source under one of our SSRCs.
                    self.collision(now, sender);
                    continue;
                }
                self.heard(now, sender, false);
            }

            if let Some(sr) = any.downcast_ref::<SenderReport>() {
                if let Some(remote) = self.remotes.get_mut(&sr.ssrc) {
                    remote.stream.process_sender_report(now, sr);
                }
                self.observe_report_blocks(now, &sr.reports);
            } else if let Some(rr) = any.downcast_ref::<ReceiverReport>() {
                self.observe_report_blocks(now, &rr.reports);
            } else if let Some(xr) = any.downcast_ref::<ExtendedReport>() {
                for block in &xr.reports {
                    if let Some(rrtr) = block
                        .as_any()
                        .downcast_ref::<ReceiverReferenceTimeReportBlock>()
                        && (self.reference_times.len() < MAX_REFERENCE_TIMES
                            || self.reference_times.contains_key(&xr.sender_ssrc))
                    {
                        self.reference_times
                            .insert(xr.sender_ssrc, ((rrtr.ntp_timestamp >> 16) as u32, now));
                    }
                }
            }
        }

        if let Some(bye) = self.bye.as_mut() {
            // RFC 3550 6.3.7: while a BYE waits, only BYE packets are counted and sized.
            if goodbyes > 0 {
                bye.members += goodbyes;
                bye.size = update_avg_rtcp_size(bye.size, size);
            }
        } else {
            self.avg_rtcp_size = update_avg_rtcp_size(self.avg_rtcp_size, size);
            if goodbyes > 0 {
                self.reverse_reconsider(now);
            }
        }
    }

    // ---- what the chain and the application write ------------------------------------

    /// Takes an RTCP packet written from above into the session's hands.
    fn adopt(&mut self, packet: Box<dyn rtcp::Packet>) {
        let any = packet.as_any();
        // The session's own reports and CNAME stand for these.
        if any.is::<SenderReport>() || any.is::<ReceiverReport>() || any.is::<SourceDescription>() {
            return;
        }
        let (sender, media) = sender_and_media(packet.as_ref());
        let packet = match (sender, self.feedback_source(media)) {
            (Some(_), Some(index)) => with_sender(packet, self.locals[index].ssrc),
            _ => packet,
        };

        // RFC 4585 3.5.2: feedback for one compound packet is merged into as few messages
        // as possible.
        let any = packet.as_any();
        if let Some(nack) = any.downcast_ref::<TransportLayerNack>() {
            for held in &mut self.pending {
                if let Some(other) = held.as_any().downcast_ref::<TransportLayerNack>()
                    && other.media_ssrc == nack.media_ssrc
                {
                    let mut sequence_numbers: Vec<u16> = other
                        .nacks
                        .iter()
                        .chain(&nack.nacks)
                        .flat_map(|pair| pair.packet_list())
                        .collect();
                    sequence_numbers.sort_unstable();
                    sequence_numbers.dedup();
                    *held = boxed(TransportLayerNack {
                        sender_ssrc: nack.sender_ssrc,
                        media_ssrc: nack.media_ssrc,
                        nacks: nack_pairs_from_sequence_numbers(&sequence_numbers),
                    });
                    return;
                }
            }
        } else if let Some(pli) = any.downcast_ref::<PictureLossIndication>()
            && self.pending.iter().any(|held| {
                held.as_any()
                    .downcast_ref::<PictureLossIndication>()
                    .is_some_and(|other| other.media_ssrc == pli.media_ssrc)
            })
        {
            return;
        }

        if self.pending.len() >= MAX_PENDING {
            self.pending.remove(0);
        }
        self.pending.push(packet);
    }

    fn has_feedback(&self) -> bool {
        self.pending.iter().any(|packet| {
            let any = packet.as_any();
            !any.is::<ExtendedReport>() && !any.is::<Goodbye>()
        })
    }

    /// RFC 4585 3.5.2: feedback was detected at `now`.
    fn schedule_feedback(&mut self, now: Instant) {
        if !self.has_feedback() || self.profile == RtcpProfile::Avp {
            // Without AVPF, feedback rides the next regular packet.
            return;
        }
        // Step 2: a packet with feedback is already scheduled; this joins it.
        if self.early_at.is_some() {
            return;
        }
        let media = self
            .pending
            .iter()
            .find_map(|packet| sender_and_media(packet.as_ref()).1);
        let Some(index) = self.feedback_source(media) else {
            return;
        };
        let Some(timing) = self.locals[index].timing else {
            return;
        };
        // Step 2b: no dither between two parties, half the regular interval among more.
        let t_dither_max = if self.is_point_to_point() {
            0.0
        } else {
            0.5 * seconds_between(timing.tp, timing.tn).max(0.0)
        };
        // Step 3: the regular packet is due within the dither; step 4a: no early packet is
        // allowed. Either way the feedback is stored for the regular packet at tn.
        if after(now, t_dither_max) > timing.tn || !timing.allow_early {
            return;
        }
        // Step 4b.
        let te = after(now, self.unit() * t_dither_max);
        if te <= now {
            self.send_early(now, index);
        } else {
            self.early_at = Some(te);
        }
    }

    // ---- building packets ------------------------------------------------------------

    fn sdes_chunk(&self, ssrc: u32) -> SourceDescriptionChunk {
        let mut items = vec![SourceDescriptionItem {
            sdes_type: SdesType::SdesCname,
            text: self.cname.clone().into(),
        }];
        if let Some(identifiers) = self.identifiers.get(&ssrc) {
            items.extend(identifiers.iter().cloned());
        }
        SourceDescriptionChunk {
            source: ssrc,
            items,
        }
    }

    /// The SR of a local SSRC that sent lately, its RR otherwise (RFC 3550 6.4).
    fn report(
        &mut self,
        index: usize,
        now: Instant,
        blocks: Vec<ReceptionReport>,
    ) -> Box<dyn rtcp::Packet> {
        let we_sent = self.we_sent(index, now);
        let local = &mut self.locals[index];
        local.rtcp_sent = true;
        if we_sent && let Some(mut report) = local.stream.generate_report(now) {
            local
                .sent_reports
                .push_back(((report.ntp_time >> 16) as u32, now));
            while local.sent_reports.len() > 8 {
                local.sent_reports.pop_front();
            }
            report.reports = blocks;
            boxed(report)
        } else {
            boxed(ReceiverReport {
                ssrc: local.ssrc,
                reports: blocks,
                ..Default::default()
            })
        }
    }

    /// The report blocks of this interval: up to `max` remote streams, taken round robin so
    /// that each is reported in turn when they do not all fit (RFC 3550 6.1).
    ///
    /// When they do not all fit, streams losing [`HIGH_LOSS_FRACTION`] or more since their
    /// last report go first, the worst first, in up to half of the blocks (RFC 8083 section
    /// 4.3: "priority SHOULD be given to reports on sources that have high packet loss
    /// rates"); the other half stays round robin, so every stream is still reported in turn.
    fn report_blocks(&mut self, now: Instant, max: usize) -> Vec<ReceptionReport> {
        let candidates: Vec<u32> = self
            .remote_order
            .iter()
            .copied()
            .filter(|ssrc| {
                self.remotes
                    .get(ssrc)
                    .is_some_and(|remote| !remote.gone && remote.stream.has_received())
            })
            .collect();
        if candidates.is_empty() || max == 0 {
            return vec![];
        }
        let mut chosen: Vec<u32> = Vec::new();
        if candidates.len() > max {
            let mut lossy: Vec<(u8, u32)> = candidates
                .iter()
                .filter_map(|ssrc| {
                    let loss = self.remotes.get(ssrc)?.stream.pending_fraction_lost();
                    (loss >= HIGH_LOSS_FRACTION).then_some((loss, *ssrc))
                })
                .collect();
            lossy.sort_by_key(|(loss, _)| std::cmp::Reverse(*loss));
            chosen.extend(lossy.iter().take(max / 2).map(|(_, ssrc)| *ssrc));
        }
        let rest: Vec<u32> = candidates
            .iter()
            .copied()
            .filter(|ssrc| !chosen.contains(ssrc))
            .collect();
        if !rest.is_empty() {
            let count = rest.len().min(max - chosen.len());
            let start = self.report_cursor % rest.len();
            self.report_cursor = (start + count) % rest.len();
            chosen.extend((0..count).map(|offset| rest[(start + offset) % rest.len()]));
        }
        chosen
            .into_iter()
            .filter_map(|ssrc| {
                self.remotes
                    .get_mut(&ssrc)
                    .map(|remote| remote.stream.generate_reception_report(now))
            })
            .collect()
    }

    /// The XR packet of a regular report: a receiver reference time when a bound stream
    /// negotiated it, and a DLRR block answering the reference times received (RFC 3611 4.4,
    /// 4.5) when a local SSRC sends.
    fn extended_report(
        &mut self,
        now: Instant,
        ssrc: u32,
        any_sender: bool,
    ) -> Option<ExtendedReport> {
        let mut blocks: Vec<Box<dyn rtcp::Packet>> = vec![];
        if self
            .remotes
            .values()
            .any(|remote| remote.rrtr && !remote.gone)
        {
            let wall_clock = *self
                .wall_clock
                .get_or_insert_with(|| SystemInstant::now(now));
            blocks.push(Box::new(ReceiverReferenceTimeReportBlock {
                ntp_timestamp: wall_clock.ntp(now),
            }));
        }
        if any_sender && !self.reference_times.is_empty() {
            let reports = self
                .reference_times
                .drain()
                .map(|(ssrc, (last_rr, arrived))| DLRRReport {
                    ssrc,
                    last_rr,
                    dlrr: (now.saturating_duration_since(arrived).as_secs_f64() * 65536.0) as u64
                        as u32,
                })
                .collect();
            blocks.push(Box::new(DLRRReportBlock { reports }));
        }
        (!blocks.is_empty()).then_some(ExtendedReport {
            sender_ssrc: ssrc,
            reports: blocks,
        })
    }

    /// Moves what is waiting into `packets`, as far as `budget` octets go. What does not fit
    /// waits for the next packet; a packet too large for any compound packet goes anyway.
    fn take_pending(&mut self, packets: &mut Vec<Box<dyn rtcp::Packet>>, budget: &mut usize) {
        /// A report without blocks and an SDES with one CNAME: what a minimal compound
        /// packet spends before its feedback.
        const MINIMAL_OVERHEAD: usize = 64;
        let mut kept = vec![];
        for packet in std::mem::take(&mut self.pending) {
            let size = packet.marshal_size();
            if size <= *budget || size + MINIMAL_OVERHEAD > self.mtu {
                *budget = budget.saturating_sub(size);
                packets.push(packet);
            } else {
                kept.push(packet);
            }
        }
        self.pending = kept;
    }

    /// Builds and sends a compound packet led by the local SSRC `first`.
    ///
    /// `Shape::Full` aggregates the other local SSRCs (RFC 8108 5.3.2) and returns the
    /// indices of those that reported; `Shape::Minimal` carries the leading report alone.
    fn send_compound(&mut self, now: Instant, first: usize, shape: Shape) -> Vec<usize> {
        let mut budget = self.mtu;
        let mut included = vec![first];
        let mut reports: Vec<Box<dyn rtcp::Packet>> = vec![];

        // The SDES chunk of an SSRC is 12 octets and its CNAME, padded, and its stream
        // identifiers: the largest one is counted for each.
        let chunk = self
            .locals
            .iter()
            .map(|local| self.sdes_chunk(local.ssrc).marshal_size())
            .max()
            .unwrap_or_else(|| self.sdes_chunk(0).marshal_size());
        let block = 24;

        let reporter = self.reporter();
        let mut blocks = vec![];
        if shape == Shape::Full {
            // What is left for report blocks once every participant's report and CNAME are
            // in: the streams that do not fit are reported next time (RFC 3550 6.1).
            let participants = self.locals.iter().filter(|l| l.participates()).count();
            let room = budget.saturating_sub(participants * (28 + chunk) + 4) / block;
            blocks = self.report_blocks(now, room.max(1));
        }
        // RFC 3550 6.1: a report carries 31 blocks; further ones follow in additional RR
        // packets from the same SSRC.
        let overflow: Vec<ReceptionReport> = if blocks.len() > MAX_REPORT_BLOCKS {
            blocks.split_off(MAX_REPORT_BLOCKS)
        } else {
            vec![]
        };
        let every = self.report_from_every_ssrc;
        let carries_blocks =
            move |index: usize| every || Some(index) == reporter || reporter.is_none();
        let first_blocks = if carries_blocks(first) {
            blocks.clone()
        } else {
            vec![]
        };
        let report = self.report(first, now, first_blocks);
        budget = budget.saturating_sub(report.marshal_size() + 4 + chunk);
        reports.push(report);

        if shape == Shape::Full {
            // RFC 8108 5.3.2: the other SSRCs, in the order their timers would expire, as
            // long as their reports fit.
            let mut others: Vec<usize> = (0..self.locals.len())
                .filter(|&index| {
                    index != first
                        && self.locals[index].participates()
                        && self.locals[index].timing.is_some()
                })
                .collect();
            others.sort_by_key(|&index| self.locals[index].timing.map(|timing| timing.tn));
            // The SSRC that carries the blocks reports right behind the leader.
            if let Some(reporter) = reporter
                && let Some(position) = others.iter().position(|&index| index == reporter)
            {
                let reporter = others.remove(position);
                others.insert(0, reporter);
            }
            for index in others {
                let own_blocks = if carries_blocks(index) {
                    blocks.clone()
                } else {
                    vec![]
                };
                let size = 28 + block * own_blocks.len() + chunk;
                if size > budget && Some(index) != reporter {
                    // It keeps its own timer and reports when that expires.
                    continue;
                }
                let report = self.report(index, now, own_blocks);
                budget = budget.saturating_sub(report.marshal_size() + chunk);
                reports.push(report);
                included.push(index);
            }
        }

        let mut packets = reports;
        if !overflow.is_empty() {
            let ssrc = self.locals[reporter.filter(|r| included.contains(r)).unwrap_or(first)].ssrc;
            // Behind the report of the SSRC they continue.
            let position = packets
                .iter()
                .position(|packet| sender_and_media(packet.as_ref()).0 == Some(ssrc))
                .map_or(packets.len(), |position| position + 1);
            for (offset, chunk) in overflow.chunks(MAX_REPORT_BLOCKS).enumerate() {
                let more = boxed(ReceiverReport {
                    ssrc,
                    reports: chunk.to_vec(),
                    ..Default::default()
                });
                budget = budget.saturating_sub(more.marshal_size());
                packets.insert(position + offset, more);
            }
        }
        packets.push(boxed(SourceDescription {
            chunks: included
                .iter()
                .map(|&index| self.sdes_chunk(self.locals[index].ssrc))
                .collect(),
        }));

        if shape == Shape::Full {
            let any_sender = included.iter().any(|&index| self.we_sent(index, now));
            let ssrc = self.locals[reporter.filter(|r| included.contains(r)).unwrap_or(first)].ssrc;
            if let Some(xr) = self.extended_report(now, ssrc, any_sender) {
                budget = budget.saturating_sub(xr.marshal_size());
                packets.push(boxed(xr));
            }
        }

        self.take_pending(&mut packets, &mut budget);
        self.early_at = None;
        self.compound_sent = true;
        self.send(now, packets);
        included
    }

    /// Congestion control feedback leaves now, outside RFC 4585's Early allowance and the
    /// regular timing (see [`RtcpSessionBuilder::with_immediate_congestion_feedback`]):
    /// reduced-size where negotiated, else in a minimal compound packet; whatever other
    /// feedback is waiting goes with it.
    fn send_congestion_feedback(&mut self, now: Instant) {
        let media = self
            .pending
            .iter()
            .find_map(|packet| sender_and_media(packet.as_ref()).1);
        let Some(index) = self.feedback_source(media) else {
            return;
        };
        if self.locals[index].timing.is_none() {
            return;
        }
        let reduced = self.reduced_size
            && self.compound_sent
            && !self.reduced_size_failed
            && self
                .pending
                .iter()
                .all(|packet| delivery_shows(packet.as_ref()))
            && self.pending.iter().map(|p| p.marshal_size()).sum::<usize>() <= REDUCED_SIZE_MAX;
        self.outside_budget = true;
        if reduced {
            self.note_reduced_nack();
            let packets = std::mem::take(&mut self.pending);
            self.send(now, packets);
        } else {
            self.send_compound(now, index, Shape::Minimal);
        }
        self.outside_budget = false;
        if self.pending.is_empty() {
            self.early_at = None;
        }
    }

    /// RFC 4585 3.5.2 step 6: the Early packet goes, from the local SSRC `index`.
    fn send_early(&mut self, now: Instant, index: usize) {
        let reduced = self.reduced_size
            && self.compound_sent
            && !self.reduced_size_failed
            && self
                .pending
                .iter()
                .all(|packet| delivery_shows(packet.as_ref()))
            && self.pending.iter().map(|p| p.marshal_size()).sum::<usize>() <= REDUCED_SIZE_MAX;

        if reduced {
            self.note_reduced_nack();
            let packets = std::mem::take(&mut self.pending);
            self.early_at = None;
            self.send(now, packets);
        } else {
            self.send_compound(now, index, Shape::Minimal);
        }
        if let Some(timing) = self.locals[index].timing.as_mut() {
            timing.early_sent();
        }
    }

    /// RFC 5506 4.2.1: watches whether reduced-size NACKs get an answer. A run of them with
    /// none of the requested packets arriving means they do not get through, and the session
    /// goes back to compound packets.
    fn note_reduced_nack(&mut self) {
        let Some(nack) = self
            .pending
            .iter()
            .find_map(|packet| packet.as_any().downcast_ref::<TransportLayerNack>())
        else {
            return;
        };
        if self.awaited.is_some() {
            self.unanswered_reduced_nacks += 1;
            if self.unanswered_reduced_nacks >= REDUCED_SIZE_UNANSWERED_LIMIT {
                self.reduced_size_failed = true;
            }
        }
        self.awaited = Some((
            nack.media_ssrc,
            nack.nacks
                .iter()
                .flat_map(|pair| pair.packet_list())
                .collect(),
        ));
    }

    /// RFC 3550 6.6 and 6.3.7: the local SSRCs that were unbound say BYE, each behind its
    /// last report, unless they never sent anything.
    fn flush_departing(&mut self, now: Instant) {
        if self.departing.is_empty() {
            return;
        }
        let departing = std::mem::take(&mut self.departing);
        let mut reports: Vec<Box<dyn rtcp::Packet>> = vec![];
        let mut chunks = vec![];
        let mut sources = vec![];
        for mut local in departing {
            self.collided.remove(&local.ssrc);
            // "A participant which never sent an RTP or RTCP packet MUST NOT send a BYE."
            if !local.rtp_sent && !local.rtcp_sent {
                continue;
            }
            let horizon = 2.0 * self.report_interval(now);
            let was_sender = local
                .last_rtp
                .is_some_and(|last| now.saturating_duration_since(last).as_secs_f64() <= horizon);
            match local.stream.generate_report(now).filter(|_| was_sender) {
                Some(report) => reports.push(boxed(report)),
                None => reports.push(boxed(ReceiverReport {
                    ssrc: local.ssrc,
                    ..Default::default()
                })),
            }
            chunks.push(self.sdes_chunk(local.ssrc));
            sources.push(local.ssrc);
        }
        if sources.is_empty() {
            return;
        }
        let mut packets = reports;
        packets.push(boxed(SourceDescription { chunks }));
        packets.push(boxed(Goodbye {
            sources,
            reason: Default::default(),
        }));

        if self.member_count() >= BYE_BACKOFF_MEMBERS && !self.left {
            // RFC 3550 6.3.7: in a large session the BYE takes its turn.
            let size = (wire_size(&packets) + self.srtcp_overhead) as f64;
            let mut input = self.interval_input(now, false, true, 0);
            input.members = 1;
            input.avg_rtcp_size = size;
            let t = randomized_interval(deterministic_interval(&input), self.unit());
            self.bye = Some(ByeBackoff {
                packets,
                size,
                tp: now,
                tn: after(now, t),
                members: 1,
            });
        } else if self.member_count() < BYE_BACKOFF_MEMBERS {
            self.compound_sent = true;
            self.send(now, packets);
        }
        // Leaving a session of more than fifty members at once: without a BYE (6.3.7 allows
        // it), since the transport does not outlive the back-off.
    }

    // ---- the timers ------------------------------------------------------------------

    /// RFC 3550 6.3.6 (with RFC 4585 3.5.3 and RFC 8108 5.3.2): works through every timer
    /// that expired by `now`.
    fn run_timers(&mut self, now: Instant) {
        if !self.started {
            return;
        }
        self.time_out_members(now);

        if let Some(te) = self.early_at
            && te <= now
        {
            let media = self
                .pending
                .iter()
                .find_map(|packet| sender_and_media(packet.as_ref()).1);
            match self.feedback_source(media) {
                Some(index) if self.has_feedback() => self.send_early(now, index),
                _ => self.early_at = None,
            }
        }

        self.run_bye_timer(now);

        for _ in 0..MAX_CATCH_UP {
            let Some(index) = (0..self.locals.len())
                .filter(|&index| {
                    self.locals[index]
                        .timing
                        .is_some_and(|timing| timing.tn <= now)
                })
                .min_by_key(|&index| self.locals[index].timing.map(|timing| timing.tn))
            else {
                return;
            };
            let Some(mut timing) = self.locals[index].timing else {
                return;
            };
            // The timer expired at tn, which may be a while ago: a session nobody woke
            // catches up with the expiries it would have suppressed.
            let tc = timing.tn;
            let t = self.interval(index, tc);
            if !timing.reconsider(tc, t) {
                self.locals[index].timing = Some(timing);
                self.pmembers = self.member_count().max(1);
                continue;
            }

            let decision = match self.profile {
                RtcpProfile::Avp => RegularDecision::Send,
                RtcpProfile::Avpf => {
                    let random = self.unit();
                    regular_decision(
                        self.t_rr_interval,
                        timing.t_rr_last,
                        tc,
                        random,
                        !self.pending.is_empty(),
                    )
                }
            };
            match decision {
                RegularDecision::Send => self.send_regular(now, index),
                RegularDecision::SendFeedbackOnly => {
                    self.send_compound(now, index, Shape::Minimal);
                    let t = self.interval(index, now);
                    if let Some(timing) = self.locals[index].timing.as_mut() {
                        timing.rescheduled(now, t);
                    }
                }
                RegularDecision::Suppress => {
                    // RFC 8108 5.3.2: "tp is updated to tc as aggregation has not taken place".
                    let t = self.interval(index, tc);
                    if let Some(timing) = self.locals[index].timing.as_mut() {
                        timing.rescheduled(tc, t);
                    }
                }
            }
            self.pmembers = self.member_count().max(1);
        }

        // Too far behind to replay: every timer starts over from now.
        for index in 0..self.locals.len() {
            if self.locals[index].timing.is_some() {
                let t = self.interval(index, now);
                if let Some(timing) = self.locals[index].timing.as_mut() {
                    timing.rescheduled(now, t);
                }
            }
        }
    }

    /// A Regular RTCP packet led by the local SSRC `first`, and the timers of every SSRC it
    /// carried (RFC 8108 5.3.2, steps a to d).
    fn send_regular(&mut self, now: Instant, first: usize) {
        let included = self.send_compound(now, first, Shape::Full);

        // a. The SSRC whose timer expired transmitted at tc. b. Each SSRC aggregated with it
        // would have transmitted when its own timer passed reconsideration.
        let mut offsets = vec![0.0];
        for &index in included.iter().skip(1) {
            let Some(mut timing) = self.locals[index].timing else {
                continue;
            };
            for _ in 0..64 {
                let t = self.interval(index, now);
                if after(timing.tp, t) <= timing.tn {
                    break;
                }
                timing.tn = after(timing.tp, t);
            }
            offsets.push(seconds_between(now, timing.tn).max(0.0));
        }
        // c. tp (and T_rr_last) of all of them is the average of those times.
        let tt_avg = after(now, offsets.iter().sum::<f64>() / offsets.len() as f64);
        // d. New timers from there.
        for &index in &included {
            if let Some(timing) = self.locals[index].timing.as_mut() {
                timing.initial = false;
                timing.t_rr_last = Some(tt_avg);
            }
            let t = self.interval(index, now);
            if let Some(timing) = self.locals[index].timing.as_mut() {
                timing.rescheduled(tt_avg, t);
            }
        }
    }

    /// RFC 3550 6.3.7: the BYE of a large session, sent when its own timer passes
    /// reconsideration against the number of BYE packets seen.
    fn run_bye_timer(&mut self, now: Instant) {
        let Some(bye) = self.bye.as_ref() else {
            return;
        };
        if bye.tn > now {
            return;
        }
        let mut input = self.interval_input(now, false, true, 0);
        input.members = bye.members;
        input.avg_rtcp_size = bye.size;
        let t = randomized_interval(deterministic_interval(&input), self.unit());
        let Some(bye) = self.bye.as_mut() else {
            return;
        };
        if after(bye.tp, t) <= now {
            let packets = std::mem::take(&mut bye.packets);
            self.bye = None;
            self.send(now, packets);
        } else {
            bye.tn = after(bye.tp, t);
        }
    }

    fn next_timeout(&self) -> Option<Instant> {
        if !self.started {
            return None;
        }
        let feedback_waits = !self.pending.is_empty();
        let regular = self.locals.iter().filter_map(|local| {
            let timing = local.timing?;
            // Until T_rr_interval has passed since the last regular packet, an expiring
            // timer only suppresses it; there is nothing to wake up for before half of it
            // (the least its dither allows) unless feedback is waiting.
            match (self.profile, timing.t_rr_last) {
                (RtcpProfile::Avpf, Some(t_rr_last))
                    if self.t_rr_interval > 0.0 && !feedback_waits =>
                {
                    Some(timing.tn.max(after(t_rr_last, 0.5 * self.t_rr_interval)))
                }
                _ => Some(timing.tn),
            }
        });
        regular
            .chain(self.early_at)
            .chain(self.bye.as_ref().map(|bye| bye.tn))
            .min()
    }

    fn control(&mut self, now: Instant, control: &RtcpSessionControl) {
        match control {
            RtcpSessionControl::Start => {}
            RtcpSessionControl::Cname(cname) => self.cname = cname.clone(),
            RtcpSessionControl::Bandwidth(bandwidth) => self.bandwidth = *bandwidth,
            RtcpSessionControl::ReducedSize(reduced_size) => self.reduced_size = *reduced_size,
            RtcpSessionControl::SrtcpOverhead(overhead) => {
                // Given after the session started (any control starts it), the average moves
                // by the difference: an average of sizes that each carry the overhead is the
                // average of the sizes plus the overhead.
                if self.started {
                    self.avg_rtcp_size += *overhead as f64 - self.srtcp_overhead as f64;
                }
                self.srtcp_overhead = *overhead;
            }
            RtcpSessionControl::TrrInt(t_rr_interval) => {
                self.t_rr_interval = t_rr_interval.as_secs_f64();
            }
            RtcpSessionControl::TrrIntCleared => {
                self.t_rr_interval = self.configured_t_rr_interval;
            }
            RtcpSessionControl::StreamIdentifiers {
                ssrc,
                mid,
                rid,
                repaired_rid,
            } => {
                let items: Vec<SourceDescriptionItem> = [
                    (SdesType::SdesMid, mid),
                    (SdesType::SdesRtpStreamId, rid),
                    (SdesType::SdesRepairedRtpStreamId, repaired_rid),
                ]
                .into_iter()
                // An SDES item holds at most 255 octets (RFC 3550 section 6.5).
                .filter_map(|(sdes_type, value)| {
                    value
                        .as_ref()
                        .filter(|value| !value.is_empty() && value.len() <= 255)
                        .map(|value| SourceDescriptionItem {
                            sdes_type,
                            text: value.clone().into(),
                        })
                })
                .collect();
                // Only the streams the session still has keep theirs.
                let (locals, departing) = (&self.locals, &self.departing);
                self.identifiers.retain(|kept, _| {
                    locals
                        .iter()
                        .chain(departing)
                        .any(|local| local.ssrc == *kept)
                });
                if items.is_empty() {
                    self.identifiers.remove(ssrc);
                } else {
                    self.identifiers.insert(*ssrc, items);
                }
            }
            RtcpSessionControl::Leave => {
                // RFC 3550 6.6: every SSRC of an endpoint that leaves says BYE.
                self.sync(now);
                self.left = true;
                self.departing.append(&mut self.locals);
                self.pending.clear();
                self.early_at = None;
                self.flush_departing(now);
                return;
            }
        }
        self.sync(now);
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for RtcpSessionInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        let now = msg.now;
        self.sync(now);
        let pass = match &msg.message.packet {
            Packet::Rtp(_) => self.observe_rtp(now, &msg.message),
            Packet::Rtcp(packets) => {
                self.observe_rtcp(now, packets);
                true
            }
        };
        if pass {
            self.read_queue.push_back(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        let now = msg.now;

        if let Some(control) = msg.message.custom::<RtcpSessionControl>().cloned() {
            self.control(now, &control);
            msg.message.attributes.retain(|attribute| {
                !matches!(attribute, Attribute::Custom(value) if value.is::<RtcpSessionControl>())
            });
            if msg.message.attributes.is_empty()
                && matches!(&msg.message.packet, Packet::Rtcp(packets) if packets.is_empty())
            {
                return Ok(());
            }
        }
        if self.left {
            // After the BYE nothing more is said (RFC 3550 6.1: BYE is the last packet).
            if matches!(msg.message.packet, Packet::Rtp(_)) {
                self.write_queue.push_back(msg);
            }
            return Ok(());
        }
        self.sync(now);

        match msg.message.packet {
            Packet::Rtp(ref packet) => {
                if let Some(index) = self.local_index(packet.header.ssrc) {
                    let local = &mut self.locals[index];
                    local.stream.process_rtp(now, packet);
                    local.last_rtp = Some(now);
                    local.rtp_sent = true;
                    self.rate
                        .add(now, packet.header.marshal_size() + packet.payload.len());
                    // A repair SSRC joins with its first packet.
                    self.sync(now);
                }
                self.write_queue.push_back(msg);
            }
            // An attribute carrier (see `Packet::Rtcp`): not the session's.
            Packet::Rtcp(ref packets) if packets.is_empty() => {
                self.write_queue.push_back(msg);
            }
            Packet::Rtcp(packets) => {
                let congestion_feedback = !packets.is_empty()
                    && packets.iter().all(|packet| {
                        let any = packet.as_any();
                        any.is::<TransportLayerCc>() || any.is::<CcFeedbackReport>()
                    });
                for packet in packets {
                    self.adopt(packet);
                }
                self.run_timers(now);
                if congestion_feedback && self.immediate_congestion_feedback {
                    self.send_congestion_feedback(now);
                }
                self.schedule_feedback(now);
            }
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, now: Self::Time) -> Result<(), Self::Error> {
        if !self.started || self.left {
            return Ok(());
        }
        self.sync(now);
        self.run_timers(now);
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        self.next_timeout()
    }
}

impl Interceptor for RtcpSessionInterceptor {
    /// A stream this endpoint sends: its SSRC reports from now on, and its RTX and FEC SSRCs
    /// from their first packet. A stream unbound a moment ago and bound again with the same
    /// SSRC (a renegotiation) carries on: no BYE, and its counts are kept.
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        let kind = Kind::of(&info.mime_type);
        let sources = std::iter::once((info.ssrc, Role::Media))
            .chain(info.ssrc_rtx.map(|ssrc| (ssrc, Role::Repair)))
            .chain(info.ssrc_fec.map(|ssrc| (ssrc, Role::Repair)));
        for (ssrc, role) in sources {
            if let Some(index) = self.local_index(ssrc) {
                self.locals[index].stream.set_clock_rate(info.clock_rate);
                continue;
            }
            let local = match self.departing.iter().position(|local| local.ssrc == ssrc) {
                Some(position) => {
                    let mut local = self.departing.remove(position);
                    local.stream.set_clock_rate(info.clock_rate);
                    local.kind = kind;
                    local.role = role;
                    local
                }
                None => Local::new(ssrc, kind, role, info.clock_rate),
            };
            self.locals.push(local);
        }
        self.sync_reporter();
    }

    /// The stream stopped: its SSRCs say BYE the next time the chain is driven, unless they
    /// are bound again first.
    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        for ssrc in std::iter::once(info.ssrc)
            .chain(info.ssrc_rtx)
            .chain(info.ssrc_fec)
        {
            if let Some(index) = self.local_index(ssrc) {
                let local = self.locals.remove(index);
                self.departing.push(local);
            }
        }
    }

    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        let rrtr = info
            .rtcp_feedback
            .iter()
            .any(|feedback| feedback.typ == crate::RTCP_FB_RRTR);
        match self.remotes.get_mut(&info.ssrc) {
            Some(remote) => {
                remote.stream.set_clock_rate(info.clock_rate);
                remote.rrtr = rrtr;
                remote.kind = Kind::of(&info.mime_type);
            }
            None => {
                self.remotes.insert(
                    info.ssrc,
                    Remote {
                        stream: ReceiverStream::new(info.ssrc, info.clock_rate),
                        kind: Kind::of(&info.mime_type),
                        rrtr,
                        gone: false,
                    },
                );
                self.remote_order.push(info.ssrc);
            }
        }
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.remotes.remove(&info.ssrc);
        self.remote_order.retain(|ssrc| *ssrc != info.ssrc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rr(ssrc: u32) -> Box<dyn rtcp::Packet> {
        boxed(ReceiverReport {
            ssrc,
            ..Default::default()
        })
    }

    /// RFC 8108 5.3.1: the size that goes into avg_rtcp_size is the packet's divided by "the
    /// number of different SSRCs that are the source of SR or RR RTCP packets" in it; a
    /// packet without any reports for one.
    #[test]
    fn a_compound_packet_counts_per_reporting_ssrc() {
        let sr = boxed(SenderReport {
            ssrc: 3,
            ..Default::default()
        });
        assert_eq!(3, reporting_ssrcs(&[rr(1), rr(2), sr]));
        // A second RR from the same SSRC (more than 31 report blocks) is the same reporter.
        assert_eq!(1, reporting_ssrcs(&[rr(1), rr(1)]));
        let pli = boxed(PictureLossIndication {
            sender_ssrc: 1,
            media_ssrc: 2,
        });
        assert_eq!(1, reporting_ssrcs(&[pli]));

        // An empty RR is 8 octets; with UDP and IPv4 under it, 36.
        assert_eq!(36, wire_size(&[rr(1)]));
        let mut session = RtcpSessionBuilder::new().build();
        session.avg_rtcp_size = 100.0;
        session.send(Instant::now(), vec![rr(1), rr(2)]);
        // (28 + 16) / 2 = 22: 100 * 15/16 + 22 / 16.
        assert!((session.avg_rtcp_size - (93.75 + 1.375)).abs() < 1e-9);
    }

    /// RFC 3711 section 3.4: the SRTCP index, E flag and authentication tag are part of the
    /// packet size: in the initial avg_rtcp_size and in every packet sent or received.
    #[test]
    fn the_srtcp_fields_count_in_the_average_packet_size() {
        let now = Instant::now();
        let started = |overhead: Option<usize>| {
            let mut session = RtcpSessionBuilder::new().build();
            session.control(now, &RtcpSessionControl::Cname("cname".to_owned()));
            if let Some(overhead) = overhead {
                session.control(now, &RtcpSessionControl::SrtcpOverhead(overhead));
            }
            session
        };
        let (plain, mut protected) = (started(None), started(Some(14)));
        assert!(plain.started && protected.started);
        assert!((protected.avg_rtcp_size - plain.avg_rtcp_size - 14.0).abs() < 1e-9);
        // Given before the session starts, the initial estimate has it.
        let mut early = RtcpSessionBuilder::new().build();
        early.srtcp_overhead = 14;
        early.cname = "cname".to_owned();
        early.sync(now);
        assert!((early.avg_rtcp_size - plain.avg_rtcp_size - 14.0).abs() < 1e-9);

        // A packet sent: 36 octets of RR, UDP and IPv4, and 14 of SRTCP.
        protected.avg_rtcp_size = 100.0;
        protected.send(now, vec![rr(1)]);
        assert!((protected.avg_rtcp_size - (93.75 + 50.0 / 16.0)).abs() < 1e-9);
        // One received: the same.
        protected.avg_rtcp_size = 100.0;
        protected.observe_rtcp(now, &[rr(2)]);
        assert!((protected.avg_rtcp_size - (93.75 + 50.0 / 16.0)).abs() < 1e-9);
    }

    /// RFC 4585 6.1: the packet sender of a feedback message is rewritten, whatever its type.
    #[test]
    fn every_feedback_type_takes_the_endpoints_ssrc() {
        let packets: Vec<Box<dyn rtcp::Packet>> = vec![
            boxed(TransportLayerNack::default()),
            boxed(PictureLossIndication::default()),
            boxed(FullIntraRequest::default()),
            boxed(SliceLossIndication::default()),
            boxed(ReceiverEstimatedMaximumBitrate::default()),
            boxed(TransportLayerCc::default()),
            boxed(RapidResynchronizationRequest::default()),
        ];
        for packet in packets {
            let rewritten = with_sender(packet, 0xABCD);
            assert_eq!(
                Some(0xABCD),
                sender_and_media(rewritten.as_ref()).0,
                "{rewritten:?}"
            );
        }
    }

    #[test]
    fn the_media_bitrate_is_measured_over_the_last_seconds() {
        let mut rate = RateWindow::default();
        let base = Instant::now();
        assert_eq!(0.0, rate.bits_per_second(base));
        // 50 packets a second of 1250 octets for three seconds: 500 kbit/s.
        for n in 0..150u32 {
            rate.add(base + Duration::from_millis(20) * n, 1250);
        }
        let measured = rate.bits_per_second(base + Duration::from_secs(3));
        assert!((measured - 500_000.0).abs() < 75_000.0, "{measured}");
        // Long after the last packet: nothing.
        assert_eq!(0.0, rate.bits_per_second(base + Duration::from_secs(30)));
    }
}
