//! The capacity-cap world: a video call between two `rtci` peer connections in virtual time,
//! over a simulated link whose capacity can be changed while the call runs. Shared by
//! `capacity_cap_video_rtc2rtc.rs` (the scenarios it has always run: path change, cameras, the
//! recovery after the cap) and `capacity_instrument.rs` (what the call's user sees at a capacity
//! drop, as distributions over an ensemble).
//!
//! The scenario is ParolNet's (`parolnet-simnet`): VP8 with RTX and Opus each way, a sender
//! whose video follows the congestion controller's target, and a receiver that reassembles VP8
//! frames with the engine's sample builder and asks for a key frame (PLI) when it has lost its
//! reference. The link is the simulated network's: a fixed one-way delay and, while capped, one
//! datagram at a time at the link's rate behind a drop-tail queue.
//!
//! A run is a function of its [`Setup`] alone when the setup has a wall clock
//! ([`Setup::anchor`]): the peers' crypto providers and RTCP sessions are seeded from
//! [`Setup::seed`], the link's losses from the same seed, and time is virtual (the one
//! `Instant::now()` below is the origin every instant is counted from, never a figure).
//! `capacity_instrument.rs` asserts it (`the_same_seed_gives_the_same_run`).

#![allow(dead_code)]

use anyhow::{Result, bail};
use bytes::Bytes;
use rtci::crypto::{CryptoError, RTCCrypto, RTCCryptoProvider, RTCRandom, default_provider};
use rtci::interceptor::{
    GccHandle, GccInterceptorBuilder, Interceptor as _, NackGeneratorBuilder, NackResponderBuilder,
    PacerBacklog, PassThroughInterceptor, ReceivedRateBound, Registry, RetransmissionRateLimit,
    RtcpRandom, RtcpSessionBuilder, Slot,
};
use rtci::media::io::sample_builder::SampleBuilder;
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::configuration::BehaviourProfile;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::{
    DefaultInterceptorHandles, DefaultInterceptorOptions, configure_key_frame_requests,
    configure_nack, configure_receiver_reference_time, configure_rtcp_reports_with, configure_twcc,
    register_default_interceptors_with_options,
};
use rtci::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtci::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtci::rtp::codec::vp8::Vp8Packet;
use rtci::rtp::packetizer::Packetizer;
use rtci::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters,
    RTCRtpEncodingParameters, RTCRtpRtxParameters, RtpCodecKind,
};
use rtci::rtp_transceiver::{
    RTCRtpReceiverId, RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverId,
};
use rtci::sansio::Protocol;
use rtci::shared::time::SystemInstant;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtci::statistics::StatsSelector;
use rtci::statistics::report::RTCStatsReportEntry;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A small deterministic generator (SplitMix64).
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// The built-in crypto provider with its random source replaced by a seeded [`Rng`] (ICE,
/// DTLS, SCTP), and the RTCP session's report times drawn from the same seed.
pub struct SeededProvider {
    pub inner: Arc<dyn RTCCryptoProvider>,
    pub rng: Mutex<Rng>,
}

impl RTCCryptoProvider for SeededProvider {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn crypto(&self) -> &dyn RTCCrypto {
        self.inner.crypto()
    }

    fn random(&self) -> &dyn RTCRandom {
        self
    }
}

impl RTCRandom for SeededProvider {
    fn fill(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        let mut rng = self.rng.lock().map_err(|_| CryptoError::RandomnessFailed)?;
        for chunk in output.chunks_mut(8) {
            chunk.copy_from_slice(&rng.next_u64().to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

pub struct SeededRtcpRandom(pub Rng);

impl RtcpRandom for SeededRtcpRandom {
    fn next_u32(&mut self) -> u32 {
        (self.0.next_u64() >> 32) as u32
    }
}

thread_local! {
    /// Whether the next `World`'s caller ignores the target: its video stays at the rate it
    /// had before the cap and does not pause.
    pub static IGNORE_TARGET: Cell<bool> = const { Cell::new(false) };
}

/// Which interceptor chain the peers of a run use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Chain {
    /// ParolNet's: NACK, the RTCP reports, key-frame requests, TWCC with the TWCC-driven GCC
    /// (`GccInterceptorBuilder`), no pacer; the video follows `GccHandle::target_bitrate_bps`.
    ParolNet,
    /// The engine's default interceptors (the pacer, GCC on transport-wide feedback, the NACK
    /// pair); the video follows the target the senders are given
    /// (`RTCRtpSender::target_bitrates`).
    Default,
    /// The default interceptors with the pacer's slot passed through.
    DefaultWithoutPacer,
}

/// How a run is set up.
#[derive(Clone, Copy, Debug)]
pub struct Setup {
    pub seed: u64,
    /// The NACK responder's rule; the engine's default when `None`.
    pub rate_limit: Option<RetransmissionRateLimit>,
    pub chain: Chain,
    /// The wall clock at the instant the peers are built (since the Unix epoch): every NTP
    /// time on the wire follows from it, so a run with one is reproducible to the byte, and
    /// runs with different ones differ in the phase of everything derived from NTP times
    /// (round-trip times to 1/65536 s). The process's wall clock when `None`.
    pub anchor: Option<Duration>,
    /// How long the cap stays after the estimate went under 400 kbit/s.
    pub cap: Duration,
    /// The target the caller's encoder has reached when the cap arrives; after 20 s of call,
    /// whatever the target, when `None`.
    pub cap_at_target: Option<u32>,
    /// Whether each peer (caller, callee) has a video track from the first offer on. One
    /// without gains it by renegotiation ([`World::set_video`]).
    pub video: [bool; 2],
    /// `DefaultInterceptorOptions::rtcp_report_from_every_ssrc` for the default chains and
    /// `RtcpSessionBuilder::with_report_from_every_ssrc` for ParolNet's, their default when
    /// `None`.
    pub report_from_every_ssrc: Option<bool>,
    /// The behaviour profile whose interceptor settings the default chains take
    /// (`DefaultInterceptorOptions::for_profile`); the build's default when `None`. The media
    /// engine and the session description stay this world's own.
    pub profile: Option<BehaviourProfile>,
    /// `DefaultInterceptorOptions::rtcp_share_follows_send_rate` for the default chains, the
    /// profile's value when `None`.
    pub share_follows_send_rate: Option<bool>,
    /// `DefaultInterceptorOptions::congestion_feedback_cadence` for the default chains, the
    /// profile's value when `None`.
    pub feedback_cadence: Option<rtci::interceptor::CongestionFeedbackCadence>,
    /// What the estimator's bound by the received rate does (draft-ietf-rmcat-gcc-02 5.5);
    /// the engine's default when `None`.
    pub received_rate_bound: Option<ReceivedRateBound>,
    /// What the default chains' pacer does with its backlog when capacity collapses
    /// (`DefaultInterceptorOptions::pacer_backlog`, docs/capacity-collapse.md); the engine's
    /// default when `None`.
    pub pacer_backlog: Option<PacerBacklog>,
    /// `DefaultInterceptorOptions::rtcp_immediate_congestion_feedback` for the default chains
    /// (`false`: RFC 4585 3.2 and 3.5.2, congestion control feedback takes its turn inside
    /// the RTCP bandwidth), the options' default when `None`.
    pub immediate_congestion_feedback: Option<bool>,
    /// A change of nothing but incidental wire sizes or seeded draws ([`PERTURBATIONS`]); the
    /// permanent tests run [`Perturbation::None`].
    pub perturbation: Perturbation,
    /// How long the receivers wait for a missing video packet before they give the gap up and
    /// ask for a key frame (`SampleBuilder::with_max_gap_wait`, docs/receiver-gap-policy.md).
    /// `None`: no bound in time (the builder's default bound turned off), the gap is held for
    /// the builder's 256 packets or until a complete key frame releases it.
    pub gap_wait: Option<Duration>,
    /// Per cent of the datagrams the callee sends (its media and all its feedback: the
    /// caller's reverse path) that are lost, drawn from the run's seed. Zero: none.
    pub reverse_loss: u32,
    /// Whether the chain probes for bandwidth (`GccInterceptorBuilder::with_bandwidth_probing`
    /// in ParolNet's chain, `DefaultInterceptorOptions::bandwidth_probing` in the default
    /// ones); the chain's own default (on) when `None`.
    pub bandwidth_probing: Option<bool>,
    /// Whether the default chains probe back towards the rate before a large drop
    /// (`DefaultInterceptorOptions::recovery_probing`; off as the engine has it).
    pub recovery_probing: bool,
}

/// What a run may change that no call's quality should depend on: the length of the ICE
/// agent's SOFTWARE text (in every STUN request and success response: the sizes of the
/// consent checks, and with them where every later packet falls in the link's queue), or one
/// more value drawn from each peer's seeded random source before the peer connection is built
/// (every seeded value after it moves: ICE credentials, DTLS randoms, SRTP keys, the RTCP
/// report intervals of the default chain). The seeded figures follow from both (train 23's
/// `o=` session id, drawn from the crypto provider since `conf/jsep-75-session-version`, moved
/// the paced chain's seed 3 freeze from 1.91 to 2.20 s), so a bound is measured over these as
/// well as over seeds and wall clocks ([`measure_the_capacity_cap`], `RTC_CAP_PERTURB`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Perturbation {
    None,
    /// `SettingEngineBuilder::with_ice_software(None)`: no SOFTWARE attribute.
    NoSoftware,
    /// `SettingEngineBuilder::with_ice_software(Some(text))`.
    Software(&'static str),
    /// This many 64-bit values drawn from the seeded crypto provider and dropped first.
    Draws(u32),
}

/// A SOFTWARE text of 27 bytes: the length of the fork's text before the crate rename (the
/// rename moved one seed's figures by changing this length, so the measurement reproduces
/// it). Only the length matters to the simulation; the bytes are neutral filler.
pub const SOFTWARE_27: &str = "pre-rename SOFTWARE length.";
/// A SOFTWARE text of 40 bytes, longer than any the engine has sent.
pub const SOFTWARE_40: &str = "rtci-ice 0.2.0-dev (perturbation: 40 B).";
const _: () = assert!(SOFTWARE_27.len() == 27 && SOFTWARE_40.len() == 40);

/// The perturbations of the measurement, by name. The engine's own SOFTWARE text is
/// `rtci-ice 0.2.0-dev` (18 bytes).
pub const PERTURBATIONS: [(&str, Perturbation); 6] = [
    ("none", Perturbation::None),
    ("nosw", Perturbation::NoSoftware),
    ("sw27", Perturbation::Software(SOFTWARE_27)),
    ("sw40", Perturbation::Software(SOFTWARE_40)),
    ("draw1", Perturbation::Draws(1)),
    ("draw2", Perturbation::Draws(2)),
];

impl Setup {
    pub fn new(seed: u64, rate_limit: Option<RetransmissionRateLimit>) -> Self {
        Self {
            seed,
            rate_limit,
            chain: Chain::ParolNet,
            anchor: None,
            cap: Duration::from_secs(20),
            cap_at_target: None,
            video: [true, true],
            report_from_every_ssrc: None,
            profile: None,
            share_follows_send_rate: None,
            feedback_cadence: None,
            received_rate_bound: None,
            pacer_backlog: None,
            immediate_congestion_feedback: None,
            perturbation: Perturbation::None,
            gap_wait: None,
            reverse_loss: 0,
            bandwidth_probing: None,
            recovery_probing: false,
        }
    }

    /// The default chains' pacer keeps (`Keep`) or flushes (`Flush`) its backlog at a collapse.
    pub fn pacer_backlog(mut self, backlog: PacerBacklog) -> Self {
        self.pacer_backlog = Some(backlog);
        self
    }

    /// The receivers give a gap up after `wait` and ask for a key frame.
    pub fn gap_wait(mut self, wait: Duration) -> Self {
        self.gap_wait = Some(wait);
        self
    }

    /// The chain does not probe for bandwidth: the estimate climbs from its 300 kbit/s as the
    /// delay-based controller raises it (8% a second, draft-ietf-rmcat-gcc-02 section 5.5),
    /// which is how a call meets a cap at a chosen rate below the path's.
    pub fn without_bandwidth_probing(mut self) -> Self {
        self.bandwidth_probing = Some(false);
        self
    }

    /// The default chains with recovery probing
    /// (`DefaultInterceptorOptions::recovery_probing`).
    pub fn recovery_probing(mut self) -> Self {
        self.recovery_probing = true;
        self
    }

    /// `per_cent` of the callee's datagrams are lost.
    pub fn reverse_loss(mut self, per_cent: u32) -> Self {
        self.reverse_loss = per_cent;
        self
    }

    /// Every local SSRC reports on every other (RFC 8108 section 5.1) or the blocks go once.
    pub fn report_from_every_ssrc(mut self, every: bool) -> Self {
        self.report_from_every_ssrc = Some(every);
        self
    }

    /// Congestion control feedback sent at once (`true`) or under RFC 4585 3.5.2's timing,
    /// inside the RTCP bandwidth (`false`), in the default chain.
    pub fn immediate_congestion_feedback(mut self, immediate: bool) -> Self {
        self.immediate_congestion_feedback = Some(immediate);
        self
    }

    /// The default chains take the interceptor settings of `profile`.
    pub fn profile(mut self, profile: BehaviourProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    /// The default chains' RTCP share follows the send rate (or not), whatever the profile
    /// says.
    pub fn share_follows_send_rate(mut self, follows: bool) -> Self {
        self.share_follows_send_rate = Some(follows);
        self
    }

    /// The default chains' congestion control feedback is built with `cadence`.
    pub fn feedback_cadence(
        mut self,
        cadence: rtci::interceptor::CongestionFeedbackCadence,
    ) -> Self {
        self.feedback_cadence = Some(cadence);
        self
    }

    /// The estimator's bound by the received rate set to `bound` in either chain.
    pub fn received_rate_bound(mut self, bound: ReceivedRateBound) -> Self {
        self.received_rate_bound = Some(bound);
        self
    }

    pub fn perturbed(mut self, perturbation: Perturbation) -> Self {
        self.perturbation = perturbation;
        self
    }

    /// A call that starts with audio alone, either way.
    pub fn audio_only(mut self) -> Self {
        self.video = [false, false];
        self
    }

    pub fn chain(mut self, chain: Chain) -> Self {
        self.chain = chain;
        self
    }

    pub fn anchor(mut self, anchor: Duration) -> Self {
        self.anchor = Some(anchor);
        self
    }

    /// The cap arrives when the caller's target has reached `bps`, not after 20 s.
    pub fn capped_at_a_target_of(mut self, bps: u32) -> Self {
        self.cap_at_target = Some(bps);
        self
    }
}

/// Three wall clocks a run is repeated on: the same second, a different phase within it.
///
/// A seeded run is reproducible for one wire image only: its figures follow from every
/// packet's size, down to the ICE agent's SOFTWARE text in each STUN message (its length moved
/// the paced chain's target at the cap's end from 212 to 132 kbit/s on one seed), so a bound
/// on them is measured over seeds and wall clocks, never on one run's figure.
pub const ANCHORS: [Duration; 3] = [
    Duration::new(1_800_000_000, 0),
    Duration::new(1_800_000_000, 333_333_333),
    Duration::new(1_800_000_000, 777_777_777),
];

pub const VP8_PT: u8 = 96;
pub const RTX_PT: u8 = 97;
/// The retransmission format of `video/red` the engine registers with video RED / ULPFEC
/// (`VIDEO_RED_RTX_PAYLOAD_TYPE`, `apt=116`).
pub const RED_RTX_PT: u8 =
    rtci::peer_connection::configuration::interceptor_registry::VIDEO_RED_RTX_PAYLOAD_TYPE;
pub const OPUS_PT: u8 = 111;
/// Payload size of an outgoing RTP packet (ParolNet's `RTP_OUTBOUND_MTU`).
pub const RTP_MTU: usize = 1200;
pub const VIDEO_FPS: u32 = 30;
/// What the audio takes of the estimate (ParolNet's `AUDIO_SHARE_BPS`: Opus at about
/// 60 kbit/s with RTP and SRTP overhead, 50 packets a second).
pub const AUDIO_SHARE_BPS: u32 = 80_000;
/// An Opus packet of 20 ms at about 60 kbit/s.
pub const OPUS_PAYLOAD: usize = 150;
/// GCC's bounds (ParolNet's `CongestionConfig::default()`).
pub const MIN_BPS: u32 = 100_000;
pub const MAX_BPS: u32 = 2_500_000;

/// The video bitrate for an estimate: what is left after the audio, with a tenth held back
/// for retransmissions (ParolNet's `video_bitrate_for`).
pub fn video_bitrate_for(total_bps: u32) -> u32 {
    let left = total_bps.saturating_sub(AUDIO_SHARE_BPS);
    ((u64::from(left) * 9 / 10) as u32).max(30_000)
}

/// The rate-following video source (ParolNet's `VideoModel`): frames whose sizes add up to
/// the bitrate, a keyframe five times a frame's budget that the following frames pay for. A
/// frame is a VP8 frame tag (bit 0 clear: keyframe), "PN", its number and its length.
#[derive(Default)]
pub struct VideoModel {
    pub number: u32,
    pub debt: i64,
}

impl VideoModel {
    pub const HEADER: usize = 13;

    pub fn next_frame(&mut self, bitrate: u32, key: bool) -> Vec<u8> {
        let budget = i64::from(bitrate / 8 / VIDEO_FPS);
        let wanted = if key { budget * 5 } else { budget };
        let size = (wanted - self.debt.clamp(0, budget * 3 / 4)).max(Self::HEADER as i64 + 3);
        self.debt += size - budget;
        self.debt = self.debt.max(-budget);
        let size = size as usize;
        let mut frame = vec![0xa5u8; size];
        frame[0] = if key { 0x10 } else { 0x11 };
        frame[1] = 0;
        frame[2] = 0;
        frame[3] = b'P';
        frame[4] = b'N';
        frame[5..9].copy_from_slice(&self.number.to_be_bytes());
        frame[9..13].copy_from_slice(&(size as u32).to_be_bytes());
        self.number = self.number.wrapping_add(1);
        frame
    }
}

/// A decoder's rule: a delta frame is usable only when the frame before it was.
#[derive(Default)]
pub struct ModelDecoder {
    pub last: Option<u32>,
}

impl ModelDecoder {
    /// Whether the reassembled `frame` is usable; `None` for something that is no frame.
    pub fn accept(&mut self, frame: &[u8]) -> Option<bool> {
        if frame.len() < VideoModel::HEADER || &frame[3..5] != b"PN" {
            return None;
        }
        let number = u32::from_be_bytes(frame[5..9].try_into().ok()?);
        let length = u32::from_be_bytes(frame[9..13].try_into().ok()?) as usize;
        let (key, complete) = (frame[0] & 1 == 0, frame.len() == length);
        let usable = complete && (key || self.last.is_some_and(|l| number == l.wrapping_add(1)));
        if usable {
            self.last = Some(number);
        } else if complete
            && self
                .last
                .is_some_and(|l| number.wrapping_sub(l) > u32::MAX / 2 || number == l)
        {
            return Some(false);
        } else {
            self.last = None;
        }
        Some(usable)
    }
}

/// How one host's uplink treats what it sends.
#[derive(Clone, Copy, Debug)]
pub struct LinkProfile {
    pub delay: Duration,
    /// Capacity in bits per second (`None`: unlimited).
    pub rate_bps: Option<u64>,
    /// The drop-tail queue, as time at the link's rate.
    pub queue: Duration,
}

impl LinkProfile {
    /// A good link: 10 ms one way, no cap.
    pub fn open() -> Self {
        Self {
            delay: Duration::from_millis(10),
            rate_bps: None,
            queue: Duration::from_millis(300),
        }
    }

    /// 300 kbit/s, 30 ms one way, 300 ms of queue.
    pub fn capped_300k() -> Self {
        Self {
            delay: Duration::from_millis(30),
            rate_bps: Some(300_000),
            queue: Duration::from_millis(300),
        }
    }
}

pub struct Uplink {
    pub profile: LinkProfile,
    pub busy_until: Option<Instant>,
    pub last_delivery: Option<Instant>,
    pub queue_drops: u64,
    /// Retransmissions (RTX packets that carry a repaired packet), and those of them dropped at
    /// the queue.
    pub rtx_sent: u64,
    pub rtx_dropped: u64,
    /// Probe padding on the RTX stream (padding-only RTX packets that carry no media), counted
    /// apart from the retransmissions, and those dropped at the queue.
    pub padding_sent: u64,
    pub padding_dropped: u64,
    pub audio_dropped: u64,
}

impl Uplink {
    pub fn new() -> Self {
        Self {
            profile: LinkProfile::open(),
            busy_until: None,
            last_delivery: None,
            queue_drops: 0,
            rtx_sent: 0,
            rtx_dropped: 0,
            padding_sent: 0,
            padding_dropped: 0,
            audio_dropped: 0,
        }
    }

    pub fn set_profile(&mut self, profile: LinkProfile) {
        self.profile = profile;
        self.busy_until = None;
    }

    /// When a datagram of `size` octets sent at `now` arrives, `None` when the queue drops
    /// it. Nothing overtakes: a datagram never arrives before one sent earlier.
    pub fn send(&mut self, now: Instant, size: usize) -> Option<Instant> {
        let mut leaves = now;
        if let Some(rate) = self.profile.rate_bps.filter(|r| *r > 0) {
            let start = self.busy_until.map_or(now, |t| t.max(now));
            if start.saturating_duration_since(now) > self.profile.queue {
                self.queue_drops += 1;
                return None;
            }
            leaves = start + Duration::from_secs_f64(size as f64 * 8.0 / rate as f64);
            self.busy_until = Some(leaves);
        }
        let at = self
            .last_delivery
            .map_or(leaves + self.profile.delay, |last| {
                (leaves + self.profile.delay).max(last)
            });
        self.last_delivery = Some(at);
        Some(at)
    }
}

/// The RTP payload type of an SRTP datagram (RFC 7983 first byte, RFC 5761 second byte).
pub fn rtp_payload_type(data: &[u8]) -> Option<u8> {
    match data {
        [b0, b1, ..] if (128..=191).contains(b0) && !(192..=223).contains(b1) => Some(b1 & 0x7f),
        _ => None,
    }
}

pub struct Peer {
    pub pc: RTCPeerConnection,
    pub addr: SocketAddr,
    pub connected: bool,
    /// ParolNet's chain: its GCC's handle.
    pub gcc: Option<GccHandle>,
    /// The default chain: its handles.
    pub handles: Option<DefaultInterceptorHandles>,
    /// The video packets the application wrote, and those that left the host (by sequence
    /// number): the difference never reached the wire (dropped by a pacer).
    pub video_written: BTreeSet<u16>,
    pub video_left: BTreeSet<u16>,
    /// The video packets written from 1 s on (the first key frame, written as the connection
    /// comes up, is not the pacer's to lose), and the call's time at the current write.
    pub video_written_late: BTreeMap<u16, Duration>,
    pub media_elapsed: Duration,
    pub audio: RTCRtpSenderId,
    /// The video sender, once the peer has a video track.
    pub video: Option<RTCRtpSenderId>,
    pub audio_packetizer: Option<Box<dyn Packetizer>>,
    pub video_packetizer: Option<Box<dyn Packetizer>>,
    /// The estimate the encoder follows, read every 100 ms.
    pub target_bps: u32,
    /// (time, estimate) each time it moved.
    pub targets: Vec<(Duration, u32)>,
    pub model: VideoModel,
    pub force_key: bool,
    pub keyframes_sent: Vec<Duration>,
    /// The receiving side.
    pub video_receiver: Option<RTCRtpReceiverId>,
    pub builder: SampleBuilder<Vp8Packet>,
    /// The builder's bound on a gap in time ([`Setup::gap_wait`]).
    pub gap_wait: Option<Duration>,
    /// Every Opus packet received: when, and its sequence number.
    pub audio_arrivals: Vec<(Duration, u16)>,
    /// How often the connection state left Connected, and whether it reached Failed
    /// ([`World::tolerate_failure`]).
    pub left_connected: u32,
    pub failed: bool,
    /// Every connection state the application was told of, and when.
    pub states: Vec<(Duration, RTCPeerConnectionState)>,
    pub decoder: ModelDecoder,
    pub usable_at: Vec<Duration>,
    /// How long after its capture each usable frame came out of the decoder.
    pub usable_lag: Vec<Duration>,
    pub unusable: u64,
    pub last_keyframe_request: Option<Instant>,
    pub keyframe_requests: Vec<Duration>,
    /// The sending side: every `OnPacerDiscard` (time, frames, packets), and the key-frame
    /// requests (PLI / FIR) it was handed.
    pub pacer_discards: Vec<(Duration, u32, usize)>,
    pub key_requests_received: u32,
    /// The key-frame requests the engine itself made of this peer's application (a Picture
    /// Loss Indication with sender SSRC 0: the pacer's, at a discard or a flush of its
    /// backlog): when, and the media SSRC named.
    pub local_key_requests: Vec<(Duration, u32)>,
    /// Every `OnKeyFrameRequest`: when, and the sender named.
    pub key_frame_request_events: Vec<(Duration, RTCRtpSenderId)>,
    /// When the application was told of a selected candidate pair, with the estimate then.
    pub pair_changes: Vec<(Duration, Option<u32>)>,
    /// The lowest `availableOutgoingBitrate` of the nominated pair (webrtc-stats) and the
    /// lowest estimate of the congestion controller, each read every 100 ms once there is one.
    pub lowest_outgoing: Option<f64>,
    pub lowest_estimate: Option<u32>,
    /// Octets of video frames the application wrote.
    pub video_octets: u64,
    /// (time, estimate) each time the congestion controller's estimate moved, looked at
    /// after every step of the world while it is `sampling`.
    pub estimates: Vec<(Duration, u32)>,
}

pub fn video_codec() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90_000,
        channels: 0,
        sdp_fmtp_line: String::new(),
        rtcp_feedback: [
            ("goog-remb", ""),
            ("ccm", "fir"),
            ("nack", ""),
            ("nack", "pli"),
        ]
        .into_iter()
        .map(|(typ, parameter)| RTCPFeedback {
            typ: typ.to_owned(),
            parameter: parameter.to_owned(),
        })
        .collect(),
    }
}

pub fn opus_codec() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_OPUS.to_owned(),
        clock_rate: 48_000,
        channels: 2,
        sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
        rtcp_feedback: vec![],
    }
}

pub fn track(
    kind: RtpCodecKind,
    codec: RTCRtpCodec,
    ssrc: u32,
    rtx: Option<u32>,
) -> MediaStreamTrack {
    let name = if kind == RtpCodecKind::Video {
        "video"
    } else {
        "audio"
    };
    MediaStreamTrack::new(
        "call".to_owned(),
        name.to_owned(),
        name.to_owned(),
        kind,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                rtx: rtx.map(|ssrc| RTCRtpRtxParameters { ssrc }),
                ..Default::default()
            },
            codec,
            ..Default::default()
        }],
    )
}

/// A peer's video track: the stream after its audio's, with a retransmission stream.
pub fn video_track(ssrc_base: u32) -> MediaStreamTrack {
    track(
        RtpCodecKind::Video,
        video_codec(),
        ssrc_base + 1,
        Some(ssrc_base + 2),
    )
}

impl Peer {
    /// A peer with ParolNet's media engine and interceptor chain, sending Opus and VP8; its
    /// NACK responder holds retransmissions to `rate_limit`, the engine's default when `None`.
    pub fn new(
        addr: &str,
        setup: &Setup,
        salt: u64,
        ssrc_base: u32,
        video: bool,
        start: Instant,
    ) -> Result<Self> {
        let seed = setup.seed ^ salt;
        let rate_limit = setup.rate_limit;
        let wall_clock = setup.anchor.map(|anchor| SystemInstant::at(start, anchor));
        let mut rng = Rng(seed);
        if let Perturbation::Draws(draws) = setup.perturbation {
            for _ in 0..draws {
                rng.next_u64();
            }
        }
        let provider: Arc<dyn RTCCryptoProvider> = Arc::new(SeededProvider {
            inner: default_provider()?,
            rng: Mutex::new(rng),
        });
        let mut media_engine = MediaEngine::default();
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: video_codec(),
                payload_type: VP8_PT,
            },
            RtpCodecKind::Video,
        )?;
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_RTX.to_owned(),
                    clock_rate: 90_000,
                    channels: 0,
                    sdp_fmtp_line: format!("apt={VP8_PT}"),
                    rtcp_feedback: vec![],
                },
                payload_type: RTX_PT,
            },
            RtpCodecKind::Video,
        )?;
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: opus_codec(),
                payload_type: OPUS_PT,
            },
            RtpCodecKind::Audio,
        )?;
        if setup.chain != Chain::ParolNet {
            let mut options = match setup.profile {
                Some(profile) => DefaultInterceptorOptions::for_profile(profile),
                None => DefaultInterceptorOptions::default(),
            };
            if let Some(follows) = setup.share_follows_send_rate {
                options.rtcp_share_follows_send_rate = follows;
            }
            if let Some(cadence) = setup.feedback_cadence {
                options.congestion_feedback_cadence = cadence;
            }
            options.rtcp_random = Some(provider.clone());
            options.wall_clock = wall_clock;
            if let Some(every) = setup.report_from_every_ssrc {
                options.rtcp_report_from_every_ssrc = every;
            }
            if let Some(rate_limit) = rate_limit {
                options.nack_retransmission_rate_limit = rate_limit;
            }
            if let Some(backlog) = setup.pacer_backlog {
                options.pacer_backlog = backlog;
            }
            if let Some(bound) = setup.received_rate_bound {
                options.gcc_received_rate_bound = bound;
            }
            if setup.recovery_probing {
                options.recovery_probing = true;
            }
            if let Some(immediate) = setup.immediate_congestion_feedback {
                options.rtcp_immediate_congestion_feedback = immediate;
            }
            if let Some(probing) = setup.bandwidth_probing {
                options.bandwidth_probing = probing;
            }
            let (mut registry, handles) = register_default_interceptors_with_options(
                Registry::new(),
                &mut media_engine,
                &options,
            )?;
            if setup.chain == Chain::DefaultWithoutPacer {
                registry = registry.with(Slot::Pacer, PassThroughInterceptor::new());
            }
            // The application's bounds, as ParolNet gives its GCC.
            handles
                .congestion_control
                .set_min_bitrate(Some(f64::from(MIN_BPS)));
            handles
                .congestion_control
                .set_session_bitrate_limit(Some(f64::from(MAX_BPS)));
            return Self::with_chain(
                addr,
                setup,
                provider,
                media_engine,
                registry,
                ssrc_base,
                video,
                None,
                Some(handles),
                start,
            );
        }
        let registry = match rate_limit {
            None => configure_nack(Registry::new(), &mut media_engine),
            // `configure_nack` with the responder's rule set (the codec carries the NACK
            // feedback already).
            Some(rate_limit) => Registry::new()
                .with(
                    Slot::NackResponder,
                    NackResponderBuilder::new()
                        .with_rate_limit(rate_limit)
                        .build(),
                )
                .with(Slot::NackGenerator, NackGeneratorBuilder::new().build()),
        };
        let session = RtcpSessionBuilder::new()
            .with_t_rr_interval(Duration::ZERO)
            .with_random(SeededRtcpRandom(Rng(seed ^ 0x5eed)));
        let session = match setup.report_from_every_ssrc {
            Some(every) => session.with_report_from_every_ssrc(every),
            None => session,
        };
        let session = match wall_clock {
            Some(anchor) => session.with_wall_clock(anchor),
            None => session,
        };
        let registry = configure_rtcp_reports_with(registry, session);
        configure_receiver_reference_time(&mut media_engine);
        let registry = configure_key_frame_requests(registry);
        let (gcc, handle) = GccInterceptorBuilder::new();
        let gcc = match setup.received_rate_bound {
            Some(bound) => gcc.with_received_rate_bound(bound),
            None => gcc,
        };
        let gcc = match setup.bandwidth_probing {
            Some(probing) => gcc.with_bandwidth_probing(probing),
            None => gcc,
        };
        let registry = configure_twcc(registry, &mut media_engine)?.with(
            Slot::CongestionControl,
            PassThroughInterceptor::new().with(
                gcc.with_min_bitrate(MIN_BPS)
                    .with_max_bitrate(MAX_BPS)
                    .build(),
            ),
        );
        Self::with_chain(
            addr,
            setup,
            provider,
            media_engine,
            registry,
            ssrc_base,
            video,
            Some(handle),
            None,
            start,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_chain(
        addr: &str,
        setup: &Setup,
        provider: Arc<dyn RTCCryptoProvider>,
        media_engine: MediaEngine,
        registry: Registry,
        ssrc_base: u32,
        video: bool,
        gcc: Option<GccHandle>,
        handles: Option<DefaultInterceptorHandles>,
        start: Instant,
    ) -> Result<Self> {
        let setting_engine = SettingEngineBuilder::new().with_crypto_provider(provider);
        let setting_engine = match setup.perturbation {
            Perturbation::NoSoftware => setting_engine.with_ice_software(None),
            Perturbation::Software(text) => setting_engine.with_ice_software(Some(text.to_owned())),
            Perturbation::None | Perturbation::Draws(_) => setting_engine,
        };
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(setting_engine.build())
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(start)?;
        let audio = pc.add_track(track(RtpCodecKind::Audio, opus_codec(), ssrc_base, None))?;
        let video = if video {
            Some(pc.add_track(video_track(ssrc_base))?)
        } else {
            None
        };
        let builder = SampleBuilder::new(256, Vp8Packet::default(), 90_000);
        Ok(Self {
            pc,
            addr: addr.parse()?,
            connected: false,
            gcc,
            handles,
            video_written: BTreeSet::new(),
            video_left: BTreeSet::new(),
            video_written_late: BTreeMap::new(),
            media_elapsed: Duration::ZERO,
            audio,
            video,
            audio_packetizer: None,
            video_packetizer: None,
            target_bps: 300_000,
            targets: Vec::new(),
            model: VideoModel::default(),
            force_key: true,
            keyframes_sent: Vec::new(),
            video_receiver: None,
            builder: builder.with_max_gap_wait(setup.gap_wait),
            gap_wait: setup.gap_wait,
            audio_arrivals: Vec::new(),
            left_connected: 0,
            states: Vec::new(),
            failed: false,
            decoder: ModelDecoder::default(),
            usable_at: Vec::new(),
            usable_lag: Vec::new(),
            unusable: 0,
            last_keyframe_request: None,
            keyframe_requests: Vec::new(),
            pacer_discards: Vec::new(),
            key_requests_received: 0,
            local_key_requests: Vec::new(),
            key_frame_request_events: Vec::new(),
            pair_changes: Vec::new(),
            lowest_outgoing: None,
            lowest_estimate: None,
            video_octets: 0,
            estimates: Vec::new(),
        })
    }

    pub fn candidate(&self) -> Result<RTCIceCandidateInit> {
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: self.addr.ip().to_string(),
                port: self.addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        Ok(RTCIceCandidate::from(&candidate).to_json()?)
    }

    /// Packetize one frame of `kind` and hand it to the engine.
    pub fn send_frame(
        &mut self,
        now: Instant,
        video: bool,
        data: &[u8],
        samples: u32,
    ) -> Result<()> {
        let Some(id) = (if video { self.video } else { Some(self.audio) }) else {
            return Ok(());
        };
        let Some(mut sender) = self.pc.rtp_sender(id) else {
            return Ok(());
        };
        let packetizer = if video {
            &mut self.video_packetizer
        } else {
            &mut self.audio_packetizer
        };
        if packetizer.is_none() {
            let Some(ssrc) = sender.ssrcs().next() else {
                return Ok(());
            };
            let Some(codec) = sender
                .get_parameters()
                .rtp_parameters
                .codecs
                .iter()
                .find(|c| !c.rtp_codec.mime_type.eq_ignore_ascii_case(MIME_TYPE_RTX))
                .cloned()
            else {
                return Ok(());
            };
            *packetizer = Some(Box::new(rtci::rtp::packetizer::new_packetizer(
                now,
                RTP_MTU,
                codec.payload_type,
                ssrc,
                codec.rtp_codec.payloader()?,
                Box::new(rtci::rtp::sequence::new_fixed_sequencer(
                    (ssrc as u16).wrapping_mul(7),
                )),
                codec.rtp_codec.clock_rate,
            )));
        }
        let Some(packetizer) = packetizer.as_mut() else {
            return Ok(());
        };
        if video {
            self.video_octets += data.len() as u64;
        }
        for packet in packetizer.packetize(now, &Bytes::copy_from_slice(data), samples)? {
            if video {
                self.video_written.insert(packet.header.sequence_number);
                if self.media_elapsed >= Duration::from_secs(1) {
                    self.video_written_late
                        .insert(packet.header.sequence_number, self.media_elapsed);
                }
            }
            sender.write_rtp(now, packet)?;
        }
        Ok(())
    }

    /// The target the encoder follows: GCC's handle in ParolNet's chain; in the default chain
    /// the sum of what the two senders are given.
    pub fn media_target(&mut self) -> Option<u32> {
        if let Some(gcc) = &self.gcc {
            return gcc.target_bitrate_bps();
        }
        let mut total = 0.0;
        let mut shares = 0;
        for id in [Some(self.audio), self.video].into_iter().flatten() {
            if let Some(sender) = self.pc.rtp_sender(id) {
                let targets = sender.target_bitrates();
                shares += targets.len();
                total += targets.iter().map(|(_, bps)| bps).sum::<f64>();
            }
        }
        // Zero is a target too: the pacer's pause.
        (shares > 0).then_some(total as u32)
    }

    /// The fraction of packets the congestion controller counts as lost (smoothed).
    pub fn packet_loss(&self) -> Option<f64> {
        match (&self.gcc, &self.handles) {
            (Some(gcc), _) => gcc.stats().packet_loss,
            (None, Some(handles)) => handles.congestion_control.stats().packet_loss,
            _ => None,
        }
    }

    /// The congestion controller's estimate itself.
    pub fn estimate(&self) -> Option<u32> {
        match (&self.gcc, &self.handles) {
            (Some(gcc), _) => gcc.estimate_bps(),
            (None, Some(handles)) => Some(handles.congestion_control.target_bitrate() as u32),
            _ => None,
        }
    }

    /// `availableOutgoingBitrate` of the nominated candidate pair.
    pub fn available_outgoing(&mut self, now: Instant) -> Option<f64> {
        self.pc
            .get_stats(now, StatsSelector::None)
            .iter()
            .find_map(|entry| match entry {
                RTCStatsReportEntry::IceCandidatePair(pair) if pair.nominated => {
                    pair.available_outgoing_bitrate
                }
                _ => None,
            })
    }

    /// The estimator's delay-based and loss-based halves.
    pub fn halves(&self) -> (u32, u32) {
        let stats = match (&self.gcc, &self.handles) {
            (Some(gcc), _) => gcc.stats(),
            (None, Some(handles)) => handles.congestion_control.stats(),
            _ => return (0, 0),
        };
        (
            stats.delay_based_bitrate.unwrap_or(0.0) as u32,
            stats.loss_based_bitrate.unwrap_or(0.0) as u32,
        )
    }

    /// The SSRCs of this peer's flows that the RTP circuit breaker (RFC 8083) has ceased: the
    /// engine drops what the application writes on them from then on. None in ParolNet's
    /// chain, which has no breaker.
    pub fn breaker_ceased(&self) -> Vec<u32> {
        self.handles.as_ref().map_or_else(Vec::new, |handles| {
            handles
                .circuit_breaker
                .ceased()
                .into_iter()
                .map(|(ssrc, _)| ssrc)
                .collect()
        })
    }

    /// Every frame the builder has ready goes to the decoder: a usable one is on the screen
    /// from `at` (the call's time at `now`), with the lag from its capture.
    pub fn take_frames(&mut self, now: Instant, at: Duration) {
        while let Some(sample) = self.builder.pop(now) {
            match self.decoder.accept(&sample.data) {
                Some(true) => {
                    self.usable_at.push(at);
                    let data = &sample.data;
                    let captured = u32::from_be_bytes([
                        0,
                        data[VideoModel::HEADER],
                        data[VideoModel::HEADER + 1],
                        data[VideoModel::HEADER + 2],
                    ]);
                    self.usable_lag
                        .push(at.saturating_sub(Duration::from_millis(u64::from(captured) * 10)));
                }
                Some(false) => self.unusable += 1,
                None => {}
            }
        }
    }

    /// The receiver's clock, for a builder with a bound on a gap in time
    /// ([`Setup::gap_wait`]): a gap that has waited the bound is given up although no packet
    /// arrives (what was complete behind it comes out), and the sender is asked for a key
    /// frame at once, at most once a second (docs/receiver-gap-policy.md, rule 2).
    pub fn gap_timeout(&mut self, now: Instant, at: Duration) -> Result<()> {
        if self.gap_wait.is_none() || self.video_receiver.is_none() {
            return Ok(());
        }
        self.take_frames(now, at);
        let gave_up = self.builder.take_key_frame_request();
        if (gave_up || self.decoder.last.is_none())
            && !self.usable_at.is_empty()
            && self
                .last_keyframe_request
                .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(1))
        {
            self.last_keyframe_request = Some(now);
            self.keyframe_requests.push(at);
            self.request_keyframe(now)?;
        }
        Ok(())
    }

    /// Ask the sender of the received video for a key frame (PLI), as ParolNet's
    /// `request_keyframes` does.
    pub fn request_keyframe(&mut self, now: Instant) -> Result<()> {
        if let Some(id) = self.video_receiver
            && let Some(mut receiver) = self.pc.rtp_receiver(id)
            && let Some(media_ssrc) = { receiver.track().ssrcs().next() }
        {
            receiver.write_rtcp(
                now,
                vec![Box::new(PictureLossIndication {
                    sender_ssrc: 0,
                    media_ssrc,
                })],
            )?;
        }
        Ok(())
    }
}

pub struct InFlight {
    pub at: Instant,
    pub order: u64,
    pub from: SocketAddr,
    pub to: SocketAddr,
    pub data: bytes::BytesMut,
}

pub struct World {
    pub peers: [Peer; 2],
    pub uplinks: [Uplink; 2],
    pub start: Instant,
    pub now: Instant,
    pub in_flight: Vec<InFlight>,
    pub order: u64,
    pub next_audio: Instant,
    pub next_video: Instant,
    pub next_target: Instant,
    pub frame: u64,
    pub media: bool,
    /// Whether each peer's camera is on: its video source produces frames.
    pub video_on: [bool; 2],
    /// Every 100 ms: time, the caller's estimate, its uplink's queue and drops, the
    /// retransmissions it sent and lost there, the callee's usable frames so far. Printed
    /// with `RTC_CAP_TRACE=1`.
    pub trace: Vec<String>,
    /// Nothing sent either way arrives (both hosts' network is gone).
    pub blackhole: bool,
    /// Only STUN arrives until the caller's application is told of a newly selected pair: the
    /// path the media went on is gone, and the new one carries the restart's checks first.
    pub stun_only: bool,
    /// The caller's estimate and counted loss after every step, while `sampling`.
    pub sampling: bool,
    pub samples: Vec<(Duration, Option<u32>, Option<f64>)>,
    /// [`Setup::reverse_loss`] and the generator its losses are drawn from.
    pub reverse_loss: u32,
    pub loss_rng: Rng,
    /// Per cent of the datagrams the caller sends that are lost while this is not zero (the
    /// instrument's forward-loss scenario), drawn from the same generator.
    pub forward_loss: u32,
    /// A peer connection that fails does not end the run ([`Peer::failed`] records it): for
    /// a measurement that reports the failure as a figure. Off: the run ends with an error.
    pub tolerate_failure: bool,
    /// The STUN datagrams (ICE consent checks and their responses, RFC 7675) that did not
    /// arrive: dropped at a link's queue, or lost on the reverse path.
    pub stun_lost: u32,
    /// Until then none of the callee's RTCP reaches the link: a feedback outage with the
    /// capacity unchanged (the instrument's `fbgap` scenario).
    pub feedback_outage_until: Option<Instant>,
    /// The RTCP datagrams that outage took.
    pub feedback_outage_lost: u32,
}

/// Whether a datagram is SRTCP (RFC 7983 first octet, RFC 5761 packet type).
pub fn is_rtcp(data: &[u8]) -> bool {
    matches!(data, [b0, b1, ..] if (128..=191).contains(b0) && (192..=223).contains(b1))
}

impl World {
    pub fn elapsed(&self) -> Duration {
        self.now.duration_since(self.start)
    }

    pub fn pump(&mut self) -> Result<()> {
        loop {
            let mut moved = false;
            for i in 0..2 {
                while let Some(msg) = self.peers[i].pc.poll_write() {
                    moved = true;
                    let payload_type = rtp_payload_type(&msg.message);
                    if payload_type == Some(VP8_PT)
                        && msg.message.len() >= 12
                        && msg.message[8..12]
                            == (0x1000_0001u32 + 0x1000_0000 * i as u32).to_be_bytes()
                    {
                        let seq = u16::from_be_bytes([msg.message[2], msg.message[3]]);
                        self.peers[i].video_left.insert(seq);
                    }
                    // RFC 7983: a first octet of 0 to 3 is STUN.
                    let stun = msg.message.first().is_some_and(|b| *b <= 3);
                    if self.blackhole
                        || (self.stun_only && !stun && self.peers[0].pair_changes.is_empty())
                    {
                        continue;
                    }
                    // The reverse path's loss ([`Setup::reverse_loss`]): the callee's
                    // datagram never reaches the link.
                    let lost = i == 1
                        && self.reverse_loss > 0
                        && self.loss_rng.next_u64() % 100 < u64::from(self.reverse_loss);
                    let in_outage = i == 1
                        && self.feedback_outage_until.is_some_and(|t| self.now < t)
                        && is_rtcp(&msg.message);
                    self.feedback_outage_lost += u32::from(in_outage);
                    let lost = lost
                        || in_outage
                        || (i == 0
                            && self.forward_loss > 0
                            && self.loss_rng.next_u64() % 100 < u64::from(self.forward_loss));
                    let arrives = if lost {
                        None
                    } else {
                        self.uplinks[i].send(self.now, msg.message.len())
                    };
                    // A bandwidth probe is a padding-only packet of the RTX stream: the RTP
                    // header's padding bit (RFC 3550 section 5.1), in the clear under SRTP, is
                    // set on it and never on a retransmission (RFC 4588 section 4 carries no
                    // padding).
                    // (The RTX of red too: video sent in RED, the `Chrome` profile, is
                    // retransmitted under it.)
                    if payload_type == Some(RTX_PT) || payload_type == Some(RED_RTX_PT) {
                        let link = &mut self.uplinks[i];
                        if msg.message[0] & 0x20 != 0 {
                            link.padding_sent += 1;
                            link.padding_dropped += u64::from(arrives.is_none());
                        } else {
                            link.rtx_sent += 1;
                            link.rtx_dropped += u64::from(arrives.is_none());
                        }
                    }
                    if payload_type == Some(OPUS_PT) {
                        self.uplinks[i].audio_dropped += u64::from(arrives.is_none());
                    }
                    if stun && arrives.is_none() {
                        self.stun_lost += 1;
                    }
                    let Some(at) = arrives else { continue };
                    self.order += 1;
                    self.in_flight.push(InFlight {
                        at,
                        order: self.order,
                        from: msg.transport.local_addr,
                        to: msg.transport.peer_addr,
                        data: msg.message,
                    });
                }
            }
            let now = self.now;
            let mut due: Vec<InFlight> = Vec::new();
            let mut i = 0;
            while i < self.in_flight.len() {
                if self.in_flight[i].at <= now {
                    due.push(self.in_flight.swap_remove(i));
                } else {
                    i += 1;
                }
            }
            due.sort_by_key(|d| (d.at, d.order));
            moved |= !due.is_empty();
            for d in due {
                let Some(peer) = self.peers.iter_mut().find(|p| p.addr == d.to) else {
                    continue;
                };
                let _ = peer.pc.handle_read(TaggedBytesMut {
                    now,
                    transport: TransportContext {
                        local_addr: d.to,
                        peer_addr: d.from,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: d.data,
                });
            }
            for i in 0..2 {
                moved |= self.events(i)?;
            }
            if !moved {
                return Ok(());
            }
        }
    }

    /// The application's side of peer `i`: connection state, tracks, received media and key
    /// frame requests. Whether anything happened.
    pub fn events(&mut self, i: usize) -> Result<bool> {
        let at = self.elapsed();
        let now = self.now;
        let tolerate_failure = self.tolerate_failure;
        let peer = &mut self.peers[i];
        let mut moved = false;
        while let Some(event) = peer.pc.poll_event() {
            moved = true;
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    peer.states.push((at, state));
                    if state == RTCPeerConnectionState::Failed {
                        if !tolerate_failure {
                            bail!("peer {i} failed");
                        }
                        peer.failed = true;
                    }
                    let connected = state == RTCPeerConnectionState::Connected;
                    if peer.connected && !connected {
                        peer.left_connected += 1;
                    }
                    peer.connected = connected;
                }
                RTCPeerConnectionEvent::OnSelectedCandidatePairChange(_) => {
                    let estimate = peer.estimate();
                    peer.pair_changes.push((at, estimate));
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    let video = peer
                        .pc
                        .rtp_receiver(init.receiver_id)
                        .is_some_and(|r| r.track().kind() == RtpCodecKind::Video);
                    if video {
                        peer.video_receiver = Some(init.receiver_id);
                        peer.request_keyframe(now)?;
                    }
                }
                RTCPeerConnectionEvent::OnPacerDiscard {
                    frames, packets, ..
                } => peer.pacer_discards.push((at, frames, packets)),
                RTCPeerConnectionEvent::OnKeyFrameRequest { sender, .. } => {
                    peer.key_frame_request_events.push((at, sender));
                }
                _ => {}
            }
        }
        while let Some(message) = peer.pc.poll_read() {
            moved = true;
            match message.message {
                RTCMessage::RtpPacket(_, packet) if packet.header.payload_type == VP8_PT => {
                    peer.builder.push(now, packet);
                    peer.take_frames(now, at);
                    // A decoder without its reference asks for a key frame, at most once a
                    // second (ParolNet's receive path); so does a builder that gave a gap up
                    // for its time bound.
                    let gave_up = peer.builder.take_key_frame_request();
                    if (gave_up || peer.decoder.last.is_none())
                        && peer
                            .last_keyframe_request
                            .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(1))
                    {
                        peer.last_keyframe_request = Some(now);
                        peer.keyframe_requests.push(at);
                        peer.request_keyframe(now)?;
                    }
                }
                RTCMessage::RtpPacket(_, packet) if packet.header.payload_type == OPUS_PT => {
                    peer.audio_arrivals
                        .push((at, packet.header.sequence_number));
                }
                RTCMessage::RtcpPacket(_, packets)
                    if packets.iter().any(|p| {
                        p.as_any().is::<PictureLossIndication>()
                            || p.as_any().is::<FullIntraRequest>()
                    }) =>
                {
                    peer.force_key = true;
                    peer.key_requests_received += 1;
                    for packet in &packets {
                        if let Some(pli) = packet.as_any().downcast_ref::<PictureLossIndication>()
                            && pli.sender_ssrc == 0
                        {
                            peer.local_key_requests.push((at, pli.media_ssrc));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(moved)
    }

    /// The application's clock: 20 ms audio frames, 30 video frames a second at the
    /// estimate, the estimate read every 100 ms.
    pub fn tick(&mut self) -> Result<()> {
        let now = self.now;
        let at = self.elapsed();
        if self.media && now >= self.next_audio {
            self.next_audio += Duration::from_millis(20);
            for peer in self.peers.iter_mut() {
                peer.send_frame(now, false, &[0x5a; OPUS_PAYLOAD], 960)?;
            }
        }
        if self.media && now >= self.next_video {
            self.frame += 1;
            self.next_video =
                self.start + Duration::from_micros(self.frame * 1_000_000 / u64::from(VIDEO_FPS));
            let ignore = IGNORE_TARGET.with(|i| i.get());
            for (i, peer) in self.peers.iter_mut().enumerate() {
                peer.media_elapsed = at;
                // A target of zero is the pacer's pause: no frame is produced until the next
                // target (a source that ignores the target, the caller under IGNORE_TARGET,
                // carries on at its rate before the cap).
                let ignoring = ignore && i == 0;
                if !self.video_on[i] || (peer.target_bps == 0 && !ignoring) {
                    continue;
                }
                let bitrate = if ignoring { 1_400_000 } else { peer.target_bps };
                let key = std::mem::take(&mut peer.force_key);
                let mut frame = peer.model.next_frame(video_bitrate_for(bitrate), key);
                // When it was captured, in units of 10 ms, after the model's header.
                let captured = (at.as_millis() / 10) as u32;
                frame[VideoModel::HEADER..VideoModel::HEADER + 3]
                    .copy_from_slice(&captured.to_be_bytes()[1..]);
                if key {
                    peer.keyframes_sent.push(at);
                }
                peer.send_frame(now, true, &frame, 90_000 / VIDEO_FPS)?;
            }
        }
        if now >= self.next_target {
            self.next_target += Duration::from_millis(100);
            let link = &self.uplinks[0];
            let (delay_based, loss_based) = self.peers[0].halves();
            self.trace.push(format!(
                "{:6.1} target {:7} estimate {:7} delay {:7} loss {:7} callee {:7} queue {:3} ms drops {:5} audio {:4} rtx {:5}/{:5} lost padding {:5} usable {:5} unusable {:4}",
                at.as_secs_f64(),
                self.peers[0].target_bps,
                self.peers[0].estimate().unwrap_or(0),
                delay_based,
                loss_based,
                self.peers[1].estimate().unwrap_or(0),
                link.busy_until
                    .map_or(0, |t| t.saturating_duration_since(now).as_millis()),
                link.queue_drops,
                link.audio_dropped,
                link.rtx_sent,
                link.rtx_dropped,
                link.padding_sent,
                self.peers[1].usable_at.len(),
                self.peers[1].unusable,
            ));
            for peer in self.peers.iter_mut() {
                // Only a peer connection whose chain tells it the estimate has one to report.
                // The statistic leaves the member out when the estimate is zero: once it
                // has been there, a report without it is a zero.
                if peer.handles.is_some() {
                    let outgoing = peer.available_outgoing(now);
                    if let Some(outgoing) = outgoing.or(peer.lowest_outgoing.map(|_| 0.0)) {
                        peer.lowest_outgoing = Some(
                            peer.lowest_outgoing
                                .map_or(outgoing, |low| low.min(outgoing)),
                        );
                    }
                }
                if let Some(estimate) = peer.estimate() {
                    peer.lowest_estimate = Some(
                        peer.lowest_estimate
                            .map_or(estimate, |low| low.min(estimate)),
                    );
                }
                if let Some(bps) = peer.media_target()
                    && bps != peer.target_bps
                {
                    peer.target_bps = bps;
                    peer.targets.push((at, bps));
                }
            }
        }
        Ok(())
    }

    pub fn advance(&mut self, to: Instant) -> Result<()> {
        while self.now < to {
            let mut next = to;
            for peer in self.peers.iter_mut() {
                if let Some(deadline) = peer.pc.poll_timeout() {
                    next = next.min(deadline);
                }
            }
            if let Some(at) = self.in_flight.iter().map(|d| d.at).min() {
                next = next.min(at);
            }
            if self.media {
                next = next.min(self.next_audio).min(self.next_video);
            }
            next = next.min(self.next_target);
            // A receiver with a bound on a gap in time: the instant the oldest gap is given up.
            for peer in self.peers.iter() {
                if let Some(t) = peer.builder.poll_timeout().filter(|t| *t > self.now) {
                    next = next.min(t);
                }
            }
            self.now = next.max(self.now).min(to);
            let at = self.elapsed();
            for peer in self.peers.iter_mut() {
                peer.pc.handle_timeout(self.now)?;
                peer.gap_timeout(self.now, at)?;
            }
            self.tick()?;
            self.pump()?;
            if self.sampling {
                let caller = &self.peers[0];
                let sample = (self.elapsed(), caller.estimate(), caller.packet_loss());
                self.samples.push(sample);
                let at = self.elapsed();
                for peer in self.peers.iter_mut() {
                    if let Some(estimate) = peer.estimate()
                        && peer.estimates.last().is_none_or(|last| last.1 != estimate)
                    {
                        peer.estimates.push((at, estimate));
                    }
                }
            }
            if self.now == next && next < to {
                // Progress even when a deadline repeats at the same instant.
                let quiet = self
                    .peers
                    .iter_mut()
                    .all(|p| p.pc.poll_timeout().is_none_or(|t| t > self.now))
                    && self.in_flight.iter().all(|d| d.at > self.now);
                if !quiet {
                    self.now += Duration::from_micros(100);
                }
            }
        }
        Ok(())
    }

    /// The 100 ms trace, with `RTC_CAP_TRACE` set.
    pub fn print_trace(&self, what: &str, setup: &Setup) {
        if std::env::var("RTC_CAP_TRACE").is_ok() {
            for line in &self.trace {
                println!("TRACE {what} {:?} seed {} {line}", setup.chain, setup.seed);
            }
        }
    }

    /// Each peer's host candidate to the other, as after gathering.
    pub fn trickle(&mut self) -> Result<()> {
        for i in 0..2 {
            let candidate = self.peers[i].candidate()?;
            self.peers[i].pc.add_local_candidate(candidate.clone())?;
            self.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
        Ok(())
    }

    /// An ICE restart from the caller, signalled at once, with the same host candidates.
    pub fn restart_ice(&mut self) -> Result<()> {
        let now = self.now;
        self.peers[0].pc.restart_ice();
        let offer = self.peers[0].pc.create_offer(None)?;
        self.peers[0].pc.set_local_description(now, offer.clone())?;
        self.peers[1].pc.set_remote_description(now, offer)?;
        let answer = self.peers[1].pc.create_answer(None)?;
        self.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        self.peers[0].pc.set_remote_description(now, answer)?;
        self.trickle()
    }

    /// Peer `i` turns its camera on or off and negotiates the change, signalled at once: its
    /// video section's direction, or, for a peer that never had a video track, a track (on the
    /// section the other peer's offer created, when there is one). As ParolNet's
    /// `set_sending`.
    pub fn set_video(&mut self, i: usize, on: bool) -> Result<()> {
        let now = self.now;
        match self.peers[i].video {
            Some(sender) => {
                let Some(mut transceiver) = self.peers[i]
                    .pc
                    .rtp_transceiver(RTCRtpTransceiverId::from(sender))
                else {
                    bail!("peer {i} has no video transceiver");
                };
                let receive = transceiver.direction().has_recv();
                transceiver
                    .set_direction(RTCRtpTransceiverDirection::from_send_recv(on, receive))?;
            }
            None if on => {
                let ssrc_base = 0x1000_0000 * (i as u32 + 1);
                let sender = self.peers[i].pc.add_track(video_track(ssrc_base))?;
                self.peers[i].video = Some(sender);
            }
            None => return Ok(()),
        }
        let offer = self.peers[i].pc.create_offer(None)?;
        self.peers[i].pc.set_local_description(now, offer.clone())?;
        self.peers[1 - i].pc.set_remote_description(now, offer)?;
        let answer = self.peers[1 - i].pc.create_answer(None)?;
        self.peers[1 - i]
            .pc
            .set_local_description(now, answer.clone())?;
        self.peers[i].pc.set_remote_description(now, answer)?;
        self.video_on[i] = on;
        // A camera turned on starts with a key frame.
        self.peers[i].force_key |= on;
        Ok(())
    }

    /// Two peers over host candidates, audio and video each way, connected.
    pub fn connected(setup: &Setup) -> Result<Self> {
        let start = Instant::now();
        let mut world = World {
            peers: [
                Peer::new(
                    "10.0.0.1:5000",
                    setup,
                    0x1111,
                    0x1000_0000,
                    setup.video[0],
                    start,
                )?,
                Peer::new(
                    "10.0.0.2:5000",
                    setup,
                    0x2222,
                    0x2000_0000,
                    setup.video[1],
                    start,
                )?,
            ],
            uplinks: [Uplink::new(), Uplink::new()],
            start,
            now: start,
            in_flight: Vec::new(),
            order: 0,
            next_audio: start,
            next_video: start,
            next_target: start,
            frame: 0,
            media: false,
            video_on: setup.video,
            trace: Vec::new(),
            stun_lost: 0,
            feedback_outage_until: None,
            feedback_outage_lost: 0,
            blackhole: false,
            stun_only: false,
            sampling: false,
            samples: Vec::new(),
            reverse_loss: setup.reverse_loss,
            forward_loss: 0,
            tolerate_failure: false,
            loss_rng: Rng(setup.seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0xfeed_beef),
        };
        let now = world.now;
        let offer = world.peers[0].pc.create_offer(None)?;
        world.peers[0]
            .pc
            .set_local_description(now, offer.clone())?;
        world.peers[1].pc.set_remote_description(now, offer)?;
        let answer = world.peers[1].pc.create_answer(None)?;
        world.peers[1]
            .pc
            .set_local_description(now, answer.clone())?;
        world.peers[0].pc.set_remote_description(now, answer)?;
        world.trickle()?;
        while !world.peers.iter().all(|p| p.connected) {
            if world.elapsed() > Duration::from_secs(10) {
                bail!("not connected");
            }
            let t = world.now + Duration::from_millis(10);
            world.advance(t)?;
        }
        // Media from the connection on; times are counted from here.
        world.media = true;
        world.start = world.now;
        world.next_audio = world.now;
        world.next_video = world.now;
        world.next_target = world.now;
        Ok(world)
    }
}

/// The estimate in force at `at`.
pub fn target_at(targets: &[(Duration, u32)], at: Duration) -> u32 {
    targets
        .iter()
        .take_while(|t| t.0 <= at)
        .last()
        .map_or(300_000, |t| t.1)
}

/// The longest time between usable frames from `from` to `to`, and when it began.
pub fn longest_gap(usable_at: &[Duration], from: Duration, to: Duration) -> (Duration, Duration) {
    let mut last = from;
    let mut longest = (Duration::ZERO, from);
    for at in usable_at.iter().filter(|t| **t >= from && **t <= to) {
        if *at - last > longest.0 {
            longest = (*at - last, last);
        }
        last = *at;
    }
    if to.saturating_sub(last) > longest.0 {
        longest = (to - last, last);
    }
    longest
}
