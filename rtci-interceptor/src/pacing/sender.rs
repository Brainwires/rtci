//! Smooths outgoing packets to a target rate.

use super::pacer::Pacer as LeakyBucket;
use crate::Interceptor;
use crate::StreamInfo;
use crate::cc::probe::{ProbePacket, ProbeRequest};
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use shared::marshal::MarshalSize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Rate used when none is configured: 1 Mb/s.
pub const DEFAULT_BITRATE: f64 = 1_000_000.0;

/// Packets held before the queue overflows (see [`QueueOverflow`]).
pub const DEFAULT_QUEUE_LIMIT: usize = 4096;

/// How long a packet may wait in the queue by default (libwebrtc's
/// `kMaxExpectedQueueLength`, 2 s); what happens to one that would wait longer is
/// [`QueueOverflow`]'s.
pub const DEFAULT_QUEUE_TIME_LIMIT: Duration = Duration::from_secs(2);

/// What the pacer does with media the target has no room for: a packet that has waited the
/// queue time limit, or the oldest one when a packet arrives at a full queue. It happens only
/// when the application writes faster than the congestion controller's target for longer
/// than the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum QueueOverflow {
    /// The media is discarded here, whole frames at a time (see [`PacerDiscard`]; counted by
    /// [`PacerInterceptor::dropped`] and [`PacerInterceptor::discarded_frames`]): nothing
    /// leaves above the target. The congestion controller's target is what the path carries (RFC
    /// 8836 section 2; RFC 8083 section 4 stops a flow that does not keep to it), so a sender
    /// that put the excess on the path anyway would fill the bottleneck's queue, lose there
    /// and drive the estimate to its floor: a 2.4 Mbit/s source on a 600 kbit/s link
    /// (`tests/gcc_rate_limited_link_rtc2rtc.rs`, and netem in
    /// `testenv_impairment::gcc_follows_a_rate_limited_link`) held a target of 500 to 590
    /// kbit/s this way, and fell to 100 kbit/s with [`QueueOverflow::Drain`]. The receiver
    /// counts the dropped packets as lost, which they are; the NACK responder does not resend
    /// them, and the application is asked for a key frame (see [`PacerDiscard`]).
    #[default]
    Drop,
    /// libwebrtc's pacer (`drain_large_queues`, `MaybeUpdateMediaRateDueToLongQueue`): the
    /// pacing rate is raised above the target as far as it takes to drain the queue before
    /// its oldest packet has waited the limit, a packet that has waited it leaves whatever the
    /// budget says, and a full queue releases its oldest over the budget (counted by
    /// [`PacerInterceptor::forced`]). Nothing the application wrote is lost here, and a
    /// source that keeps above the target puts all of it on the path. For an encoder that
    /// follows the target, as libwebrtc's does.
    Drain,
}

/// Builder for [`PacerInterceptor`].
///
/// # Example
///
/// ```
/// use rtci_interceptor::{Slot, PacerBuilder, Registry};
///
/// let chain = Registry::new()
///     .with(Slot::Pacer, PacerBuilder::new().with_target_bitrate(2_000_000.0).build())
///     .build();
/// ```
pub struct PacerBuilder {
    bitrate: f64,
    burst_bits: Option<f64>,
    queue_limit: usize,
    queue_time_limit: Option<Duration>,
    queue_overflow: QueueOverflow,
    immediate_release: bool,
}

impl Default for PacerBuilder {
    fn default() -> Self {
        Self {
            bitrate: DEFAULT_BITRATE,
            burst_bits: None,
            queue_limit: DEFAULT_QUEUE_LIMIT,
            queue_time_limit: Some(DEFAULT_QUEUE_TIME_LIMIT),
            queue_overflow: QueueOverflow::default(),
            immediate_release: true,
        }
    }
}

impl PacerBuilder {
    /// Create a builder with the default rate and queue limit.
    pub fn new() -> Self {
        Self::default()
    }

    /// The rate to pace at, in bits per second.
    pub fn with_target_bitrate(mut self, bits_per_second: f64) -> Self {
        self.bitrate = bits_per_second;
        self
    }

    /// How much may be released at once, in bits.
    ///
    /// Larger bursts smooth less but cost fewer wake-ups.
    pub fn with_burst_bits(mut self, burst_bits: f64) -> Self {
        self.burst_bits = Some(burst_bits);
        self
    }

    /// How many packets may be queued. When a packet arrives at a full queue, the oldest one
    /// is dropped or leaves over the budget, as [`Self::with_queue_overflow`] says.
    pub fn with_queue_limit(mut self, queue_limit: usize) -> Self {
        self.queue_limit = queue_limit;
        self
    }

    /// How long a packet may wait in the queue ([`DEFAULT_QUEUE_TIME_LIMIT`] by default,
    /// `None` for no bound). When the application writes faster than the congestion
    /// controller's target, the queue grows; a packet that would wait longer than this is
    /// dropped or drained above the target, as [`Self::with_queue_overflow`] says. The
    /// application learns that its source is above the target from the target itself
    /// (`TargetBitrateChanged`, `RTCRtpSender::target_bitrates`), from
    /// [`PacerInterceptor::queue_time`], and, once media had to be discarded, from
    /// [`PacerDiscard`] (`RTCPeerConnectionEvent::OnPacerDiscard` in the peer connection) and
    /// the key-frame request that goes with it.
    pub fn with_queue_time_limit(mut self, limit: Option<Duration>) -> Self {
        self.queue_time_limit = limit;
        self
    }

    /// What happens to media the target has no room for ([`QueueOverflow::Drop`] by default).
    pub fn with_queue_overflow(mut self, overflow: QueueOverflow) -> Self {
        self.queue_overflow = overflow;
        self
    }

    /// Whether a packet the budget already covers leaves when it is written, with nothing
    /// queued ahead of it. On by default.
    ///
    /// The pacer exists to keep a sender from putting more than its target rate times the
    /// burst time on the path at once (draft-ietf-rmcat-gcc-02 section 4: a group of packets
    /// of that size every `burst_time`, 5 ms recommended). The budget is that bound: it never
    /// holds more than one burst and refills at the target rate. A packet inside it adds
    /// nothing to what the bound allows, and holding it until the next wake-up only adds
    /// delay the sender caused itself, which RFC 8836 section 2 (requirement 1) asks a
    /// congestion controller for interactive media to keep as low as possible; no RFC asks
    /// for the wait. `false` restores it: every packet is queued and leaves from the next
    /// timeout, so departures happen only on the driver's clock.
    pub fn with_immediate_release(mut self, immediate_release: bool) -> Self {
        self.immediate_release = immediate_release;
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> PacerInterceptor {
        let bucket = match self.burst_bits {
            Some(burst_bits) => LeakyBucket::new(self.bitrate).with_burst_bits(burst_bits),
            None => LeakyBucket::new(self.bitrate),
        };
        let mut pacer = PacerInterceptor::new(bucket, self.queue_limit);
        pacer.immediate_release = self.immediate_release;
        pacer.queue_time_limit = self.queue_time_limit;
        pacer.queue_overflow = self.queue_overflow;
        pacer
    }
}

/// Releases queued packets at a target rate rather than as fast as they arrive.
///
/// # Where this belongs in the chain
///
/// **Close to the wire, with every generator on the application side of it.** Everything after it
/// on the write path observes the *release* instant, so a send history goes there and records what
/// actually left; placed the other way round it would record the enqueue instant and charge this
/// queueing delay to the network.
///
/// Retransmissions, FEC repair packets and generated RTCP are all produced further out and reach
/// the pacer on the belt, so they are metered along with everything else. Under the nested chain
/// they bypassed it entirely.
///
/// # Differences from upstream
///
/// - **No ticker and no goroutine.** Upstream runs a loop on a 5 ms `time.Ticker`; here the
///   budget is a pure function of the instants handed in, so a release schedule is reproducible
///   rather than merely eventually-correct.
/// - **Idle means idle.** `poll_timeout` returns `None` with nothing queued, so an idle
///   connection does not wake the whole chain at the pacing interval.
/// - **The deadline is when the head can afford to go**, not `now + interval`, so it always
///   advances — a deadline at or before the `now` just handed to `handle_timeout` is the
///   webrtc#862 busy-loop.
///
/// # Order of service
///
/// 1. **Audio** (the packets of a stream bound with an `audio/` codec) leaves the moment it is
///    written, charged to the budget, which the packets behind it then wait out. A voice that
///    waits behind a video backlog is the call breaking up.
/// 2. **Audio retransmissions** leave the same way: an audio stream's repair flows (its RTX
///    and FEC SSRCs, from [`Interceptor::bind_local_stream`]) count as audio, so an audio
///    retransmission never waits behind video either.
/// 3. **Video retransmissions** (`Attribute::Retransmission` on any other stream) wait in the
///    media queue ahead of all new media (libwebrtc's `prioritized_packet_queue.cc`: "Send
///    retransmissions before new media"), a stream's oldest packet first (by the sequence
///    number repaired, whenever each was written: a receiver that plays in order waits for
///    its oldest gap). One whose packet
///    already has a retransmission waiting is not queued again
///    ([`PacerInterceptor::duplicate_retransmissions`]), and each that leaves or is dropped is
///    reported application-ward ([`RetransmissionsLeft`]), so the NACK responder does not make
///    another while one waits.
/// 4. **Video and FEC** (every other RTP packet that is not padding) wait behind them, in the
///    order written. The **queue time bound** (2 s by default,
///    [`PacerBuilder::with_queue_time_limit`]) and the queue limit are this queue's (3 and 4):
///    by default ([`QueueOverflow::Drop`]) what has waited the bound, or the oldest packet when
///    the queue is full, is discarded, so nothing leaves above the target (a retransmission
///    one packet at a time, new media whole frames at a time: see "Discarding media" below);
///    [`QueueOverflow::Drain`] raises the pacing rate above the target instead (libwebrtc's
///    `MaybeUpdateMediaRateDueToLongQueue`) and releases those packets over the budget.
/// 5. **Padding** (padding-only packets, RFC 3550 section 5.1: the padding bit and no payload,
///    which the NACK responder fills a probe cluster with) waits in a queue of its own and leaves
///    only when no media waits. A probe cluster is written as a burst of padding the moment it is
///    asked for; queued in line with the media it would hold every packet the application writes
///    during the cluster behind all of it (140 to 180 ms for a 6000-octet cluster at 200 kbit/s
///    in `early_media_rtc2rtc`). Media written during a cluster leaves first, at the cluster's
///    rate and with its mark, so it fills the cluster in place of padding, as in libwebrtc's
///    pacer (padding has the lowest priority of its packet queue).
///
/// Padding is outside the queue time bound: it never counts toward raising the pacing rate
/// (with [`QueueOverflow::Drain`]), is never dropped as overdue nor released over the budget,
/// and so never goes ahead of media or past the rate the congestion controller set. Padding older than the bound
/// is **sent late, not dropped**. Each padding packet already holds the next sequence number
/// of its RTX stream (the responder numbers it when it fills the cluster), so dropping it
/// would leave a hole in that stream which a receiver counts as lost (RFC 3550 appendix A.3,
/// expected minus received) and the RTCP reports carry back as loss nobody had on the path.
/// Sent late it costs nothing: it leaves only from budget no media wants. A padding queue
/// that reaches the queue limit (4096 packets, far beyond what probing writes while media
/// waits) discards the padding that arrives, counted by [`PacerInterceptor::padding_discarded`]:
/// the one place padding can leave a hole, preferred to letting it go over the budget.
///
/// # Pausing the source
///
/// When the media queued would take half the queue time bound or more to leave at the target
/// ([`PacerInterceptor::expected_queue_time`]; 1 s of the default 2 s), the pacer tells the
/// application to **stop producing**: every [`Attribute::TargetBitrateChanged`] it passes
/// application-ward carries **zero** (so `RTCRtpSender::target_bitrates` and the stats read
/// zero), with [`PacerPause`] carrying the congestion controller's target for the interceptors
/// that need the path's rate, and it announces the change at once on a carrier of its own. When
/// the queue is back under a twentieth of the bound (100 ms), it announces the real target
/// again. libwebrtc does the same: its control handler gives the encoder a target of zero while
/// the pacer's expected queue time exceeds 2 s
/// (`modules/congestion_controller/rtp/control_handler.cc`, `pacing_controller.h`: "the packet
/// producers should wait (eg drop frames rather than encoding them)"). Pausing at half the
/// bound, not at the bound, leaves a source that stops when told the time to notice (a frame
/// interval, a read of its target) and room for the target to fall once more.
///
/// **What a source that follows the pause wrote is never discarded for its age**: the media
/// written before the pause began (and within 250 ms of it, the time to notice) stays queued
/// until it leaves, however long that takes. At a sudden drop of the path's capacity that can be
/// seconds: the target may fall to a tenth of what the queued media was written for, and the
/// retransmissions of what the path lost at the drop leave ahead of it (order of service 3),
/// which is also the order a receiver needs them in. Nothing new joins the queue meanwhile, so
/// it is bounded by what was there when the pause began; discarding it would leave a gap in the
/// stream that costs the receiver more than the wait (a receiver that waits for missing packets
/// by count, as `rtci-media`'s `SampleBuilder` does, sat 9 s on such a gap in
/// `tests/capacity_cap_video_rtc2rtc.rs`). The queue time bound and the discard below are for
/// media written into a pause: a source that does not follow it.
///
/// **Known limit.** After a sudden drop the picture a receiver shows can be seconds old while
/// those retransmissions leave: in that test (2.5 Mbit/s into a path that drops to
/// 300 kbit/s) the receiver never went 2 s without a usable frame (1.38 to 1.90 s), but the
/// oldest picture it showed was 5.95 to 8.56 s old, against 2.26 to 3.21 s in a chain without
/// a pacer. The 55 to 62 video packets the path dropped are repaired inside an estimate of 100
/// to 250 kbit/s of which the audio takes 76, under every retransmission rule, and 35 to 41
/// of the 90 to 103 retransmissions repeat a packet whose first repair was still in flight
/// when the receiver asked again (they arrive after it). Dropping the repairs and asking for
/// a key frame instead is worse for a receiver that plays in order (measured: frozen for 8 s,
/// as it holds the gap for its whole packet window); what is planned is no repeat repair of a
/// packet whose first repair transport-wide feedback reports received.
///
/// **A target of zero means: produce nothing until the next target.** An encoder skips (does
/// not encode) the frames captured meanwhile; it does not need a key frame to resume, because
/// nothing it encoded was lost: the next frame it encodes refers to the last one it sent, which
/// is still queued here and reaches the receiver. libwebrtc resumes the same way: it encodes the
/// last frame captured during the pause, or asks the capturer for a fresh one
/// (`video_stream_encoder.cc`, `OnBitrateUpdated`: "A pending stored frame can be processed",
/// else `RequestRefreshFrame`), and forces no key frame. Audio is not queued here and can carry
/// on; the target is the transport's. Media the application writes anyway is queued and, past
/// the bound, discarded as below, with a key-frame request: that, not the resume, is when a key
/// frame is needed.
///
/// # Discarding media
///
/// With [`QueueOverflow::Drop`], new media the target has no room for is discarded **whole
/// frames at a time**. A frame is the packets of one stream (SSRC) with one RTP timestamp (RFC
/// 3550 section 5.1: the packets of one frame share it; the marker bit ends it). A frame with a
/// packet missing is worth nothing to a decoder, and so is every later frame that refers to it,
/// up to the next key frame; a frame that waited two seconds is stale anyway. So when the
/// oldest new-media packet has waited the bound (or is the oldest of a full queue), the pacer
/// discards every queued packet of its stream that is not a retransmission, oldest frame first,
/// and the packets of the newest discarded frame the application writes after that. Nothing
/// marks a key frame on this path (the application writes RTP packets, and only the codec's
/// payload says which frame is a key frame), so no queued frame of the stream is kept as one:
/// the key frame the application writes in answer to the request below is the next frame the
/// stream sends, not one that waits behind the stale ones. Audio, retransmissions and padding
/// are never discarded this way (audio is never queued, a retransmission is dropped alone,
/// padding is sent late).
///
/// For every discard the pacer emits on its **read** leg (the application-ward direction, the
/// only one that reaches the NACK responder application-ward of it) an empty RTCP carrier with
/// [`PacerDiscard`]: the NACK responder removes those packets from its retransmission buffer, so
/// a NACK for them is answered by nothing (RFC 4588 section 7: the sender "MAY selectively
/// retransmit only the packets that it deems important"), and the peer connection hands the
/// discard to the application (`RTCPeerConnectionEvent::OnPacerDiscard`). For a media stream
/// (not a repair flow) it also emits a Picture Loss Indication (RFC 4585 section 6.3.1) for the
/// stream, sender SSRC 0, marked [`Attribute::DeliverToApplication`]: the request a receiver
/// that lost its picture sends, so an application that answers PLI with a key frame
/// (`RTCMessage::RtcpPacket`, `RTCPeerConnectionEvent::OnKeyFrameRequest`) answers this too, at
/// the target the frames it writes now are sized for.
///
/// libwebrtc does not discard in its pacer: when the expected queue time passes 2 s it pauses
/// the encoder (target zero to the encoder, `modules/congestion_controller/rtp/control_handler.cc`)
/// and drains the queue above the target ([`QueueOverflow::Drain`]); its frames are dropped
/// before they are numbered. Here the application numbers its packets, so a discarded frame
/// leaves a gap in the stream's sequence numbers that the receiver sees as loss.
pub struct PacerInterceptor {
    pacer: LeakyBucket,
    /// The rate the bucket was set to before the queue time limit raised it, while it is
    /// raised: the target to come back to (the congestion controller's, or one set through
    /// [`Self::pacer_mut`]).
    raised_from: Option<f64>,
    queue: VecDeque<TaggedPacket>,
    /// Padding-only packets, released only while `queue` is empty (see the order of service).
    padding: VecDeque<TaggedPacket>,
    /// Padding refused because the padding queue was full.
    padding_discarded: u64,
    /// The bits waiting in `queue` (padding not counted).
    queued_bits: f64,
    queue_limit: usize,
    queue_time_limit: Option<Duration>,
    queue_overflow: QueueOverflow,
    /// The SSRCs of the audio streams: their packets are not queued behind others.
    audio: HashSet<u32>,
    /// The flows the circuit breaker has ceased ([`CircuitBreakerNotice`]): their packets do
    /// not leave, and are not charged to the budget.
    ceased: HashSet<u32>,
    /// Whether a packet inside the budget leaves at once when nothing is queued ahead of it.
    immediate_release: bool,
    /// The probe cluster being sent, if one is (see [`ProbeRequest`]).
    probe: Option<ActiveProbe>,
    /// Packets released over the budget ([`QueueOverflow::Drain`]).
    forced: u64,
    /// Media packets dropped for want of room in the target ([`QueueOverflow::Drop`]).
    dropped: u64,
    /// Frames of new media discarded whole ([`QueueOverflow::Drop`]).
    discarded_frames: u64,
    /// The repair flows (RTX, FEC SSRCs) of the bound streams other than audio: a discard on
    /// one asks for no key frame.
    repair_flows: HashSet<u32>,
    /// The RTP timestamp of the newest frame discarded on each stream: its packets written
    /// later are discarded too.
    discarded_frame: HashMap<u32, u32>,
    /// Whether the application is told to pause (see "Pausing the source").
    paused: bool,
    /// When the pause in force, or the last one, began.
    pause_began: Option<Instant>,
    /// How many times a pause began.
    pauses: u64,
    /// Retransmissions not queued because the same packet's retransmission already waited.
    duplicate_retransmissions: u64,
    /// The retransmissions released and dropped since the last [`RetransmissionsLeft`].
    departed: Vec<(u32, u16)>,
    retransmissions_dropped: Vec<(u32, u16)>,
    /// Packets the budget has released, waiting to join the belt.
    released: VecDeque<TaggedPacket>,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
    /// Outbound packets ready for the next interceptor: what passed through, plus
    /// anything this one generated.
    write_queue: VecDeque<TaggedPacket>,
}

impl PacerInterceptor {
    fn new(pacer: LeakyBucket, queue_limit: usize) -> Self {
        Self {
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
            released: VecDeque::new(),
            raised_from: None,
            pacer,
            queue: VecDeque::new(),
            padding: VecDeque::new(),
            padding_discarded: 0,
            queued_bits: 0.0,
            queue_limit: queue_limit.max(1),
            queue_time_limit: Some(DEFAULT_QUEUE_TIME_LIMIT),
            queue_overflow: QueueOverflow::default(),
            audio: HashSet::new(),
            ceased: HashSet::new(),
            immediate_release: true,
            probe: None,
            forced: 0,
            dropped: 0,
            discarded_frames: 0,
            repair_flows: HashSet::new(),
            discarded_frame: HashMap::new(),
            paused: false,
            pause_began: None,
            pauses: 0,
            duplicate_retransmissions: 0,
            departed: Vec::new(),
            retransmissions_dropped: Vec::new(),
        }
    }

    /// The pacing bucket, for a bandwidth estimator to drive.
    pub fn pacer(&self) -> &LeakyBucket {
        &self.pacer
    }

    /// The pacing bucket, mutably — this is where `set_target_bitrate` is reached.
    pub fn pacer_mut(&mut self) -> &mut LeakyBucket {
        &mut self.pacer
    }

    /// How many packets are waiting to be released, padding included.
    pub fn queued(&self) -> usize {
        self.queue.len() + self.padding.len()
    }

    /// How many padding-only packets were discarded because the padding queue was full.
    pub fn padding_discarded(&self) -> u64 {
        self.padding_discarded
    }

    /// How many packets left over the budget, overdue or to make room in a full queue
    /// ([`QueueOverflow::Drain`]).
    pub fn forced(&self) -> u64 {
        self.forced
    }

    /// How many media packets were dropped, overdue or to make room in a full queue
    /// ([`QueueOverflow::Drop`]): the packets of the discarded frames and the retransmissions
    /// dropped.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// How many frames of new media were discarded whole ([`QueueOverflow::Drop`], see
    /// "Discarding media" on [`PacerInterceptor`]).
    pub fn discarded_frames(&self) -> u64 {
        self.discarded_frames
    }

    /// How many times the application was told to pause (see "Pausing the source" on
    /// [`PacerInterceptor`]).
    pub fn pauses(&self) -> u64 {
        self.pauses
    }

    /// Whether the application is told to pause now.
    pub fn paused(&self) -> bool {
        self.paused
    }

    /// How many retransmissions were not queued because a retransmission of the same packet
    /// already waited in the queue.
    pub fn duplicate_retransmissions(&self) -> u64 {
        self.duplicate_retransmissions
    }

    /// How long the media queued now takes to leave at the target: queued bits over the
    /// target (libwebrtc's `ExpectedQueueTime`). Padding is not counted.
    pub fn expected_queue_time(&self) -> Duration {
        if self.queued_bits <= 0.0 {
            return Duration::ZERO;
        }
        let target = self.target();
        if target <= 0.0 {
            return Duration::MAX;
        }
        Duration::try_from_secs_f64(self.queued_bits / target).unwrap_or(Duration::MAX)
    }

    /// How long the oldest queued media packet has waited at `now`, zero with none queued
    /// (padding is not counted: the queue time bound is the media's).
    pub fn queue_time(&self, now: Instant) -> Duration {
        self.queue.front().map_or(Duration::ZERO, |head| {
            now.saturating_duration_since(head.now)
        })
    }

    /// The rate to pace at now: the target, or more when the queue would otherwise not drain
    /// before its oldest packet has waited the queue time limit. With `q` bits queued and the
    /// oldest packet having waited `w`, the rate is max(target, q / (limit - w)); once `w`
    /// reaches the limit, everything queued may leave.
    fn pacing_rate(&self, now: Instant) -> f64 {
        let target = self.target();
        if self.queue_overflow != QueueOverflow::Drain {
            return target;
        }
        let Some(limit) = self.queue_time_limit else {
            return target;
        };
        if self.queue.is_empty() {
            return target;
        }
        let remaining = limit.saturating_sub(self.queue_time(now)).as_secs_f64();
        let needed = if remaining > 0.001 {
            self.queued_bits / remaining
        } else {
            // Overdue: everything may leave (`handle_timeout` releases it).
            1e12
        };
        target.max(needed)
    }

    /// The target rate: what the bucket paces at when the queue is short.
    fn target(&self) -> f64 {
        self.raised_from
            .unwrap_or_else(|| self.pacer.target_bitrate())
    }

    /// Paces at [`Self::pacing_rate`] from `now`: above the target while the queue needs it,
    /// back at the target once it does not.
    fn follow_queue(&mut self, now: Instant) {
        let target = self.target();
        let rate = self.pacing_rate(now);
        if rate > target {
            self.raised_from = Some(target);
            if rate != self.pacer.target_bitrate() {
                self.pacer.set_target_bitrate(rate);
            }
        } else if let Some(target) = self.raised_from.take() {
            self.pacer.set_target_bitrate(target);
        }
    }

    /// Whether `packet` is padding only: an RTP packet with the padding bit and no payload.
    fn is_padding(packet: &TaggedPacket) -> bool {
        matches!(&packet.message.packet, Packet::Rtp(rtp) if rtp.header.padding && rtp.payload.is_empty())
    }

    fn is_audio(&self, packet: &TaggedPacket) -> bool {
        matches!(&packet.message.packet, Packet::Rtp(rtp) if self.audio.contains(&rtp.header.ssrc))
    }

    /// The size of a packet on the wire, in bits — the unit the budget is kept in.
    fn bits_of(packet: &TaggedPacket) -> f64 {
        match &packet.message.packet {
            Packet::Rtp(rtp) => (rtp.marshal_size() * 8) as f64,
            Packet::Rtcp(_) => 0.0,
        }
    }

    /// The bucket releases are metered through now: the probe cluster's while one is being
    /// sent, the target rate's otherwise.
    fn bucket(&self) -> &LeakyBucket {
        self.probe
            .as_ref()
            .map_or(&self.pacer, |probe| &probe.bucket)
    }

    /// The instant the next packet can be released: the head of the media queue, or of the
    /// padding while no media waits (padding has no queue time bound to wake for).
    fn next_release(&self) -> Option<Instant> {
        let Some(head) = self.queue.front() else {
            let head = self.padding.front()?;
            return self.bucket().releasable_at(Self::bits_of(head));
        };
        let by_budget = self.bucket().releasable_at(Self::bits_of(head)).map(|at| {
            // While the rate is raised it moves with every call, and the instant computed at
            // one rate can come out a hair short of the budget at the next: a microsecond
            // later it is not, and the deadline advances (webrtc#862).
            if self.raised_from.is_some() {
                at + Duration::from_micros(1)
            } else {
                at
            }
        });
        // The rate rises as the oldest packet ages: wake by the time it reaches the limit
        // (never for a packet the bound does not apply to: that deadline would stay in the
        // past and a driver would spin on it).
        let by_limit = self
            .queue_time_limit
            .filter(|_| self.queue_overflow == QueueOverflow::Drain || self.ages_out(head))
            .map(|limit| head.now + limit);
        match (by_budget, by_limit) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Whether `bits` may leave now, and if so, spends them.
    fn try_spend(&mut self, bits: f64) -> bool {
        match self.probe.as_mut() {
            Some(probe) => {
                if !probe.bucket.can_release(bits) {
                    return false;
                }
                probe.bucket.consume(bits);
                true
            }
            None => {
                if !self.pacer.can_release(bits) {
                    return false;
                }
                self.pacer.consume(bits);
                true
            }
        }
    }

    /// Brings the budgets up to `now`, and ends a probe cluster that could not be filled.
    fn refill(&mut self, now: Instant) {
        self.pacer.refill(now);
        if let Some(probe) = self.probe.as_mut() {
            probe.bucket.refill(now);
            if now.saturating_duration_since(probe.started) > PROBE_CLUSTER_TIMEOUT {
                self.probe = None;
            }
        }
    }

    /// A packet leaves at `now`: marked as part of the probe cluster while one is being sent.
    fn release(&mut self, mut packet: TaggedPacket, bits: f64) {
        if packet.message.has(&Attribute::Retransmission)
            && !Self::is_padding(&packet)
            && let Some(key) = self.retransmission_key(&packet)
        {
            self.departed.push(key);
        }
        if let Some(probe) = self.probe.as_mut() {
            packet.message.add(Attribute::Custom(Arc::new(ProbePacket {
                cluster: probe.cluster,
            })));
            probe.remaining_bits -= bits;
            if probe.remaining_bits <= 0.0 {
                self.probe = None;
            }
        }
        self.released.push_back(packet);
    }

    /// The packet a retransmission repairs, as (SSRC on the wire, sequence number repaired): on
    /// an RTX stream the original sequence number ahead of the payload (RFC 4588 section 4),
    /// otherwise (a retransmission under the media SSRC) its own sequence number.
    fn retransmission_key(&self, packet: &TaggedPacket) -> Option<(u32, u16)> {
        let Packet::Rtp(rtp) = &packet.message.packet else {
            return None;
        };
        let ssrc = rtp.header.ssrc;
        if self.repair_flows.contains(&ssrc) {
            let osn = rtp.payload.get(..2)?;
            return Some((ssrc, u16::from_be_bytes([osn[0], osn[1]])));
        }
        Some((ssrc, rtp.header.sequence_number))
    }

    /// Whether a retransmission of the packet `packet` repairs already waits in the queue
    /// (retransmissions wait at its front).
    fn retransmission_waits(&self, packet: &TaggedPacket) -> bool {
        let Some(key) = self.retransmission_key(packet) else {
            return false;
        };
        self.queue
            .iter()
            .take_while(|queued| queued.message.has(&Attribute::Retransmission))
            .any(|queued| self.retransmission_key(queued) == Some(key))
    }

    /// Records a retransmission dropped from the queue, for [`RetransmissionsLeft`].
    fn retransmission_dropped(&mut self, packet: &TaggedPacket) {
        if let Some(key) = self.retransmission_key(packet) {
            self.retransmissions_dropped.push(key);
        }
    }

    /// Whether the pause should begin or end now (see "Pausing the source"); `true` when it
    /// changed.
    fn update_pause(&mut self, now: Instant) -> bool {
        let expected = self.expected_queue_time();
        let change = match self.queue_time_limit {
            Some(limit) if !self.paused => expected >= limit.mul_f64(PAUSE_AT),
            Some(limit) => expected <= limit.mul_f64(RESUME_AT),
            None => self.paused,
        };
        if change {
            self.paused = !self.paused;
            if self.paused {
                self.pauses += 1;
                self.pause_began = Some(now);
            }
        }
        change
    }

    /// Whether new media written at `written` is what a source that follows the pause left
    /// behind: written before the pause in force (or the last one) began, or within
    /// [`PAUSE_GRACE`] of that. It is never discarded for its age (see "Pausing the source").
    fn written_before_pause(&self, written: Instant) -> bool {
        self.pause_began
            .is_some_and(|began| written <= began + PAUSE_GRACE)
    }

    /// Whether the queued `packet` is discarded once it has waited the queue time bound
    /// ([`QueueOverflow::Drop`]): a retransmission, and new media a pausing source would not
    /// have written.
    fn ages_out(&self, packet: &TaggedPacket) -> bool {
        packet.message.has(&Attribute::Retransmission) || !self.written_before_pause(packet.now)
    }

    /// The target as the application is to read it: zero while paused, with [`PacerPause`]
    /// carrying the congestion controller's.
    fn tag_target(&self, message: &mut AttributedPacket) {
        if !self.paused {
            return;
        }
        let mut target = None;
        for attribute in &mut message.attributes {
            if let Attribute::TargetBitrateChanged { bits_per_second } = attribute {
                target = Some(*bits_per_second);
                *bits_per_second = 0.0;
            }
        }
        if let Some(target_bits_per_second) = target {
            message.add(Attribute::Custom(Arc::new(PacerPause {
                target_bits_per_second,
            })));
        }
    }

    /// After a write or a timeout: a pause that began or ended goes application-ward as the
    /// target, and the retransmissions that left or were dropped as [`RetransmissionsLeft`].
    fn tell_application_ward(&mut self, now: Instant) {
        if self.update_pause(now) {
            let mut message =
                AttributedPacket::new(Packet::Rtcp(vec![])).with(Attribute::TargetBitrateChanged {
                    bits_per_second: self.target(),
                });
            self.tag_target(&mut message);
            self.read_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message,
            });
        }
        if !self.departed.is_empty() || !self.retransmissions_dropped.is_empty() {
            let notice = RetransmissionsLeft {
                departed: std::mem::take(&mut self.departed),
                dropped: std::mem::take(&mut self.retransmissions_dropped),
            };
            self.read_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![]))
                    .with(Attribute::Custom(Arc::new(notice))),
            });
        }
    }

    /// Whether `packet` is new media (not a retransmission) of the stream `ssrc`.
    fn is_new_media_of(packet: &TaggedPacket, ssrc: u32) -> bool {
        matches!(&packet.message.packet, Packet::Rtp(rtp) if rtp.header.ssrc == ssrc)
            && !packet.message.has(&Attribute::Retransmission)
    }

    /// The stream of `packet` when it belongs to the frame discarded last on that stream; a
    /// packet of a later frame ends that frame's discard.
    fn continues_discard(&mut self, packet: &TaggedPacket) -> Option<u32> {
        let Packet::Rtp(rtp) = &packet.message.packet else {
            return None;
        };
        let ssrc = rtp.header.ssrc;
        let discarded = *self.discarded_frame.get(&ssrc)?;
        if discarded == rtp.header.timestamp {
            return Some(ssrc);
        }
        self.discarded_frame.remove(&ssrc);
        None
    }

    /// Discards the frame of the queued new-media packet at `index` and every other queued
    /// frame of its stream (see "Discarding media" on [`PacerInterceptor`]).
    fn discard_stream_of(&mut self, now: Instant, index: usize) {
        let Some(Packet::Rtp(rtp)) = self.queue.get(index).map(|packet| &packet.message.packet)
        else {
            return;
        };
        let ssrc = rtp.header.ssrc;
        let mut discarded = Vec::new();
        let mut kept = VecDeque::with_capacity(self.queue.len());
        for packet in self.queue.drain(..) {
            if Self::is_new_media_of(&packet, ssrc) {
                discarded.push(packet);
            } else {
                kept.push_back(packet);
            }
        }
        self.queue = kept;
        let bits: f64 = discarded.iter().map(Self::bits_of).sum();
        self.queued_bits = (self.queued_bits - bits).max(0.0);
        self.discard(now, ssrc, &discarded);
    }

    /// Counts the discard of `packets` (new media of the stream `ssrc`, oldest first) and tells
    /// the chain application-ward: the NACK responder and the application through
    /// [`PacerDiscard`], and the application a key frame is needed.
    fn discard(&mut self, now: Instant, ssrc: u32, packets: &[TaggedPacket]) {
        let mut sequence_numbers = Vec::with_capacity(packets.len());
        let mut octets = 0usize;
        let mut frames = 0u32;
        let mut newest = self.discarded_frame.get(&ssrc).copied();
        for packet in packets {
            if let Packet::Rtp(rtp) = &packet.message.packet {
                sequence_numbers.push(rtp.header.sequence_number);
                octets += rtp.marshal_size();
                if newest != Some(rtp.header.timestamp) {
                    frames += 1;
                    newest = Some(rtp.header.timestamp);
                }
            }
        }
        if sequence_numbers.is_empty() {
            return;
        }
        if let Some(timestamp) = newest {
            self.discarded_frame.insert(ssrc, timestamp);
        }
        self.dropped += sequence_numbers.len() as u64;
        self.discarded_frames += u64::from(frames);
        let target_bitrate = self.target();
        self.read_queue.push_back(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![])).with(Attribute::Custom(Arc::new(
                PacerDiscard {
                    ssrc,
                    sequence_numbers,
                    frames,
                    octets,
                    target_bitrate,
                },
            ))),
        });
        // A new frame lost (not only the rest of one already discarded): the stream needs a
        // key frame, asked for the way a receiver asks, so the application's PLI handling
        // answers it.
        if frames > 0 && !self.repair_flows.contains(&ssrc) {
            self.read_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(
                    PictureLossIndication {
                        sender_ssrc: 0,
                        media_ssrc: ssrc,
                    },
                )]))
                .with(Attribute::DeliverToApplication),
            });
        }
    }
}

/// Media the pacer discarded for want of room in the target ([`QueueOverflow::Drop`]): whole
/// frames of one stream (see "Discarding media" on [`PacerInterceptor`]).
///
/// The pacer sends it application-ward, on an empty RTCP carrier on its read leg, at the
/// instant of the discard. The NACK responder removes the packets named here from its
/// retransmission buffer (a NACK for them is answered by nothing) and from the original
/// packets it counts against the target (they never used the link); the peer connection
/// hands it to the application as `RTCPeerConnectionEvent::OnPacerDiscard`. It means **the
/// source is above the target**: what the application writes has to come down to the target
/// it is given (`Attribute::TargetBitrateChanged`, `RTCRtpSender::target_bitrates`). Read with
/// [`AttributedPacket::custom`](crate::AttributedPacket::custom).
#[derive(Debug, Clone, PartialEq)]
pub struct PacerDiscard {
    /// The stream the packets were of.
    pub ssrc: u32,
    /// The sequence numbers of the packets discarded, oldest first.
    pub sequence_numbers: Vec<u16>,
    /// How many frames were discarded (0 when these packets are the rest of a frame already
    /// discarded).
    pub frames: u32,
    /// The octets of the packets discarded (RTP header and payload).
    pub octets: usize,
    /// The pacer's target at the discard, bits per second.
    pub target_bitrate: f64,
}

/// The pause begins when the expected queue time reaches this share of the queue time bound:
/// half, so a source that stops when told (within a frame or a read of its target) never lets
/// its packets wait the bound, even when the target falls by half once more meanwhile.
const PAUSE_AT: f64 = 0.5;

/// The pause ends when the expected queue time is back under this share of the bound (100 ms
/// of the default 2 s): what then waits is the delay the call carries on with, so it is kept
/// short; the gap between the two shares keeps one frame from switching it on and off.
const RESUME_AT: f64 = 0.05;

/// How long after a pause began media still counts as written by a source that follows it:
/// the time such a source takes to notice (a read of its target, the frame being encoded).
const PAUSE_GRACE: Duration = Duration::from_millis(250);

/// Rides a target of zero ([`Attribute::TargetBitrateChanged`]) that the pacer hands
/// application-ward while it tells the source to pause (see "Pausing the source" on
/// [`PacerInterceptor`]): the congestion controller's target, for what application-ward of the
/// pacer needs the rate the path carries (the NACK responder's retransmission rate limit). Read
/// with [`AttributedPacket::custom`](crate::AttributedPacket::custom).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PacerPause {
    /// The congestion controller's target, bits per second.
    pub target_bits_per_second: f64,
}

/// The retransmissions that left the pacer, or were dropped there, since the last notice: each
/// as (SSRC on the wire, sequence number of the packet it repairs; the original sequence
/// number on an RTX stream). The pacer sends it application-ward on an empty RTCP carrier; the
/// NACK responder treats a packet as on its way while its retransmission waits in the pacer
/// and counts the resend interval from when it left, as libwebrtc's packet history does
/// (`modules/rtp_rtcp/source/rtp_packet_history.cc`: a request for a packet "already in pacer
/// queue" is ignored; the send time is set when it is sent). Read with
/// [`AttributedPacket::custom`](crate::AttributedPacket::custom).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RetransmissionsLeft {
    /// Released toward the wire.
    pub departed: Vec<(u32, u16)>,
    /// Dropped (waited the queue time bound, or the oldest of a full queue).
    pub dropped: Vec<(u32, u16)>,
}

/// How long a probe cluster is held open for packets to fill it. A cluster that takes longer
/// than this to leave is not a burst any more and measures nothing.
const PROBE_CLUSTER_TIMEOUT: Duration = Duration::from_millis(250);

/// A probe cluster on its way out.
struct ActiveProbe {
    cluster: u32,
    /// Meters the cluster's packets at the probe rate, one packet at a time.
    bucket: LeakyBucket,
    remaining_bits: f64,
    started: Instant,
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for PacerInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        // Follow the congestion controller's estimate.
        //
        // It arrives on the **read** leg because that is the only one it can cross on. The
        // controller is wire-most, so on the write leg it is the last interceptor to see a packet
        // and anything it attached would already have gone past here. On the read leg it is the
        // first, and this is downstream of it — so the feedback packet that produced the estimate
        // carries it here on its way to the application.
        //
        // Observed, not consumed: the packet carries on with the attribute attached, so anything
        // further along reads the same number.
        if let Some(Attribute::TargetBitrateChanged { bits_per_second }) =
            msg.message.get(&Attribute::TargetBitrateChanged {
                bits_per_second: 0.0,
            })
        {
            match self.raised_from.as_mut() {
                // Raised to drain the queue: the new target is what it comes back to.
                Some(target) => *target = *bits_per_second,
                None => self.pacer.set_target_bitrate(*bits_per_second),
            }
            // A new rate changes how long the queue takes to leave: the pause may begin or
            // end, and the application reads it on this packet.
            self.update_pause(msg.now);
            self.tag_target(&mut msg.message);
        }

        // A flow the circuit breaker ceased or restarted (it sits wire-ward of here).
        if let Some(notice) = msg.message.custom::<crate::CircuitBreakerNotice>() {
            if notice.ceased.is_some() && notice.ssrc == u32::MAX {
                self.ceased.insert(notice.ssrc);
            } else {
                self.ceased.remove(&notice.ssrc);
            }
        }

        // A probe cluster the congestion controller asks for: the next packets leave at its
        // rate, on top of the target's budget, and carry its mark. Observed, not consumed:
        // the NACK responder above reads the same request and fills the cluster.
        if let Some(request) = msg.message.custom::<ProbeRequest>() {
            let mut bucket = LeakyBucket::new(request.bits_per_second)
                .with_burst_bits(crate::pacing::pacer::MIN_BURST_BITS);
            bucket.refill(msg.now);
            self.probe = Some(ActiveProbe {
                cluster: request.cluster,
                bucket,
                remaining_bits: request.octets as f64 * 8.0,
                started: msg.now,
            });
        }

        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        let now = msg.now;
        let rtp = matches!(msg.message.packet, Packet::Rtp(_));
        self.enqueue(msg)?;
        if rtp {
            self.tell_application_ward(now);
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        // Unpaced traffic goes first — RTCP is only useful while it is fresh, and holding it
        // behind the budget would be pacing it after all.
        self.write_queue
            .pop_front()
            .or_else(|| self.released.pop_front())
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        self.release_due(now);
        self.tell_application_ward(now);
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.next_release()
    }
}

impl PacerInterceptor {
    /// A packet written: released, queued, or discarded.
    fn enqueue(&mut self, msg: TaggedPacket) -> Result<(), Error> {
        // No estimate is read here. It was, once — but the congestion controller sits wire-*ward*
        // of the pacer, so on the write leg it never sees a packet before this interceptor does and
        // the branch had no possible producer. If an application-set target is ever wanted it comes
        // back with its own `RTCEvent` variant, and a test.

        // RTCP is control traffic and mostly time-sensitive — feedback is only useful while it is
        // fresh — so it is not paced.
        if matches!(msg.message.packet, Packet::Rtcp(_)) {
            self.write_queue.push_back(msg);
            return Ok(());
        }

        // A flow the circuit breaker ceased (RFC 8083 section 4.5): its packets are dropped
        // at the breaker, below. They pass here unmetered: charged to the budget, a voice the
        // application keeps writing took 76 of a 100 kbit/s target that the video then
        // could not use (`tests/capacity_cap_video_rtc2rtc.rs`'s path), for packets that
        // never left.
        if matches!(&msg.message.packet, Packet::Rtp(rtp) if self.ceased.contains(&rtp.header.ssrc))
        {
            self.released.push_back(msg);
            return Ok(());
        }

        // Keeping the budget current at enqueue time is what lets `poll_timeout` compute a
        // deadline that is never in the past, even before the first `handle_timeout`.
        self.refill(msg.now);
        self.follow_queue(msg.now);

        // Audio is never queued behind video: its packets are small and few, and a voice that
        // waits behind a video backlog is the call breaking up. It leaves at once and is
        // charged to the budget, which the packets behind it then wait out.
        if self.is_audio(&msg) {
            let bits = Self::bits_of(&msg);
            if !self.try_spend(bits) {
                self.pacer.consume(bits);
            }
            self.release(msg, bits);
            return Ok(());
        }

        // Padding waits behind every other packet, and nothing waits behind it.
        let padding = Self::is_padding(&msg);

        // The rest of a frame already discarded is worth nothing either.
        let new_media = !padding && !msg.message.has(&Attribute::Retransmission);
        if new_media && let Some(ssrc) = self.continues_discard(&msg) {
            self.discard(msg.now, ssrc, std::slice::from_ref(&msg));
            return Ok(());
        }

        // Inside the budget and first in line: it leaves now. The budget is the bound on what
        // may enter the path at once, so nothing is gained by holding the packet for a timer.
        // Queued padding is not in line ahead of media.
        if self.immediate_release && self.queue.is_empty() && (!padding || self.padding.is_empty())
        {
            let bits = Self::bits_of(&msg);
            if self.try_spend(bits) {
                self.release(msg, bits);
                return Ok(());
            }
        }

        if padding {
            // Never over the budget and never counted toward the queue time bound (see the
            // order of service); at the limit the arrival is discarded.
            if self.padding.len() >= self.queue_limit {
                self.padding_discarded += 1;
            } else {
                self.padding.push_back(msg);
            }
            return Ok(());
        }

        // A retransmission of a packet whose retransmission already waits adds nothing but a
        // second copy (libwebrtc's packet history ignores a request for a packet "already in
        // pacer queue", `rtp_packet_history.cc`).
        if !new_media && self.retransmission_waits(&msg) {
            self.duplicate_retransmissions += 1;
            return Ok(());
        }

        if self.queue.len() >= self.queue_limit {
            // Room for the arrival: the oldest goes (the newest is the one still worth
            // sending). Discarded by default, a retransmission alone, new media with its
            // stream's queued frames; with `Drain` it leaves now, over the budget.
            let retransmission = self
                .queue
                .front()
                .is_some_and(|oldest| oldest.message.has(&Attribute::Retransmission));
            match self.queue_overflow {
                QueueOverflow::Drop if !retransmission => {
                    self.discard_stream_of(msg.now, 0);
                    if new_media && let Some(ssrc) = self.continues_discard(&msg) {
                        self.discard(msg.now, ssrc, std::slice::from_ref(&msg));
                        return Ok(());
                    }
                }
                _ => {
                    if let Some(mut oldest) = self.queue.pop_front() {
                        let bits = Self::bits_of(&oldest);
                        self.queued_bits -= bits;
                        if self.queue_overflow == QueueOverflow::Drain {
                            self.pacer.consume(bits);
                            oldest.now = msg.now;
                            self.forced += 1;
                            self.release(oldest, bits);
                        } else {
                            self.retransmission_dropped(&oldest);
                            self.dropped += 1;
                        }
                    }
                }
            }
        }

        // Held: it leaves later, from `poll_write`, when the budget allows. A retransmission
        // goes ahead of the new media waiting, behind the retransmissions before it: a repair
        // the NACK responder has already held to the congestion controller's target is worth
        // most early, and waiting behind seconds of new video it may outlive its use or be
        // dropped as overdue. libwebrtc's pacer orders its queue the same way
        // (`modules/pacing/prioritized_packet_queue.cc`, `GetPriorityForType`: "Send
        // retransmissions before new media").
        let now = msg.now;
        self.queued_bits += Self::bits_of(&msg);
        if msg.message.has(&Attribute::Retransmission) {
            let end = self
                .queue
                .iter()
                .position(|queued| !queued.message.has(&Attribute::Retransmission))
                .unwrap_or(self.queue.len());
            // Among the retransmissions of one stream the oldest packet goes first, whenever
            // it was asked for: a receiver that plays in order waits for the oldest gap, and
            // a repair that was itself lost and is made again would otherwise wait behind
            // every newer one.
            let at = self
                .retransmission_key(&msg)
                .map_or(end, |(ssrc, repaired)| {
                    self.queue
                        .iter()
                        .take(end)
                        .position(|queued| {
                            self.retransmission_key(queued)
                                .is_some_and(|(other, waiting)| {
                                    other == ssrc
                                        && waiting != repaired
                                        && waiting.wrapping_sub(repaired) < 0x8000
                                })
                        })
                        .unwrap_or(end)
                });
            self.queue.insert(at, msg);
            if at == 0 {
                // First in line now: it may leave at once if the budget allows.
                self.release_due(now);
            }
            self.follow_queue(now);
            return Ok(());
        }
        self.queue.push_back(msg);
        self.follow_queue(now);
        Ok(())
    }

    /// Releases what the budget allows at `now`, and drops what waited the bound.
    fn release_due(&mut self, now: Instant) {
        self.refill(now);
        self.follow_queue(now);

        while let Some(head) = self.queue.front() {
            let bits = Self::bits_of(head);
            // Past the queue time limit the head is dropped (`Drop`) or leaves whatever the
            // budget says (`Drain`).
            let overdue = self
                .queue_time_limit
                .is_some_and(|limit| now.saturating_duration_since(head.now) >= limit)
                && (self.queue_overflow == QueueOverflow::Drain || self.ages_out(head));
            if overdue {
                if self.queue_overflow == QueueOverflow::Drop {
                    // A retransmission is dropped alone; new media with every queued frame
                    // of its stream (see "Discarding media").
                    if head.message.has(&Attribute::Retransmission) {
                        if let Some(dropped) = self.queue.pop_front() {
                            self.retransmission_dropped(&dropped);
                        }
                        self.queued_bits = (self.queued_bits - bits).max(0.0);
                        self.dropped += 1;
                    } else {
                        self.discard_stream_of(now, 0);
                    }
                    continue;
                }
                self.pacer.consume(bits);
                self.forced += 1;
            } else if !self.try_spend(bits) {
                break;
            }

            let mut packet = self.queue.pop_front().expect("front just checked");
            self.queued_bits = (self.queued_bits - bits).max(0.0);
            // Rule 3: the packet departs now. Anything below recording departure — the send
            // history congestion control reads — must see the release instant, not the enqueue
            // instant, or this queueing delay is charged to the network.
            packet.now = now;
            // Queued for `poll_write`, which puts it back on the belt so it traverses every
            // interceptor ahead — numbering, and the send history reading the release instant just set.
            self.release(packet, bits);
        }
        if self.queue.is_empty() {
            self.queued_bits = 0.0;
            // No media waits: padding leaves from what the budget has left, never over it.
            while let Some(head) = self.padding.front() {
                let bits = Self::bits_of(head);
                if !self.try_spend(bits) {
                    break;
                }
                let mut packet = self.padding.pop_front().expect("front just checked");
                packet.now = now;
                self.release(packet, bits);
            }
        }
        self.follow_queue(now);
    }
}

impl Interceptor for PacerInterceptor {
    /// Audio streams (and their repair flows) are not queued behind others. The repair flows of
    /// the other streams are remembered: a discard on one asks for no key frame.
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        if info.mime_type.to_ascii_lowercase().starts_with("audio/") {
            self.audio.extend(crate::twcc::flow_ssrcs(info));
        } else {
            self.repair_flows
                .extend(info.ssrc_rtx.into_iter().chain(info.ssrc_fec));
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        for ssrc in crate::twcc::flow_ssrcs(info) {
            self.audio.remove(&ssrc);
            self.discarded_frame.remove(&ssrc);
            self.ceased.remove(&ssrc);
        }
        for ssrc in info.ssrc_rtx.into_iter().chain(info.ssrc_fec) {
            self.repair_flows.remove(&ssrc);
        }
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}
