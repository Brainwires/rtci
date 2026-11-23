//! Smooths outgoing packets to a target rate.

use super::pacer::Pacer as LeakyBucket;
use crate::Interceptor;
use crate::StreamInfo;
use crate::cc::probe::{ProbePacket, ProbeRequest};
use crate::{Attribute, Packet, TaggedPacket};
use sansio::Protocol;
use shared::error::Error;
use shared::marshal::MarshalSize;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Rate used when none is configured: 1 Mb/s.
pub const DEFAULT_BITRATE: f64 = 1_000_000.0;

/// Packets held before the oldest is released over the budget to make room.
pub const DEFAULT_QUEUE_LIMIT: usize = 4096;

/// How long a packet may wait in the queue by default: the pacing rate is raised above the
/// target as far as it takes to drain the queue within it (libwebrtc's `kMaxExpectedQueueLength`,
/// 2 s).
pub const DEFAULT_QUEUE_TIME_LIMIT: Duration = Duration::from_secs(2);

/// Builder for [`PacerInterceptor`].
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Slot, PacerBuilder, Registry};
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
    immediate_release: bool,
}

impl Default for PacerBuilder {
    fn default() -> Self {
        Self {
            bitrate: DEFAULT_BITRATE,
            burst_bits: None,
            queue_limit: DEFAULT_QUEUE_LIMIT,
            queue_time_limit: Some(DEFAULT_QUEUE_TIME_LIMIT),
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
    /// leaves at once, over the budget: a packet the application has numbered is never thrown
    /// away here, since the hole in the sequence would be loss the sender made itself.
    pub fn with_queue_limit(mut self, queue_limit: usize) -> Self {
        self.queue_limit = queue_limit;
        self
    }

    /// How long a packet may wait in the queue ([`DEFAULT_QUEUE_TIME_LIMIT`] by default,
    /// `None` for no bound). When the application writes faster than the congestion
    /// controller's target, the queue grows; the pacing rate is then raised above the target
    /// to what drains the queued bits before its oldest packet has waited this long
    /// (libwebrtc's pacer does the same with its expected queue length of 2 s). The
    /// application learns that its source is above the target from the target itself
    /// (`TargetBitrateChanged`, `RTCRtpSender::target_bitrates`), and from
    /// [`PacerInterceptor::queue_time`].
    pub fn with_queue_time_limit(mut self, limit: Option<Duration>) -> Self {
        self.queue_time_limit = limit;
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
pub struct PacerInterceptor {
    pacer: LeakyBucket,
    /// The rate the bucket was set to before the queue time limit raised it, while it is
    /// raised: the target to come back to (the congestion controller's, or one set through
    /// [`Self::pacer_mut`]).
    raised_from: Option<f64>,
    queue: VecDeque<TaggedPacket>,
    /// The bits waiting in `queue`.
    queued_bits: f64,
    queue_limit: usize,
    queue_time_limit: Option<Duration>,
    /// The SSRCs of the audio streams: their packets are not queued behind others.
    audio: HashSet<u32>,
    /// Whether a packet inside the budget leaves at once when nothing is queued ahead of it.
    immediate_release: bool,
    /// The probe cluster being sent, if one is (see [`ProbeRequest`]).
    probe: Option<ActiveProbe>,
    /// Packets released over the budget because the queue was full.
    forced: u64,
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
            queued_bits: 0.0,
            queue_limit: queue_limit.max(1),
            queue_time_limit: Some(DEFAULT_QUEUE_TIME_LIMIT),
            audio: HashSet::new(),
            immediate_release: true,
            probe: None,
            forced: 0,
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

    /// How many packets are waiting to be released.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// How many packets left over the budget because the queue was full (none is ever
    /// refused).
    pub fn forced(&self) -> u64 {
        self.forced
    }

    /// How long the oldest queued packet has waited at `now`, zero with nothing queued.
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

    /// The instant the head of the queue can next be released.
    fn next_release(&self) -> Option<Instant> {
        let head = self.queue.front()?;
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
        // The rate rises as the oldest packet ages: wake by the time it reaches the limit.
        let by_limit = self.queue_time_limit.map(|limit| head.now + limit);
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

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
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

        // Inside the budget and first in line: it leaves now. The budget is the bound on what
        // may enter the path at once, so nothing is gained by holding the packet for a timer.
        if self.immediate_release && self.queue.is_empty() {
            let bits = Self::bits_of(&msg);
            if self.try_spend(bits) {
                self.release(msg, bits);
                return Ok(());
            }
        }

        if self.queue.len() >= self.queue_limit {
            // The oldest leaves now, over the budget, to make room. The packets here are
            // numbered: refusing one, as the pacer once did, put a hole in its stream that no
            // packet was ever lost to on the path, which the receiver then counted as loss and
            // asked for again. The queue time limit keeps this a last resort.
            if let Some(mut oldest) = self.queue.pop_front() {
                let bits = Self::bits_of(&oldest);
                self.queued_bits -= bits;
                self.pacer.consume(bits);
                oldest.now = msg.now;
                self.forced += 1;
                self.release(oldest, bits);
            }
        }

        // Held: it leaves later, from `poll_write`, when the budget allows.
        let now = msg.now;
        self.queued_bits += Self::bits_of(&msg);
        self.queue.push_back(msg);
        self.follow_queue(now);
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
        self.refill(now);
        self.follow_queue(now);

        while let Some(head) = self.queue.front() {
            let bits = Self::bits_of(head);
            // Past the queue time limit the head leaves whatever the budget says.
            let overdue = self
                .queue_time_limit
                .is_some_and(|limit| now.saturating_duration_since(head.now) >= limit);
            if overdue {
                self.pacer.consume(bits);
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
        }
        self.follow_queue(now);
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.next_release()
    }
}

impl Interceptor for PacerInterceptor {
    /// Audio streams (and their repair flows) are not queued behind others.
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        if info.mime_type.to_ascii_lowercase().starts_with("audio/") {
            self.audio.extend(crate::twcc::flow_ssrcs(info));
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        for ssrc in crate::twcc::flow_ssrcs(info) {
            self.audio.remove(&ssrc);
        }
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}
