//! The RTP circuit breaker (RFC 8083).
//!
//! A congestion controller keeps a flow at the rate the path carries. A circuit breaker is what
//! stops the flow when that has failed: the receiver has gone, the path delivers nothing, or the
//! flow has been taking ten times what a TCP connection would get for long enough that it is no
//! longer a transient. RFC 8834 section 7.1 requires both.
//!
//! It works from the plain RTCP every RTP endpoint sends: the report blocks of SR and RR packets.
//! Nothing here depends on a congestion-control feedback format being negotiated.
//!
//! | Breaker | Trips when (RFC 8083) |
//! |---|---|
//! | RTCP timeout (4.1) | media is sent and no RTCP reports on it for three reporting intervals |
//! | Media timeout (4.2) | `MEDIA_TIMEOUT` consecutive reports show the extended highest sequence number not moving |
//! | Congestion (4.3) | the sending rate is more than ten times the TCP throughput for the reported loss and round trip time, averaged over `CB_INTERVAL` reports |
//! | Media usability (4.4) | reported loss or delay stayed past the application's bound for the application's period |
//!
//! A tripped flow ceases transmission (4.5): its RTP is dropped here, above the TWCC sender and the
//! send history, so a packet that does not leave is neither numbered nor counted. The
//! application is told ([`CircuitBreakerNotice`]) and can restart it through
//! [`CircuitBreakerHandle`], not before the interval that tripped it has passed again. The
//! breaker restarts it itself only on what section 4.5 allows an automatic restart on,
//! "information that the congestion has dissipated": the receiver's own reports on another
//! flow of the same transport (see [`CircuitBreakerBuilder::with_automatic_restart`]).
//!
//! # The intervals
//!
//! Every count above is in reporting intervals of the receiver, Tdr: "the sender's estimate of
//! the deterministic RTCP reporting interval, Td, calculated by a receiver of the data it is
//! sending", which "can be estimated by executing the algorithm in Section 6.2 of \[RFC3550\]"
//! (section 3). The RTCP session of the chain runs that algorithm and says what it gives
//! ([`RtcpReportingInterval`](crate::RtcpReportingInterval), on every RTCP packet it hands
//! application-ward); the breaker takes it as the least Tdr can be, and a receiver whose
//! reports come further apart than that (a minimum interval of its own: RTP/AVP's five
//! seconds, a `T_rr_interval`, a browser's fixed second) has the interval its reports show
//! (section 4.3: "If the incoming RTCP SR or RR packets are using a reduced minimum RTCP
//! reporting interval ... then that reduced RTCP reporting interval is used"). Reports that
//! come closer together than the calculated interval (early feedback packets that carry a
//! report) are each counted and do not shorten Tdr (section 5: they are "counted towards the
//! circuit breaker conditions", which "will potentially make the RTP circuit breaker trigger
//! earlier"). Without an RTCP session in the chain Tdr is the spacing of the reports.
//!
//! With RTP/AVPF and no `T_rr_interval` the calculated interval of a call that carries video
//! is some tens of milliseconds, so k = 5 reports without progress are a quarter of a second
//! or less: the breaker's timescale is the receiver's reporting timescale, as the RFC has it.

use crate::Interceptor;
use crate::never_sent::NeverSent;
use crate::stream_info::StreamInfo;
use crate::twcc::flow_ssrcs;
use crate::{Packet, TaggedPacket};
use sansio::Protocol;
use shared::error::Error;
use shared::marshal::MarshalSize;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// The fixed minimum RTCP interval the RTCP timeout is computed with (Tmin, RFC 8083
/// section 4.1).
pub const DEFAULT_RTCP_INTERVAL: Duration = Duration::from_secs(5);

/// The non-reporting threshold k: the RECOMMENDED value (RFC 8083 section 4.2).
pub const DEFAULT_NON_REPORTING_THRESHOLD: u32 = 5;

/// How many reporting intervals without RTCP trip the RTCP timeout breaker.
const RTCP_TIMEOUT_INTERVALS: u32 = 3;

/// How far back frame intervals are looked at for Tf ("the largest inter-frame interval used in
/// the last 10 seconds", RFC 8083 section 3).
const FRAME_INTERVAL_WINDOW: Duration = Duration::from_secs(10);

/// How many sender reports are remembered to turn a report block's LSR into a send instant.
const REMEMBERED_SENDER_REPORTS: usize = 16;

/// How many departures of a flow are remembered until a report covers them.
const REMEMBERED_DEPARTURES: usize = 4096;

/// How many times the hold of a flow that trips again soon after a restart is doubled.
const MAX_HOLD_DOUBLINGS: u32 = 6;

/// A restarted flow that has run this many times its last hold without tripping starts over
/// with the triggering interval alone as its hold.
const CLEAN_RUN_HOLDS: u32 = 10;

/// Which breaker stopped a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CircuitBreakerReason {
    /// No RTCP reported on the media being sent for three reporting intervals (section 4.1).
    RtcpTimeout,
    /// The receiver's reports showed the media not arriving (section 4.2).
    MediaTimeout,
    /// The flow sent more than ten times what TCP would have achieved (section 4.3).
    Congestion,
    /// Loss or delay stayed past the application's usability bound (section 4.4).
    MediaUnusable,
}

/// The circuit breaker ceased or restarted a flow (RFC 8083 section 4.5).
///
/// The breaker sends it application-ward, on an empty RTCP carrier on its read leg, at the
/// instant a flow ceases and when a restart takes effect: one the application asked for
/// ([`CircuitBreakerHandle::restart`]) or one the breaker made on the receiver's reports
/// ([`CircuitBreakerBuilder::with_automatic_restart`]). A ceased flow's RTP is dropped at the
/// breaker until it is restarted. Section 4.5: "RTP flows halted by the circuit breaker
/// SHOULD NOT be restarted automatically unless the sender has received information that the
/// congestion has dissipated or can reasonably be expected to have dissipated"; where no such
/// information can reach the breaker (every flow of the transport has ceased) only the
/// application can restart the flow, so it has to hear of it: the peer connection hands this
/// to the application as `RTCPeerConnectionEvent::OnCircuitBreaker`. The pacer reads it on
/// its way past and stops charging the flow's packets to its budget (they do not leave).
/// Read with [`AttributedPacket::custom`](crate::AttributedPacket::custom).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CircuitBreakerNotice {
    /// The flow (a media, RTX or FEC SSRC this endpoint sends).
    pub ssrc: u32,
    /// The breaker that tripped, `None` for a flow that was restarted.
    pub ceased: Option<CircuitBreakerReason>,
    /// For a ceased flow: how long from now until a restart is accepted (section 4.5: "the
    /// reaction to a triggered circuit breaker lasts for at least the triggering interval").
    /// The triggering interval, doubled for each time the flow tripped again soon after a
    /// restart.
    pub restart_after: Duration,
}

/// What the circuit breaker is doing with one flow.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum CircuitBreakerState {
    /// Sending normally.
    Running,
    /// The congestion breaker tripped once and the flow was given the chance to send at a tenth
    /// of its rate (section 4.3). If the breaker trips again after the next `CB_INTERVAL`
    /// reports, the flow ceases.
    Reduced {
        /// The rate the flow has to stay under, in bits per second.
        limit_bits_per_second: f64,
    },
    /// Transmission has ceased (section 4.5): the flow's RTP is dropped.
    Ceased {
        /// The breaker that tripped.
        reason: CircuitBreakerReason,
        /// When it tripped.
        at: Instant,
        /// The earliest instant a restart is accepted.
        restart_after: Instant,
    },
}

/// How the congestion breaker takes s, the packet size of the TCP throughput equation (RFC
/// 8083 section 4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum PacketSize {
    /// The mean size of the RTP packets sent over the reporting intervals the sending rate is
    /// measured over: s = (bytes sent) / (packets sent) over the last CB_INTERVAL intervals.
    /// The default: s and the rate it is compared with describe the same packets.
    #[default]
    SendingWindow,
    /// Section 3's definition as written: the mean size of the packets of the last 4 * G
    /// frames. For speech with silence frames between talkspurts s is then the silence
    /// frames' size (23 bytes) while the rate is that of the talkspurts, and a call over a
    /// link with 1 to 5 % loss is ceased.
    LastFrames,
}

/// The application's bound on what is still usable media (section 4.4). The RFC leaves the
/// bound to the application on purpose.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MediaUsability {
    /// Reported loss fraction (0.0 to 1.0) above which the media is unusable.
    pub max_loss: f64,
    /// Round trip time above which the media is unusable.
    pub max_round_trip_time: Duration,
    /// How long it has to stay unusable before transmission ceases.
    pub period: Duration,
}

#[derive(Debug, Clone, Copy)]
struct Config {
    rtcp_interval: Duration,
    t_rr_interval: Option<Duration>,
    non_reporting_threshold: u32,
    frame_group_size: u32,
    full_tcp_equation: bool,
    packet_size: PacketSize,
    reduce_before_ceasing: bool,
    group: bool,
    usability: Option<MediaUsability>,
    automatic_restart: bool,
}

/// Builder for [`CircuitBreakerInterceptor`].
///
/// # Example
///
/// ```
/// use rtci_interceptor::{CircuitBreakerBuilder, Registry, Slot};
///
/// let (breaker, handle) = CircuitBreakerBuilder::new().build();
/// let chain = Registry::new().with(Slot::CircuitBreaker, breaker).build();
/// assert!(handle.ceased().is_empty());
/// # let _ = chain;
/// ```
pub struct CircuitBreakerBuilder {
    config: Config,
}

impl Default for CircuitBreakerBuilder {
    fn default() -> Self {
        Self {
            config: Config {
                rtcp_interval: DEFAULT_RTCP_INTERVAL,
                t_rr_interval: None,
                non_reporting_threshold: DEFAULT_NON_REPORTING_THRESHOLD,
                frame_group_size: 1,
                full_tcp_equation: false,
                packet_size: PacketSize::SendingWindow,
                reduce_before_ceasing: false,
                group: false,
                usability: None,
                automatic_restart: true,
            },
        }
    }
}

impl CircuitBreakerBuilder {
    /// A builder with the RFC's recommended values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Td, this endpoint's deterministic RTCP reporting interval, computed with Tmin = 5 s
    /// (section 4.1). The RTCP timeout breaker trips after three of them. Values above 5 s are
    /// held to 5 s: the RFC says not to configure a longer one.
    pub fn with_rtcp_interval(mut self, interval: Duration) -> Self {
        self.config.rtcp_interval = interval.min(DEFAULT_RTCP_INTERVAL);
        self
    }

    /// The AVPF `T_rr_interval` in use, which replaces Tdr in `CB_INTERVAL` when it is larger
    /// (section 4.3). Held to 4 s (sections 4.1 and 4.3).
    pub fn with_t_rr_interval(mut self, interval: Duration) -> Self {
        self.config.t_rr_interval = Some(interval.min(Duration::from_secs(4)));
        self
    }

    /// k, the number of reports without progress that gives assurance the forward path failed
    /// (section 4.2). 5 is recommended.
    pub fn with_non_reporting_threshold(mut self, k: u32) -> Self {
        self.config.non_reporting_threshold = k.max(1);
        self
    }

    /// G, the number of frames the codec needs before it can change rate (section 3). 1 for a
    /// codec that can adapt on every frame.
    pub fn with_frame_group_size(mut self, frames: u32) -> Self {
        self.config.frame_group_size = frames.max(1);
        self
    }

    /// Use the full TCP throughput equation instead of the simplified one (section 4.3: MAY; it
    /// is more sensitive to loss and trips earlier).
    pub fn with_full_tcp_equation(mut self, full: bool) -> Self {
        self.config.full_tcp_equation = full;
        self
    }

    /// How s, the packet size of the TCP throughput equation, is taken (section 4.3).
    /// [`PacketSize::SendingWindow`] by default; [`PacketSize::LastFrames`] is section 3's
    /// "last 4 * G frames".
    pub fn with_packet_size(mut self, packet_size: PacketSize) -> Self {
        self.config.packet_size = packet_size;
        self
    }

    /// When the congestion breaker trips, first ask for a tenth of the rate
    /// ([`CircuitBreakerState::Reduced`]) instead of ceasing at once (section 4.3: MAY). If it
    /// trips again after the next `CB_INTERVAL` reports the flow ceases.
    pub fn with_rate_reduction(mut self, reduce: bool) -> Self {
        self.config.reduce_before_ceasing = reduce;
        self
    }

    /// Treat every flow of the connection as one group: a breaker tripping for one flow applies
    /// to all (section 8: MAY). By default each SSRC is judged on its own.
    pub fn with_grouped_flows(mut self, group: bool) -> Self {
        self.config.group = group;
        self
    }

    /// The bound past which the media is unusable (section 4.4). Without one the media
    /// usability breaker does not run: the RFC defines no bound.
    pub fn with_media_usability(mut self, usability: MediaUsability) -> Self {
        self.config.usability = Some(usability);
        self
    }

    /// Whether the breaker restarts a ceased flow itself when the receiver's reports show what
    /// stopped it has gone (`true`, the default), or leaves every restart to the application
    /// (`false`).
    ///
    /// Section 4.5: "RTP flows halted by the circuit breaker SHOULD NOT be restarted
    /// automatically unless the sender has received information that the congestion has
    /// dissipated or can reasonably be expected to have dissipated." The information the
    /// breaker takes is the receiver's reports on another flow this endpoint sends on the same
    /// transport, received after the flow ceased:
    ///
    /// - a flow stopped by the media timeout (4.2, "most likely due to a path failure")
    ///   restarts when such a report shows the other flow's packets arriving: the path
    ///   delivers;
    /// - a flow stopped by the congestion breaker (4.3) restarts when those reports, over a
    ///   whole hold, show a loss at which the rate that tripped it is within ten times the
    ///   TCP throughput again (or no loss at all);
    /// - a flow stopped for unusable media (4.4) restarts when they show loss and round trip
    ///   time back inside the application's bound over a whole hold;
    /// - a flow stopped by the RTCP timeout (4.1) restarts when a report on an SSRC this
    ///   endpoint sends arrives again: "the receiver and return path are working".
    ///
    /// Never before the hold has passed ("the reaction to a triggered circuit breaker lasts
    /// for at least the triggering interval"), and a flow that trips again soon after a
    /// restart is held twice as long each time (up to 64 times the triggering interval), so a
    /// path that keeps failing is tried ever more rarely. When every flow of the transport has
    /// ceased nothing is sent that a report could speak of: the application restarts
    /// ([`CircuitBreakerHandle::restart`]) or nobody does.
    pub fn with_automatic_restart(mut self, automatic: bool) -> Self {
        self.config.automatic_restart = automatic;
        self
    }

    /// Build the interceptor and the handle the application watches it through.
    pub fn build(self) -> (CircuitBreakerInterceptor, CircuitBreakerHandle) {
        let handle = CircuitBreakerHandle::new();
        (self.build_with_handle(&handle), handle)
    }

    /// Build the interceptor `handle` watches (made beforehand, for example to give it to the
    /// congestion controller of the same transport). One interceptor per handle.
    pub fn build_with_handle(self, handle: &CircuitBreakerHandle) -> CircuitBreakerInterceptor {
        CircuitBreakerInterceptor {
            config: self.config,
            flows: HashMap::new(),
            awaiting_rtcp_since: None,
            calculated_interval: None,
            shared: handle.shared.clone(),
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

#[derive(Default)]
struct Shared {
    states: HashMap<u32, CircuitBreakerState>,
    restarts: Vec<u32>,
    dropped: u64,
    /// The round trip time measured elsewhere in the chain, smoothed as section 3 says.
    round_trip_time: Option<Duration>,
}

fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The application's view of the circuit breaker, and its way to restart a ceased flow.
#[derive(Clone)]
pub struct CircuitBreakerHandle {
    shared: Arc<Mutex<Shared>>,
}

impl Default for CircuitBreakerHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBreakerHandle {
    /// A handle with no interceptor yet: [`CircuitBreakerBuilder::build_with_handle`] builds
    /// the one it watches.
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Mutex::new(Shared::default())),
        }
    }

    /// What the breaker is doing with the flow sent on `ssrc`, if it is bound.
    pub fn state(&self, ssrc: u32) -> Option<CircuitBreakerState> {
        lock(&self.shared).states.get(&ssrc).copied()
    }

    /// The flows that have ceased transmission, with the breaker that stopped each.
    pub fn ceased(&self) -> Vec<(u32, CircuitBreakerReason)> {
        let mut ceased: Vec<_> = lock(&self.shared)
            .states
            .iter()
            .filter_map(|(ssrc, state)| match state {
                CircuitBreakerState::Ceased { reason, .. } => Some((*ssrc, *reason)),
                _ => None,
            })
            .collect();
        ceased.sort_unstable_by_key(|(ssrc, _)| *ssrc);
        ceased
    }

    /// The lowest rate any flow has been asked to stay under after the congestion breaker
    /// tripped, in bits per second. A congestion controller takes it as an upper bound.
    pub fn rate_limit(&self) -> Option<f64> {
        lock(&self.shared)
            .states
            .values()
            .filter_map(|state| match state {
                CircuitBreakerState::Reduced {
                    limit_bits_per_second,
                } => Some(*limit_bits_per_second),
                _ => None,
            })
            .reduce(f64::min)
    }

    /// One round trip time measurement from congestion-control feedback, for the breaker to
    /// use when it cannot measure one itself.
    ///
    /// Tr is the RFC 3550 round trip time: a report block's LSR and DLSR against the instant
    /// the named sender report left. The breaker only knows that instant for sender reports
    /// that pass it on the way out; when the RTCP session sits wire-ward of it (as the standard
    /// set places it) none does, and without Tr the congestion breaker could never compare the
    /// flow with TCP. The congestion controller's feedback gives the same quantity many times
    /// a second.
    ///
    /// Give each measurement as it is made: this smooths them as section 3 says ("Tr = (0.8 *
    /// Tr) + (0.2 * Tr_new) where Tr_new is the latest RTT estimate"), once. A value that is
    /// already an average makes Tr trail the path by that average's memory on top of its own.
    pub fn report_round_trip_time(&self, round_trip_time: Duration) {
        let mut shared = lock(&self.shared);
        shared.round_trip_time = Some(match shared.round_trip_time {
            Some(previous) => previous.mul_f64(0.8) + round_trip_time.mul_f64(0.2),
            None => round_trip_time,
        });
    }

    /// How many RTP packets of ceased flows were dropped.
    pub fn dropped(&self) -> u64 {
        lock(&self.shared).dropped
    }

    /// Restart a ceased flow. Returns whether it restarted.
    ///
    /// This is the application saying the congestion can be expected to have gone (section
    /// 4.5), for a flow the breaker has no information to restart on by itself
    /// ([`CircuitBreakerBuilder::with_automatic_restart`]). It is refused until the hold has
    /// passed (the interval that tripped the breaker, doubled for each trip that followed a
    /// restart closely), so the reaction to a tripped breaker lasts at least the triggering
    /// interval however often a restart is attempted.
    pub fn restart(&self, ssrc: u32, now: Instant) -> bool {
        let mut shared = lock(&self.shared);
        match shared.states.get(&ssrc) {
            Some(CircuitBreakerState::Ceased { restart_after, .. }) if now >= *restart_after => {
                shared.states.insert(ssrc, CircuitBreakerState::Running);
                shared.restarts.push(ssrc);
                true
            }
            _ => false,
        }
    }
}

/// One reporting interval as the congestion breaker records it.
#[derive(Debug, Clone, Copy)]
struct LossSample {
    fraction_lost: f64,
    duration: Duration,
    bytes_sent: u64,
    packets_sent: u64,
    /// What the report's cumulative number lost and extended highest sequence number moved
    /// by since the previous report (RFC 3550 6.4.1): the interval's net loss, in which a
    /// packet that was only reordered counts in neither interval.
    net_lost: i64,
    net_expected: i64,
}

/// One frame's worth of packets, for the average packet size.
#[derive(Debug, Clone, Copy, Default)]
struct FrameSize {
    bytes: u64,
    packets: u64,
}

struct Flow {
    state: CircuitBreakerState,
    /// Packets and bytes sent since the last report block for this flow.
    packets_since_report: u64,
    bytes_since_report: u64,
    /// The RTP timestamp of the frame being sent and when its first packet left.
    current_frame: Option<(u32, Instant)>,
    /// Inter-frame intervals of the last ten seconds, with the instant each ended.
    frame_intervals: VecDeque<(Instant, Duration)>,
    /// Sizes of the last `4 * G` frames, newest last.
    frames: VecDeque<FrameSize>,
    /// When the last report block for this flow arrived.
    last_report_at: Option<Instant>,
    /// When the flow's last packet left.
    last_departure: Option<Instant>,
    /// Smoothed interval between the receiver's reports: the estimate of Tdr.
    receiver_interval: Option<Duration>,
    /// The reporting SSRC whose blocks the flow follows, and when it last reported.
    reporter: Option<(u32, Instant)>,
    /// The extended highest sequence number the receiver last reported.
    highest_sequence: Option<u32>,
    /// The previous report's cumulative number lost and extended highest sequence number,
    /// as reported (for the net loss of the next interval).
    previous_report: Option<(i32, u32)>,
    /// The sequence numbers the flow jumped over on its way out: the packets the pacer
    /// discarded, which the receiver counts as lost.
    never_sent: NeverSent,
    /// Consecutive reports that showed no progress while media was being sent.
    stalled_reports: u32,
    media_timeout: u32,
    losses: VecDeque<LossSample>,
    reports_received: u64,
    /// Report blocks since the rate was reduced.
    reports_since_reduction: u64,
    /// Smoothed round trip time, Tr.
    round_trip_time: Option<Duration>,
    /// Sender reports sent for this flow: the middle 32 bits of the NTP timestamp, and when.
    sender_reports: VecDeque<(u32, Instant)>,
    unusable_since: Option<Instant>,
    /// The packets no report has covered yet: sequence number and when each left, oldest
    /// first. What a report that shows no progress is held against (section 4.2).
    unreported: VecDeque<(u16, Instant)>,
    /// The newest sequence number that left.
    newest_sent: Option<u16>,
    /// What stopped the flow and what a restart waits for, while it is ceased.
    halt: Option<Halt>,
    /// How many times in a row the flow tripped soon after a restart (1 for a first trip).
    trips: u32,
    /// The hold of the last trip.
    last_hold: Duration,
    /// When the flow was last restarted.
    restarted_at: Option<Instant>,
}

/// A ceased flow: what stopped it, and what the receiver's reports on the transport's other
/// flows have shown since (the information section 4.5 lets a restart rest on).
#[derive(Debug, Clone, Copy)]
struct Halt {
    reason: CircuitBreakerReason,
    /// How long the reaction lasts at least.
    hold: Duration,
    restart_after: Instant,
    /// The rate, in bytes per second, and the packet size the congestion breaker tripped at.
    rate: f64,
    packet_size: f64,
    /// The start of the stretch of reports being weighed.
    since: Instant,
    /// Over that stretch, from reports that showed another flow's packets arriving: the time
    /// they cover, in seconds, and the fraction lost weighted by it.
    covered: f64,
    lost: f64,
}

/// A breaker that tripped: which, the interval that triggered it, and for the congestion
/// breaker the rate (bytes per second) and packet size it was judged at.
#[derive(Debug, Clone, Copy)]
struct Trip {
    reason: CircuitBreakerReason,
    interval: Duration,
    rate: f64,
    packet_size: f64,
}

impl Trip {
    fn new(reason: CircuitBreakerReason, interval: Duration) -> Self {
        Self {
            reason,
            interval,
            rate: 0.0,
            packet_size: 0.0,
        }
    }
}

/// What a report block said about a running flow, for the ceased flows of the same transport.
#[derive(Debug, Clone, Copy)]
struct Witness {
    ssrc: u32,
    /// Whether the report showed packets of the flow arriving since the one before.
    progressed: bool,
    fraction_lost: f64,
    /// The time since the flow's previous report.
    duration: Duration,
    round_trip_time: Option<Duration>,
}

impl Flow {
    fn new() -> Self {
        Self {
            state: CircuitBreakerState::Running,
            packets_since_report: 0,
            bytes_since_report: 0,
            current_frame: None,
            frame_intervals: VecDeque::new(),
            frames: VecDeque::new(),
            last_report_at: None,
            last_departure: None,
            receiver_interval: None,
            reporter: None,
            highest_sequence: None,
            previous_report: None,
            never_sent: NeverSent::default(),
            stalled_reports: 0,
            media_timeout: 0,
            losses: VecDeque::new(),
            reports_received: 0,
            reports_since_reduction: 0,
            round_trip_time: None,
            sender_reports: VecDeque::new(),
            unusable_since: None,
            unreported: VecDeque::new(),
            newest_sent: None,
            halt: None,
            trips: 0,
            last_hold: Duration::ZERO,
            restarted_at: None,
        }
    }

    fn is_ceased(&self) -> bool {
        matches!(self.state, CircuitBreakerState::Ceased { .. })
    }

    /// Tf: the largest inter-frame interval of the last ten seconds.
    fn frame_interval(&self) -> Duration {
        self.frame_intervals
            .iter()
            .map(|(_, interval)| *interval)
            .max()
            .unwrap_or_default()
    }

    /// s: the average size of the packets of the last `4 * G` frames, in bytes.
    fn packet_size(&self) -> Option<f64> {
        let (bytes, packets) = self
            .frames
            .iter()
            .fold((0u64, 0u64), |(bytes, packets), frame| {
                (bytes + frame.bytes, packets + frame.packets)
            });
        (packets > 0).then(|| bytes as f64 / packets as f64)
    }

    fn on_departure(
        &mut self,
        now: Instant,
        sequence_number: u16,
        timestamp: u32,
        size: usize,
        frames_kept: usize,
    ) {
        self.last_departure = Some(now);
        self.never_sent.on_sent(sequence_number);
        self.packets_since_report += 1;
        self.bytes_since_report += size as u64;
        // A sequence number behind the newest is a retransmission: the report that covers the
        // newest covers it.
        if self
            .newest_sent
            .is_none_or(|newest| is_newer(sequence_number, newest))
        {
            self.newest_sent = Some(sequence_number);
            self.unreported.push_back((sequence_number, now));
            while self.unreported.len() > REMEMBERED_DEPARTURES {
                self.unreported.pop_front();
            }
        }

        match self.current_frame {
            Some((current, _)) if current == timestamp => {}
            previous => {
                if let Some((_, started)) = previous {
                    self.frame_intervals
                        .push_back((now, now.saturating_duration_since(started)));
                }
                self.current_frame = Some((timestamp, now));
                self.frames.push_back(FrameSize::default());
                while self.frames.len() > frames_kept {
                    self.frames.pop_front();
                }
            }
        }
        while let Some((at, _)) = self.frame_intervals.front() {
            if now.saturating_duration_since(*at) <= FRAME_INTERVAL_WINDOW {
                break;
            }
            self.frame_intervals.pop_front();
        }
        if let Some(frame) = self.frames.back_mut() {
            frame.bytes += size as u64;
            frame.packets += 1;
        }
    }

    /// The receiver reported `highest` as the extended highest sequence number received: the
    /// departures up to it are covered.
    fn on_reported(&mut self, highest: u32) {
        let highest = highest as u16;
        while let Some((sequence_number, _)) = self.unreported.front() {
            if is_newer(*sequence_number, highest) {
                break;
            }
            self.unreported.pop_front();
        }
    }

    /// When the oldest packet no report has covered left.
    fn oldest_unreported(&self) -> Option<Instant> {
        self.unreported.front().map(|(_, sent)| *sent)
    }
}

/// Whether sequence number `a` is ahead of `b` (RFC 3550 A.1: within half the number space).
fn is_newer(a: u16, b: u16) -> bool {
    a != b && a.wrapping_sub(b) < 0x8000
}

/// The RTP circuit breaker of RFC 8083: stops a flow whose receiver has gone, whose media is
/// not arriving, or that is persistently taking far more than its share.
///
/// # Where this belongs in the chain
///
/// [`Slot::CircuitBreaker`](crate::Slot::CircuitBreaker): below the pacer, so it sees every RTP
/// packet when it is released, generated ones included; above the TWCC sender and the send
/// history, so a packet it drops is never numbered or recorded as sent.
pub struct CircuitBreakerInterceptor {
    config: Config,
    flows: HashMap<u32, Flow>,
    /// When media was first sent since RTCP last reported on it: what the RTCP timeout runs
    /// from. `None` while nothing sent is waiting to be reported on.
    awaiting_rtcp_since: Option<Instant>,
    /// What the chain's RTCP session last calculated as the deterministic reporting interval
    /// (RFC 3550 section 6.3.1), `None` when no RTCP session says.
    calculated_interval: Option<crate::RtcpReportingInterval>,
    shared: Arc<Mutex<Shared>>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

/// MEDIA_TIMEOUT = ceil(k * max(Tf, Tr, Tdr) / Tdr) (RFC 8083 section 4.2).
fn media_timeout(k: u32, tf: Duration, tr: Duration, tdr: Duration) -> u32 {
    let tdr = tdr.as_secs_f64().max(1e-3);
    let longest = tf.as_secs_f64().max(tr.as_secs_f64()).max(tdr);
    // The small allowance keeps a ratio that is a whole number in exact arithmetic from
    // being rounded up by its floating-point error.
    (f64::from(k) * longest / tdr - 1e-9).ceil().max(1.0) as u32
}

/// CB_INTERVAL = ceil(3 * min(max(10*G*Tf, 10*Tr, 3*Tdr), max(15, 3*Td)) / (3*Tdr))
/// (RFC 8083 section 4.3).
fn cb_interval(g: u32, tf: Duration, tr: Duration, tdr: Duration, td: Duration) -> u32 {
    let tdr = tdr.as_secs_f64().max(1e-3);
    let reaction = (10.0 * f64::from(g) * tf.as_secs_f64())
        .max(10.0 * tr.as_secs_f64())
        .max(3.0 * tdr);
    let cap = 15f64.max(3.0 * td.as_secs_f64());
    ((3.0 * reaction.min(cap)) / (3.0 * tdr) - 1e-9)
        .ceil()
        .max(1.0) as u32
}

/// The sending rate, in bytes per second, over the newest of `samples` that together cover at
/// least `span` (one reporting interval at least); 0 without samples.
///
/// RFC 8083 section 4.3 compares X "with the actual sending rate of the RTP stream", and the
/// RFC 3551 text it quotes gives the timescale: "The timescale on which TCP throughput is
/// measured is the round-trip time of the connection."
fn recent_rate(samples: &VecDeque<LossSample>, span: Duration) -> f64 {
    let mut covered = Duration::ZERO;
    let mut bytes = 0u64;
    for sample in samples.iter().rev() {
        covered += sample.duration;
        bytes += sample.bytes_sent;
        if covered >= span {
            break;
        }
    }
    if covered.is_zero() {
        0.0
    } else {
        bytes as f64 / covered.as_secs_f64()
    }
}

/// s over the reporting intervals the sending rate is measured over: the bytes sent in them
/// divided by the packets sent in them, `None` when none were sent.
fn window_packet_size(samples: &VecDeque<LossSample>) -> Option<f64> {
    let (bytes, packets) = samples
        .iter()
        .fold((0u64, 0u64), |(bytes, packets), sample| {
            (bytes + sample.bytes_sent, packets + sample.packets_sent)
        });
    (packets > 0).then(|| bytes as f64 / packets as f64)
}

/// The share of the packets expected over `samples` that the cumulative count says were lost
/// (RFC 3550 6.4.1: expected less received, late packets counted as received), `None` when
/// the window expected none.
///
/// The fraction lost of each report cannot be negative (RFC 3550 A.3), so a packet that is
/// only reordered across a report's boundary counts as lost in the interval that should have
/// had it and is not given back in the next: on a path that reorders, the average of the
/// fractions shows loss that never happened. RFC 8083 section 4.3 approximates the loss event
/// rate by that average, a figure meant to err on the side of more loss; it cannot be more
/// than the share actually lost, so the breaker takes the smaller of the two.
///
/// The newest report's own count is taken only where it gives packets back: a packet missing
/// at that report may still be on its way (overtaken a moment before the report went), and
/// the next report says whether it was lost. A packet really lost counts from then on, one
/// reporting interval later.
fn net_loss(samples: &VecDeque<LossSample>) -> Option<f64> {
    let newest = samples.len().saturating_sub(1);
    let (lost, expected) =
        samples
            .iter()
            .enumerate()
            .fold((0i64, 0i64), |(lost, expected), (index, sample)| {
                let net_lost = if index == newest {
                    sample.net_lost.min(0)
                } else {
                    sample.net_lost
                };
                (lost + net_lost, expected + sample.net_expected)
            });
    (expected > 0).then(|| lost.max(0) as f64 / expected as f64)
}

/// The throughput, in bytes per second, a TCP connection would achieve with packets of `s`
/// bytes, round trip time `tr` and loss event rate `p` (RFC 8083 section 4.3), with b = 1 and
/// t_RTO = 4 * Tr.
fn tcp_throughput(s: f64, tr: Duration, p: f64, full: bool) -> f64 {
    let tr = tr.as_secs_f64().max(1e-6);
    let b = 1.0;
    let simplified = tr * (2.0 * b * p / 3.0).sqrt();
    let denominator = if full {
        let t_rto = 4.0 * tr;
        simplified + t_rto * (3.0 * (3.0 * b * p / 8.0).sqrt() * p * (1.0 + 32.0 * p * p))
    } else {
        simplified
    };
    s / denominator
}

impl CircuitBreakerInterceptor {
    fn publish(&self, ssrc: u32) {
        if let Some(flow) = self.flows.get(&ssrc) {
            lock(&self.shared).states.insert(ssrc, flow.state);
        }
    }

    /// Apply the restarts the application asked for through the handle.
    fn apply_restarts(&mut self, now: Instant) {
        let restarts = std::mem::take(&mut lock(&self.shared).restarts);
        for ssrc in restarts {
            self.restart(now, ssrc);
        }
    }

    /// The flow sends again, and the chain application-ward is told.
    fn restart(&mut self, now: Instant, ssrc: u32) {
        let Some(flow) = self.flows.get_mut(&ssrc) else {
            return;
        };
        // A restarted flow starts from nothing: what was measured before describes the path
        // that tripped the breaker. What it keeps is how often it tripped, which the next
        // hold is measured by.
        let (trips, last_hold) = (flow.trips, flow.last_hold);
        *flow = Flow::new();
        flow.trips = trips;
        flow.last_hold = last_hold;
        flow.restarted_at = Some(now);
        self.publish(ssrc);
        self.notify(now, ssrc, None, Duration::ZERO);
    }

    /// Tells the chain application-ward, and through it the application, that a flow ceased
    /// or was restarted ([`CircuitBreakerNotice`]).
    fn notify(
        &mut self,
        now: Instant,
        ssrc: u32,
        ceased: Option<CircuitBreakerReason>,
        restart_after: Duration,
    ) {
        self.read_queue.push_back(TaggedPacket {
            now,
            transport: shared::TransportContext::default(),
            message: crate::AttributedPacket::new(Packet::Rtcp(vec![])).with(
                crate::Attribute::Custom(Arc::new(CircuitBreakerNotice {
                    ssrc,
                    ceased,
                    restart_after,
                })),
            ),
        });
    }

    /// Cease transmission of `ssrc`, or of every flow when flows are grouped.
    fn cease(&mut self, ssrc: u32, trip: Trip, now: Instant) {
        let ssrcs: Vec<u32> = if self.config.group {
            self.flows.keys().copied().collect()
        } else {
            vec![ssrc]
        };
        for ssrc in ssrcs {
            if let Some(flow) = self.flows.get_mut(&ssrc)
                && !flow.is_ceased()
            {
                // Section 4.5: "the reaction to a triggered circuit breaker lasts for at least
                // the triggering interval". A flow that trips again soon after a restart is
                // held twice as long each time: a restart that keeps failing is the "automatic
                // redial" the section warns of, and has to become rare.
                let soon = flow.restarted_at.is_some_and(|at| {
                    now.saturating_duration_since(at)
                        < flow.last_hold.saturating_mul(CLEAN_RUN_HOLDS)
                });
                flow.trips = if soon {
                    (flow.trips + 1).min(MAX_HOLD_DOUBLINGS + 1)
                } else {
                    1
                };
                let hold = trip.interval.saturating_mul(1 << (flow.trips - 1));
                flow.last_hold = hold;
                let restart_after = now + hold;
                flow.state = CircuitBreakerState::Ceased {
                    reason: trip.reason,
                    at: now,
                    restart_after,
                };
                flow.halt = Some(Halt {
                    reason: trip.reason,
                    hold,
                    restart_after,
                    rate: trip.rate,
                    packet_size: trip.packet_size,
                    since: now,
                    covered: 0.0,
                    lost: 0.0,
                });
                // Stopping a stream cancels its media timeout breaker (section 4.2).
                flow.stalled_reports = 0;
                log::warn!(
                    "RTP circuit breaker: SSRC {ssrc:#x} ceased transmission ({:?}), held {hold:?}",
                    trip.reason
                );
                self.publish(ssrc);
                self.notify(now, ssrc, Some(trip.reason), hold);
            }
        }
    }

    fn rtcp_timeout(&self) -> Duration {
        self.config.rtcp_interval * RTCP_TIMEOUT_INTERVALS
    }

    /// A report on a running flow, held against the ceased flows of the same transport:
    /// section 4.5's "information that the congestion has dissipated".
    fn on_witness(&mut self, now: Instant, witness: Witness) {
        if !self.config.automatic_restart {
            return;
        }
        let config = self.config;
        let mut restarts = Vec::new();
        for (ssrc, flow) in self.flows.iter_mut() {
            if *ssrc == witness.ssrc {
                continue;
            }
            let Some(halt) = flow.halt.as_mut() else {
                continue;
            };
            match halt.reason {
                // "Most likely due to a path failure" (section 4): packets of another flow
                // arriving over the same 5-tuple show the path delivers.
                CircuitBreakerReason::MediaTimeout => {
                    if witness.progressed && now >= halt.restart_after {
                        restarts.push(*ssrc);
                    }
                }
                // A report on an SSRC this endpoint sends, see `on_rtcp`.
                CircuitBreakerReason::RtcpTimeout => {}
                CircuitBreakerReason::Congestion | CircuitBreakerReason::MediaUnusable => {
                    if witness.progressed {
                        let duration = witness.duration.as_secs_f64();
                        halt.covered += duration;
                        halt.lost += witness.fraction_lost * duration;
                    }
                    if now.saturating_duration_since(halt.since) < halt.hold {
                        continue;
                    }
                    // A whole hold of reports: what do they say of the path now?
                    let informed = halt.covered >= halt.hold.as_secs_f64() / 2.0;
                    let loss = if halt.covered > 0.0 {
                        halt.lost / halt.covered
                    } else {
                        0.0
                    };
                    let dissipated = informed
                        && match halt.reason {
                            CircuitBreakerReason::Congestion => {
                                loss <= 0.0
                                    || witness.round_trip_time.is_some_and(|tr| {
                                        halt.rate
                                            <= 10.0
                                                * tcp_throughput(
                                                    halt.packet_size,
                                                    tr,
                                                    loss,
                                                    config.full_tcp_equation,
                                                )
                                    })
                            }
                            _ => config.usability.is_none_or(|usability| {
                                loss <= usability.max_loss
                                    && witness
                                        .round_trip_time
                                        .is_none_or(|tr| tr <= usability.max_round_trip_time)
                            }),
                        };
                    if dissipated {
                        restarts.push(*ssrc);
                    } else {
                        // Not yet: the next verdict is on another whole hold of reports.
                        halt.since = now;
                        halt.covered = 0.0;
                        halt.lost = 0.0;
                    }
                }
            }
        }
        for ssrc in restarts {
            log::info!("RTP circuit breaker: SSRC {ssrc:#x} restarted on the receiver's reports");
            self.restart(now, ssrc);
        }
    }

    /// One report block about a flow this endpoint sends, from the SSRC `reporter`, in a
    /// sender report or a receiver report.
    ///
    /// The breaker is RFC 8083's for a unicast session: one receiver. That receiver reports on
    /// the flow from each of its SSRCs (RFC 8108 section 5.1: "each SSRC will send RTCP reports
    /// for all other SSRCs"), the same reception each time: the flow follows one reporting
    /// SSRC, and takes another only once the one it follows has been silent for the RTCP
    /// timeout (it left, or changed SSRC). Counting every copy would count each report several
    /// times (MEDIA_TIMEOUT reached in a fraction of the reports, each loss interval's packets
    /// taken by the first copy) and see a zero spacing between the copies (Tdr).
    fn on_report_block(
        &mut self,
        now: Instant,
        reporter: u32,
        report: &rtcp::reception_report::ReceptionReport,
        in_sender_report: bool,
    ) {
        let config = self.config;
        let rtcp_timeout = self.rtcp_timeout();
        // What the RTCP session calculates for a member in the receiver's place (RFC 8083
        // section 3: "whether the receiver is sending SR or RR packets"). Tdr above five
        // seconds is not to be configured (section 4.3), so the calculation claims no more.
        let calculated = self.calculated_interval.map(|interval| {
            if in_sender_report {
                interval.sender
            } else {
                interval.receiver
            }
            .min(DEFAULT_RTCP_INTERVAL)
        });
        let Some(flow) = self.flows.get_mut(&report.ssrc) else {
            return;
        };
        if flow.is_ceased() {
            return;
        }
        if let Some((followed, at)) = flow.reporter
            && followed != reporter
            && now.saturating_duration_since(at) < rtcp_timeout
        {
            return;
        }
        flow.reporter = Some((reporter, now));

        // Tr: RFC 3550 section 6.4.1, smoothed as RFC 8083 section 3 says.
        if report.last_sender_report != 0
            && let Some((_, sent)) = flow
                .sender_reports
                .iter()
                .rev()
                .find(|(lsr, _)| *lsr == report.last_sender_report)
        {
            let delay = Duration::from_secs_f64(f64::from(report.delay) / 65_536.0);
            let sample = now.saturating_duration_since(*sent).saturating_sub(delay);
            flow.round_trip_time = Some(match flow.round_trip_time {
                Some(previous) => previous.mul_f64(0.8) + sample.mul_f64(0.2),
                None => sample,
            });
        }

        // No sender report of this flow was seen leaving (the report generator is wire-ward of
        // here): Tr is the round trip time the congestion controller measured, smoothed where
        // its measurements are handed in (`CircuitBreakerHandle::report_round_trip_time`).
        if flow.sender_reports.is_empty()
            && let Some(reported) = lock(&self.shared).round_trip_time
        {
            flow.round_trip_time = Some(reported);
        }

        // How often this receiver actually reports.
        let since_last = flow
            .last_report_at
            .map(|last| now.saturating_duration_since(last));
        if let Some(interval) = since_last {
            flow.receiver_interval = Some(match flow.receiver_interval {
                Some(previous) => previous.mul_f64(0.8) + interval.mul_f64(0.2),
                None => interval,
            });
        }
        flow.last_report_at = Some(now);
        flow.reports_received += 1;

        // Tdr: the calculated deterministic interval, or the spacing of the reports where that
        // is longer (the receiver uses a minimum interval the calculation cannot know of).
        // Without an RTCP session to calculate it, the spacing; Td until there is one.
        let tdr = match (calculated, flow.receiver_interval) {
            (Some(calculated), Some(observed)) => calculated.max(observed),
            (Some(calculated), None) => calculated,
            (None, Some(observed)) => observed,
            (None, None) => config.rtcp_interval,
        };
        let tf = flow.frame_interval();
        let tr = flow.round_trip_time.unwrap_or_default();
        let sent_packets = std::mem::take(&mut flow.packets_since_report);
        let sent_bytes = std::mem::take(&mut flow.bytes_since_report);
        log::debug!(
            "circuit breaker: report on {:#x}: fraction lost {}/256, cumulative lost {}, \
             extended highest {}, jitter {}, LSR {:#x}, DLSR {}; Tr {:?} (shared {:?}), Tdr {:?} \
             (calculated {:?}, observed {:?}), Tf {:?}, sent since last {} packets / {} bytes, \
             report {}",
            report.ssrc,
            report.fraction_lost,
            report.total_lost,
            report.last_sequence_number,
            report.jitter,
            report.last_sender_report,
            report.delay,
            flow.round_trip_time,
            lock(&self.shared).round_trip_time,
            tdr,
            calculated,
            flow.receiver_interval,
            tf,
            sent_packets,
            sent_bytes,
            flow.reports_received,
        );

        // --- Media timeout (section 4.2) ---
        let timeout = media_timeout(config.non_reporting_threshold, tf, tr, tdr);
        let progressed = match flow.highest_sequence {
            Some(previous) => report.last_sequence_number > previous,
            None => true,
        };
        let highest = flow
            .highest_sequence
            .map_or(report.last_sequence_number, |previous| {
                previous.max(report.last_sequence_number)
            });
        flow.highest_sequence = Some(highest);
        flow.on_reported(highest);
        // "If RTP data packets are being sent": a flow that has sent nothing for twice the
        // longest of its intervals has stopped (a paused pacer, a muted source), and
        // "When stopping sending an RTP stream, a sender MUST cancel the corresponding media
        // timeout circuit breaker."
        let slowest = tf.max(tr).max(tdr);
        let sending = flow
            .last_departure
            .is_some_and(|sent| now.saturating_duration_since(sent) <= slowest * 2);
        // "An RTCP packet indicating that its media was not received": a packet the report
        // does not cover left long enough ago to have arrived and been reported, a round trip
        // at least. A report that comes sooner than that after the packet says nothing of it.
        let missed = flow
            .oldest_unreported()
            .is_some_and(|sent| now.saturating_duration_since(sent) >= tr);
        let mut trip: Option<Trip> = None;
        if progressed {
            // The media is arriving: the breaker is cancelled and set anew.
            flow.stalled_reports = 0;
            flow.media_timeout = timeout;
        } else if !sending {
            flow.stalled_reports = 0;
            flow.media_timeout = timeout;
        } else if missed {
            // Media was sent and the receiver did not see it. Reconsider: the timeout only
            // ever extends.
            flow.media_timeout = flow.media_timeout.max(timeout);
            flow.stalled_reports += 1;
            log::debug!(
                "circuit breaker: {:#x}: no progress, {} of MEDIA_TIMEOUT {}",
                report.ssrc,
                flow.stalled_reports,
                flow.media_timeout
            );
            if flow.stalled_reports >= flow.media_timeout {
                trip = Some(Trip::new(
                    CircuitBreakerReason::MediaTimeout,
                    tdr * flow.media_timeout,
                ));
            }
        }

        // The interval's net loss by the cumulative count (RFC 3550 6.4.1, A.3).
        let cumulative = report.cumulative_lost();
        // The receiver counts every sequence number it did not receive as lost, the ones the
        // pacer discarded before they left included. Those are not the path's loss: over the
        // interval the report covers they come out of the count, and out of the packets
        // expected, and the fraction lost is that of the packets that left.
        let interval = flow
            .never_sent
            .on_report(report.last_sequence_number, cumulative)
            .filter(|interval| interval.never_sent() > 0);
        let never_sent = interval.map_or(0, |interval| interval.never_sent());
        let (net_lost, net_expected) = match flow
            .previous_report
            .replace((cumulative, report.last_sequence_number))
        {
            Some((previous_lost, previous_highest)) => (
                i64::from(cumulative) - i64::from(previous_lost) - never_sent,
                i64::from(report.last_sequence_number.wrapping_sub(previous_highest) as i32)
                    - never_sent,
            ),
            None => (0, 0),
        };
        let fraction_lost = interval.map_or(f64::from(report.fraction_lost) / 256.0, |interval| {
            interval.fraction_lost()
        });

        // --- Congestion (section 4.3) ---
        let cb_tdr = config.t_rr_interval.map_or(tdr, |t_rr| t_rr.max(tdr));
        let interval = cb_interval(
            config.frame_group_size,
            tf,
            tr,
            cb_tdr,
            config.rtcp_interval,
        );
        if let Some(duration) = since_last {
            // Only while at least one packet is sent every max(Tdr, Tr): with fewer, the
            // fraction lost is a measurement artefact. That is the sender's rate, not every
            // report's: reports closer together than max(Tdr, Tr) (AVPF with early feedback
            // compounds: every 10 ms on a video flow) often see no packet of a flow that sends
            // a frame every 20 ms, and clearing the samples on each such report kept the
            // breaker from ever judging the flow. Over an interval shorter than the period, a
            // packet sent within the last period is enough.
            let period = tdr.max(tr).as_secs_f64().max(1e-3);
            let enough = if duration.as_secs_f64() >= period {
                sent_packets as f64 >= (duration.as_secs_f64() / period).floor()
            } else {
                flow.last_departure
                    .is_some_and(|sent| now.saturating_duration_since(sent).as_secs_f64() <= period)
            };
            if enough {
                flow.losses.push_back(LossSample {
                    fraction_lost,
                    duration,
                    bytes_sent: sent_bytes,
                    packets_sent: sent_packets,
                    net_lost,
                    net_expected,
                });
            } else {
                flow.losses.clear();
            }
            while flow.losses.len() > interval as usize {
                flow.losses.pop_front();
            }
        }
        if matches!(flow.state, CircuitBreakerState::Reduced { .. }) {
            flow.reports_since_reduction += 1;
        }
        let window: Duration = flow.losses.iter().map(|sample| sample.duration).sum();
        if trip.is_none()
            && flow.reports_received > u64::from(interval)
            && flow.losses.len() >= interval as usize
            && !window.is_zero()
            && let Some(tr) = flow.round_trip_time
            && let Some(packet_size) = match config.packet_size {
                PacketSize::SendingWindow => window_packet_size(&flow.losses),
                PacketSize::LastFrames => flow.packet_size(),
            }
        {
            let average = flow
                .losses
                .iter()
                .map(|sample| sample.fraction_lost * sample.duration.as_secs_f64())
                .sum::<f64>()
                / window.as_secs_f64();
            let loss = average.min(net_loss(&flow.losses).unwrap_or(average));
            let bytes: u64 = flow.losses.iter().map(|sample| sample.bytes_sent).sum();
            let sending_rate = bytes as f64 / window.as_secs_f64();
            // "The actual sending rate of the RTP stream": what it sends now, over a round
            // trip (and a group of frames at least). CB_INTERVAL is there "to give the
            // congestion control algorithm time to react", so a flow whose rate came down
            // inside it is judged at the rate it came down to. The breaker trips on a flow
            // that was above ten times X over the intervals the loss is averaged over and
            // still is.
            let actual_rate = recent_rate(&flow.losses, tr.max(tf * config.frame_group_size));
            let bound = 10.0 * tcp_throughput(packet_size, tr, loss, config.full_tcp_equation);
            log::debug!(
                "circuit breaker: {:#x}: CB_INTERVAL {interval}, loss {loss:.4} over {window:?}, \
                 sending {sending_rate:.0} B/s (now {actual_rate:.0} B/s), s {packet_size:.0} B, \
                 Tr {tr:?}, 10 x TCP {bound:.0} B/s",
                report.ssrc,
            );
            if loss > 0.0 && sending_rate > bound && actual_rate > bound {
                match flow.state {
                    CircuitBreakerState::Running if config.reduce_before_ceasing => {
                        flow.state = CircuitBreakerState::Reduced {
                            limit_bits_per_second: sending_rate * 8.0 / 10.0,
                        };
                        flow.reports_since_reduction = 0;
                        // The next verdict is on what is sent from here on.
                        flow.losses.clear();
                        flow.reports_received = 0;
                    }
                    _ => {
                        trip = Some(Trip {
                            reason: CircuitBreakerReason::Congestion,
                            interval: window,
                            rate: sending_rate,
                            packet_size,
                        })
                    }
                }
            } else if matches!(flow.state, CircuitBreakerState::Reduced { .. })
                && flow.reports_since_reduction >= u64::from(interval)
            {
                // The reduction resolved it.
                flow.state = CircuitBreakerState::Running;
            }
        }

        // --- Media usability (section 4.4) ---
        if let Some(usability) = config.usability {
            let unusable = fraction_lost > usability.max_loss
                || flow
                    .round_trip_time
                    .is_some_and(|rtt| rtt > usability.max_round_trip_time);
            if unusable {
                let since = *flow.unusable_since.get_or_insert(now);
                if trip.is_none() && now.saturating_duration_since(since) >= usability.period {
                    trip = Some(Trip::new(
                        CircuitBreakerReason::MediaUnusable,
                        usability.period,
                    ));
                }
            } else {
                flow.unusable_since = None;
            }
        }

        let witness = Witness {
            ssrc: report.ssrc,
            progressed,
            fraction_lost,
            duration: since_last.unwrap_or_default(),
            round_trip_time: flow.round_trip_time,
        };
        match trip {
            Some(trip) => self.cease(witness.ssrc, trip, now),
            None => {
                self.publish(witness.ssrc);
                self.on_witness(now, witness);
            }
        }
    }

    /// Inbound RTCP: the report blocks feed the breakers, and anything at all shows the
    /// receiver and the return path are alive.
    fn on_rtcp(&mut self, now: Instant, packets: &[Box<dyn rtcp::Packet>]) {
        let mut reports = Vec::new();
        let mut has_report_packet = false;
        for packet in packets {
            let any = packet.as_any();
            if let Some(sr) = any.downcast_ref::<rtcp::sender_report::SenderReport>() {
                has_report_packet = true;
                reports.extend(
                    sr.reports
                        .iter()
                        .cloned()
                        .map(|report| (sr.ssrc, report, true)),
                );
            } else if let Some(rr) = any.downcast_ref::<rtcp::receiver_report::ReceiverReport>() {
                has_report_packet = true;
                reports.extend(
                    rr.reports
                        .iter()
                        .cloned()
                        .map(|report| (rr.ssrc, report, false)),
                );
            }
        }

        // RTCP timeout (section 4.1): a report on any SSRC this endpoint sends shows the
        // receiver and the return path work. A reduced-size packet without SR or RR counts as
        // received for this breaker too (section 5), and for this breaker only.
        let reports_on_us = reports
            .iter()
            .any(|(_, report, _)| self.flows.contains_key(&report.ssrc));
        if !packets.is_empty() && (!has_report_packet || reports_on_us) {
            self.awaiting_rtcp_since = None;
        }

        // A flow the RTCP timeout stopped had "no way of knowing if it is causing congestion"
        // (section 4.1). A report on an SSRC this endpoint sends is that way back: once the
        // hold has passed the flow sends again.
        if self.config.automatic_restart && reports_on_us {
            let due: Vec<u32> = self
                .flows
                .iter()
                .filter(|(_, flow)| {
                    flow.halt.is_some_and(|halt| {
                        halt.reason == CircuitBreakerReason::RtcpTimeout
                            && now >= halt.restart_after
                    })
                })
                .map(|(ssrc, _)| *ssrc)
                .collect();
            for ssrc in due {
                log::info!("RTP circuit breaker: SSRC {ssrc:#x} restarted: RTCP reports again");
                self.restart(now, ssrc);
            }
        }

        for (reporter, report, in_sender_report) in &reports {
            self.on_report_block(now, *reporter, report, *in_sender_report);
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for CircuitBreakerInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.apply_restarts(msg.now);
        if let Some(interval) = msg.message.custom::<crate::RtcpReportingInterval>() {
            self.calculated_interval = Some(*interval);
        }
        if let Packet::Rtcp(packets) = &msg.message.packet {
            let packets: Vec<_> = packets.to_vec();
            self.on_rtcp(msg.now, &packets);
        }
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.apply_restarts(msg.now);
        match &msg.message.packet {
            Packet::Rtp(rtp_packet) => {
                let frames_kept = 4 * self.config.frame_group_size as usize;
                if let Some(flow) = self.flows.get_mut(&rtp_packet.header.ssrc) {
                    if flow.is_ceased() {
                        // Transmission has ceased (section 4.5): the packet does not leave.
                        lock(&self.shared).dropped += 1;
                        return Ok(());
                    }
                    flow.on_departure(
                        msg.now,
                        rtp_packet.header.sequence_number,
                        rtp_packet.header.timestamp,
                        rtp_packet.marshal_size(),
                        frames_kept,
                    );
                    self.awaiting_rtcp_since.get_or_insert(msg.now);
                }
            }
            Packet::Rtcp(packets) => {
                // The sender reports this endpoint sends: a report block's LSR names one.
                for packet in packets {
                    if let Some(sr) = packet
                        .as_any()
                        .downcast_ref::<rtcp::sender_report::SenderReport>()
                        && let Some(flow) = self.flows.get_mut(&sr.ssrc)
                    {
                        flow.sender_reports
                            .push_back(((sr.ntp_time >> 16) as u32, msg.now));
                        while flow.sender_reports.len() > REMEMBERED_SENDER_REPORTS {
                            flow.sender_reports.pop_front();
                        }
                    }
                }
            }
        }
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
        self.apply_restarts(now);
        if let Some(since) = self.awaiting_rtcp_since
            && now.saturating_duration_since(since) >= self.rtcp_timeout()
        {
            // Media has been sent for three reporting intervals and nothing reported on it:
            // there is no way to know whether it is causing congestion (section 4.1).
            self.awaiting_rtcp_since = None;
            let hold = self.rtcp_timeout();
            let ssrcs: Vec<u32> = self
                .flows
                .iter()
                .filter(|(_, flow)| !flow.is_ceased() && flow.current_frame.is_some())
                .map(|(ssrc, _)| *ssrc)
                .collect();
            for ssrc in ssrcs {
                self.cease(
                    ssrc,
                    Trip::new(CircuitBreakerReason::RtcpTimeout, hold),
                    now,
                );
            }
        }
        Ok(())
    }

    /// The RTCP timeout's deadline while sent media is waiting to be reported on, `None`
    /// otherwise.
    fn poll_timeout(&mut self) -> Option<Self::Time> {
        self.awaiting_rtcp_since
            .map(|since| since + self.rtcp_timeout())
    }
}

impl Interceptor for CircuitBreakerInterceptor {
    /// The media SSRC and its repair flows are each a flow on the transport.
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        for ssrc in flow_ssrcs(info) {
            self.flows.entry(ssrc).or_insert_with(Flow::new);
            self.publish(ssrc);
        }
    }

    /// Stopping a stream cancels its breakers (section 4.2).
    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        for ssrc in flow_ssrcs(info) {
            self.flows.remove(&ssrc);
            lock(&self.shared).states.remove(&ssrc);
        }
        if self.flows.values().all(|flow| flow.current_frame.is_none()) {
            self.awaiting_rtcp_since = None;
        }
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(seconds: f64) -> Duration {
        Duration::from_secs_f64(seconds)
    }

    /// RFC 8083 section 4.2: MEDIA_TIMEOUT = ceil(k * max(Tf, Tr, Tdr) / Tdr).
    #[test]
    fn media_timeout_is_k_reports_scaled_by_the_slowest_interval() {
        // Tdr dominates: k reports.
        assert_eq!(5, media_timeout(5, secs(0.033), secs(0.1), secs(1.0)));
        // A frame every 3 s against reports every second: 15 reports.
        assert_eq!(15, media_timeout(5, secs(3.0), secs(0.1), secs(1.0)));
        // A round trip of 1.5 reporting intervals: ceil(7.5).
        assert_eq!(8, media_timeout(5, secs(0.02), secs(1.5), secs(1.0)));
    }

    /// RFC 8083 section 4.3:
    /// CB_INTERVAL = ceil(3 * min(max(10*G*Tf, 10*Tr, 3*Tdr), max(15, 3*Td)) / (3*Tdr)).
    #[test]
    fn cb_interval_gives_the_congestion_controller_time_to_react() {
        // 30 fps, 100 ms round trip, reports every second: max(0.33, 1, 3) = 3 s, 3 reports.
        assert_eq!(
            3,
            cb_interval(1, secs(1.0 / 30.0), secs(0.1), secs(1.0), secs(5.0))
        );
        // A 600 ms round trip: 10 * Tr = 6 s, 6 reports.
        assert_eq!(
            6,
            cb_interval(1, secs(0.033), secs(0.6), secs(1.0), secs(5.0))
        );
        // A long GOP (G = 300 at 30 fps is 100 s) is capped at max(15, 3 * Td) = 15 s.
        assert_eq!(
            15,
            cb_interval(300, secs(1.0 / 30.0), secs(0.1), secs(1.0), secs(5.0))
        );
        // Reports every 5 s: 3 * Tdr = 15 s, 3 reports.
        assert_eq!(
            3,
            cb_interval(1, secs(0.033), secs(0.1), secs(5.0), secs(5.0))
        );
    }

    /// The boundary values of MEDIA_TIMEOUT = ceil(k * max(Tf, Tr, Tdr) / Tdr): a ratio that is
    /// a whole number is that number, the least bit more is one more report; each of the
    /// three intervals takes over at the instant it becomes the longest.
    #[test]
    fn media_timeout_at_its_boundaries() {
        // Tr exactly Tdr: k. A millisecond longer: ceil(5 * 0.026 / 0.025) = 6.
        assert_eq!(5, media_timeout(5, secs(0.02), secs(0.025), secs(0.025)));
        assert_eq!(6, media_timeout(5, secs(0.02), secs(0.026), secs(0.025)));
        // Tf exactly twice Tdr: 10. Tf just past it: 11.
        assert_eq!(10, media_timeout(5, secs(0.05), secs(0.0), secs(0.025)));
        assert_eq!(11, media_timeout(5, secs(0.0501), secs(0.0), secs(0.025)));
        // A queue that makes the round trip 300 ms against reports every 25 ms: 60 reports.
        assert_eq!(60, media_timeout(5, secs(0.02), secs(0.3), secs(0.025)));
        // k = 1 with everything shorter than Tdr: one report.
        assert_eq!(1, media_timeout(1, secs(0.0), secs(0.0), secs(5.0)));
    }

    /// The boundary values of CB_INTERVAL: where each term of the inner max takes over, and
    /// the cap max(15, 3 * Td).
    #[test]
    fn cb_interval_at_its_boundaries() {
        // 10 * Tr exactly 3 * Tdr (0.3 s, 1 s): 3 reports. Tr a little longer: 4.
        assert_eq!(
            3,
            cb_interval(1, secs(0.02), secs(0.3), secs(1.0), secs(5.0))
        );
        assert_eq!(
            4,
            cb_interval(1, secs(0.02), secs(0.31), secs(1.0), secs(5.0))
        );
        // 10 * G * Tf takes over from 10 * Tr: G = 30 frames of 33 ms is 10 s, 10 reports.
        assert_eq!(
            10,
            cb_interval(30, secs(1.0 / 30.0), secs(0.1), secs(1.0), secs(5.0))
        );
        // The cap: 10 * Tr = 20 s is held to max(15, 3 * 5) = 15 s; with Td = 6 s to 18 s.
        assert_eq!(
            15,
            cb_interval(1, secs(0.02), secs(2.0), secs(1.0), secs(5.0))
        );
        assert_eq!(
            18,
            cb_interval(1, secs(0.02), secs(2.0), secs(1.0), secs(6.0))
        );
        // Reports every 25 ms and a 142 ms round trip: ceil(1.42 / 0.025) = 57 reports.
        assert_eq!(
            57,
            cb_interval(1, secs(0.02), secs(0.142), secs(0.025), secs(5.0))
        );
    }

    /// The sending rate "now": over the newest samples that cover the span, one at least.
    #[test]
    fn the_recent_rate_is_that_of_the_newest_samples_covering_the_span() {
        let sample = |milliseconds: u64, bytes: u64| LossSample {
            fraction_lost: 0.0,
            duration: Duration::from_millis(milliseconds),
            bytes_sent: bytes,
            packets_sent: 1,
            net_lost: 0,
            net_expected: 1,
        };
        let samples: VecDeque<LossSample> =
            [sample(100, 50_000), sample(100, 10_000), sample(100, 2_000)].into();
        // A span shorter than the newest sample: that sample, 2000 bytes in 0.1 s.
        assert!((recent_rate(&samples, secs(0.05)) - 20_000.0).abs() < 1e-6);
        // Exactly one sample long: still that one. A little more: two (12000 in 0.2 s).
        assert!((recent_rate(&samples, secs(0.1)) - 20_000.0).abs() < 1e-6);
        assert!((recent_rate(&samples, secs(0.101)) - 60_000.0).abs() < 1e-6);
        // Longer than everything held: all of it.
        assert!((recent_rate(&samples, secs(5.0)) - 62_000.0 / 0.3).abs() < 1e-6);
        assert_eq!(0.0, recent_rate(&VecDeque::new(), secs(1.0)));
    }

    /// RFC 3550 A.1 sequence number order, across the wrap.
    #[test]
    fn sequence_numbers_are_ordered_across_the_wrap() {
        assert!(is_newer(2, 1));
        assert!(!is_newer(1, 2));
        assert!(!is_newer(7, 7));
        assert!(is_newer(3, 65_530));
        assert!(!is_newer(65_530, 3));
    }

    /// RFC 8083 section 4.3: X = s / (Tr * sqrt(2*b*p/3)), b = 1.
    #[test]
    fn the_simplified_tcp_equation_matches_the_rfc() {
        // s = 1200 bytes, Tr = 100 ms, p = 0.06: sqrt(0.04) = 0.2, so 1200 / 0.02.
        let x = tcp_throughput(1200.0, secs(0.1), 0.06, false);
        assert!((x - 60_000.0).abs() < 1e-6, "{x}");
    }

    /// RFC 8083 section 4.3 with t_RTO = 4 * Tr (section 3): the full equation is the more
    /// sensitive one, so it gives the lower throughput.
    #[test]
    fn the_full_tcp_equation_matches_the_rfc() {
        let p: f64 = 0.06;
        let tr: f64 = 0.1;
        let expected = 1200.0
            / (tr * (2.0 * p / 3.0).sqrt()
                + 4.0 * tr * (3.0 * (3.0 * p / 8.0).sqrt() * p * (1.0 + 32.0 * p * p)));
        let x = tcp_throughput(1200.0, secs(tr), p, true);
        assert!((x - expected).abs() < 1e-6, "{x} against {expected}");
        assert!(x < tcp_throughput(1200.0, secs(tr), p, false));
    }
}
