//! Records what left, ingests what the remote said about it, and drives an estimator.

use super::estimator::{BandwidthEstimator, EstimatorStats};
use super::feedback::{CongestionFeedbackFormat, negotiated_congestion_feedback};
use super::probe::{ProbeController, ProbePacket, probe_estimate};
use super::tmmbr::{self, TmmbrState};
use crate::Interceptor;
use crate::circuit_breaker::CircuitBreakerHandle;
use crate::rtpfb::acknowledgement::PacketReport;
use crate::rtpfb::convert::FeedbackTimeline;
use crate::rtpfb::history::History;
use crate::stream_info::StreamInfo;
use crate::twcc::{flow_ssrcs, stream_supports_twcc};
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use rtcp::transport_feedbacks::tmmb::{
    TemporaryMaximumBitrateNotification, TemporaryMaximumBitrateRequest,
};
use sansio::Protocol;
use shared::error::Error;
use shared::marshal::{MarshalSize, Unmarshal};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// How long an unacknowledged packet is kept before it is written off.
///
/// Bounds the send history on a path that has stopped reporting. Too short and late feedback names
/// packets there is no record of; too long and memory grows on a dead path. Two seconds is several
/// round trips on any path worth estimating for, and one report interval is measured in tens of
/// milliseconds.
pub const DEFAULT_PRUNE_HORIZON: Duration = Duration::from_secs(2);

/// How long a REMB keeps bounding the target after it was received.
///
/// A receiver that uses REMB sends one at least once per second
/// (draft-ietf-rmcat-gcc-02 section 3). Three of those intervals without one and the bound is
/// taken to be gone, as a receiver that stopped estimating has no other way to lift it.
pub const REMB_TIMEOUT: Duration = Duration::from_secs(3);

/// The addresses and protocol a packet arrived between.
type PathKey = (
    std::net::SocketAddr,
    std::net::SocketAddr,
    shared::TransportProtocol,
);

/// How many packets in a row arrive between new addresses before the path counts as changed:
/// one straggler on the old pair, or one early packet on a new one, is not a change.
const PATH_CHANGE_PACKETS: u8 = 3;

/// How long after its last packet left a probe cluster counts as sent in full: the pacer
/// spaces a cluster's packets by less than this.
const PROBE_CLOSED_AFTER: Duration = Duration::from_millis(50);

/// How long a probe cluster's packets are remembered without their reports.
const PROBE_FORGET: Duration = Duration::from_secs(2);

/// A probe cluster on the path.
struct ProbeCluster {
    /// How many of its packets left.
    sent: usize,
    last_sent: Instant,
    /// The reports on them so far.
    reports: Vec<PacketReport>,
}

impl ProbeCluster {
    fn new(now: Instant) -> Self {
        Self {
            sent: 0,
            last_sent: now,
            reports: Vec::new(),
        }
    }

    /// Whether the pacer has finished sending it.
    fn closed(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_sent) >= PROBE_CLOSED_AFTER
    }
}

/// Per-stream state: the header-extension id the transport-wide sequence number is written under.
struct LocalStream {
    hdr_ext_id: u8,
    /// The one feedback format this stream is reported in; reports in the other are not read.
    feedback: Option<CongestionFeedbackFormat>,
    /// Whether `a=rtcp-fb:<pt> ccm tmmbr` was negotiated for the stream (RFC 5104 section 7.1).
    tmmbr: bool,
}

/// Whether a stream negotiated TMMBR: `ccm tmmbr`, with or without `smaxpr=` (RFC 5104
/// section 7.1).
fn stream_negotiated_tmmbr(info: &StreamInfo) -> bool {
    info.rtcp_feedback.iter().any(|feedback| {
        feedback.typ == "ccm" && feedback.parameter.split_whitespace().next() == Some("tmmbr")
    })
}

/// Builder for [`CongestionControlInterceptor`].
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Slot, CongestionControlBuilder, ConstantBitrate, Registry};
///
/// let chain = Registry::new()
///     .with(Slot::CongestionControl, CongestionControlBuilder::new(ConstantBitrate::new(1_000_000.0)).build())
///     .build();
/// # let _ = chain;
/// ```
pub struct CongestionControlBuilder<E: BandwidthEstimator> {
    estimator: E,
    prune_horizon: Duration,
    circuit_breaker: Option<CircuitBreakerHandle>,
    unnegotiated_tmmbr: bool,
    bandwidth_probing: bool,
}

impl<E: BandwidthEstimator> CongestionControlBuilder<E> {
    /// A builder driving `estimator`.
    pub fn new(estimator: E) -> Self {
        Self {
            estimator,
            prune_horizon: DEFAULT_PRUNE_HORIZON,
            circuit_breaker: None,
            unnegotiated_tmmbr: false,
            bandwidth_probing: false,
        }
    }

    /// How long an unacknowledged packet is kept before it is written off.
    pub fn with_prune_horizon(mut self, prune_horizon: Duration) -> Self {
        self.prune_horizon = prune_horizon;
        self
    }

    /// The circuit breaker of the same chain. When its congestion breaker asks for a tenth of
    /// the rate (RFC 8083 section 4.3) the limit becomes an upper bound of the estimator.
    pub fn with_circuit_breaker(mut self, handle: CircuitBreakerHandle) -> Self {
        self.circuit_breaker = Some(handle);
        self
    }

    /// Whether a TMMBR is honoured for a stream that did not negotiate `ccm tmmbr`.
    ///
    /// Off by default: RFC 5104 section 7.1 has a codec control message used only when the
    /// session description names it (`a=rtcp-fb:<pt> ccm tmmbr`), and section 7.2 has the
    /// answerer remove what it does not support, so a TMMBR for a stream without it is a
    /// message the session never agreed to and is ignored, unanswered. `true` is the lenient
    /// behaviour: every TMMBR that names one of this endpoint's streams limits it and is
    /// answered with a TMMBN.
    pub fn with_unnegotiated_tmmbr(mut self, honoured: bool) -> Self {
        self.unnegotiated_tmmbr = honoured;
        self
    }

    /// Whether the path is probed for capacity above the target: short clusters of packets
    /// at a multiple of the target, whose arrival shows at once whether the path carries
    /// that rate. Off for a builder (it needs the pacer and the NACK responder of the same
    /// chain); on in the peer connection's default interceptor set
    /// (`DefaultInterceptorOptions::bandwidth_probing`).
    ///
    /// Without it the estimate climbs as fast as the delay-based controller raises it, 8% a
    /// second in [`Gcc`](crate::Gcc): from 300 kbit/s to 2.5 Mbit/s takes most of half a
    /// minute. With it, two clusters at the start (three and six times the starting rate),
    /// further ones at twice the result while the path keeps carrying what is asked, and one
    /// every five seconds while the application sends less than the target allows; a path
    /// with 2.5 Mbit/s is found in well under a second.
    ///
    /// RFC 8836 section 2 (requirement 4, a SHOULD) asks for quick adaptation to the initial
    /// conditions and names "probing during setup" as one way; draft-ietf-rmcat-gcc-02 has
    /// none. It is libwebrtc's behaviour, in outline, and adds traffic the application did
    /// not write: padding-only packets on the RTX stream fill a cluster the application's own
    /// media does not (they carry no media, and receivers drop them), so it needs RTX
    /// negotiated to probe a sender with little to send. After a large drop of the target
    /// (a third or more), the rate before it is probed for a few seconds
    /// ([`ProbeController::with_probe_after_drop`](crate::ProbeController::with_probe_after_drop)).
    /// What it costs: an application sending a fifth of what the path carries spends about
    /// 4% of its octets on probes, one cluster every five seconds. The pacer
    /// ([`PacerInterceptor`](crate::PacerInterceptor)) and the NACK responder
    /// ([`NackResponderInterceptor`](crate::NackResponderInterceptor)) of the same chain do
    /// the sending; the estimator hears the result through
    /// [`BandwidthEstimator::on_probe_result`].
    pub fn with_bandwidth_probing(mut self, bandwidth_probing: bool) -> Self {
        self.bandwidth_probing = bandwidth_probing;
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> CongestionControlInterceptor<E> {
        self.build_with_handle().0
    }

    /// Build the interceptor and the handle the application reads the estimate from and gives
    /// the negotiated limits to.
    pub fn build_with_handle(self) -> (CongestionControlInterceptor<E>, CongestionControlHandle) {
        let shared = Arc::new(Mutex::new(Shared {
            target: self.estimator.target_bitrate(),
            stats: self.estimator.stats(),
            ..Shared::default()
        }));
        let probing = self
            .bandwidth_probing
            .then(|| ProbeController::new(self.estimator.target_bitrate(), f64::INFINITY));
        (
            CongestionControlInterceptor {
                tmmbn_owed: false,
                path: None,
                path_candidate: None,
                probing,
                probe_packets: HashMap::new(),
                probe_clusters: HashMap::new(),
                sent: VecDeque::new(),
                last_target: None,
                estimator: self.estimator,
                prune_horizon: self.prune_horizon,
                history: History::new(),
                timeline: FeedbackTimeline::new(),
                streams: HashMap::new(),
                local_ssrcs: Vec::new(),
                tmmbr: TmmbrState::default(),
                remb: None,
                round_trip_time: None,
                departures: VecDeque::new(),
                per_packet_feedback: false,
                applied_max: None,
                unnegotiated_tmmbr: self.unnegotiated_tmmbr,
                circuit_breaker: self.circuit_breaker,
                shared: shared.clone(),
                read_queue: VecDeque::new(),
                write_queue: VecDeque::new(),
            },
            CongestionControlHandle { shared },
        )
    }
}

#[derive(Default)]
struct Shared {
    target: f64,
    stats: EstimatorStats,
    session_max: Option<f64>,
    min: Option<f64>,
    remb: Option<f64>,
    tmmbr: Option<f64>,
    path_changed: bool,
    inputs_changed: bool,
}

fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The application's end of the congestion controller: the estimate, pulled when the encoder
/// wants it, and the limits only the application knows.
///
/// # Inputs from signalling
///
/// The engine's SDP layer does not feed these yet; an application that negotiates them passes
/// them on:
///
/// - `b=AS:<kbit/s>` and `b=TIAS:<bit/s>` of the remote description (RFC 8866 section 5.8,
///   RFC 3890): [`set_session_bitrate_limit`](Self::set_session_bitrate_limit). `b=AS` counts
///   IP and UDP headers, `b=TIAS` does not; the caller converts.
/// - a selected candidate pair change: [`notify_path_change`](Self::notify_path_change).
///
/// TMMBR and REMB arrive as RTCP and are read by the interceptor itself.
#[derive(Clone)]
pub struct CongestionControlHandle {
    shared: Arc<Mutex<Shared>>,
}

impl CongestionControlHandle {
    /// The current target, in bits per second.
    pub fn target_bitrate(&self) -> f64 {
        lock(&self.shared).target
    }

    /// What the estimator says about itself.
    pub fn stats(&self) -> EstimatorStats {
        lock(&self.shared).stats
    }

    /// The bit rate the remote description allows this endpoint to send (`b=AS`, `b=TIAS`), in
    /// bits per second of RTP; `None` when it names none.
    pub fn set_session_bitrate_limit(&self, bits_per_second: Option<f64>) {
        let mut shared = lock(&self.shared);
        shared.session_max = bits_per_second;
        shared.inputs_changed = true;
    }

    /// A floor for the target, in bits per second; `None` leaves the estimator's own.
    pub fn set_min_bitrate(&self, bits_per_second: Option<f64>) {
        let mut shared = lock(&self.shared);
        shared.min = bits_per_second;
        shared.inputs_changed = true;
    }

    /// The network path changed: the estimator starts over from its current target.
    pub fn notify_path_change(&self) {
        lock(&self.shared).path_changed = true;
    }

    /// The limit the receiver's last REMB set, while it is in force.
    pub fn remb_limit(&self) -> Option<f64> {
        lock(&self.shared).remb
    }

    /// The limit the TMMBR bounding set puts on this sender, while there is one.
    pub fn tmmbr_limit(&self) -> Option<f64> {
        lock(&self.shared).tmmbr
    }
}

/// Records every departing packet, resolves the remote's feedback against it, and drives a
/// [`BandwidthEstimator`].
///
/// # Where this belongs in the chain
///
/// **Wire-most.** It is the only position that sees every byte that leaves: nothing exits the chain
/// except through the interceptors ahead of it in the walk, so a retransmission emitted by the NACK
/// responder and a repair packet emitted by the FEC encoder both arrive here, already paced and
/// already numbered. An estimator reading a history that omits them sees fewer bytes than are on
/// the wire, infers headroom, and raises the target during loss — a positive feedback loop that is
/// hard to spot, because the estimator's own accounting stays internally consistent throughout.
///
/// It also has to be **below the pacer**, so `packet.now` is the instant the packet was *released*
/// rather than the instant the application enqueued it. A pacer can hold a packet for tens of
/// milliseconds; counting that as network delay is exactly the error that makes a delay-based
/// estimate collapse.
///
/// # How the estimate gets out
///
/// On the read leg, as [`Attribute::TargetBitrateChanged`]: attached to the feedback packet that
/// produced it, or, when the estimate moved on a timer with no packet to ride on, on an empty
/// RTCP packet, the chain's attribute carrier. The pacer sits application-ward of this
/// interceptor and reads the attribute on its way past. An application pulls the same number
/// from [`CongestionControlHandle`].
///
/// # Limits from outside the algorithm
///
/// The estimator's target is held under the tightest of: the negotiated session bit rate
/// ([`CongestionControlHandle::set_session_bitrate_limit`]), the receiver's REMB, the TMMBR
/// bounding set (RFC 5104; every TMMBR is answered with a TMMBN), and the circuit breaker's
/// reduced rate.
pub struct CongestionControlInterceptor<E: BandwidthEstimator> {
    estimator: E,
    history: History,
    /// The receiver's clock, followed across feedback reports.
    timeline: FeedbackTimeline,
    streams: HashMap<u32, LocalStream>,
    /// Media SSRCs in the order they were bound: the first sends this endpoint's TMMBN.
    local_ssrcs: Vec<u32>,
    tmmbr: TmmbrState,
    /// The last REMB: its bit rate and when it was read.
    remb: Option<(f64, Instant)>,
    /// Smoothed round trip time from feedback.
    round_trip_time: Option<Duration>,
    /// Departure instants of the last second, for the packet rate a TMMBR limit depends on.
    departures: VecDeque<Instant>,
    /// Whether TWCC or RFC 8888 feedback has ever been read.
    per_packet_feedback: bool,
    /// The external maximum last handed to the estimator.
    applied_max: Option<Option<f64>>,
    /// Whether a TMMBR limits a stream that did not negotiate `ccm tmmbr`.
    unnegotiated_tmmbr: bool,
    /// Whether the compound packet being read asks for a TMMBN.
    tmmbn_owed: bool,
    /// The addresses inbound packets arrive between: the path, as far as this interceptor
    /// can see it.
    path: Option<PathKey>,
    /// A different pair of addresses, and how many packets in a row arrived on it.
    path_candidate: Option<(PathKey, u8)>,
    /// Bandwidth probing, when it is on.
    probing: Option<ProbeController>,
    /// The packets that left as part of a probe cluster and await their report: SSRC and RTP
    /// sequence number to cluster.
    probe_packets: HashMap<(u32, u16), u32>,
    /// What is known of each cluster in flight.
    probe_clusters: HashMap<u32, ProbeCluster>,
    /// Departures of the last second with their sizes, for the rate being sent.
    sent: VecDeque<(Instant, usize)>,
    circuit_breaker: Option<CircuitBreakerHandle>,
    shared: Arc<Mutex<Shared>>,
    prune_horizon: Duration,
    /// The last target handed onward, so an unchanged estimate does not re-announce itself.
    /// `None` until the first one has been announced: the pacer has to learn the estimator's
    /// starting rate too, not only its changes.
    last_target: Option<f64>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl<E: BandwidthEstimator> CongestionControlInterceptor<E> {
    /// The estimator, for reading its stats.
    pub fn estimator(&self) -> &E {
        &self.estimator
    }

    /// How many TWCC feedback packets the receiver sent that never arrived here, by the gaps
    /// in the feedback packet count.
    pub fn lost_feedback(&self) -> u64 {
        self.history.lost_feedback()
    }

    /// How many sent packets are still awaiting a verdict.
    pub fn outstanding(&self) -> usize {
        self.history.len()
    }

    /// The transport-wide sequence number the TWCC sender wrote, if this stream carries one.
    ///
    /// The sender sits between the pacer and here, so by the time a packet arrives the number is
    /// already in its header — which is the whole reason this interceptor is wire-most rather than
    /// the sender being.
    fn twcc_sequence_number(&self, rtp_packet: &rtp::Packet) -> Option<u16> {
        let stream = self.streams.get(&rtp_packet.header.ssrc)?;
        let mut extension = rtp_packet.header.get_extension(stream.hdr_ext_id)?;
        rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(&mut extension)
            .ok()
            .map(|extension| extension.transport_sequence)
    }

    /// RTP packets per second over the last second.
    fn packet_rate(&mut self, now: Instant) -> f64 {
        while let Some(at) = self.departures.front() {
            if now.saturating_duration_since(*at) <= Duration::from_secs(1) {
                break;
            }
            self.departures.pop_front();
        }
        self.departures.len() as f64
    }

    fn note_round_trip_time(&mut self, now: Instant, sample: Duration) {
        let smoothed = match self.round_trip_time {
            Some(previous) => previous.mul_f64(0.8) + sample.mul_f64(0.2),
            None => sample,
        };
        self.round_trip_time = Some(smoothed);
        self.estimator.on_round_trip_time(now, smoothed);
        if let Some(breaker) = &self.circuit_breaker {
            breaker.report_round_trip_time(smoothed);
        }
    }

    /// Queue a TMMBN with the current bounding set (RFC 5104 section 4.2.2.2).
    fn send_tmmbn(&mut self, now: Instant) {
        let Some(sender_ssrc) = self.local_ssrcs.first().copied() else {
            return;
        };
        let notification = TemporaryMaximumBitrateNotification {
            sender_ssrc,
            entries: self
                .tmmbr
                .bounding()
                .iter()
                .map(|tuple| {
                    rtcp::transport_feedbacks::tmmb::TmmbEntry::new(
                        tuple.ssrc,
                        tuple.bitrate,
                        tuple.overhead,
                    )
                })
                .collect(),
        };
        self.write_queue.push_back(TaggedPacket {
            now,
            transport: shared::TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(notification)])),
        });
    }

    /// Feed one inbound RTCP packet to the history and the limits. Returns whether it was
    /// per-packet feedback.
    #[allow(clippy::borrowed_box)]
    fn ingest(&mut self, now: Instant, rtcp_packet: &Box<dyn rtcp::Packet>) -> bool {
        let payload = rtcp_packet.as_any();

        if let Some(feedback) = payload
            .downcast_ref::<rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc>(
        ) {
            self.history.on_twcc_feedback_count(feedback.fb_pkt_count);
            let mut round_trip: Option<Duration> = None;
            for acknowledgement in self.timeline.convert_twcc(feedback) {
                if let Some(rtt) = self.history.on_twcc_feedback(now, acknowledgement)
                    && acknowledgement.arrived
                {
                    round_trip = Some(round_trip.map_or(rtt, |best| best.min(rtt)));
                }
            }
            if let Some(rtt) = round_trip {
                self.note_round_trip_time(now, rtt);
            }
            self.tmmbr.on_owner_seen(now, feedback.sender_ssrc);
            return true;
        }

        if let Some(feedback) = payload
            .downcast_ref::<rtcp::transport_feedbacks::cc_feedback_report::CcFeedbackReport>(
        ) {
            let (report_delay, per_stream) = self.timeline.convert_ccfb(feedback);
            let mut round_trip: Option<Duration> = None;
            for (ssrc, acknowledgements) in per_stream {
                // A stream that runs on transport-wide feedback is not also read from RFC 8888
                // reports: the estimator would count each of its packets twice.
                if self.streams.get(&ssrc).is_some_and(|stream| {
                    stream.feedback == Some(CongestionFeedbackFormat::TransportCc)
                }) {
                    continue;
                }
                for acknowledgement in acknowledgements {
                    if let Some(rtt) = self.history.on_ccfb_feedback(now, ssrc, acknowledgement)
                        && acknowledgement.arrived
                    {
                        round_trip = Some(round_trip.map_or(rtt, |best| best.min(rtt)));
                    }
                }
            }
            if let Some(rtt) = round_trip {
                // The receiver held the report for `report_delay` after the newest arrival.
                self.note_round_trip_time(now, rtt.saturating_sub(report_delay));
            }
            self.tmmbr.on_owner_seen(now, feedback.sender_ssrc);
            return true;
        }

        // REMB: the receiver's own estimate bounds the sender's (draft-ietf-rmcat-gcc-02
        // sections 3 and 6).
        if let Some(remb) = payload.downcast_ref::<rtcp::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate>() {
            let ours = remb.ssrcs.is_empty()
                || remb.ssrcs.iter().any(|ssrc| self.streams.contains_key(ssrc));
            if ours && remb.bitrate.is_finite() && remb.bitrate >= 0.0 {
                self.remb = Some((f64::from(remb.bitrate), now));
            }
            self.tmmbr.on_owner_seen(now, remb.sender_ssrc);
            return false;
        }

        // TMMBR (RFC 5104 section 4.2.1): the typed packet, or the same bytes handed over raw.
        let request =
            if let Some(request) = payload.downcast_ref::<TemporaryMaximumBitrateRequest>() {
                Some(tmmbr::TmmbPacket {
                    fmt: tmmbr::FMT_TMMBR,
                    sender_ssrc: request.sender_ssrc,
                    entries: request
                        .entries
                        .iter()
                        .map(|entry| tmmbr::TmmbEntry {
                            ssrc: entry.ssrc,
                            bitrate: entry.bitrate(),
                            overhead: entry.measured_overhead,
                        })
                        .collect(),
                })
            } else {
                payload
                    .downcast_ref::<rtcp::raw_packet::RawPacket>()
                    .and_then(|raw| tmmbr::parse(&raw.0))
                    .filter(|packet| packet.fmt == tmmbr::FMT_TMMBR)
            };
        if let Some(packet) = request {
            let packet_rate = self.packet_rate(now);
            let round_trip_time = self.round_trip_time.unwrap_or_default();
            let mut owed = false;
            for entry in packet.entries {
                // An entry is for the media sender its SSRC names, and binds it only when the
                // session negotiated the message for that stream (RFC 5104 section 7.1).
                if self
                    .streams
                    .get(&entry.ssrc)
                    .is_some_and(|stream| stream.tmmbr || self.unnegotiated_tmmbr)
                {
                    owed |= self.tmmbr.on_request(
                        now,
                        packet.sender_ssrc,
                        entry,
                        packet_rate,
                        round_trip_time,
                    );
                }
            }
            // One TMMBN for the compound packet, however many TMMBRs and entries it had, and
            // whether or not the bounding set changed (RFC 5104 section 4.2.2.2: "only a
            // single TMMBN SHALL be sent, even if more than one TMMBR is received").
            self.tmmbn_owed |= owed;
            return false;
        }

        if let Some(bye) = payload.downcast_ref::<rtcp::goodbye::Goodbye>() {
            let packet_rate = self.packet_rate(now);
            let round_trip_time = self.round_trip_time.unwrap_or_default();
            let mut owed = false;
            for source in &bye.sources {
                owed |= self
                    .tmmbr
                    .on_owner_left(now, *source, packet_rate, round_trip_time);
            }
            self.tmmbn_owed |= owed;
            return false;
        }

        // Receiver reports: the loss-based controller's input while the receiver sends no
        // per-packet feedback (draft-ietf-rmcat-gcc-02 section 7).
        let reports =
            if let Some(rr) = payload.downcast_ref::<rtcp::receiver_report::ReceiverReport>() {
                self.tmmbr.on_owner_seen(now, rr.ssrc);
                Some(&rr.reports)
            } else if let Some(sr) = payload.downcast_ref::<rtcp::sender_report::SenderReport>() {
                self.tmmbr.on_owner_seen(now, sr.ssrc);
                Some(&sr.reports)
            } else {
                None
            };
        if let Some(reports) = reports
            && !self.per_packet_feedback
        {
            for report in reports {
                if self.streams.contains_key(&report.ssrc) {
                    self.estimator
                        .on_receiver_report(now, f64::from(report.fraction_lost) / 256.0);
                }
            }
        }

        false
    }

    /// Hand the estimator the tightest of the outside limits, when it changed.
    fn apply_bounds(&mut self, now: Instant) {
        if let Some((_, at)) = self.remb
            && now.saturating_duration_since(at) >= REMB_TIMEOUT
        {
            self.remb = None;
        }
        let remb = self.remb.map(|(bitrate, _)| bitrate);
        let tmmbr = self.tmmbr.limit();
        let breaker = self
            .circuit_breaker
            .as_ref()
            .and_then(CircuitBreakerHandle::rate_limit);

        let (session, min, inputs_changed, path_changed) = {
            let mut shared = lock(&self.shared);
            shared.remb = remb;
            shared.tmmbr = tmmbr;
            (
                shared.session_max,
                shared.min,
                std::mem::take(&mut shared.inputs_changed),
                std::mem::take(&mut shared.path_changed),
            )
        };
        if path_changed {
            self.estimator.on_path_change(now);
        }

        let max = [session, remb, tmmbr, breaker]
            .into_iter()
            .flatten()
            .reduce(f64::min);
        if inputs_changed || self.applied_max != Some(max) {
            self.applied_max = Some(max);
            self.estimator.set_external_bounds(min, max);
        }
    }

    /// Follows the addresses inbound packets arrive between, and tells the estimator when
    /// they change (RFC 8836 section 2, requirement 1: a congestion controller reacts to a
    /// change of the path, and "the application may be able to notify it").
    ///
    /// The peer connection moves to another candidate pair without this interceptor being
    /// told, but every inbound packet carries the pair it arrived on. A new local or remote
    /// address is a new path in at least one direction, and what was measured on the old one
    /// (its delay gradient, where its capacity was) describes nothing any more.
    fn observe_path(&mut self, now: Instant, transport: &shared::TransportContext) {
        let key = (
            transport.local_addr,
            transport.peer_addr,
            transport.transport_protocol,
        );
        let Some(current) = self.path else {
            self.path = Some(key);
            return;
        };
        if key == current {
            self.path_candidate = None;
            return;
        }
        let seen = match self.path_candidate {
            Some((candidate, seen)) if candidate == key => seen + 1,
            _ => 1,
        };
        if seen >= PATH_CHANGE_PACKETS {
            self.path = Some(key);
            self.path_candidate = None;
            self.estimator.on_path_change(now);
        } else {
            self.path_candidate = Some((key, seen));
        }
    }

    /// Bits per second sent over the last second.
    fn sending_rate(&mut self, now: Instant) -> f64 {
        while let Some((at, _)) = self.sent.front() {
            if now.saturating_duration_since(*at) <= Duration::from_secs(1) {
                break;
            }
            self.sent.pop_front();
        }
        self.sent.iter().map(|(_, size)| *size as f64 * 8.0).sum()
    }

    /// Sorts the reports of probe packets into their clusters, and gives the estimator the
    /// result of every cluster that has been reported in full.
    fn collect_probe_reports(&mut self, now: Instant, reports: &[PacketReport]) {
        if self.probing.is_none() {
            return;
        }
        for report in reports {
            if let Some(cluster) = self
                .probe_packets
                .remove(&(report.ssrc, report.rtp_sequence_number))
                && let Some(state) = self.probe_clusters.get_mut(&cluster)
            {
                state.reports.push(report.clone());
            }
        }
        let complete: Vec<u32> = self
            .probe_clusters
            .iter()
            .filter(|(_, state)| state.closed(now) && state.reports.len() >= state.sent)
            .map(|(cluster, _)| *cluster)
            .collect();
        for cluster in complete {
            let Some(state) = self.probe_clusters.remove(&cluster) else {
                continue;
            };
            if let Some(estimate) = probe_estimate(&state.reports)
                && let Some(probing) = self.probing.as_mut()
                && let Some(estimate) = probing.on_result(cluster, estimate)
            {
                self.estimator.on_probe_result(now, estimate);
            }
        }
        // A cluster whose packets were never all reported is forgotten with its packets.
        self.probe_clusters
            .retain(|_, state| now.saturating_duration_since(state.last_sent) < PROBE_FORGET);
        if self.probe_clusters.is_empty() {
            self.probe_packets.clear();
        }
    }

    /// Asks for the next probe cluster when one is due: the request leaves on the read leg,
    /// towards the pacer and the NACK responder.
    fn poll_probe(&mut self, now: Instant) {
        if self.probing.is_none() {
            return;
        }
        let target = self.estimator.target_bitrate();
        let sending = self.sending_rate(now);
        let media_flowing = !self.sent.is_empty();
        let max = self.applied_max.flatten().unwrap_or(f64::INFINITY);
        let Some(probing) = self.probing.as_mut() else {
            return;
        };
        probing.set_max_bitrate(max);
        if let Some(request) = probing.poll(now, target, sending, media_flowing) {
            self.read_queue.push_back(request.into_packet(now));
        }
    }

    /// Publish the estimate, and return the attribute to announce when it moved.
    fn publish(&mut self) -> Option<Attribute> {
        let target = self.estimator.target_bitrate();
        {
            let mut shared = lock(&self.shared);
            shared.target = target;
            shared.stats = self.estimator.stats();
        }
        if self.last_target == Some(target) {
            return None;
        }
        self.last_target = Some(target);
        Some(Attribute::TargetBitrateChanged {
            bits_per_second: target,
        })
    }
}

impl<E: BandwidthEstimator> Protocol<TaggedPacket, TaggedPacket, ()>
    for CongestionControlInterceptor<E>
{
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        // A packet from the wire, not one of the chain's attribute carriers (an empty RTCP
        // packet, which never had an address).
        if !matches!(&msg.message.packet, Packet::Rtcp(packets) if packets.is_empty()) {
            self.observe_path(msg.now, &msg.transport);
        }
        let mut reported = false;
        if let Packet::Rtcp(ref rtcp_packets) = msg.message.packet {
            // `for` over a borrow of `msg` while `self` is borrowed mutably: collect first.
            let feedback: Vec<_> = rtcp_packets.to_vec();
            for rtcp_packet in &feedback {
                reported |= self.ingest(msg.now, rtcp_packet);
            }
        }
        if std::mem::take(&mut self.tmmbn_owed) {
            self.send_tmmbn(msg.now);
        }

        if reported {
            self.per_packet_feedback = true;
            let reports = self.history.take_reports();
            self.estimator.on_reports(msg.now, &reports);
            self.collect_probe_reports(msg.now, &reports);
        }
        self.apply_bounds(msg.now);

        // Announced on a change, and once at the start on whatever inbound packet comes first:
        // a pacer that only ever heard about changes would run at its own default until the
        // estimate first moved, which with no feedback yet is exactly when the estimator's
        // cautious starting rate matters.
        //
        // Onto *this* packet: the pacer is application-ward of here, so it sees this packet
        // after this interceptor does and reads the attribute on its way past.
        if let Some(attribute) = self.publish() {
            msg.message.add(attribute);
        }

        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(ref rtp_packet) = msg.message.packet {
            let twcc_sequence_number = self.twcc_sequence_number(rtp_packet);
            // Only a stream this endpoint is sending is tracked; anything else has no sequence
            // space the remote will report against.
            if self.streams.contains_key(&rtp_packet.header.ssrc) {
                let size = rtp_packet.marshal_size();
                self.history.add_outgoing(
                    rtp_packet.header.ssrc,
                    rtp_packet.header.sequence_number,
                    twcc_sequence_number.is_some(),
                    twcc_sequence_number.unwrap_or_default(),
                    size,
                    // The release instant. The pacer has already run on this leg — recording the
                    // enqueue instant instead would charge its queueing delay to the network.
                    msg.now,
                );
                self.departures.push_back(msg.now);
                if self.departures.len() > 4096 {
                    self.departures.pop_front();
                }
                self.estimator.on_packet_sent(msg.now, size);

                if self.probing.is_some() {
                    self.sent.push_back((msg.now, size));
                    if self.sent.len() > 4096 {
                        self.sent.pop_front();
                    }
                    // The pacer marked it as part of a cluster: its report is the cluster's.
                    if let Some(probe) = msg.message.custom::<ProbePacket>() {
                        self.probe_packets.insert(
                            (rtp_packet.header.ssrc, rtp_packet.header.sequence_number),
                            probe.cluster,
                        );
                        let state = self
                            .probe_clusters
                            .entry(probe.cluster)
                            .or_insert_with(|| ProbeCluster::new(msg.now));
                        state.sent += 1;
                        state.last_sent = msg.now;
                    }
                }
            }
        }
        if matches!(msg.message.packet, Packet::Rtp(_)) {
            self.poll_probe(msg.now);
        }

        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
        self.history
            .prune_before(now.checked_sub(self.prune_horizon).unwrap_or(now));

        let packet_rate = self.packet_rate(now);
        let round_trip_time = self.round_trip_time.unwrap_or_default();
        if self.tmmbr.on_timeout(now, packet_rate, round_trip_time) {
            // An owner timed out: the bounding set changed and the session is told.
            self.send_tmmbn(now);
        }

        self.estimator.handle_timeout(now);
        self.apply_bounds(now);
        self.poll_probe(now);

        // No packet to ride on: the estimate leaves on the chain's attribute carrier.
        if let Some(attribute) = self.publish() {
            self.read_queue.push_back(TaggedPacket {
                now,
                transport: shared::TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(Vec::new())).with(attribute),
            });
        }
        Ok(())
    }

    /// Whatever the estimator and the outside limits want, and `None` when they want nothing.
    ///
    /// This interceptor has no timer of its own: pruning is bounded work that can ride any wake-up,
    /// and asking for one on its own account would wake the whole chain on an idle connection.
    fn poll_timeout(&mut self) -> Option<Self::Time> {
        [
            self.estimator.poll_timeout(),
            self.tmmbr.poll_timeout(),
            self.remb.map(|(_, at)| at + REMB_TIMEOUT),
            self.probing
                .as_ref()
                .and_then(ProbeController::poll_timeout),
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

impl<E: BandwidthEstimator> Interceptor for CongestionControlInterceptor<E> {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        // Tracked whether or not it negotiated transport-wide CC: RFC 8888 reports against the RTP
        // sequence number and needs no extension, so a stream without one is still worth recording.
        // The retransmission and FEC SSRCs are recorded with the media SSRC: their packets are
        // bytes on the same path, and a history without them reads the path as carrying less
        // than it does.
        // One feedback format per stream (RFC 8888 section 6): with RFC 8888 negotiated the
        // TWCC sender does not number the stream, and no number is looked for.
        let feedback = negotiated_congestion_feedback(info);
        let tmmbr = stream_negotiated_tmmbr(info);
        let hdr_ext_id = if feedback == Some(CongestionFeedbackFormat::TransportCc) {
            stream_supports_twcc(info).unwrap_or_default()
        } else {
            0
        };
        for ssrc in flow_ssrcs(info) {
            self.streams.insert(
                ssrc,
                LocalStream {
                    hdr_ext_id,
                    feedback,
                    tmmbr,
                },
            );
        }
        if !self.local_ssrcs.contains(&info.ssrc) {
            self.local_ssrcs.push(info.ssrc);
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        for ssrc in flow_ssrcs(info) {
            self.streams.remove(&ssrc);
        }
        self.local_ssrcs.retain(|ssrc| *ssrc != info.ssrc);
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}
