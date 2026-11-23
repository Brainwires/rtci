//! RTCP Extended Reports about received streams (RFC 3611 section 4): the unilateral report
//! blocks a receiver sends about each source it hears.
//!
//! [`XrReportInterceptor`] watches the RTP that arrives on every bound remote stream and, on an
//! interval, writes an XR packet with the blocks the stream asked for: Loss RLE (4.1),
//! Duplicate RLE (4.2), Packet Receipt Times (4.3), Statistics Summary (4.6) and VoIP Metrics
//! (4.7). The RTCP session puts it in its next compound packet.
//!
//! Which blocks a stream gets is what was negotiated for it with `a=rtcp-xr` (RFC 3611
//! section 5.1): the stream's RTCP feedback carries each unilateral `xr-format` as an entry of
//! type [`RTCP_FB_XR`] whose parameter is the format as signalled (`pkt-loss-rle`,
//! `pkt-loss-rle=200`, `stat-summary=loss,dup,jitt`, `voip-metrics` ...). A stream with no such
//! entry gets no block (section 5.1: "participants SHOULD NOT send XR blocks other than the
//! ones indicated"). [`XrReportBuilder::with_formats`] sends blocks without negotiation, for an
//! application that agreed on them some other way.
//!
//! The round-trip pair (receiver reference time and DLRR, sections 4.4 and 4.5) is the RTCP
//! session's.

pub(crate) mod burst;
pub(crate) mod sequence;

use crate::rfc8888::sender::random_ssrc;
use crate::rtcp_session::RtcpSessionEvent;
use crate::stream_info::StreamInfo;
use crate::{AttributedPacket, Interceptor, Packet, TaggedPacket};
use burst::BurstGapModel;
use rtcp::extended_report::{
    ExtendedReport, PacketReceiptTimesReportBlock, RLEReportBlock, StatisticsSummaryReportBlock,
    TTLorHopLimitType, VoIPMetricsReportBlock, reported_sequence_numbers,
};
use sansio::Protocol;
use sequence::SequenceExtender;
use shared::TransportContext;
use shared::error::Error;
use shared::marshal::MarshalSize;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

/// The RTCP feedback type a stream's negotiated `a=rtcp-xr` unilateral formats arrive under
/// (one entry per format, the format as its parameter).
pub const RTCP_FB_XR: &str = "xr";

/// How often the blocks are written when no interval is configured: about once per regular
/// RTCP report of a video session.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);

/// The Gmin of the VoIP Metrics burst model (RFC 3611 section 4.7.2 recommends 16).
pub const DEFAULT_GMIN: u8 = 16;

/// The largest sequence-number range one block reports on (RFC 3611 section 4.1: "MUST NOT
/// report on a sequence number range of 65,534 or more").
const MAX_RANGE: u64 = 65_533;

/// The jitter buffer the application plays a stream out of, for the VoIP Metrics block (RFC
/// 3611 section 4.7.7). The engine does not play media out, so it cannot know these itself.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JitterBufferMetrics {
    /// Adaptive (`Some(true)`), fixed (`Some(false)`) or not known (`None`).
    pub adaptive: Option<bool>,
    /// The jitter buffer rate, 0 to 15 (section 4.7.6, JB rate).
    pub rate: u8,
    /// Nominal delay in milliseconds.
    pub nominal_ms: u16,
    /// Maximum delay in milliseconds.
    pub maximum_ms: u16,
    /// Absolute maximum delay in milliseconds.
    pub absolute_maximum_ms: u16,
}

/// What a stream's negotiated XR formats ask for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct XrFormats {
    /// Loss RLE, with the largest size of the block in octets when one was given.
    pub(crate) loss_rle: Option<Option<usize>>,
    /// Duplicate RLE, with its largest size.
    pub(crate) duplicate_rle: Option<Option<usize>>,
    /// Packet Receipt Times, with its largest size.
    pub(crate) receipt_times: Option<Option<usize>>,
    /// Statistics Summary, with the fields asked for.
    pub(crate) statistics: Option<StatisticsFields>,
    /// VoIP Metrics.
    pub(crate) voip_metrics: bool,
}

/// The fields `stat-summary=` lists (RFC 3611 section 5.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct StatisticsFields {
    pub(crate) loss: bool,
    pub(crate) duplicates: bool,
    pub(crate) jitter: bool,
    /// `TTL` or `HL` was listed. Neither can be measured here (the IP header is the
    /// application's socket's), so the block says the fields are not reported.
    pub(crate) ttl_or_hop_limit: bool,
}

impl XrFormats {
    /// The formats named in `formats` (each an `xr-format` as signalled).
    pub(crate) fn parse<'a>(formats: impl IntoIterator<Item = &'a str>) -> Self {
        let mut out = XrFormats::default();
        for format in formats {
            let (name, value) = match format.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (format, None),
            };
            let size = || value.and_then(|v| v.parse::<usize>().ok());
            match name {
                "pkt-loss-rle" => out.loss_rle = Some(size()),
                "pkt-dup-rle" => out.duplicate_rle = Some(size()),
                "pkt-rcpt-times" => out.receipt_times = Some(size()),
                "stat-summary" => {
                    let mut fields = StatisticsFields::default();
                    for field in value.unwrap_or_default().split(',') {
                        match field {
                            "loss" => fields.loss = true,
                            "dup" => fields.duplicates = true,
                            "jitt" => fields.jitter = true,
                            "TTL" | "HL" => fields.ttl_or_hop_limit = true,
                            _ => {}
                        }
                    }
                    out.statistics = Some(fields);
                }
                "voip-metrics" => out.voip_metrics = true,
                _ => {}
            }
        }
        out
    }

    /// The formats a stream negotiated: its [`RTCP_FB_XR`] feedback entries.
    pub(crate) fn of_stream(info: &StreamInfo) -> Self {
        Self::parse(
            info.rtcp_feedback
                .iter()
                .filter(|feedback| feedback.typ == RTCP_FB_XR)
                .map(|feedback| feedback.parameter.as_str()),
        )
    }

    fn any(&self) -> bool {
        self.loss_rle.is_some()
            || self.duplicate_rle.is_some()
            || self.receipt_times.is_some()
            || self.statistics.is_some()
            || self.voip_metrics
    }
}

/// Builder for [`XrReportInterceptor`].
///
/// ```
/// use rtc_interceptor::{Registry, Slot, XrReportBuilder};
///
/// let chain = Registry::new()
///     .with(Slot::ExtendedReports, XrReportBuilder::new().build())
///     .build();
/// # let _ = chain;
/// ```
#[derive(Debug, Clone)]
pub struct XrReportBuilder {
    interval: Duration,
    formats: Option<Vec<String>>,
    gmin: u8,
    jitter_buffer: JitterBufferMetrics,
    sender_ssrc: Option<u32>,
}

impl Default for XrReportBuilder {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
            formats: None,
            gmin: DEFAULT_GMIN,
            jitter_buffer: JitterBufferMetrics::default(),
            sender_ssrc: None,
        }
    }
}

impl XrReportBuilder {
    /// A builder with the defaults: one report a second, blocks as negotiated, Gmin 16.
    pub fn new() -> Self {
        Self::default()
    }

    /// How often the blocks are written.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Send these `xr-format`s for every remote stream, whatever was negotiated (RFC 3611
    /// section 5.1 allows blocks agreed on outside the signalling).
    pub fn with_formats<S: Into<String>>(mut self, formats: impl IntoIterator<Item = S>) -> Self {
        self.formats = Some(formats.into_iter().map(Into::into).collect());
        self
    }

    /// The Gmin of the burst model (RFC 3611 section 4.7.2). 0 is taken as the default 16
    /// (section 4.7.6: "Gmin MUST NOT be zero").
    pub fn with_gmin(mut self, gmin: u8) -> Self {
        self.gmin = if gmin == 0 { DEFAULT_GMIN } else { gmin };
        self
    }

    /// The application's jitter buffer, reported in the VoIP Metrics block.
    pub fn with_jitter_buffer(mut self, jitter_buffer: JitterBufferMetrics) -> Self {
        self.jitter_buffer = jitter_buffer;
        self
    }

    /// The SSRC the reports are sent from. Left unset: the first local stream's, or a random
    /// one while there is none.
    pub fn with_sender_ssrc(mut self, ssrc: u32) -> Self {
        self.sender_ssrc = Some(ssrc);
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> XrReportInterceptor {
        XrReportInterceptor {
            interval: self.interval,
            formats: self
                .formats
                .map(|f| XrFormats::parse(f.iter().map(String::as_str))),
            gmin: self.gmin,
            jitter_buffer: self.jitter_buffer,
            configured_ssrc: self.sender_ssrc,
            receiver_ssrc: random_ssrc(),
            local_ssrcs: vec![],
            streams: HashMap::new(),
            round_trip: None,
            next_timeout: None,
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

/// One packet of an interval, by extended sequence number.
#[derive(Debug, Clone, Copy)]
struct Arrival {
    /// When the first copy arrived (RFC 3611 4.3: "any time other than the earliest MUST NOT
    /// be reported").
    first: Instant,
    /// Copies received.
    copies: u32,
}

/// What is known about one remote stream.
#[derive(Debug)]
struct RemoteStream {
    formats: XrFormats,
    clock_rate: u32,
    sequence: SequenceExtender,
    /// The first extended sequence number the next blocks report on.
    begin: Option<u64>,
    /// The packets of the current interval.
    arrivals: BTreeMap<u64, Arrival>,
    /// Relative transit times between consecutive packets of the interval, in timestamp
    /// units (RFC 3611 4.6).
    transit_differences: Vec<u32>,
    /// The previous packet's (arrival, RTP timestamp), for the transit difference.
    previous: Option<(Instant, u32)>,
    /// Where receipt times start: the first arrival and a random RTP-timestamp-unit offset
    /// (RFC 3611 4.3: "the first receipt time value SHOULD also be chosen at random").
    receipt_origin: Option<(Instant, u32)>,
    /// Since the beginning of reception (RFC 3611 4.7.1, 4.7.2).
    expected_total: u64,
    lost_total: u64,
    burst: BurstGapModel,
    /// Timestamp increments between consecutive packets, for the packet duration the burst
    /// and gap durations are counted in.
    timestamp_step_sum: u64,
    timestamp_steps: u64,
    previous_in_order: Option<(u64, u32)>,
}

impl RemoteStream {
    fn new(formats: XrFormats, clock_rate: u32, gmin: u8) -> Self {
        Self {
            formats,
            clock_rate: clock_rate.max(1),
            sequence: SequenceExtender::default(),
            begin: None,
            arrivals: BTreeMap::new(),
            transit_differences: vec![],
            previous: None,
            receipt_origin: None,
            expected_total: 0,
            lost_total: 0,
            burst: BurstGapModel::new(gmin),
            timestamp_step_sum: 0,
            timestamp_steps: 0,
            previous_in_order: None,
        }
    }

    fn ticks(&self, duration: Duration) -> u64 {
        (duration.as_secs_f64() * f64::from(self.clock_rate)).round() as u64
    }

    fn on_packet(&mut self, now: Instant, sequence_number: u16, timestamp: u32) {
        let extended = self.sequence.extend(sequence_number);
        if self.receipt_origin.is_none() {
            self.receipt_origin = Some((now, rand::random()));
        }
        match self.begin {
            None => self.begin = Some(extended),
            // Older than what the last blocks covered: already reported on, so a late copy
            // counts for nothing new.
            Some(begin) if extended < begin => return,
            _ => {}
        }
        let arrival = self.arrivals.entry(extended).or_insert(Arrival {
            first: now,
            copies: 0,
        });
        arrival.copies += 1;
        if arrival.copies > 1 {
            return;
        }
        if let Some((at, previous_timestamp)) = self.previous {
            // RFC 3550 6.4.1: D(i,j) = (Rj - Ri) - (Sj - Si), in timestamp units.
            let arrival_ticks = self.ticks(now.saturating_duration_since(at)) as i64;
            let sent_ticks = i64::from(timestamp.wrapping_sub(previous_timestamp) as i32);
            let difference = (arrival_ticks - sent_ticks).unsigned_abs();
            self.transit_differences
                .push(difference.min(u64::from(u32::MAX)) as u32);
        }
        self.previous = Some((now, timestamp));
        if let Some((previous_extended, previous_timestamp)) = self.previous_in_order
            && extended == previous_extended + 1
        {
            self.timestamp_step_sum += u64::from(timestamp.wrapping_sub(previous_timestamp));
            self.timestamp_steps += 1;
        }
        if self
            .previous_in_order
            .is_none_or(|(previous_extended, _)| extended > previous_extended)
        {
            self.previous_in_order = Some((extended, timestamp));
        }
    }

    /// The duration of one packet in milliseconds, from the RTP timestamps (RFC 3611 4.7.2:
    /// "if the actual values are not available, estimated values MUST be used").
    fn packet_duration_ms(&self) -> f64 {
        if self.timestamp_steps == 0 {
            return 20.0;
        }
        let ticks = self.timestamp_step_sum as f64 / self.timestamp_steps as f64;
        ticks * 1000.0 / f64::from(self.clock_rate)
    }

    fn receipt_time(&self, at: Instant) -> u32 {
        let (origin, offset) = self.receipt_origin.expect("set with the first packet");
        offset.wrapping_add(self.ticks(at.saturating_duration_since(origin)) as u32)
    }
}

/// Writes RFC 3611 report blocks about the remote streams that asked for them.
pub struct XrReportInterceptor {
    interval: Duration,
    formats: Option<XrFormats>,
    gmin: u8,
    jitter_buffer: JitterBufferMetrics,
    configured_ssrc: Option<u32>,
    receiver_ssrc: u32,
    local_ssrcs: Vec<u32>,
    streams: HashMap<u32, RemoteStream>,
    /// The most recent round trip time the RTCP session measured.
    round_trip: Option<Duration>,
    next_timeout: Option<Instant>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl XrReportInterceptor {
    /// The SSRC the reports are sent from.
    pub fn sender_ssrc(&self) -> u32 {
        self.configured_ssrc
            .or_else(|| self.local_ssrcs.first().copied())
            .unwrap_or(self.receiver_ssrc)
    }

    fn arm(&mut self, now: Instant) {
        if self.next_timeout.is_none() && !self.streams.is_empty() {
            self.next_timeout = Some(now + self.interval);
        }
    }

    /// The blocks about `ssrc` for the interval that ends now.
    fn blocks(&mut self, ssrc: u32) -> Vec<Box<dyn rtcp::Packet>> {
        let jitter_buffer = self.jitter_buffer;
        let round_trip = self.round_trip;
        let gmin = self.gmin;
        let Some(stream) = self.streams.get_mut(&ssrc) else {
            return vec![];
        };
        let (Some(begin), Some(&last)) = (stream.begin, stream.arrivals.keys().next_back()) else {
            return vec![];
        };
        // RFC 3611 4.1: one block reports on fewer than 65,534 sequence numbers; what is
        // older than that is left out.
        let begin = begin.max((last + 1).saturating_sub(MAX_RANGE));
        let end = last + 1;
        let range: Vec<u64> = (begin..end).collect();
        let begin_seq = begin as u16;
        let end_seq = end as u16;
        let received: Vec<bool> = range
            .iter()
            .map(|seq| stream.arrivals.contains_key(seq))
            .collect();
        let lost = received.iter().filter(|r| !**r).count() as u64;
        let duplicates: u64 = stream
            .arrivals
            .range(begin..end)
            .map(|(_, a)| u64::from(a.copies - 1))
            .sum();

        stream.expected_total += range.len() as u64;
        stream.lost_total += lost;
        for flag in &received {
            stream.burst.observe(!*flag, false);
        }

        let mut blocks: Vec<Box<dyn rtcp::Packet>> = vec![];
        if let Some(limit) = stream.formats.loss_rle {
            blocks.push(Box::new(rle_block(true, ssrc, begin, end, limit, &|seq| {
                stream.arrivals.contains_key(&seq)
            })));
        }
        if let Some(limit) = stream.formats.duplicate_rle {
            blocks.push(Box::new(rle_block(
                false,
                ssrc,
                begin,
                end,
                limit,
                &|seq| stream.arrivals.get(&seq).is_some_and(|a| a.copies > 1),
            )));
        }
        if let Some(limit) = stream.formats.receipt_times {
            // RFC 3611 4.3: "At least one packet MUST have been received for each sequence
            // number reported upon in this block": one block per run of received packets.
            let mut run: Vec<(u64, Instant)> = vec![];
            let mut runs: Vec<Vec<(u64, Instant)>> = vec![];
            for seq in begin..end {
                match stream.arrivals.get(&seq) {
                    Some(arrival) => run.push((seq, arrival.first)),
                    None if !run.is_empty() => runs.push(std::mem::take(&mut run)),
                    None => {}
                }
            }
            if !run.is_empty() {
                runs.push(run);
            }
            for run in runs {
                blocks.push(Box::new(receipt_times_block(stream, ssrc, &run, limit)));
            }
        }
        if let Some(fields) = stream.formats.statistics {
            let differences = &stream.transit_differences;
            let (min, max, mean, dev) = if differences.is_empty() {
                (0, 0, 0, 0)
            } else {
                let n = differences.len() as f64;
                let mean = differences.iter().map(|d| f64::from(*d)).sum::<f64>() / n;
                let variance = differences
                    .iter()
                    .map(|d| (f64::from(*d) - mean).powi(2))
                    .sum::<f64>()
                    / n;
                (
                    *differences.iter().min().expect("not empty"),
                    *differences.iter().max().expect("not empty"),
                    mean.round() as u32,
                    variance.sqrt().round() as u32,
                )
            };
            blocks.push(Box::new(
                StatisticsSummaryReportBlock {
                    loss_reports: fields.loss,
                    duplicate_reports: fields.duplicates,
                    jitter_reports: fields.jitter,
                    // The TTL / hop limit is in the IP header, which a sans-I/O engine
                    // never sees: reported as not reported (ToH 0).
                    ttl_or_hop_limit: TTLorHopLimitType::Missing,
                    ssrc,
                    begin_seq,
                    end_seq,
                    lost_packets: lost as u32,
                    dup_packets: duplicates as u32,
                    min_jitter: min,
                    max_jitter: max,
                    mean_jitter: mean,
                    dev_jitter: dev,
                    ..Default::default()
                }
                .reported(),
            ));
        }
        if stream.formats.voip_metrics {
            let metrics = stream.burst.metrics(stream.packet_duration_ms());
            let rate = |part: u64, whole: u64| -> u8 {
                (part * 256)
                    .checked_div(whole)
                    .map_or(0, |d| d.min(255) as u8)
            };
            // RFC 3611 4.7.6: PLC (unspecified here, the decoder is the application's), JBA
            // (0 unknown, 2 non-adaptive, 3 adaptive) and the JB rate.
            let jba: u8 = match jitter_buffer.adaptive {
                None => 0,
                Some(false) => 2,
                Some(true) => 3,
            };
            let jitter_buffer_rx_config = (jba << 4) | (jitter_buffer.rate & 0x0F);
            blocks.push(Box::new(VoIPMetricsReportBlock {
                ssrc,
                loss_rate: rate(stream.lost_total, stream.expected_total),
                // Discards are the application's jitter buffer's; nothing is discarded here.
                discard_rate: 0,
                burst_density: metrics.burst_density,
                gap_density: metrics.gap_density,
                burst_duration: metrics.burst_duration_ms,
                gap_duration: metrics.gap_duration_ms,
                round_trip_delay: round_trip
                    .map(|rtt| rtt.as_millis().min(u128::from(u16::MAX)) as u16)
                    .unwrap_or(0),
                // RFC 3611 4.7.3: "If an implementation is unable to provide the data, the
                // value 0 MUST be used."
                end_system_delay: 0,
                gmin,
                rx_config: jitter_buffer_rx_config,
                jb_nominal: jitter_buffer.nominal_ms,
                jb_maximum: jitter_buffer.maximum_ms,
                jb_abs_max: jitter_buffer.absolute_maximum_ms,
                ..Default::default()
            }));
        }

        // The next interval starts after this one.
        stream.begin = Some(end);
        stream.arrivals = stream.arrivals.split_off(&end);
        stream.transit_differences.clear();
        blocks
    }
}

/// A Loss or Duplicate RLE block for `begin..end`, thinned until it fits `limit` octets when
/// one was signalled (RFC 3611 5.1: "the largest size the whole report block SHOULD have").
fn rle_block(
    is_loss_rle: bool,
    ssrc: u32,
    begin: u64,
    end: u64,
    limit: Option<usize>,
    flag: &dyn Fn(u64) -> bool,
) -> RLEReportBlock {
    let mut t = 0u8;
    loop {
        let flags: Vec<bool> = reported(begin, end, t).into_iter().map(flag).collect();
        let block =
            RLEReportBlock::from_flags(is_loss_rle, ssrc, begin as u16, end as u16, t, &flags);
        if limit.is_none_or(|limit| block.marshal_size() <= limit) || t == 15 {
            return block;
        }
        t += 1;
    }
}

/// The extended sequence numbers of `begin..end` a block with thinning `t` reports on.
fn reported(begin: u64, end: u64, t: u8) -> Vec<u64> {
    let seqs = reported_sequence_numbers(begin as u16, end as u16, t);
    // Each reported 16-bit number is at its offset from `begin`.
    seqs.into_iter()
        .map(|seq| begin + u64::from(seq.wrapping_sub(begin as u16)))
        .collect()
}

fn receipt_times_block(
    stream: &RemoteStream,
    ssrc: u32,
    run: &[(u64, Instant)],
    limit: Option<usize>,
) -> PacketReceiptTimesReportBlock {
    let begin = run[0].0;
    let end = run[run.len() - 1].0 + 1;
    let mut t = 0u8;
    loop {
        let wanted = reported(begin, end, t);
        let receipt_time = run
            .iter()
            .filter(|(seq, _)| wanted.contains(seq))
            .map(|(_, at)| stream.receipt_time(*at))
            .collect();
        let block = PacketReceiptTimesReportBlock {
            t,
            ssrc,
            begin_seq: begin as u16,
            end_seq: end as u16,
            receipt_time,
        };
        if limit.is_none_or(|limit| block.marshal_size() <= limit) || t == 15 {
            return block;
        }
        t += 1;
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for XrReportInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Some(RtcpSessionEvent::RoundTripTime { rtt, .. }) =
            msg.message.custom::<RtcpSessionEvent>()
        {
            self.round_trip = Some(*rtt);
        }
        if let Packet::Rtp(packet) = &msg.message.packet
            && let Some(stream) = self.streams.get_mut(&packet.header.ssrc)
        {
            stream.on_packet(
                msg.now,
                packet.header.sequence_number,
                packet.header.timestamp,
            );
            self.arm(msg.now);
        }
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
        let Some(due) = self.next_timeout else {
            return Ok(());
        };
        if now < due {
            return Ok(());
        }
        self.next_timeout = Some(now + self.interval);
        let mut ssrcs: Vec<u32> = self.streams.keys().copied().collect();
        ssrcs.sort_unstable();
        let mut reports: Vec<Box<dyn rtcp::Packet>> = vec![];
        for ssrc in ssrcs {
            reports.extend(self.blocks(ssrc));
        }
        if !reports.is_empty() {
            let report = ExtendedReport {
                sender_ssrc: self.sender_ssrc(),
                reports,
            };
            self.write_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(report)])),
            });
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        self.next_timeout
    }
}

impl Interceptor for XrReportInterceptor {
    /// A remote stream is reported on when it negotiated at least one unilateral XR format
    /// (or the builder named some for every stream).
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        let formats = self
            .formats
            .clone()
            .unwrap_or_else(|| XrFormats::of_stream(info));
        if formats.any() {
            self.streams.insert(
                info.ssrc,
                RemoteStream::new(formats, info.clock_rate, self.gmin),
            );
        }
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);
        if self.streams.is_empty() {
            self.next_timeout = None;
        }
    }

    fn bind_local_stream(&mut self, info: &StreamInfo) {
        if !self.local_ssrcs.contains(&info.ssrc) {
            self.local_ssrcs.push(info.ssrc);
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.local_ssrcs.retain(|ssrc| *ssrc != info.ssrc);
    }
}

#[cfg(test)]
mod xr_test;
