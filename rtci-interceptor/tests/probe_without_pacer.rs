//! Bandwidth probing in a chain without a pacer.
//!
//! A probe cluster is normally the pacer's: it releases the next packets at the cluster's rate
//! and marks them, and the congestion controller measures the cluster on the reports of the
//! marked packets. In a chain without a pacer nothing marked a packet: the controller asked
//! for clusters, the NACK responder sent each one's padding as a burst, and no result ever
//! came (the start-up probes among them, so an open path was found at 8% a second).
//!
//! Now the responder's padding carries the cluster's mark when no pacer took the request, and
//! a cluster that left as one burst is measured by how far apart the path delivered it, never
//! above the rate it was asked for at. Where no cluster can be sent at all (no RTX stream to
//! pad on), the first unanswered cluster is the last one asked for until another stream
//! starts to send; the NACK responder says when it had nothing to pad a cluster with, and such
//! a cluster is counted as never asked for, so the start-up sequence waits for the stream that
//! can carry it (the first audio packet asks before the video has sent).
//!
//! The chain here is the NACK responder, the congestion controller and the TWCC sender that
//! numbers the packets; the test writes media, collects what leaves and feeds the
//! transport-wide feedback.

use bytes::Bytes;
use rtci_interceptor::{
    AttributedPacket, BandwidthEstimator, CongestionControlBuilder, Interceptor,
    NackResponderBuilder, Packet, PacketReport, ProbePacket, ProbeRequest, RTCPFeedback,
    RTPHeaderExtension, Registry, Slot, StreamInfo, TaggedPacket, TwccSenderBuilder,
};
use rtcp::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, SymbolTypeTcc,
    TransportLayerCc,
};
use sansio::Protocol as _;
use shared::TransportContext;
use shared::marshal::{MarshalSize, Unmarshal};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const TWCC_ID: u8 = 5;
const VIDEO_SSRC: u32 = 0x00A0_0001;
const VIDEO_RTX_SSRC: u32 = 0x00A0_0002;
const SECOND_SSRC: u32 = 0x00C0_0001;
const SECOND_RTX_SSRC: u32 = 0x00C0_0002;
const AUDIO_SSRC: u32 = 0x00B0_0001;
/// The estimate the recorder reports: the start-up clusters are three and six times it.
const TARGET: f64 = 300_000.0;

/// An estimator that only records the probe results it is given; its target is the test's.
struct Recorder {
    results: Arc<Mutex<Vec<f64>>>,
    target: Arc<Mutex<f64>>,
}

impl BandwidthEstimator for Recorder {
    fn on_reports(&mut self, _now: Instant, _reports: &[PacketReport]) {}

    fn target_bitrate(&self) -> f64 {
        *self.target.lock().unwrap()
    }

    fn on_probe_result(&mut self, _now: Instant, bits_per_second: f64) {
        self.results.lock().unwrap().push(bits_per_second);
    }
}

/// Video with NACK and transport-wide feedback, with or without an RTX stream.
fn video(ssrc: u32, ssrc_rtx: Option<u32>) -> StreamInfo {
    StreamInfo {
        ssrc,
        ssrc_rtx,
        payload_type: 96,
        payload_type_rtx: ssrc_rtx.map(|_| 97),
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        rtcp_feedback: vec![
            RTCPFeedback {
                typ: "nack".to_owned(),
                parameter: String::new(),
            },
            RTCPFeedback {
                typ: "transport-cc".to_owned(),
                parameter: String::new(),
            },
        ],
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: u16::from(TWCC_ID),
        }],
        ..Default::default()
    }
}

/// Opus with transport-wide feedback and no RTX stream: nothing a cluster can be padded on.
fn audio(ssrc: u32) -> StreamInfo {
    StreamInfo {
        ssrc,
        payload_type: 111,
        clock_rate: 48_000,
        channels: 2,
        mime_type: "audio/opus".to_owned(),
        rtcp_feedback: vec![RTCPFeedback {
            typ: "transport-cc".to_owned(),
            parameter: String::new(),
        }],
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: u16::from(TWCC_ID),
        }],
        ..Default::default()
    }
}

/// A packet that left the chain: its SSRC, its transport-wide number, its size on the wire
/// and the probe cluster it was marked for.
#[derive(Debug, Clone, Copy)]
struct Left {
    ssrc: u32,
    number: u16,
    size: usize,
    cluster: Option<u32>,
}

struct Sender<I> {
    chain: I,
    results: Arc<Mutex<Vec<f64>>>,
    /// The estimator's target, set by the test.
    target: Arc<Mutex<f64>>,
    sequence_number: u16,
    /// Every probe request that reached the application end, with when.
    requests: Vec<(Instant, ProbeRequest)>,
}

fn sender(streams: &[StreamInfo]) -> Sender<impl Interceptor + use<>> {
    let results = Arc::new(Mutex::new(Vec::new()));
    let target = Arc::new(Mutex::new(TARGET));
    let (controller, _handle) = CongestionControlBuilder::new(Recorder {
        results: results.clone(),
        target: target.clone(),
    })
    .with_bandwidth_probing(true)
    .build_with_handle();
    let mut chain = Registry::new()
        .with(Slot::NackResponder, NackResponderBuilder::new().build())
        .with(Slot::CongestionControl, controller)
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .build();
    for stream in streams {
        chain.bind_local_stream(stream);
    }
    Sender {
        chain,
        results,
        target,
        sequence_number: 0,
        requests: Vec::new(),
    }
}

impl<I: Interceptor> Sender<I> {
    /// Everything the chain has to hand on at `now`, either way; returns what left for the wire.
    fn pump(&mut self, now: Instant) -> Vec<Left> {
        let mut left = Vec::new();
        // The request travels application-ward (the responder fills it on the way), the
        // padding wire-ward after it: twice round is enough for both.
        for _ in 0..2 {
            while let Some(read) = self.chain.poll_read() {
                if let Some(request) = read.message.custom::<ProbeRequest>() {
                    self.requests.push((now, *request));
                }
            }
            while let Some(out) = self.chain.poll_write() {
                let cluster = out
                    .message
                    .custom::<ProbePacket>()
                    .map(|probe| probe.cluster);
                if let Packet::Rtp(packet) = &out.message.packet
                    && let Some(mut extension) = packet.header.get_extension(TWCC_ID)
                {
                    let number =
                        rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(
                            &mut extension,
                        )
                        .expect("transport-cc extension")
                        .transport_sequence;
                    left.push(Left {
                        ssrc: packet.header.ssrc,
                        number,
                        size: packet.marshal_size(),
                        cluster,
                    });
                }
            }
        }
        left
    }

    /// One millisecond of the sender's life at `now`: a media packet of `ssrc` every 20 ms.
    fn step(&mut self, now: Instant, millisecond: u64, ssrc: u32) -> Vec<Left> {
        if millisecond.is_multiple_of(20) {
            self.sequence_number = self.sequence_number.wrapping_add(1);
            self.write_media(now, ssrc, 96, self.sequence_number);
        }
        self.chain.handle_timeout(now).unwrap();
        self.pump(now)
    }

    /// One media packet of `ssrc`, 1000 octets of payload, written at `now`.
    fn write_media(&mut self, now: Instant, ssrc: u32, payload_type: u8, sequence_number: u16) {
        self.chain
            .handle_write(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        payload_type,
                        sequence_number,
                        timestamp: u32::from(sequence_number) * 3000,
                        ssrc,
                        ..Default::default()
                    },
                    payload: Bytes::from(vec![0u8; 1000]),
                })),
            })
            .unwrap();
    }

    /// Media flows until padding leaves for a probe cluster; returns the cluster's packets
    /// and when they left.
    fn first_cluster(&mut self, epoch: Instant) -> (Vec<Left>, Instant) {
        for millisecond in 0..2000u64 {
            let now = epoch + Duration::from_millis(millisecond);
            let left = self.step(now, millisecond, VIDEO_SSRC);
            let padding: Vec<Left> = left
                .into_iter()
                .filter(|packet| packet.ssrc == VIDEO_RTX_SSRC)
                .collect();
            if !padding.is_empty() {
                return (padding, now);
            }
        }
        panic!("no padding left for a probe cluster");
    }

    /// Transport-wide feedback at `now` on `packets` (consecutive numbers): the first arrived
    /// at `first_arrival` after `epoch`, each further one `spacing` after the one before.
    fn report(
        &mut self,
        now: Instant,
        packets: &[Left],
        first_arrival: Duration,
        spacing: Duration,
    ) {
        let base = packets[0].number;
        let reference_time = (first_arrival.as_micros() / 64_000) as u32;
        let mut previous = Duration::from_micros(u64::from(reference_time) * 64_000);
        let mut packet_chunks = Vec::new();
        let mut recv_deltas = Vec::new();
        for (index, packet) in packets.iter().enumerate() {
            assert_eq!(
                base.wrapping_add(index as u16),
                packet.number,
                "a report names a run of numbers"
            );
            let at = first_arrival + spacing * index as u32;
            let ticks = (at.saturating_sub(previous).as_micros() / 250) as i64;
            previous += Duration::from_micros(ticks as u64 * 250);
            let symbol = if ticks <= 255 {
                SymbolTypeTcc::PacketReceivedSmallDelta
            } else {
                SymbolTypeTcc::PacketReceivedLargeDelta
            };
            recv_deltas.push(RecvDelta {
                type_tcc_packet: symbol,
                delta: ticks * 250,
            });
            packet_chunks.push(PacketStatusChunk::RunLengthChunk(RunLengthChunk {
                type_tcc: StatusChunkTypeTcc::RunLengthChunk,
                packet_status_symbol: symbol,
                run_length: 1,
            }));
        }
        self.chain
            .handle_read(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerCc {
                    sender_ssrc: 0x5E5E_5E5E,
                    media_ssrc: VIDEO_SSRC,
                    base_sequence_number: base,
                    packet_status_count: packets.len() as u16,
                    reference_time,
                    fb_pkt_count: 0,
                    packet_chunks,
                    recv_deltas,
                })])),
            })
            .unwrap();
        self.pump(now);
    }

    fn results(&self) -> Vec<f64> {
        self.results.lock().unwrap().clone()
    }
}

/// Without a pacer the cluster is the responder's padding: every packet of it carries the
/// cluster's mark, and the cluster is the size that was asked for.
fn assert_the_padding_is_the_cluster<I: Interceptor>(sender: &Sender<I>, padding: &[Left]) {
    let (_, request) = sender.requests.last().expect("a cluster was asked for");
    assert!(
        padding
            .iter()
            .all(|packet| packet.cluster == Some(request.cluster)),
        "every padding packet carries the mark of cluster {}: {padding:?}",
        request.cluster
    );
    let octets: usize = padding.iter().map(|packet| packet.size).sum();
    assert!(
        octets >= request.octets && padding.len() >= 5,
        "the padding fills the cluster of {} octets: {octets} octets in {} packets",
        request.octets,
        padding.len()
    );
}

/// A path wider than the cluster's rate delivers the burst closely spaced (one packet a
/// millisecond, about 2.3 Mbit/s). The cluster has a result, and it is the rate that was
/// asked for (three times the estimate): a burst shows the path's width, but nothing was sent
/// to show that the path carries more than the cluster asked.
#[test]
fn a_cluster_without_a_pacer_is_measured_and_shows_no_more_than_was_asked() {
    let epoch = Instant::now();
    let mut sender = sender(&[video(VIDEO_SSRC, Some(VIDEO_RTX_SSRC))]);
    let (padding, left_at) = sender.first_cluster(epoch);
    assert_the_padding_is_the_cluster(&sender, &padding);
    let asked = sender.requests[0].1.bits_per_second;
    assert_eq!(3.0 * TARGET, asked, "the first start-up cluster");
    assert!(sender.results().is_empty());

    let arrival = left_at.duration_since(epoch) + Duration::from_millis(20);
    sender.report(
        left_at + Duration::from_millis(60),
        &padding,
        arrival,
        Duration::from_millis(1),
    );
    assert_eq!(
        vec![asked],
        sender.results(),
        "the burst arrived at 2.3 Mbit/s: the path carries the 900 kbit/s asked"
    );
}

/// A path narrower than the cluster's rate holds the burst apart (one packet every 10 ms).
/// The result is the rate the packets arrived at, less a twentieth: the link's width.
#[test]
fn a_cluster_without_a_pacer_shows_the_rate_the_path_spread_it_to() {
    let epoch = Instant::now();
    let mut sender = sender(&[video(VIDEO_SSRC, Some(VIDEO_RTX_SSRC))]);
    let (padding, left_at) = sender.first_cluster(epoch);
    assert_the_padding_is_the_cluster(&sender, &padding);

    let spacing = Duration::from_millis(10);
    let arrival = left_at.duration_since(epoch) + Duration::from_millis(20);
    sender.report(
        left_at + Duration::from_millis(400),
        &padding,
        arrival,
        spacing,
    );
    let after_first: usize = padding[1..].iter().map(|packet| packet.size).sum();
    let span = spacing.as_secs_f64() * (padding.len() - 1) as f64;
    let expected = after_first as f64 * 8.0 / span * 0.95;
    let results = sender.results();
    assert_eq!(1, results.len(), "one cluster, one result: {results:?}");
    assert!(
        (results[0] - expected).abs() < 0.02 * expected && results[0] < 3.0 * TARGET,
        "the octets after the first over the span of the arrivals, less 5%: expected about \
         {expected:.0}, got {}",
        results[0]
    );
}

/// With no RTX stream the responder has nothing to pad on and there is no pacer: no packet
/// leaves for the cluster. The controller asks once, and not again in the next twelve
/// seconds (it asked every second or so before: the start-up sequence, then every five
/// seconds of an application-limited sender), and it names no deadline that has passed. When
/// a stream with an RTX stream starts to send, clusters are asked for again and are filled.
#[test]
fn a_cluster_nothing_can_send_is_not_asked_for_again_until_another_stream_sends() {
    let epoch = Instant::now();
    let mut sender = sender(&[video(VIDEO_SSRC, None)]);
    for millisecond in 0..12_000u64 {
        let now = epoch + Duration::from_millis(millisecond);
        let left = sender.step(now, millisecond, VIDEO_SSRC);
        assert!(
            left.iter().all(|packet| packet.cluster.is_none()),
            "nothing marks a packet in this chain"
        );
        if millisecond > 1_100 {
            assert!(
                sender.chain.poll_timeout().is_none_or(|at| at > now),
                "a deadline in the past {millisecond} ms in"
            );
        }
    }
    assert_eq!(
        1,
        sender.requests.len(),
        "one cluster went unanswered, and no more were asked for: {:?}",
        sender.requests
    );
    assert!(sender.results().is_empty());

    // A second stream, with RTX, starts to send.
    sender
        .chain
        .bind_local_stream(&video(SECOND_SSRC, Some(SECOND_RTX_SSRC)));
    let mut padding = Vec::new();
    for millisecond in 12_000..15_000u64 {
        let now = epoch + Duration::from_millis(millisecond);
        let left = sender.step(now, millisecond, SECOND_SSRC);
        padding.extend(
            left.into_iter()
                .filter(|packet| packet.ssrc == SECOND_RTX_SSRC),
        );
        if !padding.is_empty() {
            break;
        }
    }
    assert!(
        sender.requests.len() >= 2,
        "a cluster is asked for once a stream that can carry one sends: {:?}",
        sender.requests
    );
    assert_the_padding_is_the_cluster(&sender, &padding);
}

/// Media of a call from `from` to `to` milliseconds after `epoch`: audio every 20 ms, and
/// from `video_from` on video every 33 ms (from `video_from`, then each 33 ms after). Stops at
/// the first padding on the video's RTX stream and returns it with its millisecond.
fn audio_and_video<I: Interceptor>(
    sender: &mut Sender<I>,
    epoch: Instant,
    (from, to): (u64, u64),
    video_from: u64,
    sequences: &mut (u16, u16),
) -> Option<(u64, Vec<Left>)> {
    for millisecond in from..to {
        let now = epoch + Duration::from_millis(millisecond);
        if millisecond.is_multiple_of(20) {
            sequences.0 = sequences.0.wrapping_add(1);
            sender.write_media(now, AUDIO_SSRC, 111, sequences.0);
        }
        if millisecond >= video_from && (millisecond - video_from).is_multiple_of(33) {
            sequences.1 = sequences.1.wrapping_add(1);
            sender.write_media(now, VIDEO_SSRC, 96, sequences.1);
        }
        sender.chain.handle_timeout(now).unwrap();
        let padding: Vec<Left> = sender
            .pump(now)
            .into_iter()
            .filter(|packet| packet.ssrc == VIDEO_RTX_SSRC)
            .collect();
        if !padding.is_empty() {
            return Some((millisecond, padding));
        }
    }
    None
}

/// A peer connection's call order: audio and video with its RTX stream are bound before
/// anything is sent, and the first audio packet leaves before the first video packet (audio
/// every 20 ms from 0 ms, video every 33 ms from 10 ms). The first audio packet is media
/// flowing, so the first start-up cluster is asked for then, when no stream with an RTX stream
/// has sent and the responder has no header to pad with: nothing leaves for it, and the
/// responder says so. The cluster is counted as never asked for, and the video's first packet
/// asks for the same start-up cluster again: it leaves as padding on the video's RTX stream at
/// 10 ms, as it would have had the video sent first. (On 0.2.0 the controller asked for
/// nothing more and the sender climbed at 8% a second; with probe-1 alone the second start-up
/// cluster was asked for a second later, when the first one's result was given up.)
#[test]
fn a_cluster_asked_for_before_the_video_sends_does_not_stop_the_probing() {
    let epoch = Instant::now();
    let mut sender = sender(&[audio(AUDIO_SSRC), video(VIDEO_SSRC, Some(VIDEO_RTX_SSRC))]);
    let (at, padding) = audio_and_video(&mut sender, epoch, (0, 3_000), 10, &mut (0, 0))
        .expect("padding left for a cluster");
    let (first_at, first) = *sender.requests.first().expect("a cluster was asked for");
    assert_eq!(
        epoch, first_at,
        "the first cluster is asked for with the first audio packet"
    );
    assert!(
        padding
            .iter()
            .all(|packet| packet.cluster != Some(first.cluster)),
        "nothing could be padded for the first cluster: {padding:?}"
    );
    assert_eq!(10, at, "the cluster leaves with the video's first packet");
    let asked: Vec<(Duration, f64)> = sender
        .requests
        .iter()
        .map(|(at, request)| (at.duration_since(epoch), request.bits_per_second))
        .collect();
    assert_eq!(
        vec![
            (Duration::ZERO, 3.0 * TARGET),
            (Duration::from_millis(10), 3.0 * TARGET)
        ],
        asked,
        "the first start-up cluster, asked for again when the video sends"
    );
    assert_the_padding_is_the_cluster(&sender, &padding);
}

/// A call of audio alone gains a video stream with RTX by renegotiation after three seconds.
/// The audio's clusters leave no packet: the first one is asked for and no more (no stream to
/// pad on), and the start-up sequence is not spent. When the video is bound, the controller's
/// next wake-up asks again before the video has sent, and again nothing leaves; the video's first
/// packet asks for the first start-up cluster, which leaves as padding on its RTX stream at
/// once. (With probe-1 alone both start-up clusters were spent on the audio and the video was
/// never probed for.)
#[test]
fn video_added_to_an_audio_call_is_probed_for_with_its_first_packet() {
    let epoch = Instant::now();
    let mut sender = sender(&[audio(AUDIO_SSRC)]);
    let mut sequences = (0, 0);
    assert!(
        audio_and_video(&mut sender, epoch, (0, 3_001), u64::MAX, &mut sequences).is_none(),
        "no padding for audio alone"
    );
    assert_eq!(
        1,
        sender.requests.len(),
        "one cluster asked for, none again while nothing changes: {:?}",
        sender.requests
    );

    sender
        .chain
        .bind_local_stream(&video(VIDEO_SSRC, Some(VIDEO_RTX_SSRC)));
    let (at, padding) = audio_and_video(&mut sender, epoch, (3_001, 6_000), 3_025, &mut sequences)
        .expect("padding left for a cluster");
    assert_eq!(
        3_025, at,
        "the cluster leaves with the video's first packet"
    );
    let asked: Vec<(Duration, f64)> = sender
        .requests
        .iter()
        .map(|(at, request)| (at.duration_since(epoch), request.bits_per_second))
        .collect();
    assert_eq!(
        vec![
            (Duration::ZERO, 3.0 * TARGET),
            (Duration::from_millis(3_001), 3.0 * TARGET),
            (Duration::from_millis(3_025), 3.0 * TARGET),
        ],
        asked,
        "the first start-up cluster each time: the audio's spent none of the sequence"
    );
    assert_the_padding_is_the_cluster(&sender, &padding);
}

/// A chain whose clusters leave as bursts does not probe for the rate before a large drop.
/// The controller learns what its clusters are from the first one it measures (all of its
/// packets left in one instant). After that the target is 2 Mbit/s and falls to 500 kbit/s:
/// with a pacer, a cluster at 85% of the rate before the drop (1.7 Mbit/s) would be asked for
/// a second later and once a second for five seconds
/// (`a_large_drop_is_followed_by_a_probe_at_the_rate_before_it`); here none is, in the seven
/// seconds after the drop. A burst is five packets of padding on top of the media, into the
/// queue that caused the drop; a paced cluster is mostly the media itself, released faster.
#[test]
fn a_chain_without_a_pacer_does_not_probe_after_a_large_drop() {
    let epoch = Instant::now();
    let mut sender = sender(&[video(VIDEO_SSRC, Some(VIDEO_RTX_SSRC))]);
    let (padding, left_at) = sender.first_cluster(epoch);
    let arrival = left_at.duration_since(epoch) + Duration::from_millis(20);
    sender.report(
        left_at + Duration::from_millis(60),
        &padding,
        arrival,
        Duration::from_millis(1),
    );
    assert_eq!(1, sender.results().len(), "the burst was measured");

    let from = left_at.duration_since(epoch).as_millis() as u64 + 61;
    *sender.target.lock().unwrap() = 2_000_000.0;
    for millisecond in from..from + 1_500 {
        sender.step(
            epoch + Duration::from_millis(millisecond),
            millisecond,
            VIDEO_SSRC,
        );
    }
    let before_the_drop = sender.requests.len();
    *sender.target.lock().unwrap() = 500_000.0;
    for millisecond in from + 1_500..from + 8_500 {
        sender.step(
            epoch + Duration::from_millis(millisecond),
            millisecond,
            VIDEO_SSRC,
        );
    }
    let after: Vec<f64> = sender.requests[before_the_drop..]
        .iter()
        .map(|(_, request)| request.bits_per_second)
        .collect();
    assert!(
        !after.contains(&(0.85 * 2_000_000.0)),
        "a cluster at the rate before the drop was asked for: {after:?}"
    );
}
