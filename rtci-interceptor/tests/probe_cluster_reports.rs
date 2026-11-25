//! Which packets a probe cluster waits for, and for how long.
//!
//! The congestion controller counts the packets the pacer marked as a cluster's
//! (`ProbePacket`) and gives the estimator the cluster's result when their reports are in.
//! Two rules keep a cluster from waiting for a report that never comes:
//!
//! - only a packet of a stream that per-packet feedback reports is counted (audio that
//!   negotiated none can leave while the cluster does, with its mark);
//! - a cluster one of whose reports is still missing half a second after its last packet left
//!   is measured on the reports it has (the feedback packet that named the missing one was
//!   lost, or the packet was dropped where no report names it).
//!
//! Before, either case left the cluster unreported "in full" for ever: it was forgotten after
//! two seconds and the controller gave the probe up, so an estimate that only a probe could
//! lift stayed where it was.
//!
//! The controller is driven alone here (with the TWCC sender that numbers its packets): the
//! test reads its `ProbeRequest`, writes the cluster's packets with their mark as a pacer
//! would, and feeds the transport-wide feedback.

use bytes::Bytes;
use rtci_interceptor::{
    Attribute, AttributedPacket, BandwidthEstimator, CongestionControlBuilder, Interceptor, Packet,
    PacketReport, ProbePacket, ProbeRequest, RTCPFeedback, RTPHeaderExtension, Registry, Slot,
    StreamInfo, TaggedPacket, TwccSenderBuilder,
};
use rtcp::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, SymbolTypeTcc,
    TransportLayerCc,
};
use shared::TransportContext;
use shared::marshal::Unmarshal;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const TWCC_ID: u8 = 5;
const VIDEO_SSRC: u32 = 0x00A0_0001;
const AUDIO_SSRC: u32 = 0x00B0_0001;

/// An estimator that only records the probe results it is given.
struct Recorder {
    results: Arc<Mutex<Vec<(Instant, f64)>>>,
}

impl BandwidthEstimator for Recorder {
    fn on_reports(&mut self, _now: Instant, _reports: &[PacketReport]) {}

    fn target_bitrate(&self) -> f64 {
        300_000.0
    }

    fn on_probe_result(&mut self, now: Instant, bits_per_second: f64) {
        self.results.lock().unwrap().push((now, bits_per_second));
    }
}

/// Video with transport-wide feedback.
fn video() -> StreamInfo {
    StreamInfo {
        ssrc: VIDEO_SSRC,
        payload_type: 96,
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
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

/// Audio that negotiated no per-packet congestion feedback.
fn audio() -> StreamInfo {
    StreamInfo {
        ssrc: AUDIO_SSRC,
        payload_type: 111,
        clock_rate: 48_000,
        mime_type: "audio/opus".to_owned(),
        ..Default::default()
    }
}

struct Sender<I> {
    chain: I,
    results: Arc<Mutex<Vec<(Instant, f64)>>>,
    sequence_number: u16,
}

fn sender() -> Sender<impl Interceptor> {
    let results = Arc::new(Mutex::new(Vec::new()));
    let (controller, _handle) = CongestionControlBuilder::new(Recorder {
        results: results.clone(),
    })
    .with_bandwidth_probing(true)
    .build_with_handle();
    let mut chain = Registry::new()
        .with(Slot::CongestionControl, controller)
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .build();
    chain.bind_local_stream(&video());
    chain.bind_local_stream(&audio());
    Sender {
        chain,
        results,
        sequence_number: 0,
    }
}

impl<I: Interceptor> Sender<I> {
    /// Writes one packet of `ssrc` at `now`, marked as part of `cluster` when given, and
    /// returns the transport-wide sequence number it left with (none on a stream without).
    fn write(&mut self, now: Instant, ssrc: u32, cluster: Option<u32>) -> Option<u16> {
        self.sequence_number = self.sequence_number.wrapping_add(1);
        let mut message = AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: if ssrc == VIDEO_SSRC { 96 } else { 111 },
                sequence_number: self.sequence_number,
                timestamp: u32::from(self.sequence_number) * 3000,
                ssrc,
                ..Default::default()
            },
            payload: Bytes::from(vec![0u8; 1180]),
        }));
        if let Some(cluster) = cluster {
            message.add(Attribute::Custom(Arc::new(ProbePacket { cluster })));
        }
        self.chain
            .handle_write(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message,
            })
            .unwrap();
        let mut transport_sequence = None;
        while let Some(out) = self.chain.poll_write() {
            if let Packet::Rtp(packet) = &out.message.packet
                && let Some(mut extension) = packet.header.get_extension(TWCC_ID)
            {
                transport_sequence = Some(
                    rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(
                        &mut extension,
                    )
                    .expect("transport-cc extension")
                    .transport_sequence,
                );
            }
        }
        transport_sequence
    }

    /// The probe cluster the controller asks for, read from what it hands application-ward.
    fn asked(&mut self) -> Option<u32> {
        let mut cluster = None;
        while let Some(read) = self.chain.poll_read() {
            if let Some(request) = read.message.custom::<ProbeRequest>() {
                cluster = Some(request.cluster);
            }
        }
        cluster
    }

    /// Media flows until the controller asks for its first cluster; returns the cluster and
    /// the instant it was asked at.
    fn first_cluster(&mut self, epoch: Instant) -> (u32, Instant) {
        for millisecond in 0..2000u64 {
            let now = epoch + Duration::from_millis(millisecond);
            if millisecond.is_multiple_of(20) {
                let numbered = self.write(now, VIDEO_SSRC, None);
                assert!(numbered.is_some(), "video is numbered transport-wide");
            }
            self.chain.handle_timeout(now).unwrap();
            if let Some(cluster) = self.asked() {
                return (cluster, now);
            }
        }
        panic!("the controller never asked for a probe cluster");
    }

    /// Transport-wide feedback at `now`: each `(number, departure)` arrived 20 ms after it left.
    fn report(&mut self, now: Instant, epoch: Instant, packets: &[(u16, Instant)]) {
        let Some((base, first)) = packets.first().copied() else {
            return;
        };
        let delay = Duration::from_millis(20);
        let reference_time =
            ((first + delay).saturating_duration_since(epoch).as_micros() / 64_000) as u32;
        let mut previous = Duration::from_micros(u64::from(reference_time) * 64_000);
        let mut packet_chunks = Vec::new();
        let mut recv_deltas = Vec::new();
        for (index, (number, departure)) in packets.iter().enumerate() {
            assert_eq!(
                base.wrapping_add(index as u16),
                *number,
                "a report names a run of numbers"
            );
            let at = (*departure + delay).saturating_duration_since(epoch);
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
        while self.chain.poll_read().is_some() {}
    }

    fn results(&self) -> Vec<(Instant, f64)> {
        self.results.lock().unwrap().clone()
    }
}

/// A packet of a stream no per-packet feedback reports (audio that negotiated none) leaves
/// with the cluster's mark. The cluster does not wait for it: once every packet that feedback
/// does report is reported, the cluster has its result, with the first feedback.
#[test]
fn a_cluster_does_not_wait_for_a_packet_no_feedback_reports() {
    let epoch = Instant::now();
    let mut sender = sender();
    let (cluster, asked) = sender.first_cluster(epoch);

    let mut numbered = Vec::new();
    for index in 0..6u64 {
        let now = asked + Duration::from_millis(1 + 2 * index);
        let number = sender
            .write(now, VIDEO_SSRC, Some(cluster))
            .expect("video is numbered transport-wide");
        numbered.push((number, now));
        if index == 2 {
            // Audio leaves in the middle of the cluster, marked like the rest.
            assert_eq!(None, sender.write(now, AUDIO_SSRC, Some(cluster)));
        }
    }
    assert!(sender.results().is_empty());

    // Every video packet of the cluster is reported 100 ms later: that is the whole cluster.
    let at = asked + Duration::from_millis(100);
    sender.report(at, epoch, &numbered);
    let results = sender.results();
    assert_eq!(
        1,
        results.len(),
        "the cluster has its result with the first feedback, not waiting for the audio packet: \
         {results:?}"
    );
    assert_eq!(at, results[0].0);
}

/// One packet of a cluster is never reported (the feedback that named it was lost). The
/// cluster is not measured while the report may still come; half a second after its last
/// packet left it is measured on the reports it has, in time for the probe that awaits it.
#[test]
fn a_cluster_with_a_report_missing_is_measured_on_the_reports_it_has() {
    let epoch = Instant::now();
    let mut sender = sender();
    let (cluster, asked) = sender.first_cluster(epoch);

    let mut numbered = Vec::new();
    for index in 0..6u64 {
        let now = asked + Duration::from_millis(1 + 2 * index);
        let number = sender
            .write(now, VIDEO_SSRC, Some(cluster))
            .expect("video is numbered transport-wide");
        numbered.push((number, now));
    }
    let last_left = numbered[5].1;

    // Five of the six are reported; the sixth never is.
    sender.report(asked + Duration::from_millis(100), epoch, &numbered[..5]);
    assert!(
        sender.results().is_empty(),
        "one report may still come: {:?}",
        sender.results()
    );

    // Later media is reported 300 ms after the cluster left: still inside the wait.
    let early = last_left + Duration::from_millis(280);
    let number = sender.write(early, VIDEO_SSRC, None).expect("numbered");
    sender.report(early + Duration::from_millis(20), epoch, &[(number, early)]);
    assert!(
        sender.results().is_empty(),
        "measured before the wait for the missing report ended: {:?}",
        sender.results()
    );

    // And again 520 ms after it left: the wait is over, the five reports are the cluster.
    let late = last_left + Duration::from_millis(500);
    let number = sender.write(late, VIDEO_SSRC, None).expect("numbered");
    let at = late + Duration::from_millis(20);
    sender.report(at, epoch, &[(number, late)]);
    let results = sender.results();
    assert_eq!(
        1,
        results.len(),
        "the cluster is measured on the five reports it has: {results:?}"
    );
    assert_eq!(at, results[0].0);
    // Six packets of 1200 octets 2 ms apart are 4.8 Mbit/s; the five reported ones say so.
    assert!(
        (3_000_000.0..=6_000_000.0).contains(&results[0].1),
        "{results:?}"
    );
}
