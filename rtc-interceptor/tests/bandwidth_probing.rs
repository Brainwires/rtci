//! How long `Gcc` takes to find a path's capacity, with bandwidth probing and without.
//!
//! A sender starts at 300 kbit/s on a path that carries 2.5 Mbit/s and sends what its target
//! allows. Without probing the estimate climbs 8% a second; with it, clusters of packets at a
//! multiple of the target show within a second what the path carries. Everything runs on a
//! virtual clock through the chain the default interceptor set builds for a sender: the
//! congestion controller, the TWCC sender, the pacer and the NACK responder, whose RTX stream
//! fills the clusters.
//!
//! Run with `--nocapture` to read the ramp.

mod path_simulator;

use path_simulator::{Arrival, Path, PathProfile};
use rtc_interceptor::{
    AttributedPacket, CongestionControlBuilder, Gcc, Interceptor, NackResponderBuilder,
    PacerBuilder, Packet, ProbePacket, RTCPFeedback, RTPHeaderExtension, Registry, Slot,
    StreamInfo, TaggedPacket, TwccSenderBuilder,
};
use rtcp::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, SymbolTypeTcc,
    TransportLayerCc,
};
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::{MarshalSize, Unmarshal};
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const TWCC_ID: u8 = 5;
const MEDIA_SSRC: u32 = 0x00A0_0001;
const RTX_SSRC: u32 = 0x00A0_0002;
const CAPACITY: f64 = 2_500_000.0;
const START: f64 = 300_000.0;
const PACKET_OCTETS: usize = 1200;

fn stream(with_rtx: bool) -> StreamInfo {
    StreamInfo {
        ssrc: MEDIA_SSRC,
        ssrc_rtx: with_rtx.then_some(RTX_SSRC),
        payload_type: 96,
        payload_type_rtx: with_rtx.then_some(97),
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        rtcp_feedback: vec![
            RTCPFeedback {
                typ: "transport-cc".to_owned(),
                parameter: String::new(),
            },
            RTCPFeedback {
                typ: "nack".to_owned(),
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

/// Transport-wide feedback that says exactly when each packet arrived: the reference time is
/// the 64 ms tick before the first arrival, and every delta is the true gap, large where a
/// small one does not hold it. (The shared `twcc_feedback_for` clips gaps to 63 ms, which is
/// fine for a delay trend and not for the arrival rate of a probe cluster.)
fn feedback(now: Instant, epoch: Instant, arrivals: &[Arrival]) -> Option<TaggedPacket> {
    let base = arrivals.first()?.twcc_sequence_number;
    let first = arrivals.iter().find_map(|arrival| arrival.at)?;
    let reference_time = (first.saturating_duration_since(epoch).as_micros() / 64_000) as u32;
    let mut previous = Duration::from_micros(u64::from(reference_time) * 64_000);
    let mut packet_chunks = Vec::new();
    let mut recv_deltas = Vec::new();
    for arrival in arrivals {
        let symbol = match arrival.at {
            Some(at) => {
                let at = at.saturating_duration_since(epoch);
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
                symbol
            }
            None => SymbolTypeTcc::PacketNotReceived,
        };
        packet_chunks.push(PacketStatusChunk::RunLengthChunk(RunLengthChunk {
            type_tcc: StatusChunkTypeTcc::RunLengthChunk,
            packet_status_symbol: symbol,
            run_length: 1,
        }));
    }
    Some(TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerCc {
            sender_ssrc: 0x5E5E_5E5E,
            media_ssrc: MEDIA_SSRC,
            base_sequence_number: base,
            packet_status_count: arrivals.len() as u16,
            reference_time,
            fb_pkt_count: 0,
            packet_chunks,
            recv_deltas,
        })])),
    })
}

struct Run {
    /// When the target first reached 90% of the capacity.
    reached: Option<Duration>,
    /// The highest target seen.
    peak: f64,
    /// The target at the end, as a share of the capacity.
    final_share: f64,
    /// Packets that left as part of a probe cluster, and how many of them were on the RTX
    /// stream.
    probe_packets: usize,
    probe_rtx_packets: usize,
    /// Octets on the RTX stream over the whole run, as a share of all octets sent.
    rtx_share: f64,
    /// Share of the offered packets the path dropped.
    loss: f64,
}

/// `media_share` is what the application sends, as a share of the target: 1.0 follows it.
fn run(probing: bool, with_rtx: bool, media_share: f64, duration: Duration) -> Run {
    let epoch = Instant::now();
    let estimator = Gcc::new(START, 30_000.0, 20_000_000.0);
    let (controller, handle) = CongestionControlBuilder::new(estimator)
        .with_bandwidth_probing(probing)
        .build_with_handle();
    let mut chain = Registry::new()
        .with(Slot::CongestionControl, controller)
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .with(
            Slot::Pacer,
            PacerBuilder::new().with_target_bitrate(START).build(),
        )
        .with(Slot::NackResponder, NackResponderBuilder::new().build())
        .build();
    chain.bind_local_stream(&stream(with_rtx));

    let mut path = Path::new(
        PathProfile {
            capacity_bits_per_second: CAPACITY,
            queue_capacity_bits: CAPACITY * 0.3,
            ..PathProfile::steady()
        },
        epoch,
    );

    let mut sequence_number = 0u16;
    let mut next_media = Duration::ZERO;
    let mut next_feedback = Duration::from_millis(100);
    let mut pending: Vec<Arrival> = Vec::new();
    let mut reached = None;
    let mut peak: f64 = 0.0;
    let mut probe_packets = 0usize;
    let mut probe_rtx_packets = 0usize;
    let mut rtx_octets = 0usize;
    let mut octets = 0usize;
    let mut offered = 0u64;
    let mut dropped = 0u64;

    let step = Duration::from_millis(1);
    let mut elapsed = Duration::ZERO;
    while elapsed < duration {
        let now = epoch + elapsed;
        let target = handle.target_bitrate();
        peak = peak.max(target);
        if reached.is_none() && target >= 0.9 * CAPACITY {
            reached = Some(elapsed);
        }

        // The application writes media at its share of the target.
        while next_media <= elapsed {
            let packet = rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    payload_type: 96,
                    sequence_number,
                    timestamp: (next_media.as_secs_f64() * 90_000.0) as u32,
                    ssrc: MEDIA_SSRC,
                    ..Default::default()
                },
                payload: vec![0u8; PACKET_OCTETS - 20].into(),
            };
            sequence_number = sequence_number.wrapping_add(1);
            chain
                .handle_write(TaggedPacket {
                    now,
                    transport: TransportContext::default(),
                    message: AttributedPacket::new(Packet::Rtp(packet)),
                })
                .unwrap();
            next_media += Duration::from_secs_f64(
                PACKET_OCTETS as f64 * 8.0 / (target * media_share).max(30_000.0),
            );
        }

        for _ in 0..64 {
            match chain.poll_timeout() {
                Some(at) if at <= now => chain.handle_timeout(now).unwrap(),
                _ => break,
            }
        }

        // What leaves goes onto the path.
        while let Some(out) = chain.poll_write() {
            let Packet::Rtp(packet) = &out.message.packet else {
                continue;
            };
            let size = packet.marshal_size();
            octets += size;
            let on_rtx = packet.header.ssrc == RTX_SSRC;
            if on_rtx {
                rtx_octets += size;
            }
            if out.message.custom::<ProbePacket>().is_some() {
                probe_packets += 1;
                if on_rtx {
                    probe_rtx_packets += 1;
                }
            }
            let mut extension = packet
                .header
                .get_extension(TWCC_ID)
                .expect("every packet is numbered transport-wide");
            let transport_sequence =
                rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(
                    &mut extension,
                )
                .expect("transport-cc extension")
                .transport_sequence;
            offered += 1;
            if !path.offer(out.now, transport_sequence, (size * 8) as f64) {
                dropped += 1;
            }
        }

        // The receiver reports every 100 ms on what has arrived, in transport-wide order.
        path.drain_to(now);
        pending.extend(path.take_arrivals());
        if elapsed >= next_feedback {
            next_feedback += Duration::from_millis(100);
            pending.sort_by_key(|arrival| arrival.twcc_sequence_number);
            // Only a run without gaps can be reported: what is still on the path is not lost.
            let mut run_length = 0;
            for (index, arrival) in pending.iter().enumerate() {
                if index > 0
                    && arrival.twcc_sequence_number
                        != pending[index - 1].twcc_sequence_number.wrapping_add(1)
                {
                    break;
                }
                run_length = index + 1;
            }
            let reported: Vec<Arrival> = pending.drain(..run_length).collect();
            if let Some(feedback) = feedback(now, epoch, &reported) {
                chain.handle_read(feedback).unwrap();
            }
        }
        while chain.poll_read().is_some() {}

        elapsed += step;
    }

    Run {
        reached,
        peak,
        final_share: handle.target_bitrate() / CAPACITY,
        probe_packets,
        probe_rtx_packets,
        rtx_share: rtx_octets as f64 / octets.max(1) as f64,
        loss: dropped as f64 / offered.max(1) as f64,
    }
}

fn print(title: &str, run: &Run) {
    println!(
        "{title}: 90% of capacity after {:?}, peak {:.0} kbit/s, final {:.2} of capacity, \
         {} probe packets ({} on RTX), RTX {:.2}% of octets, loss {:.2}%",
        run.reached,
        run.peak / 1000.0,
        run.final_share,
        run.probe_packets,
        run.probe_rtx_packets,
        run.rtx_share * 100.0,
        run.loss * 100.0,
    );
}

/// The default: no probing, no probe packet ever, and the climb from 300 kbit/s to 2.5 Mbit/s
/// is the delay-based controller's own, 8% a second: more than fifteen seconds.
#[test]
fn without_probing_the_estimate_climbs_at_the_controllers_pace() {
    let outcome = run(false, true, 1.0, Duration::from_secs(60));
    print("without probing", &outcome);

    assert_eq!(0, outcome.probe_packets, "probing is off by default");
    assert_eq!(
        0.0, outcome.rtx_share,
        "and nothing is sent that was not written"
    );
    let reached = outcome.reached.expect("the capacity is found in the end");
    assert!(
        reached > Duration::from_secs(15),
        "8% a second from 300 kbit/s: {reached:?}"
    );
}

/// With probing the same path is found in under three seconds (measured: 0.4 s, against 26.1 s
/// without): the clusters at three and six times the starting rate arrive as they left, the
/// one after them meets the bottleneck, and the estimate is what that one measured. The
/// clusters are filled with retransmissions on the RTX stream (18 packets in the whole run),
/// the estimate does not run past the capacity, and the path drops no more than it does under
/// the controller's own search around the capacity (3% here over a minute at the capacity,
/// 1.8% without probing over the half minute it spends there).
#[test]
fn with_probing_the_capacity_is_found_within_seconds() {
    let outcome = run(true, true, 1.0, Duration::from_secs(60));
    print("with probing", &outcome);

    let reached = outcome.reached.expect("the capacity is found");
    assert!(reached < Duration::from_secs(3), "{reached:?}");
    assert!(outcome.probe_packets >= 10, "{}", outcome.probe_packets);
    assert!(
        outcome.probe_rtx_packets > 0,
        "the clusters were filled from the RTX stream"
    );
    assert!(
        outcome.peak <= 1.2 * CAPACITY,
        "the estimate stays near what the path carries: {}",
        outcome.peak
    );
    assert!(
        (0.5..=1.1).contains(&outcome.final_share),
        "{}",
        outcome.final_share
    );
    assert!(outcome.rtx_share < 0.05, "{}", outcome.rtx_share);
    assert!(outcome.loss < 0.05, "{}", outcome.loss);
}

/// Without RTX there is nothing to fill a cluster with but the application's own media: the
/// sender never puts a second copy of a packet on the media stream, and the estimate still
/// climbs at least as the controller alone would.
#[test]
fn without_rtx_probing_adds_no_packet_of_its_own() {
    let outcome = run(true, false, 1.0, Duration::from_secs(60));
    print("with probing, no RTX", &outcome);

    assert_eq!(0, outcome.probe_rtx_packets);
    assert_eq!(0.0, outcome.rtx_share);
    assert!(outcome.reached.is_some());
}

/// An application that sends a fifth of what it may: the delay-based controller learns nothing
/// about the room above what is sent, and without probing the estimate is bound to one and a
/// half times the received rate (draft-ietf-rmcat-gcc-02 section 5.5). With it, a cluster
/// every five seconds measures the path, and the estimate rests on the last measurement: near
/// the capacity, never past it (measured: 0.95 of it at the end, peak 2.37 Mbit/s). The price
/// is the clusters, here on the RTX stream: 58 packets in 30 s, 3.8% of the octets.
#[test]
fn an_application_limited_sender_is_probed_now_and_then() {
    let outcome = run(true, true, 0.2, Duration::from_secs(30));
    print("with probing, application limited", &outcome);

    assert!(
        outcome.probe_packets >= 15,
        "start-up clusters and one every five seconds: {}",
        outcome.probe_packets
    );
    assert!(outcome.peak <= 1.2 * CAPACITY, "{}", outcome.peak);
    assert!(
        (0.5..=1.1).contains(&outcome.final_share),
        "{}",
        outcome.final_share
    );
    assert!(outcome.rtx_share < 0.3, "{}", outcome.rtx_share);
    assert!(outcome.loss < 0.02, "{}", outcome.loss);
}
