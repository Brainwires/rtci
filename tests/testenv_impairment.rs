//! Data channels, RTP loss recovery, the jitter buffer and congestion control over a link that
//! netem impairs (loss, delay, jitter, reordering, a rate limit), between two hosts on the test
//! environment's WAN. Needs `scripts/test-env/run.sh`; ignored elsewhere.
//!
//! Each test sets the impairment it needs on both hosts' interfaces and clears it when done;
//! the tests share those two hosts, so they run one at a time (`SERIAL`).

mod common;
mod testenv;

use bytes::{Bytes, BytesMut};
use rtc::data_channel::RTCDataChannelInit;
use rtc::interceptor::{Gcc, JitterBufferBuilder, Registry, Slot};
use rtc::media::io::Writer;
use rtc::media::io::ivf_reader::IVFReader;
use rtc::media::io::ivf_writer::IVFWriter;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::interceptor_registry::{
    CongestionFeedback, configure_congestion_control, configure_nack,
};
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::RTCRtpSenderId;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtc::statistics::StatsSelector;
use std::collections::HashSet;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use testenv::{Env, EnvPeer, Gather, negotiate, pump};

static SERIAL: Mutex<()> = Mutex::new(());

/// netem on both hosts' WAN interfaces for the guard's lifetime.
struct Netem;

impl Netem {
    fn set(args: &str) -> Netem {
        for ns in ["open-a", "open-b"] {
            let _ = Command::new("ip")
                .args([
                    "netns", "exec", ns, "tc", "qdisc", "del", "dev", "eth0", "root",
                ])
                .output();
            if args.is_empty() {
                continue;
            }
            let mut cmd = Command::new("ip");
            cmd.args([
                "netns", "exec", ns, "tc", "qdisc", "add", "dev", "eth0", "root", "netem",
            ]);
            cmd.args(args.split_whitespace());
            let out = cmd.output().expect("tc");
            assert!(
                out.status.success(),
                "tc netem {args} in {ns}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        eprintln!("NETEM: {}", if args.is_empty() { "none" } else { args });
        Netem
    }
}

impl Drop for Netem {
    fn drop(&mut self) {
        for ns in ["open-a", "open-b"] {
            let _ = Command::new("ip")
                .args([
                    "netns", "exec", ns, "tc", "qdisc", "del", "dev", "eth0", "root",
                ])
                .output();
        }
    }
}

fn pair(env: &Env, a: RTCPeerConnection, b: RTCPeerConnection) -> (EnvPeer, EnvPeer) {
    (
        EnvPeer::new("a", "open-a", Gather::HOST, env, a).expect("peer a"),
        EnvPeer::new("b", "open-b", Gather::HOST, env, b).expect("peer b"),
    )
}

fn plain_pc() -> RTCPeerConnection {
    RTCPeerConnectionBuilder::new()
        .build(Instant::now())
        .unwrap()
}

fn dc_open_id(p: &EnvPeer) -> Option<rtc::data_channel::RTCDataChannelId> {
    p.events.iter().find_map(|e| match e {
        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => Some(*id),
        _ => None,
    })
}

fn dc_messages(p: &EnvPeer) -> Vec<u32> {
    p.reads
        .iter()
        .filter_map(|m| match &m.message {
            RTCMessage::DataChannelMessage(_, msg) => {
                Some(u32::from_be_bytes(msg.data[..4].try_into().unwrap()))
            }
            _ => None,
        })
        .collect()
}

/// What `send_numbered` saw: the numbers b received, in order of arrival, and (when not every
/// message was expected) how long after the first send a's send queue had given up the last one.
struct Delivery {
    got: Vec<u32>,
    drained_after: Option<Duration>,
}

/// Sends `count` numbered 1 KiB messages from a to b over a channel made with `init`.
fn send_numbered(
    init: RTCDataChannelInit,
    count: u32,
    timeout: Duration,
    expect_all: bool,
) -> Delivery {
    common::install_crypto_provider();
    let env = Env::get();
    let (mut a, mut b) = pair(&env, plain_pc(), plain_pc());
    a.pc.create_data_channel("impaired", Some(init)).unwrap();
    negotiate(&mut a, &mut b).unwrap();
    let mut next = 0u32;
    let mut last_send = Instant::now();
    let started = Instant::now();
    let mut drained_at: Option<Instant> = None;
    pump(&mut [&mut a, &mut b], timeout, |p| {
        if let Some(id) = dc_open_id(p[0])
            && next < count
            && last_send.elapsed() >= Duration::from_millis(2)
            && let Some(mut dc) = p[0].pc.data_channel(id)
        {
            let mut payload = next.to_be_bytes().to_vec();
            payload.resize(1024, 0xab);
            if dc
                .send(Instant::now(), BytesMut::from(&payload[..]))
                .is_ok()
            {
                next += 1;
                last_send = Instant::now();
            }
        }
        let got = dc_messages(p[1]).len() as u32;
        if expect_all {
            got >= count
        } else {
            // Done once the send queue has given up every message (sent, or abandoned before
            // sending), plus time for the last ones to arrive.
            let dequeued = dc_open_id(p[0])
                .and_then(|id| p[0].pc.data_channel(id))
                .map_or(0, |dc| dc.bytes_dequeued());
            if next >= count && dequeued >= count as u64 * 1024 && drained_at.is_none() {
                drained_at = Some(Instant::now());
            }
            drained_at.is_some_and(|t| t.elapsed() > Duration::from_secs(2))
        }
    })
    .unwrap();
    if !expect_all {
        eprintln!(
            "send queue drained {} after the first send",
            drained_at.map_or("never".to_owned(), |t| format!(
                "{:.1} s",
                (t - started).as_secs_f64()
            ))
        );
    }
    assert_eq!(
        next,
        count,
        "a could not send everything (state {:?})",
        a.connection_state()
    );
    let dc_stats = |p: &mut EnvPeer| {
        let r = p.pc.get_stats(Instant::now(), StatsSelector::None);
        r.data_channels()
            .map(|d| format!("sent {} received {}", d.messages_sent, d.messages_received))
            .collect::<Vec<_>>()
    };
    eprintln!(
        "data channel stats: a {:?}, b {:?}; packets a sent {} (refused {}) received {}, b sent {} received {}",
        dc_stats(&mut a),
        dc_stats(&mut b),
        a.sent_direct,
        a.send_errors,
        a.recv_direct,
        b.sent_direct,
        b.recv_direct
    );
    Delivery {
        got: dc_messages(&b),
        drained_after: drained_at.map(|t| t - started),
    }
}

#[test]
#[ignore = "needs the real-network test environment (netem): scripts/test-env/run.sh"]
fn reliable_ordered_channel_survives_loss_and_reordering() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _netem = Netem::set("delay 40ms 10ms distribution normal loss 5% reorder 10% 50%");
    let got = send_numbered(
        RTCDataChannelInit {
            ordered: true,
            ..Default::default()
        },
        500,
        Duration::from_secs(90),
        true,
    )
    .got;
    assert_eq!(
        got,
        (0..500).collect::<Vec<_>>(),
        "every message, once, in order"
    );
}

#[test]
#[ignore = "needs the real-network test environment (netem): scripts/test-env/run.sh"]
fn reliable_unordered_channel_delivers_everything() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _netem = Netem::set("delay 30ms 15ms loss 5% reorder 25% 50%");
    let got = send_numbered(
        RTCDataChannelInit {
            ordered: false,
            ..Default::default()
        },
        500,
        Duration::from_secs(90),
        true,
    )
    .got;
    let unique: HashSet<u32> = got.iter().copied().collect();
    assert_eq!(unique.len(), 500, "every message arrives");
    assert_eq!(got.len(), 500, "and only once");
}

#[test]
#[ignore = "needs the real-network test environment (netem): scripts/test-env/run.sh"]
fn unreliable_channel_loses_without_retransmitting() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _netem = Netem::set("delay 20ms loss 10%");
    let Delivery { got, drained_after } = send_numbered(
        RTCDataChannelInit {
            ordered: false,
            max_retransmits: Some(0),
            ..Default::default()
        },
        1000,
        Duration::from_secs(90),
        false,
    );
    let unique: HashSet<u32> = got.iter().copied().collect();
    eprintln!(
        "unreliable: {} of 1000 delivered over a 10%-loss link (each way), queue drained after {drained_after:?}",
        unique.len()
    );
    assert_eq!(unique.len(), got.len(), "no duplicates");
    // A link that drops 10% of packets each way delivers about 90% of single-packet messages
    // sent without retransmission (RFC 3758: an abandoned message is skipped with FORWARD-TSN,
    // never re-sent). Fewer than 800 means the sender stalled or abandoned messages it never
    // sent; more than 960 means the loss did not apply or something retransmitted.
    assert!(
        (800..=960).contains(&unique.len()),
        "{} of 1000 delivered over a 10%-loss link; expected 800 to 960",
        unique.len()
    );
    // One message every 2 ms is 2 s of sending; the queue must not hold messages back for
    // long after (a stall the delivery count alone could hide).
    let drained_after = drained_after.expect("the send queue never drained");
    assert!(
        drained_after < Duration::from_secs(30),
        "the send queue took {drained_after:?} to drain"
    );
}

const VP8_PT: u8 = 96;

fn vp8_codec() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: String::new(),
        rtcp_feedback: vec![],
    }
}

#[derive(Clone, Copy, Default)]
struct Chain {
    nack: bool,
    jitter_buffer: bool,
    gcc: bool,
}

fn video_pc(chain: Chain) -> RTCPeerConnection {
    let mut me = MediaEngine::default();
    me.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: vp8_codec(),
            payload_type: VP8_PT,
        },
        RtpCodecKind::Video,
    )
    .unwrap();
    let mut registry = Registry::new();
    if chain.nack {
        registry = configure_nack(registry, &mut me);
    }
    if chain.jitter_buffer {
        registry = registry.with(
            Slot::JitterBuffer,
            JitterBufferBuilder::new()
                .with_depth(Duration::from_millis(250))
                .build(),
        );
    }
    if chain.gcc {
        registry = configure_congestion_control(
            registry,
            Gcc::default(),
            CongestionFeedback::Twcc,
            &mut me,
        )
        .unwrap();
    }
    RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .with_interceptor_registry(registry)
        .build(Instant::now())
        .unwrap()
}

fn add_video_track(pc: &mut RTCPeerConnection, ssrc: u32) -> RTCRtpSenderId {
    pc.add_track(MediaStreamTrack::new(
        "env-stream".to_owned(),
        "env-video".to_owned(),
        "env-video".to_owned(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: vp8_codec(),
            ..Default::default()
        }],
    ))
    .unwrap()
}

fn negotiated_pt(pc: &mut RTCPeerConnection, id: RTCRtpSenderId) -> u8 {
    pc.rtp_sender(id)
        .and_then(|mut s| {
            s.get_parameters()
                .rtp_parameters
                .codecs
                .first()
                .map(|c| c.payload_type)
        })
        .unwrap_or(VP8_PT)
}

fn rtp_received(p: &EnvPeer) -> impl Iterator<Item = &rtc::rtp::Packet> {
    p.reads.iter().filter_map(|m| match &m.message {
        RTCMessage::RtpPacket(_, pkt) => Some(pkt),
        _ => None,
    })
}

/// Sends `count` 1000-byte RTP packets at 200 packets/s and returns the fraction of distinct
/// sequence numbers the receiver got (after any recovery the chain does).
fn rtp_delivery(chain: Chain, count: u16) -> f64 {
    common::install_crypto_provider();
    let env = Env::get();
    let (mut a, mut b) = pair(&env, video_pc(chain), video_pc(chain));
    let ssrc = 0x1234_5678;
    let sender = add_video_track(&mut a.pc, ssrc);
    negotiate(&mut a, &mut b).unwrap();
    let mut sent = 0u16;
    let mut last = Instant::now();
    let start_seq = 1000u16;
    let mut done_at: Option<Instant> = None;
    pump(&mut [&mut a, &mut b], Duration::from_secs(60), |p| {
        if p[0].connected()
            && p[1].connected()
            && sent < count
            && last.elapsed() >= Duration::from_millis(5)
        {
            let pt = negotiated_pt(&mut p[0].pc, sender);
            let mut s = p[0].pc.rtp_sender(sender).unwrap();
            let seq = start_seq.wrapping_add(sent);
            let _ = s.write_rtp(
                Instant::now(),
                rtc::rtp::Packet {
                    header: rtc::rtp::header::Header {
                        version: 2,
                        payload_type: pt,
                        sequence_number: seq,
                        timestamp: sent as u32 * 450,
                        ssrc,
                        marker: true,
                        ..Default::default()
                    },
                    payload: Bytes::from(vec![0x10u8; 1000]),
                },
            );
            sent += 1;
            last = Instant::now();
            if sent == count {
                done_at = Some(Instant::now());
            }
        }
        // Let retransmissions settle after the last packet.
        done_at.is_some_and(|t| t.elapsed() > Duration::from_secs(3))
    })
    .unwrap();
    assert_eq!(
        sent,
        count,
        "sender never connected: {:?} / {:?}",
        a.connection_state(),
        b.connection_state()
    );
    let seqs: HashSet<u16> = rtp_received(&b)
        .filter(|p| p.header.ssrc == ssrc)
        .map(|p| p.header.sequence_number)
        .collect();
    seqs.len() as f64 / count as f64
}

#[test]
#[ignore = "needs the real-network test environment (netem): scripts/test-env/run.sh"]
fn nack_recovers_lost_rtp() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _netem = Netem::set("delay 30ms 5ms loss 5%");
    let without = rtp_delivery(Chain::default(), 2000);
    let with = rtp_delivery(
        Chain {
            nack: true,
            ..Default::default()
        },
        2000,
    );
    eprintln!(
        "RTP over 5% loss (each way): {:.2}% delivered without NACK, {:.2}% with",
        without * 100.0,
        with * 100.0
    );
    assert!(without < 0.98, "the link is not lossy ({without})");
    // Every packet: NACK retransmits a lost one until it arrives (RFC 4585 6.2.1), and the
    // run waits 3 s after the last packet for the repairs.
    assert!(with >= 1.0, "NACK left {:.2}% lost", (1.0 - with) * 100.0);
}

/// A VP8 stream GStreamer encoded (`run.sh`: videotestsrc ! vp8enc ! ivfmux) goes through
/// loss, jitter and reordering with NACK and the jitter buffer; the receiver depacketizes it
/// into an IVF file that `run.sh` then decodes with GStreamer.
#[test]
#[ignore = "needs the real-network test environment (netem, GStreamer fixtures): scripts/test-env/run.sh"]
fn vp8_file_through_nack_and_jitter_buffer() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _netem = Netem::set("delay 40ms 20ms distribution normal loss 2% reorder 10% 50%");
    common::install_crypto_provider();
    let env = Env::get();
    let media = std::env::var("RTC_TESTENV_MEDIA").expect("RTC_TESTENV_MEDIA");
    let (mut ivf, header) =
        IVFReader::new(std::fs::File::open(format!("{media}/vp8.ivf")).unwrap()).unwrap();
    let mut frames = vec![];
    while let Ok((f, _)) = ivf.parse_next_frame() {
        frames.push(f.freeze());
    }
    assert!(frames.len() >= 100, "fixture has {} frames", frames.len());

    let chain = Chain {
        nack: true,
        jitter_buffer: true,
        gcc: false,
    };
    let (mut a, mut b) = pair(&env, video_pc(chain), video_pc(chain));
    let ssrc = 0x0bad_cafe;
    let sender = add_video_track(&mut a.pc, ssrc);
    negotiate(&mut a, &mut b).unwrap();
    let out_path = format!("{media}/received-vp8.ivf");
    let mut writer = IVFWriter::new(std::fs::File::create(&out_path).unwrap(), &header).unwrap();
    let mut packetizer = None;
    let mut next = 0usize;
    let mut last = Instant::now();
    let mut done_at = None;
    let mut written = 0usize;
    pump(&mut [&mut a, &mut b], Duration::from_secs(90), |p| {
        if p[0].connected()
            && p[1].connected()
            && next < frames.len()
            && last.elapsed() >= Duration::from_millis(33)
        {
            let pt = negotiated_pt(&mut p[0].pc, sender);
            let pk = packetizer.get_or_insert_with(|| {
                rtc::rtp::packetizer::new_packetizer(
                    Instant::now(),
                    1200,
                    pt,
                    ssrc,
                    vp8_codec().payloader().unwrap(),
                    Box::new(rtc::rtp::sequence::new_random_sequencer()),
                    90000,
                )
            });
            use rtc::rtp::packetizer::Packetizer;
            let packets = pk.packetize(Instant::now(), &frames[next], 3000).unwrap();
            let mut s = p[0].pc.rtp_sender(sender).unwrap();
            for pkt in packets {
                let _ = s.write_rtp(Instant::now(), pkt);
            }
            next += 1;
            last = Instant::now();
            if next == frames.len() {
                done_at = Some(Instant::now());
            }
        }
        for m in p[1].reads.drain(..) {
            if let RTCMessage::RtpPacket(_, pkt) = m.message {
                writer.write_rtp(&pkt).unwrap();
                written += 1;
            }
        }
        done_at.is_some_and(|t: Instant| t.elapsed() > Duration::from_secs(3))
    })
    .unwrap();
    writer.close().unwrap();
    assert_eq!(next, frames.len(), "sender never connected");
    let (mut out, _) = IVFReader::new(std::fs::File::open(&out_path).unwrap()).unwrap();
    let mut got = vec![];
    while let Ok((f, _)) = out.parse_next_frame() {
        got.push(f.freeze());
    }
    // A lost frame shifts every later one, so match by content rather than position.
    let sent: HashSet<&Bytes> = frames.iter().collect();
    let exact = got.iter().filter(|g| sent.contains(g)).count();
    eprintln!(
        "VP8: sent {} frames, received {} ({exact} byte-identical to a sent frame, {written} packets)",
        frames.len(),
        got.len()
    );
    assert!(
        got.len() as f64 >= frames.len() as f64 * 0.98,
        "only {} of {} frames",
        got.len(),
        frames.len()
    );
    assert!(
        exact as f64 >= got.len() as f64 * 0.98,
        "{} of {} received frames match no sent frame",
        got.len() - exact,
        got.len()
    );
}

/// GCC (transport-wide congestion control feedback) brings its target down to a link that
/// netem limits to 600 kbit/s, while the sender offers ~2.4 Mbit/s.
#[test]
#[ignore = "needs the real-network test environment (netem): scripts/test-env/run.sh"]
fn gcc_follows_a_rate_limited_link() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _netem = Netem::set("delay 20ms rate 600kbit limit 200");
    common::install_crypto_provider();
    let env = Env::get();
    let chain = Chain {
        nack: false,
        jitter_buffer: false,
        gcc: true,
    };
    let (mut a, mut b) = pair(&env, video_pc(chain), video_pc(chain));
    let ssrc = 0x6cc0_0001;
    let sender = add_video_track(&mut a.pc, ssrc);
    negotiate(&mut a, &mut b).unwrap();
    let mut seq = 0u16;
    let mut last = Instant::now();
    let mut connected_at = None;
    let mut samples = vec![];
    let mut last_sample = Instant::now();
    pump(&mut [&mut a, &mut b], Duration::from_secs(45), |p| {
        if p[0].connected() && p[1].connected() {
            connected_at.get_or_insert_with(Instant::now);
            if last.elapsed() >= Duration::from_millis(4) {
                let pt = negotiated_pt(&mut p[0].pc, sender);
                let mut s = p[0].pc.rtp_sender(sender).unwrap();
                let _ = s.write_rtp(
                    Instant::now(),
                    rtc::rtp::Packet {
                        header: rtc::rtp::header::Header {
                            version: 2,
                            payload_type: pt,
                            sequence_number: seq,
                            timestamp: seq as u32 * 360,
                            ssrc,
                            ..Default::default()
                        },
                        payload: Bytes::from(vec![0u8; 1200]),
                    },
                );
                seq = seq.wrapping_add(1);
                last = Instant::now();
            }
            if last_sample.elapsed() >= Duration::from_secs(1) {
                last_sample = Instant::now();
                let report = p[0].pc.get_stats(Instant::now(), StatsSelector::None);
                if let Some(o) = report
                    .outbound_rtp_streams()
                    .find(|o| o.sent_rtp_stream_stats.rtp_stream_stats.ssrc == ssrc)
                {
                    samples.push(o.target_bitrate);
                }
            }
        }
        connected_at.is_some_and(|t: Instant| t.elapsed() > Duration::from_secs(30))
    })
    .unwrap();
    eprintln!("GCC target (bit/s, one per second): {samples:?}");
    assert!(samples.len() >= 20, "too few samples: {samples:?}");
    let tail = &samples[samples.len() - 5..];
    let mean = tail.iter().sum::<f64>() / tail.len() as f64;
    assert!(mean > 0.0, "no estimate");
    // The target settles at or below the bottleneck (draft-ietf-rmcat-gcc-02 5.5: on
    // overuse the rate drops to 0.85 x the acknowledged rate), with headroom for the
    // estimate's swing; above 660 kbit/s it overshoots the link, under 300 it collapsed.
    assert!(
        (300_000.0..=660_000.0).contains(&mean),
        "GCC's target over the last 5 s is {mean:.0} bit/s on a 600 kbit/s link; expected 300 to 660 kbit/s"
    );
}
