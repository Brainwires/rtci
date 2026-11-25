use super::*;
use crate::stream_info::{RTCPFeedback, RTPHeaderExtension};

const SSRC: u32 = 0x5151_0001;
const AST_ID: u8 = 3;

fn remote(remb: bool, transport_cc: bool, abs_send_time: bool) -> StreamInfo {
    let mut rtcp_feedback = Vec::new();
    if remb {
        rtcp_feedback.push(RTCPFeedback {
            typ: GOOG_REMB.to_owned(),
            parameter: String::new(),
        });
    }
    let mut rtp_header_extensions = Vec::new();
    if transport_cc {
        rtcp_feedback.push(RTCPFeedback {
            typ: "transport-cc".to_owned(),
            parameter: String::new(),
        });
        rtp_header_extensions.push(RTPHeaderExtension {
            uri: crate::twcc::TRANSPORT_CC_URI.to_owned(),
            id: 5,
        });
    }
    if abs_send_time {
        rtp_header_extensions.push(RTPHeaderExtension {
            uri: ABS_SEND_TIME_URI.to_owned(),
            id: u16::from(AST_ID),
        });
    }
    StreamInfo {
        ssrc: SSRC,
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        rtcp_feedback,
        rtp_header_extensions,
        ..Default::default()
    }
}

/// The path: `capacity` bit/s, a FIFO, 20 ms of propagation. Packets of 1000 octets sent at
/// `rate(t)`, 30 frames a second (one RTP timestamp per frame). Returns every REMB sent, with
/// the second it was sent at.
fn run(
    info: &StreamInfo,
    seconds: u64,
    capacity: f64,
    rate: impl Fn(f64) -> f64,
) -> Vec<(f64, ReceiverEstimatedMaximumBitrate)> {
    let mut remb = RembGeneratorBuilder::new().with_sender_ssrc(7).build();
    remb.bind_remote_stream(info);
    let epoch = Instant::now();
    let mut stamp = AbsSendTimeInterceptor::new();
    let mut local = info.clone();
    local.ssrc = SSRC;
    stamp.bind_local_stream(&local);

    let mut in_flight: VecDeque<(Duration, TaggedPacket)> = VecDeque::new();
    let mut free_at = Duration::ZERO;
    let mut next_send = Duration::ZERO;
    let mut sequence = 0u16;
    let mut out = Vec::new();
    let step = Duration::from_millis(1);
    let mut elapsed = Duration::ZERO;
    while elapsed < Duration::from_secs(seconds) {
        let now = epoch + elapsed;
        while next_send <= elapsed {
            let frame = (next_send.as_secs_f64() * 30.0).floor() / 30.0;
            let packet = TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        payload_type: 96,
                        sequence_number: sequence,
                        timestamp: (frame * 90_000.0) as u32,
                        ssrc: SSRC,
                        ..Default::default()
                    },
                    payload: vec![0u8; 988].into(),
                })),
            };
            sequence = sequence.wrapping_add(1);
            stamp.handle_write(packet).unwrap();
            let packet = stamp.poll_write().unwrap();
            let serialization = Duration::from_secs_f64(8_000.0 / capacity);
            free_at = free_at.max(elapsed) + serialization;
            in_flight.push_back((free_at + Duration::from_millis(20), packet));
            next_send += Duration::from_secs_f64(8_000.0 / rate(elapsed.as_secs_f64()));
        }
        while in_flight.front().is_some_and(|(at, _)| *at <= elapsed) {
            let (_, mut packet) = in_flight.pop_front().unwrap();
            packet.now = now;
            remb.handle_read(packet).unwrap();
        }
        while remb.poll_read().is_some() {}
        if remb.poll_timeout().is_some_and(|at| at <= now) {
            remb.handle_timeout(now).unwrap();
        }
        while let Some(packet) = remb.poll_write() {
            if let Packet::Rtcp(packets) = packet.message.packet {
                for packet in packets {
                    if let Some(remb) = packet
                        .as_any()
                        .downcast_ref::<ReceiverEstimatedMaximumBitrate>()
                    {
                        out.push((elapsed.as_secs_f64(), remb.clone()));
                    }
                }
            }
        }
        elapsed += step;
    }
    out
}

/// draft-ietf-rmcat-gcc-02 section 3 (receive-side variant, and REMB at least once a second):
/// a stream that negotiated `goog-remb` and no per-packet feedback gets a REMB from its first
/// estimate on (the incoming rate after five seconds), naming it, from the configured SSRC,
/// with no more than a second between two.
#[test]
fn a_remb_stream_gets_an_estimate_at_least_once_a_second() {
    for abs_send_time in [false, true] {
        let rembs = run(
            &remote(true, false, abs_send_time),
            20,
            10_000_000.0,
            |_| 800_000.0,
        );
        assert!(!rembs.is_empty(), "abs-send-time {abs_send_time}");
        let first = rembs[0].0;
        assert!(
            (5.0..6.0).contains(&first),
            "the first after the initialisation time: {first}"
        );
        for pair in rembs.windows(2) {
            assert!(pair[1].0 - pair[0].0 <= 1.0 + 1e-9, "{pair:?}");
        }
        let (_, last) = rembs.last().unwrap();
        assert_eq!(7, last.sender_ssrc);
        assert_eq!(vec![SSRC], last.ssrcs);
        assert!(
            (600_000.0..=1_300_000.0).contains(&f64::from(last.bitrate)),
            "abs-send-time {abs_send_time}: {}",
            last.bitrate
        );
    }
}

/// Section 3: "as soon as congestion is detected". The sender goes from 800 kbit/s to 2 Mbit/s
/// over a 1 Mbit/s path at 10 s: the queue grows, and a lower REMB follows within the half
/// second, long before the next periodic one would.
#[test]
fn congestion_sends_a_lower_remb_at_once() {
    for abs_send_time in [false, true] {
        let rembs = run(&remote(true, false, abs_send_time), 16, 1_000_000.0, |t| {
            if t < 10.0 { 800_000.0 } else { 2_000_000.0 }
        });
        let before = rembs
            .iter()
            .rev()
            .find(|(at, _)| *at < 10.0)
            .map(|(_, remb)| f64::from(remb.bitrate))
            .expect("an estimate before the change");
        let lower = rembs
            .iter()
            .find(|(at, remb)| *at >= 10.0 && f64::from(remb.bitrate) < 0.97 * before)
            .map(|(at, _)| *at)
            .expect("a lower estimate after it");
        assert!(lower < 10.6, "abs-send-time {abs_send_time}: at {lower}");
        let later: Vec<f64> = rembs
            .iter()
            .filter(|(at, _)| *at > 13.0)
            .map(|(_, remb)| f64::from(remb.bitrate))
            .collect();
        assert!(
            later.iter().all(|bitrate| *bitrate <= 1_200_000.0),
            "abs-send-time {abs_send_time}: {later:?}"
        );
    }
}

/// With transport-wide feedback (or RFC 8888) negotiated the sender estimates for itself; a
/// stream without `goog-remb` did not ask for REMB. Neither gets one.
#[test]
fn no_remb_without_goog_remb_or_with_per_packet_feedback() {
    assert!(run(&remote(true, true, false), 10, 10_000_000.0, |_| 800_000.0).is_empty());
    assert!(
        run(&remote(false, false, false), 10, 10_000_000.0, |_| {
            800_000.0
        })
        .is_empty()
    );
}

/// Section 3: the sender of the receive-side variant stamps abs-send-time on its packets: 6.18
/// fixed-point seconds of the instant they pass, in the negotiated extension.
#[test]
fn abs_send_time_is_stamped_as_the_packet_passes() {
    let mut stamp = AbsSendTimeInterceptor::new();
    stamp.bind_local_stream(&remote(true, false, true));
    let epoch = Instant::now();
    let mut values = Vec::new();
    for ms in [0u64, 250, 1_500] {
        stamp
            .handle_write(TaggedPacket {
                now: epoch + Duration::from_millis(ms),
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        ssrc: SSRC,
                        ..Default::default()
                    },
                    payload: vec![0u8; 10].into(),
                })),
            })
            .unwrap();
        let Packet::Rtp(packet) = stamp.poll_write().unwrap().message.packet else {
            panic!("rtp");
        };
        let mut data = packet.header.get_extension(AST_ID).expect("stamped");
        values.push(
            rtp::extension::abs_send_time_extension::AbsSendTimeExtension::unmarshal(&mut data)
                .unwrap()
                .timestamp,
        );
    }
    assert_eq!(vec![0, 1 << 16, 3 << 17], values);
}

/// A packet sent again as it was (the answer to a NACK when no RTX is negotiated: the media
/// SSRC and the sequence number of the first transmission) keeps the stamp its first
/// transmission left with. Under SRTP it is the same packet index, which protects one packet
/// only (RFC 3711 section 3.3.1): with a new stamp it is a different packet, the SRTP sender
/// refuses it and the retransmission never leaves. An RTX retransmission, a new packet of
/// the retransmission stream, is stamped as it passes, and so is a packet that reuses a
/// sequence number without being a retransmission.
#[test]
fn a_packet_sent_again_as_it_was_keeps_its_abs_send_time() {
    const RTX_SSRC: u32 = 0x5151_0002;
    let mut stamp = AbsSendTimeInterceptor::new();
    let mut info = remote(true, false, true);
    info.ssrc_rtx = Some(RTX_SSRC);
    stamp.bind_local_stream(&info);
    let epoch = Instant::now();
    let mut pass = |ms: u64, ssrc: u32, sequence_number: u16, retransmission: bool| -> u64 {
        let mut message = AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                ssrc,
                sequence_number,
                ..Default::default()
            },
            payload: vec![0u8; 10].into(),
        }));
        if retransmission {
            message = message.with(crate::Attribute::Retransmission);
        }
        stamp
            .handle_write(TaggedPacket {
                now: epoch + Duration::from_millis(ms),
                transport: TransportContext::default(),
                message,
            })
            .unwrap();
        let Packet::Rtp(packet) = stamp.poll_write().unwrap().message.packet else {
            panic!("rtp");
        };
        let mut data = packet.header.get_extension(AST_ID).expect("stamped");
        rtp::extension::abs_send_time_extension::AbsSendTimeExtension::unmarshal(&mut data)
            .unwrap()
            .timestamp
    };

    assert_eq!(0, pass(0, SSRC, 100, false));
    assert_eq!(1 << 16, pass(250, SSRC, 101, false));
    // The packets again, half a second and more later: the stamps they first left with.
    assert_eq!(0, pass(500, SSRC, 100, true));
    assert_eq!(1 << 16, pass(750, SSRC, 101, true));
    assert_eq!(
        0,
        pass(1_000, SSRC, 100, true),
        "however often it is sent again"
    );
    // An RTX packet is a new packet: stamped as it passes (1.5 s is 3 << 17).
    assert_eq!(3 << 17, pass(1_500, RTX_SSRC, 7, true));
    // A retransmission of a packet never seen here is stamped as it passes.
    assert_eq!(3 << 17, pass(1_500, SSRC, 5000, true));
    // The same sequence number on a packet that is not a retransmission: a new stamp.
    assert_eq!(3 << 17, pass(1_500, SSRC, 100, false));
}
