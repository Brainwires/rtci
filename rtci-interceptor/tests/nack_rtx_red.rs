//! RFC 4588 section 8.1: "apt (associated payload type) ... the value of this parameter is the
//! payload type of the associated original stream", and section 8.6: "the retransmission
//! payload type is mapped to the payload type of the original stream with the apt parameter".
//! A retransmission therefore goes under the RTX format whose `apt` is the payload type the
//! packet LEFT under, which is not always the one its stream was bound with: video in RED
//! (RFC 2198; RFC 5109 section 14.2) leaves under the `red` payload type, and its RTX format
//! is the one with `apt=<red>`. libwebrtc: `modules/rtp_rtcp/source/rtp_sender.cc`,
//! `rtx_payload_type_map_.find(packet.PayloadType())`.

use bytes::Bytes;
use rtci_interceptor::{
    AttributedPacket, Interceptor, NackResponderBuilder, Packet, RTCPFeedback, RedPlacement,
    Registry, RetransmissionRateLimit, Slot, StreamInfo, TaggedPacket, UlpfecReceiveBuilder,
    UlpfecSendBuilder,
};
use rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use sansio::Protocol;
use shared::TransportContext;
use std::time::Instant;

const SSRC: u32 = 0x1234;
const RTX_SSRC: u32 = 0x5678;
const VP8: u8 = 96;
const VP8_RTX: u8 = 97;
const VP9: u8 = 98;
const RED: u8 = 116;
const RED_RTX: u8 = 117;
const ULPFEC: u8 = 43;

/// A VP8 stream of a section that also has RED with its own RTX and ULPFEC, as the `Chrome`
/// profile and Chromium describe video; VP9 has no retransmission format.
fn stream() -> StreamInfo {
    StreamInfo {
        ssrc: SSRC,
        ssrc_rtx: Some(RTX_SSRC),
        payload_type: VP8,
        payload_type_rtx: Some(VP8_RTX),
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_owned(),
            parameter: String::new(),
        }],
        section_mime_types: vec![
            (VP8, "video/VP8".to_owned()),
            (VP8_RTX, "video/rtx".to_owned()),
            (VP9, "video/VP9".to_owned()),
            (RED, "video/red".to_owned()),
            (RED_RTX, "video/rtx".to_owned()),
            (ULPFEC, "video/ulpfec".to_owned()),
        ],
        section_fmtp_lines: vec![
            (VP8, String::new()),
            (VP8_RTX, format!("apt={VP8}")),
            (VP9, String::new()),
            (RED, String::new()),
            (RED_RTX, format!("apt={RED};rtx-time=3000")),
            (ULPFEC, String::new()),
        ],
        ..Default::default()
    }
}

fn tagged(now: Instant, packet: Packet) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(packet),
    }
}

fn media(payload_type: u8, sequence_number: u16) -> rtp::Packet {
    rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            marker: true,
            payload_type,
            sequence_number,
            timestamp: u32::from(sequence_number) * 3000,
            ssrc: SSRC,
            ..Default::default()
        },
        payload: Bytes::from(vec![0x10, sequence_number as u8, 0xAA, 0xBB]),
    }
}

fn nack(now: Instant, sequence_number: u16) -> TaggedPacket {
    tagged(
        now,
        Packet::Rtcp(vec![Box::new(TransportLayerNack {
            sender_ssrc: 1,
            media_ssrc: SSRC,
            nacks: vec![NackPair {
                packet_id: sequence_number,
                lost_packets: 0,
            }],
        })]),
    )
}

fn responder() -> rtci_interceptor::NackResponderInterceptor {
    NackResponderBuilder::new()
        .with_rate_limit(RetransmissionRateLimit::Unlimited)
        .build()
}

/// What `chain` writes next that is RTP.
fn written(chain: &mut impl Interceptor) -> Vec<rtp::Packet> {
    std::iter::from_fn(|| chain.poll_write())
        .filter_map(|tagged| match tagged.message.packet {
            Packet::Rtp(packet) => Some(packet),
            _ => None,
        })
        .collect()
}

/// RFC 4588 section 4, as a receiver does it: the payload type is the `apt` of the format the
/// retransmission arrived under, the sequence number the OSN, the SSRC the original stream's.
fn restored(rtx: &rtp::Packet, info: &StreamInfo) -> rtp::Packet {
    let (_, fmtp) = info
        .section_fmtp_lines
        .iter()
        .find(|(payload_type, _)| *payload_type == rtx.header.payload_type)
        .expect("the format the retransmission arrived under");
    let apt = fmtp
        .split(';')
        .find_map(|parameter| parameter.trim().strip_prefix("apt="))
        .and_then(|value| value.parse::<u8>().ok())
        .expect("an apt");
    let mut packet = rtx.clone();
    packet.header.ssrc = info.ssrc;
    packet.header.payload_type = apt;
    packet.header.sequence_number = u16::from_be_bytes([rtx.payload[0], rtx.payload[1]]);
    packet.payload = rtx.payload.slice(2..);
    packet
}

/// Video the FEC encoder rewrote into RED is retransmitted under the RTX format of `red`,
/// and a receiver that restores it by that format's `apt` and opens the RED packet has the
/// VP8 packet that was written.
#[test]
fn a_red_packet_is_retransmitted_under_the_rtx_format_whose_apt_is_red() {
    let fec = UlpfecSendBuilder::red(RED, ULPFEC)
        .with_red_placement(RedPlacement::OwnPacket)
        .with_flush_on_marker(true)
        .with_adaptive_rate(false)
        .build();
    let mut chain = Registry::new()
        .with(Slot::FecEncoder, fec)
        .with(Slot::NackResponder, responder())
        .build();
    let info = stream();
    chain.bind_local_stream(&info);

    let now = Instant::now();
    let original = media(VP8, 100);
    chain
        .handle_write(tagged(now, Packet::Rtp(original.clone())))
        .unwrap();
    let sent = written(&mut chain);
    let on_the_wire = sent
        .iter()
        .find(|packet| packet.payload.first() == Some(&VP8))
        .expect("the media packet, in RED: its block header names VP8");
    assert_eq!(RED, on_the_wire.header.payload_type);

    chain
        .handle_read(nack(now, on_the_wire.header.sequence_number))
        .unwrap();
    while chain.poll_read().is_some() {}
    let rtx = written(&mut chain)
        .into_iter()
        .find(|packet| packet.header.ssrc == RTX_SSRC)
        .expect("a retransmission on the RTX SSRC");
    assert_eq!(RED_RTX, rtx.header.payload_type);

    // The receiving side: RFC 4588 restores a RED packet, the FEC decoder opens it.
    let back = restored(&rtx, &info);
    assert_eq!(RED, back.header.payload_type);
    assert_eq!(
        on_the_wire.header.sequence_number,
        back.header.sequence_number
    );
    let mut receiver = Registry::new()
        .with(
            Slot::FecDecoder,
            UlpfecReceiveBuilder::red(RED, ULPFEC).build(),
        )
        .build();
    receiver.bind_remote_stream(&StreamInfo {
        payload_type: RED,
        payload_type_rtx: Some(RED_RTX),
        mime_type: "video/red".to_owned(),
        ..info.clone()
    });
    receiver
        .handle_read(tagged(now, Packet::Rtp(back)))
        .unwrap();
    let opened = std::iter::from_fn(|| receiver.poll_read())
        .find_map(|tagged| match tagged.message.packet {
            Packet::Rtp(packet) => Some(packet),
            _ => None,
        })
        .expect("the media packet");
    assert_eq!(VP8, opened.header.payload_type);
    assert_eq!(original.payload, opened.payload);
}

/// Each packet is retransmitted under the format whose `apt` is its own payload type. One
/// whose payload type has no retransmission format, on a stream that negotiated RTX, is not
/// retransmitted at all: RFC 4588 names no format for it, and it is never sent under another
/// payload type's format nor again on the media SSRC (libwebrtc's `BuildRtxPacket` returns
/// nothing for it).
#[test]
fn the_payload_type_a_packet_left_under_selects_its_rtx_format() {
    let mut chain = Registry::new()
        .with(Slot::NackResponder, responder())
        .build();
    chain.bind_local_stream(&stream());

    let now = Instant::now();
    for (payload_type, sequence_number) in [(VP8, 10u16), (RED, 11), (VP9, 12)] {
        chain
            .handle_write(tagged(
                now,
                Packet::Rtp(media(payload_type, sequence_number)),
            ))
            .unwrap();
    }
    written(&mut chain);

    let mut repairs = vec![];
    for sequence_number in [10u16, 11, 12] {
        chain.handle_read(nack(now, sequence_number)).unwrap();
        while chain.poll_read().is_some() {}
        repairs.push(
            written(&mut chain)
                .iter()
                .map(|packet| (packet.header.ssrc, packet.header.payload_type))
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(
        vec![
            vec![(RTX_SSRC, VP8_RTX)],
            vec![(RTX_SSRC, RED_RTX)],
            // VP9 has no retransmission format in this section.
            vec![],
        ],
        repairs
    );
}

/// The stream's own pair (the payload type it was bound with and its RTX payload type)
/// holds also when the section's list names retransmission formats for other payload types
/// only.
#[test]
fn the_streams_own_rtx_format_holds_beside_the_sections() {
    let mut info = stream();
    info.section_mime_types
        .retain(|(payload_type, _)| *payload_type != VP8_RTX);
    info.section_fmtp_lines
        .retain(|(payload_type, _)| *payload_type != VP8_RTX);
    let mut chain = Registry::new()
        .with(Slot::NackResponder, responder())
        .build();
    chain.bind_local_stream(&info);

    let now = Instant::now();
    chain
        .handle_write(tagged(now, Packet::Rtp(media(VP8, 30))))
        .unwrap();
    written(&mut chain);
    chain.handle_read(nack(now, 30)).unwrap();
    while chain.poll_read().is_some() {}
    assert_eq!(
        vec![(RTX_SSRC, VP8_RTX)],
        written(&mut chain)
            .iter()
            .map(|packet| (packet.header.ssrc, packet.header.payload_type))
            .collect::<Vec<_>>()
    );
}

/// FEC data is not retransmitted, and a lost FEC packet's sequence number is still answered:
/// a NACK that names a FEC packet (ULPFEC in a RED packet of its own, in the media's sequence
/// space) gets, under the RTX of `red`, the packet's sequence number with its RED block
/// header and nothing else: three octets. Restored and read by the FEC receiver it is what
/// any FEC packet becomes on its way to the application: present, without a payload. So a
/// receiver that puts frames together does not wait for a media packet that never was.
/// Without an RTX stream nothing answers (the packet as it was is all that could leave under
/// its number). libwebrtc keeps no FEC packet for retransmission
/// (`ulpfec_generator.cc:233`: `set_allow_retransmission(false)`) and ignores such a NACK
/// (`rtp_sender.cc:348-351`); its receiver does not need the number to find the next frame.
#[test]
fn a_nack_for_a_fec_packet_in_red_is_answered_with_its_sequence_number_alone() {
    for rtx in [true, false] {
        let fec = UlpfecSendBuilder::red(RED, ULPFEC)
            .with_red_placement(RedPlacement::OwnPacket)
            .with_num_media_packets(2)
            .with_num_fec_packets(1)
            .with_adaptive_rate(false)
            // The packets carry no marker bit: the FEC follows its block.
            .with_fec_after_frame(false)
            .build();
        let mut chain = Registry::new()
            .with(Slot::FecEncoder, fec)
            .with(Slot::NackResponder, responder())
            .build();
        let info = if rtx {
            stream()
        } else {
            StreamInfo {
                ssrc_rtx: None,
                payload_type_rtx: None,
                ..stream()
            }
        };
        chain.bind_local_stream(&info);

        let now = Instant::now();
        let mut sent = vec![];
        for sequence_number in 200..204u16 {
            chain
                .handle_write(tagged(now, Packet::Rtp(media(VP8, sequence_number))))
                .unwrap();
            sent.extend(written(&mut chain));
        }
        let fec_packets: Vec<u16> = sent
            .iter()
            .filter(|packet| packet.payload.first() == Some(&ULPFEC))
            .map(|packet| packet.header.sequence_number)
            .collect();
        let media_packets: Vec<u16> = sent
            .iter()
            .filter(|packet| packet.payload.first() == Some(&VP8))
            .map(|packet| packet.header.sequence_number)
            .collect();
        assert!(!fec_packets.is_empty(), "the encoder sent FEC ({sent:?})");
        assert_eq!(4, media_packets.len());
        assert!(sent.iter().all(|packet| packet.header.payload_type == RED));

        for sequence_number in &fec_packets {
            chain.handle_read(nack(now, *sequence_number)).unwrap();
            while chain.poll_read().is_some() {}
            let answer = written(&mut chain);
            if !rtx {
                assert_eq!(
                    0,
                    answer.len(),
                    "no repair of the FEC packet {sequence_number} without an RTX stream"
                );
                continue;
            }
            assert_eq!(1, answer.len(), "FEC packet {sequence_number}");
            assert_eq!(
                (RTX_SSRC, RED_RTX),
                (answer[0].header.ssrc, answer[0].header.payload_type)
            );
            let [high, low] = sequence_number.to_be_bytes();
            assert_eq!(
                &[high, low, ULPFEC][..],
                &answer[0].payload[..],
                "the original sequence number and the RED block header, no FEC data"
            );
            // What the receiver makes of it: the RED packet, and from that the packet without
            // a payload that stands for a FEC packet's sequence number.
            let red = restored(&answer[0], &info);
            assert_eq!(
                (SSRC, RED, *sequence_number),
                (
                    red.header.ssrc,
                    red.header.payload_type,
                    red.header.sequence_number
                )
            );
            let mut receiver = Registry::new()
                .with(
                    Slot::FecDecoder,
                    rtci_interceptor::UlpfecReceiveBuilder::red(RED, ULPFEC).build(),
                )
                .build();
            receiver.bind_remote_stream(&info);
            receiver.handle_read(tagged(now, Packet::Rtp(red))).unwrap();
            let delivered: Vec<rtp::Packet> = std::iter::from_fn(|| receiver.poll_read())
                .filter_map(|tagged| match tagged.message.packet {
                    Packet::Rtp(packet) => Some(packet),
                    _ => None,
                })
                .collect();
            assert_eq!(1, delivered.len());
            assert_eq!(*sequence_number, delivered[0].header.sequence_number);
            assert!(delivered[0].payload.is_empty(), "present, and no media");
        }
        chain.handle_read(nack(now, media_packets[0])).unwrap();
        while chain.poll_read().is_some() {}
        let repair: Vec<(u32, u8)> = written(&mut chain)
            .iter()
            .map(|packet| (packet.header.ssrc, packet.header.payload_type))
            .collect();
        let expected = if rtx {
            (RTX_SSRC, RED_RTX)
        } else {
            // No retransmission format negotiated: the RED packet again as it was.
            (SSRC, RED)
        };
        assert_eq!(vec![expected], repair, "the media packet is repaired");
    }
}

/// A binder that does not list the section's formats names one RTX payload type for the
/// stream, and that is the one used, as before.
#[test]
fn without_the_sections_formats_the_streams_rtx_payload_type_is_used() {
    let mut chain = Registry::new()
        .with(Slot::NackResponder, responder())
        .build();
    chain.bind_local_stream(&StreamInfo {
        section_mime_types: vec![],
        section_fmtp_lines: vec![],
        ..stream()
    });

    let now = Instant::now();
    chain
        .handle_write(tagged(now, Packet::Rtp(media(RED, 20))))
        .unwrap();
    written(&mut chain);
    chain.handle_read(nack(now, 20)).unwrap();
    while chain.poll_read().is_some() {}
    let repair = written(&mut chain);
    assert_eq!(
        vec![(RTX_SSRC, VP8_RTX)],
        repair
            .iter()
            .map(|packet| (packet.header.ssrc, packet.header.payload_type))
            .collect::<Vec<_>>()
    );
}
