//! ULPFEC in RED as libwebrtc writes and reads it: known answers.
//!
//! The `Chrome` behaviour profile sends video FEC as libwebrtc does (`RedPlacement::OwnPacket`,
//! RFC 5109 section 14.2 with the FEC in RED packets of their own). These tests hold the
//! engine's output against a transcription of libwebrtc's own code at commit a222406d
//! (`specs/libwebrtc/modules/rtp_rtcp/source/`):
//!
//! - the generator (`forward_error_correction.cc` `GenerateFecPayloads`, `XorHeaders`,
//!   `XorPayloads`; `ulpfec_header_reader_writer.cc` `FinalizeFecHeader`; `ulpfec_generator.cc`
//!   `GetFecPackets`): the FEC payload the engine sends is the octets libwebrtc's generator
//!   writes for the same media;
//! - the receiver (`ulpfec_receiver.cc` `AddReceivedRedPacket` / `ProcessReceivedFec`,
//!   `UlpfecHeaderReader::ReadFecHeader`, `ForwardErrorCorrection::RecoverPacket`), which zeroes
//!   the extensions a pacer writes (`RtpPacket::ZeroMutableExtensions`: transport-wide sequence
//!   number, abs-send-time, toffset) in its copy of every media packet before the XOR: it
//!   rebuilds a lost media packet from the engine's FEC.
//!
//! Browser cell: "ULPFEC in RED to the browser" in `scripts/test-env/interop/scenarios.spec.mjs`.

use bytes::Bytes;
use rtci_interceptor::{
    AttributedPacket, Interceptor, Packet, RTCPFeedback, RTPHeaderExtension, RedPlacement,
    Registry, Slot, StreamInfo, TaggedPacket, TwccSenderBuilder, UlpfecReceiveBuilder,
    UlpfecSendBuilder,
};
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::Marshal;
use std::time::Instant;

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const TWCC_ID: u8 = 4;
const MID_ID: u8 = 9;

const MEDIA_SSRC: u32 = 0xf9ff_0043;
const MEDIA_PT: u8 = 96;
/// The numbers Chromium's offer gave red and ulpfec in the browser cell (hosted run
/// 45432068740).
const RED_PT: u8 = 118;
const FEC_PT: u8 = 120;

/// libwebrtc's fixed RTP header and ULPFEC header sizes (`kRtpHeaderSize`,
/// `kFecLevel0HeaderSize`, level 1 with L = 0).
const RTP_HEADER: usize = 12;
const ULPFEC_HEADER_SHORT_MASK: usize = 10 + 2 + 2;

fn stream(with_twcc: bool) -> StreamInfo {
    StreamInfo {
        ssrc: MEDIA_SSRC,
        payload_type: MEDIA_PT,
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        rtcp_feedback: if with_twcc {
            vec![RTCPFeedback {
                typ: "transport-cc".to_owned(),
                parameter: String::new(),
            }]
        } else {
            vec![]
        },
        rtp_header_extensions: if with_twcc {
            vec![RTPHeaderExtension {
                uri: TRANSPORT_CC_URI.to_owned(),
                id: u16::from(TWCC_ID),
            }]
        } else {
            vec![]
        },
        section_mime_types: vec![
            (MEDIA_PT, "video/VP8".to_owned()),
            (RED_PT, "video/red".to_owned()),
            (FEC_PT, "video/ulpfec".to_owned()),
        ],
        ..Default::default()
    }
}

/// The `Chrome` profile's encoder (`configure_video_red_ulpfec`): FEC in RED packets of its own,
/// a block closed at the end of each frame; a fixed amount, one FEC packet per block.
fn sender(with_twcc: bool) -> impl Interceptor {
    sender_zeroing(with_twcc, false)
}

/// [`sender`], the encoder protecting the pacer-written extensions as zeros when `zero`
/// (`with_mutable_extensions_zeroed`, the `Chrome` profile's).
fn sender_zeroing(with_twcc: bool, zero: bool) -> impl Interceptor {
    let mut fec = UlpfecSendBuilder::red(RED_PT, FEC_PT)
        .with_red_placement(RedPlacement::OwnPacket)
        .with_flush_on_marker(true)
        .with_adaptive_rate(false)
        .with_mutable_extensions_zeroed(zero)
        .build();
    let tap = fec.wire_tap();
    let registry = Registry::new()
        .with(Slot::FecEncoder, fec)
        .with(Slot::FecWireImage, tap);
    let registry = if with_twcc {
        registry.with(Slot::TwccSender, TwccSenderBuilder::new().build())
    } else {
        registry
    };
    let mut chain = registry.build();
    chain.bind_local_stream(&stream(with_twcc));
    chain
}

/// A VP8 frame of `count` packets from `first`, each with the MID extension (not one a pacer
/// writes, so libwebrtc keeps it in its copies), of different sizes.
fn frame(first: u16, count: u16, timestamp: u32) -> Vec<rtp::Packet> {
    (0..count)
        .map(|index| {
            let sequence_number = first.wrapping_add(index);
            let mut header = rtp::header::Header {
                version: 2,
                marker: index + 1 == count,
                payload_type: MEDIA_PT,
                sequence_number,
                timestamp,
                ssrc: MEDIA_SSRC,
                ..Default::default()
            };
            header
                .set_extension(MID_ID, Bytes::from_static(b"0"))
                .expect("mid");
            rtp::Packet {
                header,
                payload: Bytes::from(
                    (0..(40 + usize::from(index) * 17))
                        .map(|octet| (octet as u8).wrapping_mul(7).wrapping_add(index as u8))
                        .collect::<Vec<u8>>(),
                ),
            }
        })
        .collect()
}

fn send(chain: &mut impl Interceptor, packets: Vec<rtp::Packet>) -> Vec<rtp::Packet> {
    let now = Instant::now();
    let mut wire = Vec::new();
    for packet in packets {
        chain
            .handle_write(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(packet)),
            })
            .expect("write");
        while let Some(out) = chain.poll_write() {
            if let Packet::Rtp(rtp) = out.message.packet {
                wire.push(rtp);
            }
        }
    }
    wire
}

fn bytes(packet: &rtp::Packet) -> Vec<u8> {
    packet.marshal().expect("marshal").to_vec()
}

fn headers_size(packet: &rtp::Packet) -> usize {
    bytes(packet).len() - packet.payload.len()
}

fn is_fec(packet: &rtp::Packet) -> bool {
    packet.header.payload_type == RED_PT && packet.payload[0] & 0x7F == FEC_PT
}

/// `UlpfecReceiver::AddReceivedRedPacket` for a media packet: the RTP header as received with
/// the RED payload type replaced by the block's (marker kept), then the payload after the
/// one-octet RED header.
fn libwebrtc_media_copy(red: &rtp::Packet) -> Vec<u8> {
    let wire = bytes(red);
    let headers = headers_size(red);
    assert_eq!(0, wire[headers] & 0x80, "one RED block, F = 0");
    let mut copy = wire[..headers].to_vec();
    copy[1] = (copy[1] & 0x80) | wire[headers];
    copy.extend_from_slice(&wire[headers + 1..]);
    copy
}

/// `RtpPacket::ZeroMutableExtensions` for the one-byte extensions this file uses: the value of
/// the transport-wide sequence number is zeroed (libwebrtc's pacer fills it after the FEC).
fn zero_mutable_extensions(copy: &mut [u8]) {
    if copy[0] & 0x10 == 0 {
        return;
    }
    let csrcs = usize::from(copy[0] & 0x0F) * 4;
    let start = RTP_HEADER + csrcs;
    assert_eq!([0xBE, 0xDE], copy[start..start + 2], "one-byte extensions");
    let words = usize::from(u16::from_be_bytes([copy[start + 2], copy[start + 3]]));
    let mut at = start + 4;
    let end = at + words * 4;
    while at < end {
        let id = copy[at] >> 4;
        if id == 0 {
            at += 1;
            continue;
        }
        let length = usize::from(copy[at] & 0x0F) + 1;
        if id == TWCC_ID {
            copy[at + 1..at + 1 + length].fill(0);
        }
        at += 1 + length;
    }
}

/// `ForwardErrorCorrection::XorHeaders` and `XorPayloads` of `src` into `dst`, the payload at
/// `dst_offset`.
fn libwebrtc_xor(src: &[u8], dst: &mut Vec<u8>, dst_offset: usize) {
    dst[0] ^= src[0];
    dst[1] ^= src[1];
    let length = ((src.len() - RTP_HEADER) as u16).to_be_bytes();
    dst[2] ^= length[0];
    dst[3] ^= length[1];
    for index in 4..8 {
        dst[index] ^= src[index];
    }
    let payload = &src[RTP_HEADER..];
    if dst.len() < dst_offset + payload.len() {
        dst.resize(dst_offset + payload.len(), 0);
    }
    for (index, octet) in payload.iter().enumerate() {
        dst[dst_offset + index] ^= octet;
    }
}

/// libwebrtc's generator for one FEC packet over `media` (consecutive sequence numbers, at most
/// 16, all protected): `GenerateFecPayloads` then `UlpfecHeaderWriter::FinalizeFecHeader`.
fn libwebrtc_fec_payload(media: &[Vec<u8>]) -> Vec<u8> {
    assert!(!media.is_empty() && media.len() <= 16);
    let mut fec = vec![0u8; ULPFEC_HEADER_SHORT_MASK];
    for packet in media {
        libwebrtc_xor(packet, &mut fec, ULPFEC_HEADER_SHORT_MASK);
    }
    let sn_base = [media[0][2], media[0][3]];
    let mask = (!0u16) << (16 - media.len());
    // FinalizeFecHeader: E = 0, L = 0, length recovery to octets 8-9, SN base, protection
    // length = the whole rest, the mask.
    fec[0] &= 0x7F;
    fec[0] &= 0xBF;
    fec[8] = fec[2];
    fec[9] = fec[3];
    fec[2..4].copy_from_slice(&sn_base);
    let protection_length = (fec.len() - ULPFEC_HEADER_SHORT_MASK) as u16;
    fec[10..12].copy_from_slice(&protection_length.to_be_bytes());
    fec[12..14].copy_from_slice(&mask.to_be_bytes());
    fec
}

/// libwebrtc's receiver for one FEC packet (its RED payload) and the media copies that arrived:
/// the rebuilt packet when exactly one protected packet is missing (`AttemptRecovery`).
fn libwebrtc_recover(
    fec_red_payload: &[u8],
    fec_ssrc: u32,
    arrived: &[Vec<u8>],
) -> Option<Vec<u8>> {
    assert_eq!(
        FEC_PT, fec_red_payload[0],
        "RED header: F = 0, the ulpfec payload type"
    );
    let mut fec = fec_red_payload[1..].to_vec();
    // UlpfecHeaderReader::ReadFecHeader.
    let long_mask = fec[0] & 0x40 != 0;
    let mask_size = if long_mask { 6 } else { 2 };
    let header_size = 12 + mask_size;
    let sn_base = u16::from_be_bytes([fec[2], fec[3]]);
    let protection_length = usize::from(u16::from_be_bytes([fec[10], fec[11]]));
    fec[2] = fec[8];
    fec[3] = fec[9];
    let protected: Vec<u16> = (0..mask_size * 8)
        .filter(|bit| fec[12 + bit / 8] & (0x80 >> (bit % 8)) != 0)
        .map(|bit| sn_base.wrapping_add(bit as u16))
        .collect();
    let sequence = |copy: &[u8]| u16::from_be_bytes([copy[2], copy[3]]);
    let missing: Vec<u16> = protected
        .iter()
        .copied()
        .filter(|sn| !arrived.iter().any(|copy| sequence(copy) == *sn))
        .collect();
    if missing.len() != 1 {
        return None;
    }
    // StartPacketRecovery, the XORs, FinishPacketRecovery.
    assert!(fec.len() >= header_size + protection_length);
    let mut rebuilt = fec[..RTP_HEADER].to_vec();
    rebuilt.extend_from_slice(&fec[header_size..header_size + protection_length]);
    for copy in arrived
        .iter()
        .filter(|copy| protected.contains(&sequence(copy)))
    {
        libwebrtc_xor(copy, &mut rebuilt, RTP_HEADER);
    }
    rebuilt[0] |= 0x80;
    rebuilt[0] &= 0xBF;
    let size = usize::from(u16::from_be_bytes([rebuilt[2], rebuilt[3]])) + RTP_HEADER;
    rebuilt.resize(size, 0);
    rebuilt[2..4].copy_from_slice(&missing[0].to_be_bytes());
    rebuilt[8..12].copy_from_slice(&fec_ssrc.to_be_bytes());
    Some(rebuilt)
}

/// Known answer: for a three-packet frame, the engine sends libwebrtc's FEC packet, octet for
/// octet: the RED payload is the ulpfec payload type and the payload libwebrtc's generator
/// writes over the same media; the RTP header is the media SSRC, the next sequence number of
/// the media stream, the frame's timestamp, marker 0, RED's payload type (`GetFecPackets`).
#[test]
fn the_fec_packet_is_what_libwebrtcs_generator_writes_for_the_same_media() {
    let mut chain = sender(false);
    let wire = send(&mut chain, frame(30_228, 3, 922_772_235));
    assert_eq!(
        4,
        wire.len(),
        "three media packets and one FEC packet: {wire:?}"
    );
    let (media, fec): (Vec<_>, Vec<_>) = wire.iter().partition(|packet| !is_fec(packet));
    assert_eq!(1, fec.len());
    let fec = fec[0];
    for packet in &media {
        assert_eq!(
            RED_PT, packet.header.payload_type,
            "the media goes in RED too"
        );
        assert_eq!(MEDIA_PT, packet.payload[0], "one primary block: F = 0, VP8");
    }

    let copies: Vec<Vec<u8>> = media
        .iter()
        .map(|packet| libwebrtc_media_copy(packet))
        .collect();
    let mut expected = vec![FEC_PT];
    expected.extend(libwebrtc_fec_payload(&copies));
    assert_eq!(
        expected,
        fec.payload.to_vec(),
        "the FEC packet's RED payload"
    );

    assert_eq!(MEDIA_SSRC, fec.header.ssrc);
    assert_eq!(
        30_231, fec.header.sequence_number,
        "the media stream's next number"
    );
    assert_eq!(
        922_772_235, fec.header.timestamp,
        "the last protected packet's"
    );
    assert!(!fec.header.marker);
    assert_eq!(RED_PT, fec.header.payload_type);
}

/// With the transport-wide sequence number written below the encoder (the engine's chain), the
/// FEC covers the numbers as sent while libwebrtc's receiver zeroes them in its copies. A lost
/// packet still comes back from libwebrtc's recovery with every octet as sent except that
/// number's value (libwebrtc's own FEC brings it back as zero; a rebuilt packet never reaches
/// its congestion controller). Each of the frame's packets is lost in turn.
#[test]
fn libwebrtcs_receiver_rebuilds_each_lost_packet_from_the_engines_fec() {
    let mut chain = sender(true);
    let wire = send(&mut chain, frame(1_000, 3, 90_000));
    let (media, fec): (Vec<_>, Vec<_>) = wire.iter().partition(|packet| !is_fec(packet));
    assert_eq!((3, 1), (media.len(), fec.len()), "{wire:?}");
    let fec = fec[0];

    for lost in 0..media.len() {
        let arrived: Vec<Vec<u8>> = media
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != lost)
            .map(|(_, packet)| {
                let mut copy = libwebrtc_media_copy(packet);
                zero_mutable_extensions(&mut copy);
                copy
            })
            .collect();
        let rebuilt = libwebrtc_recover(&fec.payload, fec.header.ssrc, &arrived)
            .unwrap_or_else(|| panic!("packet {lost} not rebuilt"));
        let mut sent = libwebrtc_media_copy(media[lost]);
        assert_eq!(sent.len(), rebuilt.len(), "packet {lost}: length");
        // The value octets of the transport-wide number differ; everything else is as sent.
        let mut rebuilt_zeroed = rebuilt.clone();
        zero_mutable_extensions(&mut rebuilt_zeroed);
        zero_mutable_extensions(&mut sent);
        assert_eq!(sent, rebuilt_zeroed, "packet {lost} rebuilt");
        assert_eq!(
            MEDIA_PT,
            rebuilt[1] & 0x7F,
            "a VP8 packet, not RED (dropped by libwebrtc)"
        );
    }
}

/// Without the extensions a pacer writes, libwebrtc's recovery gives back the packet exactly,
/// for a one-packet frame (what the browser cell's VP8 fixture sends) and a longer one.
#[test]
fn libwebrtcs_receiver_rebuilds_the_packet_exactly_without_pacer_extensions() {
    for count in [1u16, 5] {
        let mut chain = sender(false);
        let wire = send(&mut chain, frame(65_533, count, 3_000));
        let (media, fec): (Vec<_>, Vec<_>) = wire.iter().partition(|packet| !is_fec(packet));
        assert_eq!(1, fec.len(), "{wire:?}");
        for lost in 0..media.len() {
            let arrived: Vec<Vec<u8>> = media
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != lost)
                .map(|(_, packet)| libwebrtc_media_copy(packet))
                .collect();
            assert_eq!(
                Some(libwebrtc_media_copy(media[lost])),
                libwebrtc_recover(&fec[0].payload, fec[0].header.ssrc, &arrived),
                "frame of {count}, packet {lost} lost (sequence numbers wrap)"
            );
        }
    }
}

/// With the mutable extensions zeroed in what the encoder protects, as libwebrtc's sender
/// protects them (its FEC is computed before `RtpSenderEgress::SendPacket` writes the
/// transport-wide sequence number, abs-send-time and toffset), libwebrtc's receiver rebuilds
/// each lost packet exactly as it rebuilds one from its own FEC: every octet as sent, those
/// values zero. Without it (the test above) those octets are XOR noise.
#[test]
fn with_mutable_extensions_zeroed_libwebrtcs_receiver_rebuilds_exactly_what_its_own_fec_would() {
    let mut chain = sender_zeroing(true, true);
    let wire = send(&mut chain, frame(1_000, 3, 90_000));
    let (media, fec): (Vec<_>, Vec<_>) = wire.iter().partition(|packet| !is_fec(packet));
    assert_eq!((3, 1), (media.len(), fec.len()), "{wire:?}");
    let fec = fec[0];
    for lost in 0..media.len() {
        let arrived: Vec<Vec<u8>> = media
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != lost)
            .map(|(_, packet)| {
                let mut copy = libwebrtc_media_copy(packet);
                zero_mutable_extensions(&mut copy);
                copy
            })
            .collect();
        let rebuilt = libwebrtc_recover(&fec.payload, fec.header.ssrc, &arrived)
            .unwrap_or_else(|| panic!("packet {lost} not rebuilt"));
        let mut expected = libwebrtc_media_copy(media[lost]);
        zero_mutable_extensions(&mut expected);
        assert_eq!(expected, rebuilt, "packet {lost} rebuilt exactly");
        // The transport-wide number did leave with the packet: only the FEC left it out.
        let mut sent = libwebrtc_media_copy(media[lost]);
        assert_ne!(sent, rebuilt, "packet {lost}: the number was on the wire");
        zero_mutable_extensions(&mut sent);
        assert_eq!(sent, rebuilt);
    }
}

/// The receiving half, as libwebrtc's receiver does it
/// (`UlpfecReceiveBuilder::with_mutable_extensions_zeroed`): FEC computed over the packets with
/// the pacer-written values zeroed (libwebrtc's sender's form, here the engine's sender with the
/// same setting) rebuilds a lost packet with every octet as sent and the transport-wide number
/// zero. A receiver that keeps the values in its copies rebuilds that number as XOR noise.
#[test]
fn with_mutable_extensions_zeroed_the_engines_receiver_rebuilds_libwebrtcs_form_exactly() {
    let mut chain = sender_zeroing(true, true);
    let wire = send(&mut chain, frame(1_000, 3, 90_000));
    let lost = 1;
    let media: Vec<&rtp::Packet> = wire.iter().filter(|packet| !is_fec(packet)).collect();
    let lost_packet = media[lost].clone();
    for zeroing in [true, false] {
        let mut receiver = Registry::new()
            .with(
                Slot::FecDecoder,
                UlpfecReceiveBuilder::red(RED_PT, FEC_PT)
                    .with_mutable_extensions_zeroed(zeroing)
                    .build(),
            )
            .build();
        receiver.bind_remote_stream(&stream(true));
        let mut delivered = Vec::new();
        for packet in &wire {
            if packet.header.sequence_number == lost_packet.header.sequence_number {
                continue;
            }
            receiver
                .handle_read(TaggedPacket {
                    now: Instant::now(),
                    transport: TransportContext::default(),
                    message: AttributedPacket::new(Packet::Rtp(packet.clone())),
                })
                .expect("read");
            while let Some(out) = receiver.poll_read() {
                if let Packet::Rtp(rtp) = out.message.packet {
                    delivered.push(rtp);
                }
            }
        }
        let rebuilt = delivered
            .iter()
            .find(|packet| packet.header.sequence_number == lost_packet.header.sequence_number)
            .expect("the lost packet is rebuilt");
        assert_eq!(
            rebuilt.payload,
            lost_packet.payload.slice(1..),
            "zeroing {zeroing}"
        );
        let number = rebuilt
            .header
            .get_extension(TWCC_ID)
            .expect("the extension is there");
        if zeroing {
            assert_eq!(number.as_ref(), [0, 0], "rebuilt as libwebrtc rebuilds it");
            assert_eq!(
                rebuilt.header.get_extension(MID_ID),
                lost_packet.header.get_extension(MID_ID),
                "the other extensions as sent"
            );
        } else {
            assert_ne!(
                number,
                lost_packet.header.get_extension(TWCC_ID).unwrap(),
                "noise: the FEC covered zeros, the copies the numbers"
            );
        }
    }
}
