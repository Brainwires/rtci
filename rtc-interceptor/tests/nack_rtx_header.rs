//! RFC 4588 4: an RTX retransmission keeps the original header "as is" apart from the SSRC,
//! payload type and sequence number, so CSRCs and header extensions go with it. The RID becomes
//! the repaired-RID (RFC 8852 3.2).

use bytes::Bytes;
use rtc_interceptor::{
    AttributedPacket, Interceptor, NackResponderBuilder, Packet, RTCPFeedback, RTPHeaderExtension,
    Registry, Slot, StreamInfo, TaggedPacket,
};
use rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use sansio::Protocol;
use shared::TransportContext;
use std::time::Instant;

const SSRC: u32 = 0x1234;
const RTX_SSRC: u32 = 0x5678;
const RTX_PT: u8 = 97;
const AUDIO_LEVEL_ID: u8 = 1;
const RID_ID: u8 = 10;
const REPAIRED_RID_ID: u8 = 11;

fn stream_info() -> StreamInfo {
    StreamInfo {
        ssrc: SSRC,
        ssrc_rtx: Some(RTX_SSRC),
        clock_rate: 90000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        payload_type_rtx: Some(RTX_PT),
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_string(),
            parameter: String::new(),
        }],
        rtp_header_extensions: vec![
            RTPHeaderExtension {
                uri: "urn:ietf:params:rtp-hdrext:ssrc-audio-level".to_string(),
                id: u16::from(AUDIO_LEVEL_ID),
            },
            RTPHeaderExtension {
                uri: "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id".to_string(),
                id: u16::from(RID_ID),
            },
            RTPHeaderExtension {
                uri: "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id".to_string(),
                id: u16::from(REPAIRED_RID_ID),
            },
        ],
        ..Default::default()
    }
}

fn original(now: Instant, sequence_number: u16) -> TaggedPacket {
    let mut header = rtp::header::Header {
        version: 2,
        marker: true,
        payload_type: 96,
        sequence_number,
        timestamp: 3000,
        ssrc: SSRC,
        csrc: vec![7, 8],
        ..Default::default()
    };
    header
        .set_extension(AUDIO_LEVEL_ID, Bytes::from_static(&[0x85]))
        .unwrap();
    header
        .set_extension(RID_ID, Bytes::from_static(b"q"))
        .unwrap();

    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header,
            payload: Bytes::from_static(&[0xAA, 0xBB]),
        })),
    }
}

fn nack(now: Instant, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerNack {
            sender_ssrc: 1,
            media_ssrc: SSRC,
            nacks: vec![NackPair {
                packet_id: sequence_number,
                lost_packets: 0,
            }],
        })])),
    }
}

#[test]
fn an_rtx_packet_keeps_the_originals_csrcs_and_extensions() {
    let mut chain = Registry::new()
        .with(Slot::NackResponder, NackResponderBuilder::new().build())
        .build();
    chain.bind_local_stream(&stream_info());

    let now = Instant::now();
    for sequence_number in 100..110u16 {
        chain.handle_write(original(now, sequence_number)).unwrap();
    }
    while chain.poll_write().is_some() {}

    chain.handle_read(nack(now, 104)).unwrap();
    while chain.poll_read().is_some() {}

    let rtx = std::iter::from_fn(|| chain.poll_write())
        .find_map(|tagged| match tagged.message.packet {
            Packet::Rtp(packet) if packet.header.ssrc == RTX_SSRC => Some(packet),
            _ => None,
        })
        .expect("a retransmission on the RTX SSRC");

    assert_eq!(2, rtx.header.version);
    assert_eq!(RTX_PT, rtx.header.payload_type);
    assert_eq!(3000, rtx.header.timestamp);
    assert!(rtx.header.marker);
    assert!(!rtx.header.padding);
    assert_eq!(vec![7, 8], rtx.header.csrc);
    assert_eq!(
        Some(Bytes::from_static(&[0x85])),
        rtx.header.get_extension(AUDIO_LEVEL_ID)
    );
    assert_eq!(None, rtx.header.get_extension(RID_ID));
    assert_eq!(
        Some(Bytes::from_static(b"q")),
        rtx.header.get_extension(REPAIRED_RID_ID)
    );
    // OSN, then the original payload.
    assert_eq!(&[0x00, 104, 0xAA, 0xBB], &rtx.payload[..]);
}

/// RFC 4588 section 4: "the padding of the original packet MUST be removed": an original
/// sent with padding is retransmitted with no P bit, no padding octets, and the original
/// payload after the OSN.
#[test]
fn the_padding_of_the_original_is_not_retransmitted() {
    let mut chain = Registry::new()
        .with(Slot::NackResponder, NackResponderBuilder::new().build())
        .build();
    chain.bind_local_stream(&stream_info());

    let now = Instant::now();
    let mut padded = original(now, 200);
    if let Packet::Rtp(packet) = &mut padded.message.packet {
        packet.header.padding = true;
        packet.header.padding_size = 4;
    }
    chain.handle_write(padded).unwrap();
    while chain.poll_write().is_some() {}

    chain.handle_read(nack(now, 200)).unwrap();
    while chain.poll_read().is_some() {}
    let rtx = std::iter::from_fn(|| chain.poll_write())
        .find_map(|tagged| match tagged.message.packet {
            Packet::Rtp(packet) if packet.header.ssrc == RTX_SSRC => Some(packet),
            _ => None,
        })
        .expect("a retransmission on the RTX SSRC");
    assert!(!rtx.header.padding);
    let wire = shared::marshal::Marshal::marshal(&rtx).unwrap();
    assert_eq!(0, wire[0] & 0x20, "no P bit on the wire");
    assert_eq!(&[0x00, 200, 0xAA, 0xBB], &wire[wire.len() - 4..]);
}
