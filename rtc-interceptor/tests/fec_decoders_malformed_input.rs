//! The FEC decoders against input a peer can make them read: truncated at every length, with
//! length and count fields that claim more than the packet holds.
//!
//! Each parser has to answer with an error, and each decoder has to stay inside its buffers:
//! nothing here may panic, and nothing that is not an RTP packet of the protected stream may come
//! out as "recovered". (Reviewed for the same reason the `ulpfec_receive` fuzz target was
//! corrected; these are the cases a reader of the code would try first.)

use bytes::Bytes;
use rtc_interceptor::{
    Attribute, AttributedPacket, FlexFecHeader, FlexFecHeaderError, FlexFecProtection,
    FlexFecReceiveBuilder, FlexFecSendBuilder, Interceptor, Packet, Registry, Slot, StreamInfo,
    TaggedPacket, UlpfecDecoder, UlpfecError, UlpfecPacket, depacketize_red_for_ulpfec,
};
use sansio::Protocol;
use shared::TransportContext;
use std::time::Instant;

const MEDIA_SSRC: u32 = 1000;
const REPAIR_SSRC: u32 = 2000;
const FEC_PT: u8 = 117;

fn media(sequence_number: u16, length: usize) -> rtp::Packet {
    rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            payload_type: 96,
            sequence_number,
            timestamp: u32::from(sequence_number) * 3000,
            ssrc: MEDIA_SSRC,
            ..Default::default()
        },
        payload: Bytes::from(vec![sequence_number as u8; length]),
    }
}

// ---------------------------------------------------------------------------------------------
// ULPFEC (RFC 5109 section 7.3, 7.4)
// ---------------------------------------------------------------------------------------------

/// A well-formed one-level FEC packet with a 16-bit mask: FEC header, level header, 8 octets.
fn ulpfec_packet() -> Vec<u8> {
    let mut packet = vec![
        0x00, 0x60, // E=0 L=0, recovery bits; PT recovery
        0x00, 0x0A, // SN base 10
        0x00, 0x00, 0x00, 0x00, // TS recovery
        0x00, 0x08, // length recovery
        0x00, 0x08, // protection length 8
        0xC0, 0x00, // mask: packets 10 and 11
    ];
    packet.extend_from_slice(&[0xAA; 8]);
    packet
}

#[test]
fn a_ulpfec_packet_truncated_anywhere_is_an_error_not_a_panic() {
    let whole = ulpfec_packet();
    assert!(UlpfecPacket::parse(&whole).is_ok());

    for length in 0..whole.len() {
        assert!(
            UlpfecPacket::parse(&whole[..length]).is_err(),
            "{length} of {} octets parsed",
            whole.len()
        );
        let mut decoder = UlpfecDecoder::new(MEDIA_SSRC);
        decoder.push_media(&media(10, 20));
        assert!(decoder.push_fec(&whole[..length]).is_err());
    }
}

#[test]
fn a_ulpfec_level_that_claims_more_than_the_packet_holds_is_refused() {
    let mut packet = ulpfec_packet();
    // Protection length 0xFFFF with eight octets behind it.
    packet[10] = 0xFF;
    packet[11] = 0xFF;
    assert_eq!(
        Err(UlpfecError::TruncatedLevel),
        UlpfecPacket::parse(&packet).map(|_| ())
    );

    // The 48-bit mask flag with only a 16-bit level header's worth of octets.
    let mut long_mask = ulpfec_packet();
    long_mask[0] |= 0x40;
    long_mask.truncate(14);
    assert_eq!(
        Err(UlpfecError::TooShort),
        UlpfecPacket::parse(&long_mask).map(|_| ())
    );

    // A level that protects nothing.
    let mut empty_mask = ulpfec_packet();
    empty_mask[12] = 0;
    empty_mask[13] = 0;
    assert_eq!(
        Err(UlpfecError::EmptyMask),
        UlpfecPacket::parse(&empty_mask).map(|_| ())
    );
}

/// The length recovery field comes off the wire. A value far beyond what the FEC packet
/// protects must not make the decoder read past its data or hand out a packet.
#[test]
fn a_ulpfec_length_recovery_beyond_the_protected_octets_recovers_nothing() {
    for claimed in [0x0100u16, 0x7FFF, 0xFFFF] {
        let mut packet = ulpfec_packet();
        packet[8..10].copy_from_slice(&claimed.to_be_bytes());

        let mut decoder = UlpfecDecoder::new(MEDIA_SSRC);
        // Packet 10 arrived, 11 did not: the FEC packet is asked to rebuild 11.
        decoder.push_media(&media(10, 8));
        let recovered = decoder.push_fec(&packet).unwrap_or_default();

        for packet in &recovered {
            assert_eq!(MEDIA_SSRC, packet.header.ssrc);
        }
        assert!(
            recovered.is_empty(),
            "length recovery {claimed:#x} XOR 8 names octets the level never protected"
        );
    }
}

/// Every header field at its extreme, on every level count up to the limit: bounded work, no
/// panic.
#[test]
fn ulpfec_packets_of_all_ones_and_many_levels_are_survived() {
    let mut decoder = UlpfecDecoder::new(MEDIA_SSRC);
    for sequence_number in 0..40u16 {
        decoder.push_media(&media(sequence_number, 30));
    }
    for levels in 1..=40usize {
        for fill in [0x00u8, 0xFF, 0x80, 0x7F] {
            let mut packet = vec![fill; 10];
            for _ in 0..levels {
                packet.extend_from_slice(&[0x00, 0x02, fill | 0x01, fill]);
                packet.extend_from_slice(&[fill; 2]);
            }
            let _ = decoder.push_fec(&packet);
            // The L bit may be set by `fill`: the same octets read as 48-bit masks.
            let _ = UlpfecPacket::parse(&packet);
        }
    }
    assert!(decoder.held_fec_packets() <= rtc_interceptor::ULPFEC_MAX_HELD_FEC);
}

// ---------------------------------------------------------------------------------------------
// RED carrying ULPFEC (RFC 2198 section 3)
// ---------------------------------------------------------------------------------------------

#[test]
fn a_red_payload_truncated_anywhere_is_an_error_or_a_shorter_primary_never_a_panic() {
    // One redundant FEC block of 6 octets, then the primary block (payload type 96).
    let mut payload = vec![0x80 | FEC_PT, 0x00, 0x00, 0x06, 96];
    payload.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
    payload.extend_from_slice(&[9, 9, 9]);
    let whole = depacketize_red_for_ulpfec(&payload, FEC_PT).expect("well formed");
    assert_eq!(1, whole.fec.len());
    assert_eq!(Some((96, Bytes::from_static(&[9, 9, 9]))), whole.primary);

    for length in 0..payload.len() {
        match depacketize_red_for_ulpfec(&payload[..length], FEC_PT) {
            // Cut inside the headers or inside the redundant block.
            Err(_) => assert!(length < 11, "a cut at {length} leaves the FEC block whole"),
            // Cut inside the primary block: RED has no length for it, so it is just shorter.
            Ok(red) => {
                assert!(length >= 11);
                assert_eq!(Bytes::from_static(&[1, 2, 3, 4, 5, 6]), red.fec[0]);
            }
        }
    }
}

#[test]
fn a_red_block_length_beyond_the_payload_is_refused() {
    // The header says 1023 octets of redundant data; three follow.
    let payload = [0x80 | FEC_PT, 0x00, 0x03, 0xFF, 96, 1, 2, 3];
    assert_eq!(
        Err(UlpfecError::MalformedRed),
        depacketize_red_for_ulpfec(&payload, FEC_PT).map(|_| ())
    );

    // Nothing but redundant-block headers: the primary header never comes.
    let headers_only = [0x80 | FEC_PT, 0, 0, 0].repeat(64);
    assert_eq!(
        Err(UlpfecError::MalformedRed),
        depacketize_red_for_ulpfec(&headers_only, FEC_PT).map(|_| ())
    );
}

// ---------------------------------------------------------------------------------------------
// FlexFEC, RFC 8627 (section 4.2.2)
// ---------------------------------------------------------------------------------------------

/// A flexible-mask header with all three masks: 8 octets of recovery fields, SN base, 15-bit
/// mask with k=1, 31-bit mask with k=1, 64-bit mask.
fn flexfec_header_with_three_masks() -> Vec<u8> {
    let mut header = vec![0x00, 0x60, 0x00, 0x10, 0, 0, 0, 0];
    header.extend_from_slice(&[0x00, 0x64]); // SN base 100
    header.extend_from_slice(&[0x80 | 0x40, 0x00]); // k=1, bit 0
    header.extend_from_slice(&[0x80, 0x00, 0x00, 0x01]); // k=1, last bit
    header.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
    header
}

#[test]
fn a_flexfec_header_truncated_anywhere_is_an_error_not_a_panic() {
    let whole = flexfec_header_with_three_masks();
    assert!(FlexFecHeader::parse(&[MEDIA_SSRC], &whole).is_ok());

    for length in 0..whole.len() {
        assert_eq!(
            Err(FlexFecHeaderError::Truncated),
            FlexFecHeader::parse(&[MEDIA_SSRC], &whole[..length]).map(|_| ()),
            "{length} of {} octets",
            whole.len()
        );
    }
}

/// One mask block per CSRC: a CSRC list longer than the blocks the payload holds is a
/// truncated header, however long the list.
#[test]
fn a_flexfec_csrc_list_longer_than_the_mask_blocks_is_refused() {
    let whole = flexfec_header_with_three_masks();
    for count in [2usize, 3, 15] {
        let csrc = vec![MEDIA_SSRC; count];
        assert_eq!(
            Err(FlexFecHeaderError::Truncated),
            FlexFecHeader::parse(&csrc, &whole).map(|_| ())
        );
    }
    assert_eq!(
        Err(FlexFecHeaderError::NoProtectedSsrc),
        FlexFecHeader::parse(&[], &whole).map(|_| ())
    );
}

fn flexfec_stream() -> StreamInfo {
    StreamInfo {
        ssrc: MEDIA_SSRC,
        ssrc_fec: Some(REPAIR_SSRC),
        payload_type: 96,
        payload_type_fec: Some(98),
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        mime_type_fec: "video/flexfec".to_owned(),
        sdp_fmtp_line_fec: "repair-window=10000000".to_owned(),
        ..Default::default()
    }
}

fn tagged(packet: rtp::Packet) -> TaggedPacket {
    TaggedPacket {
        now: Instant::now(),
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(packet)),
    }
}

/// Six media packets of one size (so every octet of a repair packet is needed to rebuild any of
/// them) and the repair packets `protection` gives for them, as sent.
fn protected_block(protection: FlexFecProtection) -> (Vec<rtp::Packet>, Vec<rtp::Packet>) {
    let mut sender = Registry::new()
        .with(
            Slot::FecEncoder,
            FlexFecSendBuilder::new()
                .with_protection(protection)
                .build(),
        )
        .build();
    sender.bind_local_stream(&flexfec_stream());
    let mut wire = Vec::new();
    for sequence_number in 0..6u16 {
        sender
            .handle_write(tagged(media(sequence_number, 40)))
            .expect("write");
        while let Some(packet) = sender.poll_write() {
            if let Packet::Rtp(rtp) = packet.message.packet {
                wire.push(rtp);
            }
        }
    }
    wire.into_iter()
        .partition(|packet| packet.header.ssrc == MEDIA_SSRC)
}

/// Feed the media without packet 2 and then `repair`; return what came out marked recovered.
fn recover_with(media: &[rtp::Packet], repair: rtp::Packet) -> Vec<rtp::Packet> {
    let mut receiver = Registry::new()
        .with(Slot::FecDecoder, FlexFecReceiveBuilder::new().build())
        .build();
    receiver.bind_remote_stream(&flexfec_stream());
    let mut recovered = Vec::new();
    let arriving = media
        .iter()
        .filter(|packet| packet.header.sequence_number != 2)
        .cloned()
        .chain(std::iter::once(repair));
    for packet in arriving {
        receiver.handle_read(tagged(packet)).expect("read");
        while let Some(out) = receiver.poll_read() {
            if out.message.has(&Attribute::RecoveredByFec)
                && let Packet::Rtp(rtp) = out.message.packet
            {
                recovered.push(rtp);
            }
        }
    }
    recovered
}

/// A repair packet cut short at every length, in each layout: never a panic, and never a
/// recovered packet from a repair packet that lost part of what it protects with.
#[test]
fn a_flexfec_repair_packet_truncated_anywhere_recovers_nothing_and_does_not_panic() {
    for protection in [
        FlexFecProtection::Row { l: 6 },
        FlexFecProtection::Column { l: 1, d: 6 },
    ] {
        let (media, repair) = protected_block(protection);
        assert!(
            !repair.is_empty(),
            "{protection:?} produced no repair packet"
        );
        let whole = repair[0].clone();
        assert_eq!(
            1,
            recover_with(&media, whole.clone()).len(),
            "the untouched repair packet does recover packet 2 ({protection:?})"
        );

        for length in 0..whole.payload.len() {
            let mut cut = whole.clone();
            cut.payload = whole.payload.slice(..length);
            let recovered = recover_with(&media, cut);
            assert!(
                recovered.is_empty(),
                "{length} of {} repair octets rebuilt a packet ({protection:?})",
                whole.payload.len()
            );
        }
    }
}

/// The length recovery and the L / D fields come off the wire. Values far beyond the packet
/// must not be read as buffer sizes.
#[test]
fn flexfec_recovery_fields_at_their_extremes_recover_nothing_and_do_not_panic() {
    let (media, repair) = protected_block(FlexFecProtection::Row { l: 6 });
    let whole = repair[0].clone();

    // Length recovery (octets 2 and 3 of the FEC header) says 64 KiB.
    let mut payload = whole.payload.to_vec();
    payload[2] ^= 0xFF;
    payload[3] ^= 0xFF;
    let mut oversized = whole.clone();
    oversized.payload = Bytes::from(payload);
    assert!(recover_with(&media, oversized).is_empty());

    // Every octet of the header forced to all ones, one at a time and all together.
    for index in 0..whole.payload.len().min(24) {
        let mut payload = whole.payload.to_vec();
        payload[index] = 0xFF;
        let mut mutated = whole.clone();
        mutated.payload = Bytes::from(payload);
        for packet in recover_with(&media, mutated) {
            assert_eq!(MEDIA_SSRC, packet.header.ssrc);
            assert_eq!(2, packet.header.version);
        }
    }
    let mut all_ones = whole.clone();
    all_ones.payload = Bytes::from(vec![0xFF; whole.payload.len()]);
    assert!(recover_with(&media, all_ones).is_empty());
}
