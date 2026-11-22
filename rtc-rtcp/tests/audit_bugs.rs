//! The codec bugs the conformance audit found, each reproduced from wire bytes.
//!
//! Every test here failed before its fix: the audit was made by reading, so each finding was
//! confirmed by running these against the code as it was.

use bytes::Bytes;
use rtc_rtcp::extended_report::{
    ExtendedReport, LossRLEReportBlock, VoIPMetricsReportBlock, rle::Chunk,
};
use rtc_rtcp::goodbye::Goodbye;
use rtc_rtcp::packet::{self, Packet};
use rtc_rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtc_rtcp::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate;
use rtc_rtcp::receiver_report::ReceiverReport;
use rtc_rtcp::sender_report::SenderReport;
use rtc_rtcp::source_description::SourceDescription;
use rtc_rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
use rtc_rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use shared::marshal::{Marshal, Unmarshal};

/// A sender report with no report block, 28 octets.
const SR: [u8; 28] = [
    0x80, 0xc8, 0x00, 0x06, // v=2, p=0, count=0, SR, len=6
    0x90, 0x2f, 0x9e, 0x2e, // ssrc
    0xda, 0x8b, 0xd1, 0xfc, 0xdd, 0xdd, 0xa0, 0x5a, // ntp
    0xaa, 0xf4, 0xed, 0xd5, // rtp
    0x00, 0x00, 0x00, 0x01, // packet count
    0x00, 0x00, 0x00, 0x02, // octet count
];

/// A receiver report with no report block, 8 octets.
const RR: [u8; 8] = [0x80, 0xc9, 0x00, 0x01, 0x90, 0x2f, 0x9e, 0x2e];

fn datagram(parts: &[&[u8]]) -> Bytes {
    Bytes::from(parts.concat())
}

fn only<T: 'static>(packets: &[Box<dyn Packet>], index: usize) -> &T {
    packets[index]
        .as_any()
        .downcast_ref::<T>()
        .unwrap_or_else(|| panic!("packet {index} is {:?}", packets[index]))
}

// RFC 3550 6.5 / RFC 7941 4.2.6 (audit rfc3550.md B2, rfc7941.md S1).
#[test]
fn an_sdes_item_above_type_8_does_not_end_the_chunk_or_fail_the_datagram() {
    let sdes = [
        0x81, 0xca, 0x00, 0x03, // v=2, p=0, count=1, SDES, len=3
        0x90, 0x2f, 0x9e, 0x2e, // ssrc
        0x01, 0x01, b'a', // CNAME "a"
        0x0f, 0x01, b'0', // MID "0" (RFC 8843, item 15)
        0x00, 0x00, // END + padding
    ];
    let packets = packet::unmarshal(&mut datagram(&[&SR, &sdes])).expect("SR + SDES must parse");

    assert_eq!(2, packets.len());
    only::<SenderReport>(&packets, 0);
    let sdes = only::<SourceDescription>(&packets, 1);
    assert_eq!(1, sdes.chunks.len());
    assert_eq!(2, sdes.chunks[0].items.len(), "CNAME and MID");
    assert_eq!(&b"a"[..], &sdes.chunks[0].items[0].text[..]);
    assert_eq!(&b"0"[..], &sdes.chunks[0].items[1].text[..]);
}

// RFC 3611 2 with RFC 3550 6.4.1 padding (audit rfc3611.md bug 1).
#[test]
fn a_padded_extended_report_parses_and_keeps_the_report_before_it() {
    let xr = [
        0xa0, 0xcf, 0x00, 0x05, // v=2, p=1, XR, len=5
        0x90, 0x2f, 0x9e, 0x2e, // ssrc
        0x04, 0x00, 0x00, 0x02, // BT=4 (RRTR), block length 2
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // NTP timestamp
        0x00, 0x00, 0x00, 0x04, // four padding octets
    ];
    let packets = packet::unmarshal(&mut datagram(&[&RR, &xr])).expect("RR + padded XR must parse");

    assert_eq!(2, packets.len());
    only::<ReceiverReport>(&packets, 0);
    let xr = only::<ExtendedReport>(&packets, 1);
    assert_eq!(1, xr.reports.len(), "the padding is not a report block");
}

// RFC 3611 4 (audit rfc3611.md bug 4).
#[test]
fn a_malformed_extended_report_block_does_not_fail_the_other_blocks_or_the_datagram() {
    let xr = [
        0x80, 0xcf, 0x00, 0x09, // v=2, p=0, XR, len=9
        0x90, 0x2f, 0x9e, 0x2e, // ssrc
        0x04, 0x00, 0x00, 0x03, // BT=4 (RRTR) with block length 3 instead of 2
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x05, 0x00, 0x00,
        0x03, // BT=5 (DLRR), one sub-block
        0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x09,
    ];
    let packets =
        packet::unmarshal(&mut datagram(&[&SR, &xr])).expect("SR + XR with a bad block must parse");

    assert_eq!(2, packets.len());
    only::<SenderReport>(&packets, 0);
    let xr = only::<ExtendedReport>(&packets, 1);
    assert_eq!(
        2,
        xr.reports.len(),
        "the bad block is kept, the good one parsed"
    );
    assert_eq!(vec![7], xr.reports[1].destination_ssrc());
}

// RFC 3550 6.1 "unknown packet types" (audit rfc3550.md B1).
#[test]
fn an_unknown_packet_type_is_written_back_with_its_type() {
    let raw = [0x80, 0xd0, 0x00, 0x01, 1, 2, 3, 4]; // PT 208
    let packets = packet::unmarshal(&mut Bytes::copy_from_slice(&raw)).unwrap();

    assert_eq!(1, packets.len());
    assert_eq!(&raw[..], &packet::marshal(&packets).unwrap()[..]);
}

// draft-holmer-rmcat-transport-wide-cc-extensions-01 3.1 (audit T3).
#[test]
fn transport_cc_feedback_whose_chunks_end_the_packet_is_accepted() {
    let raw = [
        0x8f, 0xcd, 0x00, 0x05, // v=2, p=0, FMT=15, RTPFB, len=5
        0x00, 0x00, 0x00, 0x01, // sender ssrc
        0x00, 0x00, 0x00, 0x02, // media ssrc
        0x00, 0x64, 0x00, 0x0f, // base sequence 100, status count 15
        0x00, 0x00, 0x01, 0x07, // reference time 1, fb pkt count 7
        0x00, 0x0a, // run length: 10 not received
        0x00, 0x05, // run length: 5 not received
    ];
    let twcc = TransportLayerCc::unmarshal(&mut Bytes::copy_from_slice(&raw))
        .expect("two chunks and no deltas is a whole packet");

    assert_eq!(15, twcc.packet_status_count);
    assert_eq!(2, twcc.packet_chunks.len());
    assert!(twcc.recv_deltas.is_empty());
    assert_eq!(&raw[..], &twcc.marshal().unwrap()[..]);
}

// Same draft, 3.1.3 / 3.1.4: the status count ends the list (audit T4).
#[test]
fn transport_cc_symbols_past_the_status_count_own_no_delta() {
    let raw = [
        0xaf, 0xcd, 0x00, 0x05, // v=2, p=1, FMT=15, RTPFB, len=5
        0x00, 0x00, 0x00, 0x01, // sender ssrc
        0x00, 0x00, 0x00, 0x02, // media ssrc
        0x00, 0x64, 0x00, 0x01, // base sequence 100, status count 1
        0x00, 0x00, 0x01, 0x07, // reference time 1, fb pkt count 7
        0xd4, 0x00, // two-bit status vector: small, small, then nothing
        0x04, // the one delta the one reported packet owns
        0x01, // one padding octet
    ];
    let twcc = TransportLayerCc::unmarshal(&mut Bytes::copy_from_slice(&raw)).unwrap();

    assert_eq!(1, twcc.recv_deltas.len(), "one packet reported, one delta");
    assert_eq!(1000, twcc.recv_deltas[0].delta);
}

// RFC 4585 6.4 (audit rfc4585.md bug 4).
#[test]
fn application_layer_feedback_that_is_not_remb_does_not_fail_the_datagram() {
    let afb = [
        0x8f, 0xce, 0x00, 0x03, // v=2, p=0, FMT=15, PSFB, len=3
        0x00, 0x00, 0x00, 0x01, // sender ssrc
        0x00, 0x00, 0x00, 0x00, // media ssrc
        b'A', b'B', b'C', b'D', // an application's own message
    ];
    let packets = packet::unmarshal(&mut datagram(&[&RR, &afb])).expect("RR + AFB must parse");

    assert_eq!(2, packets.len());
    only::<ReceiverReport>(&packets, 0);
    assert_eq!(&afb[..], &packets[1].marshal().unwrap()[..]);
}

// RFC 3611 4.1: a terminating null chunk rounds the block up (audit rfc3611.md bug 2).
#[test]
fn a_loss_rle_block_with_an_odd_chunk_count_survives_a_round_trip() {
    let xr = ExtendedReport {
        sender_ssrc: 1,
        reports: vec![Box::new(LossRLEReportBlock {
            is_loss_rle: true,
            t: 0,
            ssrc: 2,
            begin_seq: 10,
            end_seq: 16,
            chunks: vec![Chunk(0x4006)],
        })],
    };
    let raw = xr.marshal().unwrap();

    assert_eq!(
        0,
        raw[0] & 0x20,
        "no RTCP padding: the block is padded by a null chunk"
    );
    assert_eq!(&[0x40, 0x06, 0x00, 0x00][..], &raw[raw.len() - 4..]);
    assert_eq!(xr, ExtendedReport::unmarshal(&mut raw.freeze()).unwrap());
}

// RFC 3611 4: a block of a type defined later is kept as it is (audit rfc3611.md bug 3).
#[test]
fn an_extended_report_block_of_an_unknown_type_is_written_back_unchanged() {
    let raw = [
        0x80, 0xcf, 0x00, 0x03, // v=2, p=0, XR, len=3
        0x90, 0x2f, 0x9e, 0x2e, // ssrc
        0x0e, 0x5a, 0x00, 0x01, // BT=14, type-specific 0x5a, block length 1
        0x01, 0x02, 0x03, 0x04,
    ];
    let xr = ExtendedReport::unmarshal(&mut Bytes::copy_from_slice(&raw)).unwrap();

    assert_eq!(&raw[..], &xr.marshal().unwrap()[..]);
}

// RFC 3611 4.7.4 - 4.7.6 (audit rfc3611.md bug 5).
#[test]
fn default_voip_metrics_say_unavailable_not_zero() {
    let vm = VoIPMetricsReportBlock::default();

    assert_eq!(127, vm.signal_level);
    assert_eq!(127, vm.noise_level);
    assert_eq!(127, vm.rerl);
    assert_eq!(127, vm.rfactor);
    assert_eq!(127, vm.ext_rfactor);
    assert_eq!(127, vm.mos_lq);
    assert_eq!(127, vm.mos_cq);
    assert_eq!(
        16, vm.gmin,
        "RFC 3611 4.7.2 recommends 16; 0 is not allowed"
    );
}

// RFC 5104 4.3.1 (audit rfc5104.md bug 1).
#[test]
fn a_full_intra_request_without_an_entry_is_not_marshalled() {
    let fir = FullIntraRequest {
        sender_ssrc: 1,
        media_ssrc: 0,
        fir: vec![],
    };

    assert!(fir.marshal().is_err());
}

// RFC 4585 6.2.1: the length field is 16 bits (audit rfc4585.md bug 2).
#[test]
fn a_generic_nack_with_more_than_253_pairs_is_marshalled() {
    let nack = TransportLayerNack {
        sender_ssrc: 1,
        media_ssrc: 2,
        nacks: (0..300u16)
            .map(|i| NackPair {
                packet_id: i * 20,
                lost_packets: 1,
            })
            .collect(),
    };
    let raw = nack
        .marshal()
        .expect("300 pairs fit the 16-bit length field");

    assert_eq!(
        nack,
        TransportLayerNack::unmarshal(&mut raw.freeze()).unwrap()
    );
}

// RFC 3550 6.6: the reason is padded with null octets, which is not the padding of the P bit;
// a BYE without a reason has no length octet.
#[test]
fn a_goodbye_is_padded_with_nulls_and_never_sets_the_padding_bit() {
    let bare = Goodbye {
        sources: vec![1],
        reason: Bytes::new(),
    };
    assert_eq!(
        &[0x81, 0xcb, 0x00, 0x01, 0, 0, 0, 1][..],
        &bare.marshal().unwrap()[..]
    );

    let with_reason = Goodbye {
        sources: vec![1],
        reason: Bytes::from_static(b"ab"),
    };
    assert_eq!(
        &[0x81, 0xcb, 0x00, 0x02, 0, 0, 0, 1, 2, b'a', b'b', 0][..],
        &with_reason.marshal().unwrap()[..]
    );
}

// RFC 3550 6.4.1: padding is not part of the control information (audit RFC3550-6.1-13).
#[test]
fn the_padding_of_a_sender_report_is_not_a_profile_extension() {
    let mut raw = SR.to_vec();
    raw[0] |= 0x20; // P
    raw[3] += 1; // one more word
    raw.extend_from_slice(&[0, 0, 0, 4]);
    let sr = SenderReport::unmarshal(&mut Bytes::from(raw)).unwrap();

    assert!(sr.profile_extensions.is_empty());
    assert_eq!(1, sr.packet_count);
}

// Found while the tests above were written, not by the audit.

// RFC 3550 6.5: a chunk is padded with null octets. The last one was written as a padding
// count, as if it were the padding of the P bit.
#[test]
fn an_sdes_chunk_is_padded_with_null_octets() {
    let sdes = [
        0x81, 0xca, 0x00, 0x03, // v=2, p=0, count=1, SDES, len=3
        0x90, 0x2f, 0x9e, 0x2e, // ssrc
        0x01, 0x02, b'a', b'b', // CNAME "ab"
        0x00, 0x00, 0x00, 0x00, // END + three null octets
    ];
    let parsed = SourceDescription::unmarshal(&mut Bytes::copy_from_slice(&sdes)).unwrap();

    assert_eq!(&sdes[..], &parsed.marshal().unwrap()[..]);
}

// draft-alvestrand-rmcat-remb-03 2.2: mantissa * 2^exp with a mantissa of zero is zero. It
// was read as 2^(exp + 23): 8.4 Mbit/s for an estimate of nothing.
#[test]
fn a_remb_of_zero_is_read_as_zero() {
    let remb = [
        0x8f, 0xce, 0x00, 0x04, // v=2, p=0, FMT=15, PSFB, len=4
        0x00, 0x00, 0x00, 0x01, // sender ssrc
        0x00, 0x00, 0x00, 0x00, // media ssrc
        b'R', b'E', b'M', b'B', // unique identifier
        0x00, 0x00, 0x00, 0x00, // no SSRC, exp 0, mantissa 0
    ];
    let parsed =
        ReceiverEstimatedMaximumBitrate::unmarshal(&mut Bytes::copy_from_slice(&remb)).unwrap();

    assert_eq!(0.0, parsed.bitrate);
}
