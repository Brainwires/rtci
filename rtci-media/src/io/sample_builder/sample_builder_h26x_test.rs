//! H.264 (RFC 6184) and H.265 (RFC 7798) through the sample builder: NAL units come out in
//! RTP sequence-number order whatever order their packets arrive in, a fragmented NAL unit
//! is reassembled in that order, duplicates are dropped, and an access unit ends at a new
//! timestamp even when the marker bit that should have ended it never came.

use bytes::Bytes;
use rtp::codec::h264::H264Packet;
use rtp::codec::h265::H265Packet;
use rtp::packetizer::Depacketizer;
use rtp::{Header, Packet};
use std::time::Instant;

use super::*;

fn packet(sequence_number: u16, timestamp: u32, marker: bool, payload: &[u8]) -> Packet {
    Packet {
        header: Header {
            sequence_number,
            timestamp,
            marker,
            ..Default::default()
        },
        payload: Bytes::copy_from_slice(payload),
    }
}

/// The samples (data, RTP timestamp) that come out of pushing `packets` in the given order.
fn samples<T: Depacketizer>(depacketizer: T, packets: Vec<Packet>) -> Vec<(Bytes, u32)> {
    let now = Instant::now();
    let mut builder = SampleBuilder::new(10, depacketizer, 90000);
    let mut out = vec![];
    for p in packets {
        builder.push(now, p);
        while let Some((sample, timestamp)) = builder.pop_with_timestamp(now) {
            out.push((sample.data, timestamp));
        }
    }
    out
}

fn annex_b(units: &[&[u8]]) -> Bytes {
    let mut out = vec![];
    for unit in units {
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(unit);
    }
    Bytes::from(out)
}

const IDR: &[u8] = &[0x65, 0xA0, 0xA1];
const SLICE_1: &[u8] = &[0x41, 0xB0];
const SLICE_2: &[u8] = &[0x41, 0xB1];
const NEXT: &[u8] = &[0x41, 0xC0];

/// RFC 6184 sections 5.6 and 7.1: in the single NAL unit and non-interleaved modes NAL units
/// are passed to the decoder in RTP sequence-number order. Packets that arrive 3, 1, 2 come
/// out 1, 2, 3.
#[test]
fn h264_nal_units_come_out_in_sequence_number_order() {
    let out = samples(
        H264Packet::default(),
        vec![
            packet(3, 3000, true, SLICE_2),
            packet(1, 3000, false, IDR),
            packet(2, 3000, false, SLICE_1),
            packet(4, 6000, true, NEXT),
            packet(5, 9000, true, NEXT),
        ],
    );
    assert_eq!((annex_b(&[IDR, SLICE_1, SLICE_2]), 3000), out[0]);
}

/// RFC 6184 section 5.8: the fragments of an FU-A are put together in sequence-number order.
#[test]
fn h264_fragments_are_reassembled_in_sequence_number_order() {
    // An IDR NAL unit (header 0x65) in three FU-A fragments: indicator 0x7C, headers with the
    // start (0x85), middle (0x05) and end (0x45) bits.
    let out = samples(
        H264Packet::default(),
        vec![
            packet(12, 3000, true, &[0x7C, 0x45, 0x05, 0x06]),
            packet(10, 3000, false, &[0x7C, 0x85, 0x01, 0x02]),
            packet(11, 3000, false, &[0x7C, 0x05, 0x03, 0x04]),
            packet(13, 6000, true, NEXT),
            packet(14, 9000, true, NEXT),
        ],
    );
    assert_eq!(
        (
            annex_b(&[&[0x65, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]]),
            3000
        ),
        out[0]
    );
}

/// RFC 6184 section 5.1: "decoders MUST NOT rely on this property" (the marker bit on the
/// last packet of an access unit): an access unit whose marker never came ends where the
/// next timestamp begins.
#[test]
fn an_h264_access_unit_ends_at_the_next_timestamp_without_a_marker() {
    let out = samples(
        H264Packet::default(),
        vec![
            packet(1, 3000, false, IDR),
            packet(2, 3000, false, SLICE_1),
            packet(3, 6000, true, NEXT),
            packet(4, 9000, true, NEXT),
        ],
    );
    assert_eq!((annex_b(&[IDR, SLICE_1]), 3000), out[0]);
    assert_eq!((annex_b(&[NEXT]), 6000), out[1]);
}

const H265_IDR: &[u8] = &[0x26, 0x01, 0xD0];
const H265_TRAIL_1: &[u8] = &[0x02, 0x01, 0xE0];
const H265_TRAIL_2: &[u8] = &[0x02, 0x01, 0xE1];

/// RFC 7798 section 6: with `sprop-max-don-diff` 0 "NAL units ... are passed in RTP
/// sequence number order" and "duplicated or outdated RTP packets ... are removed": packets
/// 3, 1, 2, 1 again come out 1, 2, 3, once each.
#[test]
fn h265_nal_units_come_out_in_order_and_duplicates_once() {
    let out = samples(
        H265Packet::default(),
        vec![
            packet(3, 3000, true, H265_TRAIL_2),
            packet(1, 3000, false, H265_IDR),
            packet(2, 3000, false, H265_TRAIL_1),
            packet(1, 3000, false, H265_IDR),
            packet(4, 6000, true, H265_TRAIL_1),
            packet(5, 9000, true, H265_TRAIL_1),
        ],
    );
    assert_eq!(
        (annex_b(&[H265_IDR, H265_TRAIL_1, H265_TRAIL_2]), 3000),
        out[0]
    );
    assert_eq!(1, out.iter().filter(|(_, ts)| *ts == 3000).count());
}

/// Pushes an access unit whose packets are `fragments` (sequence numbers from 10, timestamp
/// 3000, the marker on the last) with the one at `lost` left out, then single-packet access
/// units until the builder has given up the gap; returns the samples.
fn samples_after_a_lost_fragment<T: Depacketizer>(
    depacketizer: T,
    fragments: &[&[u8]],
    lost: usize,
    next: &[u8],
) -> Vec<(Bytes, u32)> {
    let mut packets = vec![];
    for (i, fragment) in fragments.iter().enumerate() {
        if i != lost {
            packets.push(packet(
                10 + i as u16,
                3000,
                i == fragments.len() - 1,
                fragment,
            ));
        }
    }
    let first_next = 10 + fragments.len() as u16;
    for n in 0..16u16 {
        packets.push(packet(
            first_next + n,
            6000 + 3000 * u32::from(n),
            true,
            next,
        ));
    }
    samples(depacketizer, packets)
}

/// RFC 6184 section 5.8: "the receiver SHOULD discard the following fragmentation units ...
/// in transmission order corresponding to the same fragmented NAL unit" after a lost one.
/// The sample builder never hands a depacketizer packets across a missing sequence number:
/// the access unit whose middle FU-A was lost is dropped whole (its start, and the end that
/// follows the loss), never spliced into a NAL unit with a hole in it; the next access unit
/// comes out.
#[test]
fn h264_an_access_unit_whose_middle_fragment_was_lost_is_dropped() {
    let out = samples_after_a_lost_fragment(
        H264Packet::default(),
        &[
            &[0x7C, 0x85, 0x01, 0x02],
            &[0x7C, 0x05, 0x03, 0x04],
            &[0x7C, 0x45, 0x05, 0x06],
        ],
        1,
        NEXT,
    );
    assert!(
        out.iter().all(|(_, ts)| *ts != 3000),
        "the access unit with the lost fragment is not delivered: {out:?}"
    );
    assert!(
        out.iter()
            .all(|(data, _)| !data.windows(2).any(|w| w == [0x05, 0x06])),
        "the fragment after the loss is discarded: {out:?}"
    );
    assert_eq!((annex_b(&[NEXT]), 6000), out[0]);
}

/// RFC 7798 section 4.4.3: "the receiver SHOULD discard the following fragmentation units
/// in transmission order corresponding to the same fragmented NAL unit" after a lost one.
/// As for H.264: the access unit is dropped, the next one comes out.
#[test]
fn h265_an_access_unit_whose_middle_fragment_was_lost_is_dropped() {
    // An IDR_W_RADL NAL unit (type 19) in three FUs: payload header type 49 (0x62 0x01), FU
    // headers start (0x93), middle (0x13), end (0x53).
    let out = samples_after_a_lost_fragment(
        H265Packet::default(),
        &[
            &[0x62, 0x01, 0x93, 0x01, 0x02],
            &[0x62, 0x01, 0x13, 0x03, 0x04],
            &[0x62, 0x01, 0x53, 0x05, 0x06],
        ],
        1,
        H265_TRAIL_1,
    );
    assert!(
        out.iter().all(|(_, ts)| *ts != 3000),
        "the access unit with the lost fragment is not delivered: {out:?}"
    );
    assert!(
        out.iter()
            .all(|(data, _)| !data.windows(2).any(|w| w == [0x05, 0x06])),
        "the fragment after the loss is discarded: {out:?}"
    );
    assert_eq!((annex_b(&[H265_TRAIL_1]), 6000), out[0]);
}

/// The NAL units (their last octet, a tag) of the samples that come out when packets
/// `1..=n` carrying `payload(seq)` arrive in `arrival` order, then packets `n+1..n+8` in
/// order: each packet is an access unit of its own.
fn tags_through_jitter<T: Depacketizer>(
    depacketizer: T,
    payload: impl Fn(u16) -> Vec<u8>,
    arrival: &[u16],
    unit_len: usize,
) -> Vec<u8> {
    let last = *arrival.iter().max().unwrap_or(&0);
    let mut packets: Vec<Packet> = arrival
        .iter()
        .map(|&seq| packet(seq, 3000 * u32::from(seq), true, &payload(seq)))
        .collect();
    for seq in last + 1..=last + 8 {
        packets.push(packet(seq, 3000 * u32::from(seq), true, &payload(seq)));
    }
    let data: Vec<u8> = samples(depacketizer, packets)
        .into_iter()
        .flat_map(|(data, _)| data.to_vec())
        .collect();
    data.chunks(unit_len)
        .map(|unit| unit[unit_len - 1])
        .collect()
}

/// The DONs sent, by sequence number: pairs swapped (interleaved), then in order.
fn interleaved_don(seq: u16) -> u16 {
    let i = seq - 1;
    if i < 8 { i ^ 1 } else { i }
}

/// Arrival order with transmission delay jitter: packets 1 to 8 arrive 3 1 4 2 7 5 8 6.
const JITTERED: [u16; 8] = [3, 1, 4, 2, 7, 5, 8, 6];

/// RFC 6184 section 7.2: "Receivers SHOULD also prepare for transmission delay jitter, i.e.,
/// either reserve separate buffers for transmission delay jitter buffering and
/// de-interleaving buffering ..." and "take transmission delay jitter into account in the
/// buffering operation". The sample builder is the jitter buffer, the depacketizer's
/// de-interleaving buffer the other: an interleaved stream (DONs 1 0 3 2 ...) whose packets
/// also arrive out of order comes out in decoding order. The de-interleaving buffer alone,
/// given the packets as they arrived, would not restore it.
#[test]
fn h264_an_interleaved_stream_with_jitter_comes_out_in_decoding_order() {
    let depacketizer = || {
        H264Packet::default()
            .with_deinterleaving(rtp::codec::h264::H264DeinterleavingBuffer::new(1, None))
    };
    let payload = |seq: u16| {
        let don = interleaved_don(seq);
        rtp::codec::h264::stap_b(don, &[Bytes::from(vec![0x41, don as u8])])
            .expect("a STAP-B")
            .to_vec()
    };
    let tags = tags_through_jitter(depacketizer(), payload, &JITTERED, 6);
    assert!(tags.len() >= 8, "{tags:?}");
    assert_eq!((0..tags.len() as u8).collect::<Vec<_>>(), tags);
}

/// RFC 7798 section 6: "Receivers should also prepare for transmission delay jitter; that is,
/// either reserve separate buffers for transmission delay jitter buffering and
/// de-packetization buffering or use a receiver buffer for both". As for H.264: DONL single
/// NAL unit packets sent out of decoding order (`sprop-max-don-diff` 1) and arriving out of
/// order come out in decoding order.
#[test]
fn h265_a_reordered_stream_with_jitter_comes_out_in_decoding_order() {
    let mut depacketizer = H265Packet::default();
    depacketizer
        .with_depacketization_buffer(rtp::codec::h265::H265DepacketizationBuffer::new(1, 1));
    let payload = |seq: u16| {
        let don = interleaved_don(seq);
        vec![0x02, 0x01, (don >> 8) as u8, don as u8, don as u8]
    };
    let tags = tags_through_jitter(depacketizer, payload, &JITTERED, 7);
    assert!(tags.len() >= 8, "{tags:?}");
    assert_eq!((0..tags.len() as u8).collect::<Vec<_>>(), tags);
}
