//! A complete key frame releases what is missing before it
//! (`SampleBuilder::with_key_frame_release`, `Depacketizer::is_key_frame_start`): nothing sent
//! before a key frame is needed once it is there (RFC 7741 section 3, RFC 5104 section 2.2),
//! and a sender that discarded its backlog and sent a key frame never fills the gap. See
//! `docs/receiver-gap-policy.md`, rule 3.

use bytes::Bytes;
use rtp::codec::av1::Av1Depacketizer;
use rtp::codec::h264::H264Packet;
use rtp::codec::h265::H265Packet;
use rtp::codec::vp8::Vp8Packet;
use rtp::codec::vp9::Vp9Packet;
use rtp::packetizer::Depacketizer;
use rtp::{Header, Packet};
use std::time::{Duration, Instant};

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

fn pop_all<T: Depacketizer>(builder: &mut SampleBuilder<T>, now: Instant) -> Vec<Sample> {
    std::iter::from_fn(|| builder.pop(now)).collect()
}

/// What came out, as (RTP timestamp, packets dropped before it).
fn outline(samples: &[Sample]) -> Vec<(u32, u16)> {
    samples
        .iter()
        .map(|sample| (sample.packet_timestamp, sample.prev_dropped_packets))
        .collect()
}

/// One-packet frames 1 (timestamp 1000), 3 (3000), 4 (4000) and 5 (5000) with packet 2 never
/// arriving, on a builder with no bound in time (so nothing but a key frame can release the
/// gap here): frames 1, 3 and 5 are interframes and frame 4 is `fourth`.
fn fourth_frame<T: Depacketizer>(
    depacketizer: T,
    inter: &[u8],
    fourth: &[u8],
) -> (Vec<(u32, u16)>, SampleBuilder<T>) {
    let now = Instant::now();
    let mut builder = SampleBuilder::new(256, depacketizer, 90_000).with_max_gap_wait(None);
    let mut samples = Vec::new();
    for (sequence_number, payload) in [(1u16, inter), (3, inter), (4, fourth), (5, inter)] {
        builder.push(
            now,
            packet(
                sequence_number,
                1000 * u32::from(sequence_number),
                true,
                payload,
            ),
        );
        samples.extend(pop_all(&mut builder, now));
    }
    (outline(&samples), builder)
}

/// With a key frame fourth: frame 1 (complete before the gap) comes out, the missing packet 2
/// and frame 3 are dropped, and the key frame is the next sample, counting the two; no
/// key-frame request is raised. With an interframe fourth nothing is released: every frame
/// waits behind the gap.
fn a_key_frame_releases_and_an_interframe_does_not<T: Depacketizer>(
    make: impl Fn() -> T,
    inter: &[u8],
    key: &[u8],
) {
    let (samples, mut builder) = fourth_frame(make(), inter, key);
    assert_eq!(vec![(1000, 0), (4000, 2)], samples);
    assert_eq!(1, builder.key_frame_releases());
    assert!(!builder.take_key_frame_request(), "the key frame is there");
    assert_eq!(0, builder.skipped_gaps());
    assert_eq!(Some(5), builder.nack_horizon());

    let (samples, mut builder) = fourth_frame(make(), inter, inter);
    assert_eq!(Vec::<(u32, u16)>::new(), samples, "held behind the gap");
    assert_eq!(0, builder.key_frame_releases());
    assert!(!builder.take_key_frame_request());
    assert_eq!(None, builder.nack_horizon());
}

/// VP8 (RFC 7741 section 4.3): the payload header's P bit, 0 in a key frame.
#[test]
fn a_complete_vp8_key_frame_releases_the_gap_before_it() {
    a_key_frame_releases_and_an_interframe_does_not(
        Vp8Packet::default,
        &[0x10, 0x01, 0xAA],
        &[0x10, 0x00, 0xAA],
    );
}

/// VP9 (RFC 9628 section 4.2): the descriptor's P bit, 0 in a frame without inter-picture
/// prediction (B and E set: a frame of one packet).
#[test]
fn a_complete_vp9_key_frame_releases_the_gap_before_it() {
    a_key_frame_releases_and_an_interframe_does_not(
        Vp9Packet::default,
        &[0x4C, 0xAA],
        &[0x0C, 0xAA],
    );
}

/// AV1 (RTP specification section 4.4): the aggregation header's N bit, set on the first
/// packet of a coded video sequence (W=1: one OBU, a frame OBU).
#[test]
fn a_complete_av1_key_frame_releases_the_gap_before_it() {
    a_key_frame_releases_and_an_interframe_does_not(
        Av1Depacketizer::new,
        &[0x10, 0x30, 0xAA, 0xBB],
        &[0x18, 0x30, 0xAA, 0xBB],
    );
}

/// H.264 (RFC 6184): a single NAL unit packet with the first slice of an IDR picture.
#[test]
fn a_complete_h264_key_frame_releases_the_gap_before_it() {
    a_key_frame_releases_and_an_interframe_does_not(
        H264Packet::default,
        &[0x41, 0x9A, 0x00],
        &[0x65, 0x88, 0x80],
    );
}

/// H.265 (RFC 7798): a single NAL unit packet with the first slice segment of an IDR picture.
#[test]
fn a_complete_h265_key_frame_releases_the_gap_before_it() {
    a_key_frame_releases_and_an_interframe_does_not(
        H265Packet::default,
        &[0x02, 0x01, 0x80, 0x00],
        &[0x26, 0x01, 0x80, 0x00],
    );
}

/// A key frame releases the gap only once every packet of it is there. VP8: frame A (1),
/// frame B (2 and the missing 3), interframe C (4), key frame K (5, 6, 7) and interframe D
/// (8). With 5 and 6 of K nothing moves; when 7 completes it, A comes out, B's packet 2, the
/// missing 3 and C are dropped (three packets), and K is the next sample once D has arrived
/// behind it.
#[test]
fn an_incomplete_key_frame_releases_nothing_until_its_last_packet() {
    let now = Instant::now();
    let inter_head = [0x10, 0x01, 0xAA];
    let key_head = [0x10, 0x00, 0xAA];
    let continuation = [0x00, 0xBB, 0xCC];
    let mut builder = SampleBuilder::new(256, Vp8Packet::default(), 90_000).with_max_gap_wait(None);
    let mut samples = Vec::new();
    for p in [
        packet(1, 1000, true, &inter_head),
        packet(2, 2000, false, &inter_head),
        packet(4, 4000, true, &inter_head),
        packet(5, 5000, false, &key_head),
        packet(6, 5000, false, &continuation),
    ] {
        builder.push(now, p);
        samples.extend(pop_all(&mut builder, now));
    }
    assert_eq!(vec![(1000, 0)], outline(&samples), "A; B waits for 3");
    assert_eq!(0, builder.key_frame_releases());

    builder.push(now, packet(7, 5000, true, &continuation));
    samples.extend(pop_all(&mut builder, now));
    assert_eq!(1, builder.key_frame_releases());
    assert_eq!(Some(5), builder.nack_horizon());
    assert_eq!(
        vec![(1000, 0)],
        outline(&samples),
        "K waits for its successor"
    );

    builder.push(now, packet(8, 8000, true, &inter_head));
    samples.extend(pop_all(&mut builder, now));
    assert_eq!(vec![(1000, 0), (5000, 3)], outline(&samples));
    assert_eq!(
        Bytes::from_static(&[0x00, 0xAA, 0xBB, 0xCC, 0xBB, 0xCC]),
        samples[1].data,
        "the whole key frame"
    );
    assert!(!builder.take_key_frame_request());
}

/// Late repairs of what a key frame released are ignored: packets 2 and 3 arrive after the
/// key frame (4) released the gap. They start no gap, and frames go on in order.
#[test]
fn repairs_of_what_a_key_frame_released_are_ignored() {
    let inter = [0x10, 0x01, 0xAA];
    let (samples, mut builder) = fourth_frame(Vp8Packet::default(), &inter, &[0x10, 0x00, 0xAA]);
    assert_eq!(vec![(1000, 0), (4000, 2)], samples);

    let now = Instant::now();
    builder.push(now, packet(2, 2000, true, &inter));
    builder.push(now, packet(3, 3000, true, &inter));
    builder.push(now, packet(6, 6000, true, &inter));
    let samples = pop_all(&mut builder, now);
    assert_eq!(vec![(5000, 0)], outline(&samples));
    assert_eq!(1, builder.key_frame_releases());
    assert_eq!(None, builder.poll_timeout());
}

/// With the release turned off a key frame behind a gap waits like any other frame: only a
/// bound gives the gap up (here the time bound, 200 ms after the gap was known), with its
/// key-frame request.
#[test]
fn without_key_frame_release_only_a_bound_gives_the_gap_up() {
    let t0 = Instant::now();
    let inter = [0x10, 0x01, 0xAA];
    let key = [0x10, 0x00, 0xAA];
    let mut builder = SampleBuilder::new(256, Vp8Packet::default(), 90_000)
        .with_max_gap_wait(Duration::from_millis(200))
        .with_key_frame_release(false);
    let mut samples = Vec::new();
    for (sequence_number, payload) in [(1u16, &inter), (3, &inter), (4, &key), (5, &inter)] {
        builder.push(
            t0,
            packet(
                sequence_number,
                1000 * u32::from(sequence_number),
                true,
                payload,
            ),
        );
        samples.extend(pop_all(&mut builder, t0));
    }
    assert_eq!(Vec::<(u32, u16)>::new(), outline(&samples));
    assert_eq!(0, builder.key_frame_releases());
    assert_eq!(
        Some(t0 + Duration::from_millis(200)),
        builder.poll_timeout()
    );

    samples.extend(pop_all(&mut builder, t0 + Duration::from_millis(200)));
    assert_eq!(vec![(1000, 0), (3000, 1), (4000, 0)], outline(&samples));
    assert!(builder.take_key_frame_request());
    assert_eq!(1, builder.skipped_gaps());
}

/// H.264 parameter sets sent in packets of their own before the IDR slice belong to the key
/// frame (the same RTP timestamp, RFC 6184 section 5.1) and come out with it: interframe 1,
/// the missing 2, then SPS (3), PPS (4) and the IDR slice (5) of one access unit, then
/// interframe 6.
#[test]
fn h264_parameter_sets_before_the_idr_slice_are_kept_with_the_key_frame() {
    let now = Instant::now();
    let inter = [0x41, 0x9A, 0x00];
    let mut builder =
        SampleBuilder::new(256, H264Packet::default(), 90_000).with_max_gap_wait(None);
    let mut samples = Vec::new();
    for p in [
        packet(1, 1000, true, &inter),
        packet(3, 5000, false, &[0x67, 0x42, 0x00]),
        packet(4, 5000, false, &[0x68, 0xCE, 0x3C]),
        packet(5, 5000, true, &[0x65, 0x88, 0x80]),
        packet(6, 6000, true, &inter),
    ] {
        builder.push(now, p);
        samples.extend(pop_all(&mut builder, now));
    }
    assert_eq!(vec![(1000, 0), (5000, 1)], outline(&samples));
    assert_eq!(
        Bytes::from_static(&[
            0, 0, 0, 1, 0x67, 0x42, 0x00, 0, 0, 0, 1, 0x68, 0xCE, 0x3C, 0, 0, 0, 1, 0x65, 0x88,
            0x80
        ]),
        samples[1].data
    );
    assert_eq!(1, builder.key_frame_releases());
}

/// A key frame with no gap before it changes nothing: every frame comes out in order.
#[test]
fn a_key_frame_without_a_gap_before_it_releases_nothing() {
    let (samples, builder) = {
        let now = Instant::now();
        let mut builder = SampleBuilder::new(256, Vp8Packet::default(), 90_000);
        let mut samples = Vec::new();
        for (sequence_number, payload) in [
            (1u16, [0x10, 0x01, 0xAA]),
            (2, [0x10, 0x01, 0xAA]),
            (3, [0x10, 0x00, 0xAA]),
            (4, [0x10, 0x01, 0xAA]),
        ] {
            builder.push(
                now,
                packet(
                    sequence_number,
                    1000 * u32::from(sequence_number),
                    true,
                    &payload,
                ),
            );
            samples.extend(pop_all(&mut builder, now));
        }
        (outline(&samples), builder)
    };
    assert_eq!(vec![(1000, 0), (2000, 0), (3000, 0)], samples);
    assert_eq!(0, builder.key_frame_releases());
}
