//! Packets without a payload: present, and not media. The engine delivers one for every
//! sequence number of a video stream that a FEC packet took (ULPFEC in RED packets of its own,
//! the form browsers send: RFC 2198 with RFC 5109 section 14.2), and libwebrtc sends padding
//! in the media stream's sequence numbers. To the builder such a packet is not a gap, belongs
//! to no sample and starts none.

use bytes::Bytes;
use rtp::codec::vp8::Vp8Packet;
use rtp::{Header, Packet};
use std::time::{Duration, Instant};

use super::*;

/// A VP8 packet (RFC 7741 section 4.2) of an interframe: `head` starts a frame (S=1, PID=0,
/// then the payload header with P=1), otherwise it continues one; `marker` ends it.
fn vp8(sequence_number: u16, timestamp: u32, head: bool, marker: bool) -> Packet {
    let descriptor = if head { 0x10 } else { 0x00 };
    Packet {
        header: Header {
            sequence_number,
            timestamp,
            marker,
            ..Default::default()
        },
        payload: Bytes::from(vec![descriptor, 0x01, sequence_number as u8]),
    }
}

/// What the engine delivers for a sequence number a FEC packet took: the packet's header (the
/// timestamp of the frame the FEC followed, no marker) and no payload.
fn emptied(sequence_number: u16, timestamp: u32) -> Packet {
    Packet {
        header: Header {
            sequence_number,
            timestamp,
            ..Default::default()
        },
        payload: Bytes::new(),
    }
}

fn ms(milliseconds: u64) -> Duration {
    Duration::from_millis(milliseconds)
}

fn pop_all(builder: &mut SampleBuilder<Vp8Packet>, now: Instant) -> Vec<Sample> {
    std::iter::from_fn(|| builder.pop(now)).collect()
}

/// Pushes the packets 10 ms apart from `t0`, popping after each: the samples each one released.
fn feed(
    builder: &mut SampleBuilder<Vp8Packet>,
    t0: Instant,
    packets: Vec<Packet>,
) -> Vec<(u16, Sample)> {
    let mut released = Vec::new();
    for (i, packet) in packets.into_iter().enumerate() {
        let now = t0 + ms(10 * i as u64);
        let sequence_number = packet.header.sequence_number;
        builder.push(now, packet);
        assert_eq!(
            None,
            builder.poll_timeout(),
            "no gap is waited for after packet {sequence_number}"
        );
        released.extend(
            pop_all(builder, now)
                .into_iter()
                .map(|sample| (sequence_number, sample)),
        );
    }
    released
}

/// A frame of four media packets with a FEC sequence number between them (3) and two after
/// its last packet (6, 7), then two one-packet frames. The frame comes out whole, without its
/// empty packet, as soon as the next frame's first packet says how long it lasts; nothing is a
/// gap, nothing is waited for and no key frame is asked for. The empty packets after the frame
/// are counted as padding before the next sample.
#[test]
fn a_frame_with_empty_packets_inside_and_after_it_completes_without_waiting() {
    let t0 = Instant::now();
    let mut builder = SampleBuilder::new(256, Vp8Packet::default(), 90_000);
    let released = feed(
        &mut builder,
        t0,
        vec![
            vp8(1, 3000, true, false),
            vp8(2, 3000, false, false),
            emptied(3, 3000),
            vp8(4, 3000, false, false),
            vp8(5, 3000, false, true),
            emptied(6, 3000),
            emptied(7, 3000),
            vp8(8, 6000, true, true),
            vp8(9, 9000, true, true),
        ],
    );

    assert_eq!(2, released.len(), "the two frames with a successor");
    let (at, frame) = &released[0];
    assert_eq!(8, *at, "released by the first media packet after it");
    assert_eq!(3000, frame.packet_timestamp);
    assert_eq!(
        &[0x01, 1, 0x01, 2, 0x01, 4, 0x01, 5][..],
        &frame.data[..],
        "the four media packets, in order"
    );
    assert_eq!(
        Duration::from_secs_f64(3000.0 / 90_000.0),
        frame.duration,
        "until the next frame, not until the empty packet behind it"
    );
    assert_eq!(0, frame.prev_dropped_packets);

    let (at, next) = &released[1];
    assert_eq!(9, *at);
    assert_eq!(6000, next.packet_timestamp);
    assert_eq!(2, next.prev_padding_packets, "packets 6 and 7");
    assert_eq!(
        0,
        next.prev_dropped_packets
            .saturating_sub(next.prev_padding_packets),
        "no media was dropped"
    );
    assert!(!builder.take_key_frame_request());
    assert_eq!(0, builder.skipped_gaps());
}

/// An empty packet does not make a missing media packet present: with packet 2 of the frame
/// missing and an empty packet at 3, the frame waits, is given up at the bound and a key frame
/// is asked for.
#[test]
fn a_missing_media_packet_beside_an_empty_packet_is_still_a_gap() {
    let t0 = Instant::now();
    let mut builder =
        SampleBuilder::new(256, Vp8Packet::default(), 90_000).with_max_gap_wait(ms(200));
    let mut samples = Vec::new();
    for (at, packet) in [
        (ms(0), vp8(1, 3000, true, false)),
        (ms(10), emptied(3, 3000)),
        (ms(20), vp8(4, 3000, false, true)),
        (ms(30), vp8(5, 6000, true, true)),
        (ms(40), vp8(6, 9000, true, true)),
    ] {
        builder.push(t0 + at, packet);
        samples.extend(pop_all(&mut builder, t0 + at));
    }
    assert!(samples.is_empty(), "the frame waits for packet 2");
    assert_eq!(
        Some(t0 + ms(210)),
        builder.poll_timeout(),
        "the gap was known when packet 3 arrived"
    );

    assert!(pop_all(&mut builder, t0 + ms(209)).is_empty());
    let samples = pop_all(&mut builder, t0 + ms(210));
    assert_eq!(
        vec![6000],
        samples
            .iter()
            .map(|sample| sample.packet_timestamp)
            .collect::<Vec<_>>(),
        "the incomplete frame is dropped; the next one comes out"
    );
    assert!(builder.take_key_frame_request(), "a key frame is asked for");
    assert_eq!(1, builder.skipped_gaps());
}

/// A sample lasts until the next one starts, and an empty packet starts none: a frame followed
/// by an empty packet waits for the next media packet, as it would without the empty packet,
/// and has its real duration.
#[test]
fn an_empty_packet_does_not_say_when_the_next_sample_starts() {
    let t0 = Instant::now();
    let mut builder = SampleBuilder::new(256, Vp8Packet::default(), 90_000);
    builder.push(t0, vp8(1, 3000, true, true));
    builder.push(t0 + ms(5), emptied(2, 3000));
    assert!(
        pop_all(&mut builder, t0 + ms(5)).is_empty(),
        "nothing says yet how long the frame lasts"
    );

    builder.push(t0 + ms(33), vp8(3, 6000, true, true));
    let samples = pop_all(&mut builder, t0 + ms(33));
    assert_eq!(1, samples.len());
    assert_eq!(3000, samples[0].packet_timestamp);
    assert_eq!(
        Duration::from_secs_f64(3000.0 / 90_000.0),
        samples[0].duration
    );
}

/// The empty packets behind a frame that was given up are padding too, not lost media: frame B
/// (packets 2 and the missing 3) is dropped at the bound, the FEC sequence number behind it (4,
/// with B's timestamp) is counted as padding, and frame C reports two packets of media
/// dropped, not three.
#[test]
fn empty_packets_behind_a_frame_that_was_given_up_are_padding() {
    let t0 = Instant::now();
    let mut builder =
        SampleBuilder::new(256, Vp8Packet::default(), 90_000).with_max_gap_wait(ms(200));
    let mut samples = Vec::new();
    for (at, packet) in [
        (ms(0), vp8(1, 3000, true, true)),
        (ms(10), vp8(2, 6000, true, false)),
        (ms(20), emptied(4, 6000)),
        (ms(30), vp8(5, 9000, true, true)),
        (ms(40), vp8(6, 12000, true, true)),
    ] {
        builder.push(t0 + at, packet);
        samples.extend(pop_all(&mut builder, t0 + at));
    }
    samples.extend(pop_all(&mut builder, t0 + ms(220)));

    assert_eq!(
        vec![3000, 9000],
        samples
            .iter()
            .map(|sample| sample.packet_timestamp)
            .collect::<Vec<_>>()
    );
    let after_the_gap = &samples[1];
    assert_eq!(1, after_the_gap.prev_padding_packets, "packet 4");
    assert_eq!(
        2,
        after_the_gap
            .prev_dropped_packets
            .saturating_sub(after_the_gap.prev_padding_packets),
        "packet 2 and the missing packet 3"
    );
}
