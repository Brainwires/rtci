//! The wall-clock bound on a gap (`SampleBuilder::with_max_gap_wait`): a missing packet is
//! waited for as long as the bound from when the builder knew of the gap, then given up with a
//! key-frame request (see `docs/receiver-gap-policy.md`).

use bytes::Bytes;
use rtp::codec::vp8::Vp8Packet;
use rtp::{Header, Packet};
use std::time::{Duration, Instant};

use super::*;

/// A VP8 packet (RFC 7741 section 4.2): `head` starts a frame (S=1, PID=0), otherwise it
/// continues one; `marker` ends it.
fn vp8(sequence_number: u16, timestamp: u32, head: bool, marker: bool) -> Packet {
    let descriptor = if head { 0x10 } else { 0x00 };
    Packet {
        header: Header {
            sequence_number,
            timestamp,
            marker,
            ..Default::default()
        },
        payload: Bytes::from(vec![descriptor, sequence_number as u8, 0xAB]),
    }
}

fn ms(milliseconds: u64) -> Duration {
    Duration::from_millis(milliseconds)
}

/// Frame A (sequence number 1, timestamp 3000), frame B (2 and 3, timestamp 6000), frame C (4,
/// timestamp 9000) and frame D (5, timestamp 12000): the packets other than 3, arriving 10 ms
/// apart from `t0`, so the gap at 3 is known at `t0 + 20 ms` (when 4 arrives).
fn without_packet_3(builder: &mut SampleBuilder<Vp8Packet>, t0: Instant) -> Vec<Sample> {
    let mut samples = Vec::new();
    for (at, packet) in [
        (ms(0), vp8(1, 3000, true, true)),
        (ms(10), vp8(2, 6000, true, false)),
        (ms(20), vp8(4, 9000, true, true)),
        (ms(30), vp8(5, 12000, true, true)),
    ] {
        builder.push(t0 + at, packet);
        samples.extend(pop_all(builder, t0 + at));
    }
    samples
}

fn pop_all(builder: &mut SampleBuilder<Vp8Packet>, now: Instant) -> Vec<Sample> {
    std::iter::from_fn(|| builder.pop(now)).collect()
}

fn timestamps(samples: &[Sample]) -> Vec<u32> {
    samples
        .iter()
        .map(|sample| sample.packet_timestamp)
        .collect()
}

/// A gap that never fills is given up once it has been missing for the bound: packet 3 is
/// missing from 20 ms (when 4 arrived), the bound is 200 ms, so nothing changes at 219 ms and
/// at 220 ms frame B (its packet 2 and the missing 3) is dropped, frame C comes out counting the
/// two packets in `prev_dropped_packets`, and a key-frame request is raised, once.
#[test]
fn a_gap_that_never_fills_is_skipped_at_the_bound_with_a_key_frame_request() {
    let t0 = Instant::now();
    let mut builder =
        SampleBuilder::new(256, Vp8Packet::default(), 90_000).with_max_gap_wait(ms(200));
    let samples = without_packet_3(&mut builder, t0);
    assert_eq!(vec![3000], timestamps(&samples), "B waits for 3");

    assert!(
        pop_all(&mut builder, t0 + ms(219)).is_empty(),
        "not before the bound"
    );
    assert!(!builder.take_key_frame_request());

    let samples = pop_all(&mut builder, t0 + ms(220));
    assert_eq!(
        vec![9000],
        timestamps(&samples),
        "C, and D waits for its successor"
    );
    assert_eq!(2, samples[0].prev_dropped_packets);
    assert!(builder.take_key_frame_request(), "a key frame is asked for");
    assert!(!builder.take_key_frame_request(), "once");
    assert_eq!(1, builder.skipped_gaps());
    assert_eq!(None, builder.poll_timeout(), "no gap left");
}

/// A gap repaired before the bound changes nothing: packet 3 arrives at 150 ms, B and C come
/// out in order with nothing dropped, and no key frame is asked for, then or later.
#[test]
fn a_gap_repaired_before_the_bound_changes_nothing() {
    let t0 = Instant::now();
    let mut builder =
        SampleBuilder::new(256, Vp8Packet::default(), 90_000).with_max_gap_wait(ms(200));
    let mut samples = without_packet_3(&mut builder, t0);
    builder.push(t0 + ms(150), vp8(3, 6000, false, true));
    samples.extend(pop_all(&mut builder, t0 + ms(150)));
    samples.extend(pop_all(&mut builder, t0 + ms(1_000)));

    assert_eq!(vec![3000, 6000, 9000], timestamps(&samples));
    assert!(
        samples
            .iter()
            .all(|sample| sample.prev_dropped_packets == 0)
    );
    assert!(!builder.take_key_frame_request());
    assert_eq!(0, builder.skipped_gaps());
    assert_eq!(None, builder.poll_timeout());
}

/// Without the bound the builder behaves as before: the gap holds B, C and D back however long
/// nothing arrives (10 s here), no deadline is named and no key frame is asked for; the gap is
/// given up only when more than `max_late` (8) positions are buffered, by the packets that
/// arrive behind it: 10 drops packet 2 and 11 the missing 3 (positions 2 to 11 buffered), and C
/// then counts the two packets dropped.
#[test]
fn without_the_bound_a_gap_is_held_until_max_late() {
    let t0 = Instant::now();
    let mut builder = SampleBuilder::new(8, Vp8Packet::default(), 90_000);
    let mut samples = without_packet_3(&mut builder, t0);
    assert_eq!(None, builder.poll_timeout());
    samples.extend(pop_all(&mut builder, t0 + ms(10_000)));
    assert_eq!(vec![3000], timestamps(&samples), "held after 10 s");
    assert!(!builder.take_key_frame_request());

    for sequence_number in 6..=11u16 {
        let at = t0 + ms(10_000) + ms(10) * u32::from(sequence_number);
        builder.push(
            at,
            vp8(
                sequence_number,
                3000 * u32::from(sequence_number),
                true,
                true,
            ),
        );
        samples.extend(pop_all(&mut builder, at));
    }
    let c = samples
        .iter()
        .find(|sample| sample.packet_timestamp == 9000)
        .expect("C once max_late is exceeded");
    assert_eq!(2, c.prev_dropped_packets);
    assert!(
        !builder.take_key_frame_request(),
        "no request without the bound"
    );
    assert_eq!(0, builder.skipped_gaps());
}

/// The deadline is when the oldest gap will have waited the bound, from the arrival of the
/// first packet after it (4, at 20 ms; 5 arriving later does not move it); `None` with no gap
/// and without a bound.
#[test]
fn the_deadline_is_the_oldest_gap_plus_the_bound() {
    let t0 = Instant::now();
    let mut builder =
        SampleBuilder::new(256, Vp8Packet::default(), 90_000).with_max_gap_wait(ms(200));
    builder.push(t0, vp8(1, 3000, true, true));
    builder.push(t0 + ms(10), vp8(2, 6000, true, false));
    pop_all(&mut builder, t0 + ms(10));
    assert_eq!(None, builder.poll_timeout(), "no gap");

    builder.push(t0 + ms(20), vp8(4, 9000, true, true));
    assert_eq!(Some(t0 + ms(220)), builder.poll_timeout());
    builder.push(t0 + ms(30), vp8(5, 12000, true, true));
    pop_all(&mut builder, t0 + ms(30));
    assert_eq!(Some(t0 + ms(220)), builder.poll_timeout());

    let mut unbounded = SampleBuilder::new(256, Vp8Packet::default(), 90_000);
    without_packet_3(&mut unbounded, t0);
    assert_eq!(None, unbounded.poll_timeout(), "no bound, no deadline");
}
