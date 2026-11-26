//! The wall-clock bound on a gap (`SampleBuilder::with_max_gap_wait`): a missing packet is
//! waited for as long as the bound from when the builder knew of the gap, then given up with a
//! key-frame request (see `docs/receiver-gap-policy.md`). The bound is on by default for a
//! format with key frames (`DEFAULT_MAX_GAP_WAIT`) and off for any other.

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
    let mut builder = SampleBuilder::new(8, Vp8Packet::default(), 90_000).with_max_gap_wait(None);
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

    let mut unbounded =
        SampleBuilder::new(256, Vp8Packet::default(), 90_000).with_max_gap_wait(None);
    without_packet_3(&mut unbounded, t0);
    assert_eq!(None, unbounded.poll_timeout(), "no bound, no deadline");
}

/// A builder of a video format bounds the wait by default: with nothing but `new`, the gap at
/// 3 (known at 20 ms) is held at 20 ms + the default less 1 ms and given up, with a key-frame
/// request, at 20 ms + the default.
#[test]
fn a_video_builder_gives_a_gap_up_after_the_default_bound() {
    let t0 = Instant::now();
    let mut builder = SampleBuilder::new(256, Vp8Packet::default(), 90_000);
    let samples = without_packet_3(&mut builder, t0);
    assert_eq!(vec![3000], timestamps(&samples), "B waits for 3");
    assert_eq!(
        Some(t0 + ms(20) + DEFAULT_MAX_GAP_WAIT),
        builder.poll_timeout()
    );

    let just_before = t0 + ms(20) + DEFAULT_MAX_GAP_WAIT - ms(1);
    assert!(pop_all(&mut builder, just_before).is_empty());
    assert!(!builder.take_key_frame_request());

    let samples = pop_all(&mut builder, t0 + ms(20) + DEFAULT_MAX_GAP_WAIT);
    assert_eq!(vec![9000], timestamps(&samples));
    assert_eq!(2, samples[0].prev_dropped_packets);
    assert!(builder.take_key_frame_request());
    assert_eq!(1, builder.skipped_gaps());
}

/// The default bound is 300 ms: the value the capacity instrument measured
/// (`docs/receiver-gap-policy.md`).
#[test]
fn the_default_bound_is_300_ms() {
    let t0 = Instant::now();
    let mut builder = SampleBuilder::new(256, Vp8Packet::default(), 90_000);
    without_packet_3(&mut builder, t0);
    assert_eq!(Some(t0 + ms(320)), builder.poll_timeout());
}

/// Reordering inside the default bound is still delivered in order: packet 3 arrives 150 ms
/// late, B and C come out in sequence with nothing dropped and no key frame is asked for.
#[test]
fn reordering_inside_the_default_bound_is_delivered_in_order() {
    let t0 = Instant::now();
    let mut builder = SampleBuilder::new(256, Vp8Packet::default(), 90_000);
    let mut samples = without_packet_3(&mut builder, t0);
    builder.push(t0 + ms(170), vp8(3, 6000, false, true));
    samples.extend(pop_all(&mut builder, t0 + ms(170)));
    samples.extend(pop_all(&mut builder, t0 + ms(2_000)));

    assert_eq!(vec![3000, 6000, 9000], timestamps(&samples));
    assert!(
        samples
            .iter()
            .all(|sample| sample.prev_dropped_packets == 0)
    );
    assert!(!builder.take_key_frame_request());
    assert_eq!(0, builder.skipped_gaps());
}

/// An audio builder is as it was: no bound in time unless one is set. Opus packets 1, 2, 4, 5
/// (3 never comes): 4 and 5 are held however long nothing arrives, no deadline is named, and
/// the gap goes when more than `max_late` (4) positions are buffered; no key frame is ever
/// asked for. With a bound set, the same builder gives the gap up in time.
#[test]
fn an_audio_builder_has_no_time_bound_by_default() {
    use rtp::codec::opus::OpusPacket;
    fn opus(sequence_number: u16) -> Packet {
        Packet {
            header: Header {
                sequence_number,
                timestamp: 960 * u32::from(sequence_number),
                ..Default::default()
            },
            payload: Bytes::from(vec![0x78, sequence_number as u8]),
        }
    }
    fn run(mut builder: SampleBuilder<OpusPacket>, t0: Instant) -> SampleBuilder<OpusPacket> {
        for sequence_number in [1u16, 2, 4, 5] {
            builder.push(t0, opus(sequence_number));
        }
        builder
    }
    let t0 = Instant::now();

    let mut builder = run(SampleBuilder::new(4, OpusPacket, 48_000), t0);
    assert_eq!(None, builder.poll_timeout(), "no deadline");
    let mut out: Vec<u32> = std::iter::from_fn(|| builder.pop(t0 + ms(10_000)))
        .map(|sample| sample.packet_timestamp)
        .collect();
    assert_eq!(vec![960], out, "2, 4 and 5 wait for 3");
    for sequence_number in 6..=8u16 {
        builder.push(t0 + ms(10_000), opus(sequence_number));
        out.extend(
            std::iter::from_fn(|| builder.pop(t0 + ms(10_000)))
                .map(|sample| sample.packet_timestamp),
        );
    }
    assert!(out.contains(&(960 * 4)), "given up by max_late: {out:?}");
    assert!(!builder.take_key_frame_request());
    assert_eq!(0, builder.skipped_gaps());
    assert_eq!(0, builder.key_frame_releases());

    let mut bounded = run(
        SampleBuilder::new(4, OpusPacket, 48_000).with_max_gap_wait(ms(100)),
        t0,
    );
    assert_eq!(Some(t0 + ms(100)), bounded.poll_timeout());
    let out: Vec<u32> = std::iter::from_fn(|| bounded.pop(t0 + ms(100)))
        .map(|sample| sample.packet_timestamp)
        .collect();
    assert_eq!(vec![960, 960 * 2, 960 * 4], out);
    assert_eq!(1, bounded.skipped_gaps());
}

/// Repairs that arrive after their gap was given up are ignored: packet 3 comes 100 ms after
/// the bound gave it up, and a duplicate of packet 1 (long built into a sample) with it.
/// Neither starts a gap of its own: no deadline is named, nothing more is skipped, no second
/// key-frame request is raised, and the frames that follow come out as they arrive.
#[test]
fn a_packet_older_than_what_was_consumed_is_ignored() {
    let t0 = Instant::now();
    let mut builder =
        SampleBuilder::new(256, Vp8Packet::default(), 90_000).with_max_gap_wait(ms(200));
    let mut samples = without_packet_3(&mut builder, t0);
    samples.extend(pop_all(&mut builder, t0 + ms(220)));
    assert_eq!(vec![3000, 9000], timestamps(&samples));
    assert!(builder.take_key_frame_request());
    assert_eq!(
        Some(5),
        builder.nack_horizon(),
        "D (5) is the oldest in use"
    );

    builder.push(t0 + ms(320), vp8(3, 6000, false, true));
    builder.push(t0 + ms(320), vp8(1, 3000, true, true));
    builder.push(t0 + ms(320), vp8(2, 6000, true, false));
    assert_eq!(None, builder.poll_timeout(), "no gap of their making");
    builder.push(t0 + ms(330), vp8(6, 15000, true, true));
    samples.extend(pop_all(&mut builder, t0 + ms(330)));
    samples.extend(pop_all(&mut builder, t0 + ms(5_000)));
    assert_eq!(vec![3000, 9000, 12000], timestamps(&samples));
    assert_eq!(0, samples[2].prev_dropped_packets);
    assert!(!builder.take_key_frame_request(), "no second request");
    assert_eq!(1, builder.skipped_gaps());
    assert_eq!(Some(6), builder.nack_horizon());
}

/// RFC 4585 section 4.2: "The RTP receivers MUST NOT rely on the RTP senders reacting to any
/// of the FB messages." A VP8 stream at 30 frames a second, one packet a frame, a key frame
/// every 30 frames on the sender's own schedule, from a sender that reacts to no feedback (the
/// session negotiated none); the packet of frame 35 is lost for good. A builder with nothing
/// but `new` delivers frame 36 and every frame after the gap within the default bound of their
/// arrival, raises its key-frame request (which nobody answers), and a decoder that needs
/// every reference resumes at frame 60, the sender's next scheduled key frame: nothing waits
/// for a retransmission or for an answer to the request.
#[test]
fn a_receiver_does_not_wait_for_feedback_the_sender_never_answers() {
    const FRAMES: u16 = 100;
    const KEY_FRAME_INTERVAL: u16 = 30;
    const LOST: u16 = 35;
    let t0 = Instant::now();
    let interval = ms(33);
    let arrival = |frame: u16| t0 + interval * u32::from(frame);
    let packet = |frame: u16| {
        let key = frame.is_multiple_of(KEY_FRAME_INTERVAL);
        Packet {
            header: Header {
                sequence_number: 1000 + frame,
                timestamp: 3000 * u32::from(frame),
                marker: true,
                ..Default::default()
            },
            // RFC 7741: the descriptor with S=1, then the payload header, P=0 on a key frame.
            payload: Bytes::from(vec![0x10, if key { 0x00 } else { 0x01 }, frame as u8]),
        }
    };

    let mut builder = SampleBuilder::new(256, Vp8Packet::default(), 90_000);
    // (frame, when the application got it, packets dropped before it)
    let mut delivered: Vec<(u16, Instant, u16)> = Vec::new();
    let mut requests = 0;
    let mut collect = |builder: &mut SampleBuilder<Vp8Packet>, now: Instant| {
        while let Some(sample) = builder.pop(now) {
            delivered.push((
                (sample.packet_timestamp / 3000) as u16,
                now,
                sample.prev_dropped_packets,
            ));
        }
        if builder.take_key_frame_request() {
            // The application would send a PLI; the sender reacts to none.
            requests += 1;
        }
    };
    for frame in 0..FRAMES {
        let now = arrival(frame);
        // The builder's deadlines before this arrival, as an application's timer would (a
        // deadline that does not move after its pop has been served).
        let mut served = None;
        while let Some(deadline) = builder.poll_timeout().filter(|d| *d < now) {
            if served == Some(deadline) {
                break;
            }
            served = Some(deadline);
            collect(&mut builder, deadline);
        }
        if frame != LOST {
            builder.push(now, packet(frame));
        }
        collect(&mut builder, now);
    }
    collect(&mut builder, arrival(FRAMES) + ms(1_000));

    // Every frame after the gap reaches the application within the bound of its arrival
    // (the last one waits for a successor to end it, as every frame does: 33 ms).
    for frame in LOST + 1..FRAMES - 1 {
        let Some((_, at, _)) = delivered.iter().find(|(f, _, _)| *f == frame) else {
            panic!("frame {frame} never delivered: {delivered:?}");
        };
        assert!(
            *at <= arrival(frame) + DEFAULT_MAX_GAP_WAIT,
            "frame {frame} held {:?} after its arrival",
            *at - arrival(frame)
        );
    }
    assert!(requests >= 1, "a key frame is asked for");

    // A decoder that needs every reference: a key frame decodes; any other frame only after
    // the frame before it decoded with nothing dropped between them.
    let mut decoded = Vec::new();
    let mut previous: Option<u16> = None;
    for (frame, _, dropped) in &delivered {
        let key = frame.is_multiple_of(KEY_FRAME_INTERVAL);
        let decodable = key || (*dropped == 0 && previous == Some(frame - 1));
        if decodable {
            decoded.push(*frame);
            previous = Some(*frame);
        } else {
            previous = None;
        }
    }
    let after_gap: Vec<u16> = decoded.iter().copied().filter(|f| *f > LOST).collect();
    assert_eq!(
        Some(&60),
        after_gap.first(),
        "decoding resumes at the sender's next scheduled key frame"
    );
    assert_eq!(
        (60..FRAMES - 1).collect::<Vec<u16>>(),
        after_gap[..after_gap.len().min((FRAMES - 61) as usize)].to_vec(),
        "and every frame from it decodes"
    );
}
