//! RFC 4588 section 7: retransmissions are congestion controlled. The NACK responder holds
//! what it retransmits to the congestion controller's target, which it reads from
//! `Attribute::TargetBitrateChanged` as the estimate passes on the read leg. By default (the
//! RFC's form) they take only what the original packets leave of it over the last second, and
//! while they wait the target reported for the original media is lowered by a retransmission
//! reserve; with libwebrtc's rule the retransmissions alone stay under the target.

use rtc_interceptor::{
    Attribute, AttributedPacket, Interceptor, MinimumTarget, NackResponderBuilder, PacerBuilder,
    PacerDiscard, Packet, RTCPFeedback, Registry, RetransmissionRateLimit, RetransmissionReserve,
    Slot, StreamInfo, TaggedPacket,
};
use rtcp::transport_feedbacks::transport_layer_nack::{
    TransportLayerNack, nack_pairs_from_sequence_numbers,
};
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::MarshalSize;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

const SSRC: u32 = 0x1234;
const RTX_SSRC: u32 = 0x5678;
const RTX_PAYLOAD_TYPE: u8 = 97;
/// Every original packet: a 12-byte header and 1000 bytes of payload.
const PAYLOAD: usize = 1000;
const ORIGINAL: usize = 12 + PAYLOAD;
/// Its retransmission carries the original sequence number ahead of the payload.
const RETRANSMISSION: usize = ORIGINAL + 2;

fn stream_info() -> StreamInfo {
    StreamInfo {
        ssrc: SSRC,
        ssrc_rtx: Some(RTX_SSRC),
        payload_type_rtx: Some(RTX_PAYLOAD_TYPE),
        clock_rate: 90000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_string(),
            parameter: String::new(),
        }],
        ..Default::default()
    }
}

fn responder(builder: NackResponderBuilder) -> impl Interceptor {
    let mut chain = Registry::new()
        .with(Slot::NackResponder, builder.build())
        .build();
    chain.bind_local_stream(&stream_info());
    chain
}

/// Sends originals 0 to `count - 1`, 10 ms apart from `base`.
fn send(chain: &mut impl Interceptor, base: Instant, count: u16) {
    for sequence_number in 0..count {
        chain
            .handle_write(TaggedPacket {
                now: base + Duration::from_millis(10) * u32::from(sequence_number),
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        payload_type: 96,
                        sequence_number,
                        ssrc: SSRC,
                        ..Default::default()
                    },
                    payload: vec![0u8; PAYLOAD].into(),
                })),
            })
            .unwrap();
    }
    while chain.poll_write().is_some() {}
}

/// What leaves on the write leg and reaches the application on the read leg.
#[derive(Default, Debug)]
struct Seen {
    /// Retransmissions written.
    retransmitted: usize,
    /// Every `RetransmissionReserve` written, bits per second.
    reserves: Vec<f64>,
    /// Every `TargetBitrateChanged` read, bits per second.
    targets: Vec<f64>,
}

/// Takes everything the chain has for the wire and the application.
fn drain(chain: &mut impl Interceptor) -> Seen {
    let mut seen = Seen::default();
    while let Some(tagged) = chain.poll_read() {
        if let Some(Attribute::TargetBitrateChanged { bits_per_second }) =
            tagged.message.get(&Attribute::TargetBitrateChanged {
                bits_per_second: 0.0,
            })
        {
            seen.targets.push(*bits_per_second);
        }
    }
    while let Some(tagged) = chain.poll_write() {
        if let Some(reserve) = tagged.message.custom::<RetransmissionReserve>() {
            seen.reserves.push(reserve.bits_per_second);
        }
        if let Packet::Rtp(packet) = &tagged.message.packet {
            assert_eq!(RTX_SSRC, packet.header.ssrc);
            assert_eq!(
                RETRANSMISSION,
                packet.header.marshal_size() + packet.payload.len()
            );
            seen.retransmitted += 1;
        }
    }
    seen
}

/// Reads a NACK for `sequence_numbers` at `now`, riding with the estimate `target_bps` when
/// given (as a congestion controller wire-ward of the responder attaches it), with the
/// controller's minimum `minimum_bps` when given ([`MinimumTarget`]).
fn read_nack(
    chain: &mut impl Interceptor,
    now: Instant,
    sequence_numbers: &[u16],
    target_bps: Option<f64>,
    minimum_bps: Option<f64>,
) {
    let mut message = AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerNack {
        sender_ssrc: 1,
        media_ssrc: SSRC,
        nacks: nack_pairs_from_sequence_numbers(sequence_numbers),
    })]));
    if let Some(bits_per_second) = target_bps {
        message.add(Attribute::TargetBitrateChanged { bits_per_second });
        if let Some(bits_per_second) = minimum_bps {
            message.add(Attribute::Custom(Arc::new(MinimumTarget {
                bits_per_second,
            })));
        }
    }
    chain
        .handle_read(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message,
        })
        .unwrap();
}

/// A NACK for `sequence_numbers` at `now` (see [`read_nack`]), and the number of
/// retransmissions that leave for it at once.
fn nack(
    chain: &mut impl Interceptor,
    now: Instant,
    sequence_numbers: &[u16],
    target_bps: Option<f64>,
) -> usize {
    read_nack(chain, now, sequence_numbers, target_bps, None);
    while chain.poll_read().is_some() {}
    let mut retransmitted = 0;
    while let Some(tagged) = chain.poll_write() {
        if let Packet::Rtp(packet) = &tagged.message.packet {
            assert_eq!(RTX_SSRC, packet.header.ssrc);
            assert_eq!(
                RETRANSMISSION,
                packet.header.marshal_size() + packet.payload.len()
            );
            retransmitted += 1;
        }
    }
    retransmitted
}

/// 30 originals in the 300 ms before the NACK, which asks for 20 of them.
fn scenario(builder: NackResponderBuilder, target_bps: Option<f64>) -> usize {
    let base = Instant::now();
    let mut chain = responder(builder);
    send(&mut chain, base, 30);
    let lost: Vec<u16> = (0..20).collect();
    nack(
        &mut chain,
        base + Duration::from_millis(300),
        &lost,
        target_bps,
    )
}

fn up_to_target() -> NackResponderBuilder {
    NackResponderBuilder::new().with_rate_limit(RetransmissionRateLimit::UpToTarget)
}

/// Drives the chain as the documented loop does (take what is written, sleep until
/// `poll_timeout`, `handle_timeout`), nothing else waking it, from `from` until the next
/// deadline is `until` or later: each retransmission that leaves, as (offset from `from`,
/// sequence number it repairs). What waits written at `from` counts at offset zero.
fn drive(chain: &mut impl Interceptor, from: Instant, until: Instant) -> Vec<(Duration, u16)> {
    let mut left = Vec::new();
    let mut now = from;
    loop {
        while chain.poll_read().is_some() {}
        while let Some(tagged) = chain.poll_write() {
            if let Packet::Rtp(packet) = &tagged.message.packet {
                assert_eq!(RTX_SSRC, packet.header.ssrc);
                left.push((
                    now - from,
                    u16::from_be_bytes([packet.payload[0], packet.payload[1]]),
                ));
            }
        }
        match chain.poll_timeout() {
            Some(due) if due < until => {
                assert!(due >= now, "a deadline in the past: a spin");
                now = due;
                chain.handle_timeout(now).unwrap();
            }
            _ => return left,
        }
    }
}

/// When the `k`-th retransmission (from 1) leaves under a constant `limit` (octets a window):
/// the smoothing bucket holds a tenth of the window's allowance (at least 1500 octets) at
/// first and fills at the allowance's rate, each retransmission taking its size.
fn smoothed_offset(k: usize, limit: f64) -> Duration {
    let depth = (limit / 10.0).max(1500.0);
    Duration::from_secs_f64(((k * RETRANSMISSION) as f64 - depth).max(0.0) / limit)
}

/// The retransmissions released by `until` (see [`drive`]) after a NACK for `lost` at `at`.
fn released(
    chain: &mut impl Interceptor,
    at: Instant,
    lost: &[u16],
    target_bps: Option<f64>,
    until: Instant,
) -> Vec<(Duration, u16)> {
    read_nack(chain, at, lost, target_bps, None);
    drive(chain, at, until)
}

/// libwebrtc's rule, a setting: the retransmissions alone stay under the target over the last
/// second, whatever the originals took. At 80 kbit/s, 10 000 octets a second: nine
/// retransmissions of 1014 octets in a window, although the originals already took three times
/// that. They leave spread over the window at its rate (one at once, from the bucket's 1500
/// octets, then one every 101.4 ms), never more than nine in any second: the tenth waits until
/// the first leaves the window, a second after it.
#[test]
fn retransmissions_alone_stay_under_the_target() {
    let target = 80_000.0;
    let limit = target / 8.0;
    let allowed = limit as usize / RETRANSMISSION;
    assert_eq!(9, allowed);
    let base = Instant::now();
    let mut chain = responder(up_to_target());
    send(&mut chain, base, 30);
    let at = base + Duration::from_millis(300);
    let lost: Vec<u16> = (0..20).collect();
    let left = released(
        &mut chain,
        at,
        &lost,
        Some(target),
        at + Duration::from_secs(3),
    );
    let in_first_window = left
        .iter()
        .filter(|(offset, _)| *offset < Duration::from_secs(1))
        .count();
    assert_eq!(allowed, in_first_window);
    for (k, (offset, _)) in left.iter().take(allowed).enumerate() {
        let expected = smoothed_offset(k + 1, limit);
        assert!(
            offset.abs_diff(expected) < Duration::from_millis(1),
            "retransmission {} at {offset:?}, expected {expected:?}",
            k + 1
        );
    }
    assert_eq!(
        Duration::from_secs(1),
        left[allowed].0,
        "the tenth: when the first left"
    );
    // The total over any window: never more than the nine.
    for (start, _) in &left {
        let in_window = left
            .iter()
            .filter(|(offset, _)| *offset >= *start && *offset < *start + Duration::from_secs(1))
            .count();
        assert!(
            in_window <= allowed,
            "{in_window} within a second from {start:?}"
        );
    }
}

/// RFC 4588 section 7, the default: the retransmissions take what the original packets leave of
/// the target over the last second, or the retransmission reserve the original media has been
/// lowered by before they are sent, whichever is more. Twenty requests of 1014 octets with no
/// round trip measured need 162 kbit/s, at most half the target: at 320 kbit/s the reserve is
/// 160 kbit/s (20 000 octets a second), more than the 9 640 the 30 originals (30 360 octets)
/// leave of 40 000: nineteen leave. At 240 kbit/s the originals leave nothing; the reserve is
/// 120 kbit/s, 15 000 octets: fourteen.
///
/// They leave spread over the window: one at once (the bucket holds a tenth of the
/// allowance, at least 1500 octets), the rest at the allowance's rate. Counted until the first
/// original leaves the window (700 ms after the NACK), never more than those figures, and more
/// with the reserve than with the originals' share alone.
#[test]
fn retransmissions_take_what_the_originals_leave_or_the_reserve() {
    assert_eq!(9640 / RETRANSMISSION, 9);
    let window = |builder: NackResponderBuilder, target: f64| -> (usize, usize) {
        let base = Instant::now();
        let mut chain = responder(builder);
        send(&mut chain, base, 30);
        let at = base + Duration::from_millis(300);
        let lost: Vec<u16> = (0..20).collect();
        let left = released(
            &mut chain,
            at,
            &lost,
            Some(target),
            base + Duration::from_secs(1),
        );
        let at_once = left.iter().filter(|(offset, _)| offset.is_zero()).count();
        (at_once, left.len())
    };
    let (at_once, with_reserve_320) = window(NackResponderBuilder::new(), 320_000.0);
    assert_eq!(1, at_once);
    assert!((2..=19).contains(&with_reserve_320), "{with_reserve_320}");
    let (at_once, with_reserve_240) = window(NackResponderBuilder::new(), 240_000.0);
    assert_eq!(1, at_once);
    assert!((2..=14).contains(&with_reserve_240), "{with_reserve_240}");
    assert!(with_reserve_320 > with_reserve_240);
    let rfc = || NackResponderBuilder::new().with_rate_limit(RetransmissionRateLimit::WithinTarget);
    assert_eq!((1, with_reserve_320), window(rfc(), 320_000.0));
    // Without a reserve (at most 0 % of the target) the originals' share alone: at most nine,
    // fewer than with the reserve; none at 240 kbit/s.
    let no_reserve = || NackResponderBuilder::new().with_max_reserve_fraction(0.0);
    let (at_once, share_320) = window(no_reserve(), 320_000.0);
    assert_eq!(1, at_once);
    assert!((1..=9).contains(&share_320) && share_320 < with_reserve_320);
    assert_eq!((0, 0), window(no_reserve(), 240_000.0));
}

/// Without a target (no congestion controller in the chain) and with the limit off, every
/// packet asked for is retransmitted.
#[test]
fn without_a_target_retransmissions_are_not_held_back() {
    assert_eq!(20, scenario(NackResponderBuilder::new(), None));
    assert_eq!(
        20,
        scenario(
            NackResponderBuilder::new().with_rate_limit(RetransmissionRateLimit::Unlimited),
            Some(80_000.0)
        )
    );
}

/// A retransmission the limit holds back waits and leaves by itself when the limit has room:
/// the responder's deadline is that instant and not earlier (a driver woken at once would
/// spin). At 80 kbit/s under libwebrtc's rule the window allows 10 000 octets: the first leaves
/// at once, the second when the bucket has filled again by 528 octets (52.8 ms), and so on; a
/// request asked for again keeps its place and changes no deadline; the tenth waits for the
/// window, a second after the first.
#[test]
fn a_held_back_retransmission_is_due_when_the_window_has_room() {
    let limit = 10_000.0;
    let base = Instant::now();
    let mut chain = responder(up_to_target());
    send(&mut chain, base, 30);
    let lost: Vec<u16> = (0..20).collect();
    let at = base + Duration::from_millis(300);
    assert_eq!(1, nack(&mut chain, at, &lost, Some(80_000.0)));
    let due = chain.poll_timeout().expect("nineteen wait");
    assert!(
        due.duration_since(at).abs_diff(smoothed_offset(2, limit)) < Duration::from_millis(1),
        "due {:?} after the NACK",
        due - at
    );
    // The receiver asks again meanwhile: the requests keep their place.
    assert_eq!(
        0,
        nack(&mut chain, at + Duration::from_millis(10), &lost[1..], None)
    );
    assert_eq!(Some(due), chain.poll_timeout());
    chain
        .handle_timeout(due - Duration::from_millis(1))
        .unwrap();
    assert_eq!(0, drain(&mut chain).retransmitted, "not before");
    chain.handle_timeout(due).unwrap();
    assert_eq!(
        1,
        drain(&mut chain).retransmitted,
        "the second when it is due"
    );
    let rest = drive(&mut chain, due, at + Duration::from_millis(1_001));
    assert_eq!(
        8,
        rest.len(),
        "seven more in the first second, and the tenth at its end"
    );
    assert_eq!(
        at + Duration::from_secs(1),
        due + rest[7].0,
        "the tenth when the first has left the window"
    );
}

/// Requests waiting for the rate limit are answered a stream's oldest packet first, whenever
/// each was asked for: a receiver that plays in order waits for its oldest gap, and a packet
/// asked for again because its repair was lost would otherwise wait behind every newer one. At
/// 80 kbit/s with libwebrtc's rule one retransmission of 1014 octets leaves every 101.4 ms
/// after the first: a NACK for 0 to 8 at 400 ms, one for 30 at 410 ms and one for 10 at
/// 420 ms, while 1 to 8 still wait: 10 leaves before 30.
#[test]
fn waiting_requests_are_answered_oldest_packet_first() {
    let base = Instant::now();
    let mut chain = responder(up_to_target());
    send(&mut chain, base, 40);
    let at = base + Duration::from_millis(400);
    let first: Vec<u16> = (0..9).collect();
    assert_eq!(1, nack(&mut chain, at, &first, Some(80_000.0)));
    assert_eq!(
        0,
        nack(&mut chain, at + Duration::from_millis(10), &[30], None)
    );
    assert_eq!(
        0,
        nack(&mut chain, at + Duration::from_millis(20), &[10], None)
    );
    let order: Vec<u16> = drive(
        &mut chain,
        at + Duration::from_millis(20),
        at + Duration::from_secs(3),
    )
    .into_iter()
    .map(|(_, seq)| seq)
    .collect();
    assert_eq!(vec![1, 2, 3, 4, 5, 6, 7, 8, 10, 30], order);
}

/// A request the receiver stops making is dropped after `PENDING_REQUEST_LIFETIME` (the
/// receiver asks again every round trip while it misses the packet); one it makes again stays.
/// At 8 kbit/s no retransmission ever fits the window.
#[test]
fn a_request_no_longer_made_is_dropped() {
    let lifetime = rtc_interceptor::PENDING_REQUEST_LIFETIME;
    for asked_again in [false, true] {
        let base = Instant::now();
        let mut chain = responder(up_to_target());
        send(&mut chain, base, 30);
        let lost: Vec<u16> = (0..20).collect();
        let at = base + Duration::from_millis(300);
        assert_eq!(0, nack(&mut chain, at, &lost, Some(8_000.0)));
        let mut last = at;
        if asked_again {
            last = at + Duration::from_millis(900);
            assert_eq!(0, nack(&mut chain, last, &lost, None));
        }
        let due = chain.poll_timeout().expect("the requests run out");
        assert!(
            due > last + lifetime && due <= last + lifetime + Duration::from_millis(1),
            "due {:?} after the last request",
            due - last
        );
        chain.handle_timeout(last + lifetime).unwrap();
        assert_eq!(Some(due), chain.poll_timeout(), "still waiting");
        chain.handle_timeout(due).unwrap();
        assert_eq!(0, drain(&mut chain).retransmitted);
        assert_eq!(None, chain.poll_timeout(), "nothing waits");
    }
}

/// RFC 4588 section 7, "the sender SHOULD NOT send retransmission packets without reducing
/// the packet rate and bitrate of the original stream": while retransmissions wait, the target
/// reported to the application is the controller's less a reserve, at most half of it, and the
/// reserve goes down the write leg to the congestion controller, before the retransmissions
/// use it. Ten packets of 1014 octets waiting with no round trip measured (a second) need
/// 81 kbit/s: at 240 kbit/s the reserve is that (10 140 octets: all ten over the window), at
/// 150 kbit/s it is half the target (9 375 octets: nine). Both targets are under what the 30
/// originals took: without the reserve nothing would leave.
#[test]
fn the_target_for_the_original_media_leaves_room_for_the_waiting_retransmissions() {
    for (target, reserve, leave) in [
        (240_000.0, 10.0 * RETRANSMISSION as f64 * 8.0, 10),
        (150_000.0, 75_000.0, 9),
    ] {
        let base = Instant::now();
        let mut chain = responder(NackResponderBuilder::new());
        send(&mut chain, base, 30);
        let lost: Vec<u16> = (0..10).collect();
        read_nack(
            &mut chain,
            base + Duration::from_millis(300),
            &lost,
            Some(target),
            None,
        );
        let seen = drain(&mut chain);
        // The bucket's tenth of the allowance (at least 1500 octets) leaves at once: one.
        assert_eq!(1, seen.retransmitted, "at {target}");
        assert_eq!(vec![reserve], seen.reserves, "at {target}");
        assert_eq!(vec![target - reserve], seen.targets, "at {target}");
        // And the rest of what the reserve allows as the bucket fills, before the first
        // original leaves the window (700 ms on): never more than it allows over the window.
        let rest = drive(
            &mut chain,
            base + Duration::from_millis(300),
            base + Duration::from_secs(1),
        );
        assert!(
            !rest.is_empty() && 1 + rest.len() <= leave,
            "at {target}: {} in all",
            1 + rest.len()
        );
    }
}

/// With nothing waiting and nothing retransmitted in the last second the reserve is released:
/// the application's target is the controller's again.
#[test]
fn the_reserve_is_released_when_nothing_waits() {
    let base = Instant::now();
    let mut chain = responder(NackResponderBuilder::new());
    send(&mut chain, base, 30);
    let at = base + Duration::from_millis(300);
    // 500 kbit/s: 62 500 octets, the originals took 30 360, the five fit the window; the
    // bucket's tenth of the 32 140 they leave (3214 octets) lets three leave at once.
    read_nack(&mut chain, at, &[0, 1, 2, 3, 4], Some(500_000.0), None);
    let seen = drain(&mut chain);
    assert_eq!(3, seen.retransmitted);
    let needed = 5.0 * RETRANSMISSION as f64 * 8.0;
    assert_eq!(
        vec![needed],
        seen.reserves,
        "their rate is reserved before they leave"
    );
    assert_eq!(vec![500_000.0 - needed], seen.targets);
    // The other two as the bucket fills; then, with nothing waiting, the reserve falls back to
    // zero a window after the last of them.
    let mut last = at;
    let mut left = 0;
    let mut reserves = Vec::new();
    let mut targets = Vec::new();
    while let Some(due) = chain.poll_timeout() {
        assert!(due > last, "a spin at {due:?}");
        last = due;
        chain.handle_timeout(due).unwrap();
        let seen = drain(&mut chain);
        left += seen.retransmitted;
        reserves.extend(seen.reserves);
        targets.extend(seen.targets);
    }
    assert_eq!(2, left);
    assert_eq!(Some(&0.0), reserves.last());
    assert_eq!(Some(&500_000.0), targets.last());
    assert!(
        last >= at + Duration::from_secs(1),
        "released {:?} after",
        last - at
    );
    assert_eq!(None, chain.poll_timeout());
}

/// libwebrtc's rule leaves the application's target alone.
#[test]
fn up_to_the_target_the_original_media_is_not_lowered() {
    let base = Instant::now();
    let mut chain = responder(up_to_target());
    send(&mut chain, base, 30);
    let lost: Vec<u16> = (0..20).collect();
    read_nack(
        &mut chain,
        base + Duration::from_millis(300),
        &lost,
        Some(240_000.0),
        None,
    );
    let seen = drain(&mut chain);
    assert!(seen.reserves.is_empty());
    assert_eq!(vec![240_000.0], seen.targets);
}

/// Near the congestion controller's floor ([`MinimumTarget`]) the original media cannot be
/// lowered by the reserve: the retransmissions of the packets asked for take the window's room
/// first, whatever the originals took. At 100 kbit/s the 30 originals (30 360 octets) took more
/// than the window's 12 500 octets; the reserve is half the target, 50 kbit/s. With a minimum
/// of 100 kbit/s, 100 − 50 is under it: the retransmissions have the window's 12 500 octets a
/// second. With a minimum of 40 kbit/s, or none announced, the reserve's 6 250. The original
/// media is told the target less the reserve, never less than the minimum. The
/// retransmissions leave at that rate (the k-th at (k × 1014 − 1500) / rate s): by the time the
/// first original leaves the window (700 ms on) ten at the window's rate, five at the
/// reserve's.
#[test]
fn near_the_floor_retransmissions_take_the_room_first() {
    for (minimum, limit, media_target) in [
        (None, 6_250.0, 50_000.0),
        (Some(40_000.0), 6_250.0, 50_000.0),
        (Some(100_000.0), 12_500.0, 100_000.0),
    ] {
        let base = Instant::now();
        let mut chain = responder(NackResponderBuilder::new());
        send(&mut chain, base, 30);
        let lost: Vec<u16> = (0..20).collect();
        let at = base + Duration::from_millis(300);
        read_nack(&mut chain, at, &lost, Some(100_000.0), minimum);
        let seen = drain(&mut chain);
        assert_eq!(vec![media_target], seen.targets, "minimum {minimum:?}");
        let mut left = vec![Duration::ZERO; seen.retransmitted];
        left.extend(
            drive(&mut chain, at, base + Duration::from_secs(1))
                .into_iter()
                .map(|(offset, _)| offset),
        );
        let expected = (1..)
            .take_while(|k| smoothed_offset(*k, limit) < Duration::from_millis(700))
            .count();
        assert_eq!(expected, left.len(), "minimum {minimum:?}: {left:?}");
        for (k, offset) in left.iter().enumerate() {
            assert!(
                offset.abs_diff(smoothed_offset(k + 1, limit)) < Duration::from_millis(1),
                "minimum {minimum:?}: retransmission {} at {offset:?}",
                k + 1
            );
        }
    }
}

/// A driver that follows the documented loop (take what is written, then sleep until
/// `poll_timeout`, then `handle_timeout`) with nothing else waking it: the retransmissions the
/// limit holds back leave at their own due times, and the driver never spins (each deadline is
/// later than the instant it was handed last). Under the default rule at 240 kbit/s the 30
/// originals took the window: of twenty requests the 120 kbit/s reserve lets one leave at once
/// (the bucket's tenth of its 15 000 octets, at least 1500), the rest as the bucket fills and
/// the window empties, until the requests run out a second after they were made.
#[test]
fn a_held_retransmission_wakes_the_driver_once_at_its_due_time() {
    let base = Instant::now();
    let mut chain = responder(NackResponderBuilder::new());
    send(&mut chain, base, 30);
    let lost: Vec<u16> = (0..20).collect();
    let at = base + Duration::from_millis(300);
    read_nack(&mut chain, at, &lost, Some(240_000.0), None);
    assert_eq!(
        1,
        drain(&mut chain).retransmitted,
        "the bucket's share at once"
    );

    let mut now = at;
    let mut wakes = Vec::new();
    let mut later = 0;
    while let Some(due) = chain.poll_timeout() {
        assert!(
            due > now,
            "a deadline at {due:?} handed back at {now:?}: a spin"
        );
        assert!(wakes.len() < 100, "woken {} times", wakes.len());
        now = due;
        chain.handle_timeout(now).unwrap();
        wakes.push(now - at);
        later += drain(&mut chain).retransmitted;
    }
    assert!(
        later >= 1,
        "a held retransmission left by itself: {wakes:?}"
    );
    assert!(
        wakes.len() <= later + 3,
        "{} wake-ups for {later} retransmissions: {wakes:?}",
        wakes.len()
    );
}

/// What the pacer discards (whole frames that waited its queue time bound) is never resent: the
/// pacer tells the NACK responder application-ward of it which packets it discarded
/// ([`PacerDiscard`] on its read leg), and the responder takes them out of its retransmission
/// buffer, so a NACK for them is answered by nothing (RFC 4588 section 7: the sender "MAY
/// selectively retransmit only the packets that it deems important"). Ten originals (frames of
/// their own, 8096 bits each) against a 12 kbit/s target (a budget of 12 000 bits at most), the
/// clock advanced in 10 ms steps. 0 is written at 0 ms and leaves at once (3904 bits left); 1
/// and 2, written at 10 and 20 ms, queue, and with 2 the queue holds 1.35 s at the target,
/// half the 2 s bound or more: the pause begins at 20 ms, and 1 and 2 are a following
/// source's, never discarded for their age. 3 to 9 are written into the pause, 300 to 360 ms.
/// One leaves each time the budget has 8096 bits again: 1 at 350 ms, 2 at 1030 ms, 3 at
/// 1700 ms; 4 would at 2380 ms, but written at 310 ms it has waited the bound at 2310 ms, and
/// 4 to 9 are discarded. A NACK for all ten, with a target that has room for them, has
/// exactly those that left (0 to 3) resent.
#[test]
fn a_nack_for_a_packet_the_pacer_discarded_is_answered_by_nothing() {
    let base = Instant::now();
    let mut chain = Registry::new()
        .with(
            Slot::Pacer,
            PacerBuilder::new().with_target_bitrate(12_000.0).build(),
        )
        .with(Slot::NackResponder, NackResponderBuilder::new().build())
        .build();
    chain.bind_local_stream(&stream_info());

    let mut left = BTreeSet::new();
    let mut discarded = BTreeSet::new();
    let take = |chain: &mut dyn Interceptor,
                left: &mut BTreeSet<u16>,
                discarded: &mut BTreeSet<u16>|
     -> Vec<u16> {
        let mut resent = Vec::new();
        while let Some(tagged) = chain.poll_read() {
            if let Some(discard) = tagged.message.custom::<PacerDiscard>() {
                assert_eq!(SSRC, discard.ssrc);
                discarded.extend(discard.sequence_numbers.iter().copied());
            }
        }
        while let Some(tagged) = chain.poll_write() {
            if let Packet::Rtp(packet) = &tagged.message.packet {
                if packet.header.ssrc == SSRC {
                    left.insert(packet.header.sequence_number);
                } else {
                    assert_eq!(RTX_SSRC, packet.header.ssrc);
                    resent.push(u16::from_be_bytes([packet.payload[0], packet.payload[1]]));
                }
            }
        }
        resent
    };
    let written_at = |sequence_number: u16| match sequence_number {
        0..=2 => Duration::from_millis(10) * u32::from(sequence_number),
        _ => {
            Duration::from_millis(300) + Duration::from_millis(10) * u32::from(sequence_number - 3)
        }
    };
    let mut now = base;
    for step in 0..=300u32 {
        now = base + Duration::from_millis(10) * step;
        if step > 0 {
            chain.handle_timeout(now).unwrap();
            take(&mut chain, &mut left, &mut discarded);
        }
        for sequence_number in (0..10u16).filter(|n| base + written_at(*n) == now) {
            chain
                .handle_write(TaggedPacket {
                    now,
                    transport: TransportContext::default(),
                    message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                        header: rtp::header::Header {
                            version: 2,
                            payload_type: 96,
                            sequence_number,
                            timestamp: u32::from(sequence_number) * 3000,
                            ssrc: SSRC,
                            marker: true,
                            ..Default::default()
                        },
                        payload: vec![0u8; PAYLOAD].into(),
                    })),
                })
                .unwrap();
            take(&mut chain, &mut left, &mut discarded);
        }
    }
    assert!(
        !left.is_empty() && !discarded.is_empty(),
        "{left:?} {discarded:?}"
    );
    assert!(left.is_disjoint(&discarded), "{left:?} {discarded:?}");
    assert_eq!(10, left.len() + discarded.len(), "{left:?} {discarded:?}");
    assert_eq!(
        BTreeSet::from([0, 1, 2, 3]),
        left,
        "discarded {discarded:?}"
    );
    assert_eq!(BTreeSet::from_iter(4..10u16), discarded);

    let all: Vec<u16> = (0..10).collect();
    read_nack(&mut chain, now, &all, Some(10_000_000.0), None);
    let mut resent = BTreeSet::new();
    let until = now + Duration::from_secs(1);
    while now < until {
        resent.extend(take(&mut chain, &mut left, &mut discarded));
        now += Duration::from_millis(10);
        chain.handle_timeout(now).unwrap();
    }
    assert_eq!(
        left, resent,
        "resent only what left; discarded {discarded:?}"
    );
}

/// Counts the retransmissions the NACK responder hands toward the pacer.
struct RetransmissionsMade {
    made: Arc<std::sync::atomic::AtomicUsize>,
    reads: std::collections::VecDeque<TaggedPacket>,
    writes: std::collections::VecDeque<TaggedPacket>,
}

impl sansio::Protocol<TaggedPacket, TaggedPacket, ()> for RetransmissionsMade {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = shared::error::Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.reads.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<TaggedPacket> {
        self.reads.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if msg.message.has(&Attribute::Retransmission) {
            self.made.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.writes.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        self.writes.pop_front()
    }
}

impl Interceptor for RetransmissionsMade {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

/// While a retransmission waits in the pacer, a NACK for the same packet makes no other
/// (libwebrtc's packet history: a request for a packet "already in pacer queue" is ignored),
/// and once it left, the resend interval counts from its departure, which the pacer reports
/// ([`RetransmissionsLeft`]), not from when it was made. At 12 kbit/s a retransmission waits
/// some 0.4 s for the budget: a second NACK 90 ms after the first makes nothing, one 10 ms after
/// it left makes nothing (within the 20 ms interval of its departure, 0.4 s after it was made),
/// one 50 ms after it left makes the next.
#[test]
fn a_retransmission_waiting_in_the_pacer_is_not_made_again() {
    let base = Instant::now();
    let made = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut chain = Registry::new()
        .with(
            Slot::Pacer,
            PacerBuilder::new().with_target_bitrate(12_000.0).build(),
        )
        .with(
            Slot::from(3_500),
            RetransmissionsMade {
                made: Arc::clone(&made),
                reads: Default::default(),
                writes: Default::default(),
            },
        )
        // The rule under test is the pacer's report, whatever the rate limit: with the default
        // limit the originals written here fill the 12 kbit/s target and no retransmission
        // would be made at all.
        .with(
            Slot::NackResponder,
            NackResponderBuilder::new()
                .with_rate_limit(RetransmissionRateLimit::Unlimited)
                .build(),
        )
        .build();
    chain.bind_local_stream(&stream_info());
    let count = || made.load(std::sync::atomic::Ordering::Relaxed);
    // Everything the chain has: the repaired sequence numbers of the retransmissions that left.
    let pump = |chain: &mut dyn Interceptor| -> Vec<u16> {
        while chain.poll_read().is_some() {}
        let mut left = Vec::new();
        while let Some(tagged) = chain.poll_write() {
            if let Packet::Rtp(packet) = &tagged.message.packet
                && packet.header.ssrc == RTX_SSRC
            {
                left.push(u16::from_be_bytes([packet.payload[0], packet.payload[1]]));
            }
        }
        left
    };
    let write = |chain: &mut dyn Interceptor, at: Instant, sequence_number: u16| {
        chain
            .handle_write(TaggedPacket {
                now: at,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        payload_type: 96,
                        sequence_number,
                        timestamp: u32::from(sequence_number) * 3000,
                        ssrc: SSRC,
                        marker: true,
                        ..Default::default()
                    },
                    payload: vec![0u8; PAYLOAD].into(),
                })),
            })
            .unwrap();
    };
    let ms = |milliseconds: u64| base + Duration::from_millis(milliseconds);

    // A first retransmission, before the pacer has reported any: it waits and leaves.
    write(&mut chain, base, 0);
    pump(&mut chain);
    read_nack(&mut chain, ms(10), &[0], None, None);
    pump(&mut chain);
    assert_eq!(1, count());
    let mut left = Vec::new();
    for step in 2..=60 {
        chain.handle_timeout(ms(10 * step)).unwrap();
        left.extend(pump(&mut chain));
    }
    assert_eq!(vec![0], left, "the first retransmission left");

    for sequence_number in 1..=3 {
        write(&mut chain, ms(600), sequence_number);
    }
    pump(&mut chain);
    read_nack(&mut chain, ms(610), &[1], None, None);
    pump(&mut chain);
    assert_eq!(2, count(), "the retransmission of 1 is made");
    read_nack(&mut chain, ms(700), &[1], None, None);
    pump(&mut chain);
    assert_eq!(2, count(), "and not again while it waits in the pacer");

    let mut departed = None;
    let mut now = ms(700);
    while departed.is_none() && now < ms(3_000) {
        now += Duration::from_millis(10);
        chain.handle_timeout(now).unwrap();
        if pump(&mut chain).contains(&1) {
            departed = Some(now);
        }
    }
    let departed = departed.expect("the retransmission of 1 left");
    assert!(
        departed >= ms(800),
        "it waited: left at {:?}",
        departed - base
    );
    read_nack(
        &mut chain,
        departed + Duration::from_millis(10),
        &[1],
        None,
        None,
    );
    pump(&mut chain);
    assert_eq!(
        2,
        count(),
        "10 ms after it left: within the resend interval"
    );
    read_nack(
        &mut chain,
        departed + Duration::from_millis(50),
        &[1],
        None,
        None,
    );
    pump(&mut chain);
    assert_eq!(3, count(), "50 ms after it left: made again");
}
