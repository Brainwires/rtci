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

/// libwebrtc's rule, a setting: the retransmissions alone stay under the target over the last
/// second, whatever the originals took. At 80 kbit/s, 10 000 octets a second: nine
/// retransmissions of 1014 octets, although the originals already took three times that.
#[test]
fn retransmissions_alone_stay_under_the_target() {
    let target = 80_000.0;
    let allowed = (target / 8.0) as usize / RETRANSMISSION;
    assert_eq!(9, allowed);
    assert_eq!(allowed, scenario(up_to_target(), Some(target)));
}

/// RFC 4588 section 7, the default: the retransmissions take what the original packets leave of
/// the target over the last second, or the retransmission reserve the original media has been
/// lowered by before they are sent, whichever is more. Twenty requests of 1014 octets with no
/// round trip measured need 162 kbit/s, at most half the target: at 320 kbit/s the reserve is
/// 160 kbit/s (20 000 octets a second), more than the 9 640 the 30 originals (30 360 octets)
/// leave of 40 000: nineteen leave. At 240 kbit/s the originals leave nothing; the reserve is
/// 120 kbit/s, 15 000 octets: fourteen.
#[test]
fn retransmissions_take_what_the_originals_leave_or_the_reserve() {
    assert_eq!(9640 / RETRANSMISSION, 9);
    assert_eq!(19, scenario(NackResponderBuilder::new(), Some(320_000.0)));
    assert_eq!(14, scenario(NackResponderBuilder::new(), Some(240_000.0)));
    let rfc = || NackResponderBuilder::new().with_rate_limit(RetransmissionRateLimit::WithinTarget);
    assert_eq!(19, scenario(rfc(), Some(320_000.0)));
    // Without a reserve (at most 0 % of the target) the originals' share alone: nine, none.
    let no_reserve = || NackResponderBuilder::new().with_max_reserve_fraction(0.0);
    assert_eq!(9, scenario(no_reserve(), Some(320_000.0)));
    assert_eq!(0, scenario(no_reserve(), Some(240_000.0)));
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

/// A retransmission the limit holds back waits and leaves by itself when the window has room:
/// the responder's deadline is that instant, a second after the retransmission whose leaving
/// the window makes the room, and not earlier (a driver woken at once would spin).
#[test]
fn a_held_back_retransmission_is_due_when_the_window_has_room() {
    let base = Instant::now();
    let mut chain = responder(up_to_target());
    send(&mut chain, base, 30);
    let lost: Vec<u16> = (0..20).collect();
    let at = base + Duration::from_millis(300);
    assert_eq!(9, nack(&mut chain, at, &lost, Some(80_000.0)));
    // The nine took the window at `at`: the tenth fits when the first of them has left it.
    let due = chain.poll_timeout().expect("eleven wait");
    assert_eq!(at + Duration::from_secs(1), due);
    // The receiver asks again meanwhile: the requests keep their place.
    assert_eq!(
        0,
        nack(
            &mut chain,
            at + Duration::from_millis(500),
            &lost[9..],
            None
        )
    );
    assert_eq!(Some(due), chain.poll_timeout());
    chain
        .handle_timeout(due - Duration::from_millis(1))
        .unwrap();
    assert_eq!(0, drain(&mut chain).retransmitted, "not before");
    chain.handle_timeout(due).unwrap();
    assert_eq!(9, drain(&mut chain).retransmitted, "the next nine at once");
    assert_eq!(0, nack(&mut chain, due, &lost[18..], None));
    assert_eq!(
        Some(due + Duration::from_secs(1)),
        chain.poll_timeout(),
        "the last two wait for the next second"
    );
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
/// 81 kbit/s: at 240 kbit/s the reserve is that (10 140 octets: all ten leave), at 150 kbit/s
/// it is half the target (9 375 octets: nine leave). Both targets are under what the 30
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
        assert_eq!(leave, seen.retransmitted, "at {target}");
        assert_eq!(vec![reserve], seen.reserves, "at {target}");
        assert_eq!(vec![target - reserve], seen.targets, "at {target}");
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
    // 500 kbit/s: 62 500 octets, the originals took 30 360, the five fit.
    read_nack(&mut chain, at, &[0, 1, 2, 3, 4], Some(500_000.0), None);
    let seen = drain(&mut chain);
    assert_eq!(5, seen.retransmitted);
    let in_use = 5.0 * RETRANSMISSION as f64 * 8.0;
    assert_eq!(
        vec![in_use],
        seen.reserves,
        "their rate is reserved while in the window"
    );
    assert_eq!(vec![500_000.0 - in_use], seen.targets);
    let due = chain
        .poll_timeout()
        .expect("the reserve falls back to zero");
    assert_eq!(at + Duration::from_secs(1), due);
    chain.handle_timeout(due).unwrap();
    let seen = drain(&mut chain);
    assert_eq!(vec![0.0], seen.reserves);
    assert_eq!(vec![500_000.0], seen.targets);
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
/// of 100 kbit/s, 100 − 50 is under it: twelve retransmissions of 1014 octets fill the 12 500.
/// With a minimum of 40 kbit/s, or none announced, the reserve's 6 250 octets: six. The
/// original media is told the target less the reserve, never less than the minimum.
#[test]
fn near_the_floor_retransmissions_take_the_room_first() {
    for (minimum, expected, media_target) in [
        (None, 6250 / RETRANSMISSION, 50_000.0),
        (Some(40_000.0), 6250 / RETRANSMISSION, 50_000.0),
        (Some(100_000.0), 12_500 / RETRANSMISSION, 100_000.0),
    ] {
        let base = Instant::now();
        let mut chain = responder(NackResponderBuilder::new());
        send(&mut chain, base, 30);
        let lost: Vec<u16> = (0..20).collect();
        let at = base + Duration::from_millis(300);
        read_nack(&mut chain, at, &lost, Some(100_000.0), minimum);
        let seen = drain(&mut chain);
        assert_eq!(vec![media_target], seen.targets, "minimum {minimum:?}");
        let mut retransmitted = seen.retransmitted;
        chain.handle_timeout(at).unwrap();
        retransmitted += drain(&mut chain).retransmitted;
        assert_eq!(expected, retransmitted, "minimum {minimum:?}");
        if minimum.is_some_and(|minimum| minimum > 50_000.0) {
            let due = chain.poll_timeout().expect("the rest wait");
            assert_eq!(
                at + Duration::from_secs(1),
                due,
                "until the twelve leave the window"
            );
        }
    }
}

/// A driver that follows the documented loop (take what is written, then sleep until
/// `poll_timeout`, then `handle_timeout`) with nothing else waking it: the retransmissions the
/// limit holds back leave at their own due times, and the driver never spins (each deadline is
/// later than the instant it was handed last). Under the default rule at 240 kbit/s the 30
/// originals took the window: of twenty requests the 120 kbit/s reserve lets fourteen leave at
/// once, the rest as the window empties, until the requests run out a second after they were
/// made.
#[test]
fn a_held_retransmission_wakes_the_driver_once_at_its_due_time() {
    let base = Instant::now();
    let mut chain = responder(NackResponderBuilder::new());
    send(&mut chain, base, 30);
    let lost: Vec<u16> = (0..20).collect();
    let at = base + Duration::from_millis(300);
    read_nack(&mut chain, at, &lost, Some(240_000.0), None);
    assert_eq!(
        14,
        drain(&mut chain).retransmitted,
        "the reserve's share at once"
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
/// their own) written in 90 ms against a 12 kbit/s target: about one leaves every 0.7 s, and at
/// 2 s the rest have waited the bound and are discarded. A NACK for all ten, with a target that
/// has room for them, has exactly those that left resent.
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
    for sequence_number in 0..10u16 {
        chain
            .handle_write(TaggedPacket {
                now: base + Duration::from_millis(10) * u32::from(sequence_number),
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
    let mut now = base;
    while now < base + Duration::from_secs(3) {
        now += Duration::from_millis(10);
        chain.handle_timeout(now).unwrap();
        take(&mut chain, &mut left, &mut discarded);
    }
    assert!(
        !left.is_empty() && !discarded.is_empty(),
        "{left:?} {discarded:?}"
    );
    assert!(left.is_disjoint(&discarded), "{left:?} {discarded:?}");
    assert_eq!(10, left.len() + discarded.len(), "{left:?} {discarded:?}");

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
        .with(Slot::NackResponder, NackResponderBuilder::new().build())
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
