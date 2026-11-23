//! RFC 4588 section 7: retransmissions are congestion controlled. The NACK responder holds
//! what it retransmits to the congestion controller's target, which it reads from
//! `Attribute::TargetBitrateChanged` as the estimate passes on the read leg: by default the
//! retransmissions alone stay under the target over the last second (libwebrtc's rule); in the
//! RFC's form they take only what the original packets leave of it.

use rtc_interceptor::{
    Attribute, AttributedPacket, Interceptor, NackResponderBuilder, Packet, RTCPFeedback, Registry,
    RetransmissionRateLimit, Slot, StreamInfo, TaggedPacket,
};
use rtcp::transport_feedbacks::transport_layer_nack::{
    TransportLayerNack, nack_pairs_from_sequence_numbers,
};
use shared::TransportContext;
use shared::marshal::MarshalSize;
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

/// A NACK for `sequence_numbers` at `now`, riding with the estimate `target_bps` when given (as
/// a congestion controller wire-ward of the responder attaches it), and the number of
/// retransmissions that leave for it.
fn nack(
    chain: &mut impl Interceptor,
    now: Instant,
    sequence_numbers: &[u16],
    target_bps: Option<f64>,
) -> usize {
    let mut message = AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerNack {
        sender_ssrc: 1,
        media_ssrc: SSRC,
        nacks: nack_pairs_from_sequence_numbers(sequence_numbers),
    })]));
    if let Some(bits_per_second) = target_bps {
        message.add(Attribute::TargetBitrateChanged { bits_per_second });
    }
    chain
        .handle_read(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message,
        })
        .unwrap();
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

/// The default: the retransmissions alone stay under the target over the last second, whatever
/// the originals took. At 80 kbit/s, 10 000 octets a second: nine retransmissions of 1014
/// octets, although the originals already took three times that.
#[test]
fn retransmissions_alone_stay_under_the_target() {
    let target = 80_000.0;
    let allowed = (target / 8.0) as usize / RETRANSMISSION;
    assert_eq!(9, allowed);
    assert_eq!(allowed, scenario(NackResponderBuilder::new(), Some(target)));
}

/// RFC 4588 section 7, "the acceptable packet rate and bitrate include both the original and
/// retransmitted data": at 320 kbit/s (40 000 octets a second) the 30 originals (30 360 octets)
/// leave 9 640, room for nine retransmissions; at 240 kbit/s they leave none.
#[test]
fn retransmissions_take_what_the_originals_leave_of_the_target() {
    let rfc = || NackResponderBuilder::new().with_rate_limit(RetransmissionRateLimit::WithinTarget);
    let left = 40_000 - 30 * ORIGINAL;
    assert_eq!(9, left / RETRANSMISSION);
    assert_eq!(9, scenario(rfc(), Some(320_000.0)));
    assert_eq!(0, scenario(rfc(), Some(240_000.0)));
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

/// The window is the last second: what was retransmitted a second ago no longer counts, and
/// the packets refused before are retransmitted when the receiver asks again.
#[test]
fn the_allowance_comes_back_after_a_second() {
    let base = Instant::now();
    let mut chain = responder(NackResponderBuilder::new());
    send(&mut chain, base, 30);
    let lost: Vec<u16> = (0..20).collect();
    let at = base + Duration::from_millis(300);
    assert_eq!(9, nack(&mut chain, at, &lost, Some(80_000.0)));
    // Half a second later the window still holds those nine: nothing more.
    assert_eq!(
        0,
        nack(
            &mut chain,
            at + Duration::from_millis(500),
            &lost[9..],
            None
        )
    );
    // A second after them, nine more.
    assert_eq!(
        9,
        nack(
            &mut chain,
            at + Duration::from_millis(1000),
            &lost[9..],
            None
        )
    );
}
