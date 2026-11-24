//! The NACK settings of `DefaultInterceptorOptions` reach the NACK interceptors of the chain
//! `register_default_interceptors_with_options` builds.
//!
//! Each test builds that whole chain (RTCP session, congestion control, pacer, NACK responder
//! and generator, ...) from the options, drives it in virtual time and counts what leaves on
//! the write leg: retransmissions for `nack_retransmission_rate_limit`, NACKs for
//! `nack_max_nacks_per_packet`. A registry that dropped either setting on the way to the
//! builders would build the builders' defaults, and the counts would be those of the default.

use bytes::Bytes;
use rtc::interceptor::{
    AttributedPacket, Interceptor, PacerQueueOverflow, Packet, RTCPFeedback, Registry,
    RetransmissionRateLimit, StreamInfo, TaggedPacket,
};
use rtc::peer_connection::configuration::interceptor_registry::{
    DefaultInterceptorOptions, register_default_interceptors_with_options,
};
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::rtcp::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate;
use rtc::rtcp::transport_feedbacks::transport_layer_nack::{
    TransportLayerNack, nack_pairs_from_sequence_numbers,
};
use rtc::rtp::header::Header;
use rtc::sansio::Protocol;
use rtc::shared::TransportContext;
use std::time::{Duration, Instant};

const LOCAL_SSRC: u32 = 0x1111_1111;
const LOCAL_RTX_SSRC: u32 = 0x2222_2222;
const REMOTE_SSRC: u32 = 0x3333_3333;
/// The step virtual time advances by.
const STEP: Duration = Duration::from_millis(5);

fn stream_info(ssrc: u32, rtx: Option<u32>) -> StreamInfo {
    let feedback = |typ: &str, parameter: &str| RTCPFeedback {
        typ: typ.to_owned(),
        parameter: parameter.to_owned(),
    };
    StreamInfo {
        ssrc,
        ssrc_rtx: rtx,
        payload_type: 96,
        payload_type_rtx: rtx.map(|_| 97),
        mime_type: "video/VP8".to_owned(),
        clock_rate: 90000,
        rtcp_feedback: vec![feedback("nack", ""), feedback("nack", "pli")],
        ..Default::default()
    }
}

fn tagged(now: Instant, packet: Packet) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(packet),
    }
}

fn rtp(ssrc: u32, sequence_number: u16, payload: usize) -> Packet {
    Packet::Rtp(rtc::rtp::packet::Packet {
        header: Header {
            version: 2,
            payload_type: 96,
            sequence_number,
            timestamp: u32::from(sequence_number) * 3000,
            ssrc,
            ..Default::default()
        },
        payload: Bytes::from(vec![0u8; payload]),
    })
}

/// The default chain with `options`, a fresh media engine with the default codecs, without
/// bandwidth probing (its padding would ride on the RTX stream the counts look at).
fn default_chain(mut options: DefaultInterceptorOptions) -> impl Interceptor {
    let mut media_engine = MediaEngine::default();
    media_engine
        .register_default_codecs()
        .expect("default codecs");
    options.bandwidth_probing = false;
    let (registry, _handles) =
        register_default_interceptors_with_options(Registry::new(), &mut media_engine, &options)
            .expect("default interceptors");
    registry.build()
}

/// What the chain hands the wire and the application at once; `on_write` sees every packet
/// written.
fn drain(chain: &mut impl Interceptor, on_write: &mut impl FnMut(&Packet)) {
    while chain.poll_read().is_some() {}
    while let Some(tagged) = chain.poll_write() {
        on_write(&tagged.message.packet);
    }
}

/// Advances virtual time from `*now` to `until` in steps of [`STEP`], firing the chain's timers
/// and taking what it writes.
fn run_until(
    chain: &mut impl Interceptor,
    now: &mut Instant,
    until: Instant,
    on_write: &mut impl FnMut(&Packet),
) {
    while *now < until {
        *now += STEP;
        chain.handle_timeout(*now).expect("timeout");
        drain(chain, on_write);
    }
}

/// Originals sent before the NACK, and asked for in it.
const ORIGINALS: u16 = 60;

/// A local video stream with RTX sends [`ORIGINALS`] packets of 1012 octets, 40 ms apart
/// (202 kbit/s, under the congestion controller's 300 kbit/s start). Three seconds later the
/// receiver asks for all of them in one compound packet with a REMB of 100 kbit/s (the
/// controller's floor): the controller lowers its target to that and announces it on the
/// same packet, so the pacer and the NACK responder read it before the NACK. Returns how many
/// retransmissions leave the chain in the six seconds that follow. The pacer drains its queue
/// above the target (`PacerQueueOverflow::Drain`), so it drops none of them; whatever the
/// responder lets through leaves. Ends before the RTP circuit breaker's RTCP timeout (15 s).
fn retransmissions_for_a_nack_of_every_packet(limit: RetransmissionRateLimit) -> usize {
    let mut options = DefaultInterceptorOptions::default();
    options.nack_retransmission_rate_limit = limit;
    options.pacer_queue_overflow = PacerQueueOverflow::Drain;
    let mut chain = default_chain(options);
    chain.bind_local_stream(&stream_info(LOCAL_SSRC, Some(LOCAL_RTX_SSRC)));

    let start = Instant::now();
    let mut now = start;
    let mut retransmissions = 0usize;
    let mut originals = 0usize;
    let mut on_write = |packet: &Packet| {
        if let Packet::Rtp(rtp) = packet {
            match rtp.header.ssrc {
                LOCAL_RTX_SSRC if !rtp.payload.is_empty() => retransmissions += 1,
                LOCAL_SSRC => originals += 1,
                _ => {}
            }
        }
    };

    for sequence_number in 0..ORIGINALS {
        run_until(
            &mut chain,
            &mut now,
            start + Duration::from_millis(40) * u32::from(sequence_number),
            &mut on_write,
        );
        chain
            .handle_write(tagged(now, rtp(LOCAL_SSRC, sequence_number, 1000)))
            .expect("write");
        drain(&mut chain, &mut on_write);
    }
    let nack_at = now + Duration::from_secs(3);
    run_until(&mut chain, &mut now, nack_at, &mut on_write);

    let all: Vec<u16> = (0..ORIGINALS).collect();
    chain
        .handle_read(tagged(
            now,
            Packet::Rtcp(vec![
                Box::new(ReceiverEstimatedMaximumBitrate {
                    sender_ssrc: REMOTE_SSRC,
                    bitrate: 100_000.0,
                    ssrcs: vec![LOCAL_SSRC],
                }),
                Box::new(TransportLayerNack {
                    sender_ssrc: REMOTE_SSRC,
                    media_ssrc: LOCAL_SSRC,
                    nacks: nack_pairs_from_sequence_numbers(&all),
                }),
            ]),
        ))
        .expect("read");
    drain(&mut chain, &mut on_write);
    run_until(
        &mut chain,
        &mut now,
        nack_at + Duration::from_secs(6),
        &mut on_write,
    );
    drop(on_write);

    assert_eq!(
        usize::from(ORIGINALS),
        originals,
        "every original left before the NACK ({limit:?})"
    );
    retransmissions
}

/// `nack_retransmission_rate_limit` reaches the NACK responder. With `Unlimited` every packet
/// asked for is retransmitted. With `UpToTarget` and with the default `WithinTarget` the
/// retransmissions are held to the 100 kbit/s target, 12 500 octets in a second: twelve
/// retransmissions of 1014 octets, and as many again when the first leave the window a second
/// later, before the requests the receiver does not repeat run out
/// (`PENDING_REQUEST_LIFETIME`): far fewer than the sixty asked for. A registry that gave the
/// responder its default instead of `Unlimited` would hold them too.
#[test]
fn the_retransmission_rate_limit_option_reaches_the_nack_responder() {
    assert_eq!(
        usize::from(ORIGINALS),
        retransmissions_for_a_nack_of_every_packet(RetransmissionRateLimit::Unlimited),
        "Unlimited retransmits every packet asked for"
    );
    for limit in [
        RetransmissionRateLimit::UpToTarget,
        RetransmissionRateLimit::WithinTarget,
    ] {
        let retransmissions = retransmissions_for_a_nack_of_every_packet(limit);
        assert!(
            (1..=usize::from(ORIGINALS) / 2).contains(&retransmissions),
            "{limit:?}: {retransmissions} retransmissions of {ORIGINALS} asked for"
        );
    }
}

/// The sequence number the remote's stream loses.
const LOST: u16 = 5;

/// The remote sends a video stream with NACK, a packet every 50 ms for eight seconds, and
/// packet [`LOST`] never arrives. Returns how many NACKs that leave the chain ask for it. The
/// generator looks for gaps every 100 ms and, with no round trip measured, asks again each
/// time; the RTCP session merges the requests waiting for one compound packet into one NACK,
/// so the count is that of the compound packets that carry a request for it.
fn requests_for_a_lost_packet(max_nacks_per_packet: u16) -> usize {
    let mut options = DefaultInterceptorOptions::default();
    options.nack_max_nacks_per_packet = max_nacks_per_packet;
    let mut chain = default_chain(options);
    chain.bind_local_stream(&stream_info(LOCAL_SSRC, None));
    chain.bind_remote_stream(&stream_info(REMOTE_SSRC, None));

    let start = Instant::now();
    let mut now = start;
    let mut requests = 0usize;
    let mut on_write = |packet: &Packet| {
        if let Packet::Rtcp(packets) = packet {
            requests += packets
                .iter()
                .filter_map(|packet| packet.as_any().downcast_ref::<TransportLayerNack>())
                .filter(|nack| {
                    nack.media_ssrc == REMOTE_SSRC
                        && nack
                            .nacks
                            .iter()
                            .any(|pair| pair.packet_list().contains(&LOST))
                })
                .count();
        }
    };

    for sequence_number in 0..160u16 {
        run_until(
            &mut chain,
            &mut now,
            start + Duration::from_millis(50) * u32::from(sequence_number),
            &mut on_write,
        );
        if sequence_number != LOST {
            chain
                .handle_read(tagged(now, rtp(REMOTE_SSRC, sequence_number, 200)))
                .expect("read");
        }
        drain(&mut chain, &mut on_write);
    }
    run_until(
        &mut chain,
        &mut now,
        start + Duration::from_secs(8),
        &mut on_write,
    );
    drop(on_write);
    requests
}

/// `nack_max_nacks_per_packet` reaches the NACK generator. With a limit of two the lost packet
/// is asked for at most twice (once if both requests left in one compound packet); unlimited
/// (0, the default) it is asked for again and again over the eight seconds. A registry that
/// gave the generator its default instead of the limit would keep asking.
#[test]
fn the_max_requests_per_packet_option_reaches_the_nack_generator() {
    let limited = requests_for_a_lost_packet(2);
    assert!(
        (1..=2).contains(&limited),
        "asked for {limited} times with a limit of two"
    );
    let unlimited = requests_for_a_lost_packet(0);
    assert!(
        unlimited >= 4,
        "asked for {unlimited} times without a limit"
    );
}
