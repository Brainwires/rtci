//! `DefaultInterceptorOptions::probe_after_drop` reaches the congestion controller of the
//! default interceptor set: after a large drop of the target the default
//! ([`AfterDropProbe::Repeated`]) asks for clusters at 85% of the rate before the drop, and
//! [`AfterDropProbe::Off`] asks for none.
//!
//! The drop is made without a network: the session's bit-rate limit is set to a third of the
//! starting target for half a second (the estimate follows a limit at once, and no feedback
//! ever raises it again), while the application goes on sending at the starting rate, so it
//! is never application limited.

use rtci::interceptor::{
    AfterDropProbe, AttributedPacket, Interceptor, Packet, ProbeRequest, RTCPFeedback,
    RTPHeaderExtension, Registry, StreamInfo, TaggedPacket,
};
use rtci::peer_connection::configuration::interceptor_registry::{
    DefaultInterceptorOptions, register_default_interceptors_with_options,
};
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::sansio::Protocol;
use rtci::shared::TransportContext;
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const MEDIA_SSRC: u32 = 0x0B0B_0001;
const RTX_SSRC: u32 = 0x0B0B_0002;

/// The starting target, and every probe request of a 9 s run as (milliseconds into the run,
/// bits per second asked). The limit is on from 2 s to 2.5 s.
fn requests(options: &DefaultInterceptorOptions) -> (f64, Vec<(u64, f64)>) {
    let mut media_engine = MediaEngine::default();
    let (registry, handles) =
        register_default_interceptors_with_options(Registry::new(), &mut media_engine, options)
            .expect("default interceptors");
    let start = handles.congestion_control.target_bitrate();
    let mut chain = registry.build();
    chain.bind_local_stream(&StreamInfo {
        ssrc: MEDIA_SSRC,
        ssrc_rtx: Some(RTX_SSRC),
        payload_type: 96,
        payload_type_rtx: Some(97),
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        rtcp_feedback: vec![
            RTCPFeedback {
                typ: "transport-cc".to_owned(),
                parameter: String::new(),
            },
            RTCPFeedback {
                typ: "nack".to_owned(),
                parameter: String::new(),
            },
        ],
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: 5,
        }],
        ..Default::default()
    });

    let epoch = Instant::now();
    let mut seen = Vec::new();
    let mut sequence_number = 0u16;
    // 1000-octet packets at the starting target.
    let interval = Duration::from_secs_f64(8_000.0 / start);
    let mut next_media = Duration::ZERO;
    for millisecond in 0..9_000u64 {
        let elapsed = Duration::from_millis(millisecond);
        let now = epoch + elapsed;
        if millisecond == 2_000 {
            handles
                .congestion_control
                .set_session_bitrate_limit(Some(start / 3.0));
        }
        if millisecond == 2_500 {
            handles.congestion_control.set_session_bitrate_limit(None);
        }
        while next_media <= elapsed {
            chain
                .handle_write(TaggedPacket {
                    now,
                    transport: TransportContext::default(),
                    message: AttributedPacket::new(Packet::Rtp(rtci::rtp::packet::Packet {
                        header: rtci::rtp::header::Header {
                            version: 2,
                            payload_type: 96,
                            sequence_number,
                            ssrc: MEDIA_SSRC,
                            ..Default::default()
                        },
                        payload: vec![0xAB; 980].into(),
                    })),
                })
                .expect("write");
            sequence_number = sequence_number.wrapping_add(1);
            next_media += interval;
        }
        for _ in 0..64 {
            match chain.poll_timeout() {
                Some(at) if at <= now => chain.handle_timeout(now).expect("timeout"),
                _ => break,
            }
        }
        while chain.poll_write().is_some() {}
        while let Some(read) = chain.poll_read() {
            if let Some(request) = read.message.custom::<ProbeRequest>() {
                seen.push((millisecond, request.bits_per_second));
            }
        }
    }
    (start, seen)
}

/// The probes after the drop among the requests: those at 85% of the starting target.
fn after_the_drop(start: f64, requests: &[(u64, f64)]) -> Vec<u64> {
    requests
        .iter()
        .filter(|(at, rate)| *at >= 2_000 && *rate == 0.85 * start)
        .map(|(at, _)| *at)
        .collect()
}

/// The default set asks for the rate before the drop once the limit that hid it is gone,
/// within five seconds of the drop.
#[test]
fn the_default_set_probes_for_the_rate_before_a_large_drop() {
    let options = DefaultInterceptorOptions::default();
    let (start, seen) = requests(&options);
    println!("MEASURE default: start {start}, requests {seen:?}");
    let probes = after_the_drop(start, &seen);
    assert!(!probes.is_empty(), "no probe after the drop: {seen:?}");
    assert!(
        probes.iter().all(|at| (2_500..=7_100).contains(at)),
        "after the limit is lifted, while the drop is five seconds old: {probes:?}"
    );
}

/// With `probe_after_drop` off the same call is asked for nothing at that rate.
#[test]
fn with_the_probe_after_a_drop_off_the_default_set_asks_for_nothing() {
    let mut options = DefaultInterceptorOptions::default();
    options.probe_after_drop = AfterDropProbe::Off;
    let (start, seen) = requests(&options);
    println!("MEASURE off: start {start}, requests {seen:?}");
    assert_eq!(Vec::<u64>::new(), after_the_drop(start, &seen), "{seen:?}");
}
