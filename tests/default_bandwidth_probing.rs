//! The default interceptor set probes the path for capacity (RFC 8836 section 2, requirement 4:
//! adapt as quickly as possible to the initial conditions, a SHOULD), and its probes carry no
//! media: a cluster the application's own packets do not fill is padding on the RTX stream,
//! which a receiver drops, never a second copy of a packet it may play twice.

use rtc::interceptor::{
    AttributedPacket, Interceptor, Packet, ProbePacket, RTCPFeedback, RTPHeaderExtension, Registry,
    StreamInfo, TaggedPacket,
};
use rtc::peer_connection::configuration::interceptor_registry::{
    DefaultInterceptorOptions, register_default_interceptors_with_options,
};
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::sansio::Protocol;
use rtc::shared::TransportContext;
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const MEDIA_SSRC: u32 = 0x0B0B_0001;
const RTX_SSRC: u32 = 0x0B0B_0002;

/// What left the sender in the first second of a 300 kbit/s stream: (probe packets, probe
/// packets on the RTX stream that carry a payload, padding-only packets on the RTX stream).
fn first_second(options: &DefaultInterceptorOptions) -> (usize, usize, usize) {
    let mut media_engine = MediaEngine::default();
    let (registry, _handles) =
        register_default_interceptors_with_options(Registry::new(), &mut media_engine, options)
            .expect("default interceptors");
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
    let (mut probes, mut probes_with_payload, mut padding_only) = (0, 0, 0);
    let mut sequence_number = 0u16;
    for millisecond in 0..1_000u64 {
        let now = epoch + Duration::from_millis(millisecond);
        // 1000-octet packets at 300 kbit/s: one every 27 ms or so.
        if millisecond % 27 == 0 {
            chain
                .handle_write(TaggedPacket {
                    now,
                    transport: TransportContext::default(),
                    message: AttributedPacket::new(Packet::Rtp(rtc::rtp::packet::Packet {
                        header: rtc::rtp::header::Header {
                            version: 2,
                            payload_type: 96,
                            sequence_number,
                            ssrc: MEDIA_SSRC,
                            ..Default::default()
                        },
                        payload: vec![0xAB; 1000].into(),
                    })),
                })
                .expect("write");
            sequence_number = sequence_number.wrapping_add(1);
        }
        if chain.poll_timeout().is_some_and(|at| at <= now) {
            chain.handle_timeout(now).expect("timeout");
        }
        while chain.poll_read().is_some() {}
        while let Some(out) = chain.poll_write() {
            let Packet::Rtp(packet) = &out.message.packet else {
                continue;
            };
            let on_rtx = packet.header.ssrc == RTX_SSRC;
            if out.message.custom::<ProbePacket>().is_some() {
                probes += 1;
                if on_rtx && !packet.payload.is_empty() {
                    probes_with_payload += 1;
                }
            }
            if on_rtx && packet.payload.is_empty() && packet.header.padding {
                padding_only += 1;
            }
        }
    }
    (probes, probes_with_payload, padding_only)
}

/// The default set sends its start-up clusters within the first second, filled with
/// padding-only packets on the RTX stream; none of its probe packets on the RTX stream carries
/// a payload.
#[test]
fn the_default_set_probes_with_padding_the_receiver_drops() {
    let (probes, with_payload, padding_only) = first_second(&DefaultInterceptorOptions::default());
    assert!(probes >= 10, "start-up clusters: {probes} probe packets");
    assert!(padding_only >= 5, "{padding_only} padding-only RTX packets");
    assert_eq!(
        0, with_payload,
        "no probe repeats media a receiver could play twice"
    );
}

/// The opt-out sends only what the application writes.
#[test]
fn without_probing_the_default_set_sends_only_what_was_written() {
    let mut options = DefaultInterceptorOptions::default();
    options.bandwidth_probing = false;
    let (probes, with_payload, padding_only) = first_second(&options);
    assert_eq!((0, 0, 0), (probes, with_payload, padding_only));
}
