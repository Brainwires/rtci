//! The probe after a large drop of the target, at the congestion controller: which clusters
//! it asks for under each [`AfterDropProbe`], and when.
//!
//! The chain is the one the default interceptor set builds for a sender (congestion
//! controller, TWCC sender, pacer, NACK responder); the estimator is the test's: its target
//! and its reading of the path are set from outside, and nothing ever reports a packet, so
//! every cluster is given up a second after it was asked for. The target is 2 Mbit/s for
//! three seconds and 300 kbit/s from then on: a large drop. The estimator reads over-use for
//! half a second from the drop, under-use for the next half, and normal from 4 s on.
//!
//! What is read is every [`ProbeRequest`] that reaches the application end. A probe after the
//! drop asks for 85% of the rate before it (1.7 Mbit/s); the clusters of an
//! application-limited sender ask for twice the target (600 kbit/s after the drop).

use rtci_interceptor::{
    AfterDropProbe, AttributedPacket, BandwidthEstimator, CongestionControlBuilder, Interceptor,
    NackResponderBuilder, PacerBuilder, Packet, PacketReport, ProbeRequest, RTCPFeedback,
    RTPHeaderExtension, Registry, Slot, StreamInfo, TaggedPacket, TwccSenderBuilder, Usage,
};
use sansio::Protocol;
use shared::TransportContext;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const MEDIA_SSRC: u32 = 0x00A0_0001;
const RTX_SSRC: u32 = 0x00A0_0002;
const BEFORE: f64 = 2_000_000.0;
const AFTER: f64 = 300_000.0;
const DROP_AT: Duration = Duration::from_secs(3);
const PACKET_OCTETS: usize = 1000;

/// An estimator whose target and reading of the path are the test's.
struct Scripted {
    target: Arc<Mutex<f64>>,
    usage: Arc<Mutex<Usage>>,
}

impl BandwidthEstimator for Scripted {
    fn on_reports(&mut self, _now: Instant, _reports: &[PacketReport]) {}

    fn target_bitrate(&self) -> f64 {
        *self.target.lock().unwrap()
    }

    fn usage(&self) -> Usage {
        *self.usage.lock().unwrap()
    }
}

fn stream() -> StreamInfo {
    StreamInfo {
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
    }
}

/// When the probes after the drop were asked for in a 12 s run: the requests at 85% of the
/// rate before it. `media_share` is what the application sends, as a share of its target.
fn drop_probes(form: AfterDropProbe, media_share: f64) -> Vec<Duration> {
    let epoch = Instant::now();
    let target = Arc::new(Mutex::new(BEFORE));
    let usage = Arc::new(Mutex::new(Usage::Normal));
    let controller = CongestionControlBuilder::new(Scripted {
        target: target.clone(),
        usage: usage.clone(),
    })
    .with_bandwidth_probing(true)
    .with_after_drop_probe(form)
    .build();
    let mut chain = Registry::new()
        .with(Slot::CongestionControl, controller)
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .with(
            Slot::Pacer,
            PacerBuilder::new().with_target_bitrate(BEFORE).build(),
        )
        .with(Slot::NackResponder, NackResponderBuilder::new().build())
        .build();
    chain.bind_local_stream(&stream());

    let mut seen = Vec::new();
    let mut sequence_number = 0u16;
    let mut next_media = Duration::ZERO;
    let mut elapsed = Duration::ZERO;
    while elapsed < Duration::from_secs(12) {
        let now = epoch + elapsed;
        let rate = if elapsed < DROP_AT { BEFORE } else { AFTER };
        *target.lock().unwrap() = rate;
        *usage.lock().unwrap() = if elapsed < DROP_AT {
            Usage::Normal
        } else if elapsed < DROP_AT + Duration::from_millis(500) {
            Usage::Over
        } else if elapsed < DROP_AT + Duration::from_secs(1) {
            Usage::Under
        } else {
            Usage::Normal
        };

        while next_media <= elapsed {
            chain
                .handle_write(TaggedPacket {
                    now,
                    transport: TransportContext::default(),
                    message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                        header: rtp::header::Header {
                            version: 2,
                            payload_type: 96,
                            sequence_number,
                            timestamp: (next_media.as_secs_f64() * 90_000.0) as u32,
                            ssrc: MEDIA_SSRC,
                            ..Default::default()
                        },
                        payload: vec![0u8; PACKET_OCTETS - 20].into(),
                    })),
                })
                .unwrap();
            sequence_number = sequence_number.wrapping_add(1);
            next_media +=
                Duration::from_secs_f64(PACKET_OCTETS as f64 * 8.0 / (rate * media_share));
        }
        for _ in 0..64 {
            match chain.poll_timeout() {
                Some(at) if at <= now => chain.handle_timeout(now).unwrap(),
                _ => break,
            }
        }
        while chain.poll_write().is_some() {}
        while let Some(read) = chain.poll_read() {
            if let Some(request) = read.message.custom::<ProbeRequest>() {
                println!("MEASURE {form:?} share {media_share}: {elapsed:?} {request:?}");
                if elapsed > DROP_AT && request.bits_per_second == 0.85 * BEFORE {
                    seen.push(elapsed);
                }
            }
        }
        elapsed += Duration::from_millis(1);
    }
    seen
}

/// [`AfterDropProbe::Repeated`], a builder's default: from a second after the drop, once a
/// second until the drop is five seconds old, whether or not the sender is application
/// limited and whatever the estimator reads.
#[test]
fn the_repeated_probe_is_asked_once_a_second_for_five_seconds() {
    for media_share in [1.0, 0.5] {
        let seen = drop_probes(AfterDropProbe::Repeated, media_share);
        let expected: Vec<Duration> = (1..=5)
            .map(|second| DROP_AT + Duration::from_secs(second))
            .collect();
        assert_eq!(expected, seen, "sending {media_share} of the target");
    }
}

/// [`AfterDropProbe::Libwebrtc`]: one cluster, when the estimator's reading has gone from
/// under-use to normal (a second after the drop here), for a sender that is application
/// limited; none for one that keeps up with its target.
#[test]
fn libwebrtcs_probe_is_asked_once_when_overuse_has_ended_and_only_of_a_limited_sender() {
    let seen = drop_probes(AfterDropProbe::Libwebrtc, 0.5);
    assert_eq!(1, seen.len(), "{seen:?}");
    let after = seen[0] - DROP_AT;
    assert!(
        after >= Duration::from_secs(1) && after <= Duration::from_millis(1_100),
        "when the reading is normal again: {after:?} after the drop"
    );
    assert_eq!(
        Vec::<Duration>::new(),
        drop_probes(AfterDropProbe::Libwebrtc, 1.0),
        "a sender at its target is not probed"
    );
}

/// [`AfterDropProbe::Off`]: no probe after the drop.
#[test]
fn without_the_probe_nothing_asks_for_the_rate_before_the_drop() {
    for media_share in [1.0, 0.5] {
        assert_eq!(
            Vec::<Duration>::new(),
            drop_probes(AfterDropProbe::Off, media_share),
            "sending {media_share} of the target"
        );
    }
}
