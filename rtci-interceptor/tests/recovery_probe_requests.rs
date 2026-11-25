//! Recovery probing at the congestion controller: which clusters it asks for, and when.
//!
//! The chain is the one the default interceptor set builds for a sender (congestion
//! controller, TWCC sender, pacer, NACK responder); the estimator is the test's: its target
//! and its over-use reading are set from outside, and nothing ever reports a packet, so every
//! cluster is given up a second after it was asked for. The application sends at its target
//! throughout (it is never application limited). The target is 2 Mbit/s for three seconds and
//! 300 kbit/s from then on: a large drop.
//!
//! What is read is every [`ProbeRequest`] that reaches the application end. A recovery
//! cluster is the one at twice the target (600 kbit/s); the probes after the drop ask for 85%
//! of the rate before it (1.7 Mbit/s) and end five seconds after it.

use rtci_interceptor::{
    AttributedPacket, BandwidthEstimator, CongestionControlBuilder, Interceptor,
    NackResponderBuilder, PacerBuilder, Packet, PacketReport, ProbeRequest, RTCPFeedback,
    RTPHeaderExtension, Registry, Slot, StreamInfo, TaggedPacket, TwccSenderBuilder, Usage,
};
use sansio::Protocol;
use shared::TransportContext;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// An estimator whose target and over-use reading are the test's.
struct Scripted {
    target: Arc<Mutex<f64>>,
    overusing: Arc<AtomicBool>,
}

impl BandwidthEstimator for Scripted {
    fn on_reports(&mut self, _now: Instant, _reports: &[PacketReport]) {}

    fn target_bitrate(&self) -> f64 {
        *self.target.lock().unwrap()
    }

    fn usage(&self) -> Usage {
        if self.overusing.load(Ordering::Relaxed) {
            Usage::Over
        } else {
            Usage::Normal
        }
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

/// The requests of a 30 s run, as (time into the run, bits per second asked). The estimator
/// reads over-use during `overused`.
fn requests(
    recovery_probing: bool,
    overused: Option<(Duration, Duration)>,
) -> Vec<(Duration, f64)> {
    let epoch = Instant::now();
    let target = Arc::new(Mutex::new(BEFORE));
    let overusing = Arc::new(AtomicBool::new(false));
    let controller = CongestionControlBuilder::new(Scripted {
        target: target.clone(),
        overusing: overusing.clone(),
    })
    .with_bandwidth_probing(true)
    .with_recovery_probing(recovery_probing)
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
    while elapsed < Duration::from_secs(30) {
        let now = epoch + elapsed;
        let rate = if elapsed < DROP_AT { BEFORE } else { AFTER };
        *target.lock().unwrap() = rate;
        overusing.store(
            overused.is_some_and(|(from, until)| elapsed >= from && elapsed < until),
            Ordering::Relaxed,
        );

        // The application writes media at its target.
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
            next_media += Duration::from_secs_f64(PACKET_OCTETS as f64 * 8.0 / rate);
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
                seen.push((elapsed, request.bits_per_second));
            }
        }
        elapsed += Duration::from_millis(1);
    }
    seen
}

/// The recovery clusters among the requests: those at twice the target after the drop.
fn recovery(requests: &[(Duration, f64)]) -> Vec<Duration> {
    requests
        .iter()
        .filter(|(at, rate)| *at > DROP_AT && *rate == 2.0 * AFTER)
        .map(|(at, _)| *at)
        .collect()
}

/// Without the setting, a builder's default: after the probes that follow the drop (1.7
/// Mbit/s, within five seconds of it) a sender at its target is asked for nothing.
#[test]
fn without_the_setting_nothing_is_asked_once_the_drop_is_five_seconds_old() {
    let seen = requests(false, None);
    println!("MEASURE requests without recovery probing: {seen:?}");
    assert!(
        seen.iter()
            .any(|(at, rate)| *at > DROP_AT && *rate == 0.85 * BEFORE),
        "the probes after the drop are asked for"
    );
    assert_eq!(
        Vec::<Duration>::new(),
        recovery(&seen),
        "no cluster at twice the target"
    );
    assert!(
        seen.iter()
            .all(|(at, _)| *at <= DROP_AT + Duration::from_millis(6_100)),
        "nothing after the drop is five seconds old (and its last cluster given up): {seen:?}"
    );
}

/// With `with_recovery_probing(true)`: from five seconds after the drop a cluster at twice
/// the target about every five seconds (one more second when the cluster before it was not
/// answered), for the rest of the run.
#[test]
fn with_the_setting_twice_the_target_is_asked_about_every_five_seconds() {
    let seen = requests(true, None);
    println!("MEASURE requests with recovery probing: {seen:?}");
    let recovery = recovery(&seen);
    let first = *recovery.first().expect("recovery clusters are asked for");
    assert!(
        first >= DROP_AT + Duration::from_secs(5)
            && first <= DROP_AT + Duration::from_millis(6_500),
        "the first one five seconds after the drop: {first:?}"
    );
    assert!(
        (4..=5).contains(&recovery.len()),
        "about every five seconds until the run ends at 30 s: {recovery:?}"
    );
    for pair in recovery.windows(2) {
        let gap = pair[1] - pair[0];
        assert!(
            gap >= Duration::from_secs(5) && gap <= Duration::from_millis(6_500),
            "{gap:?} between two recovery clusters: {recovery:?}"
        );
    }
}

/// While the estimator reads over-use ([`BandwidthEstimator::usage`]) no recovery cluster
/// is asked for; the one that fell due meanwhile goes out when the reading ends.
#[test]
fn no_recovery_cluster_is_asked_while_the_estimator_reads_overuse() {
    let (from, until) = (Duration::from_secs(10), Duration::from_secs(22));
    let seen = requests(true, Some((from, until)));
    println!("MEASURE requests with recovery probing, over-use from 10 s to 22 s: {seen:?}");
    let recovery = recovery(&seen);
    assert!(
        recovery.iter().any(|at| *at < from),
        "one before the over-use: {recovery:?}"
    );
    assert!(
        recovery.iter().all(|at| *at < from || *at >= until),
        "none during it: {recovery:?}"
    );
    assert!(
        recovery
            .iter()
            .any(|at| *at >= until && *at <= until + Duration::from_millis(200)),
        "the one that was due goes out when it ends: {recovery:?}"
    );
}
