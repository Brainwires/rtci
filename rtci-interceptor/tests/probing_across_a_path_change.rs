//! Bandwidth probing across a path change, at the congestion controller: which clusters it
//! asks for once it is told of a new path.
//!
//! The chain is the one the default interceptor set builds for a sender (congestion
//! controller, TWCC sender, pacer, NACK responder); the estimator is the test's: its target is
//! set from outside, it starts over at 300 kbit/s when it is told of a path change, and
//! nothing ever reports a packet, so every cluster is given up a second after it was asked
//! for. The script is an outage ended by an ICE restart as the default chain's estimator goes
//! through it: 2 Mbit/s for three seconds, then halved every half second while nothing is
//! acknowledged (1000, 500, 250, 125 kbit/s; each halving a large drop of the target), and the
//! new path at 5.8 s, 300 ms after the probe for the rate before the last halving was asked
//! into the dead path.
//!
//! What is read is every [`ProbeRequest`] that reaches the application end from the path
//! change on. The application sends at its target throughout, so no cluster of an
//! application-limited sender is due.

use rtci_interceptor::{
    AttributedPacket, BandwidthEstimator, CongestionControlBuilder, CongestionControlHandle,
    Interceptor, NackResponderBuilder, PacerBuilder, Packet, PacketReport, PathChanged,
    ProbeRequest, RTCPFeedback, RTPHeaderExtension, Registry, Slot, StreamInfo, TaggedPacket,
    TwccSenderBuilder,
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
const START: f64 = 300_000.0;
const OUTAGE_AT: Duration = Duration::from_secs(3);
const CHANGE_AT: Duration = Duration::from_millis(5_800);
const PACKET_OCTETS: usize = 1000;

/// An estimator whose target is the test's, and which starts over at [`START`] on a new path.
struct Scripted {
    target: Arc<Mutex<f64>>,
}

impl BandwidthEstimator for Scripted {
    fn on_reports(&mut self, _now: Instant, _reports: &[PacketReport]) {}

    fn target_bitrate(&self) -> f64 {
        *self.target.lock().unwrap()
    }

    fn on_path_change(&mut self, _now: Instant) {
        *self.target.lock().unwrap() = START;
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

/// How the congestion controller learns of the new path.
#[derive(Debug, Clone, Copy)]
enum Told {
    /// The peer connection's word on the read leg ([`PathChanged`]).
    PeerConnection,
    /// The application's, through the handle
    /// ([`CongestionControlHandle::notify_path_change`]).
    Application,
}

/// The target of the old path at `elapsed`: [`BEFORE`], then halved every half second from
/// [`OUTAGE_AT`] down to 125 kbit/s.
fn old_path_target(elapsed: Duration) -> f64 {
    if elapsed < OUTAGE_AT {
        return BEFORE;
    }
    let halvings = ((elapsed - OUTAGE_AT).as_millis() / 500 + 1).min(4);
    BEFORE / f64::from(1u32 << halvings)
}

/// The clusters asked for in a 12 s run: (time, bit rate), those before the path change and
/// those from it on.
type Requests = Vec<(Duration, f64)>;

fn run(told: Told) -> (Requests, Requests) {
    let epoch = Instant::now();
    let target = Arc::new(Mutex::new(BEFORE));
    let (controller, handle): (_, CongestionControlHandle) =
        CongestionControlBuilder::new(Scripted {
            target: target.clone(),
        })
        .with_bandwidth_probing(true)
        .build_with_handle();
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

    let (mut before, mut after) = (Vec::new(), Vec::new());
    let mut changed = false;
    let mut sequence_number = 0u16;
    let mut next_media = Duration::ZERO;
    let mut elapsed = Duration::ZERO;
    while elapsed < Duration::from_secs(12) {
        let now = epoch + elapsed;
        if elapsed < CHANGE_AT {
            *target.lock().unwrap() = old_path_target(elapsed);
        } else if !changed {
            changed = true;
            match told {
                Told::PeerConnection => chain
                    .handle_read(PathChanged.into_packet(now, None))
                    .unwrap(),
                // The handle's word is taken at the controller's next read or timeout.
                Told::Application => {
                    handle.notify_path_change();
                    chain.handle_timeout(now).unwrap();
                }
            }
        }
        let rate = *target.lock().unwrap();

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
                println!("MEASURE {told:?}: {elapsed:?} {request:?}");
                let list = if elapsed < CHANGE_AT {
                    &mut before
                } else {
                    &mut after
                };
                list.push((elapsed, request.bits_per_second));
            }
        }
        elapsed += Duration::from_millis(1);
    }
    assert!(changed);
    assert_eq!(START, *target.lock().unwrap(), "the estimator started over");
    (before, after)
}

/// What every way of learning of the new path is held to: probing starts over as at the
/// start of the call. The first start-up cluster (three times the rate the estimator starts
/// over at) is asked for at once, although the old path's last probe after a drop is still
/// awaiting a result that cannot come; the second (six times) when the first is given up;
/// and nothing asks for the rate before a drop of the old path, nor for anything else.
fn assert_probing_starts_over(told: Told) {
    let (before, after) = run(told);
    // The premise: the outage's last halving (to 125 kbit/s at 4.5 s) was being probed for
    // when the path changed, the cluster asked for at 5.5 s and awaited until 6.5 s.
    let stale = before.last().expect("clusters before the change");
    assert_eq!(0.85 * 250_000.0, stale.1, "{told:?}: {before:?}");
    assert!(
        CHANGE_AT - stale.0 < Duration::from_secs(1),
        "{told:?}: the old path's cluster is outstanding at the change: {before:?}"
    );

    let rates: Vec<f64> = after.iter().map(|(_, rate)| *rate).collect();
    assert_eq!(
        vec![3.0 * START, 6.0 * START],
        rates,
        "{told:?}: the start-up clusters and nothing else: {after:?}"
    );
    assert!(
        after[0].0 - CHANGE_AT <= Duration::from_millis(100),
        "{told:?}: the first cluster comes with the new path's first packets: {after:?}"
    );
    let second = after[1].0 - after[0].0;
    assert!(
        second >= Duration::from_secs(1) && second <= Duration::from_millis(1_150),
        "{told:?}: the second when the first is given up: {after:?}"
    );
}

/// RFC 8836 section 2, requirements 1 and 4: the peer connection's word that it selected
/// another candidate pair starts probing over.
#[test]
fn the_peer_connections_path_change_starts_probing_over() {
    assert_probing_starts_over(Told::PeerConnection);
}

/// The same for a path change the application reports
/// ([`CongestionControlHandle::notify_path_change`]).
#[test]
fn the_applications_path_change_starts_probing_over() {
    assert_probing_starts_over(Told::Application);
}
