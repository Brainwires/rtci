//! When the congestion control feedback generators (transport-wide feedback, RFC 8888) build
//! a report: the drafts' cadence by default, libwebrtc's with the setting.
//!
//! draft-ietf-rmcat-gcc-02 section 3: "The RECOMMENDED feedback interval is once per received
//! video frame or at least once every 30 ms if audio-only or multi-stream. If the feedback
//! overhead needs to be limited this interval can be increased to 100 ms."
//! draft-holmer-rmcat-transport-wide-cc-extensions-01 section 3: "It is recommended that a
//! feedback message is sent for every frame received, but in cases of low uplink bandwidth it
//! is acceptable to send them less frequently".

use rtci_interceptor::{
    Attribute, AttributedPacket, CongestionFeedbackCadence, Interceptor, Packet, RTCPFeedback,
    RTPHeaderExtension, Registry, Rfc8888Builder, RtcpBandwidthShare, SendEstimate, Slot,
    StreamInfo, TaggedPacket, TwccReceiverBuilder,
};
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::Marshal;
use std::sync::Arc;
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const EXTENSION_ID: u8 = 5;
const AUDIO: u32 = 0x1000;
const VIDEO: u32 = 0x2000;

/// A remote stream that negotiated both feedback formats' prerequisites: the generator under
/// test picks its own.
fn stream(ssrc: u32, mime_type: &str, feedback: (&str, &str)) -> StreamInfo {
    StreamInfo {
        ssrc,
        clock_rate: 90_000,
        mime_type: mime_type.to_owned(),
        payload_type: 96,
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: u16::from(EXTENSION_ID),
        }],
        rtcp_feedback: vec![RTCPFeedback {
            typ: feedback.0.to_owned(),
            parameter: feedback.1.to_owned(),
        }],
        ..Default::default()
    }
}

const TWCC: (&str, &str) = ("transport-cc", "");
const CCFB: (&str, &str) = ("ack", "ccfb");

/// The media of a call for `seconds`: Opus every 20 ms when `audio`, and when `video` a
/// frame of three packets every `frame_interval`, the last with the marker.
struct Media {
    audio: bool,
    video: bool,
    frame_interval: Duration,
    seconds: u64,
}

struct Arrival {
    at: Duration,
    ssrc: u32,
    marker: bool,
}

impl Media {
    fn arrivals(&self) -> Vec<Arrival> {
        let end = Duration::from_secs(self.seconds);
        let mut arrivals = vec![];
        if self.audio {
            let mut at = Duration::from_millis(7);
            while at < end {
                arrivals.push(Arrival {
                    at,
                    ssrc: AUDIO,
                    marker: false,
                });
                at += Duration::from_millis(20);
            }
        }
        if self.video {
            let mut at = Duration::from_millis(11);
            while at < end {
                for part in 0..3u32 {
                    arrivals.push(Arrival {
                        at: at + Duration::from_millis(1) * part,
                        ssrc: VIDEO,
                        marker: part == 2,
                    });
                }
                at += self.frame_interval;
            }
        }
        arrivals.sort_by_key(|arrival| arrival.at);
        arrivals
    }
}

fn rtp(
    now: Instant,
    ssrc: u32,
    sequence_number: u16,
    transport: u16,
    marker: bool,
) -> TaggedPacket {
    let mut packet = rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            ssrc,
            sequence_number,
            payload_type: 96,
            marker,
            ..Default::default()
        },
        payload: vec![0u8; 100].into(),
    };
    let extension = rtp::extension::transport_cc_extension::TransportCcExtension {
        transport_sequence: transport,
    };
    packet
        .header
        .set_extension(EXTENSION_ID, extension.marshal().unwrap().freeze())
        .unwrap();
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(packet)),
    }
}

/// What the RTCP session (its share of the RTCP bandwidth) or the congestion controller (its
/// estimate) attaches to a packet on its way application-ward.
fn carrier<T: Send + Sync + 'static>(now: Instant, value: T) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![]))
            .with(Attribute::Custom(Arc::new(value))),
    }
}

/// Takes what the chain wrote: the instants of its feedback packets go to `times`.
fn collect(chain: &mut impl Interceptor, epoch: Instant, times: &mut Vec<Duration>) {
    while chain.poll_read().is_some() {}
    while let Some(packet) = chain.poll_write() {
        if let Packet::Rtcp(packets) = &packet.message.packet
            && !packets.is_empty()
        {
            times.push(packet.now.duration_since(epoch));
        }
    }
}

/// Every timer of the chain due by `until`, each at its deadline.
fn timers(chain: &mut impl Interceptor, epoch: Instant, until: Instant, times: &mut Vec<Duration>) {
    while let Some(deadline) = chain.poll_timeout()
        && deadline <= until
    {
        chain.handle_timeout(deadline).unwrap();
        collect(chain, epoch, times);
    }
}

/// Runs `media` through `chain` in virtual time, every timer of the chain taken when due,
/// and returns when each feedback packet was built (since the start).
fn feedback_times(chain: &mut impl Interceptor, epoch: Instant, media: &Media) -> Vec<Duration> {
    let mut times = vec![];
    let mut sequence_numbers = [0u16; 2];
    let mut transport = 0u16;
    for arrival in media.arrivals() {
        let now = epoch + arrival.at;
        timers(chain, epoch, now, &mut times);
        let index = usize::from(arrival.ssrc == VIDEO);
        chain
            .handle_read(rtp(
                now,
                arrival.ssrc,
                sequence_numbers[index],
                transport,
                arrival.marker,
            ))
            .unwrap();
        sequence_numbers[index] = sequence_numbers[index].wrapping_add(1);
        transport = transport.wrapping_add(1);
        collect(chain, epoch, &mut times);
    }
    let end = epoch + Duration::from_secs(media.seconds);
    timers(chain, epoch, end, &mut times);
    times
}

fn twcc(builder: TwccReceiverBuilder) -> impl Interceptor {
    Registry::new()
        .with(Slot::TwccReceiver, builder.build())
        .build()
}

fn rfc8888(builder: Rfc8888Builder) -> impl Interceptor {
    Registry::new().with(Slot::Rfc8888, builder.build()).build()
}

fn gaps(times: &[Duration]) -> Vec<Duration> {
    times.windows(2).map(|pair| pair[1] - pair[0]).collect()
}

const VIDEO_ALONE: Media = Media {
    audio: false,
    video: true,
    frame_interval: Duration::from_millis(40),
    seconds: 2,
};

const AUDIO_AND_VIDEO: Media = Media {
    audio: true,
    video: true,
    frame_interval: Duration::from_millis(40),
    seconds: 2,
};

const AUDIO_ALONE: Media = Media {
    audio: true,
    video: false,
    frame_interval: Duration::from_millis(40),
    seconds: 2,
};

/// "once per received video frame": a session's one video stream at 25 frames a second gets
/// a transport-wide feedback packet as each frame ends, 25 a second, each at the instant the
/// frame's last packet arrived (11 ms + 2 ms into every 40).
#[test]
fn transport_wide_feedback_of_one_video_stream_is_sent_for_every_frame_received() {
    let mut chain = twcc(TwccReceiverBuilder::new());
    chain.bind_remote_stream(&stream(VIDEO, "video/VP8", TWCC));
    let times = feedback_times(&mut chain, Instant::now(), &VIDEO_ALONE);
    assert_eq!(50, times.len(), "{times:?}");
    for (frame, at) in times.iter().enumerate() {
        assert_eq!(
            Duration::from_millis(13 + 40 * frame as u64),
            *at,
            "frame {frame}"
        );
    }
}

/// The same from the RFC 8888 generator (RFC 8888 section 4: "sending feedback once per
/// frame is an upper bound before the reporting overhead becomes excessive").
#[test]
fn rfc_8888_feedback_of_one_video_stream_is_sent_for_every_frame_received() {
    let mut chain = rfc8888(Rfc8888Builder::new());
    chain.bind_remote_stream(&stream(VIDEO, "video/VP8", CCFB));
    let times = feedback_times(&mut chain, Instant::now(), &VIDEO_ALONE);
    assert_eq!(50, times.len(), "{times:?}");
    assert!(
        gaps(&times)
            .iter()
            .all(|gap| *gap == Duration::from_millis(40)),
        "{times:?}"
    );
}

/// "or at least once every 30 ms if audio-only or multi-stream": audio beside video, and
/// audio alone, are reported every 30 ms, whatever the frames do.
#[test]
fn audio_only_and_multi_stream_sessions_are_reported_every_30_ms() {
    for (media, name) in [
        (&AUDIO_AND_VIDEO, "audio and video"),
        (&AUDIO_ALONE, "audio"),
    ] {
        let mut chain = twcc(TwccReceiverBuilder::new());
        chain.bind_remote_stream(&stream(AUDIO, "audio/opus", TWCC));
        if media.video {
            chain.bind_remote_stream(&stream(VIDEO, "video/VP8", TWCC));
        }
        let times = feedback_times(&mut chain, Instant::now(), media);
        assert!((65..=67).contains(&times.len()), "{name}: {}", times.len());
        assert!(
            gaps(&times)
                .iter()
                .all(|gap| *gap == Duration::from_millis(30)),
            "{name}: {times:?}"
        );

        let mut chain = rfc8888(Rfc8888Builder::new());
        chain.bind_remote_stream(&stream(AUDIO, "audio/opus", CCFB));
        if media.video {
            chain.bind_remote_stream(&stream(VIDEO, "video/VP8", CCFB));
        }
        let times = feedback_times(&mut chain, Instant::now(), media);
        assert!(
            (65..=67).contains(&times.len()),
            "RFC 8888, {name}: {}",
            times.len()
        );
    }
}

/// "If the feedback overhead needs to be limited this interval can be increased to 100 ms":
/// the RTCP session says what the RTCP bandwidth gives this endpoint; where that does not
/// hold a feedback packet every 30 ms the interval is the time in which it holds one, and
/// never more than 100 ms.
#[test]
fn the_interval_is_increased_to_100_ms_where_the_rtcp_bandwidth_does_not_hold_more() {
    let epoch = Instant::now();
    // 3.8 kbit/s, an audio call's share: a feedback packet of about 100 octets fits every
    // 200 ms. The draft's ceiling holds: ten a second.
    let mut chain = twcc(TwccReceiverBuilder::new());
    chain.bind_remote_stream(&stream(AUDIO, "audio/opus", TWCC));
    chain
        .handle_read(carrier(
            epoch,
            RtcpBandwidthShare {
                bits_per_second: 3_800.0,
            },
        ))
        .unwrap();
    let times = feedback_times(&mut chain, epoch, &AUDIO_ALONE);
    assert!((19..=20).contains(&times.len()), "{}", times.len());
    assert!(
        gaps(&times)
            .iter()
            .skip(1)
            .all(|gap| *gap == Duration::from_millis(100)),
        "{times:?}"
    );

    // One video stream at 25 frames a second with the same share: every third frame at
    // most (a frame ends every 40 ms, the interval is 100 ms).
    let mut chain = twcc(TwccReceiverBuilder::new());
    chain.bind_remote_stream(&stream(VIDEO, "video/VP8", TWCC));
    chain
        .handle_read(carrier(
            epoch,
            RtcpBandwidthShare {
                bits_per_second: 3_800.0,
            },
        ))
        .unwrap();
    let times = feedback_times(&mut chain, epoch, &VIDEO_ALONE);
    assert!((16..=20).contains(&times.len()), "{}", times.len());
    assert!(
        gaps(&times)
            .iter()
            .skip(1)
            .all(|gap| *gap >= Duration::from_millis(100) && *gap <= Duration::from_millis(120)),
        "{times:?}"
    );
}

/// libwebrtc's cadence, the `Chrome` behaviour profile's
/// (`transport_sequence_number_feedback_generator.cc`): every 100 ms until the congestion
/// controller's estimate is known, then the time in which 5% of it holds 68 octets, between
/// 50 and 250 ms. A frame's end brings nothing.
#[test]
fn the_send_estimate_cadence_is_sized_to_five_percent_of_the_endpoints_own_estimate() {
    let builder =
        || TwccReceiverBuilder::new().with_cadence(CongestionFeedbackCadence::SendEstimate);
    let epoch = Instant::now();

    let mut chain = twcc(builder());
    chain.bind_remote_stream(&stream(VIDEO, "video/VP8", TWCC));
    let times = feedback_times(&mut chain, epoch, &VIDEO_ALONE);
    assert!(
        (19..=20).contains(&times.len()),
        "no estimate: {}",
        times.len()
    );

    for (estimate, interval_ms) in [(1_000_000.0, 50.0), (100_000.0, 108.8), (20_000.0, 250.0)] {
        let mut chain = twcc(builder());
        chain.bind_remote_stream(&stream(VIDEO, "video/VP8", TWCC));
        chain
            .handle_read(carrier(
                epoch,
                SendEstimate {
                    bits_per_second: estimate,
                },
            ))
            .unwrap();
        let times = feedback_times(&mut chain, epoch, &VIDEO_ALONE);
        let expected = 2_000.0 / interval_ms;
        assert!(
            (times.len() as f64 - expected).abs() <= 1.5,
            "{estimate}: {} against {expected}",
            times.len()
        );
    }
}

/// A fixed interval stays fixed whatever arrives.
#[test]
fn a_fixed_interval_ignores_frames_and_shares() {
    let mut chain = twcc(
        TwccReceiverBuilder::new()
            .with_adaptive_interval(false)
            .with_interval(Duration::from_millis(100)),
    );
    chain.bind_remote_stream(&stream(VIDEO, "video/VP8", TWCC));
    let times = feedback_times(&mut chain, Instant::now(), &VIDEO_ALONE);
    assert!((19..=20).contains(&times.len()), "{}", times.len());
}
