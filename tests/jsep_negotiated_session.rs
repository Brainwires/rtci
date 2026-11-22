//! What an applied answer negotiated reaches the interceptors that act on it: reduced-size
//! RTCP (`a=rtcp-rsize`, RFC 5506), the bandwidth of the `b=` lines (RFC 9429 section 5.10,
//! RFC 3556), `trr-int` (RFC 4585 section 4.2) and `rtx-time` (RFC 4588 section 8.1).
//!
//! The peer connection writes each as a control message into its interceptor chain. A probe
//! at the application end of the chain records what is written, before the RTCP session, the
//! bitrate limit and the NACK interceptors take it; what those do with it is tested where they
//! live (`rtc-interceptor/tests/rtcp_session_*.rs`, `nack_control_rtx_time.rs`,
//! `configuration/remote_bitrate_limit.rs`).

mod jsep_common;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jsep_common::{TestResult, media_sections, video_track};
use rtc::interceptor::{
    Gcc, Interceptor, NackControl, Registry, RtcpBandwidth, RtcpSessionControl, Slot, StreamInfo,
    TaggedPacket,
};
use rtc::peer_connection::configuration::interceptor_registry::{
    CongestionFeedback, configure_congestion_control, register_default_interceptors,
};
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::remote_bitrate_limit::RemoteBitrateLimit;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind,
};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;

#[derive(Debug, Clone, PartialEq)]
enum Control {
    Session(RtcpSessionControl),
    BitrateLimit(Option<f64>),
    Nack(NackControl),
}

type Seen = Arc<Mutex<Vec<Control>>>;

/// Records the control messages written into the chain and hands every packet on.
struct Probe {
    seen: Seen,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for Probe {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<TaggedPacket> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Error> {
        let mut seen = self.seen.lock().expect("probe");
        if let Some(control) = msg.message.custom::<RtcpSessionControl>() {
            seen.push(Control::Session(control.clone()));
        }
        if let Some(RemoteBitrateLimit(limit)) = msg.message.custom::<RemoteBitrateLimit>() {
            seen.push(Control::BitrateLimit(*limit));
        }
        if let Some(control) = msg.message.custom::<NackControl>() {
            seen.push(Control::Nack(*control));
        }
        drop(seen);
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        self.write_queue.pop_front()
    }
}

impl Interceptor for Probe {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

fn codec(mime_type: &str, clock_rate: u32, channels: u16, fmtp: &str) -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: mime_type.to_owned(),
        clock_rate,
        channels,
        sdp_fmtp_line: fmtp.to_owned(),
        rtcp_feedback: vec![],
    }
}

/// A peer with Opus (111), VP8 (96) and RTX (97, with `rtx_fmtp`), the default interceptors,
/// congestion control, and the probe. `trr_int`: the `trr-int` it announces for video.
fn peer(
    rtx_fmtp: &str,
    trr_int: Option<u32>,
) -> Result<(RTCPeerConnection, Seen), Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: codec(MIME_TYPE_OPUS, 48000, 2, ""),
            payload_type: 111,
        },
        RtpCodecKind::Audio,
    )?;
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: codec(MIME_TYPE_VP8, 90000, 0, ""),
            payload_type: 96,
        },
        RtpCodecKind::Video,
    )?;
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: codec(MIME_TYPE_RTX, 90000, 0, rtx_fmtp),
            payload_type: 97,
        },
        RtpCodecKind::Video,
    )?;
    if let Some(trr_int) = trr_int {
        media_engine.register_feedback(
            RTCPFeedback {
                typ: "trr-int".to_owned(),
                parameter: trr_int.to_string(),
            },
            RtpCodecKind::Video,
        );
    }
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    let registry = configure_congestion_control(
        registry,
        Gcc::default(),
        CongestionFeedback::Twcc,
        &mut media_engine,
    )?;
    let seen: Seen = Seen::default();
    let registry = registry.with(
        Slot::Custom(20_000),
        Probe {
            seen: seen.clone(),
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        },
    );
    let pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(Instant::now())?;
    Ok((pc, seen))
}

fn take(seen: &Seen) -> Vec<Control> {
    std::mem::take(&mut *seen.lock().expect("probe"))
}

fn reduced_size(controls: &[Control]) -> Vec<bool> {
    controls
        .iter()
        .filter_map(|control| match control {
            Control::Session(RtcpSessionControl::ReducedSize(on)) => Some(*on),
            _ => None,
        })
        .collect()
}

fn bandwidth(controls: &[Control]) -> Vec<RtcpBandwidth> {
    controls
        .iter()
        .filter_map(|control| match control {
            Control::Session(RtcpSessionControl::Bandwidth(bandwidth)) => Some(*bandwidth),
            _ => None,
        })
        .collect()
}

fn bitrate_limit(controls: &[Control]) -> Vec<Option<f64>> {
    controls
        .iter()
        .filter_map(|control| match control {
            Control::BitrateLimit(limit) => Some(*limit),
            _ => None,
        })
        .collect()
}

/// `answer` with `lines` (one set per media section, each line ending in CRLF) put after the
/// section's `c=` line, where `b=` lines go (RFC 8866 section 5).
fn with_section_lines(answer: &str, lines: &[&str]) -> String {
    let mut out = String::new();
    let mut section = None::<usize>;
    for line in answer.split_inclusive("\r\n") {
        if line.starts_with("m=") {
            section = Some(section.map_or(0, |i| i + 1));
        }
        out.push_str(line);
        if line.starts_with("c=")
            && let Some(i) = section
        {
            out.push_str(lines[i]);
        }
    }
    out
}

/// An offer of `a` (audio it only receives, then video it sends) answered by `b`; the answer
/// reaches `a` as `edit` leaves it. Returns what each side's chain was told.
fn negotiate(
    a: &mut RTCPeerConnection,
    b: &mut RTCPeerConnection,
    edit: impl Fn(&str) -> String,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let now = Instant::now();
    let offer = a.create_offer(None)?;
    a.set_local_description(now, offer.clone())?;
    b.set_remote_description(now, offer.clone())?;
    let answer = b.create_answer(None)?;
    b.set_local_description(now, answer.clone())?;
    let edited = edit(&answer.sdp);
    a.set_remote_description(now, RTCSessionDescription::answer(edited.clone())?)?;
    Ok((offer.sdp, edited))
}

fn add_media(pc: &mut RTCPeerConnection) -> TestResult {
    pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(rtc::rtp_transceiver::RTCRtpTransceiverInit {
            direction: rtc::rtp_transceiver::RTCRtpTransceiverDirection::Recvonly,
            streams: vec![],
            send_encodings: vec![],
        }),
    )?;
    pc.add_track(video_track("camera", 0x0a0a_0a0a))?;
    Ok(())
}

#[test]
fn the_rtcp_session_is_told_whether_reduced_size_rtcp_was_negotiated() -> TestResult {
    let (mut a, seen_a) = peer("apt=96", None)?;
    let (mut b, seen_b) = peer("apt=96", None)?;
    add_media(&mut a)?;
    // Nothing is said before an answer is applied.
    let offer = a.create_offer(None)?;
    a.set_local_description(Instant::now(), offer)?;
    assert!(take(&seen_a).is_empty());
    a.set_local_description(Instant::now(), RTCSessionDescription::rollback(None)?)?;

    negotiate(&mut a, &mut b, str::to_owned)?;
    assert_eq!(reduced_size(&take(&seen_a)), vec![true], "the offerer");
    assert_eq!(reduced_size(&take(&seen_b)), vec![true], "the answerer");

    // The next answer leaves `a=rtcp-rsize` out (RFC 9429 section 5.11: "reduced-size RTCP
    // MUST NOT be used"): the session goes back to compound packets.
    negotiate(&mut a, &mut b, |answer| {
        answer.replace("a=rtcp-rsize\r\n", "")
    })?;
    assert_eq!(reduced_size(&take(&seen_a)), vec![false]);
    Ok(())
}

#[test]
fn the_b_lines_of_the_remote_description_bound_rtcp_and_the_send_rate() -> TestResult {
    let (mut a, seen_a) = peer("apt=96", None)?;
    let (mut b, _) = peer("apt=96", None)?;
    add_media(&mut a)?;

    // Every section has the lines: the session's figures are their sums (RFC 8859: SUM).
    // The send limit is that of the sections this endpoint sends in: the video one.
    negotiate(&mut a, &mut b, |answer| {
        with_section_lines(
            answer,
            &[
                "b=AS:64\r\nb=RS:800\r\nb=RR:1600\r\n",
                "b=AS:9000\r\nb=TIAS:500000\r\nb=RS:3200\r\nb=RR:6400\r\n",
            ],
        )
    })?;
    let controls = take(&seen_a);
    assert_eq!(
        bandwidth(&controls),
        vec![RtcpBandwidth {
            session: Some(64_000 + 500_000),
            rs: Some(800 + 3200),
            rr: Some(1600 + 6400),
        }]
    );
    assert_eq!(bitrate_limit(&controls), vec![Some(500_000.0)]);

    // A section without a line leaves the sum unknown: the session measures the media
    // instead. The section this endpoint sends in still has its limit.
    negotiate(&mut a, &mut b, |answer| {
        with_section_lines(answer, &["", "b=AS:300\r\nb=RR:0\r\n"])
    })?;
    let controls = take(&seen_a);
    assert_eq!(bandwidth(&controls), vec![RtcpBandwidth::default()]);
    // RFC 9429 section 5.10: "TIAS = AS * 1000 * 0.95 - (50 * 40 * 8)".
    assert_eq!(bitrate_limit(&controls), vec![Some(269_000.0)]);

    // No lines: no figures and no limit, which also lifts the earlier one.
    negotiate(&mut a, &mut b, str::to_owned)?;
    let controls = take(&seen_a);
    assert_eq!(bandwidth(&controls), vec![RtcpBandwidth::default()]);
    assert_eq!(bitrate_limit(&controls), vec![None]);
    Ok(())
}

#[test]
fn the_rtcp_session_is_told_the_trr_int_this_endpoint_announced() -> TestResult {
    let (mut a, seen_a) = peer("apt=96", Some(250))?;
    let (mut b, seen_b) = peer("apt=96", Some(1500))?;
    add_media(&mut a)?;
    let (offer, answer) = negotiate(&mut a, &mut b, str::to_owned)?;
    assert!(offer.contains("a=rtcp-fb:96 trr-int 250\r\n"), "{offer}");
    // The answer states the answerer's own interval, not the offered number.
    assert!(answer.contains("a=rtcp-fb:96 trr-int 1500\r\n"), "{answer}");
    let trr_int = |controls: &[Control]| -> Vec<Duration> {
        controls
            .iter()
            .filter_map(|control| match control {
                Control::Session(RtcpSessionControl::TrrInt(interval)) => Some(*interval),
                _ => None,
            })
            .collect()
    };
    // Each side's interval is the one in its own description (RFC 4585 section 4.2).
    assert_eq!(trr_int(&take(&seen_a)), vec![Duration::from_millis(250)]);
    assert_eq!(trr_int(&take(&seen_b)), vec![Duration::from_millis(1500)]);

    // Without the parameter nothing is said: the session keeps its configured interval.
    let (mut a, seen_a) = peer("apt=96", None)?;
    let (mut b, _) = peer("apt=96", None)?;
    add_media(&mut a)?;
    negotiate(&mut a, &mut b, str::to_owned)?;
    assert!(trr_int(&take(&seen_a)).is_empty());
    Ok(())
}

#[test]
fn the_nack_interceptors_are_told_the_rtx_time_of_each_description() -> TestResult {
    let (mut a, seen_a) = peer("apt=96;rtx-time=3000", None)?;
    let (mut b, seen_b) = peer("apt=96;rtx-time=1500", None)?;
    add_media(&mut a)?;
    let (offer, answer) = negotiate(&mut a, &mut b, str::to_owned)?;
    assert!(
        offer.contains("a=fmtp:97 apt=96;rtx-time=3000\r\n"),
        "{offer}"
    );

    // What each description says of payload type 97.
    let rtx_time = |sdp: &str| -> Option<Duration> {
        media_sections(sdp)
            .iter()
            .flatten()
            .find_map(|l| l.strip_prefix("a=fmtp:97 "))
            .and_then(|fmtp| {
                fmtp.split(';')
                    .find_map(|parameter| parameter.trim().strip_prefix("rtx-time="))
            })
            .map(|ms| Duration::from_millis(ms.parse().expect("milliseconds")))
    };
    assert_eq!(rtx_time(&offer), Some(Duration::from_millis(3000)));
    let nack = |controls: &[Control]| -> Vec<NackControl> {
        controls
            .iter()
            .filter_map(|control| match control {
                Control::Nack(control) => Some(*control),
                _ => None,
            })
            .collect()
    };

    // The offerer sent the offer and received the answer.
    assert_eq!(
        nack(&take(&seen_a)),
        vec![
            NackControl::LocalRtxTime {
                payload_type_rtx: 97,
                rtx_time: rtx_time(&offer),
            },
            NackControl::RemoteRtxTime {
                payload_type_rtx: 97,
                rtx_time: rtx_time(&answer),
            },
        ]
    );
    assert_eq!(
        nack(&take(&seen_b)),
        vec![
            NackControl::LocalRtxTime {
                payload_type_rtx: 97,
                rtx_time: rtx_time(&answer),
            },
            NackControl::RemoteRtxTime {
                payload_type_rtx: 97,
                rtx_time: rtx_time(&offer),
            },
        ]
    );

    // A retransmission format without the parameter says so too (`None`), which withdraws
    // what an earlier description announced.
    let (mut a, seen_a) = peer("apt=96", None)?;
    let (mut b, _) = peer("apt=96", None)?;
    add_media(&mut a)?;
    negotiate(&mut a, &mut b, str::to_owned)?;
    assert_eq!(
        nack(&take(&seen_a)),
        vec![
            NackControl::LocalRtxTime {
                payload_type_rtx: 97,
                rtx_time: None,
            },
            NackControl::RemoteRtxTime {
                payload_type_rtx: 97,
                rtx_time: None,
            },
        ]
    );
    Ok(())
}

/// RFC 9143 section 15: the RTCP MID SDES item "SHOULD be sent in the first few RTCP packets
/// after joining the session and SHOULD be sent regularly thereafter"; RFC 8852 sections 3.1
/// and 3.2 for the rids. Each SSRC the sender sends on (its RTX one included) is handed to the
/// RTCP session with the mid of its m= section; what the session writes is tested in
/// `rtc-interceptor/tests/rtcp_session_reports.rs`.
#[test]
fn the_rtcp_session_is_told_the_mid_of_each_sent_stream() -> TestResult {
    let (mut a, seen_a) = peer("apt=96", None)?;
    let (mut b, _) = peer("apt=96", None)?;
    add_media(&mut a)?;
    let (offer, _) = negotiate(&mut a, &mut b, str::to_owned)?;
    let video = media_sections(&offer)
        .into_iter()
        .find(|section| section[0].starts_with("m=video"))
        .expect("a video section");
    let mid = video
        .iter()
        .find_map(|line| line.strip_prefix("a=mid:"))
        .expect("a mid")
        .to_owned();
    let rtx_ssrc: u32 = video
        .iter()
        .find_map(|line| line.strip_prefix("a=ssrc-group:FID "))
        .and_then(|group| group.split_whitespace().nth(1))
        .expect("an RTX SSRC")
        .parse()?;

    let mut identified: Vec<(u32, Option<String>, Option<String>, Option<String>)> = take(&seen_a)
        .into_iter()
        .filter_map(|control| match control {
            Control::Session(RtcpSessionControl::StreamIdentifiers {
                ssrc,
                mid,
                rid,
                repaired_rid,
            }) => Some((ssrc, mid, rid, repaired_rid)),
            _ => None,
        })
        .collect();
    identified.sort();
    let mut expected = vec![
        (0x0a0a_0a0a, Some(mid.clone()), None, None),
        (rtx_ssrc, Some(mid), None, None),
    ];
    expected.sort();
    assert_eq!(identified, expected);
    Ok(())
}
