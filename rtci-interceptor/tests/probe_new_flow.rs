//! A media flow that starts after the call's start-up probing is over is probed for.
//!
//! RFC 8836 section 2, requirement 4: the algorithm "SHOULD adapt as quickly as possible to
//! initial network conditions at the start of a flow". A call that starts with audio alone
//! spends its start-up clusters on the audio: the pacer marks the audio packets it releases,
//! which leave at the audio's rate and show nothing of the path. When the video is added
//! mid-call (a renegotiation), nothing else asks for a cluster: a sender that follows its
//! target is not application limited. The video then climbed at the controller's 8 % a second
//! in every chain, the paced one too (`tests/probe_start_order_rtc2rtc.rs`, 461 kbit/s six
//! seconds after the video started).
//!
//! Now the first packet of a media stream that starts after the start-up sequence is over
//! owes the sequence again, at three and six times the target then.
//!
//! The controller is driven alone (with the TWCC sender that numbers its packets): the test
//! marks the packets of each cluster asked for as a pacer would (the next five audio packets),
//! and gives no feedback, so each cluster's result is given up after a second, as a cluster of
//! audio packets has no result that lifts the estimate either.

use bytes::Bytes;
use rtci_interceptor::{
    Attribute, AttributedPacket, BandwidthEstimator, CongestionControlBuilder, Interceptor, Packet,
    PacketReport, ProbePacket, ProbeRequest, RTCPFeedback, RTPHeaderExtension, Registry, Slot,
    StreamInfo, TaggedPacket, TwccSenderBuilder,
};
use shared::TransportContext;
use std::sync::Arc;
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const TWCC_ID: u8 = 5;
const VIDEO_SSRC: u32 = 0x00A0_0001;
const VIDEO_RTX_SSRC: u32 = 0x00A0_0002;
const AUDIO_SSRC: u32 = 0x00B0_0001;
const TARGET: f64 = 300_000.0;

/// An estimator whose target is fixed and that takes no probe result.
struct Fixed;

impl BandwidthEstimator for Fixed {
    fn on_reports(&mut self, _now: Instant, _reports: &[PacketReport]) {}

    fn target_bitrate(&self) -> f64 {
        TARGET
    }
}

fn stream(ssrc: u32, ssrc_rtx: Option<u32>, payload_type: u8, mime_type: &str) -> StreamInfo {
    StreamInfo {
        ssrc,
        ssrc_rtx,
        payload_type,
        payload_type_rtx: ssrc_rtx.map(|_| 97),
        clock_rate: if payload_type == 111 { 48_000 } else { 90_000 },
        mime_type: mime_type.to_owned(),
        rtcp_feedback: vec![RTCPFeedback {
            typ: "transport-cc".to_owned(),
            parameter: String::new(),
        }],
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: u16::from(TWCC_ID),
        }],
        ..Default::default()
    }
}

struct Sender<I> {
    chain: I,
    sequence_number: u16,
    /// Every cluster asked for: when (from the start) and at what rate.
    requests: Vec<(Duration, f64)>,
    /// The cluster being "paced" and how many of its packets are still to be marked.
    marking: Option<(u32, usize)>,
}

impl<I: Interceptor> Sender<I> {
    fn write(&mut self, now: Instant, ssrc: u32) {
        self.sequence_number = self.sequence_number.wrapping_add(1);
        let mut message = AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: if ssrc == VIDEO_SSRC { 96 } else { 111 },
                sequence_number: self.sequence_number,
                timestamp: u32::from(self.sequence_number) * 960,
                ssrc,
                ..Default::default()
            },
            payload: Bytes::from(vec![0u8; 1000]),
        }));
        if let Some((cluster, left)) = self.marking.as_mut() {
            message.add(Attribute::Custom(Arc::new(ProbePacket {
                cluster: *cluster,
            })));
            *left -= 1;
            if *left == 0 {
                self.marking = None;
            }
        }
        self.chain
            .handle_write(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message,
            })
            .unwrap();
        while self.chain.poll_write().is_some() {}
    }

    fn read(&mut self, epoch: Instant, now: Instant) {
        while let Some(read) = self.chain.poll_read() {
            if let Some(request) = read.message.custom::<ProbeRequest>() {
                self.requests
                    .push((now.duration_since(epoch), request.bits_per_second));
                self.marking = Some((request.cluster, 5));
            }
        }
    }

    /// Audio every 20 ms from `from` to `to` milliseconds, and the video's first packet at
    /// `video_at` when given.
    fn run(&mut self, epoch: Instant, (from, to): (u64, u64), video_at: Option<u64>) {
        for millisecond in from..to {
            let now = epoch + Duration::from_millis(millisecond);
            if millisecond.is_multiple_of(20) {
                self.write(now, AUDIO_SSRC);
            }
            if video_at == Some(millisecond) {
                self.write(now, VIDEO_SSRC);
            }
            self.chain.handle_timeout(now).unwrap();
            self.read(epoch, now);
        }
    }
}

/// Three seconds of audio alone: the two start-up clusters are asked for and their results
/// given up, and nothing more is asked for. Then a video stream is bound and sends its first
/// packet: the start-up sequence is asked for again from it, at three times the target.
#[test]
fn a_video_stream_added_mid_call_is_probed_for_with_its_first_packet() {
    let epoch = Instant::now();
    let (controller, _handle) = CongestionControlBuilder::new(Fixed)
        .with_bandwidth_probing(true)
        .build_with_handle();
    let mut chain = Registry::new()
        .with(Slot::CongestionControl, controller)
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .build();
    chain.bind_local_stream(&stream(AUDIO_SSRC, None, 111, "audio/opus"));
    let mut sender = Sender {
        chain,
        sequence_number: 0,
        requests: Vec::new(),
        marking: None,
    };

    sender.run(epoch, (0, 3_000), None);
    assert_eq!(
        vec![
            (Duration::ZERO, 3.0 * TARGET),
            (Duration::from_millis(1_000), 6.0 * TARGET)
        ],
        sender.requests,
        "the start-up sequence, spent on the audio"
    );

    sender
        .chain
        .bind_local_stream(&stream(VIDEO_SSRC, Some(VIDEO_RTX_SSRC), 96, "video/VP8"));
    sender.run(epoch, (3_000, 3_100), Some(3_010));
    assert_eq!(
        Some(&(Duration::from_millis(3_010), 3.0 * TARGET)),
        sender.requests.get(2),
        "the start-up sequence again, with the video's first packet: {:?}",
        sender.requests
    );
}

/// Audio and video whose first packets leave 10 ms apart: the video's first packet comes
/// while the start-up sequence is under way, and changes nothing.
#[test]
fn a_flow_that_starts_during_the_start_up_changes_nothing() {
    let epoch = Instant::now();
    let (controller, _handle) = CongestionControlBuilder::new(Fixed)
        .with_bandwidth_probing(true)
        .build_with_handle();
    let mut chain = Registry::new()
        .with(Slot::CongestionControl, controller)
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .build();
    chain.bind_local_stream(&stream(AUDIO_SSRC, None, 111, "audio/opus"));
    chain.bind_local_stream(&stream(VIDEO_SSRC, Some(VIDEO_RTX_SSRC), 96, "video/VP8"));
    let mut sender = Sender {
        chain,
        sequence_number: 0,
        requests: Vec::new(),
        marking: None,
    };
    sender.run(epoch, (0, 3_000), Some(10));
    assert_eq!(
        vec![
            (Duration::ZERO, 3.0 * TARGET),
            (Duration::from_millis(1_000), 6.0 * TARGET)
        ],
        sender.requests
    );
}
