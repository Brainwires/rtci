//! What the application supplies through the `update_*_stats` methods, and only that, reaches
//! the report.

use crate::media_stream::MediaStreamTrack;
use crate::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use crate::peer_connection::util_test::{Pair, new_pair_with, send_until_seen, signal_pair};
use crate::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use crate::statistics::StatsSelector;
use crate::statistics::accumulator::RTCStatsAccumulator;
use crate::statistics::report::RTCStatsReportEntry;
use crate::statistics::{
    AudioPlayoutStatsUpdate, AudioReceiverStatsUpdate, AudioSourceStatsUpdate, DecoderStatsUpdate,
    EncoderStatsUpdate, VideoSourceStatsUpdate,
};
use std::time::Instant;

fn vp8() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: String::new(),
        rtcp_feedback: vec![],
    }
}

fn vp8_only() -> MediaEngine {
    let mut media_engine = MediaEngine::default();
    media_engine
        .register_codec(
            RTCRtpCodecParameters {
                rtp_codec: vp8(),
                payload_type: 96,
            },
            RtpCodecKind::Video,
        )
        .expect("vp8");
    media_engine
}

/// An update merges: a field it leaves `None` keeps what an earlier update supplied.
#[test]
fn an_update_merges_into_what_was_supplied_before() {
    let now = Instant::now();
    let mut stats = RTCStatsAccumulator::new();
    stats.get_or_create_inbound_rtp_streams(9, RtpCodecKind::Video, "t", "0", None, None, 0);

    assert!(stats.update_decoder_stats(
        9,
        DecoderStatsUpdate {
            frames_received: Some(10),
            frames_decoded: Some(9),
            ..Default::default()
        },
    ));
    assert!(stats.update_decoder_stats(
        9,
        DecoderStatsUpdate {
            frames_decoded: Some(10),
            frame_width: Some(640),
            ..Default::default()
        },
    ));
    let inbound = stats.inbound_rtp_streams[&9].snapshot(now, "x");
    assert_eq!(inbound.frames_received, Some(10));
    assert_eq!(inbound.frames_decoded, Some(10));
    assert_eq!(inbound.frame_width, Some(640));
    assert_eq!(inbound.frame_height, None);

    // No stream with that SSRC: nothing to update, and nothing is created.
    assert!(!stats.update_decoder_stats(10, DecoderStatsUpdate::default()));
    assert!(!stats.update_encoder_stats(10, EncoderStatsUpdate::default()));
    assert_eq!(stats.inbound_rtp_streams.len(), 1);
}

/// A video pipeline hands its jitter buffer members over with the decoder update (a video
/// stream has no audio update); they reach the report, and win over an audio update's values.
#[test]
fn the_decoder_update_carries_the_jitter_buffer_members_of_a_video_stream() {
    let now = Instant::now();
    let mut stats = RTCStatsAccumulator::new();
    stats.get_or_create_inbound_rtp_streams(9, RtpCodecKind::Video, "t", "0", None, None, 0);

    assert!(stats.update_decoder_stats(
        9,
        DecoderStatsUpdate {
            jitter_buffer_delay: Some(1.5),
            jitter_buffer_target_delay: Some(2.0),
            jitter_buffer_minimum_delay: Some(0.5),
            jitter_buffer_emitted_count: Some(30),
            ..Default::default()
        },
    ));
    let inbound = stats.inbound_rtp_streams[&9].snapshot(now, "x");
    assert_eq!(inbound.jitter_buffer_delay, Some(1.5));
    assert_eq!(inbound.jitter_buffer_target_delay, Some(2.0));
    assert_eq!(inbound.jitter_buffer_minimum_delay, Some(0.5));
    assert_eq!(inbound.jitter_buffer_emitted_count, Some(30));

    // A later decoder update that leaves them out keeps them; an audio update does not
    // override what the decoder update supplied.
    assert!(stats.update_decoder_stats(
        9,
        DecoderStatsUpdate {
            frames_decoded: Some(30),
            ..Default::default()
        },
    ));
    assert!(stats.update_audio_receiver_stats(
        9,
        AudioReceiverStatsUpdate {
            jitter_buffer_delay: Some(9.0),
            ..Default::default()
        },
    ));
    let inbound = stats.inbound_rtp_streams[&9].snapshot(now, "x");
    assert_eq!(inbound.jitter_buffer_delay, Some(1.5));
    assert_eq!(inbound.jitter_buffer_emitted_count, Some(30));
}

/// Through a real call: the sender's encoder and capture stats, and the receiver's decoder and
/// playout stats, appear where webrtc-stats puts them, and every reference they add resolves.
#[test]
fn supplied_stats_reach_the_report_and_their_references_resolve() {
    let (mut sender, mut receiver) = new_pair_with(vp8_only(), vp8_only()).expect("pair");
    let ssrc = 0x7777_0001;
    let sender_id = sender
        .add_track(MediaStreamTrack::new(
            "feed-stream".to_owned(),
            "feed-video".to_owned(),
            "feed-video".to_owned(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    ssrc: Some(ssrc),
                    ..Default::default()
                },
                codec: vp8(),
                ..Default::default()
            }],
        ))
        .expect("add_track");
    signal_pair(&mut sender, &mut receiver).expect("signal");
    let mut pair = Pair::new(sender, receiver);
    pair.connect().expect("connect");
    let mut sequence_number = 0;
    send_until_seen(&mut pair, sender_id, ssrc, 96, 0xAA, &mut sequence_number);
    let now = pair.now;

    // Before anything is supplied, nothing the engine cannot measure is claimed.
    let report = pair.offerer.get_stats(now, StatsSelector::None);
    let outbound = report.outbound_rtp_streams().next().expect("outbound");
    assert_eq!(outbound.frames_encoded, None);
    // The track is attached to the sender, so its media source exists (webrtc-stats 8.11),
    // with what the engine knows of it: the track's id and kind.
    let source = report
        .iter()
        .find_map(|entry| match entry {
            RTCStatsReportEntry::VideoSource(source) => Some(source),
            _ => None,
        })
        .expect("the media source of the attached track");
    assert_eq!(outbound.media_source_id, source.media_source_stats.stats.id);
    assert_eq!(source.media_source_stats.track_identifier, "feed-video");
    assert_eq!((source.width, source.frames), (None, None));

    // Sender side.
    assert!(pair.offerer.update_encoder_stats(
        ssrc,
        EncoderStatsUpdate {
            frames_encoded: Some(30),
            frame_width: Some(1280),
            frame_height: Some(720),
            encoder_implementation: Some("app-vp8".to_owned()),
            ..Default::default()
        },
    ));
    assert!(pair.offerer.update_video_source_stats(
        sender_id,
        VideoSourceStatsUpdate {
            width: Some(1280),
            height: Some(720),
            frames: Some(31),
            ..Default::default()
        },
    ));
    assert!(
        !pair
            .offerer
            .update_audio_source_stats(sender_id, AudioSourceStatsUpdate::default()),
        "the sender sends video, so it has no audio source"
    );

    let report = pair.offerer.get_stats(now, StatsSelector::None);
    let outbound = report.outbound_rtp_streams().next().expect("outbound");
    assert_eq!(outbound.frames_encoded, Some(30));
    assert_eq!(outbound.frame_width, Some(1280));
    assert_eq!(outbound.encoder_implementation.as_deref(), Some("app-vp8"));
    match report.get(&outbound.media_source_id) {
        Some(RTCStatsReportEntry::VideoSource(source)) => {
            assert_eq!(source.media_source_stats.track_identifier, "feed-video");
            assert_eq!(source.width, Some(1280));
            assert_eq!(source.frames, Some(31));
        }
        other => panic!(
            "mediaSourceId {} names no video source: {other:?}",
            outbound.media_source_id
        ),
    }
    // The sender selector brings the source along with the stream that references it.
    let selected = pair
        .offerer
        .get_stats(now, StatsSelector::Sender(sender_id));
    assert!(selected.contains(&outbound.media_source_id));

    // Receiver side.
    assert!(pair.answerer.update_decoder_stats(
        ssrc,
        DecoderStatsUpdate {
            frames_decoded: Some(1),
            key_frames_decoded: Some(1),
            ..Default::default()
        },
    ));
    pair.answerer.update_audio_playout_stats(
        "RTCAudioPlayout_speaker",
        &[ssrc],
        AudioPlayoutStatsUpdate {
            total_samples_count: Some(4800),
            ..Default::default()
        },
    );
    let report = pair.answerer.get_stats(now, StatsSelector::None);
    let inbound = report.inbound_rtp_streams().next().expect("inbound");
    assert_eq!(inbound.frames_decoded, Some(1));
    assert_eq!(inbound.key_frames_decoded, Some(1));
    // The playout object is there with what was supplied. `playoutId` is an audio stream's
    // member (webrtc-stats 8.5), so this video stream does not name it.
    assert_eq!(inbound.playout_id, None);
    let playout = report
        .iter()
        .find_map(|entry| match entry {
            RTCStatsReportEntry::AudioPlayout(playout) => Some(playout),
            _ => None,
        })
        .expect("the playout object");
    assert_eq!(playout.total_samples_count, Some(4800));
    assert_eq!(playout.total_playout_delay, None);
}
