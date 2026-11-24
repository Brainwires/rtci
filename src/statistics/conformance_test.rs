//! webrtc-stats rules the accumulators have to keep, each driven through the code a peer
//! connection runs: the RTCP walk, the stream registry, the report.

use crate::peer_connection::util_test::{new_pair, signal_pair};
use crate::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
use crate::rtp_transceiver::{RTCRtpReceiverId, RTCRtpSenderId};
use crate::statistics::StatsSelector;
use crate::statistics::accumulator::{
    EncoderStatsUpdate, IceCandidateAccumulator, RTCStatsAccumulator,
};
use crate::statistics::report::{RTCStatsReport, RTCStatsReportEntry};
use rtcp::extended_report::{DLRRReport, DLRRReportBlock, ExtendedReport};
use rtcp::receiver_report::ReceiverReport;
use rtcp::reception_report::ReceptionReport;
use rtcp::sender_report::SenderReport;
use serde_json::Value;
use shared::time::SystemInstant;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// The remote-outbound object of a report, as JSON.
fn remote_outbound(report: &RTCStatsReport) -> Value {
    report
        .iter()
        .find_map(|entry| match entry {
            RTCStatsReportEntry::RemoteOutboundRtp(stats) => {
                Some(serde_json::to_value(stats).expect("serializes"))
            }
            _ => None,
        })
        .expect("a remote-outbound-rtp object")
}

/// The id of each outbound-rtp and inbound-rtp object of a report.
fn stream_ids(report: &RTCStatsReport) -> (Vec<String>, Vec<String>) {
    (
        report
            .outbound_rtp_streams()
            .map(|s| s.sent_rtp_stream_stats.rtp_stream_stats.stats.id.clone())
            .collect(),
        report
            .inbound_rtp_streams()
            .map(|s| {
                s.received_rtp_stream_stats
                    .rtp_stream_stats
                    .stats
                    .id
                    .clone()
            })
            .collect(),
    )
}

fn sender_report(ssrc: u32, ntp_time: u64) -> Vec<Box<dyn rtcp::Packet>> {
    vec![Box::new(SenderReport {
        ssrc,
        ntp_time,
        rtp_time: 90_000,
        packet_count: 10,
        octet_count: 2_000,
        ..Default::default()
    })]
}

/// webrtc-stats 8.10 `remoteTimestamp`: "derived from the NTP timestamp in an RTCP Sender
/// Report (SR) block, which reflects the remote endpoint's clock". The time the report arrived
/// here used to be given instead.
#[test]
fn remote_timestamp_is_the_sender_reports_ntp_time() {
    let mut stats = RTCStatsAccumulator::new();
    stats.get_or_create_inbound_rtp_streams(7, RtpCodecKind::Video, "track", "0", None, None, 0);
    // A remote clock at 2027-01-15T08:00:00.250Z, whatever ours says.
    let remote_clock = Duration::from_millis(1_800_000_000_250);
    let now = Instant::now();
    stats.on_rtcp_received(
        &sender_report(7, SystemInstant::unix2ntp(remote_clock)),
        now,
    );

    let remote = remote_outbound(&stats.snapshot(now + Duration::from_secs(3)));
    let remote_timestamp = remote["remoteTimestamp"].as_f64().expect("remoteTimestamp");
    assert!(
        (remote_timestamp - 1_800_000_000_250.0).abs() < 0.001,
        "the sender report said 1800000000250 ms, remoteTimestamp is {remote_timestamp}"
    );
    assert_eq!(remote["reportsSent"], 1);
    assert_eq!(remote["packetsSent"], 10);
    assert_eq!(remote["bytesSent"], 2_000);
}

/// A sender report whose NTP timestamp is not wall-clock time (RFC 3550 6.4.1 lets a sender
/// without one put something else there; before 1970 it cannot be an epoch time) gives no
/// `remoteTimestamp`, and breaks nothing.
#[test]
fn a_sender_report_without_wall_clock_time_gives_no_remote_timestamp() {
    let mut stats = RTCStatsAccumulator::new();
    stats.get_or_create_inbound_rtp_streams(7, RtpCodecKind::Video, "track", "0", None, None, 0);
    let now = Instant::now();
    for ntp_time in [0, 1, 0x0000_1000_0000_0000, 0x83AA_7E7F_FFFF_FFFF] {
        stats.on_rtcp_received(&sender_report(7, ntp_time), now);
        let remote = remote_outbound(&stats.snapshot(now));
        assert!(
            remote.get("remoteTimestamp").is_none(),
            "NTP time {ntp_time:#x} is before 1970: {remote}"
        );
    }
    // A second into 1970 is one. (The first second of a month and the last before it are
    // a possible leap second's, whose timestamps are not taken: RFC 7164 section 5.1.)
    stats.on_rtcp_received(&sender_report(7, 0x83AA_7E81_0000_0000), now);
    let remote = remote_outbound(&stats.snapshot(now));
    assert_eq!(remote["remoteTimestamp"], 1000.0);
    assert_eq!(remote["reportsSent"], 5);
}

/// webrtc-stats 4.3: "the stats ID of a deleted object MUST NOT be reused"; 8.1: an SSRC that
/// comes back after its stream was deleted is a new object, with counters from zero and a new
/// id. The id was built from the kind and the SSRC alone, so the new object took the old id.
#[test]
fn a_recycled_ssrc_is_a_new_object_with_a_new_id() {
    let now = Instant::now();
    let mut stats = RTCStatsAccumulator::new();
    let bind = |stats: &mut RTCStatsAccumulator| {
        stats.get_or_create_outbound_rtp_streams(10, RtpCodecKind::Video, "0", "", 0, None, 0);
        stats.get_or_create_inbound_rtp_streams(
            20,
            RtpCodecKind::Video,
            "track",
            "0",
            None,
            None,
            0,
        );
    };
    let mut seen_outbound = HashSet::new();
    let mut seen_inbound = HashSet::new();
    for round in 0..4 {
        bind(&mut stats);
        stats
            .outbound_rtp_streams
            .get_mut(&10)
            .unwrap()
            .on_rtp_sent(12, 100, now);
        let report = stats.snapshot(now);
        let (outbound, inbound) = stream_ids(&report);
        assert_eq!((outbound.len(), inbound.len()), (1, 1));
        // The same object keeps its id from one report to the next...
        assert_eq!(
            stream_ids(&stats.snapshot(now)),
            (outbound.clone(), inbound.clone())
        );
        // ...and no object ever gets the id of one that was deleted.
        assert!(
            seen_outbound.insert(outbound[0].clone()),
            "round {round}: the outbound id {} was a deleted object's",
            outbound[0]
        );
        assert!(
            seen_inbound.insert(inbound[0].clone()),
            "round {round}: the inbound id {} was a deleted object's",
            inbound[0]
        );
        let outbound_stats = report.outbound_rtp_streams().next().unwrap();
        assert_eq!(
            outbound_stats.sent_rtp_stream_stats.packets_sent, 1,
            "round {round}: the counters start from zero"
        );

        // The SSRCs are no longer bound: both objects are deleted.
        stats.retire_rtp_streams(&HashSet::new(), &HashSet::new());
        assert_eq!(stream_ids(&stats.snapshot(now)), (vec![], vec![]));
    }
}

fn codec(mime_type: &str, sdp_fmtp_line: &str) -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: mime_type.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: sdp_fmtp_line.to_owned(),
        rtcp_feedback: vec![],
    }
}

/// The (id, sdpFmtpLine) of each codec object of a report, sorted.
fn codecs(report: &RTCStatsReport) -> Vec<(String, String)> {
    let mut codecs: Vec<(String, String)> = report
        .iter()
        .filter_map(|entry| match entry {
            RTCStatsReportEntry::Codec(codec) => {
                Some((codec.stats.id.clone(), codec.sdp_fmtp_line.clone()))
            }
            _ => None,
        })
        .collect();
    codecs.sort();
    codecs
}

/// webrtc-stats 8.3: one codec object per payload type per transport, shared by the streams
/// that use it in either direction, "unless sdpFmtpLine is different when sending and
/// receiving"; deleted when no stream references it, and the same object (the same id) when
/// the codec is used again.
#[test]
fn a_payload_type_has_one_codec_object_unless_the_directions_differ() {
    let now = Instant::now();
    let mut stats = RTCStatsAccumulator::new();
    stats.get_or_create_outbound_rtp_streams(10, RtpCodecKind::Video, "0", "", 0, None, 0);
    stats.get_or_create_inbound_rtp_streams(20, RtpCodecKind::Video, "t", "0", None, None, 0);
    stats.get_or_create_inbound_rtp_streams(21, RtpCodecKind::Video, "u", "1", None, None, 1);

    // The same codec sent and received under payload type 96: one object for the three
    // streams.
    stats.register_outbound_codec(10, &codec("video/VP8", ""), 96);
    stats.register_inbound_codec(20, &codec("video/VP8", ""), 96);
    stats.register_inbound_codec(21, &codec("video/VP8", ""), 96);
    let report = stats.snapshot(now);
    let shared = codecs(&report);
    assert_eq!(shared.len(), 1, "{shared:?}");
    let outbound = report.outbound_rtp_streams().next().unwrap();
    assert_eq!(
        outbound.sent_rtp_stream_stats.rtp_stream_stats.codec_id,
        shared[0].0
    );
    for inbound in report.inbound_rtp_streams() {
        assert_eq!(
            inbound.received_rtp_stream_stats.rtp_stream_stats.codec_id,
            shared[0].0
        );
    }

    // No stream references it any more: deleted. Used again: the same id.
    stats.retire_rtp_streams(&HashSet::new(), &HashSet::new());
    stats.cleanup_unreferenced_codecs();
    assert!(codecs(&stats.snapshot(now)).is_empty());
    stats.get_or_create_inbound_rtp_streams(22, RtpCodecKind::Video, "v", "0", None, None, 0);
    stats.register_inbound_codec(22, &codec("video/VP8", ""), 96);
    assert_eq!(codecs(&stats.snapshot(now)), shared, "revived with its id");

    // Payload type 102 means H.264 with one profile to send and another to receive: two
    // objects, each stream naming the one of its direction.
    stats.get_or_create_outbound_rtp_streams(11, RtpCodecKind::Video, "0", "", 0, None, 0);
    stats.register_inbound_codec(22, &codec("video/H264", "profile-level-id=42e01f"), 102);
    stats.register_outbound_codec(11, &codec("video/H264", "profile-level-id=640c1f"), 102);
    stats.cleanup_unreferenced_codecs();
    let report = stats.snapshot(now);
    let split = codecs(&report);
    assert_eq!(split.len(), 2, "{split:?}");
    let fmtp_of = |id: &str| {
        split
            .iter()
            .find(|(codec_id, _)| codec_id == id)
            .map(|(_, fmtp)| fmtp.clone())
            .expect("the stream's codec is in the report")
    };
    let outbound = report.outbound_rtp_streams().next().unwrap();
    let inbound = report.inbound_rtp_streams().next().unwrap();
    assert_eq!(
        fmtp_of(&outbound.sent_rtp_stream_stats.rtp_stream_stats.codec_id),
        "profile-level-id=640c1f"
    );
    assert_eq!(
        fmtp_of(&inbound.received_rtp_stream_stats.rtp_stream_stats.codec_id),
        "profile-level-id=42e01f"
    );
    // Asked again, each direction keeps the object it has.
    stats.register_inbound_codec(22, &codec("video/H264", "profile-level-id=42e01f"), 102);
    stats.register_outbound_codec(11, &codec("video/H264", "profile-level-id=640c1f"), 102);
    assert_eq!(codecs(&stats.snapshot(now)), split);
}

fn reception(ssrc: u32, last_sequence_number: u32, lost: u32) -> ReceptionReport {
    ReceptionReport {
        ssrc,
        last_sequence_number,
        total_lost: lost,
        ..Default::default()
    }
}

fn receiver_report(report: ReceptionReport) -> Vec<Box<dyn rtcp::Packet>> {
    vec![Box::new(ReceiverReport {
        reports: vec![report],
        ..Default::default()
    })]
}

/// The remote-inbound object of a report, as JSON.
fn remote_inbound(report: &RTCStatsReport) -> Value {
    report
        .iter()
        .find_map(|entry| match entry {
            RTCStatsReportEntry::RemoteInboundRtp(stats) => {
                Some(serde_json::to_value(stats).expect("serializes"))
            }
            _ => None,
        })
        .expect("a remote-inbound-rtp object")
}

/// webrtc-stats 8.6 `roundTripTime`: it "MUST NOT exist until a RTCP Receiver Report is
/// received with a DLSR value other than 0"; and `timestamp` is when the report arrived.
#[test]
fn a_receiver_report_with_no_delay_since_last_sr_measures_no_round_trip() {
    let t0 = Instant::now();
    let mut stats = RTCStatsAccumulator::new();
    stats
        .get_or_create_outbound_rtp_streams(10, RtpCodecKind::Video, "0", "", 0, None, 0)
        .on_sequence_number_sent(1);
    let ntp_time: u64 = 0xE5C2_3A10_8000_0000;
    stats.on_rtcp_sent(
        &[Box::new(SenderReport {
            ssrc: 10,
            ntp_time,
            ..Default::default()
        })],
        t0,
    );

    // The report echoes our sender report, with a DLSR of 0.
    let mut echo = reception(10, 50, 0);
    echo.last_sender_report = (ntp_time >> 16) as u32;
    echo.delay = 0;
    let first_arrival = t0 + Duration::from_millis(100);
    stats.on_rtcp_received(&receiver_report(echo.clone()), first_arrival);
    let first = remote_inbound(&stats.snapshot(t0 + Duration::from_secs(1)));
    assert!(first.get("roundTripTime").is_none(), "{first}");
    assert_eq!(first["roundTripTimeMeasurements"], 0);
    assert_eq!(first["totalRoundTripTime"], 0.0);

    // The next one says it held the sender report for 20 ms: 250 - 20 = 230 ms on the wire.
    echo.delay = (0.020 * 65536.0) as u32;
    let second_arrival = t0 + Duration::from_millis(250);
    stats.on_rtcp_received(&receiver_report(echo), second_arrival);
    let second = remote_inbound(&stats.snapshot(t0 + Duration::from_secs(2)));
    let rtt = second["roundTripTime"].as_f64().expect("roundTripTime");
    assert!((rtt - 0.230).abs() < 0.0001, "{rtt}");
    assert_eq!(second["roundTripTimeMeasurements"], 1);

    // Each object is stamped with the arrival of its report, not with the time of the call.
    let between = second["timestamp"].as_f64().unwrap() - first["timestamp"].as_f64().unwrap();
    assert!(
        (between - 150.0).abs() < 0.001,
        "the two reports arrived 150 ms apart, the timestamps are {between} ms apart"
    );
}

/// webrtc-stats 8.1: "the total counters of an RTP stream only increase". The remote
/// receiver's `packetsReceived` is derived from each reception report; a report that arrives
/// after a later one does not take packets back.
#[test]
fn remote_packets_received_never_goes_down() {
    let now = Instant::now();
    let mut stats = RTCStatsAccumulator::new();
    stats
        .get_or_create_outbound_rtp_streams(10, RtpCodecKind::Video, "0", "", 0, None, 0)
        .on_sequence_number_sent(1);
    let mut seen = Vec::new();
    // (highest sequence number, cumulative loss): the third report is an older one, late.
    for (highest, lost) in [(100, 0), (200, 4), (150, 2), (260, 4)] {
        stats.on_rtcp_received(&receiver_report(reception(10, highest, lost)), now);
        seen.push(
            remote_inbound(&stats.snapshot(now))["packetsReceived"]
                .as_u64()
                .unwrap(),
        );
    }
    assert_eq!(seen, [100, 196, 196, 256]);
}

/// webrtc-stats 8.10 `roundTripTime`: it "MUST NOT exist if the latest SR does not contain
/// the DLRR report block, or if the last RR timestamp in the DLRR report block is zero, or if
/// the delay since last RR value in the DLRR report block is zero". The last value used to
/// stay through sender reports that had no DLRR block.
#[test]
fn remote_outbound_round_trip_time_is_the_latest_sender_reports() {
    let t0 = Instant::now();
    let mut stats = RTCStatsAccumulator::new();
    let stream =
        stats.get_or_create_inbound_rtp_streams(20, RtpCodecKind::Video, "t", "0", None, None, 0);
    // Our receiver reports about the stream come from SSRC 99, and so did the receiver
    // reference time the remote sender answers.
    stream.receiver_ssrc = Some(99);
    stream.on_reference_time_sent(0x1234_0000, t0);

    let sr = || -> Box<dyn rtcp::Packet> {
        Box::new(SenderReport {
            ssrc: 20,
            ntp_time: 0xE5C2_3A10_8000_0000,
            ..Default::default()
        })
    };
    let dlrr = |last_rr: u32, delay: u32| -> Box<dyn rtcp::Packet> {
        Box::new(ExtendedReport {
            sender_ssrc: 20,
            reports: vec![Box::new(DLRRReportBlock {
                reports: vec![DLRRReport {
                    ssrc: 99,
                    last_rr,
                    dlrr: delay,
                }],
            })],
        })
    };
    let rtt = |stats: &RTCStatsAccumulator| {
        let remote = remote_outbound(&stats.snapshot(t0));
        (
            remote.get("roundTripTime").and_then(Value::as_f64),
            remote["roundTripTimeMeasurements"].as_u64().unwrap(),
        )
    };
    let ten_ms = (0.010 * 65536.0) as u32;

    // A sender report with a DLRR block that answers our reference time after holding it
    // 10 ms: 60 - 10 = 50 ms.
    stats.on_rtcp_received(
        &[sr(), dlrr(0x1234_0000, ten_ms)],
        t0 + Duration::from_millis(60),
    );
    let (measured, count) = rtt(&stats);
    assert!((measured.expect("measured") - 0.050).abs() < 0.0001);
    assert_eq!(count, 1);

    // The next sender report has no DLRR block: no round trip time; the count stays.
    stats.on_rtcp_received(&[sr()], t0 + Duration::from_millis(1060));
    assert_eq!(rtt(&stats), (None, 1));

    // A block with a zero delay, or a zero last RR, measures nothing either.
    stats.on_rtcp_received(
        &[sr(), dlrr(0x1234_0000, 0)],
        t0 + Duration::from_millis(2060),
    );
    assert_eq!(rtt(&stats), (None, 1));
    stats.on_rtcp_received(&[sr(), dlrr(0, ten_ms)], t0 + Duration::from_millis(3060));
    assert_eq!(rtt(&stats), (None, 1));

    // The block may stand before the sender report in the compound packet: it is that
    // report's all the same.
    stats.on_rtcp_received(
        &[dlrr(0x1234_0000, ten_ms), sr()],
        t0 + Duration::from_millis(3560),
    );
    let (measured, count) = rtt(&stats);
    assert!((measured.expect("measured") - 3.550).abs() < 0.0001);
    assert_eq!(count, 2);

    // And a good one measures again.
    stats.on_rtcp_received(
        &[sr(), dlrr(0x1234_0000, ten_ms)],
        t0 + Duration::from_millis(4060),
    );
    let (measured, count) = rtt(&stats);
    assert!((measured.expect("measured") - 4.050).abs() < 0.0001);
    assert_eq!(count, 3);
}

/// webrtc-stats 8.11: a media source "exists from the time a track is attached to a sender
/// until it is attached to none"; an outbound stream names its sender's.
#[test]
fn a_media_source_lives_while_its_track_is_attached_to_a_sender() {
    let now = Instant::now();
    let mut stats = RTCStatsAccumulator::new();
    stats.get_or_create_outbound_rtp_streams(10, RtpCodecKind::Video, "0", "", 0, None, 0);
    stats.get_or_create_outbound_rtp_streams(11, RtpCodecKind::Audio, "1", "", 0, None, 1);
    let sources = |stats: &RTCStatsAccumulator| {
        let report = stats.snapshot(now);
        let mut sources: Vec<(String, String)> = report
            .iter()
            .filter_map(|entry| match entry {
                RTCStatsReportEntry::VideoSource(s) => Some((
                    "video".to_owned(),
                    s.media_source_stats.track_identifier.clone(),
                )),
                RTCStatsReportEntry::AudioSource(s) => Some((
                    "audio".to_owned(),
                    s.media_source_stats.track_identifier.clone(),
                )),
                _ => None,
            })
            .collect();
        sources.sort();
        let named: Vec<bool> = {
            let mut streams: Vec<_> = report.outbound_rtp_streams().collect();
            streams.sort_by_key(|s| s.sent_rtp_stream_stats.rtp_stream_stats.ssrc);
            streams
                .iter()
                .map(|s| report.contains(&s.media_source_id))
                .collect()
        };
        (sources, named)
    };
    assert_eq!(sources(&stats), (vec![], vec![false, false]));

    stats.sync_media_sources(&[
        (0, "camera".to_owned(), RtpCodecKind::Video),
        (1, "microphone".to_owned(), RtpCodecKind::Audio),
    ]);
    assert_eq!(
        sources(&stats),
        (
            vec![
                ("audio".to_owned(), "microphone".to_owned()),
                ("video".to_owned(), "camera".to_owned())
            ],
            vec![true, true]
        )
    );

    // The video sender's track is replaced, the audio sender's is gone.
    stats.sync_media_sources(&[(0, "screen".to_owned(), RtpCodecKind::Video)]);
    assert_eq!(
        sources(&stats),
        (
            vec![("video".to_owned(), "screen".to_owned())],
            vec![true, false]
        )
    );
}

/// webrtc-stats 7.1: a candidate is deleted once the ICE transport has let go of it and no
/// candidate pair that is still reported names it.
#[test]
fn a_candidate_goes_when_the_agent_and_every_pair_let_go_of_it() {
    let now = Instant::now();
    let mut stats = RTCStatsAccumulator::new();
    for id in ["RTCLocalIceCandidate_a", "RTCLocalIceCandidate_b"] {
        stats.register_local_candidate(id.to_owned(), IceCandidateAccumulator::default());
    }
    for id in ["RTCRemoteIceCandidate_x", "RTCRemoteIceCandidate_y"] {
        stats.register_remote_candidate(id.to_owned(), IceCandidateAccumulator::default());
    }
    stats.get_or_create_candidate_pair("a", "x");
    let ids = |stats: &RTCStatsAccumulator| {
        let mut ids: Vec<String> = stats
            .snapshot(now)
            .iter()
            .filter(|entry| {
                matches!(
                    entry,
                    RTCStatsReportEntry::LocalCandidate(_)
                        | RTCStatsReportEntry::RemoteCandidate(_)
                )
            })
            .map(|entry| entry.id().to_owned())
            .collect();
        ids.sort();
        ids
    };
    let held =
        |ids: &[&str]| -> HashSet<String> { ids.iter().map(|id| (*id).to_owned()).collect() };

    // The agent holds b and y; a and x are only in the pair: all four stay.
    stats.retain_candidates(
        &held(&["RTCLocalIceCandidate_b"]),
        &held(&["RTCRemoteIceCandidate_y"]),
    );
    assert_eq!(ids(&stats).len(), 4);

    // The pair goes (an ICE restart dropped it): a and x go with it.
    stats.sync_ice_candidate_pairs(&[]);
    stats.retain_candidates(
        &held(&["RTCLocalIceCandidate_b"]),
        &held(&["RTCRemoteIceCandidate_y"]),
    );
    assert_eq!(
        ids(&stats),
        ["RTCLocalIceCandidate_b", "RTCRemoteIceCandidate_y"]
    );
}

/// webrtc 8.2 `getStats(selector)`: a selector that is no sender or receiver of the connection
/// is an `InvalidAccessError`; one that is, with no stream yet, selects nothing.
#[test]
fn a_selector_that_is_not_the_connections_is_an_invalid_access_error() {
    let (mut offerer, mut answerer) = new_pair().expect("pair");
    let transceiver = offerer
        .add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(crate::rtp_transceiver::RTCRtpTransceiverInit {
                direction: crate::rtp_transceiver::RTCRtpTransceiverDirection::Sendonly,
                streams: vec![],
                send_encodings: vec![Default::default()],
            }),
        )
        .expect("transceiver");
    let now = Instant::now();
    let sender = offerer
        .rtp_transceiver(transceiver)
        .and_then(|t| t.sender())
        .expect("a sender");
    assert!(
        offerer
            .try_get_stats(now, StatsSelector::Sender(sender))
            .expect("the connection's sender")
            .is_empty(),
        "the sender has no stream before negotiation"
    );
    signal_pair(&mut offerer, &mut answerer).expect("signal");
    let selected = offerer
        .try_get_stats(now, StatsSelector::Sender(sender))
        .expect("the connection's sender");
    assert_eq!(selected.outbound_rtp_streams().count(), 1);
    assert!(
        !offerer
            .try_get_stats(now, StatsSelector::None)
            .unwrap()
            .is_empty()
    );
    for selector in [
        StatsSelector::Sender(RTCRtpSenderId(7)),
        StatsSelector::Receiver(RTCRtpReceiverId(7)),
    ] {
        assert_eq!(
            offerer.try_get_stats(now, selector).err(),
            Some(shared::error::Error::InvalidAccessError)
        );
    }

    // A transport that has not started says so: `dtlsState` is a required member.
    let fresh = new_pair()
        .expect("pair")
        .0
        .get_stats(now, StatsSelector::None);
    let transport = serde_json::to_value(fresh.transport().expect("transport")).unwrap();
    assert_eq!(transport["dtlsState"], "new", "{transport}");
    assert_eq!(transport["dtlsRole"], "unknown");
    assert_eq!(transport["iceRole"], "unknown");
    assert_eq!(transport["selectedCandidatePairChanges"], 0);
    assert_eq!(transport["bytesSent"], 0);
    assert!(transport.get("selectedCandidatePairId").is_none());
}

/// webrtc-stats 8.8 `targetBitrate`: "the current encoder target" of the stream. The
/// application supplies it; the congestion controller's estimate for the connection stands in
/// while there is one stream to give it to, and was written to every stream alike.
#[test]
fn target_bitrate_is_the_streams_own_target() {
    let now = Instant::now();
    let mut stats = RTCStatsAccumulator::new();
    let targets = |stats: &RTCStatsAccumulator| {
        let report = stats.snapshot(now);
        let mut targets: Vec<(u32, Option<f64>)> = report
            .outbound_rtp_streams()
            .map(|s| {
                (
                    s.sent_rtp_stream_stats.rtp_stream_stats.ssrc,
                    s.target_bitrate,
                )
            })
            .collect();
        targets.sort_by_key(|(ssrc, _)| *ssrc);
        targets
    };

    stats.get_or_create_outbound_rtp_streams(10, RtpCodecKind::Video, "0", "", 0, None, 0);
    assert_eq!(targets(&stats), [(10, None)], "no estimate yet");
    stats.on_target_bitrate(0, 800_000.0, &std::collections::HashMap::new());
    assert_eq!(targets(&stats), [(10, Some(800_000.0))]);

    // A second stream: the estimate is the connection's, not either stream's.
    stats.get_or_create_outbound_rtp_streams(11, RtpCodecKind::Video, "1", "", 0, None, 1);
    stats.on_target_bitrate(0, 900_000.0, &std::collections::HashMap::new());
    assert_eq!(targets(&stats), [(10, None), (11, None)]);

    // The encoder says what it aims at for one of them.
    assert!(stats.update_encoder_stats(
        11,
        EncoderStatsUpdate {
            target_bitrate: Some(300_000.0),
            ..Default::default()
        }
    ));
    assert_eq!(targets(&stats), [(10, None), (11, Some(300_000.0))]);
}
