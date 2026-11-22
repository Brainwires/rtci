//! A whole report from an rtc-to-rtc call, walked object by object.
//!
//! webrtc-stats: every id a stats object names resolves to an object in the same report, and a
//! member the implementation does not measure is not present. This drives a call with media,
//! RTCP reports and a data channel, then fails on any reference that does not resolve, on any
//! member from the list of those the engine never measures (nothing here supplies them), and
//! on any value outside the W3C enums or any empty string standing for "no value".

use crate::media_stream::MediaStreamTrack;
use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use crate::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use crate::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use crate::peer_connection::transport::RTCDtlsRole;
use crate::peer_connection::util_test::{
    ANSWERER_ADDR, OFFERER_ADDR, Pair, new_peer, send_until_seen, signal_pair,
};
use crate::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use crate::statistics::StatsSelector;
use crate::statistics::report::{RTCStatsReport, RTCStatsReportEntry};
use serde_json::Value;
use std::collections::HashSet;
use std::time::Duration;

/// Members that need an encoder, a decoder, capture, playout, ECN or RFC 8888 feedback: the
/// engine measures none of them, so with nothing supplied none may appear.
const NEVER_WRITTEN: &[&str] = &[
    "framesDecoded",
    "keyFramesDecoded",
    "framesRendered",
    "framesDropped",
    "frameWidth",
    "frameHeight",
    "framesPerSecond",
    "qpSum",
    "totalDecodeTime",
    "totalInterFrameDelay",
    "totalSquaredInterFrameDelay",
    "pauseCount",
    "totalPausesDuration",
    "freezeCount",
    "totalFreezesDuration",
    "packetsDiscarded",
    "fecPacketsDiscarded",
    "totalProcessingDelay",
    "estimatedPlayoutTimestamp",
    "jitterBufferDelay",
    "jitterBufferTargetDelay",
    "jitterBufferEmittedCount",
    "jitterBufferMinimumDelay",
    "totalSamplesReceived",
    "concealedSamples",
    "silentConcealedSamples",
    "concealmentEvents",
    "insertedSamplesForDeceleration",
    "removedSamplesForAcceleration",
    "audioLevel",
    "totalAudioEnergy",
    "totalSamplesDuration",
    "framesReceived",
    "decoderImplementation",
    "playoutId",
    "powerEfficientDecoder",
    "framesAssembledFromMultiplePackets",
    "totalAssemblyTime",
    "totalCorruptionProbability",
    "totalSquaredCorruptionProbability",
    "corruptionMeasurements",
    "packetsReceivedWithEct1",
    "packetsReceivedWithCe",
    "packetsReportedAsLost",
    "packetsReportedAsLostButRecovered",
    "packetsWithBleachedEct1Marking",
    "packetsSentWithEct1",
    "framesSent",
    "hugeFramesSent",
    "framesEncoded",
    "keyFramesEncoded",
    "psnrSum",
    "psnrMeasurements",
    "totalEncodeTime",
    "qualityLimitationReason",
    "qualityLimitationDurations",
    "qualityLimitationResolutionChanges",
    "encoderImplementation",
    "powerEfficientEncoder",
    "scalabilityMode",
    "availableIncomingBitrate",
    "packetsDiscardedOnSend",
    "bytesDiscardedOnSend",
    // Removed from webrtc-stats: never written, supplied or not.
    "totalEncodedBytesTarget",
];

/// Members whose empty string is a real value rather than "none".
const EMPTY_ALLOWED: &[&str] = &["protocol"];

/// Members webrtc-stats declares nullable (`DOMString? address`: a candidate address that is not
/// exposed).
const NULL_ALLOWED: &[&str] = &["address"];

fn vp8() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: String::new(),
        rtcp_feedback: vec![],
    }
}

/// A peer with VP8 and the default interceptors (NACK, TWCC, RTCP reports, key frame requests).
fn peer(addr: &str, answering_dtls_role: RTCDtlsRole) -> RTCPeerConnection {
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
    let registry = register_default_interceptors(interceptor::Registry::new(), &mut media_engine)
        .expect("default interceptors");
    new_peer(
        media_engine,
        SettingEngineBuilder::new()
            .with_answering_dtls_role(answering_dtls_role)
            .build(),
        Some(registry),
        addr,
    )
    .expect("peer")
}

fn entry_json(entry: &RTCStatsReportEntry) -> Value {
    match entry {
        RTCStatsReportEntry::PeerConnection(s) => serde_json::to_value(s),
        RTCStatsReportEntry::Transport(s) => serde_json::to_value(s),
        RTCStatsReportEntry::IceCandidatePair(s) => serde_json::to_value(s),
        RTCStatsReportEntry::LocalCandidate(s) => serde_json::to_value(s),
        RTCStatsReportEntry::RemoteCandidate(s) => serde_json::to_value(s),
        RTCStatsReportEntry::Certificate(s) => serde_json::to_value(s),
        RTCStatsReportEntry::Codec(s) => serde_json::to_value(s),
        RTCStatsReportEntry::DataChannel(s) => serde_json::to_value(s),
        RTCStatsReportEntry::InboundRtp(s) => serde_json::to_value(s),
        RTCStatsReportEntry::OutboundRtp(s) => serde_json::to_value(s),
        RTCStatsReportEntry::RemoteInboundRtp(s) => serde_json::to_value(s),
        RTCStatsReportEntry::RemoteOutboundRtp(s) => serde_json::to_value(s),
        RTCStatsReportEntry::AudioSource(s) => serde_json::to_value(s),
        RTCStatsReportEntry::VideoSource(s) => serde_json::to_value(s),
        RTCStatsReportEntry::AudioPlayout(s) => serde_json::to_value(s),
    }
    .expect("a stats object serializes")
}

/// Every problem the report has, one line each.
fn problems(side: &str, report: &RTCStatsReport) -> Vec<String> {
    let objects: Vec<Value> = report.iter().map(entry_json).collect();
    let ids: HashSet<&str> = report.ids().collect();
    let mut problems = Vec::new();
    for object in &objects {
        let map = object.as_object().expect("a stats object is a JSON object");
        let id = map.get("id").and_then(Value::as_str).unwrap_or("?");
        for (member, value) in map {
            if member.ends_with("Id")
                && let Some(target) = value.as_str()
                && !ids.contains(target)
            {
                problems.push(format!(
                    "{side}: {id}.{member} = {target:?} resolves to nothing"
                ));
            }
            if NEVER_WRITTEN.contains(&member.as_str()) {
                problems.push(format!(
                    "{side}: {id}.{member} is present but never measured"
                ));
            }
            match value {
                Value::String(text)
                    if text.is_empty() && !EMPTY_ALLOWED.contains(&member.as_str()) =>
                {
                    problems.push(format!("{side}: {id}.{member} is an empty string"));
                }
                Value::String(text) if text.eq_ignore_ascii_case("unspecified") => {
                    problems.push(format!("{side}: {id}.{member} = {text:?} is no W3C value"));
                }
                Value::Null if !NULL_ALLOWED.contains(&member.as_str()) => {
                    problems.push(format!("{side}: {id}.{member} is null"));
                }
                _ => {}
            }
        }
    }
    problems
}

fn count(report: &RTCStatsReport, typ: &str) -> usize {
    report
        .iter()
        .filter(|e| entry_json(e)["type"] == typ)
        .count()
}

#[test]
fn every_reference_resolves_and_nothing_unmeasured_is_reported() {
    let mut offerer = peer(OFFERER_ADDR, RTCDtlsRole::Server);
    let mut answerer = peer(ANSWERER_ADDR, RTCDtlsRole::Client);
    let ssrc = 0x5157_0001;
    let sender_id = offerer
        .add_track(MediaStreamTrack::new(
            "integrity-stream".to_owned(),
            "integrity-video".to_owned(),
            "integrity-video".to_owned(),
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
    offerer
        .create_data_channel("integrity", None)
        .expect("data channel");

    // Before any description: the report is already one that resolves.
    let early = offerer.get_stats(std::time::Instant::now(), StatsSelector::None);
    let early_problems = problems("offerer before negotiation", &early);
    assert!(early_problems.is_empty(), "{early_problems:#?}");

    signal_pair(&mut offerer, &mut answerer).expect("signal");
    let mut pair = Pair::new(offerer, answerer);
    pair.connect().expect("connect");

    // Four seconds of media at 50 packets a second: sender reports go out once a second, and
    // the receiver reports that answer them echo them.
    let mut sequence_number = 0u16;
    send_until_seen(&mut pair, sender_id, ssrc, 96, 0x01, &mut sequence_number);
    for _ in 0..200 {
        sequence_number = sequence_number.wrapping_add(1);
        let packet = rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                timestamp: u32::from(sequence_number) * 1800,
                ssrc,
                marker: true,
                ..Default::default()
            },
            payload: bytes::Bytes::from_static(&[0x10, 0x00, 0x00]),
        };
        let now = pair.now;
        pair.offerer
            .rtp_sender(sender_id)
            .expect("sender")
            .write_rtp(now, packet)
            .expect("write_rtp");
        pair.run_until(Duration::from_millis(20), |_| false)
            .expect("drive pair");
    }

    let now = pair.now;
    let offerer_report = pair.offerer.get_stats(now, StatsSelector::None);
    let answerer_report = pair.answerer.get_stats(now, StatsSelector::None);
    let mut all = problems("offerer", &offerer_report);
    all.extend(problems("answerer", &answerer_report));
    assert!(all.is_empty(), "{all:#?}");

    // The objects the call must have produced, so the walk above walked something.
    for (side, report, types) in [
        (
            "offerer",
            &offerer_report,
            &[
                "peer-connection",
                "transport",
                "candidate-pair",
                "local-candidate",
                "remote-candidate",
                "certificate",
                "codec",
                "data-channel",
                "outbound-rtp",
                "remote-inbound-rtp",
            ][..],
        ),
        (
            "answerer",
            &answerer_report,
            &[
                "peer-connection",
                "transport",
                "candidate-pair",
                "codec",
                "data-channel",
                "inbound-rtp",
                "remote-outbound-rtp",
            ][..],
        ),
    ] {
        for typ in types {
            assert!(count(report, typ) >= 1, "{side}: no {typ} object");
        }
    }

    // The RTCP-derived members are there, in their W3C units.
    let remote_inbound = offerer_report
        .iter()
        .map(entry_json)
        .find(|o| o["type"] == "remote-inbound-rtp")
        .expect("remote-inbound-rtp");
    assert!(
        remote_inbound["roundTripTimeMeasurements"].as_u64() >= Some(1),
        "a receiver report echoed a sender report: {remote_inbound}"
    );
    assert!(remote_inbound["roundTripTime"].as_f64().is_some());
    let inbound = answerer_report
        .iter()
        .map(entry_json)
        .find(|o| o["type"] == "inbound-rtp")
        .expect("inbound-rtp");
    let jitter = inbound["jitter"].as_f64().expect("jitter, in seconds");
    assert!(
        jitter < 1.0,
        "jitter is in seconds, not RTP units: {jitter}"
    );
    assert!(inbound["packetsReceived"].as_u64() >= Some(200));

    // A selected report is held to the same rules.
    let selected = pair
        .offerer
        .get_stats(now, StatsSelector::Sender(sender_id));
    let selected_problems = problems("offerer, sender selector", &selected);
    assert!(selected_problems.is_empty(), "{selected_problems:#?}");

    pair.close().expect("close");
}
