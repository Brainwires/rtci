//! Stats members as webrtc-stats defines them: one test per member the engine used to get
//! wrong.

use crate::data_channel::RTCDataChannelState;
use crate::peer_connection::transport::{
    RTCDtlsTransportState, RTCIceCandidateType, RTCIceRole, RTCIceTransportState,
};
use crate::peer_connection::util_test::{Pair, new_pair, signal_pair};
use crate::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
use crate::statistics::StatsSelector;
use crate::statistics::accumulator::{
    IceCandidateAccumulator, MediaSourceStatsAccumulator, RTCStatsAccumulator,
    TransportStatsAccumulator, base64_encode,
};
use crate::statistics::stats::ice_candidate_pair::RTCStatsIceCandidatePairState;
use ice::CandidatePairStats;
use ice::candidate::candidate_pair::CandidatePairState;
use std::time::Instant;

/// RFC 4648 section 10's test vectors.
#[test]
fn base64_matches_rfc_4648() {
    for (input, output) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64_encode(input.as_bytes()), output, "{input:?}");
    }
    assert_eq!(base64_encode(&[0xFB, 0xFF]), "+/8=");
}

/// webrtc-stats `RTCIceCandidateStats.priority` is the candidate's 32-bit priority, not its
/// high 16 bits; members a candidate has no value for are left out.
#[test]
fn a_candidate_reports_its_whole_priority_and_only_the_members_it_has() {
    let host = IceCandidateAccumulator {
        transport_id: "RTCTransport".to_owned(),
        address: Some("192.0.2.1".to_owned()),
        port: 50000,
        protocol: "udp".to_owned(),
        candidate_type: RTCIceCandidateType::Host,
        priority: 2_130_706_431,
        foundation: "1".to_owned(),
        related_port: 0,
        ..Default::default()
    };
    let stats = host.snapshot_local(Instant::now(), "RTCLocalIceCandidate_1");
    assert_eq!(stats.priority, 2_130_706_431);
    assert_eq!(stats.related_port, None);
    let json = serde_json::to_value(&stats).unwrap();
    assert_eq!(json["priority"], 2_130_706_431u32);
    for absent in [
        "relatedAddress",
        "relatedPort",
        "relayProtocol",
        "tcpType",
        "url",
    ] {
        assert!(json.get(absent).is_none(), "{absent} in {json}");
    }
}

/// webrtc-stats `RTCCodecStats.transportId` names the transport the codec is used on; a
/// video codec has no `channels`.
#[test]
fn a_codec_names_its_transport() {
    let mut stats = RTCStatsAccumulator::new();
    stats.get_or_create_outbound_rtp_streams(7, RtpCodecKind::Video, "0", "", 0, None, 0);
    stats.register_outbound_codec(
        7,
        &RTCRtpCodec {
            mime_type: "video/VP8".to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: String::new(),
            rtcp_feedback: vec![],
        },
        96,
    );
    let report = stats.snapshot(Instant::now());
    let transport_id = report.transport().unwrap().stats.id.clone();
    let codec = report
        .iter()
        .find_map(|e| match e {
            crate::statistics::report::RTCStatsReportEntry::Codec(c) => Some(c),
            _ => None,
        })
        .expect("the codec the stream references");
    assert_eq!(codec.transport_id, transport_id);
    assert_eq!(codec.channels, None);
    let json = serde_json::to_value(codec).unwrap();
    assert_eq!(json["transportId"], transport_id.as_str());
    assert!(json.get("channels").is_none());
    assert!(json.get("sdpFmtpLine").is_none());
}

/// webrtc-stats `RTCMediaSourceStats.trackIdentifier`, not `trackId`.
#[test]
fn a_media_source_names_its_track_as_track_identifier() {
    let source = MediaSourceStatsAccumulator {
        track_id: "camera".to_owned(),
        kind: RtpCodecKind::Video,
        ..Default::default()
    };
    let json = serde_json::to_value(source.snapshot_video(Instant::now(), "s")).unwrap();
    assert_eq!(json["trackIdentifier"], "camera");
    assert!(json.get("trackId").is_none());
    // Nothing captured was reported, so nothing captured is claimed.
    assert!(json.get("width").is_none());
    assert!(json.get("frames").is_none());
}

/// An undecided ICE role is webrtc-stats' "unknown"; a transport state there is none of yet,
/// and empty strings, are left out rather than written as values the W3C enums don't have.
#[test]
fn a_fresh_transport_writes_no_value_outside_the_w3c_enums() {
    let transport = TransportStatsAccumulator::default();
    let json = serde_json::to_value(transport.snapshot(Instant::now())).unwrap();
    assert_eq!(json["iceRole"], "unknown");
    assert_eq!(json["dtlsRole"], "unknown");
    for absent in [
        "iceState",
        "dtlsState",
        "iceLocalUsernameFragment",
        "tlsVersion",
        "dtlsCipher",
        "srtpCipher",
        "selectedCandidatePairId",
        "localCertificateId",
        "remoteCertificateId",
    ] {
        assert!(json.get(absent).is_none(), "{absent} in {json}");
    }

    let controlling = TransportStatsAccumulator {
        ice_role: RTCIceRole::Controlling,
        ice_state: RTCIceTransportState::Checking,
        dtls_state: RTCDtlsTransportState::Connecting,
        ..Default::default()
    };
    let json = serde_json::to_value(controlling.snapshot(Instant::now())).unwrap();
    assert_eq!(json["iceRole"], "controlling");
    assert_eq!(json["iceState"], "checking");
    assert_eq!(json["dtlsState"], "connecting");
}

fn agent_pair(local: &str, remote: &str, state: CandidatePairState) -> CandidatePairStats {
    CandidatePairStats {
        local_candidate_id: local.to_owned(),
        remote_candidate_id: remote.to_owned(),
        state,
        ..CandidatePairStats::new(Instant::now())
    }
}

/// Every pair the agent holds is reported with its own state, not only the selected one; a
/// pair the agent dropped goes, except the selected pair.
#[test]
fn every_candidate_pair_is_reported_with_its_state() {
    let mut stats = RTCStatsAccumulator::new();
    stats.sync_ice_candidate_pairs(&[
        agent_pair("a", "x", CandidatePairState::Succeeded),
        agent_pair("a", "y", CandidatePairState::InProgress),
        agent_pair("b", "x", CandidatePairState::Failed),
    ]);
    assert_eq!(stats.ice_candidate_pairs.len(), 3);
    let state = |stats: &RTCStatsAccumulator, id: &str| stats.ice_candidate_pairs[id].state;
    assert_eq!(
        state(&stats, "RTCIceCandidatePair_a_x"),
        RTCStatsIceCandidatePairState::Succeeded
    );
    assert_eq!(
        state(&stats, "RTCIceCandidatePair_a_y"),
        RTCStatsIceCandidatePairState::InProgress
    );
    assert_eq!(
        state(&stats, "RTCIceCandidatePair_b_x"),
        RTCStatsIceCandidatePairState::Failed
    );

    stats
        .transport
        .on_selected_candidate_pair_changed("RTCIceCandidatePair_a_x".to_owned());
    stats.sync_ice_candidate_pairs(&[agent_pair("c", "z", CandidatePairState::Waiting)]);
    let mut ids: Vec<_> = stats.ice_candidate_pairs.keys().cloned().collect();
    ids.sort();
    assert_eq!(ids, ["RTCIceCandidatePair_a_x", "RTCIceCandidatePair_c_z"]);
}

/// The congestion controller's estimate is the selected pair's `availableOutgoingBitrate`
/// as well as the streams' `targetBitrate`; before any estimate the member is left out.
#[test]
fn the_estimate_is_the_selected_pairs_available_outgoing_bitrate() {
    let mut stats = RTCStatsAccumulator::new();
    stats.sync_ice_candidate_pairs(&[agent_pair("a", "x", CandidatePairState::Succeeded)]);
    stats
        .transport
        .on_selected_candidate_pair_changed("RTCIceCandidatePair_a_x".to_owned());
    let now = Instant::now();
    let snapshot = |stats: &RTCStatsAccumulator| {
        stats.ice_candidate_pairs["RTCIceCandidatePair_a_x"].snapshot(now, "p")
    };
    assert_eq!(snapshot(&stats).available_outgoing_bitrate, None);

    stats.on_target_bitrate(0, 640_000.0, &std::collections::HashMap::new());
    assert_eq!(snapshot(&stats).available_outgoing_bitrate, Some(640_000.0));
}

/// An estimate that came while the selected pair had no stats entry yet (the controller
/// announces only changes, so it may not come again) is put on the entry once it is listed:
/// `sync_outgoing_estimates`, whichever order the selection, the estimate and the entry came in.
#[test]
fn an_estimate_made_before_the_selected_pair_is_listed_reaches_it() {
    let mut stats = RTCStatsAccumulator::new();
    stats.on_selected_candidate_pair(Some("RTCIceCandidatePair_a_x".to_owned()));
    stats.on_target_bitrate(0, 640_000.0, &std::collections::HashMap::new());
    stats.sync_ice_candidate_pairs(&[agent_pair("a", "x", CandidatePairState::Succeeded)]);
    let now = Instant::now();
    let snapshot = |stats: &RTCStatsAccumulator| {
        stats.ice_candidate_pairs["RTCIceCandidatePair_a_x"].snapshot(now, "p")
    };
    assert_eq!(
        snapshot(&stats).available_outgoing_bitrate,
        None,
        "the entry is new"
    );

    stats.sync_outgoing_estimates();
    assert_eq!(snapshot(&stats).available_outgoing_bitrate, Some(640_000.0));
}

/// The same through `get_stats` on a connection: the estimate came while the selected pair's
/// entry did not carry it (it is made afresh, from the agent's pairs, when it is missing), and
/// the report still has it on the pair in use.
#[test]
fn get_stats_puts_an_earlier_estimate_on_the_selected_pair() {
    let (mut offerer, mut answerer) = new_pair().expect("pair");
    offerer.create_data_channel("estimate", None).expect("dc");
    signal_pair(&mut offerer, &mut answerer).expect("signal");
    let mut pair = Pair::new(offerer, answerer);
    pair.connect().expect("connect");
    let now = pair.now;
    let stats = &mut pair.offerer.pipeline_context.stats;
    let selected = stats.transport.selected_candidate_pair_id.clone();
    assert!(!selected.is_empty(), "a pair is selected");
    stats.on_target_bitrate(0, 640_000.0, &std::collections::HashMap::new());
    if let Some(entry) = stats.ice_candidate_pairs.get_mut(&selected) {
        entry.available_outgoing_bitrate = 0.0;
    }

    let report = pair.offerer.get_stats(now, StatsSelector::None);
    let estimates: Vec<_> = report
        .candidate_pairs()
        .filter_map(|p| p.available_outgoing_bitrate)
        .collect();
    assert_eq!(
        estimates,
        [640_000.0],
        "on the selected pair, and on no other"
    );
}

/// Through a real connection: `dtlsState` follows the DTLS transport, a data channel is
/// reported from `connecting` (before it opens) on, every candidate pair the agent holds is
/// in the report, and the certificates are base64 DER.
#[test]
fn a_connection_reports_dtls_state_channel_state_and_every_pair() {
    let (mut offerer, mut answerer) = new_pair().expect("pair");
    offerer
        .create_data_channel("members", None)
        .expect("data channel");

    let now = Instant::now();
    let before = offerer.get_stats(now, StatsSelector::None);
    assert_eq!(
        before.transport().unwrap().dtls_state,
        RTCDtlsTransportState::New
    );
    let channel = before
        .data_channels()
        .next()
        .expect("the channel before it opens");
    assert_eq!(channel.state, RTCDataChannelState::Connecting);
    assert_eq!(channel.label, "members");

    signal_pair(&mut offerer, &mut answerer).expect("signal");
    let mut pair = Pair::new(offerer, answerer);
    pair.connect().expect("connect");
    let now = pair.now;
    let report = pair.offerer.get_stats(now, StatsSelector::None);
    assert_eq!(
        report.transport().unwrap().dtls_state,
        RTCDtlsTransportState::Connected
    );
    let agent_pairs = pair
        .offerer
        .ice_transport()
        .agent
        .get_candidate_pairs_stats(now)
        .len();
    assert!(agent_pairs >= 1);
    assert_eq!(report.candidate_pairs().count(), agent_pairs);
    for certificate in report.iter().filter_map(|e| match e {
        crate::statistics::report::RTCStatsReportEntry::Certificate(c) => Some(c),
        _ => None,
    }) {
        // DER starts with a SEQUENCE (0x30) and a long-form length (0x82): "MII" in base64.
        assert!(
            certificate.base64_certificate.starts_with("MI"),
            "not base64 DER: {}",
            certificate.base64_certificate
        );
    }
}
