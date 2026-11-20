//! RTCP into the RTP stream stats, through the accumulator's own entry points.

use super::RTCStatsAccumulator;
use crate::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
use crate::statistics::report::RTCStatsReportEntry;
use rtcp::receiver_report::ReceiverReport;
use rtcp::reception_report::ReceptionReport;
use rtcp::sender_report::SenderReport;
use std::time::{Duration, Instant};

const OUT_SSRC: u32 = 0x1111_0001;
const IN_SSRC: u32 = 0x2222_0002;

fn vp8() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: "video/VP8".to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: String::new(),
        rtcp_feedback: vec![],
    }
}

/// An accumulator with one outbound and one inbound video stream, both with a VP8 codec
/// registered (so the clock rate is known), and the first outbound packet sent at sequence
/// number 500.
fn call() -> RTCStatsAccumulator {
    let mut stats = RTCStatsAccumulator::new();
    let outbound = stats.get_or_create_outbound_rtp_streams(
        OUT_SSRC,
        RtpCodecKind::Video,
        "0",
        "",
        0,
        None,
        0,
    );
    outbound.on_sequence_number_sent(500);
    stats.get_or_create_inbound_rtp_streams(
        IN_SSRC,
        RtpCodecKind::Video,
        "remote-video",
        "0",
        None,
        None,
        0,
    );
    stats.register_outbound_codec(OUT_SSRC, &vp8(), 96);
    stats.register_inbound_codec(IN_SSRC, &vp8(), 96);
    stats
}

fn block(ssrc: u32) -> ReceptionReport {
    ReceptionReport {
        ssrc,
        ..Default::default()
    }
}

fn remote_inbound_count(stats: &RTCStatsAccumulator, now: Instant) -> usize {
    stats
        .snapshot(now)
        .iter()
        .filter(|e| matches!(e, RTCStatsReportEntry::RemoteInboundRtp(_)))
        .count()
}

fn remote_outbound_count(stats: &RTCStatsAccumulator, now: Instant) -> usize {
    stats
        .snapshot(now)
        .iter()
        .filter(|e| matches!(e, RTCStatsReportEntry::RemoteOutboundRtp(_)))
        .count()
}

/// RFC 3550 section 6.4.1: RTT = A - LSR - DLSR. Our SR goes out at `t0`; the peer's RR comes
/// back 180 ms later, saying it held our SR for 100 ms (DLSR 6553.6 units, truncated to 6553):
/// the round trip is 80 ms, give or take one DLSR unit (~15 us).
#[test]
fn a_receiver_report_that_echoes_our_sender_report_measures_the_round_trip() {
    let t0 = Instant::now();
    let mut stats = call();
    let ntp_time: u64 = 0xE5C2_3A10_8000_0000;
    stats.on_rtcp_sent(
        &[Box::new(SenderReport {
            ssrc: OUT_SSRC,
            ntp_time,
            ..Default::default()
        })],
        t0,
    );
    let mut report = block(OUT_SSRC);
    report.last_sender_report = (ntp_time >> 16) as u32;
    report.delay = 6553;
    stats.on_rtcp_received(
        &[Box::new(ReceiverReport {
            reports: vec![report],
            ..Default::default()
        })],
        t0 + Duration::from_millis(180),
    );

    let stream = &stats.outbound_rtp_streams[&OUT_SSRC];
    assert_eq!(stream.rtt_measurements, 1);
    let rtt = stream
        .remote_round_trip_time
        .expect("a round trip was measured");
    assert!((rtt - 0.080).abs() < 0.0001, "rtt = {rtt}");
    let remote = stream.snapshot_remote(t0);
    assert_eq!(remote.round_trip_time, Some(rtt));
    assert_eq!(remote.total_round_trip_time, rtt);
    assert_eq!(remote.round_trip_time_measurements, 1);
}

/// A report whose LSR names no sender report we sent (or LSR 0, before the peer has any)
/// measures nothing: it must not count as a measurement of 0.
#[test]
fn a_receiver_report_without_a_matching_sender_report_measures_nothing() {
    let now = Instant::now();
    let mut stats = call();
    let mut unknown = block(OUT_SSRC);
    unknown.last_sender_report = 0x1234_5678;
    unknown.delay = 100;
    stats.on_rtcp_received(
        &[Box::new(ReceiverReport {
            reports: vec![block(OUT_SSRC), unknown],
            ..Default::default()
        })],
        now,
    );

    let stream = &stats.outbound_rtp_streams[&OUT_SSRC];
    assert_eq!(stream.remote_reports_received, 2);
    assert_eq!(stream.rtt_measurements, 0);
    assert_eq!(stream.snapshot_remote(now).round_trip_time, None);
}

/// The remote-inbound object is created by the first reception report about the SSRC
/// (webrtc-stats 6.1), and a reception report inside an SR counts as much as one in an RR.
#[test]
fn remote_inbound_exists_from_the_first_reception_report_even_inside_a_sender_report() {
    let now = Instant::now();
    let mut stats = call();
    assert_eq!(remote_inbound_count(&stats, now), 0);
    assert_eq!(
        stats
            .snapshot(now)
            .outbound_rtp_streams()
            .next()
            .unwrap()
            .remote_id,
        None,
        "remoteId must not name an object that is not in the report"
    );

    let mut report = block(OUT_SSRC);
    report.last_sequence_number = 599;
    report.total_lost = 4;
    report.jitter = 900;
    stats.on_rtcp_received(
        &[Box::new(SenderReport {
            ssrc: 0x9999_0009,
            reports: vec![report],
            ..Default::default()
        })],
        now,
    );

    assert_eq!(remote_inbound_count(&stats, now), 1);
    let snapshot = stats.snapshot(now);
    let outbound = snapshot.outbound_rtp_streams().next().unwrap();
    let remote_id = outbound.remote_id.clone().expect("named once it exists");
    assert!(snapshot.contains(&remote_id));
    let remote = stats.outbound_rtp_streams[&OUT_SSRC].snapshot_remote(now);
    // 599 - 500 + 1 - 4
    assert_eq!(remote.received_rtp_stream_stats.packets_received, 96);
    assert_eq!(remote.received_rtp_stream_stats.packets_lost, 4);
    // 900 units at 90 kHz.
    assert_eq!(remote.received_rtp_stream_stats.jitter, Some(0.01));
}

/// The remote-outbound object is created by the first sender report for the SSRC.
#[test]
fn remote_outbound_exists_from_the_first_sender_report() {
    let now = Instant::now();
    let mut stats = call();
    assert_eq!(remote_outbound_count(&stats, now), 0);

    stats.on_rtcp_received(
        &[Box::new(SenderReport {
            ssrc: IN_SSRC,
            packet_count: 42,
            octet_count: 4200,
            ..Default::default()
        })],
        now,
    );

    assert_eq!(remote_outbound_count(&stats, now), 1);
    let snapshot = stats.snapshot(now);
    let inbound = snapshot.inbound_rtp_streams().next().unwrap();
    assert!(snapshot.contains(inbound.remote_id.as_deref().expect("named once it exists")));
}

/// The cumulative number of packets lost is a signed 24-bit field (RFC 3550 section 6.4.1):
/// 0xFFFFFF is -1, one duplicate more than expected.
#[test]
fn cumulative_loss_is_signed() {
    let now = Instant::now();
    let mut stats = call();
    let mut report = block(OUT_SSRC);
    report.total_lost = 0xFF_FFFF;
    stats.on_rtcp_received(
        &[Box::new(ReceiverReport {
            reports: vec![report],
            ..Default::default()
        })],
        now,
    );
    assert_eq!(
        stats.outbound_rtp_streams[&OUT_SSRC].remote_packets_lost,
        -1
    );

    let mut sent = block(IN_SSRC);
    sent.total_lost = 0xFF_FFFE;
    sent.jitter = 450;
    stats.on_rtcp_sent(
        &[Box::new(ReceiverReport {
            reports: vec![sent],
            ..Default::default()
        })],
        now,
    );
    let inbound = stats.inbound_rtp_streams[&IN_SSRC].snapshot(now, "x");
    assert_eq!(inbound.received_rtp_stream_stats.packets_lost, -2);
    // 450 units at 90 kHz: 5 ms, in seconds as webrtc-stats defines jitter.
    assert_eq!(inbound.received_rtp_stream_stats.jitter, Some(0.005));
}

/// Without a codec there is no clock rate, so no jitter in seconds: it is left out rather than
/// reported in the wrong unit.
#[test]
fn jitter_without_a_clock_rate_is_left_out() {
    let now = Instant::now();
    let mut stats = RTCStatsAccumulator::new();
    stats.get_or_create_inbound_rtp_streams(
        IN_SSRC,
        RtpCodecKind::Audio,
        "remote-audio",
        "1",
        None,
        None,
        0,
    );
    let mut sent = block(IN_SSRC);
    sent.jitter = 450;
    stats.on_rtcp_sent(
        &[Box::new(ReceiverReport {
            reports: vec![sent],
            ..Default::default()
        })],
        now,
    );
    let inbound = stats.inbound_rtp_streams[&IN_SSRC].snapshot(now, "x");
    assert_eq!(inbound.received_rtp_stream_stats.jitter, None);
    let json = serde_json::to_value(&inbound).unwrap();
    assert!(json.get("jitter").is_none(), "{json}");
}
