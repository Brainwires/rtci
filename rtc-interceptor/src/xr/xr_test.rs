//! RFC 3611 section 4: the report blocks a receiver writes about each source.

use super::*;
use crate::stream_info::RTCPFeedback;
use bytes::Bytes;
use rtcp::extended_report::VoIPMetricsReportBlock;

const SSRC: u32 = 0x0A0B_0C0D;

fn stream(formats: &[&str]) -> StreamInfo {
    StreamInfo {
        ssrc: SSRC,
        clock_rate: 8_000,
        rtcp_feedback: formats
            .iter()
            .map(|format| RTCPFeedback {
                typ: RTCP_FB_XR.to_owned(),
                parameter: (*format).to_owned(),
            })
            .collect(),
        ..Default::default()
    }
}

fn interceptor(formats: &[&str]) -> XrReportInterceptor {
    let mut xr = XrReportBuilder::new().with_sender_ssrc(1).build();
    xr.bind_remote_stream(&stream(formats));
    xr
}

fn rtp(now: Instant, seq: u16, timestamp: u32) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 0,
                sequence_number: seq,
                timestamp,
                ssrc: SSRC,
                ..Default::default()
            },
            payload: Bytes::from_static(&[0; 160]),
        })),
    }
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// Feeds packets `(seq, arrival offset in ms)` at 160 ticks (20 ms) per sequence number.
fn feed(xr: &mut XrReportInterceptor, base: Instant, packets: &[(u16, u64)], first_seq: u16) {
    for (seq, at) in packets {
        let timestamp = u32::from(seq.wrapping_sub(first_seq)) * 160;
        xr.handle_read(rtp(base + ms(*at), *seq, timestamp))
            .unwrap();
        while xr.poll_read().is_some() {}
    }
}

/// The XR written at `at`, if any.
fn report(xr: &mut XrReportInterceptor, at: Instant) -> Option<ExtendedReport> {
    xr.handle_timeout(at).unwrap();
    let written = xr.poll_write()?;
    match written.message.packet {
        Packet::Rtcp(mut packets) => {
            let packet = packets.remove(0);
            Some(
                packet
                    .as_any()
                    .downcast_ref::<ExtendedReport>()
                    .expect("an XR")
                    .clone(),
            )
        }
        Packet::Rtp(_) => panic!("RTP written"),
    }
}

fn block<T: 'static + Clone>(report: &ExtendedReport) -> Vec<T> {
    report
        .reports
        .iter()
        .filter_map(|b| b.as_any().downcast_ref::<T>().cloned())
        .collect()
}

/// Packets 10 to 19 at 20 ms each, 13 and 15 lost.
fn ten_with_two_lost() -> Vec<(u16, u64)> {
    (10u16..20)
        .filter(|seq| *seq != 13 && *seq != 15)
        .map(|seq| (seq, u64::from(seq - 10) * 20))
        .collect()
}

/// RFC 3611 section 5.1: "participants SHOULD NOT send XR blocks other than the ones
/// indicated by the parameters": a stream that negotiated none gets none.
#[test]
fn a_stream_that_negotiated_no_xr_format_gets_no_block() {
    let base = Instant::now();
    let mut xr = interceptor(&[]);
    feed(&mut xr, base, &ten_with_two_lost(), 10);
    assert!(report(&mut xr, base + ms(1_000)).is_none());
    assert_eq!(None, xr.poll_timeout());
}

/// RFC 3611 section 4.1: one bit per sequence number of `begin_seq..end_seq`, 1 for a packet
/// that arrived; the next block starts where this one ended.
#[test]
fn the_loss_rle_block_marks_each_sequence_number_received_or_not() {
    let base = Instant::now();
    let mut xr = interceptor(&["pkt-loss-rle"]);
    feed(&mut xr, base, &ten_with_two_lost(), 10);
    let report = report(&mut xr, base + ms(1_000)).expect("an XR");
    assert_eq!(1, report.sender_ssrc);
    let loss = block::<RLEReportBlock>(&report);
    assert_eq!(1, loss.len());
    assert!(loss[0].is_loss_rle);
    assert_eq!(SSRC, loss[0].ssrc);
    assert_eq!((10, 20), (loss[0].begin_seq, loss[0].end_seq));
    let mut expected = vec![true; 10];
    expected[3] = false;
    expected[5] = false;
    assert_eq!(expected, loss[0].flags());

    feed(&mut xr, base, &[(20, 1_010), (21, 1_030)], 10);
    let next = self::report(&mut xr, base + ms(2_000)).expect("an XR");
    let loss = block::<RLEReportBlock>(&next);
    assert_eq!((20, 22), (loss[0].begin_seq, loss[0].end_seq));
}

/// RFC 3611 section 4.1 and Appendix A.1: across the 16-bit wrap the range runs on; a
/// sequence number 32,768 behind is taken as behind, not ahead with a rollover.
#[test]
fn the_reported_range_runs_across_the_sequence_number_wrap() {
    let base = Instant::now();
    let mut xr = interceptor(&["pkt-loss-rle"]);
    feed(
        &mut xr,
        base,
        &[(65_534, 0), (65_535, 20), (1, 60), (2, 80)],
        65_534,
    );
    let report = report(&mut xr, base + ms(1_000)).expect("an XR");
    let loss = block::<RLEReportBlock>(&report);
    assert_eq!((65_534, 3), (loss[0].begin_seq, loss[0].end_seq));
    assert_eq!(vec![true, true, false, true, true], loss[0].flags());
}

/// RFC 3611 section 4.2: the Duplicate RLE block marks the sequence numbers that arrived more
/// than once.
#[test]
fn duplicates_are_marked_in_the_duplicate_rle_block() {
    let base = Instant::now();
    let mut xr = interceptor(&["pkt-dup-rle"]);
    feed(&mut xr, base, &[(1, 0), (2, 20), (2, 25), (3, 40)], 1);
    let report = report(&mut xr, base + ms(1_000)).expect("an XR");
    let duplicates = block::<RLEReportBlock>(&report);
    assert!(!duplicates[0].is_loss_rle);
    assert_eq!(vec![false, true, false], duplicates[0].flags());
}

/// RFC 3611 section 4.3: "At least one packet MUST have been received for each sequence
/// number reported upon in this block", so a range with losses takes one block per run of
/// received packets; and of duplicates "any time other than the earliest MUST NOT be
/// reported". Receipt times are in RTP timestamp units, 20 ms apart at 8 kHz.
#[test]
fn receipt_times_cover_only_received_runs_and_the_earliest_copy() {
    let base = Instant::now();
    let mut xr = interceptor(&["pkt-rcpt-times"]);
    let mut packets = ten_with_two_lost();
    // A late copy of 11, 500 ms after the first.
    packets.push((11, 520));
    feed(&mut xr, base, &packets, 10);
    let report = report(&mut xr, base + ms(1_000)).expect("an XR");
    let blocks = block::<PacketReceiptTimesReportBlock>(&report);
    let ranges: Vec<(u16, u16)> = blocks.iter().map(|b| (b.begin_seq, b.end_seq)).collect();
    assert_eq!(vec![(10, 13), (14, 15), (16, 20)], ranges);
    let first = &blocks[0].receipt_time;
    assert_eq!(3, first.len());
    assert_eq!(
        160,
        first[1].wrapping_sub(first[0]),
        "11 is reported at its first arrival"
    );
    assert_eq!(160, first[2].wrapping_sub(first[1]));
    assert_eq!(
        4 * 160,
        blocks[1].receipt_time[0].wrapping_sub(first[0]),
        "14 arrived 80 ms after 10"
    );
}

/// RFC 3611 section 4.6: the counts of lost and duplicate packets of the range, and the
/// minimum, maximum, mean and deviation of the relative transit time between consecutive
/// packets; the TTL cannot be measured here, so ToH says it is not reported even when asked.
#[test]
fn the_statistics_summary_counts_loss_duplicates_and_transit_jitter() {
    let base = Instant::now();
    let mut xr = interceptor(&["stat-summary=loss,dup,jitt,TTL"]);
    // 1 to 5 every 20 ms, 4 arriving 10 ms late, a copy of 2, and 6 missing before 7.
    feed(
        &mut xr,
        base,
        &[
            (1, 0),
            (2, 20),
            (2, 21),
            (3, 40),
            (4, 70),
            (5, 80),
            (7, 120),
        ],
        1,
    );
    let report = report(&mut xr, base + ms(1_000)).expect("an XR");
    let summary = block::<StatisticsSummaryReportBlock>(&report);
    let summary = &summary[0];
    assert!(summary.loss_reports && summary.duplicate_reports && summary.jitter_reports);
    assert_eq!(TTLorHopLimitType::Missing, summary.ttl_or_hop_limit);
    assert_eq!((1, 8), (summary.begin_seq, summary.end_seq));
    assert_eq!(1, summary.lost_packets);
    assert_eq!(1, summary.dup_packets);
    // Transit differences in ticks: 0 (2), 0 (3), 80 (4 late), 80 (5 back), 0 (7).
    assert_eq!(0, summary.min_jitter);
    assert_eq!(80, summary.max_jitter);
    assert_eq!(32, summary.mean_jitter);
    assert_eq!(39, summary.dev_jitter);
    assert_eq!(0, summary.max_ttl_or_hl);
}

/// RFC 3611 section 4.6: a field the signalling did not ask for carries no report.
#[test]
fn the_statistics_summary_reports_only_the_fields_asked_for() {
    let base = Instant::now();
    let mut xr = interceptor(&["stat-summary=loss"]);
    feed(&mut xr, base, &ten_with_two_lost(), 10);
    let report = report(&mut xr, base + ms(1_000)).expect("an XR");
    let summary = &block::<StatisticsSummaryReportBlock>(&report)[0];
    assert!(summary.loss_reports);
    assert!(!summary.duplicate_reports && !summary.jitter_reports);
    assert_eq!(2, summary.lost_packets);
    assert_eq!(0, summary.max_jitter);
}

/// RFC 3611 section 4.7: the loss rate since the beginning of reception, the burst and gap
/// metrics, the round trip delay once there is an estimate, the end system delay 0 when
/// unknown, a constant non-zero Gmin and the jitter buffer the application described; the
/// rates and densities are zero before anything was lost.
#[test]
fn voip_metrics_are_populated_from_the_reception() {
    let base = Instant::now();
    let mut xr = XrReportBuilder::new()
        .with_formats(["voip-metrics"])
        .with_jitter_buffer(JitterBufferMetrics {
            adaptive: Some(true),
            rate: 4,
            nominal_ms: 40,
            maximum_ms: 120,
            absolute_maximum_ms: 200,
        })
        .build();
    xr.bind_remote_stream(&stream(&[]));
    let clean: Vec<(u16, u64)> = (0u16..50).map(|seq| (seq, u64::from(seq) * 20)).collect();
    feed(&mut xr, base, &clean, 0);
    let first = report(&mut xr, base + ms(1_000)).expect("an XR");
    let first = &block::<VoIPMetricsReportBlock>(&first)[0];
    assert_eq!(0, first.loss_rate);
    assert_eq!(0, first.discard_rate);
    assert_eq!((0, 0), (first.burst_density, first.gap_density));
    assert_eq!(0, first.burst_duration);
    assert_eq!(1_000, first.gap_duration, "50 packets of 20 ms");
    assert_eq!(0, first.round_trip_delay, "no estimate yet");
    assert_eq!(0, first.end_system_delay);
    assert_eq!(16, first.gmin);
    assert_eq!(0b0011_0100, first.rx_config, "adaptive, rate 4");
    assert_eq!(
        (40, 120, 200),
        (first.jb_nominal, first.jb_maximum, first.jb_abs_max)
    );
    assert_eq!(127, first.mos_lq, "not available");

    // The RTCP session measures a round trip time.
    xr.handle_read(TaggedPacket {
        now: base + ms(1_100),
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![])).with(crate::Attribute::Custom(
            std::sync::Arc::new(RtcpSessionEvent::RoundTripTime {
                ssrc: 9,
                rtt: ms(87),
            }),
        )),
    })
    .unwrap();
    while xr.poll_read().is_some() {}
    // 50 to 99 with a burst: 60, 61 and 63 lost.
    let lossy: Vec<(u16, u64)> = (50u16..100)
        .filter(|seq| ![60, 61, 63].contains(seq))
        .map(|seq| (seq, u64::from(seq) * 20))
        .collect();
    feed(&mut xr, base, &lossy, 0);
    let second = report(&mut xr, base + ms(2_000)).expect("an XR");
    let second = &block::<VoIPMetricsReportBlock>(&second)[0];
    assert_eq!(87, second.round_trip_delay);
    assert_eq!(16, second.gmin, "Gmin is constant across the session");
    // 3 lost of 100 expected since the beginning: 7.68, integer part 7.
    assert_eq!(7, second.loss_rate);
    // One burst, 60 to 63: 3 of 4 lost.
    assert_eq!(192, second.burst_density);
    assert_eq!(80, second.burst_duration);
    assert_eq!(0, second.gap_density);
    assert_eq!(960, second.gap_duration, "96 packets in two gaps");
}

/// RFC 3611 section 5.1: `pkt-loss-rle=<size>` is the largest size the block should have;
/// thinning brings it under (section 4.1).
#[test]
fn a_signalled_size_thins_the_block_until_it_fits() {
    let base = Instant::now();
    let mut xr = interceptor(&["pkt-loss-rle=16"]);
    // Every odd sequence number lost: at full resolution a bit vector each 15 packets.
    let packets: Vec<(u16, u64)> = (0u16..100)
        .filter(|seq| seq % 2 == 0)
        .map(|seq| (seq, u64::from(seq) * 20))
        .collect();
    feed(&mut xr, base, &packets, 0);
    let report = report(&mut xr, base + ms(3_000)).expect("an XR");
    let loss = &block::<RLEReportBlock>(&report)[0];
    assert!(loss.marshal_size() <= 16, "{loss:?}");
    assert_eq!(1, loss.t);
    assert!(
        loss.flags().iter().all(|f| *f),
        "the even numbers all arrived"
    );
}
