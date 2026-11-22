//! The per-SSRC stats maps shrink when a stream goes, and hold one RTX / FEC entry per stream.

use super::RTCStatsAccumulator;
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use std::collections::HashSet;
use std::time::Instant;

fn inbound(stats: &mut RTCStatsAccumulator, ssrc: u32, rtx: Option<u32>, fec: Option<u32>) {
    stats.get_or_create_inbound_rtp_streams(ssrc, RtpCodecKind::Video, "t", "0", rtx, fec, 0);
}

/// A stream's RTX SSRC that keeps changing (a peer re-announcing its repair stream) leaves one
/// reverse entry, not one per announcement; packets on a replaced RTX SSRC are no longer
/// counted as the stream's retransmissions.
#[test]
fn a_changing_rtx_ssrc_leaves_one_reverse_entry() {
    let mut stats = RTCStatsAccumulator::new();
    inbound(&mut stats, 1, Some(2), None);
    for rtx in 1_000..2_000 {
        stats.update_inbound_rtx_ssrc(1, rtx);
    }
    assert_eq!(stats.inbound_rtx_ssrc_to_primary.len(), 1);
    let now = Instant::now();
    assert!(stats.on_rtp_received(1_999, 22, 0, now));
    assert!(!stats.on_rtp_received(2, 22, 0, now));
    assert!(!stats.on_rtp_received(1_000, 22, 0, now));
    assert_eq!(stats.inbound_rtp_streams[&1].rtx_ssrc, Some(1_999));
}

/// Removing a stream removes its reverse entries with it.
#[test]
fn removing_a_stream_removes_its_reverse_entries() {
    let mut stats = RTCStatsAccumulator::new();
    inbound(&mut stats, 1, Some(2), Some(3));
    inbound(&mut stats, 4, Some(5), None);
    stats.get_or_create_outbound_rtp_streams(6, RtpCodecKind::Video, "0", "", 0, Some(7), 0);

    stats.remove_inbound_rtp_stream(1);
    assert!(!stats.inbound_rtp_streams.contains_key(&1));
    assert!(!stats.inbound_rtx_ssrc_to_primary.contains_key(&2));
    assert!(!stats.fec_ssrc_to_primary.contains_key(&3));
    assert!(
        stats.on_rtp_received(5, 22, 0, Instant::now()),
        "another stream's entry stays"
    );

    stats.remove_outbound_rtp_stream(6);
    assert!(stats.outbound_rtp_streams.is_empty());
    assert!(stats.outbound_rtx_ssrc_to_primary.is_empty());
}

/// Streams whose SSRC is no longer bound are retired: 10,000 SSRCs that came and went leave
/// nothing behind, while the bound ones keep their counters.
#[test]
fn unbound_streams_are_retired() {
    let mut stats = RTCStatsAccumulator::new();
    for ssrc in 0..10_000u32 {
        inbound(&mut stats, ssrc, Some(ssrc + 100_000), Some(ssrc + 200_000));
    }
    stats.get_or_create_outbound_rtp_streams(
        500_000,
        RtpCodecKind::Video,
        "0",
        "",
        0,
        Some(500_001),
        0,
    );
    stats
        .inbound_rtp_streams
        .get_mut(&7)
        .unwrap()
        .on_rtx_received(10);

    let inbound_live: HashSet<u32> = [7].into_iter().collect();
    stats.retire_rtp_streams(&inbound_live, &HashSet::new());

    assert_eq!(stats.inbound_rtp_streams.len(), 1);
    assert_eq!(
        stats.inbound_rtp_streams[&7].retransmitted_packets_received,
        1
    );
    assert_eq!(stats.inbound_rtx_ssrc_to_primary.len(), 1);
    assert_eq!(stats.fec_ssrc_to_primary.len(), 1);
    assert!(stats.outbound_rtp_streams.is_empty());
    assert!(stats.outbound_rtx_ssrc_to_primary.is_empty());
}

/// The remote's SSRCs and ours are chosen independently: an inbound RTX SSRC equal to an
/// outbound one must not take over the other's attribution.
#[test]
fn inbound_and_outbound_rtx_ssrcs_do_not_collide() {
    let mut stats = RTCStatsAccumulator::new();
    stats.get_or_create_outbound_rtp_streams(10, RtpCodecKind::Video, "0", "", 0, Some(99), 0);
    inbound(&mut stats, 20, Some(99), None);

    // A retransmission going out on our RTX SSRC 99: 2 bytes of original sequence number and
    // 100 of the packet it repeats. A padding-only packet coming in on the remote's RTX SSRC,
    // also 99.
    let now = Instant::now();
    stats.on_rtp_sent(99, 1, 12, 102, false, now);
    assert!(stats.on_rtp_received(99, 62, 0, now));
    let outbound = &stats.outbound_rtp_streams[&10];
    assert_eq!(outbound.retransmitted_packets_sent, 1);
    assert_eq!(outbound.retransmitted_bytes_sent, 100);
    assert_eq!(
        (outbound.packets_sent, outbound.bytes_sent),
        (1, 100),
        "the RTX packet is a packet of the stream, and its retransmission a subset of it"
    );
    assert_eq!(outbound.header_bytes_sent, 14);
    let inbound = &stats.inbound_rtp_streams[&20];
    assert_eq!(inbound.packets_received, 1);
    assert_eq!(inbound.header_bytes_received, 62);
    assert_eq!(inbound.retransmitted_packets_received, 0);
}
