//! RTCP into the RTP stream statistics.
//!
//! The interceptor handler hands every RTCP compound packet that crosses it, in either
//! direction, to [`RTCStatsAccumulator::on_rtcp_received`] / [`RTCStatsAccumulator::on_rtcp_sent`].
//! What each packet means for the stats is decided here, next to the accumulators it updates.

use super::RTCStatsAccumulator;
use rtcp::extended_report::{
    DLRRReportBlock, EcnSummaryReportBlock, ExtendedReport, ReceiverReferenceTimeReportBlock,
};
use rtcp::header::{FORMAT_CCFB, PacketType};
use rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtcp::receiver_report::ReceiverReport;
use rtcp::reception_report::ReceptionReport;
use rtcp::sender_report::SenderReport;
use rtcp::transport_feedbacks::cc_feedback_report::CcFeedbackReport;
use rtcp::transport_feedbacks::ecn_feedback::EcnFeedback;
use rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack;
use std::time::Instant;

/// The reception report blocks a packet carries: an RR's, and an SR's too (RFC 3550 section
/// 6.4.1: a sender that also receives puts its report blocks in its SR).
fn reception_reports(packet: &dyn rtcp::Packet) -> &[ReceptionReport] {
    if let Some(rr) = packet.as_any().downcast_ref::<ReceiverReport>() {
        &rr.reports
    } else if let Some(sr) = packet.as_any().downcast_ref::<SenderReport>() {
        &sr.reports
    } else {
        &[]
    }
}

/// Whether the packet is RFC 8888 congestion control feedback (PT 205, FMT 11).
fn is_ccfb(packet: &dyn rtcp::Packet) -> bool {
    let header = packet.header();
    header.packet_type == PacketType::TransportSpecificFeedback && header.count == FORMAT_CCFB
}

impl RTCStatsAccumulator {
    /// Counts an incoming RTCP compound packet.
    ///
    /// * A sender report describes the remote sender of one of our inbound streams (the
    ///   remote-outbound object).
    /// * A reception report block, in an RR or an SR, describes how the remote receives one of
    ///   our outbound streams (the remote-inbound object): loss, jitter, and a round trip time
    ///   when it echoes one of our sender reports.
    /// * NACK, PLI and FIR are feedback about one of our outbound streams.
    /// * An XR DLRR sub-block (RFC 3611 section 4.5) answers a receiver reference time we sent
    ///   for one of our inbound streams: the remote-outbound object's round trip time.
    /// * An RFC 8888 report block describes, packet by packet, how the remote received one of
    ///   our outbound streams: ECN marks, losses and recoveries (the remote-inbound object).
    pub(crate) fn on_rtcp_received(&mut self, packets: &[Box<dyn rtcp::Packet>], now: Instant) {
        // The sender reports first, wherever they stand in the compound packet: a sender
        // report ends the round trip time its stream had (webrtc-stats 8.10: none "if the
        // latest SR does not contain the DLRR report block"), and the DLRR block that came
        // with it, before or after it in the compound, gives the new one below.
        for packet in packets {
            if let Some(sr) = packet.as_any().downcast_ref::<SenderReport>()
                && let Some(stream) = self.inbound_rtp_streams.get_mut(&sr.ssrc)
            {
                stream.on_rtcp_sr_received(
                    u64::from(sr.packet_count),
                    u64::from(sr.octet_count),
                    sr.ntp_time,
                    now,
                );
            }
        }

        for packet in packets {
            let packet = packet.as_ref();
            if is_ccfb(packet) {
                self.transport.on_ccfb_received();
            }

            if let Some(ccfb) = packet.as_any().downcast_ref::<CcFeedbackReport>() {
                for block in &ccfb.report_blocks {
                    if let Some(stream) = self.outbound_rtp_streams.get_mut(&block.media_ssrc) {
                        stream.on_ccfb_block_received(block, now);
                    }
                }
            }

            for report in reception_reports(packet) {
                if let Some(stream) = self.outbound_rtp_streams.get_mut(&report.ssrc) {
                    stream.on_receiver_report(report, now);
                }
            }

            if let Some(xr) = packet.as_any().downcast_ref::<ExtendedReport>() {
                for block in &xr.reports {
                    let Some(dlrr) = block.as_any().downcast_ref::<DLRRReportBlock>() else {
                        continue;
                    };
                    for sub in &dlrr.reports {
                        // A sub-block names the SSRC our reference time came from, which is the
                        // SSRC our receiver reports about the stream are sent from.
                        if let Some(stream) = self
                            .inbound_rtp_streams
                            .values_mut()
                            .find(|s| s.receiver_ssrc == Some(sub.ssrc))
                        {
                            stream.on_dlrr_received(sub.last_rr, sub.dlrr, now);
                        }
                    }
                }
            }

            if let Some(nack) = packet.as_any().downcast_ref::<TransportLayerNack>()
                && let Some(stream) = self.outbound_rtp_streams.get_mut(&nack.media_ssrc)
            {
                stream.on_nack_received();
            }

            // RFC 6679 sections 5.1 and 5.2: the receiver's ECN counters about one of our
            // outbound streams. An XR ECN Summary Report carries no sequence number; the
            // reception report about the same SSRC in the compound packet gives it.
            if let Some(feedback) = packet.as_any().downcast_ref::<EcnFeedback>()
                && let Some(stream) = self.outbound_rtp_streams.get_mut(&feedback.media_ssrc)
            {
                stream.on_ecn_counters_received(
                    feedback.extended_highest_sequence_number,
                    feedback.counters,
                    now,
                );
            }
            if let Some(xr) = packet.as_any().downcast_ref::<ExtendedReport>() {
                let summaries = xr
                    .reports
                    .iter()
                    .filter_map(|block| block.as_any().downcast_ref::<EcnSummaryReportBlock>())
                    .flat_map(|block| &block.reports);
                for summary in summaries {
                    let highest = packets
                        .iter()
                        .flat_map(|p| reception_reports(p.as_ref()))
                        .find(|report| report.ssrc == summary.ssrc)
                        .map(|report| report.last_sequence_number);
                    if let Some(highest) = highest
                        && let Some(stream) = self.outbound_rtp_streams.get_mut(&summary.ssrc)
                    {
                        stream.on_ecn_counters_received(highest, summary.counters, now);
                    }
                }
            }

            if let Some(pli) = packet.as_any().downcast_ref::<PictureLossIndication>()
                && let Some(stream) = self.outbound_rtp_streams.get_mut(&pli.media_ssrc)
            {
                stream.on_pli_received();
            }

            if let Some(fir) = packet.as_any().downcast_ref::<FullIntraRequest>() {
                for entry in &fir.fir {
                    if let Some(stream) = self.outbound_rtp_streams.get_mut(&entry.ssrc) {
                        stream.on_fir_received();
                    }
                }
            }
        }
    }

    /// Counts an outgoing RTCP compound packet.
    ///
    /// * A sender report for one of our outbound streams is remembered, so the reception report
    ///   that echoes it gives a round trip time.
    /// * A reception report block, in an RR or an SR, is what we tell the remote sender about
    ///   one of our inbound streams: its cumulative loss and jitter are the inbound object's.
    /// * NACK, PLI and FIR are feedback we send about one of our inbound streams.
    /// * An XR receiver reference time block (RFC 3611 section 4.4) is remembered for the
    ///   inbound stream whose receiver reports come from the same SSRC, so the DLRR that
    ///   echoes it gives a round trip time.
    /// * An RFC 8888 report block we send about one of our inbound streams counts the packets
    ///   it reports lost, and later recovered.
    pub(crate) fn on_rtcp_sent(&mut self, packets: &[Box<dyn rtcp::Packet>], now: Instant) {
        for packet in packets {
            let packet = packet.as_ref();
            if is_ccfb(packet) {
                self.transport.on_ccfb_sent();
            }

            if let Some(ccfb) = packet.as_any().downcast_ref::<CcFeedbackReport>() {
                for block in &ccfb.report_blocks {
                    if let Some(stream) = self.inbound_rtp_streams.get_mut(&block.media_ssrc) {
                        stream.on_ccfb_block_sent(block);
                    }
                }
            }

            if let Some(sr) = packet.as_any().downcast_ref::<SenderReport>()
                && let Some(stream) = self.outbound_rtp_streams.get_mut(&sr.ssrc)
            {
                stream.on_sender_report_sent(sr.ntp_time, now);
            }

            let reporter_ssrc = packet
                .as_any()
                .downcast_ref::<ReceiverReport>()
                .map(|rr| rr.ssrc)
                .or_else(|| {
                    packet
                        .as_any()
                        .downcast_ref::<SenderReport>()
                        .map(|sr| sr.ssrc)
                });
            for report in reception_reports(packet) {
                if let Some(stream) = self.inbound_rtp_streams.get_mut(&report.ssrc) {
                    stream.on_rtcp_rr_generated(i64::from(report.cumulative_lost()), report.jitter);
                    stream.receiver_ssrc = reporter_ssrc;
                }
            }

            if let Some(xr) = packet.as_any().downcast_ref::<ExtendedReport>() {
                for block in &xr.reports {
                    if let Some(rrtr) = block
                        .as_any()
                        .downcast_ref::<ReceiverReferenceTimeReportBlock>()
                        && let Some(stream) = self
                            .inbound_rtp_streams
                            .values_mut()
                            .find(|s| s.receiver_ssrc == Some(xr.sender_ssrc))
                    {
                        stream.on_reference_time_sent((rrtr.ntp_timestamp >> 16) as u32, now);
                    }
                }
            }

            if let Some(nack) = packet.as_any().downcast_ref::<TransportLayerNack>()
                && let Some(stream) = self.inbound_rtp_streams.get_mut(&nack.media_ssrc)
            {
                stream.on_nack_sent();
            }

            if let Some(pli) = packet.as_any().downcast_ref::<PictureLossIndication>()
                && let Some(stream) = self.inbound_rtp_streams.get_mut(&pli.media_ssrc)
            {
                stream.on_pli_sent();
            }

            if let Some(fir) = packet.as_any().downcast_ref::<FullIntraRequest>() {
                for entry in &fir.fir {
                    if let Some(stream) = self.inbound_rtp_streams.get_mut(&entry.ssrc) {
                        stream.on_fir_sent();
                    }
                }
            }
        }
    }
}
