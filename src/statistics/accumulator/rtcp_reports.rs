//! RTCP into the RTP stream statistics.
//!
//! The interceptor handler hands every RTCP compound packet that crosses it, in either
//! direction, to [`RTCStatsAccumulator::on_rtcp_received`] / [`RTCStatsAccumulator::on_rtcp_sent`].
//! What each packet means for the stats is decided here, next to the accumulators it updates.

use super::RTCStatsAccumulator;
use super::rtp_stream::cumulative_lost;
use rtcp::header::{FORMAT_CCFB, PacketType};
use rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtcp::receiver_report::ReceiverReport;
use rtcp::reception_report::ReceptionReport;
use rtcp::sender_report::SenderReport;
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
    pub(crate) fn on_rtcp_received(&mut self, packets: &[Box<dyn rtcp::Packet>], now: Instant) {
        for packet in packets {
            let packet = packet.as_ref();
            if is_ccfb(packet) {
                self.transport.on_ccfb_received();
            }

            if let Some(sr) = packet.as_any().downcast_ref::<SenderReport>()
                && let Some(stream) = self.inbound_rtp_streams.get_mut(&sr.ssrc)
            {
                stream.on_rtcp_sr_received(
                    u64::from(sr.packet_count),
                    u64::from(sr.octet_count),
                    now,
                );
            }

            for report in reception_reports(packet) {
                if let Some(stream) = self.outbound_rtp_streams.get_mut(&report.ssrc) {
                    stream.on_receiver_report(report, now);
                }
            }

            if let Some(nack) = packet.as_any().downcast_ref::<TransportLayerNack>()
                && let Some(stream) = self.outbound_rtp_streams.get_mut(&nack.media_ssrc)
            {
                stream.on_nack_received();
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
    pub(crate) fn on_rtcp_sent(&mut self, packets: &[Box<dyn rtcp::Packet>], now: Instant) {
        for packet in packets {
            let packet = packet.as_ref();
            if is_ccfb(packet) {
                self.transport.on_ccfb_sent();
            }

            if let Some(sr) = packet.as_any().downcast_ref::<SenderReport>()
                && let Some(stream) = self.outbound_rtp_streams.get_mut(&sr.ssrc)
            {
                stream.on_sender_report_sent(sr.ntp_time, now);
            }

            for report in reception_reports(packet) {
                if let Some(stream) = self.inbound_rtp_streams.get_mut(&report.ssrc) {
                    stream.on_rtcp_rr_generated(cumulative_lost(report.total_lost), report.jitter);
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
