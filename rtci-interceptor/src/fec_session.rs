//! The SSRCs of a FEC session of its own (RFC 5109 section 14.1), on the wire and in a chain.
//!
//! RFC 5109 section 7.2: "The SSRC value SHALL be the same as the SSRC value of the media
//! stream it protects", and section 14.1: "the FEC and the payload MUST NOT be multiplexed by
//! SSRC into one single RTP session since they always have the same SSRC". So a separate FEC
//! stream is a second RTP session, on a transport of its own, in which the media stream's
//! SSRC names the FEC stream.
//!
//! A chain serves every RTP session of a connection and keys what it keeps on the SSRC: the
//! buffers a NACK is answered from, the members of an RTCP session, the send history of a
//! congestion controller, the session a stream is in ([`PerRtpSession`](crate::PerRtpSession)).
//! One SSRC that is two streams cannot pass through it. [`FecSessionSsrcMap`] is the
//! boundary: inside the chain every SSRC of a FEC session is the wire SSRC XOR a key, and
//! whoever drives the chain applies the map to each RTP and RTCP packet of a FEC session's
//! transport, on the way in and on the way out. XOR with one key is its own inverse and maps
//! distinct SSRCs to distinct SSRCs, so the map needs no table: nothing a peer sends can make
//! it grow.
//!
//! The media stream names its FEC stream's chain SSRC in
//! [`StreamInfo::fec_session`](crate::StreamInfo::fec_session); the FEC stream is bound as a
//! stream of its own under that SSRC, in the FEC session.

use rtcp::extended_report::{DLRRReportBlock, ExtendedReport, ReceiverReferenceTimeReportBlock};
use rtcp::goodbye::Goodbye;
use rtcp::receiver_report::ReceiverReport;
use rtcp::sender_report::SenderReport;
use rtcp::source_description::SourceDescription;
use rtcp::transport_feedbacks::cc_feedback_report::CcFeedbackReport;
use rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;

/// Maps the SSRCs of a FEC session (RFC 5109 section 14.1) between the wire and the chain; see
/// the `fec_session` module's source documentation.
///
/// # Example
///
/// ```
/// use rtci_interceptor::FecSessionSsrcMap;
///
/// let map = FecSessionSsrcMap::new(0x5109_5109);
/// let media_ssrc = 0x1234_5678;
/// let in_chain = map.map(media_ssrc);
/// assert_ne!(in_chain, media_ssrc);
/// // The same map takes a packet in and out.
/// assert_eq!(map.map(in_chain), media_ssrc);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecSessionSsrcMap {
    key: u32,
}

impl FecSessionSsrcMap {
    /// A map with `key`. Zero would leave every SSRC as it is, the very collision the map is
    /// for, so it is replaced by 1.
    pub fn new(key: u32) -> Self {
        Self { key: key.max(1) }
    }

    /// A map with a random key.
    pub fn random() -> Self {
        Self::new(rand::random())
    }

    /// The key.
    pub fn key(&self) -> u32 {
        self.key
    }

    /// The chain's SSRC for a wire SSRC of the FEC session, and the wire SSRC for the chain's.
    pub fn map(&self, ssrc: u32) -> u32 {
        ssrc ^ self.key
    }

    /// Maps the SSRC of an RTP packet of the FEC session. A FEC packet has no CSRC list
    /// (RFC 5109 section 7.2 uses the fields "according to RFC 3550": a FEC packet is not a
    /// mixer's), and one that came with entries keeps them as they are.
    pub fn map_rtp(&self, packet: &mut rtp::Packet) {
        packet.header.ssrc = self.map(packet.header.ssrc);
    }

    /// Maps every SSRC of a compound RTCP packet of the FEC session: sender and receiver
    /// reports with their report blocks, source descriptions, goodbyes, transport-wide and
    /// RFC 8888 congestion control feedback, and the receiver reference time and DLRR blocks
    /// of an extended report.
    ///
    /// Any other packet is left out of the result: feedback about pictures, bit rates or
    /// retransmission has no meaning for a FEC stream, and a packet passed on with its SSRCs
    /// unmapped would name another stream of the connection. An extended report keeps the
    /// blocks named above and is left out when none remains.
    pub fn map_rtcp(&self, packets: &[Box<dyn rtcp::Packet>]) -> Vec<Box<dyn rtcp::Packet>> {
        packets
            .iter()
            .filter_map(|packet| self.map_rtcp_packet(packet.as_ref()))
            .collect()
    }

    fn map_rtcp_packet(&self, packet: &dyn rtcp::Packet) -> Option<Box<dyn rtcp::Packet>> {
        let any = packet.as_any();
        if let Some(report) = any.downcast_ref::<SenderReport>() {
            let mut report = report.clone();
            report.ssrc = self.map(report.ssrc);
            for block in &mut report.reports {
                block.ssrc = self.map(block.ssrc);
            }
            return Some(Box::new(report));
        }
        if let Some(report) = any.downcast_ref::<ReceiverReport>() {
            let mut report = report.clone();
            report.ssrc = self.map(report.ssrc);
            for block in &mut report.reports {
                block.ssrc = self.map(block.ssrc);
            }
            return Some(Box::new(report));
        }
        if let Some(description) = any.downcast_ref::<SourceDescription>() {
            let mut description = description.clone();
            for chunk in &mut description.chunks {
                chunk.source = self.map(chunk.source);
            }
            return Some(Box::new(description));
        }
        if let Some(goodbye) = any.downcast_ref::<Goodbye>() {
            let mut goodbye = goodbye.clone();
            for source in &mut goodbye.sources {
                *source = self.map(*source);
            }
            return Some(Box::new(goodbye));
        }
        if let Some(feedback) = any.downcast_ref::<TransportLayerCc>() {
            let mut feedback = feedback.clone();
            feedback.sender_ssrc = self.map(feedback.sender_ssrc);
            feedback.media_ssrc = self.map(feedback.media_ssrc);
            return Some(Box::new(feedback));
        }
        if let Some(feedback) = any.downcast_ref::<CcFeedbackReport>() {
            let mut feedback = feedback.clone();
            feedback.sender_ssrc = self.map(feedback.sender_ssrc);
            for block in &mut feedback.report_blocks {
                block.media_ssrc = self.map(block.media_ssrc);
            }
            return Some(Box::new(feedback));
        }
        if let Some(report) = any.downcast_ref::<ExtendedReport>() {
            let mut blocks: Vec<Box<dyn rtcp::Packet>> = Vec::new();
            for block in &report.reports {
                let any = block.as_any();
                if any
                    .downcast_ref::<ReceiverReferenceTimeReportBlock>()
                    .is_some()
                {
                    blocks.push(block.clone());
                } else if let Some(dlrr) = any.downcast_ref::<DLRRReportBlock>() {
                    let mut dlrr = dlrr.clone();
                    for report in &mut dlrr.reports {
                        report.ssrc = self.map(report.ssrc);
                    }
                    blocks.push(Box::new(dlrr));
                }
            }
            if blocks.is_empty() {
                return None;
            }
            return Some(Box::new(ExtendedReport {
                sender_ssrc: self.map(report.sender_ssrc),
                reports: blocks,
            }));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtcp::extended_report::DLRRReport;
    use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
    use rtcp::reception_report::ReceptionReport;
    use rtcp::source_description::{SdesType, SourceDescriptionChunk, SourceDescriptionItem};
    use rtcp::transport_feedbacks::cc_feedback_report::CcFeedbackReportBlock;

    const KEY: u32 = 0x5109_0141;
    const MEDIA: u32 = 0x1111_2222;
    const PEER: u32 = 0x3333_4444;

    fn downcast<T: Clone + 'static>(packet: &dyn rtcp::Packet) -> T {
        packet
            .as_any()
            .downcast_ref::<T>()
            .expect("the packet keeps its type")
            .clone()
    }

    #[test]
    fn the_map_is_its_own_inverse_and_never_the_identity() {
        for key in [0, 1, KEY, u32::MAX] {
            let map = FecSessionSsrcMap::new(key);
            for ssrc in [0, 1, MEDIA, PEER, u32::MAX] {
                assert_ne!(map.map(ssrc), ssrc, "key {key:#x}");
                assert_eq!(map.map(map.map(ssrc)), ssrc, "key {key:#x}");
            }
        }
        assert_eq!(
            FecSessionSsrcMap::new(0).key(),
            1,
            "a zero key maps nothing"
        );
        assert_ne!(FecSessionSsrcMap::random().key(), 0);
    }

    #[test]
    fn distinct_ssrcs_stay_distinct() {
        let map = FecSessionSsrcMap::new(KEY);
        assert_ne!(map.map(MEDIA), map.map(PEER));
        assert_eq!(map.map(MEDIA), MEDIA ^ KEY);
    }

    #[test]
    fn an_rtp_packet_changes_only_its_ssrc() {
        let map = FecSessionSsrcMap::new(KEY);
        let original = rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 100,
                sequence_number: 7,
                timestamp: 9,
                ssrc: MEDIA,
                ..Default::default()
            },
            payload: bytes::Bytes::from_static(&[1, 2, 3]),
        };
        let mut packet = original.clone();
        map.map_rtp(&mut packet);
        assert_eq!(packet.header.ssrc, MEDIA ^ KEY);
        packet.header.ssrc = MEDIA;
        assert_eq!(packet, original);
    }

    #[test]
    fn every_ssrc_of_the_reports_of_a_session_is_mapped() {
        let map = FecSessionSsrcMap::new(KEY);
        let block = ReceptionReport {
            ssrc: PEER,
            fraction_lost: 3,
            ..Default::default()
        };
        let compound: Vec<Box<dyn rtcp::Packet>> = vec![
            Box::new(SenderReport {
                ssrc: MEDIA,
                packet_count: 5,
                reports: vec![block.clone()],
                ..Default::default()
            }),
            Box::new(ReceiverReport {
                ssrc: MEDIA,
                reports: vec![block],
                ..Default::default()
            }),
            Box::new(SourceDescription {
                chunks: vec![SourceDescriptionChunk {
                    source: MEDIA,
                    items: vec![SourceDescriptionItem {
                        sdes_type: SdesType::SdesCname,
                        text: bytes::Bytes::from_static(b"cname"),
                    }],
                }],
            }),
            Box::new(Goodbye {
                sources: vec![MEDIA, PEER],
                ..Default::default()
            }),
            Box::new(TransportLayerCc {
                sender_ssrc: PEER,
                media_ssrc: MEDIA,
                ..Default::default()
            }),
            Box::new(CcFeedbackReport {
                sender_ssrc: PEER,
                report_blocks: vec![CcFeedbackReportBlock {
                    media_ssrc: MEDIA,
                    ..Default::default()
                }],
                report_timestamp: 1,
            }),
            Box::new(ExtendedReport {
                sender_ssrc: PEER,
                reports: vec![
                    Box::new(ReceiverReferenceTimeReportBlock { ntp_timestamp: 9 }),
                    Box::new(DLRRReportBlock {
                        reports: vec![DLRRReport {
                            ssrc: MEDIA,
                            last_rr: 1,
                            dlrr: 2,
                        }],
                    }),
                ],
            }),
        ];
        let mapped = map.map_rtcp(&compound);
        assert_eq!(mapped.len(), compound.len());

        let sr: SenderReport = downcast(mapped[0].as_ref());
        assert_eq!((sr.ssrc, sr.reports[0].ssrc), (MEDIA ^ KEY, PEER ^ KEY));
        assert_eq!((sr.packet_count, sr.reports[0].fraction_lost), (5, 3));
        let rr: ReceiverReport = downcast(mapped[1].as_ref());
        assert_eq!((rr.ssrc, rr.reports[0].ssrc), (MEDIA ^ KEY, PEER ^ KEY));
        let sdes: SourceDescription = downcast(mapped[2].as_ref());
        assert_eq!(sdes.chunks[0].source, MEDIA ^ KEY);
        assert_eq!(&sdes.chunks[0].items[0].text[..], b"cname");
        let bye: Goodbye = downcast(mapped[3].as_ref());
        assert_eq!(bye.sources, vec![MEDIA ^ KEY, PEER ^ KEY]);
        let twcc: TransportLayerCc = downcast(mapped[4].as_ref());
        assert_eq!(
            (twcc.sender_ssrc, twcc.media_ssrc),
            (PEER ^ KEY, MEDIA ^ KEY)
        );
        let ccfb: CcFeedbackReport = downcast(mapped[5].as_ref());
        assert_eq!(
            (ccfb.sender_ssrc, ccfb.report_blocks[0].media_ssrc),
            (PEER ^ KEY, MEDIA ^ KEY)
        );
        let xr: ExtendedReport = downcast(mapped[6].as_ref());
        assert_eq!(xr.sender_ssrc, PEER ^ KEY);
        assert_eq!(xr.reports.len(), 2);
        let dlrr: DLRRReportBlock = downcast(xr.reports[1].as_ref());
        assert_eq!(dlrr.reports[0].ssrc, MEDIA ^ KEY);

        // And back: what the chain wrote is what the wire carries.
        let back = map.map_rtcp(&mapped);
        assert_eq!(back.len(), compound.len());
        for (back, original) in back.iter().zip(&compound) {
            assert!(back.equal(original.as_ref()), "{back} != {original}");
        }
    }

    #[test]
    fn rtcp_with_no_meaning_for_a_fec_stream_is_left_out() {
        let map = FecSessionSsrcMap::new(KEY);
        let compound: Vec<Box<dyn rtcp::Packet>> = vec![
            Box::new(ReceiverReport {
                ssrc: PEER,
                ..Default::default()
            }),
            Box::new(PictureLossIndication {
                sender_ssrc: PEER,
                media_ssrc: MEDIA,
            }),
        ];
        let mapped = map.map_rtcp(&compound);
        assert_eq!(mapped.len(), 1, "the picture loss indication is dropped");
        let rr: ReceiverReport = downcast(mapped[0].as_ref());
        assert_eq!(rr.ssrc, PEER ^ KEY);
    }
}
