//! The loss-driven FEC rate in a chain: the receiver's reported loss sets how many repair
//! packets each block gets, none when nothing is lost (draft-ietf-payload-flexible-fec-scheme-03
//! section 8, RFC 8627 section 8, RFC 5109 section 12), and the FEC sent is taken out of the
//! congestion controller's target on its way to the application, so media and FEC together
//! stay at the target.

use rtci_interceptor::{
    Attribute, AttributedPacket, FlexFec03SendBuilder, FlexFecProtection, FlexFecSendBuilder,
    Interceptor, Packet, Registry, Slot, StreamInfo, TaggedPacket, UlpfecSendBuilder,
};
use rtcp::receiver_report::ReceiverReport;
use rtcp::reception_report::ReceptionReport;
use sansio::Protocol;
use shared::TransportContext;
use std::time::{Duration, Instant};

const MEDIA_SSRC: u32 = 1000;
const REPAIR_SSRC: u32 = 2000;
const MEDIA_PT: u8 = 96;
const REPAIR_PT: u8 = 98;

fn stream(mime_type_fec: &str) -> StreamInfo {
    StreamInfo {
        ssrc: MEDIA_SSRC,
        ssrc_fec: Some(REPAIR_SSRC),
        payload_type: MEDIA_PT,
        payload_type_fec: Some(REPAIR_PT),
        mime_type: "video/VP8".to_owned(),
        mime_type_fec: mime_type_fec.to_owned(),
        sdp_fmtp_line_fec: "repair-window=200000".to_owned(),
        clock_rate: 90_000,
        ..Default::default()
    }
}

struct Harness {
    chain: Box<dyn Interceptor>,
    epoch: Instant,
    next_seq: u16,
}

impl Harness {
    fn new(chain: Box<dyn Interceptor>, info: &StreamInfo) -> Self {
        let mut harness = Self {
            chain,
            epoch: Instant::now(),
            next_seq: 0,
        };
        harness.chain.bind_local_stream(info);
        harness
    }

    /// Sends `count` media packets 10 ms apart from `at_ms`; returns (media, repair) packets
    /// that came out and their repair octets.
    fn send(&mut self, at_ms: u64, count: u16) -> (usize, usize, usize) {
        let (mut media, mut repair, mut octets) = (0, 0, 0);
        for n in 0..count {
            let seq = self.next_seq;
            self.next_seq = self.next_seq.wrapping_add(1);
            self.chain
                .handle_write(TaggedPacket {
                    now: self.epoch + Duration::from_millis(at_ms + u64::from(n) * 10),
                    transport: TransportContext::default(),
                    message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                        header: rtp::header::Header {
                            version: 2,
                            payload_type: MEDIA_PT,
                            sequence_number: seq,
                            timestamp: u32::from(seq) * 3000,
                            ssrc: MEDIA_SSRC,
                            ..Default::default()
                        },
                        payload: vec![0x55u8; 1000].into(),
                    })),
                })
                .unwrap();
            while let Some(out) = self.chain.poll_write() {
                if let Packet::Rtp(rtp) = &out.message.packet {
                    if rtp.header.ssrc == MEDIA_SSRC {
                        media += 1;
                    } else {
                        repair += 1;
                        octets += rtp.payload.len();
                    }
                }
            }
        }
        (media, repair, octets)
    }

    /// The receiver's report on the media stream: `fraction_lost` in 1/256.
    fn report(&mut self, at_ms: u64, fraction_lost: u8) {
        self.chain
            .handle_read(TaggedPacket {
                now: self.epoch + Duration::from_millis(at_ms),
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(ReceiverReport {
                    ssrc: 0x7777,
                    reports: vec![ReceptionReport {
                        ssrc: MEDIA_SSRC,
                        fraction_lost,
                        ..Default::default()
                    }],
                    ..Default::default()
                })])),
            })
            .unwrap();
        while self.chain.poll_read().is_some() {}
    }

    /// The target the application is told when the congestion controller announces
    /// `bits_per_second` at `at_ms`.
    fn target_seen(&mut self, at_ms: u64, bits_per_second: f64) -> f64 {
        self.chain
            .handle_read(TaggedPacket {
                now: self.epoch + Duration::from_millis(at_ms),
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![]))
                    .with(Attribute::TargetBitrateChanged { bits_per_second }),
            })
            .unwrap();
        let mut seen = None;
        while let Some(msg) = self.chain.poll_read() {
            for attribute in &msg.message.attributes {
                if let Attribute::TargetBitrateChanged { bits_per_second } = attribute {
                    seen = Some(*bits_per_second);
                }
            }
        }
        seen.expect("the target is passed on")
    }
}

fn flexfec03(adaptive: bool) -> Box<dyn Interceptor> {
    Box::new(
        Registry::new()
            .with(
                Slot::FecEncoder,
                FlexFec03SendBuilder::new()
                    .with_num_media_packets(10)
                    .with_num_fec_packets(1)
                    .with_adaptive_rate(adaptive)
                    .build(),
            )
            .build(),
    )
}

/// draft-03 section 8: "SHOULD" not send repair that would not help, and adjust the amount
/// of FEC to the loss. Before any report the configured amount goes (one per ten); a report of
/// no loss stops the repair; 20% loss raises it to four per ten; the bound is half the block.
#[test]
fn the_receivers_loss_sets_how_much_flexfec_is_sent() {
    let mut h = Harness::new(flexfec03(true), &stream("video/flexfec-03"));
    assert_eq!(h.send(0, 100).1, 10, "configured: one per block of ten");

    h.report(1000, 0);
    assert_eq!(h.send(1000, 100).1, 0, "no loss, no repair");

    // Smoothed over reports (weight 0.3): after the report of no loss, four of 20%.
    for n in 0..4 {
        h.report(2000 + n, 51);
    }
    let (media, repair, _) = h.send(2000, 100);
    assert_eq!(media, 100);
    assert_eq!(repair, 40, "four per block of ten at 20% loss");

    h.report(3000, 230); // 90%
    assert_eq!(h.send(3000, 100).1, 50, "at most half the block");
}

/// `with_adaptive_rate(false)`: the configured amount whatever the loss.
#[test]
fn a_fixed_flexfec_rate_ignores_the_loss() {
    let mut h = Harness::new(flexfec03(false), &stream("video/flexfec-03"));
    h.report(0, 0);
    assert_eq!(h.send(0, 100).1, 10);
    h.report(1000, 128);
    assert_eq!(h.send(1000, 100).1, 10);
}

/// RFC 5109 section 12: FEC "MUST NOT substantially increase the total bandwidth (media and
/// FEC) as network loss increases". The repair bit rate of the last second is taken out of the
/// target the application encodes at, so the media gives way to the FEC.
#[test]
fn the_fec_bit_rate_is_taken_out_of_the_target_the_application_sees() {
    let mut h = Harness::new(flexfec03(true), &stream("video/flexfec-03"));
    h.report(0, 51);
    h.report(1, 51);
    h.report(2, 51);
    let (_, repair, octets) = h.send(0, 100);
    assert!(repair > 0);
    let seen = h.target_seen(990, 2_000_000.0);
    let fec_bps = octets as f64 * 8.0;
    assert!(
        seen < 2_000_000.0 - 0.8 * fec_bps && seen > 2_000_000.0 - 1.5 * fec_bps,
        "the target loses the repair rate: {seen} ({fec_bps} bit/s of FEC)"
    );
    // Without FEC in the last second, the target passes as it is.
    h.report(1000, 0);
    assert_eq!(h.target_seen(3000, 2_000_000.0), 2_000_000.0);
}

/// RFC 8627 section 8 ("SHOULD [...] adjust the amount [...] of FEC from the observed loss
/// rate"): flexible masks get as many repair packets as the loss asks for.
#[test]
fn the_receivers_loss_sets_how_much_rfc_8627_flexfec_is_sent() {
    let chain = Box::new(
        Registry::new()
            .with(
                Slot::FecEncoder,
                FlexFecSendBuilder::new()
                    .with_protection(FlexFecProtection::Mask {
                        media_packets: 10,
                        fec_packets: 1,
                    })
                    .build(),
            )
            .build(),
    );
    let mut h = Harness::new(chain, &stream("video/flexfec"));
    assert_eq!(h.send(0, 100).1, 10);
    h.report(1000, 0);
    assert_eq!(h.send(1000, 100).1, 0);
    // Smoothed over reports (weight 0.3): after the report of no loss, four of 20%.
    for n in 0..4 {
        h.report(2000 + n, 51);
    }
    assert_eq!(h.send(2000, 100).1, 40);
}

/// RFC 5109 section 12: "users of this payload format MUST monitor packet loss": ULPFEC (here
/// in its own stream) follows the reported loss the same way.
#[test]
fn the_receivers_loss_sets_how_much_ulpfec_is_sent() {
    let chain = Box::new(
        Registry::new()
            .with(
                Slot::FecEncoder,
                UlpfecSendBuilder::stream()
                    .with_num_media_packets(10)
                    .with_num_fec_packets(1)
                    .build(),
            )
            .build(),
    );
    let mut h = Harness::new(chain, &stream("video/ulpfec"));
    assert_eq!(h.send(0, 100).1, 10);
    h.report(1000, 0);
    assert_eq!(h.send(1000, 100).1, 0);
    // Smoothed over reports (weight 0.3): after the report of no loss, four of 20%.
    for n in 0..4 {
        h.report(2000 + n, 51);
    }
    assert_eq!(h.send(2000, 100).1, 40);
}
