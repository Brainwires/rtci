//! A loss-driven FEC rate, shared by the FEC senders (FlexFEC draft-03, RFC 8627 FlexFEC,
//! ULPFEC), and the FEC overhead taken out of the target the application encodes at.
//!
//! * draft-ietf-payload-flexible-fec-scheme-03 section 8: repair flows "SHOULD" not be sent
//!   when they would not help recover anything, and the amount of FEC is adjusted to the loss
//!   observed; RFC 8627 section 8 likewise ("SHOULD [...] adjust the amount [...] of FEC from
//!   the observed loss rate"); RFC 5109 section 12: users of the format "MUST" monitor packet
//!   loss, and FEC "MUST NOT substantially increase the total bandwidth (media and FEC) as
//!   network loss increases".
//! * The loss is the protected stream's, as its receiver reports it (RFC 3550 6.4.1 fraction
//!   lost, which counts what the path lost, not what FEC rebuilt), smoothed over reports.
//! * The repair packets per block follow it: enough for twice the measured loss
//!   (`ceil(2 * loss * media packets)`), none under [`MIN_LOSS`], at most [`FecRate::max`]
//!   (half the block by default). Before any report the configured amount is sent.
//! * The FEC sent is taken out of the congestion controller's target on its way to the
//!   application ([`FecRate::media_target`]): the bit rate of the repair packets of the last
//!   second is subtracted, so media and FEC together stay at the target however the loss
//!   moves (RFC 5109 section 12), and the controller, which counts the repair packets on the
//!   wire, is not overrun.

use crate::{Attribute, Packet, TaggedPacket};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Smoothed loss under which no repair packet is sent: it would not help recover anything.
pub const MIN_LOSS: f64 = 0.005;
/// Weight of a new report in the smoothed loss.
const LOSS_WEIGHT: f64 = 0.3;
/// The window the FEC bit rate is measured over.
const RATE_WINDOW: Duration = Duration::from_secs(1);

/// The loss-driven amount of FEC for one sender. See the module documentation.
#[derive(Debug, Clone)]
pub struct FecRate {
    media_packets: u32,
    configured: u32,
    max: u32,
    adaptive: bool,
    loss: Option<f64>,
    /// Repair packets sent in the last [`RATE_WINDOW`]: when and how many octets.
    sent: VecDeque<(Instant, usize)>,
}

impl FecRate {
    /// `fec_packets` repair packets per `media_packets` source packets until the loss is known;
    /// `adaptive` false keeps that amount whatever the loss.
    pub fn new(media_packets: u32, fec_packets: u32, adaptive: bool) -> Self {
        let media_packets = media_packets.max(1);
        Self {
            media_packets,
            configured: fec_packets,
            max: media_packets.div_ceil(2).max(fec_packets),
            adaptive,
            loss: None,
            sent: VecDeque::new(),
        }
    }

    /// The most repair packets per block, whatever the loss.
    pub fn with_max(mut self, max: u32) -> Self {
        self.max = max;
        self
    }

    /// The most repair packets per block.
    pub fn max(&self) -> u32 {
        self.max
    }

    /// The smoothed loss fraction, once a report gave one.
    pub fn loss(&self) -> Option<f64> {
        self.loss
    }

    /// A receiver report's fraction lost (RFC 3550 6.4.1, in 1/256) for a protected stream.
    pub fn on_fraction_lost(&mut self, fraction_lost: u8) {
        let sample = f64::from(fraction_lost) / 256.0;
        self.loss = Some(match self.loss {
            Some(loss) => (1.0 - LOSS_WEIGHT) * loss + LOSS_WEIGHT * sample,
            None => sample,
        });
    }

    /// Repair packets for the next block.
    pub fn fec_packets(&self) -> u32 {
        match self.loss {
            Some(loss) if self.adaptive => {
                if loss < MIN_LOSS {
                    0
                } else {
                    // At least one, unless the bound allows none (`clamp` would panic on it).
                    ((2.0 * loss * f64::from(self.media_packets)).ceil() as u32)
                        .max(1)
                        .min(self.max)
                }
            }
            _ => self.configured,
        }
    }

    /// Whether any repair is to be sent now (for protection shapes whose amount is fixed:
    /// sent or not).
    pub fn protects(&self) -> bool {
        self.fec_packets() > 0
    }

    /// A repair packet of `size` octets left at `now`.
    pub fn on_repair_sent(&mut self, now: Instant, size: usize) {
        self.sent.push_back((now, size));
        self.expire(now);
    }

    fn expire(&mut self, now: Instant) {
        while self
            .sent
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) > RATE_WINDOW)
        {
            self.sent.pop_front();
        }
    }

    /// The bit rate of the repair packets of the last second at `now`.
    pub fn fec_bitrate(&mut self, now: Instant) -> f64 {
        self.expire(now);
        self.sent
            .iter()
            .map(|(_, size)| *size as f64 * 8.0)
            .sum::<f64>()
            / RATE_WINDOW.as_secs_f64()
    }

    /// The target the application encodes at, out of the congestion controller's `target`:
    /// what is left after the FEC.
    pub fn media_target(&mut self, now: Instant, target: f64) -> f64 {
        (target - self.fec_bitrate(now)).max(0.0)
    }

    /// Reads what an inbound packet tells the FEC rate, and takes the FEC out of a target it
    /// carries: the receiver reports of `protected` streams feed the loss, and an
    /// [`Attribute::TargetBitrateChanged`] on the packet is lowered by the FEC bit rate.
    pub fn on_read(&mut self, msg: &mut TaggedPacket, protected: impl Fn(u32) -> bool) {
        if let Packet::Rtcp(packets) = &msg.message.packet {
            for packet in packets {
                let any = packet.as_any();
                let reports = if let Some(rr) =
                    any.downcast_ref::<rtcp::receiver_report::ReceiverReport>()
                {
                    &rr.reports
                } else if let Some(sr) = any.downcast_ref::<rtcp::sender_report::SenderReport>() {
                    &sr.reports
                } else {
                    continue;
                };
                for report in reports {
                    if protected(report.ssrc) {
                        self.on_fraction_lost(report.fraction_lost);
                    }
                }
            }
        }
        let now = msg.now;
        let fec = self.fec_bitrate(now);
        if fec > 0.0 {
            for attribute in &mut msg.message.attributes {
                if let Attribute::TargetBitrateChanged { bits_per_second } = attribute {
                    *bits_per_second = (*bits_per_second - fec).max(0.0);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn before_any_report_the_configured_amount_is_sent() {
        assert_eq!(FecRate::new(10, 1, true).fec_packets(), 1);
        assert_eq!(FecRate::new(5, 2, true).fec_packets(), 2);
    }

    #[test]
    fn no_loss_means_no_repair_and_more_loss_more_repair_up_to_the_bound() {
        let mut rate = FecRate::new(10, 1, true);
        rate.on_fraction_lost(0);
        assert_eq!(
            rate.fec_packets(),
            0,
            "repair that helps nothing is not sent"
        );
        let mut rate = FecRate::new(10, 1, true);
        rate.on_fraction_lost(5); // 2%
        assert_eq!(rate.fec_packets(), 1);
        let mut rate = FecRate::new(10, 1, true);
        rate.on_fraction_lost(13); // 5%
        assert_eq!(rate.fec_packets(), 2);
        let mut rate = FecRate::new(10, 1, true);
        rate.on_fraction_lost(51); // 20%
        assert_eq!(rate.fec_packets(), 4);
        let mut rate = FecRate::new(10, 1, true);
        rate.on_fraction_lost(200); // 78%
        assert_eq!(rate.fec_packets(), 5, "at most half the block");
    }

    #[test]
    fn the_loss_is_smoothed_over_reports() {
        let mut rate = FecRate::new(10, 1, true);
        rate.on_fraction_lost(51);
        rate.on_fraction_lost(0);
        let loss = rate.loss().unwrap();
        assert!((loss - 0.7 * 51.0 / 256.0).abs() < 1e-9);
        assert_eq!(rate.fec_packets(), 3);
    }

    #[test]
    fn a_fixed_rate_ignores_the_loss() {
        let mut rate = FecRate::new(10, 1, false);
        rate.on_fraction_lost(0);
        assert_eq!(rate.fec_packets(), 1);
        rate.on_fraction_lost(128);
        assert_eq!(rate.fec_packets(), 1);
    }

    #[test]
    fn the_fec_of_the_last_second_comes_out_of_the_media_target() {
        let mut rate = FecRate::new(10, 1, true);
        let now = Instant::now();
        for n in 0..10u64 {
            rate.on_repair_sent(now + Duration::from_millis(n * 100), 1250);
        }
        let at = now + Duration::from_millis(950);
        assert!((rate.fec_bitrate(at) - 100_000.0).abs() < 1e-6);
        assert!((rate.media_target(at, 1_000_000.0) - 900_000.0).abs() < 1e-6);
        // A second later the repair has aged out.
        assert_eq!(rate.media_target(at + Duration::from_secs(2), 1e6), 1e6);
    }

    /// A fixed corpus of arbitrary report and send sequences: the repair per block stays
    /// within zero and the bound, the media target never goes negative or above the target it
    /// is cut from, and the FEC bit rate never goes negative.
    #[test]
    fn arbitrary_reports_keep_the_rate_within_its_bounds() {
        let mut state = 0x0FEC_0001u32;
        let mut next = move || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state >> 8
        };
        for _ in 0..300 {
            let media = 1 + next() % 48;
            let configured = next() % 8;
            let mut rate = FecRate::new(media, configured, next() % 4 != 0);
            if next() % 3 == 0 {
                rate = rate.with_max(next() % 30);
            }
            let mut at = Instant::now();
            for _ in 0..300 {
                at += Duration::from_millis(u64::from(next() % 200));
                match next() % 3 {
                    0 => rate.on_fraction_lost(next() as u8),
                    1 => rate.on_repair_sent(at, (next() % 1500) as usize),
                    _ => {
                        let k = rate.fec_packets();
                        assert!(k <= rate.max().max(configured), "{k} over the bound");
                        let target = f64::from(next() % 5_000_000);
                        let media_target = rate.media_target(at, target);
                        assert!((0.0..=target).contains(&media_target));
                        assert!(rate.fec_bitrate(at) >= 0.0);
                    }
                }
            }
        }
    }
}
