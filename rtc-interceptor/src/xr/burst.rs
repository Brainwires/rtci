//! The burst and gap metrics of the VoIP Metrics block (RFC 3611 section 4.7.2).

/// Burst and gap accounting since the beginning of reception, by the definitions of RFC 3611
/// section 4.7.2: a burst is the longest run that starts and ends with a lost or discarded
/// packet and holds no `gmin` or more consecutive received packets; a lost packet with at
/// least `gmin` received packets on either side is in a gap. Before the first packet and after
/// the report there are taken to be `gmin` received packets.
#[derive(Debug, Clone)]
pub(crate) struct BurstGapModel {
    gmin: u64,
    /// Packets seen so far, received or not.
    position: u64,
    /// Received packets since the last loss.
    received_since_loss: u64,
    /// The losses that may still form a burst: (first position, last position, count).
    open: Option<(u64, u64, u64)>,
    /// Closed bursts.
    bursts: u64,
    burst_packets: u64,
    burst_losses: u64,
    /// Losses that ended up in a gap.
    gap_losses: u64,
}

/// The metrics of RFC 3611 section 4.7.2 at a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BurstGapMetrics {
    pub(crate) burst_density: u8,
    pub(crate) gap_density: u8,
    pub(crate) burst_duration_ms: u16,
    pub(crate) gap_duration_ms: u16,
}

/// `part / whole` as RFC 3611 4.7.2 writes a density: times 256, capped at 255, the integer
/// part; 0 when nothing was expected.
fn density(part: u64, whole: u64) -> u8 {
    (part * 256)
        .checked_div(whole)
        .map_or(0, |d| d.min(255) as u8)
}

impl BurstGapModel {
    pub(crate) fn new(gmin: u8) -> Self {
        Self {
            gmin: u64::from(gmin.max(1)),
            position: 0,
            received_since_loss: 0,
            open: None,
            bursts: 0,
            burst_packets: 0,
            burst_losses: 0,
            gap_losses: 0,
        }
    }

    /// The next packet in sequence order: lost (or discarded) or received.
    pub(crate) fn observe(&mut self, lost: bool, discarded: bool) {
        let position = self.position;
        self.position += 1;
        if !(lost || discarded) {
            self.received_since_loss += 1;
            return;
        }
        match self.open {
            Some((first, _, count)) if self.received_since_loss < self.gmin => {
                self.open = Some((first, position, count + 1));
            }
            _ => {
                self.close();
                self.open = Some((position, position, 1));
            }
        }
        self.received_since_loss = 0;
    }

    fn close(&mut self) {
        if let Some((first, last, count)) = self.open.take() {
            let (bursts, packets, losses, gap) = Self::closed(first, last, count);
            self.bursts += bursts;
            self.burst_packets += packets;
            self.burst_losses += losses;
            self.gap_losses += gap;
        }
    }

    /// What a run of losses adds when it closes: one loss alone is in a gap, two or more
    /// make a burst from the first to the last.
    fn closed(first: u64, last: u64, count: u64) -> (u64, u64, u64, u64) {
        if count >= 2 {
            (1, last - first + 1, count, 0)
        } else {
            (0, 0, 0, 1)
        }
    }

    /// The metrics now, with the losses still open closed as if `gmin` received packets
    /// followed (section 4.7.2), and `packet_ms` the duration of one packet.
    pub(crate) fn metrics(&self, packet_ms: f64) -> BurstGapMetrics {
        let (mut bursts, mut burst_packets, mut burst_losses, mut gap_losses) = (
            self.bursts,
            self.burst_packets,
            self.burst_losses,
            self.gap_losses,
        );
        if let Some((first, last, count)) = self.open {
            let (b, p, l, g) = Self::closed(first, last, count);
            bursts += b;
            burst_packets += p;
            burst_losses += l;
            gap_losses += g;
        }
        let gap_packets = self.position - burst_packets;
        // Gaps lie between, before and after the bursts; one that holds no packet is none.
        let gaps = if bursts == 0 {
            u64::from(gap_packets > 0)
        } else {
            (bursts + 1).min(gap_packets.max(1))
        };
        let mean_ms = |packets: u64, periods: u64| -> u16 {
            if periods == 0 {
                0
            } else {
                (packets as f64 * packet_ms / periods as f64)
                    .round()
                    .min(f64::from(u16::MAX)) as u16
            }
        };
        BurstGapMetrics {
            burst_density: density(burst_losses, burst_packets),
            gap_density: density(gap_losses, gap_packets),
            burst_duration_ms: mean_ms(burst_packets, bursts),
            gap_duration_ms: mean_ms(gap_packets, gaps),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3611 section 4.7.2's example: with Gmin 16 and 10 ms packets, the twelve packets
    /// from the first discard to the last loss are the one burst, with four losses and
    /// discards, the rest two gaps with one each (density 0.04: 10), the burst lasts 120 ms.
    /// The RFC writes the burst density as 84 from the rounded 0.33; the field's definition
    /// (256 x 4 / 12, integer part) gives 85. The pattern as printed holds 63 packets, not
    /// 64, so the second gap is 280 ms and the mean gap 255 ms where the RFC's 64 packets
    /// give 520 ms in two gaps.
    #[test]
    fn the_example_of_rfc3611_section_4_7_2() {
        let pattern = "11110111111111111111111X111X1011110111111111111111111X111111111";
        let mut model = BurstGapModel::new(16);
        for packet in pattern.chars() {
            model.observe(packet == '0', packet == 'X');
        }
        let metrics = model.metrics(10.0);
        assert_eq!(85, metrics.burst_density);
        assert_eq!(10, metrics.gap_density);
        assert_eq!(120, metrics.burst_duration_ms);
        assert_eq!(255, metrics.gap_duration_ms);
    }

    /// RFC 3611 4.7.2: "If there have been no burst periods, the burst duration value MUST
    /// be zero"; the densities are zero when nothing was lost; an isolated loss is a gap's.
    #[test]
    fn without_bursts_the_burst_metrics_are_zero() {
        let mut model = BurstGapModel::new(16);
        for i in 0..100 {
            model.observe(i == 50, false);
        }
        let metrics = model.metrics(20.0);
        assert_eq!(0, metrics.burst_density);
        assert_eq!(0, metrics.burst_duration_ms);
        assert_eq!(2, metrics.gap_density, "1 in 100, times 256");
        assert_eq!(2_000, metrics.gap_duration_ms);

        let metrics = BurstGapModel::new(16).metrics(20.0);
        assert_eq!(
            BurstGapMetrics {
                burst_density: 0,
                gap_density: 0,
                burst_duration_ms: 0,
                gap_duration_ms: 0
            },
            metrics
        );
    }
}
