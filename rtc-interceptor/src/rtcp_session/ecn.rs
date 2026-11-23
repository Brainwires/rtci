//! What an ECN-capable RTP receiver counts about one source (RFC 6679 section 5.1): the
//! packets received with each ECN field value, the lost and the duplicated ones, and the
//! extended highest sequence number, for the RTCP ECN Feedback packet (section 5.1) and the
//! XR ECN Summary Report block (section 5.2).

use rtcp::transport_feedbacks::ecn_feedback::EcnCounters;
use shared::EcnCodepoint;

/// One bit per 16-bit sequence number: which were received since they were last reused.
const WORDS: usize = 65536 / 64;

/// What [`EcnTally::on_packet`] found worth telling the sender at once (section 7.2.1:
/// "An immediate or early ... ECN feedback packet SHOULD be generated on receipt of the first
/// ECT- or ECN-CE-marked packet from a sender that has not previously sent any ECT traffic";
/// "Reception of subsequent ECN-CE-marked packets MUST result in additional early or
/// immediate ECN feedback packets"; section 7.3.2: a receiver "that receives a packet with an
/// ECN-CE mark, or that detects a packet loss, MUST schedule the transmission of an RTCP ECN
/// feedback packet as soon as possible").
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EcnEvents {
    pub(crate) first_ect: bool,
    pub(crate) ce: bool,
    pub(crate) loss: bool,
}

impl EcnEvents {
    pub(crate) fn any(&self) -> bool {
        self.first_ect || self.ce || self.loss
    }
}

/// The counts about one source, kept in 64 bits and reported in the field widths of the
/// packets ("using a local representation that is at least 32 bits"). "The counters SHALL be
/// initiated to 0 for each new SSRC received": a tally starts at zero when the source binds.
pub(crate) struct EcnTally {
    ect0: u64,
    ect1: u64,
    ce: u64,
    not_ect: u64,
    duplicates: u64,
    /// Distinct packets received.
    received: u64,
    /// The first and the highest extended sequence numbers received.
    base: Option<u64>,
    highest: u64,
    seen: Box<[u64]>,
}

impl Default for EcnTally {
    fn default() -> Self {
        Self {
            ect0: 0,
            ect1: 0,
            ce: 0,
            not_ect: 0,
            duplicates: 0,
            received: 0,
            base: None,
            highest: 0,
            seen: vec![0u64; WORDS].into_boxed_slice(),
        }
    }
}

impl EcnTally {
    fn bit(&self, sequence_number: u16) -> bool {
        let i = usize::from(sequence_number);
        self.seen[i / 64] & (1 << (i % 64)) != 0
    }

    fn set(&mut self, sequence_number: u16, value: bool) {
        let i = usize::from(sequence_number);
        if value {
            self.seen[i / 64] |= 1 << (i % 64);
        } else {
            self.seen[i / 64] &= !(1 << (i % 64));
        }
    }

    /// Counts an RTP packet of the source that arrived with `ecn`.
    pub(crate) fn on_packet(
        &mut self,
        sequence_number: u16,
        ecn: Option<EcnCodepoint>,
    ) -> EcnEvents {
        let mut events = EcnEvents {
            first_ect: ecn.is_some() && self.ect0 + self.ect1 + self.ce == 0,
            ce: ecn == Some(EcnCodepoint::Ce),
            loss: false,
        };
        // The ECN-CE counter includes "ECN-CE marks in any duplicate packets", and every
        // counter counts every packet received.
        match ecn {
            Some(EcnCodepoint::Ect0) => self.ect0 += 1,
            Some(EcnCodepoint::Ect1) => self.ect1 += 1,
            Some(EcnCodepoint::Ce) => self.ce += 1,
            None => self.not_ect += 1,
        }

        let extended = match self.base {
            None => {
                self.base = Some(u64::from(sequence_number));
                self.highest = u64::from(sequence_number);
                self.set(sequence_number, true);
                self.received = 1;
                return events;
            }
            Some(_) => {
                let delta = sequence_number.wrapping_sub(self.highest as u16);
                if delta < 0x8000 {
                    self.highest + u64::from(delta)
                } else {
                    self.highest.saturating_sub(u64::from(delta.wrapping_neg()))
                }
            }
        };
        let base = self.base.unwrap_or_default();
        if extended < base {
            // Older than the first packet: counted by ECN field value only.
            return events;
        }
        if extended > self.highest {
            // The numbers skipped over are reused from 65536 earlier: clear them.
            for skipped in self.highest + 1..extended {
                self.set(skipped as u16, false);
            }
            events.loss = extended > self.highest + 1;
            self.highest = extended;
            self.set(sequence_number, true);
            self.received += 1;
        } else if self.bit(sequence_number) {
            self.duplicates += 1;
        } else {
            // Late, not lost: it fills its gap.
            self.set(sequence_number, true);
            self.received += 1;
        }
        events
    }

    /// The extended highest sequence number received (RFC 3550), 32 bits.
    pub(crate) fn extended_highest(&self) -> u32 {
        self.highest as u32
    }

    /// Whether any packet of the source arrived.
    pub(crate) fn heard(&self) -> bool {
        self.base.is_some()
    }

    /// The counters as the packets carry them: the ECT counters in 32 bits, the others in
    /// their 16 least significant bits. Lost is "the cumulative number of RTP packets that the
    /// receiver expected to receive minus the number of packets it actually received that are
    /// not a duplicate".
    pub(crate) fn counters(&self) -> EcnCounters {
        let expected = self
            .base
            .map_or(0, |base| self.highest.saturating_sub(base) + 1);
        EcnCounters {
            ect0: self.ect0 as u32,
            ect1: self.ect1 as u32,
            ce: self.ce as u16,
            not_ect: self.not_ect as u16,
            lost: expected.saturating_sub(self.received) as u16,
            duplicates: self.duplicates as u16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_split_by_ecn_field_and_count_loss_and_duplicates_apart() {
        let mut tally = EcnTally::default();
        assert_eq!(
            tally.counters(),
            EcnCounters::default(),
            "they start at zero"
        );
        tally.on_packet(10, Some(EcnCodepoint::Ect0));
        tally.on_packet(11, Some(EcnCodepoint::Ect1));
        let events = tally.on_packet(13, Some(EcnCodepoint::Ce));
        assert!(events.ce && events.loss, "a CE mark, and 12 is missing");
        tally.on_packet(13, None); // a duplicate, not-ECT
        let counters = tally.counters();
        assert_eq!(
            counters,
            EcnCounters {
                ect0: 1,
                ect1: 1,
                ce: 1,
                not_ect: 1,
                lost: 1,
                duplicates: 1,
            }
        );
        assert_eq!(tally.extended_highest(), 13);

        // 12 arrives late: not lost any more.
        tally.on_packet(12, None);
        assert_eq!(tally.counters().lost, 0);
    }

    #[test]
    fn the_first_ect_packet_of_a_source_is_an_event_and_later_ones_are_not() {
        let mut tally = EcnTally::default();
        assert!(!tally.on_packet(1, None).any());
        assert!(tally.on_packet(2, Some(EcnCodepoint::Ect1)).first_ect);
        assert!(!tally.on_packet(3, Some(EcnCodepoint::Ect1)).any());
    }

    /// Section 5.1: kept in more than 32 bits locally, the 16-bit fields carry the least
    /// significant bits ("the field will wrap if more than 65535 ... have been received").
    #[test]
    fn a_16_bit_counter_carries_the_low_bits_of_a_wider_count() {
        let mut tally = EcnTally::default();
        for n in 0..70_000u32 {
            tally.on_packet(n as u16, Some(EcnCodepoint::Ce));
        }
        assert_eq!(tally.counters().ce, (70_000u32 % 65_536) as u16);
        assert_eq!(tally.extended_highest(), 69_999);
        assert_eq!(tally.counters().lost, 0);
    }

    #[test]
    fn the_extended_highest_sequence_number_crosses_a_wrap() {
        let mut tally = EcnTally::default();
        tally.on_packet(65534, None);
        tally.on_packet(65535, None);
        tally.on_packet(0, None);
        tally.on_packet(1, None);
        assert_eq!(tally.extended_highest(), 65537);
        assert_eq!(tally.counters().lost, 0);
        assert_eq!(tally.counters().duplicates, 0);
    }
}
