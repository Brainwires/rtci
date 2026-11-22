use std::time::Instant;

/// RFC 3550 Appendix A.1: a forward jump of up to this many sequence numbers is a gap (loss), a
/// larger one is a source that restarted (or a wild packet).
const MAX_DROPOUT: u16 = 3000;
/// RFC 3550 Appendix A.1: a packet up to this many sequence numbers behind the highest seen is
/// late or a duplicate, one further behind is a source that restarted (or a wild packet).
const MAX_MISORDER: u16 = 100;
/// 2^16, the modulus of RTP sequence numbers.
const RTP_SEQ_MOD: u32 = 1 << 16;

/// The largest and smallest cumulative number of packets lost a report can carry: the field is
/// a signed 24-bit integer (RFC 3550 section 6.4.1), and Appendix A.3 clamps to it.
const MAX_CUMULATIVE_LOST: i64 = 0x7F_FFFF;
const MIN_CUMULATIVE_LOST: i64 = -0x80_0000;

/// The reception statistics of one remote SSRC, kept exactly as RFC 3550 Appendix A.1 (sequence
/// numbers), A.3 (expected, lost, fraction lost) and A.8 (interarrival jitter) describe.
///
/// Appendix A.1's probation (`MIN_SEQUENTIAL`) is not used: a stream is bound from the
/// negotiated description and its packets are SRTP authenticated, so the first packet of a
/// source is taken as its first.
pub(crate) struct ReceiverStream {
    ssrc: u32,
    receiver_ssrc: u32,
    clock_rate: f64,

    /// Whether a packet has been received (the sequence state below is initialised).
    started: bool,
    /// The highest sequence number seen (`max_seq`).
    max_seq: u16,
    /// The count of sequence number cycles, shifted: a multiple of 2^16 (`cycles`).
    cycles: u32,
    /// The first sequence number seen (`base_seq`).
    base_seq: u32,
    /// The last "bad" sequence number plus one (`bad_seq`); 2^16 + 1 when there is none.
    bad_seq: u32,
    /// Packets received, late ones and duplicates included (`received`).
    received: u32,
    /// `expected` at the previous report (`expected_prior`).
    expected_prior: u32,
    /// `received` at the previous report (`received_prior`).
    received_prior: u32,

    /// The relative transit time of the previous packet, in timestamp units (`transit`).
    last_rtp_time_rtp: u32,
    last_rtp_time_time: Option<Instant>,
    jitter: f64,
    last_sender_report: u32,
    last_sender_report_time: Option<Instant>,
}

impl ReceiverStream {
    pub(crate) fn new(ssrc: u32, clock_rate: u32) -> Self {
        Self {
            ssrc,
            receiver_ssrc: rand::random::<u32>(),
            clock_rate: clock_rate as f64,

            started: false,
            max_seq: 0,
            cycles: 0,
            base_seq: 0,
            bad_seq: RTP_SEQ_MOD + 1,
            received: 0,
            expected_prior: 0,
            received_prior: 0,

            last_rtp_time_rtp: 0,
            last_rtp_time_time: None,
            jitter: 0.0,
            last_sender_report: 0,
            last_sender_report_time: None,
        }
    }

    /// The SSRC this stream reports on.
    pub(crate) fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// The SSRC this stream's receiver reports (and XR blocks) are sent from.
    pub(crate) fn receiver_ssrc(&self) -> u32 {
        self.receiver_ssrc
    }

    /// The clock rate of the codec the stream is received with.
    pub(crate) fn set_clock_rate(&mut self, clock_rate: u32) {
        self.clock_rate = clock_rate as f64;
    }

    /// Whether any packet of the stream has been received.
    pub(crate) fn has_received(&self) -> bool {
        self.started
    }

    /// When the stream's last packet arrived.
    pub(crate) fn last_received(&self) -> Option<Instant> {
        self.last_rtp_time_time
    }

    /// RFC 3550 Appendix A.1 `init_seq`.
    fn init_seq(&mut self, seq: u16) {
        self.base_seq = u32::from(seq);
        self.max_seq = seq;
        self.bad_seq = RTP_SEQ_MOD + 1;
        self.cycles = 0;
        self.received = 0;
        self.received_prior = 0;
        self.expected_prior = 0;
    }

    /// RFC 3550 Appendix A.1 `update_seq`, without the probation: whether the packet belongs
    /// to the sequence and was counted.
    fn update_seq(&mut self, seq: u16) -> bool {
        if !self.started {
            self.started = true;
            self.init_seq(seq);
            self.received = 1;
            return true;
        }

        let udelta = seq.wrapping_sub(self.max_seq);
        if udelta < MAX_DROPOUT {
            // In order, with a permissible gap.
            if seq < self.max_seq {
                // The sequence number wrapped: count another 64K cycle.
                self.cycles = self.cycles.wrapping_add(RTP_SEQ_MOD);
            }
            self.max_seq = seq;
        } else if u32::from(udelta) <= RTP_SEQ_MOD - u32::from(MAX_MISORDER) {
            // The sequence number made a very large jump.
            if u32::from(seq) == self.bad_seq {
                // Two sequential packets: the other side restarted without telling us, so
                // re-sync as if this were the first packet.
                self.init_seq(seq);
            } else {
                self.bad_seq = (u32::from(seq) + 1) & (RTP_SEQ_MOD - 1);
                return false;
            }
        } else {
            // A duplicate or a reordered packet.
        }
        self.received = self.received.wrapping_add(1);
        true
    }

    pub(crate) fn process_rtp(&mut self, now: Instant, pkt: &rtp::packet::Packet) {
        if !self.update_seq(pkt.header.sequence_number) {
            return;
        }

        // RFC 3550 Appendix A.8, for every packet of the sequence, in arrival order:
        // D = (Rj - Ri) - (Sj - Si), J += (|D| - J) / 16. The timestamp difference is taken
        // signed, so a wrap of the 32-bit timestamp is a small step, not a jump of 2^32.
        if let Some(last_rtp_time_time) = self.last_rtp_time_time {
            let d = now.duration_since(last_rtp_time_time).as_secs_f64() * self.clock_rate
                - pkt.header.timestamp.wrapping_sub(self.last_rtp_time_rtp) as i32 as f64;
            self.jitter += (d.abs() - self.jitter) / 16.0;
        }

        self.last_rtp_time_rtp = pkt.header.timestamp;
        self.last_rtp_time_time = Some(now);
    }

    pub(crate) fn process_sender_report(
        &mut self,
        now: Instant,
        sr: &rtcp::sender_report::SenderReport,
    ) {
        self.last_sender_report = (sr.ntp_time >> 16) as u32;
        self.last_sender_report_time = Some(now);
    }

    /// The reception report block for this stream (RFC 3550 section 6.4.1, Appendix A.3),
    /// closing the reporting interval: the next block's fraction lost counts from here.
    /// The fraction lost (in 1/256) a report made now would carry, without making one: the
    /// interval's state is left as it is.
    pub(crate) fn pending_fraction_lost(&self) -> u8 {
        if !self.started {
            return 0;
        }
        let extended_max = self.cycles.wrapping_add(u32::from(self.max_seq));
        let expected = extended_max.wrapping_sub(self.base_seq).wrapping_add(1);
        let expected_interval = expected.wrapping_sub(self.expected_prior);
        let received_interval = self.received.wrapping_sub(self.received_prior);
        let lost_interval = i64::from(expected_interval) - i64::from(received_interval);
        if expected_interval == 0 || lost_interval <= 0 {
            0
        } else {
            ((lost_interval << 8) / i64::from(expected_interval)).min(255) as u8
        }
    }

    pub(crate) fn generate_reception_report(
        &mut self,
        now: Instant,
    ) -> rtcp::reception_report::ReceptionReport {
        // Appendix A.3: the extended highest sequence number, the packets expected, and the
        // cumulative number lost as expected less received. Late packets were counted when
        // they arrived, so they are not lost; duplicates were counted too, so the number can
        // be negative. It is clamped to the 24 bits it is carried in.
        let extended_max = self.cycles.wrapping_add(u32::from(self.max_seq));
        let expected = if self.started {
            extended_max.wrapping_sub(self.base_seq).wrapping_add(1)
        } else {
            0
        };
        let lost = (i64::from(expected) - i64::from(self.received))
            .clamp(MIN_CUMULATIVE_LOST, MAX_CUMULATIVE_LOST);

        // The fraction lost over the interval since the previous report; zero when duplicates
        // make the interval's loss negative.
        let expected_interval = expected.wrapping_sub(self.expected_prior);
        self.expected_prior = expected;
        let received_interval = self.received.wrapping_sub(self.received_prior);
        self.received_prior = self.received;
        let lost_interval = i64::from(expected_interval) - i64::from(received_interval);
        let fraction_lost = if expected_interval == 0 || lost_interval <= 0 {
            0
        } else {
            ((lost_interval << 8) / i64::from(expected_interval)).min(255) as u8
        };

        // DLSR: the delay since the last sender report, in 1/65536 s; zero when there is none.
        let delay = match self.last_sender_report_time {
            Some(sr_time) => (now.duration_since(sr_time).as_secs_f64() * 65536.0) as u64 as u32,
            None => 0,
        };

        let mut report = rtcp::reception_report::ReceptionReport {
            ssrc: self.ssrc,
            last_sequence_number: extended_max,
            last_sender_report: self.last_sender_report,
            fraction_lost,
            total_lost: 0,
            delay,
            jitter: self.jitter as u32,
        };
        report.set_cumulative_lost(lost as i32);
        report
    }

    pub(crate) fn generate_report(
        &mut self,
        now: Instant,
    ) -> rtcp::receiver_report::ReceiverReport {
        rtcp::receiver_report::ReceiverReport {
            ssrc: self.receiver_ssrc,
            reports: vec![self.generate_reception_report(now)],
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_rtp_packet(seq: u16, timestamp: u32) -> rtp::packet::Packet {
        rtp::packet::Packet {
            header: rtp::header::Header {
                sequence_number: seq,
                timestamp,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_receiver_stream_before_any_packet() {
        // Port of pion's TestReceiverInterceptor/before any packet
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        let rr = stream.generate_report(now);

        assert_eq!(rr.reports.len(), 1);
        assert_eq!(rr.reports[0].ssrc, 123456);
        assert_eq!(rr.reports[0].last_sequence_number, 0);
        assert_eq!(rr.reports[0].last_sender_report, 0);
        assert_eq!(rr.reports[0].fraction_lost, 0);
        assert_eq!(rr.reports[0].total_lost, 0);
        assert_eq!(rr.reports[0].delay, 0);
        assert_eq!(rr.reports[0].jitter, 0);
    }

    #[test]
    fn test_receiver_stream_after_rtp_packets() {
        // Port of pion's TestReceiverInterceptor/after RTP packets
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        for i in 0..10u16 {
            let pkt = make_rtp_packet(i, 0);
            stream.process_rtp(now, &pkt);
        }

        let rr = stream.generate_report(now);

        assert_eq!(rr.reports.len(), 1);
        assert_eq!(rr.reports[0].ssrc, 123456);
        assert_eq!(rr.reports[0].last_sequence_number, 9);
        assert_eq!(rr.reports[0].last_sender_report, 0);
        assert_eq!(rr.reports[0].fraction_lost, 0);
        assert_eq!(rr.reports[0].total_lost, 0);
        assert_eq!(rr.reports[0].delay, 0);
        assert_eq!(rr.reports[0].jitter, 0);
    }

    #[test]
    fn test_receiver_stream_jitter_ts_wrap() {
        // steady 20 ms at 48 khz across u32::MAX: was ~2^32 / 16
        let mut stream = ReceiverStream::new(123456, 48000);
        let now = Instant::now();
        for i in 0..4u16 {
            let ts = (u32::MAX - 1919).wrapping_add(960 * i as u32);
            stream.process_rtp(
                now + Duration::from_millis(20 * i as u64),
                &make_rtp_packet(i, ts),
            );
        }
        assert_eq!(stream.generate_report(now).reports[0].jitter, 0);
    }

    #[test]
    fn test_receiver_stream_jitter_delay_across_ts_wrap() {
        // 100 ms late right after the wrap: d = 4800, jitter = 4800 / 16
        let mut stream = ReceiverStream::new(123456, 48000);
        let now = Instant::now();
        stream.process_rtp(now, &make_rtp_packet(1, u32::MAX - 959));
        stream.process_rtp(now + Duration::from_millis(120), &make_rtp_packet(2, 0));
        assert_eq!(stream.generate_report(now).reports[0].jitter, 300);
    }

    #[test]
    fn test_receiver_stream_overflow() {
        // Port of pion's TestReceiverInterceptor/overflow
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        // Receive packet at 0xffff
        stream.process_rtp(now, &make_rtp_packet(0xffff, 0));

        // Wrap to 0x00
        stream.process_rtp(now, &make_rtp_packet(0x00, 0));

        // Out-of-order packet 0xfffe: it does not move the highest sequence number
        stream.process_rtp(now, &make_rtp_packet(0xfffe, 0));

        let rr = stream.generate_report(now);

        assert_eq!(rr.reports.len(), 1);
        assert_eq!(rr.reports[0].ssrc, 123456);
        // Extended sequence number should show 1 cycle (1 << 16)
        assert_eq!(rr.reports[0].last_sequence_number, 1 << 16);
        assert_eq!(rr.reports[0].fraction_lost, 0);
        // RFC 3550 Appendix A.3: two packets expected from the first sequence number on
        // (0xffff, 0x0000), three received, so the cumulative loss is minus one.
        assert_eq!(rr.reports[0].cumulative_lost(), -1);
    }

    #[test]
    fn test_receiver_stream_packet_loss() {
        // Port of pion's TestReceiverInterceptor/packet loss
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        // Receive packet 1
        stream.process_rtp(now, &make_rtp_packet(0x01, 0));

        // Skip packet 2, receive packet 3
        stream.process_rtp(now, &make_rtp_packet(0x03, 0));

        let rr = stream.generate_report(now);

        assert_eq!(rr.reports.len(), 1);
        assert_eq!(rr.reports[0].ssrc, 123456);
        assert_eq!(rr.reports[0].last_sequence_number, 0x03);
        // fraction_lost = 256 * 1 / 3 = 85
        assert_eq!(rr.reports[0].fraction_lost, (256u32 * 1 / 3) as u8);
        assert_eq!(rr.reports[0].total_lost, 1);
    }

    #[test]
    fn test_receiver_stream_overflow_and_packet_loss() {
        // Port of pion's TestReceiverInterceptor/overflow and packet loss
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        // Receive packet 0xffff
        stream.process_rtp(now, &make_rtp_packet(0xffff, 0));

        // Skip 0x00, receive 0x01
        stream.process_rtp(now, &make_rtp_packet(0x01, 0));

        let rr = stream.generate_report(now);

        assert_eq!(rr.reports.len(), 1);
        assert_eq!(rr.reports[0].ssrc, 123456);
        // Extended sequence number: 1 cycle + 0x01
        assert_eq!(rr.reports[0].last_sequence_number, (1 << 16) | 0x01);
        // fraction_lost = 256 * 1 / 3 = 85
        assert_eq!(rr.reports[0].fraction_lost, (256u32 * 1 / 3) as u8);
        assert_eq!(rr.reports[0].total_lost, 1);
    }

    #[test]
    fn test_receiver_stream_reordered_packets() {
        // Port of pion's TestReceiverInterceptor/reordered packets
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        // Receive packets in order: 1, 3, 2, 4
        for seq in [0x01u16, 0x03, 0x02, 0x04] {
            stream.process_rtp(now, &make_rtp_packet(seq, 0));
        }

        let rr = stream.generate_report(now);

        assert_eq!(rr.reports.len(), 1);
        assert_eq!(rr.reports[0].ssrc, 123456);
        assert_eq!(rr.reports[0].last_sequence_number, 0x04);
        // No loss because packet 2 arrived (just out of order)
        assert_eq!(rr.reports[0].fraction_lost, 0);
        assert_eq!(rr.reports[0].total_lost, 0);
    }

    #[test]
    fn test_receiver_stream_jitter() {
        // Port of pion's TestReceiverInterceptor/jitter
        let mut stream = ReceiverStream::new(123456, 90000);
        let base_time = Instant::now();

        // First packet
        stream.process_rtp(base_time, &make_rtp_packet(0x01, 42378934));

        // Second packet arrives 1 second later, but RTP timestamp only advances by 60000
        // (should be 90000 for 1 second at 90kHz clock rate)
        // D = |arrival_diff * clock_rate - rtp_diff| = |1 * 90000 - 60000| = 30000
        let later_time = base_time + Duration::from_secs(1);
        stream.process_rtp(later_time, &make_rtp_packet(0x02, 42378934 + 60000));

        let rr = stream.generate_report(later_time);

        assert_eq!(rr.reports.len(), 1);
        assert_eq!(rr.reports[0].ssrc, 123456);
        assert_eq!(rr.reports[0].last_sequence_number, 0x02);
        // jitter = D / 16 = 30000 / 16 = 1875
        assert_eq!(rr.reports[0].jitter, 30000 / 16);
    }

    #[test]
    fn test_receiver_stream_delay() {
        // Port of pion's TestReceiverInterceptor/delay
        let mut stream = ReceiverStream::new(123456, 90000);
        let base_time = Instant::now();

        // Receive a sender report
        let sr = rtcp::sender_report::SenderReport {
            ssrc: 123456,
            ntp_time: 0x1234_5678_0000_0000, // Some NTP time
            rtp_time: 987654321,
            packet_count: 0,
            octet_count: 0,
            ..Default::default()
        };
        stream.process_sender_report(base_time, &sr);

        // Generate receiver report 1 second later
        let later_time = base_time + Duration::from_secs(1);
        let rr = stream.generate_report(later_time);

        assert_eq!(rr.reports.len(), 1);
        // DLSR in 1/65536 seconds units: 1 second = 65536
        assert_eq!(rr.reports[0].delay, 65536);
        // LSR is middle 32 bits of NTP time
        assert_eq!(rr.reports[0].last_sender_report, 0x5678_0000);
    }

    #[test]
    fn test_receiver_stream_delay_before_sender_report() {
        // Test that delay is 0 before receiving any sender report
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        // Receive some RTP packets
        for i in 0..5u16 {
            stream.process_rtp(now, &make_rtp_packet(i, 0));
        }

        // Generate report without having received any SR
        let rr = stream.generate_report(now);

        assert_eq!(rr.reports[0].delay, 0);
        assert_eq!(rr.reports[0].last_sender_report, 0);
    }

    #[test]
    fn test_receiver_stream_cumulative_loss() {
        // Test that total_lost accumulates across reports
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        // First batch: receive 1, skip 2, receive 3
        stream.process_rtp(now, &make_rtp_packet(1, 0));
        stream.process_rtp(now, &make_rtp_packet(3, 0));

        let rr1 = stream.generate_report(now);
        assert_eq!(rr1.reports[0].total_lost, 1);

        // Second batch: receive 4, skip 5, receive 6
        stream.process_rtp(now, &make_rtp_packet(4, 0));
        stream.process_rtp(now, &make_rtp_packet(6, 0));

        let rr2 = stream.generate_report(now);
        // Total lost should now be 2 (1 from first batch + 1 from second)
        assert_eq!(rr2.reports[0].total_lost, 2);
    }

    #[test]
    fn test_receiver_stream_24bit_loss_clamping() {
        // The cumulative loss is clamped to the signed 24 bits it is carried in
        // (RFC 3550 section 6.4.1, Appendix A.3), at both ends.
        let now = Instant::now();

        let mut stream = ReceiverStream::new(123456, 90000);
        stream.process_rtp(now, &make_rtp_packet(1, 0));
        // 2^24 sequence numbers later, having received almost nothing in between.
        stream.cycles = 256 << 16;
        let rr = stream.generate_report(now);
        assert_eq!(rr.reports[0].total_lost, 0x7F_FFFF);
        assert_eq!(rr.reports[0].cumulative_lost(), 0x7F_FFFF);

        let mut stream = ReceiverStream::new(123456, 90000);
        stream.process_rtp(now, &make_rtp_packet(1, 0));
        // Far more duplicates than packets expected.
        stream.received = 0x0100_0000;
        let rr = stream.generate_report(now);
        assert_eq!(rr.reports[0].cumulative_lost(), -0x80_0000);
    }

    /// RFC 3550 6.4.1: "packets that arrive late are not counted as lost".
    #[test]
    fn a_late_packet_is_no_longer_lost_in_the_next_report() {
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        stream.process_rtp(now, &make_rtp_packet(1, 0));
        stream.process_rtp(now, &make_rtp_packet(3, 0));
        let first = stream.generate_report(now);
        assert_eq!(first.reports[0].cumulative_lost(), 1);
        assert_eq!(first.reports[0].fraction_lost, (256u32 / 3) as u8);

        // Packet 2 arrives after the report that counted it lost.
        stream.process_rtp(now, &make_rtp_packet(2, 0));
        let second = stream.generate_report(now);
        assert_eq!(second.reports[0].cumulative_lost(), 0);
        // Nothing new was expected in the interval and one packet arrived: no loss.
        assert_eq!(second.reports[0].fraction_lost, 0);
    }

    /// RFC 3550 6.4.1: "the loss may be negative if there are duplicates".
    #[test]
    fn duplicates_make_the_cumulative_loss_negative() {
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        for seq in [1u16, 2, 3, 3, 3] {
            stream.process_rtp(now, &make_rtp_packet(seq, 0));
        }
        let rr = stream.generate_report(now);
        assert_eq!(rr.reports[0].last_sequence_number, 3);
        assert_eq!(rr.reports[0].cumulative_lost(), -2);
        // Appendix A.3: a negative interval loss reports a fraction of zero.
        assert_eq!(rr.reports[0].fraction_lost, 0);
        // On the wire: the 24-bit two's complement.
        assert_eq!(rr.reports[0].total_lost, 0xFF_FFFE);
    }

    /// Appendix A.3: the fraction is the loss of the interval over what the interval expected,
    /// as an 8-bit fixed point number.
    #[test]
    fn fraction_lost_covers_the_interval_since_the_previous_report() {
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        // Interval one: 1..=10 with nothing lost.
        for seq in 1..=10u16 {
            stream.process_rtp(now, &make_rtp_packet(seq, 0));
        }
        assert_eq!(stream.generate_report(now).reports[0].fraction_lost, 0);

        // Interval two: 11..=20 expected, five of them received.
        for seq in [11u16, 12, 13, 14, 20] {
            stream.process_rtp(now, &make_rtp_packet(seq, 0));
        }
        let rr = stream.generate_report(now);
        // 5 lost of 10 expected: 5 * 256 / 10 = 128.
        assert_eq!(rr.reports[0].fraction_lost, 128);
        assert_eq!(rr.reports[0].cumulative_lost(), 5);
        assert_eq!(rr.reports[0].last_sequence_number, 20);
    }

    /// Appendix A.1: one packet far outside the window is not part of the sequence; two in a
    /// row are a source that restarted, and the statistics start again from there.
    #[test]
    fn a_large_jump_is_ignored_once_and_a_restart_when_it_repeats() {
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        for seq in 100..=109u16 {
            stream.process_rtp(now, &make_rtp_packet(seq, 0));
        }
        // A wild packet: more than MAX_DROPOUT ahead.
        stream.process_rtp(now, &make_rtp_packet(40_000, 0));
        let rr = stream.generate_report(now);
        assert_eq!(rr.reports[0].last_sequence_number, 109);
        assert_eq!(rr.reports[0].cumulative_lost(), 0);

        // The packet after it, in sequence with it: the source restarted.
        stream.process_rtp(now, &make_rtp_packet(40_001, 0));
        stream.process_rtp(now, &make_rtp_packet(40_002, 0));
        let rr = stream.generate_report(now);
        assert_eq!(rr.reports[0].last_sequence_number, 40_002);
        assert_eq!(rr.reports[0].cumulative_lost(), 0);
        assert_eq!(rr.reports[0].fraction_lost, 0);
    }

    /// Appendix A.1: a gap of up to MAX_DROPOUT is loss, not a restart.
    #[test]
    fn a_gap_below_the_dropout_limit_is_counted_as_loss() {
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        stream.process_rtp(now, &make_rtp_packet(10, 0));
        stream.process_rtp(now, &make_rtp_packet(10 + 2999, 0));
        let rr = stream.generate_report(now);
        assert_eq!(rr.reports[0].last_sequence_number, 3009);
        assert_eq!(rr.reports[0].cumulative_lost(), 2998);
    }
}
