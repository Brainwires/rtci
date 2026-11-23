use log::warn;
use shared::time::SystemInstant;
use std::time::Instant;

pub(crate) struct SenderStream {
    ssrc: u32,
    clock_rate: f64,
    /// The clock rates of the other payload types the stream may be sent with on this SSRC
    /// (RFC 7160: one SSRC across clock rates).
    payload_clock_rates: Vec<(u8, f64)>,
    /// The clock rate of the packet the RTP / wall clock pair below was taken from: what the
    /// sender report extrapolates with.
    last_clock_rate: f64,

    /// Whether to always use the latest packet, even if out-of-order.
    use_latest_packet: bool,

    /// Track if first packet has been processed
    started: bool,

    /// Last sequence number seen (for out-of-order detection)
    last_rtp_sn: u16,

    /// data from rtp packets
    last_rtp_time_rtp: u32,
    last_rtp_time_time: Option<Instant>,
    time_baseline: Option<SystemInstant>,

    /// Regular reports issued since the stream last sent an RTP packet.
    reports_since_sent: u32,

    counters: Counters,
}

impl SenderStream {
    pub(crate) fn new(ssrc: u32, clock_rate: u32, use_latest_packet: bool) -> Self {
        SenderStream {
            ssrc,
            clock_rate: clock_rate as f64,
            payload_clock_rates: Vec::new(),
            last_clock_rate: clock_rate as f64,

            use_latest_packet,

            started: false,
            last_rtp_sn: 0,
            last_rtp_time_rtp: 0,
            last_rtp_time_time: None,
            time_baseline: None,
            reports_since_sent: 0,

            counters: Default::default(),
        }
    }

    pub(crate) fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// The clock rate of the codec the stream is now sent with (a renegotiation changed it).
    pub(crate) fn set_clock_rate(&mut self, clock_rate: u32) {
        self.clock_rate = clock_rate as f64;
        if self.last_rtp_time_time.is_none() {
            self.last_clock_rate = self.clock_rate;
        }
    }

    /// The clock rates of the other payload types the stream may be sent with (the m=
    /// section's other formats): a packet of one of them is timed with its own rate.
    pub(crate) fn set_payload_clock_rates(&mut self, rates: &[(u8, u32)]) {
        self.payload_clock_rates = rates
            .iter()
            .filter(|(_, rate)| *rate > 0)
            .map(|(pt, rate)| (*pt, f64::from(*rate)))
            .collect();
    }

    fn clock_rate_of(&self, payload_type: u8) -> f64 {
        self.payload_clock_rates
            .iter()
            .find(|(pt, _)| *pt == payload_type)
            .map_or(self.clock_rate, |(_, rate)| *rate)
    }

    pub(crate) fn process_rtp(&mut self, now: Instant, pkt: &rtp::packet::Packet) {
        let seq = pkt.header.sequence_number;

        // Check if this packet should update timestamp info
        // Use u16 arithmetic: diff > 0 && diff < (1<<15) means in-order
        let diff = seq.wrapping_sub(self.last_rtp_sn);
        let is_in_order = !self.started || (diff > 0 && diff < (1 << 15));

        // Update timestamp mapping if:
        // - use_latest_packet is enabled (always update), OR
        // - this is the first packet, OR
        // - packet is in-order
        if self.use_latest_packet || is_in_order {
            self.started = true;
            self.last_rtp_sn = seq;

            // Update time only on first packet of a frame (when timestamp changes)
            // This ensures sender report is not affected by processing delay
            // of pushing a large frame which could span multiple packets.
            // The first accepted packet always establishes the mapping, even when its RTP
            // timestamp happens to be the zero `last_rtp_time_rtp` starts at.
            if self.last_rtp_time_time.is_none() || pkt.header.timestamp != self.last_rtp_time_rtp {
                self.last_rtp_time_rtp = pkt.header.timestamp;
                self.last_rtp_time_time = Some(now);
                self.last_clock_rate = self.clock_rate_of(pkt.header.payload_type);
                // The wall clock is read once, when the stream starts; every later NTP
                // timestamp is that reading plus the time the caller says has passed. Read
                // again at each frame, the NTP time followed the machine's clock instead of
                // the caller's, so two sender reports were not as far apart in NTP time as
                // the instants they were written at.
                self.time_baseline
                    .get_or_insert_with(|| SystemInstant::shared(now));
            }
        }

        self.reports_since_sent = 0;

        // Always count packets and octets regardless of order
        self.counters.increment_packets();
        self.counters.count_octets(pkt.payload.len());
    }

    /// Whether this stream has sent anything, so a report about it means something.
    pub(crate) fn has_sent(&self) -> bool {
        self.last_rtp_time_time.is_some()
    }

    /// When the stream last sent the first packet of a frame.
    pub(crate) fn last_sent(&self) -> Option<Instant> {
        self.last_rtp_time_time
    }

    /// The regular report of this stream for an interval that ends now, or `None` when the
    /// stream is not a sender.
    ///
    /// RFC 3550 section 6.4: a sender report is issued "if a site has sent any data packets
    /// during the interval since issuing the last report or the previous one". A stream that
    /// has been silent for two reports sends no further sender report until it sends again.
    pub(crate) fn generate_regular_report(
        &mut self,
        now: Instant,
    ) -> Option<rtcp::sender_report::SenderReport> {
        if self.reports_since_sent >= 2 {
            return None;
        }
        let report = self.generate_report(now)?;
        self.reports_since_sent += 1;
        Some(report)
    }

    /// Whether [`generate_regular_report`](Self::generate_regular_report) would give a sender
    /// report: the stream sent during the last two reporting intervals.
    pub(crate) fn is_sender(&self) -> bool {
        self.has_sent() && self.reports_since_sent < 2
    }

    /// The sender report of this stream as of `now`, whether or not it sent lately.
    pub(crate) fn generate_report(
        &mut self,
        now: Instant,
    ) -> Option<rtcp::sender_report::SenderReport> {
        if let (Some(last_rtp_time_time), Some(time_baseline)) =
            (self.last_rtp_time_time, self.time_baseline)
        {
            // RFC 3550 section 6.4.1: the RTP timestamp of the instant the NTP timestamp
            // names, extrapolated from the last packet. The ticks elapsed are reduced modulo
            // 2^32 like every RTP timestamp; a float cast to `u32` would stop at `u32::MAX`
            // instead once a stream has been idle for 2^32 ticks (13 h at 90 kHz).
            //
            // RFC 7160 section 3.2: on one SSRC across clock rates the timestamp runs at the
            // rate of the format being sent, so the extrapolation is at the rate of the last
            // packet's payload type, never across a change with the rate the stream was bound
            // with (it gave PCMU's 8 kHz stream 48 kHz worth of ticks).
            let elapsed_ticks = (now.duration_since(last_rtp_time_time).as_secs_f64()
                * self.last_clock_rate) as u64;
            Some(rtcp::sender_report::SenderReport {
                ssrc: self.ssrc,
                ntp_time: time_baseline.ntp(now),
                rtp_time: self.last_rtp_time_rtp.wrapping_add(elapsed_ticks as u32),
                packet_count: self.counters.packet_count(),
                octet_count: self.counters.octet_count(),
                ..Default::default()
            })
        } else {
            None
        }
    }
}

#[derive(Default)]
pub(crate) struct Counters {
    packets: u32,
    octets: u32,
}

/// Wrapping counters used for generating [`rtcp::sender_report::SenderReport`]
impl Counters {
    pub(crate) fn increment_packets(&mut self) {
        self.packets = self.packets.wrapping_add(1);
    }

    pub(crate) fn count_octets(&mut self, octets: usize) {
        // account for a payload size of at most `u32::MAX`
        // and log a message if larger
        self.octets = self
            .octets
            .wrapping_add(octets.try_into().unwrap_or_else(|_| {
                warn!("packet payload larger than 32 bits");
                u32::MAX
            }));
    }

    pub(crate) fn packet_count(&self) -> u32 {
        self.packets
    }

    pub(crate) fn octet_count(&self) -> u32 {
        self.octets
    }

    #[cfg(test)]
    pub(crate) fn mock(packets: u32, octets: u32) -> Self {
        Self { packets, octets }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rtp_packet(seq: u16, timestamp: u32, payload_len: usize) -> rtp::packet::Packet {
        rtp::packet::Packet {
            header: rtp::header::Header {
                sequence_number: seq,
                timestamp,
                ..Default::default()
            },
            payload: vec![0u8; payload_len].into(),
            ..Default::default()
        }
    }

    #[test]
    fn test_sender_stream_before_any_packet() {
        // Test that sender stream works before any packets are sent
        let stream = SenderStream::new(123456, 90000, false);
        let now = Instant::now();

        // No RTP has been sent, so there is no RTP-to-wall-clock mapping to report yet.
        let mut stream = stream;
        assert!(stream.generate_report(now).is_none());
    }

    #[test]
    fn test_sender_stream_after_rtp_packets() {
        // Test sender stream after sending RTP packets
        let mut stream = SenderStream::new(123456, 90000, false);
        let now = Instant::now();

        // Send 10 packets with 2-byte payload each
        for i in 0..10 {
            let pkt = make_rtp_packet(i, 0, 2);
            stream.process_rtp(now, &pkt);
        }

        let sr = stream
            .generate_report(now)
            .expect("a report is available once RTP has been sent");

        assert_eq!(sr.ssrc, 123456);
        assert_eq!(sr.packet_count, 10);
        assert_eq!(sr.octet_count, 20);
    }

    #[test]
    fn test_sender_stream_out_of_order_packets() {
        // Test that out-of-order packets are counted but don't update RTP timestamp
        let mut stream = SenderStream::new(123456, 90000, false);
        let now = Instant::now();

        // Send 10 in-order packets
        for i in 0..10u16 {
            let pkt = make_rtp_packet(i, i as u32, 2);
            stream.process_rtp(now, &pkt);
        }

        // Skip packet 10, send packet 12 first
        let pkt = make_rtp_packet(12, 12, 2);
        stream.process_rtp(now, &pkt);

        // Now send the out-of-order packet 11
        let pkt = make_rtp_packet(11, 11, 2);
        stream.process_rtp(now, &pkt);

        let sr = stream
            .generate_report(now)
            .expect("a report is available once RTP has been sent");

        assert_eq!(sr.ssrc, 123456);
        // All 12 packets are counted
        assert_eq!(sr.packet_count, 12);
        assert_eq!(sr.octet_count, 24);
        // RTP timestamp should be from the last in-order packet (12), not the out-of-order (11)
        assert_eq!(sr.rtp_time, 12);
    }

    #[test]
    fn test_sender_stream_out_of_order_with_use_latest_packet() {
        // Test that with use_latest_packet, out-of-order packets DO update RTP timestamp
        let mut stream = SenderStream::new(123456, 90000, true); // use_latest_packet = true
        let now = Instant::now();

        // Send 10 in-order packets
        for i in 0..10u16 {
            let pkt = make_rtp_packet(i, i as u32, 2);
            stream.process_rtp(now, &pkt);
        }

        // Skip packet 10, send packet 12 first
        let pkt = make_rtp_packet(12, 12, 2);
        stream.process_rtp(now, &pkt);

        // Now send the out-of-order packet 11
        let pkt = make_rtp_packet(11, 11, 2);
        stream.process_rtp(now, &pkt);

        let sr = stream
            .generate_report(now)
            .expect("a report is available once RTP has been sent");

        assert_eq!(sr.ssrc, 123456);
        // All 12 packets are counted
        assert_eq!(sr.packet_count, 12);
        assert_eq!(sr.octet_count, 24);
        // RTP timestamp should be from the LATEST packet (11), since use_latest_packet is true
        assert_eq!(sr.rtp_time, 11);
    }

    #[test]
    fn test_sender_stream_frame_first_packet_optimization() {
        // Test that only the first packet of a frame updates the time mapping
        let mut stream = SenderStream::new(123456, 90000, false);
        let base_time = Instant::now();

        // First packet of frame with timestamp 1000
        let pkt1 = make_rtp_packet(0, 1000, 100);
        stream.process_rtp(base_time, &pkt1);

        // Second packet of same frame (same timestamp), arrives later
        let later_time = base_time + std::time::Duration::from_millis(10);
        let pkt2 = make_rtp_packet(1, 1000, 100);
        stream.process_rtp(later_time, &pkt2);

        // The time mapping should still be from the first packet
        // Generate report at base_time - RTP time should be 1000 (no extrapolation)
        let sr = stream
            .generate_report(base_time)
            .expect("a report is available once RTP has been sent");
        assert_eq!(sr.rtp_time, 1000);
    }

    #[test]
    fn test_sender_stream_sequence_wrap() {
        // Test sequence number wraparound
        let mut stream = SenderStream::new(123456, 90000, false);
        let now = Instant::now();

        // Send packet near the end of sequence space
        let pkt = make_rtp_packet(65534, 100, 10);
        stream.process_rtp(now, &pkt);

        // Send packet at 65535
        let pkt = make_rtp_packet(65535, 200, 10);
        stream.process_rtp(now, &pkt);

        // Wrap around to 0
        let pkt = make_rtp_packet(0, 300, 10);
        stream.process_rtp(now, &pkt);

        // Continue to 1
        let pkt = make_rtp_packet(1, 400, 10);
        stream.process_rtp(now, &pkt);

        let sr = stream
            .generate_report(now)
            .expect("a report is available once RTP has been sent");

        assert_eq!(sr.packet_count, 4);
        assert_eq!(sr.octet_count, 40);
        // RTP time should be from the last in-order packet
        assert_eq!(sr.rtp_time, 400);
    }

    #[test]
    fn test_counters_wrapping() {
        let mut counters = Counters::default();

        // Set to max - 1
        counters.packets = u32::MAX - 1;
        counters.octets = u32::MAX - 1;

        // Increment should wrap
        counters.increment_packets();
        assert_eq!(counters.packet_count(), u32::MAX);

        counters.increment_packets();
        assert_eq!(counters.packet_count(), 0);

        counters.count_octets(1);
        assert_eq!(counters.octet_count(), u32::MAX);

        counters.count_octets(1);
        assert_eq!(counters.octet_count(), 0);
    }

    /// RFC 3550 6.4.1: the RTP timestamp is the last packet's plus the ticks elapsed since,
    /// modulo 2^32, however long the stream has been idle.
    #[test]
    fn the_extrapolated_rtp_timestamp_wraps_instead_of_saturating() {
        let mut stream = SenderStream::new(123456, 90000, false);
        let base = Instant::now();
        stream.process_rtp(base, &make_rtp_packet(0, 1000, 10));

        let hour = std::time::Duration::from_secs(3600);
        let at_14h = stream.generate_report(base + 14 * hour).unwrap();
        let at_15h = stream.generate_report(base + 15 * hour).unwrap();

        let ticks = |hours: u64| (hours * 3600 * 90_000) as u32; // truncating: modulo 2^32
        assert_eq!(at_14h.rtp_time, 1000u32.wrapping_add(ticks(14)));
        assert_eq!(at_15h.rtp_time, 1000u32.wrapping_add(ticks(15)));
        assert_ne!(at_14h.rtp_time, at_15h.rtp_time);
    }

    /// RFC 3550 6.4.1: the NTP timestamp is the wallclock time of the report, and the RTP
    /// timestamp "corresponds to the same time".
    #[test]
    fn the_report_pairs_the_ntp_time_with_the_rtp_time_of_the_same_instant() {
        let mut stream = SenderStream::new(123456, 48000, false);
        let base = Instant::now();
        stream.process_rtp(base, &make_rtp_packet(0, 5000, 10));

        let first = stream.generate_report(base).unwrap();
        let later = stream
            .generate_report(base + std::time::Duration::from_millis(1500))
            .unwrap();

        // 1.5 s later: 72000 ticks at 48 kHz, and 1.5 in 32.32 fixed point NTP seconds.
        assert_eq!(later.rtp_time.wrapping_sub(first.rtp_time), 72_000);
        let ntp_delta = later.ntp_time - first.ntp_time;
        let expected = 3u64 << 31;
        assert!(
            ntp_delta.abs_diff(expected) < (1 << 12),
            "ntp advanced by {ntp_delta:#x}, expected {expected:#x}"
        );
    }

    /// RFC 7160 section 3.2 (one SSRC across clock rates): the sender report's RTP timestamp
    /// is extrapolated at the rate of the format the stream is sent with now. Bound with Opus
    /// (48 kHz, payload type 111) and switched to PCMU (8 kHz, payload type 0), one second
    /// after the last PCMU frame the report is 8000 ticks on, not 48000; back on Opus it is
    /// 48000 again.
    #[test]
    fn the_report_extrapolates_at_the_rate_of_the_format_sent_last() {
        let packet = |seq: u16, timestamp: u32, payload_type: u8| {
            let mut packet = make_rtp_packet(seq, timestamp, 10);
            packet.header.payload_type = payload_type;
            packet
        };
        let mut stream = SenderStream::new(123456, 48000, false);
        stream.set_payload_clock_rates(&[(0, 8000), (8, 8000)]);
        let base = Instant::now();
        let second = std::time::Duration::from_secs(1);
        stream.process_rtp(base, &packet(0, 10_000, 111));
        stream.process_rtp(base, &packet(1, 20_000, 0));
        let report = stream.generate_report(base + second).unwrap();
        assert_eq!(report.rtp_time, 28_000, "PCMU: 8 kHz");

        stream.process_rtp(base + second, &packet(2, 90_000, 111));
        let report = stream.generate_report(base + second * 2).unwrap();
        assert_eq!(report.rtp_time, 138_000, "Opus: 48 kHz");
    }

    /// RFC 3550 6.4: a sender report only while data was sent "during the interval since
    /// issuing the last report or the previous one".
    #[test]
    fn a_silent_stream_stops_being_a_sender_after_two_reports() {
        let mut stream = SenderStream::new(123456, 90000, false);
        let base = Instant::now();
        let second = std::time::Duration::from_secs(1);
        stream.process_rtp(base, &make_rtp_packet(0, 1000, 10));

        assert!(stream.generate_regular_report(base + second).is_some());
        assert!(stream.generate_regular_report(base + 2 * second).is_some());
        assert!(stream.generate_regular_report(base + 3 * second).is_none());
        assert!(stream.generate_regular_report(base + 4 * second).is_none());
        assert!(!stream.is_sender());

        // Sending again makes it a sender again.
        stream.process_rtp(base + 5 * second, &make_rtp_packet(1, 2000, 10));
        assert!(stream.is_sender());
        let report = stream.generate_regular_report(base + 6 * second).unwrap();
        assert_eq!(report.packet_count, 2);
    }
}
