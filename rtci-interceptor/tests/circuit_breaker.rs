//! The RTP circuit breaker (RFC 8083), in a chain.
//!
//! Driven the way a peer connection drives it: RTP written on the way out, the receiver's RTCP
//! read on the way in, and the clock advanced through `handle_timeout`.

use rtci_interceptor::{
    Attribute, AttributedPacket, CircuitBreakerBuilder, CircuitBreakerHandle, CircuitBreakerNotice,
    CircuitBreakerPacketSize, CircuitBreakerReason, CircuitBreakerState, Interceptor,
    MediaUsability, Packet, Registry, RtcpReportingInterval, Slot, StreamInfo, TaggedPacket,
};
use rtcp::receiver_report::ReceiverReport;
use rtcp::reception_report::ReceptionReport;
use rtcp::sender_report::SenderReport;
use sansio::Protocol;
use shared::TransportContext;
use std::sync::Arc;
use std::time::{Duration, Instant};

const VIDEO: u32 = 0x1111_1111;
const AUDIO: u32 = 0x2222_2222;
/// The LSR the sender report below is known by.
const NTP: u64 = 0x0001_2345_6789_0000;

struct Harness {
    chain: Box<dyn Interceptor>,
    handle: CircuitBreakerHandle,
    epoch: Instant,
    sequence: u16,
    /// RTP packets that left the chain.
    left: u64,
    /// The extended highest sequence number the receiver of the congestion tests reports.
    received: u32,
    /// What the receiver last reported on each SSRC: the extended highest sequence number and
    /// the cumulative number lost, which follows the fraction lost it reports (RFC 3550 A.3).
    reported: std::collections::HashMap<u32, (u32, i32)>,
    /// What the breaker told the chain application-ward.
    notices: Vec<CircuitBreakerNotice>,
    /// The sequence number last sent on each SSRC by `send_numbered`.
    numbered: std::collections::HashMap<u32, u16>,
    /// What the chain's RTCP session would say it calculates as the reporting interval: put
    /// on every RTCP packet read, as the session does.
    interval: Option<RtcpReportingInterval>,
}

fn ms(milliseconds: u64) -> Duration {
    Duration::from_millis(milliseconds)
}

impl Harness {
    fn new(builder: CircuitBreakerBuilder) -> Self {
        let (breaker, handle) = builder.build();
        let mut chain = Registry::new().with(Slot::CircuitBreaker, breaker).build();
        for ssrc in [VIDEO, AUDIO] {
            chain.bind_local_stream(&StreamInfo {
                ssrc,
                clock_rate: 90_000,
                ..Default::default()
            });
        }
        Self {
            notices: Vec::new(),
            chain: Box::new(chain),
            handle,
            epoch: Instant::now(),
            sequence: 0,
            left: 0,
            received: 0,
            reported: std::collections::HashMap::new(),
            numbered: std::collections::HashMap::new(),
            interval: None,
        }
    }

    fn drain(&mut self) {
        while let Some(packet) = self.chain.poll_write() {
            if matches!(packet.message.packet, Packet::Rtp(_)) {
                self.left += 1;
            }
        }
        while let Some(read) = self.chain.poll_read() {
            if let Some(notice) = read.message.custom::<CircuitBreakerNotice>() {
                self.notices.push(*notice);
            }
        }
    }

    fn tagged(&self, at: Duration, packet: Packet) -> TaggedPacket {
        TaggedPacket {
            now: self.epoch + at,
            transport: TransportContext::default(),
            message: AttributedPacket::new(packet),
        }
    }

    /// One RTP packet of 1200 bytes on the wire, one frame per packet.
    fn send(&mut self, at: Duration, ssrc: u32) {
        self.send_sized(at, ssrc, 1188);
    }

    /// One RTP packet with a payload of `payload` bytes, one frame per packet.
    fn send_sized(&mut self, at: Duration, ssrc: u32, payload: usize) {
        self.sequence = self.sequence.wrapping_add(1);
        let packet = rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number: self.sequence,
                timestamp: (at.as_micros() as u32).wrapping_mul(90) / 1000,
                ssrc,
                ..Default::default()
            },
            payload: vec![0u8; payload].into(),
        };
        let message = self.tagged(at, Packet::Rtp(packet));
        self.chain.handle_write(message).expect("write");
        self.drain();
    }

    /// One RTP packet of 1200 bytes on `ssrc`, numbered in the SSRC's own sequence (from 1).
    /// Returns its sequence number.
    fn send_numbered(&mut self, at: Duration, ssrc: u32) -> u32 {
        let sequence = self.numbered.entry(ssrc).or_insert(0);
        *sequence = sequence.wrapping_add(1);
        let sequence_number = *sequence;
        let packet = rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                timestamp: (at.as_micros() as u32).wrapping_mul(90) / 1000,
                ssrc,
                ..Default::default()
            },
            payload: vec![0u8; 1188].into(),
        };
        let message = self.tagged(at, Packet::Rtp(packet));
        self.chain.handle_write(message).expect("write");
        self.drain();
        u32::from(sequence_number)
    }

    /// `per_second` packets a second on `ssrc` from `from` up to `to`.
    fn send_for(&mut self, from: Duration, to: Duration, ssrc: u32, per_second: u32) {
        let step = Duration::from_secs(1) / per_second;
        let mut at = from;
        while at < to {
            self.send(at, ssrc);
            at += step;
        }
    }

    /// The sender report whose LSR the receiver echoes.
    fn send_sender_report(&mut self, at: Duration, ssrc: u32) {
        let message = self.tagged(
            at,
            Packet::Rtcp(vec![Box::new(SenderReport {
                ssrc,
                ntp_time: NTP,
                ..Default::default()
            })]),
        );
        self.chain.handle_write(message).expect("write");
        self.drain();
    }

    fn receive(&mut self, at: Duration, packets: Vec<Box<dyn rtcp::Packet>>) {
        let mut message = self.tagged(at, Packet::Rtcp(packets));
        if let Some(interval) = self.interval {
            message.message.add(Attribute::Custom(Arc::new(interval)));
        }
        self.chain.handle_read(message).expect("read");
        self.drain();
    }

    /// A report block about `ssrc` with nothing lost, carried in the receiver's sender report.
    fn report_in_sender_report(&mut self, at: Duration, ssrc: u32, highest: u32) {
        self.receive(
            at,
            vec![Box::new(SenderReport {
                ssrc: 0x9999_9999,
                reports: vec![ReceptionReport {
                    ssrc,
                    last_sequence_number: highest,
                    ..Default::default()
                }],
                ..Default::default()
            })],
        );
    }

    /// The cumulative number lost a receiver reporting `fraction_lost` of the packets up to
    /// `highest` would report.
    fn cumulative(&mut self, ssrc: u32, fraction_lost: u8, highest: u32) -> i32 {
        let (previous, lost) = self.reported.get(&ssrc).copied().unwrap_or((0, 0));
        let expected = i64::from(highest.saturating_sub(previous));
        let lost = lost + (expected * i64::from(fraction_lost) / 256) as i32;
        self.reported.insert(ssrc, (highest, lost));
        lost
    }

    /// A receiver report about `ssrc`: the fraction lost (in 1/256) and the extended highest
    /// sequence number received, with the cumulative number lost that goes with them.
    fn report(&mut self, at: Duration, ssrc: u32, fraction_lost: u8, highest: u32) {
        let lost = self.cumulative(ssrc, fraction_lost, highest);
        self.report_counts(at, ssrc, fraction_lost, highest, lost);
    }

    /// A receiver report with the cumulative number lost given as it is.
    fn report_counts(
        &mut self,
        at: Duration,
        ssrc: u32,
        fraction_lost: u8,
        highest: u32,
        cumulative_lost: i32,
    ) {
        let mut block = ReceptionReport {
            ssrc,
            fraction_lost,
            last_sequence_number: highest,
            ..Default::default()
        };
        block.set_cumulative_lost(cumulative_lost);
        self.receive(
            at,
            vec![Box::new(ReceiverReport {
                ssrc: 0x9999_9999,
                reports: vec![block],
                ..Default::default()
            })],
        );
    }

    /// The same, echoing the sender report sent at `sr_at` so the round trip is `rtt`.
    fn report_with_rtt(
        &mut self,
        at: Duration,
        ssrc: u32,
        fraction_lost: u8,
        highest: u32,
        sr_at: Duration,
        rtt: Duration,
    ) {
        let held = at - sr_at - rtt;
        let lost = self.cumulative(ssrc, fraction_lost, highest);
        let mut block = ReceptionReport {
            ssrc,
            fraction_lost,
            last_sequence_number: highest,
            last_sender_report: (NTP >> 16) as u32,
            delay: (held.as_secs_f64() * 65_536.0) as u32,
            ..Default::default()
        };
        block.set_cumulative_lost(lost);
        self.receive(
            at,
            vec![Box::new(ReceiverReport {
                ssrc: 0x9999_9999,
                reports: vec![block],
                ..Default::default()
            })],
        );
    }

    fn tick(&mut self, at: Duration) {
        self.chain.handle_timeout(self.epoch + at).expect("timeout");
        self.drain();
    }

    fn reason(&self, ssrc: u32) -> Option<CircuitBreakerReason> {
        match self.handle.state(ssrc) {
            Some(CircuitBreakerState::Ceased { reason, .. }) => Some(reason),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Breaker 1: RTCP timeout (section 4.1)
// ---------------------------------------------------------------------------------------------

/// Section 4.1: a sender that has received no RTCP reporting on its SSRC for three times its
/// deterministic reporting interval (Tmin = 5 s) ceases transmission.
#[test]
fn media_sent_with_no_rtcp_for_three_intervals_ceases() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());

    harness.send_for(ms(0), ms(14_900), VIDEO, 10);
    assert_eq!(
        Some(ms(15_000)),
        harness
            .chain
            .poll_timeout()
            .map(|at| at.duration_since(harness.epoch)),
        "three intervals of five seconds after media was first sent"
    );
    harness.tick(ms(14_999));
    assert_eq!(
        Some(CircuitBreakerState::Running),
        harness.handle.state(VIDEO)
    );

    harness.tick(ms(15_000));
    assert_eq!(
        Some(CircuitBreakerReason::RtcpTimeout),
        harness.reason(VIDEO)
    );
    assert_eq!(
        Some(CircuitBreakerState::Running),
        harness.handle.state(AUDIO),
        "a flow that sent nothing has nothing to cease"
    );

    // Section 4.5: transmission has ceased.
    let left = harness.left;
    harness.send(ms(15_100), VIDEO);
    assert_eq!(left, harness.left, "the packet does not leave");
    assert_eq!(1, harness.handle.dropped());
    assert_eq!(
        None,
        harness.chain.poll_timeout(),
        "and no timer is left running"
    );
}

/// Section 4.1: a report on any SSRC the sender uses on the same transport shows the receiver
/// and the return path are working.
#[test]
fn a_report_on_another_ssrc_of_the_sender_prevents_the_rtcp_timeout() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());

    for second in 0..40u64 {
        harness.send_for(ms(second * 1000), ms(second * 1000 + 1000), VIDEO, 10);
        harness.send(ms(second * 1000 + 500), AUDIO);
        // Round-robin reporting that only ever names the audio SSRC.
        harness.report(ms(second * 1000 + 999), AUDIO, 0, second as u32 + 1);
        harness.tick(ms(second * 1000 + 1000));
    }

    assert_eq!(
        Some(CircuitBreakerState::Running),
        harness.handle.state(VIDEO)
    );
}

/// Section 4.1 asks for reports "on the SSRC it is using": a receiver report that names none of
/// this sender's SSRCs is not a report on its media.
#[test]
fn a_report_that_names_none_of_the_senders_ssrcs_does_not_prevent_the_rtcp_timeout() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());

    for second in 0..15u64 {
        harness.send_for(ms(second * 1000), ms(second * 1000 + 1000), VIDEO, 10);
        harness.report(ms(second * 1000 + 999), 0x7777_7777, 0, second as u32);
    }
    harness.tick(ms(15_000));

    assert_eq!(
        Some(CircuitBreakerReason::RtcpTimeout),
        harness.reason(VIDEO)
    );
}

/// Section 5: a reduced-size RTCP packet without SR or RR is counted as received for the RTCP
/// timeout breaker.
#[test]
fn reduced_size_rtcp_without_a_report_counts_for_the_rtcp_timeout() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());

    for second in 0..40u64 {
        harness.send_for(ms(second * 1000), ms(second * 1000 + 1000), VIDEO, 10);
        harness.receive(
            ms(second * 1000 + 999),
            vec![Box::new(
                rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication {
                    sender_ssrc: 0x9999_9999,
                    media_ssrc: VIDEO,
                },
            )],
        );
        harness.tick(ms(second * 1000 + 1000));
    }

    assert_eq!(
        Some(CircuitBreakerState::Running),
        harness.handle.state(VIDEO)
    );
}

// ---------------------------------------------------------------------------------------------
// Breaker 2: media timeout (section 4.2)
// ---------------------------------------------------------------------------------------------

/// Section 4.2: MEDIA_TIMEOUT consecutive reports showing a non-increasing extended highest
/// sequence number while media is being sent trip the breaker; with reports every second and
/// 10 packets a second MEDIA_TIMEOUT is k = 5.
#[test]
fn five_reports_without_progress_trip_the_media_timeout() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());

    // The media arrives for three seconds.
    for second in 0..3u64 {
        harness.send_for(ms(second * 1000), ms(second * 1000 + 1000), VIDEO, 10);
        harness.report(ms(second * 1000 + 999), VIDEO, 0, (second as u32 + 1) * 10);
    }
    // Then the forward path fails: the receiver keeps reporting, the number stops moving.
    for second in 3..7u64 {
        harness.send_for(ms(second * 1000), ms(second * 1000 + 1000), VIDEO, 10);
        harness.report(ms(second * 1000 + 999), VIDEO, 0, 30);
        assert_eq!(
            Some(CircuitBreakerState::Running),
            harness.handle.state(VIDEO),
            "{} stalled reports are fewer than MEDIA_TIMEOUT",
            second - 2
        );
    }
    harness.send_for(ms(7000), ms(8000), VIDEO, 10);
    harness.report(ms(7999), VIDEO, 0, 30);

    assert_eq!(
        Some(CircuitBreakerReason::MediaTimeout),
        harness.reason(VIDEO)
    );
}

/// Section 4.2: a report that indicates reception cancels the breaker; a new one is set.
#[test]
fn a_report_showing_reception_cancels_the_media_timeout() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());

    let mut highest = 10;
    for second in 0..30u64 {
        harness.send_for(ms(second * 1000), ms(second * 1000 + 1000), VIDEO, 10);
        // Four stalled reports, then one that shows progress, over and over.
        if second % 5 == 4 {
            highest += 50;
        }
        harness.report(ms(second * 1000 + 999), VIDEO, 0, highest);
    }

    assert_eq!(
        Some(CircuitBreakerState::Running),
        harness.handle.state(VIDEO)
    );
}

/// Section 4.2: the timeout scales with the framing interval. A source that sends a frame
/// every three seconds against reports every second has MEDIA_TIMEOUT = ceil(5 * 3 / 1) = 15,
/// so five reports without progress do not trip it.
#[test]
fn the_media_timeout_scales_with_a_slow_frame_rate() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());

    harness.send(ms(0), VIDEO);
    harness.report(ms(999), VIDEO, 0, 1);
    // Reports without progress count from the first one that follows media the receiver did
    // not see: the frame sent at 3 s. Fourteen of them by the report at 16 s.
    for second in 1..17u64 {
        if second % 3 == 0 {
            harness.send(ms(second * 1000), VIDEO);
        }
        harness.report(ms(second * 1000 + 999), VIDEO, 0, 1);
    }
    assert_eq!(
        Some(CircuitBreakerState::Running),
        harness.handle.state(VIDEO),
        "14 stalled reports are fewer than 15"
    );

    harness.report(ms(17_999), VIDEO, 0, 1);
    assert_eq!(
        Some(CircuitBreakerReason::MediaTimeout),
        harness.reason(VIDEO)
    );
}

/// Section 4.2: stopping a stream cancels its media timeout breaker.
#[test]
fn unbinding_a_stream_cancels_its_breakers() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());
    harness.send_for(ms(0), ms(1000), VIDEO, 10);

    harness.chain.unbind_local_stream(&StreamInfo {
        ssrc: VIDEO,
        ..Default::default()
    });

    assert_eq!(None, harness.handle.state(VIDEO));
    assert_eq!(
        None,
        harness.chain.poll_timeout(),
        "nothing sent is waiting for a report"
    );
}

/// Section 4.2 counts RTCP packets "indicating that the media being sent was not received".
/// A report that reaches the sender less than a round trip after a packet left cannot show
/// that packet, arrived or not: it says nothing of it. A voice flow (a packet every 20 ms, a
/// 20 ms round trip) whose receiver's calculated interval is 100 ms gets six reports 2 ms
/// apart right after a packet left (early feedback packets that carry a report): none
/// counts. The packet and the ones after it are then lost, and the reports that keep coming
/// count from the instant the packet is a round trip old: MEDIA_TIMEOUT = 5 of them later the
/// breaker trips (section 5: such reports are "counted towards the circuit breaker
/// conditions", which "will potentially make the RTP circuit breaker trigger earlier").
#[test]
fn a_report_within_a_round_trip_of_a_packet_says_nothing_of_it() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());
    harness.interval = Some(RtcpReportingInterval {
        sender: ms(100),
        receiver: ms(100),
    });
    harness.handle.report_round_trip_time(ms(20));

    // A second of voice, reported every 100 ms.
    let mut arrived = 0;
    for t in (0..1000u64).step_by(20) {
        arrived = harness.send_numbered(ms(t), AUDIO);
        if t % 100 == 80 {
            harness.report(ms(t + 15), AUDIO, 0, arrived);
        }
    }

    // A packet leaves, and six reports follow it within its round trip.
    harness.send_numbered(ms(1000), AUDIO);
    for t in (1002..=1018u64).step_by(2) {
        harness.report(ms(t), AUDIO, 0, arrived);
        assert_eq!(
            Some(CircuitBreakerState::Running),
            harness.handle.state(AUDIO),
            "the report at {t} ms comes before the packet could have been reported"
        );
    }

    // It never arrives, nor does the next. From 20 ms after it left the reports count.
    harness.send_numbered(ms(1020), AUDIO);
    for t in (1020..=1026u64).step_by(2) {
        harness.report(ms(t), AUDIO, 0, arrived);
        assert_eq!(
            Some(CircuitBreakerState::Running),
            harness.handle.state(AUDIO),
            "{} reports without progress are fewer than MEDIA_TIMEOUT",
            (t - 1018) / 2
        );
    }
    harness.report(ms(1028), AUDIO, 0, arrived);
    assert_eq!(
        Some(CircuitBreakerReason::MediaTimeout),
        harness.reason(AUDIO)
    );
}

/// Section 4.2: "If RTP data packets are being sent but the RTCP SR or RR packets ...
/// indicate a non-increasing extended highest sequence number", and "When stopping sending an
/// RTP stream, a sender MUST cancel the corresponding media timeout circuit breaker". A flow
/// (a packet every 20 ms, reports every 100 ms) loses its last three packets and then stops:
/// its packets wait in a paused pacer, or its source is muted. Twenty reports without
/// progress follow and the flow is not ceased. When it sends again into a path that delivers
/// nothing the breaker trips, after MEDIA_TIMEOUT = ceil(5 * 2.02 / 0.1) = 101 reports: the
/// pause is the flow's longest frame interval of the last ten seconds (Tf).
#[test]
fn a_flow_that_stops_sending_has_its_media_timeout_cancelled() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());
    let mut arrived = 0;
    for t in (0..1000u64).step_by(20) {
        let sent = harness.send_numbered(ms(t), VIDEO);
        if t < 940 {
            arrived = sent;
        }
        if t % 100 == 80 {
            harness.report(ms(t + 19), VIDEO, 0, arrived);
        }
    }

    // Nothing is sent for two seconds; the receiver keeps reporting.
    for t in (1099..3000u64).step_by(100) {
        harness.report(ms(t), VIDEO, 0, arrived);
        assert_eq!(
            Some(CircuitBreakerState::Running),
            harness.handle.state(VIDEO),
            "at {t} ms the flow is not sending"
        );
    }

    // It sends again and nothing arrives.
    for t in 3000..=13_099u64 {
        if t % 20 == 0 {
            harness.send_numbered(ms(t), VIDEO);
        }
        if t % 100 == 99 {
            harness.report(ms(t), VIDEO, 0, arrived);
            if t < 13_099 {
                assert_eq!(
                    Some(CircuitBreakerState::Running),
                    harness.handle.state(VIDEO),
                    "at {t} ms: fewer than 101 reports without progress"
                );
            }
        }
    }
    assert_eq!(
        Some(CircuitBreakerReason::MediaTimeout),
        harness.reason(VIDEO)
    );
}

/// When the first report without progress that counts arrives on a flow that sends a packet
/// every `packet_ms`, is reported every `report_ms` and stops arriving after `arrives_until`;
/// `None` when the breaker does not trip before `until`.
fn media_timeout_at(
    interval: Option<RtcpReportingInterval>,
    in_sender_report: bool,
    packet_ms: u64,
    report_ms: u64,
    arrives_until: u64,
    until: u64,
) -> Option<u64> {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());
    harness.interval = interval;
    let mut arrived = 0;
    for t in 0..until {
        if t % packet_ms == 0 {
            let sent = harness.send_numbered(ms(t), VIDEO);
            if t < arrives_until {
                arrived = sent;
            }
        }
        if t % report_ms == report_ms / 2 {
            if in_sender_report {
                harness.report_in_sender_report(ms(t), VIDEO, arrived);
            } else {
                harness.report(ms(t), VIDEO, 0, arrived);
            }
            if harness.reason(VIDEO).is_some() {
                return Some(t);
            }
        }
    }
    None
}

/// Section 3: Tdr is "the sender's estimate of the deterministic RTCP reporting interval, Td,
/// calculated by a receiver", which "can be estimated by executing the algorithm in Section
/// 6.2 of \[RFC3550\]". The chain's RTCP session executes it and says what it gives; reports
/// that come closer together than that do not shorten Tdr, they are each counted (section 5).
/// A flow that sends a frame a second (Tf = 1 s) and is reported every 100 ms, the calculated
/// interval one second: MEDIA_TIMEOUT = ceil(5 * 1 / 1) = 5, and the fifth report after the
/// lost frame trips the breaker, 450 ms after it left. With no RTCP session to say what the
/// interval is, Tdr is the spacing of the reports, MEDIA_TIMEOUT = ceil(5 * 1 / 0.1) = 50.
#[test]
fn reports_closer_together_than_the_calculated_interval_do_not_shorten_tdr() {
    let second = RtcpReportingInterval {
        sender: ms(1000),
        receiver: ms(1000),
    };
    assert_eq!(
        Some(3450),
        media_timeout_at(Some(second), false, 1000, 100, 3000, 9000)
    );
    assert_eq!(
        Some(7950),
        media_timeout_at(None, false, 1000, 100, 3000, 9000)
    );
}

/// Section 4.3: "If the incoming RTCP SR or RR packets are using a reduced minimum RTCP
/// reporting interval ..., then that reduced RTCP reporting interval is used": the interval
/// is the one the receiver's reports use. A receiver that reports every second where the
/// calculation gives 30 ms (it keeps a minimum of its own: a browser, a `T_rr_interval`) has
/// Tdr = 1 s: ten packets a second, MEDIA_TIMEOUT = k = 5 reports, not ceil(5 * 0.1 / 0.03).
#[test]
fn a_receiver_that_reports_less_often_than_calculated_has_the_interval_its_reports_show() {
    let calculated = RtcpReportingInterval {
        sender: ms(30),
        receiver: ms(30),
    };
    // The packet sent at 3 s is the first lost. The report at 3.5 s still shows progress (the
    // packets up to 2.9 s); those at 4.5, 5.5, 6.5, 7.5 and 8.5 s do not.
    assert_eq!(
        Some(8500),
        media_timeout_at(Some(calculated), false, 100, 1000, 3000, 20_000)
    );
}

/// Section 3: the estimate takes "whether the receiver is sending SR or RR packets" (RFC 3550
/// section 6.3.1 gives senders and receivers their own shares of the RTCP bandwidth). The
/// session says both intervals; a report block is held against the one of the packet that
/// carried it. A frame every four seconds, reports every second, 30 ms calculated for a
/// sender and 2 s for a receiver: in receiver reports Tdr = 2 s and MEDIA_TIMEOUT =
/// ceil(5 * 4 / 2) = 10, in sender reports Tdr is the reports' second and it is 20.
#[test]
fn the_calculated_interval_is_that_of_a_receiver_that_sends_or_does_not() {
    let calculated = RtcpReportingInterval {
        sender: ms(30),
        receiver: ms(2000),
    };
    assert_eq!(
        Some(13_500),
        media_timeout_at(Some(calculated), false, 4000, 1000, 1, 30_000)
    );
    assert_eq!(
        Some(23_500),
        media_timeout_at(Some(calculated), true, 4000, 1000, 1, 30_000)
    );
}

/// Section 3: "Tr = (0.8 * Tr) + (0.2 * Tr_new) where Tr_new is the latest RTT estimate".
/// The round trip times a congestion controller hands in are measurements, smoothed here and
/// only here: 100 ms and then 500 ms make Tr 180 ms. A flow reported every 100 ms then has
/// MEDIA_TIMEOUT = ceil(5 * 0.18 / 0.1) = 9, counted from the first report that comes a round
/// trip after the first lost packet (sent at 1 s): the ninth is the report at 1.999 s.
#[test]
fn the_round_trip_times_handed_in_are_smoothed_once() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());
    harness.handle.report_round_trip_time(ms(100));
    harness.handle.report_round_trip_time(ms(500));
    let mut arrived = 0;
    for t in 0..2000u64 {
        if t % 20 == 0 {
            let sent = harness.send_numbered(ms(t), VIDEO);
            if t < 1000 {
                arrived = sent;
            }
        }
        if t % 100 == 99 {
            harness.report(ms(t), VIDEO, 0, arrived);
            if t < 1999 {
                assert_eq!(
                    Some(CircuitBreakerState::Running),
                    harness.handle.state(VIDEO),
                    "at {t} ms"
                );
            }
        }
    }
    assert_eq!(
        Some(CircuitBreakerReason::MediaTimeout),
        harness.reason(VIDEO)
    );
}

// ---------------------------------------------------------------------------------------------
// Breaker 3: congestion (section 4.3)
// ---------------------------------------------------------------------------------------------

/// One second of media at `per_second` packets, then the receiver's report with a 100 ms round
/// trip and the given loss.
fn congested_second(harness: &mut Harness, second: u64, per_second: u32, fraction_lost: u8) {
    let start = ms(second * 1000);
    harness.send_sender_report(start, VIDEO);
    harness.send_for(start, start + ms(1000), VIDEO, per_second);
    harness.received += per_second;
    let received = harness.received;
    harness.report_with_rtt(
        start + ms(999),
        VIDEO,
        fraction_lost,
        received,
        start,
        ms(100),
    );
}

/// Section 4.3: with 25% loss and a 100 ms round trip, TCP would achieve
/// 1200 / (0.1 * sqrt(2 * 0.25 / 3)) = 29.4 kB/s. A flow sending 480 kB/s is more than ten times
/// that, and trips once more than CB_INTERVAL (3) report blocks have been received.
#[test]
fn a_flow_sending_ten_times_the_tcp_throughput_trips_the_congestion_breaker() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());

    for second in 0..3u64 {
        congested_second(&mut harness, second, 400, 64);
        assert_eq!(
            Some(CircuitBreakerState::Running),
            harness.handle.state(VIDEO),
            "not before more than CB_INTERVAL reports"
        );
    }
    congested_second(&mut harness, 3, 400, 64);

    assert_eq!(
        Some(CircuitBreakerReason::Congestion),
        harness.reason(VIDEO)
    );
}

/// Tr is the RFC 3550 round trip time, which needs the instant a sender report left. When the
/// report generator is wire-ward of the breaker no sender report passes it, and the round trip
/// time the congestion controller measured is used instead: without one the congestion breaker
/// could never compare the flow with TCP.
#[test]
fn the_congestion_breaker_uses_a_reported_round_trip_time_when_it_sees_no_sender_report() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());

    // No sender report is written through the chain, and the reports echo none.
    let mut unmeasured = Harness::new(CircuitBreakerBuilder::new());
    for (harness, reported) in [(&mut harness, true), (&mut unmeasured, false)] {
        if reported {
            harness.handle.report_round_trip_time(ms(100));
        }
        for second in 0..6u64 {
            let start = ms(second * 1000);
            harness.send_for(start, start + ms(1000), VIDEO, 400);
            harness.report(start + ms(999), VIDEO, 64, (second as u32 + 1) * 400);
        }
    }

    assert_eq!(
        Some(CircuitBreakerReason::Congestion),
        harness.reason(VIDEO)
    );
    assert_eq!(
        Some(CircuitBreakerState::Running),
        unmeasured.handle.state(VIDEO),
        "with no round trip time at all there is nothing to compare with"
    );
}

/// Section 4.3 with RFC 3550's loss counts: on a path that reorders and loses nothing, a
/// packet overtaken across a report's boundary is missing from one interval (its fraction
/// lost is positive, the cumulative count goes up) and arrives in the next (whose fraction
/// lost cannot go below zero, while the cumulative count comes back down). The average of
/// the fractions then shows loss the receiver's own cumulative count says never happened.
///
/// 1000 packets a second of 1200 bytes (1.2 MB/s), a 100 ms round trip, a report every
/// 200 ms (CB_INTERVAL 5): every other report says 10 of its 200 packets are missing (12/256)
/// and the next one says none, the cumulative count back at 0. The average, 2.5 %, puts ten
/// times TCP at 0.93 MB/s, under the flow's rate; the most the cumulative count shows over
/// five reports is 10 of 1000 (the last interval's packets still on their way), which puts
/// it at 1.47 MB/s. The flow keeps running. The same fractions with the cumulative count
/// growing (the packets really lost) trip it.
#[test]
fn reordering_that_the_cumulative_count_takes_back_does_not_trip_the_congestion_breaker() {
    let run = |real_loss: bool| {
        let mut harness = Harness::new(CircuitBreakerBuilder::new());
        harness.handle.report_round_trip_time(ms(100));
        let mut lost = 0;
        for interval in 0..40u64 {
            let start = ms(interval * 200);
            harness.send_for(start, start + ms(200), VIDEO, 1000);
            harness.received += 200;
            let fraction = if interval % 2 == 0 {
                lost += 10;
                12
            } else {
                if !real_loss {
                    lost -= 10;
                }
                0
            };
            let received = harness.received;
            harness.report_counts(start + ms(199), VIDEO, fraction, received, lost);
        }
        harness.handle.state(VIDEO)
    };
    assert_eq!(Some(CircuitBreakerState::Running), run(false));
    assert!(
        matches!(
            run(true),
            Some(CircuitBreakerState::Ceased {
                reason: CircuitBreakerReason::Congestion,
                ..
            })
        ),
        "the same fractions with the packets really lost"
    );
}

/// Six seconds of 500 sequence numbers a second on VIDEO from `first + 1`, each second reported
/// with 100 of them lost (51/256, the cumulative count 100 up) and a 100 ms round trip. With
/// `discards`, numbers 201 to 300 of each second are numbered and never leave, as after a
/// pacer discard application-ward of the breaker (`PacerQueueOverflow::Drop`): taken as path
/// loss, the 400 packets that leave (480 kB/s) are more than ten times the 40 kB/s TCP would
/// get at the 13.3% the cumulative count shows over CB_INTERVAL.
fn reports_of_loss_that_was_never_sent(first: u16, discards: bool) -> Option<CircuitBreakerState> {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());
    harness.handle.report_round_trip_time(ms(100));
    harness.sequence = first;
    let mut highest = u32::from(first);
    for second in 0..6u64 {
        let start = ms(second * 1000);
        if discards {
            harness.send_for(start, start + ms(500), VIDEO, 400);
            harness.sequence = harness.sequence.wrapping_add(100);
            harness.send_for(start + ms(500), start + ms(1000), VIDEO, 400);
        } else {
            harness.send_for(start, start + ms(1000), VIDEO, 500);
        }
        highest += 500;
        let lost = (second as i32 + 1) * 100;
        harness.report_counts(start + ms(999), VIDEO, 51, highest, lost);
    }
    harness.handle.state(VIDEO)
}

/// Section 4.3 takes the loss from the receiver's reports, and the receiver counts every
/// sequence number it did not receive as lost (RFC 3550 section 6.4.1), the ones the pacer
/// discarded before they left included. The breaker sees exactly the packets that left: over
/// the interval a report covers, the numbers it never saw leave come out of the loss and out
/// of the packets expected. Reports whose loss is all such numbers do not trip the congestion
/// breaker; the same reports for a stream that left whole do.
#[test]
fn reported_loss_of_sequence_numbers_never_sent_does_not_trip_the_congestion_breaker() {
    assert_eq!(
        Some(CircuitBreakerState::Running),
        reports_of_loss_that_was_never_sent(0, true)
    );
    assert!(
        matches!(
            reports_of_loss_that_was_never_sent(0, false),
            Some(CircuitBreakerState::Ceased {
                reason: CircuitBreakerReason::Congestion,
                ..
            })
        ),
        "the same reports for a stream that left whole"
    );
}

/// The same with the numbers never sent across the wrap of the 16-bit sequence number: the
/// first second's 65531 to 65535 and 0 to 94, reported against an extended highest sequence
/// number one cycle on.
#[test]
fn reported_loss_of_sequence_numbers_never_sent_across_the_wrap_does_not_trip_the_congestion_breaker()
 {
    assert_eq!(
        Some(CircuitBreakerState::Running),
        reports_of_loss_that_was_never_sent(65_330, true)
    );
    assert!(
        matches!(
            reports_of_loss_that_was_never_sent(65_330, false),
            Some(CircuitBreakerState::Ceased {
                reason: CircuitBreakerReason::Congestion,
                ..
            })
        ),
        "the same reports for a stream that left whole"
    );
}

/// RFC 8083 section 4.3 compares the sending rate with ten times X = s / (Tr * sqrt(2p/3)).
/// By default s is the mean size of the packets sent over the reporting intervals the rate is
/// measured over (bytes sent / packets sent there), so both describe the same packets. A
/// speech-like flow, each second 40 packets of 1200 bytes and then 10 silence frames of 23
/// bytes (48 kB/s), over a path that loses one packet in 50 (each report: 5/256, the
/// cumulative count one up) with a 100 ms round trip. Over CB_INTERVAL (3 reports) the
/// confirmed loss is 2 in 150: by the window s is 965 bytes and ten times X about 1 MB/s, and
/// the call keeps running. Section 3's "last 4 * G frames"
/// (`CircuitBreakerPacketSize::LastFrames`) takes the silence frames' 23 bytes, ten times X
/// falls to 24 kB/s, and the flow is ceased.
#[test]
fn the_packet_size_is_that_of_the_window_the_rate_is_measured_over() {
    let run = |packet_size: Option<CircuitBreakerPacketSize>| {
        let builder = match packet_size {
            Some(packet_size) => CircuitBreakerBuilder::new().with_packet_size(packet_size),
            None => CircuitBreakerBuilder::new(),
        };
        let mut harness = Harness::new(builder);
        harness.handle.report_round_trip_time(ms(100));
        let mut lost = 0;
        for second in 0..12u64 {
            let start = ms(second * 1000);
            for n in 0..50u64 {
                let payload = if n < 40 { 1188 } else { 11 };
                harness.send_sized(start + ms(n * 20), VIDEO, payload);
            }
            harness.received += 50;
            lost += 1;
            let received = harness.received;
            harness.report_counts(start + ms(999), VIDEO, 5, received, lost);
        }
        harness.handle.state(VIDEO)
    };
    assert_eq!(
        Some(CircuitBreakerState::Running),
        run(None),
        "the default is the window's packet size"
    );
    assert_eq!(
        Some(CircuitBreakerState::Running),
        run(Some(CircuitBreakerPacketSize::SendingWindow))
    );
    assert!(
        matches!(
            run(Some(CircuitBreakerPacketSize::LastFrames)),
            Some(CircuitBreakerState::Ceased {
                reason: CircuitBreakerReason::Congestion,
                ..
            })
        ),
        "the last frames' packet size"
    );
}

/// Section 4.3: "a sender that is transmitting at least one RTP packet every max(Tdr, Tr)
/// seconds" is judged on its rate, not on every report. A video flow sending a frame of 19
/// packets every 20 ms (1.1 MB/s) whose receiver reports every 10 ms (AVPF compounds) sees no
/// packet between every other pair of reports; those reports used to clear the samples, so
/// the breaker never judged the flow. With 25 % loss and a 100 ms round trip (ten times TCP is
/// 0.3 MB/s) it now trips.
#[test]
fn reports_closer_together_than_the_frames_still_judge_the_flow() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());
    harness.handle.report_round_trip_time(ms(100));
    let mut lost = 0i32;
    for tick in 0..600u64 {
        let at = ms(tick * 10);
        if tick % 2 == 0 {
            for _ in 0..19 {
                harness.send(at, VIDEO);
            }
            harness.received += 19;
            lost += 5;
        }
        let received = harness.received;
        let fraction = if tick % 2 == 0 { 67 } else { 0 };
        harness.report_counts(at + ms(5), VIDEO, fraction, received, lost);
    }
    assert_eq!(
        Some(CircuitBreakerReason::Congestion),
        harness.reason(VIDEO)
    );
}

/// The same loss does not trip a flow within ten times the TCP throughput: 100 packets a second
/// is 120 kB/s against a bound of 294 kB/s.
#[test]
fn a_flow_within_ten_times_the_tcp_throughput_keeps_running() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());

    for second in 0..30u64 {
        congested_second(&mut harness, second, 100, 64);
    }

    assert_eq!(
        Some(CircuitBreakerState::Running),
        harness.handle.state(VIDEO)
    );
}

/// Section 4.3 compares X with "the actual sending rate of the RTP stream", and CB_INTERVAL is
/// there "to give the congestion control algorithm time to react to congestion". A flow that
/// sent 480 kB/s into 25 % loss for three seconds and then came down to 120 kB/s (ten times
/// TCP is about 300 kB/s) is, at the fourth report, still above the bound on the average of
/// the three intervals the loss is averaged over (360 kB/s) and under it at the rate it sends
/// now: it reacted, and it is not ceased, then or later. The flow that stays at 480 kB/s is
/// (`a_flow_sending_ten_times_the_tcp_throughput_trips_the_congestion_breaker`).
#[test]
fn a_flow_that_brought_its_rate_down_within_cb_interval_is_not_ceased() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());

    for second in 0..30u64 {
        let per_second = if second < 3 { 400 } else { 100 };
        congested_second(&mut harness, second, per_second, 64);
        assert_eq!(
            Some(CircuitBreakerState::Running),
            harness.handle.state(VIDEO),
            "second {second}"
        );
    }
}

/// A flow of 1200-byte packets on VIDEO at `before` kbit/s until `falls_at` and at `after`
/// kbit/s from then on, with a report every `every` that shows `loss`/256 of what was sent
/// lost and a round trip of `rtt`. Returns when the breaker ceased the flow, if it did before
/// `until`.
fn rate_through_a_collapse(
    every: Duration,
    rtt: Duration,
    loss: u8,
    (before, after): (u32, u32),
    falls_at: Duration,
    until: Duration,
) -> Option<Duration> {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());
    harness.handle.report_round_trip_time(rtt);
    let gap = |kbps: u32| Duration::from_secs_f64(1200.0 * 8.0 / (f64::from(kbps) * 1000.0));
    let (mut packet_at, mut report_at) = (Duration::ZERO, every);
    let mut sent = 0u32;
    while packet_at.min(report_at) < until {
        if packet_at <= report_at {
            harness.send(packet_at, VIDEO);
            sent += 1;
            packet_at += gap(if packet_at < falls_at { before } else { after });
        } else {
            let lost = (u64::from(sent) * u64::from(loss) / 256) as i32;
            harness.report_counts(report_at, VIDEO, loss, sent, lost);
            if harness.reason(VIDEO).is_some() {
                return Some(report_at);
            }
            report_at += every;
        }
    }
    None
}

/// The figures of a call whose two directions lost their capacity at once (both peers'
/// video ceased 2 s later, for good): a report every 330 ms, a 142 ms round trip, 59 % of the
/// packets lost. CB_INTERVAL is ceil(1.42 / 0.33) = 5 reports and ten times TCP about
/// 137 kB/s. The video sends 200 kB/s for 1.6 s more and then 31 kB/s: at the sixth report
/// its average over the five intervals is 161 kB/s and it sends a fifth of the bound. It is
/// not ceased, and runs on under the same loss. A sender that stays at 200 kB/s is ceased at
/// that sixth report, 1.98 s in.
#[test]
fn a_video_flow_that_follows_a_collapse_of_both_directions_down_is_not_ceased() {
    let run = |after: u32| {
        rate_through_a_collapse(
            ms(330),
            ms(142),
            151,
            (1600, after),
            ms(1600),
            Duration::from_secs(10),
        )
    };
    assert_eq!(None, run(250));
    assert_eq!(Some(ms(1980)), run(1600));
}

/// The figures of a collapse behind a queue of a second (voice and video ceased 3.4 s in, for
/// good): a report every 38 ms, a round trip grown to 800 ms, 10 % lost. CB_INTERVAL is
/// ceil(8 / 0.038) = 211 reports (ten round trips) and ten times TCP 57.6 kB/s. A flow that
/// sent 75 kB/s for six seconds and has sent 37.5 kB/s since is at 65 kB/s on the average of
/// those 8 s and under the bound at the rate it sends: not ceased. One that stays at 75 kB/s
/// is, at report 212.
#[test]
fn a_flow_that_follows_a_collapse_behind_a_long_queue_down_is_not_ceased() {
    let run = |after: u32| {
        rate_through_a_collapse(
            ms(38),
            ms(800),
            26,
            (600, after),
            Duration::from_secs(6),
            Duration::from_secs(20),
        )
    };
    assert_eq!(None, run(300));
    assert_eq!(Some(ms(212 * 38)), run(600));
}

/// Section 4.3: the full TCP equation is more sensitive. At 25% loss it gives 3.8 kB/s, so the
/// 120 kB/s flow the simplified equation lets run is stopped.
#[test]
fn the_full_tcp_equation_trips_earlier() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new().with_full_tcp_equation(true));

    for second in 0..4u64 {
        congested_second(&mut harness, second, 100, 64);
    }

    assert_eq!(
        Some(CircuitBreakerReason::Congestion),
        harness.reason(VIDEO)
    );
}

/// Section 4.3: the sender may first reduce its rate by a factor of ten; if the breaker trips
/// again after the next CB_INTERVAL reports it MUST cease.
#[test]
fn a_flow_that_does_not_reduce_its_rate_ceases_at_the_second_trip() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new().with_rate_reduction(true));

    for second in 0..4u64 {
        congested_second(&mut harness, second, 400, 64);
    }
    let Some(CircuitBreakerState::Reduced {
        limit_bits_per_second,
    }) = harness.handle.state(VIDEO)
    else {
        panic!(
            "expected a reduction, got {:?}",
            harness.handle.state(VIDEO)
        );
    };
    assert!(
        (limit_bits_per_second - 384_000.0).abs() < 4_000.0,
        "a tenth of 3.84 Mbit/s, got {limit_bits_per_second}"
    );
    assert_eq!(Some(limit_bits_per_second), harness.handle.rate_limit());

    // The sender carries on as before.
    for second in 4..8u64 {
        congested_second(&mut harness, second, 400, 64);
    }
    assert_eq!(
        Some(CircuitBreakerReason::Congestion),
        harness.reason(VIDEO)
    );
}

/// And one that does reduce, and stays within the bound, runs on.
#[test]
fn a_flow_that_reduces_its_rate_keeps_running() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new().with_rate_reduction(true));

    for second in 0..4u64 {
        congested_second(&mut harness, second, 400, 64);
    }
    assert!(matches!(
        harness.handle.state(VIDEO),
        Some(CircuitBreakerState::Reduced { .. })
    ));

    for second in 4..12u64 {
        congested_second(&mut harness, second, 40, 64);
    }
    assert_eq!(
        Some(CircuitBreakerState::Running),
        harness.handle.state(VIDEO)
    );
    assert_eq!(None, harness.handle.rate_limit());
}

/// One second of media at 400 packets a second and 25% loss, with an 850 ms round trip.
fn congested_second_on_a_long_path(harness: &mut Harness, second: u64) {
    let start = ms(second * 1000);
    harness.send_sender_report(start, VIDEO);
    harness.send_for(start, start + ms(1000), VIDEO, 400);
    harness.report_with_rtt(
        start + ms(999),
        VIDEO,
        64,
        (second as u32 + 1) * 400,
        start,
        ms(850),
    );
}

/// Section 4.3: CB_INTERVAL gives the congestion controller ten round trips. With an 850 ms
/// round trip and reports every second that is ceil(8.5) = 9 reports, so the breaker does not
/// trip on the fourth report as it does on a short path.
#[test]
fn cb_interval_follows_the_round_trip_time() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());

    for second in 0..9u64 {
        congested_second_on_a_long_path(&mut harness, second);
        assert_eq!(
            Some(CircuitBreakerState::Running),
            harness.handle.state(VIDEO),
            "report {} of more than 9",
            second + 1
        );
    }
    congested_second_on_a_long_path(&mut harness, 9);
    assert_eq!(
        Some(CircuitBreakerReason::Congestion),
        harness.reason(VIDEO)
    );
}

/// Section 4.3: when T_rr_interval is used, Tdr in CB_INTERVAL is replaced by
/// max(T_rr_interval, Tdr). With T_rr_interval = 4 s the same flow has
/// CB_INTERVAL = ceil(3 * min(max(8.5, 12), 15) / 12) = 3.
#[test]
fn t_rr_interval_replaces_a_shorter_tdr_in_cb_interval() {
    let mut harness =
        Harness::new(CircuitBreakerBuilder::new().with_t_rr_interval(Duration::from_secs(4)));

    for second in 0..3u64 {
        congested_second_on_a_long_path(&mut harness, second);
        assert_eq!(
            Some(CircuitBreakerState::Running),
            harness.handle.state(VIDEO)
        );
    }
    congested_second_on_a_long_path(&mut harness, 3);
    assert_eq!(
        Some(CircuitBreakerReason::Congestion),
        harness.reason(VIDEO)
    );
}

/// Sections 4.1 and 4.3: T_rr_interval is not configured above 4 seconds. Asked for 60 s, the
/// breaker uses 4 s: CB_INTERVAL stays 3 where 60 s would make it 1.
#[test]
fn t_rr_interval_is_held_to_four_seconds() {
    let mut harness =
        Harness::new(CircuitBreakerBuilder::new().with_t_rr_interval(Duration::from_secs(60)));

    // With CB_INTERVAL = 1 the second report would already trip the breaker.
    for second in 0..3u64 {
        congested_second_on_a_long_path(&mut harness, second);
        assert_eq!(
            Some(CircuitBreakerState::Running),
            harness.handle.state(VIDEO)
        );
    }
    congested_second_on_a_long_path(&mut harness, 3);
    assert_eq!(
        Some(CircuitBreakerReason::Congestion),
        harness.reason(VIDEO)
    );
}

// ---------------------------------------------------------------------------------------------
// Breaker 4: media usability (section 4.4), ceasing and restarting (section 4.5), groups
// (section 8)
// ---------------------------------------------------------------------------------------------

/// Section 4.4: media that stays past the application's bound for the application's period is
/// no longer sent.
#[test]
fn media_unusable_for_the_configured_period_ceases() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new().with_media_usability(
        MediaUsability {
            max_loss: 0.5,
            max_round_trip_time: Duration::from_secs(2),
            period: Duration::from_secs(5),
        },
    ));

    // 60% loss at a rate far too low for the congestion breaker to care about.
    for second in 0..5u64 {
        harness.send_for(ms(second * 1000), ms(second * 1000 + 1000), VIDEO, 2);
        harness.report(ms(second * 1000 + 999), VIDEO, 154, (second as u32 + 1) * 2);
        assert_eq!(
            Some(CircuitBreakerState::Running),
            harness.handle.state(VIDEO)
        );
    }
    harness.send_for(ms(5000), ms(6000), VIDEO, 2);
    harness.report(ms(5999), VIDEO, 154, 12);

    assert_eq!(
        Some(CircuitBreakerReason::MediaUnusable),
        harness.reason(VIDEO)
    );
}

/// Section 4.4 judges usability by the loss the receiver reports, and the receiver counts every
/// sequence number it did not receive as lost (RFC 3550 section 6.4.1), the ones the pacer
/// discarded before they left included. Over the interval a report covers, the numbers the
/// breaker never saw leave come out of the loss. Six seconds of 10 sequence numbers a second on
/// VIDEO, each second reported with 6 of them lost (154/256, 60%, the cumulative count 6 up),
/// against a bound of 50% for 5 s; with no round trip time known the congestion breaker does
/// not run. With `discards`, numbers 3 to 8 of each second are numbered and never leave (2
/// packets, a gap of 6, 2 packets): the corrected loss is 0 and the flow keeps running. Sent
/// without gaps, the same reports are the path's loss: unusable from the first report (0.999 s),
/// the flow ceases at the sixth (5.999 s).
#[test]
fn reported_loss_of_sequence_numbers_never_sent_does_not_make_the_media_unusable() {
    let run = |discards: bool| {
        let mut harness = Harness::new(CircuitBreakerBuilder::new().with_media_usability(
            MediaUsability {
                max_loss: 0.5,
                max_round_trip_time: Duration::from_secs(2),
                period: Duration::from_secs(5),
            },
        ));
        for second in 0..6u64 {
            let start = ms(second * 1000);
            if discards {
                harness.send_for(start, start + ms(250), VIDEO, 8);
                harness.sequence = harness.sequence.wrapping_add(6);
                harness.send_for(start + ms(500), start + ms(750), VIDEO, 8);
            } else {
                harness.send_for(start, start + ms(1000), VIDEO, 10);
            }
            let highest = (second as u32 + 1) * 10;
            let lost = (second as i32 + 1) * 6;
            harness.report_counts(start + ms(999), VIDEO, 154, highest, lost);
        }
        harness.handle.state(VIDEO)
    };
    assert_eq!(Some(CircuitBreakerState::Running), run(true));
    assert!(
        matches!(
            run(false),
            Some(CircuitBreakerState::Ceased {
                reason: CircuitBreakerReason::MediaUnusable,
                ..
            })
        ),
        "the same reports for a stream that left whole"
    );
}

/// RFC 8083 section 4.5: a flow the breaker ceased stays ceased until it is restarted, and
/// where the breaker has nothing to restart it on that is the application's to do ("Ideally,
/// a human user will be involved"), so the application has to hear that a flow ceased: the
/// breaker says so application-ward at the instant it happens, once per flow, and again when
/// a restart takes effect.
#[test]
fn a_ceased_flow_and_its_restart_are_announced_application_ward() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());
    harness.send_for(ms(0), ms(1000), VIDEO, 10);
    harness.send_for(ms(0), ms(1000), AUDIO, 10);
    assert!(harness.notices.is_empty());
    harness.tick(ms(15_000));
    // Both flows ceased (the RTCP timeout is the session's): one notice each, with the
    // breaker that tripped and the triggering interval a restart has to wait.
    let mut ceased = harness.notices.clone();
    ceased.sort_by_key(|notice| notice.ssrc);
    assert_eq!(
        vec![
            CircuitBreakerNotice {
                ssrc: VIDEO,
                ceased: Some(CircuitBreakerReason::RtcpTimeout),
                restart_after: ms(15_000),
            },
            CircuitBreakerNotice {
                ssrc: AUDIO,
                ceased: Some(CircuitBreakerReason::RtcpTimeout),
                restart_after: ms(15_000),
            },
        ],
        ceased
    );

    // Said once: packets written into the ceased flow say nothing more.
    harness.send(ms(16_000), VIDEO);
    assert_eq!(2, harness.notices.len());

    // The restart the application asks for is announced when it takes effect.
    let epoch = harness.epoch;
    assert!(harness.handle.restart(VIDEO, epoch + ms(30_000)));
    harness.send(ms(30_001), VIDEO);
    assert_eq!(
        Some(&CircuitBreakerNotice {
            ssrc: VIDEO,
            ceased: None,
            restart_after: Duration::ZERO,
        }),
        harness.notices.last()
    );
    assert_eq!(3, harness.notices.len());
}

/// Section 4.5 with the restart left to the application
/// (`CircuitBreakerBuilder::with_automatic_restart(false)`): a halted flow is not restarted
/// automatically, whatever the reports say, and a restart is refused until the interval that
/// tripped the breaker has passed again.
#[test]
fn a_ceased_flow_restarts_only_on_request_and_not_before_the_triggering_interval() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new().with_automatic_restart(false));
    harness.send_for(ms(0), ms(1000), VIDEO, 10);
    harness.tick(ms(15_000));
    assert_eq!(
        Some(CircuitBreakerReason::RtcpTimeout),
        harness.reason(VIDEO)
    );

    // RTCP coming back does not restart it, before the hold has passed or after.
    harness.report(ms(16_000), VIDEO, 0, 10);
    assert_eq!(
        Some(CircuitBreakerReason::RtcpTimeout),
        harness.reason(VIDEO)
    );
    let epoch = harness.epoch;
    assert!(
        !harness.handle.restart(VIDEO, epoch + ms(29_999)),
        "the reaction lasts at least the triggering interval"
    );
    harness.report(ms(30_500), VIDEO, 0, 10);
    assert_eq!(
        Some(CircuitBreakerReason::RtcpTimeout),
        harness.reason(VIDEO),
        "the restart is the application's"
    );

    assert!(harness.handle.restart(VIDEO, epoch + ms(30_500)));
    let left = harness.left;
    harness.send(ms(30_501), VIDEO);
    assert_eq!(left + 1, harness.left, "the flow sends again");
    assert_eq!(
        Some(CircuitBreakerState::Running),
        harness.handle.state(VIDEO)
    );
}

/// Section 4.5: a halted flow is not restarted automatically "unless the sender has received
/// information that the congestion has dissipated". A flow the RTCP timeout stopped had "no
/// way of knowing if it is causing congestion" (section 4.1); a report on an SSRC this
/// endpoint sends is that way back, and "the reaction to a triggered circuit breaker lasts
/// for at least the triggering interval": a report before the 15 s have passed again, or one
/// that names none of the endpoint's SSRCs, restarts nothing; the first report on the flow
/// after them does.
#[test]
fn a_flow_the_rtcp_timeout_stopped_restarts_when_reports_on_it_come_back() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());
    harness.send_for(ms(0), ms(1000), VIDEO, 10);
    harness.tick(ms(15_000));
    assert_eq!(
        Some(CircuitBreakerReason::RtcpTimeout),
        harness.reason(VIDEO)
    );

    harness.report(ms(16_000), VIDEO, 0, 10);
    harness.report(ms(29_999), VIDEO, 0, 10);
    harness.report(ms(30_000), 0x7777_7777, 0, 10);
    assert_eq!(
        Some(CircuitBreakerReason::RtcpTimeout),
        harness.reason(VIDEO)
    );
    assert_eq!(1, harness.notices.len());

    harness.report(ms(30_100), VIDEO, 0, 10);
    assert_eq!(
        Some(CircuitBreakerState::Running),
        harness.handle.state(VIDEO)
    );
    assert_eq!(
        Some(&CircuitBreakerNotice {
            ssrc: VIDEO,
            ceased: None,
            restart_after: Duration::ZERO,
        }),
        harness.notices.last()
    );
    let left = harness.left;
    harness.send(ms(30_101), VIDEO);
    assert_eq!(left + 1, harness.left, "the flow sends again");
}

/// A call's voice (a packet every 20 ms) beside its video (one every 40 ms) with a 20 ms round
/// trip, the receiver reporting on both every 25 ms: what a peer built on this engine does
/// beside a video stream under RTP/AVPF with no `T_rr_interval`. Voice packets sent inside
/// `lost` (milliseconds) do not arrive; the video stops arriving from `video_dies_at`.
/// Returns the harness and what the breaker said application-ward, with the millisecond.
fn voice_beside_video(
    builder: CircuitBreakerBuilder,
    lost: &[std::ops::RangeInclusive<u64>],
    video_dies_at: Option<u64>,
    until: u64,
) -> (Harness, Vec<(u64, CircuitBreakerNotice)>) {
    let mut harness = Harness::new(builder);
    harness.handle.report_round_trip_time(ms(20));
    let (mut voice, mut video) = (0, 0);
    let mut told = Vec::new();
    for t in 0..until {
        if t % 20 == 0 {
            let sent = harness.send_numbered(ms(t), AUDIO);
            if !lost.iter().any(|range| range.contains(&t)) {
                voice = sent;
            }
        }
        if t % 40 == 10 {
            let sent = harness.send_numbered(ms(t), VIDEO);
            if video_dies_at.is_none_or(|at| t < at) {
                video = sent;
            }
        }
        if t % 25 == 5 {
            harness.report(ms(t), VIDEO, 0, video);
            harness.report(ms(t), AUDIO, 0, voice);
        }
        while told.len() < harness.notices.len() {
            told.push((t, harness.notices[told.len()]));
        }
    }
    (harness, told)
}

fn ceased(
    ssrc: u32,
    reason: CircuitBreakerReason,
    restart_after: Duration,
) -> CircuitBreakerNotice {
    CircuitBreakerNotice {
        ssrc,
        ceased: Some(reason),
        restart_after,
    }
}

fn restarted(ssrc: u32) -> CircuitBreakerNotice {
    CircuitBreakerNotice {
        ssrc,
        ceased: None,
        restart_after: Duration::ZERO,
    }
}

/// What a sudden drop of a path's capacity did to a call: the queue in front of the
/// bottleneck filled with video and dropped seven voice packets in a row. With reports every
/// 25 ms, MEDIA_TIMEOUT = ceil(5 * max(Tf, Tr, Tdr) / Tdr) = 5 of them, each a round trip or
/// more after the first lost packet, show no new voice packet: by section 4.2 the voice
/// ceases, 130 ms after that packet left. It used to stay silent for the rest of the call.
///
/// Section 4.5: "RTP flows halted by the circuit breaker SHOULD NOT be restarted
/// automatically unless the sender has received information that the congestion has
/// dissipated", rate limited "so that the reaction to a triggered circuit breaker lasts for
/// at least the triggering interval". The media timeout is the sign of a path failure, and
/// the receiver's report that the video sent over the same 5-tuple is still arriving is the
/// information that the path has not failed: the first such report after the triggering
/// interval (5 * 25 ms) restarts the voice. Six packets were dropped meanwhile.
#[test]
fn a_voice_flow_the_media_timeout_stopped_restarts_on_the_reports_of_the_video_beside_it() {
    let (harness, told) =
        voice_beside_video(CircuitBreakerBuilder::new(), &[2000..=2120], None, 3000);

    assert_eq!(
        vec![
            (
                2130,
                ceased(AUDIO, CircuitBreakerReason::MediaTimeout, ms(125))
            ),
            (2255, restarted(AUDIO)),
        ],
        told
    );
    assert_eq!(6, harness.handle.dropped());
    assert_eq!(
        Some(CircuitBreakerState::Running),
        harness.handle.state(AUDIO)
    );
    assert_eq!(
        Some(CircuitBreakerState::Running),
        harness.handle.state(VIDEO)
    );
}

/// Section 4.5 warns of "automatic redial systems": a restart that keeps failing has to
/// become rare. A flow that trips again soon after a restart (within ten times its last hold)
/// is held twice as long as the time before; one that has run that long without tripping
/// starts over at the triggering interval.
#[test]
fn a_flow_that_trips_again_soon_after_a_restart_is_held_twice_as_long() {
    let (_, told) = voice_beside_video(
        CircuitBreakerBuilder::new(),
        &[2000..=2120, 2260..=2380, 6000..=6120],
        None,
        6500,
    );

    assert_eq!(
        vec![
            (
                2130,
                ceased(AUDIO, CircuitBreakerReason::MediaTimeout, ms(125))
            ),
            (2255, restarted(AUDIO)),
            // 125 ms after the restart: the hold doubles.
            (
                2380,
                ceased(AUDIO, CircuitBreakerReason::MediaTimeout, ms(250))
            ),
            (2630, restarted(AUDIO)),
            // 3.5 s of clean running later: the triggering interval alone.
            (
                6130,
                ceased(AUDIO, CircuitBreakerReason::MediaTimeout, ms(125))
            ),
            (6255, restarted(AUDIO)),
        ],
        told
    );
}

/// With the restart left to the application the same voice flow stays ceased beside a video
/// that arrives, until the application restarts it.
#[test]
fn with_automatic_restart_off_the_reports_of_another_flow_restart_nothing() {
    let (harness, told) = voice_beside_video(
        CircuitBreakerBuilder::new().with_automatic_restart(false),
        &[2000..=2120],
        None,
        3000,
    );

    assert_eq!(
        vec![(
            2130,
            ceased(AUDIO, CircuitBreakerReason::MediaTimeout, ms(125))
        )],
        told
    );
    assert_eq!(
        Some(CircuitBreakerReason::MediaTimeout),
        harness.reason(AUDIO)
    );
    assert!(harness.handle.restart(AUDIO, harness.epoch + ms(3000)));
}

/// Section 4.5: without "information that the congestion has dissipated" a halted flow is not
/// restarted. A peer that vanishes while its RTCP keeps arriving (nothing of the voice or the
/// video gets through any more, the reports say so every 25 ms) has both flows ceased by the
/// media timeout, the video after MEDIA_TIMEOUT = ceil(5 * 40 / 25) = 8 reports, and nothing
/// restarts either: no report shows a packet of this endpoint arriving.
#[test]
fn flows_whose_peer_receives_nothing_any_more_cease_and_are_not_restarted() {
    let (harness, told) = voice_beside_video(
        CircuitBreakerBuilder::new(),
        &[2000..=u64::MAX],
        Some(2000),
        10_000,
    );

    assert_eq!(
        vec![
            (
                2130,
                ceased(AUDIO, CircuitBreakerReason::MediaTimeout, ms(125))
            ),
            (
                2205,
                ceased(VIDEO, CircuitBreakerReason::MediaTimeout, ms(200))
            ),
        ],
        told
    );
    assert_eq!(
        vec![
            (VIDEO, CircuitBreakerReason::MediaTimeout),
            (AUDIO, CircuitBreakerReason::MediaTimeout)
        ],
        harness.handle.ceased()
    );
}

/// Section 4.5 for the congestion breaker: the information that the congestion has
/// dissipated is the loss the receiver reports on another flow sent over the same 5-tuple. A
/// video flow (600 kB/s into 25 % loss with a 100 ms round trip, ten times TCP about
/// 360 kB/s) is ceased at its fourth report; the triggering interval is the 3 s the loss was
/// averaged over. The voice beside it is reported every second. Over the first hold its
/// reports still show 25 % loss, at which 600 kB/s is twice ten times TCP: nothing restarts.
/// Over the next whole hold they show 1/256, at which the rate that tripped the breaker is
/// well inside the bound: the video restarts at the report that completes that hold.
#[test]
fn a_flow_stopped_for_congestion_restarts_when_another_flows_reports_show_it_gone() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());
    harness.handle.report_round_trip_time(ms(100));
    let (mut video, mut voice) = (0, 0);
    let mut told = Vec::new();
    for t in 0..11_000u64 {
        if t % 2 == 0 {
            video = harness.send_numbered(ms(t), VIDEO);
        }
        if t % 20 == 0 {
            voice = harness.send_numbered(ms(t), AUDIO);
        }
        if t % 1000 == 999 {
            harness.report(ms(t), VIDEO, 64, video);
        }
        if t % 1000 == 499 {
            let loss = if t < 8000 { 64 } else { 1 };
            harness.report(ms(t), AUDIO, loss, voice);
        }
        while told.len() < harness.notices.len() {
            told.push((t, harness.notices[told.len()]));
        }
    }

    assert_eq!(
        vec![
            (
                3999,
                ceased(
                    VIDEO,
                    CircuitBreakerReason::Congestion,
                    Duration::from_secs(3)
                )
            ),
            (10_499, restarted(VIDEO)),
        ],
        told
    );
    assert_eq!(
        Some(CircuitBreakerState::Running),
        harness.handle.state(VIDEO)
    );
}

/// Section 4.5 for the media usability breaker: a flow ceased because its reported loss
/// stayed past the application's bound restarts when the reports on another flow of the
/// transport have shown a loss inside that bound for a whole hold (the application's period).
#[test]
fn a_flow_stopped_as_unusable_restarts_when_another_flows_reports_are_inside_the_bound() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new().with_media_usability(
        MediaUsability {
            max_loss: 0.5,
            max_round_trip_time: Duration::from_secs(2),
            period: Duration::from_secs(5),
        },
    ));
    let (mut video, mut voice) = (0, 0);
    let mut told = Vec::new();
    for t in 0..12_000u64 {
        if t % 500 == 0 {
            video = harness.send_numbered(ms(t), VIDEO);
        }
        if t % 100 == 0 {
            voice = harness.send_numbered(ms(t), AUDIO);
        }
        if t % 1000 == 999 {
            harness.report(ms(t), VIDEO, 154, video);
        }
        if t % 1000 == 499 {
            harness.report(ms(t), AUDIO, 0, voice);
        }
        while told.len() < harness.notices.len() {
            told.push((t, harness.notices[told.len()]));
        }
    }

    assert_eq!(
        vec![
            (
                5999,
                ceased(
                    VIDEO,
                    CircuitBreakerReason::MediaUnusable,
                    Duration::from_secs(5)
                )
            ),
            (11_499, restarted(VIDEO)),
        ],
        told
    );
}

/// Section 8: by default each SSRC is judged on its own.
#[test]
fn one_flow_ceasing_leaves_the_others_running() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new());

    for second in 0..8u64 {
        harness.send_for(ms(second * 1000), ms(second * 1000 + 1000), VIDEO, 10);
        harness.send_for(ms(second * 1000), ms(second * 1000 + 1000), AUDIO, 10);
        harness.report(ms(second * 1000 + 998), VIDEO, 0, 10);
        harness.report(ms(second * 1000 + 999), AUDIO, 0, (second as u32 + 1) * 10);
    }

    assert_eq!(
        Some(CircuitBreakerReason::MediaTimeout),
        harness.reason(VIDEO)
    );
    assert_eq!(
        Some(CircuitBreakerState::Running),
        harness.handle.state(AUDIO)
    );
}

/// Section 8: the sender may treat its flows as a group, so a breaker tripping for one applies
/// to all.
#[test]
fn grouped_flows_cease_together() {
    let mut harness = Harness::new(CircuitBreakerBuilder::new().with_grouped_flows(true));

    for second in 0..8u64 {
        harness.send_for(ms(second * 1000), ms(second * 1000 + 1000), VIDEO, 10);
        harness.send_for(ms(second * 1000), ms(second * 1000 + 1000), AUDIO, 10);
        harness.report(ms(second * 1000 + 998), VIDEO, 0, 10);
        harness.report(ms(second * 1000 + 999), AUDIO, 0, (second as u32 + 1) * 10);
    }

    assert_eq!(
        vec![
            (VIDEO, CircuitBreakerReason::MediaTimeout),
            (AUDIO, CircuitBreakerReason::MediaTimeout)
        ],
        harness.handle.ceased()
    );
}
