//! How many congestion control feedback packets a second the RTCP session lets out, and how
//! large they are, at the RFC defaults.
//!
//! The RTCP session sends every RTCP packet of the endpoint and keeps them inside the RTCP
//! bandwidth: 5% of the session bandwidth (RFC 3550 section 6.2), shared between the members,
//! with the early feedback allowance of RTP/AVPF (RFC 4585 section 3.5) and `T_rr_interval`
//! zero when `trr-int` was not signalled. A send-side congestion controller needs its feedback
//! often: with fewer than two reports a second `Gcc` converges 1.6 times slower and overshoots
//! (`gcc_feedback_rate.rs`). This file measures what the two together produce, two engines
//! against each other on a virtual clock, at media rates from one audio stream up.
//!
//! Run with `--nocapture` to read the table.

use rtc_interceptor::{
    AttributedPacket, CongestionFeedbackFormat, Interceptor, Packet, RTCPFeedback,
    RTPHeaderExtension, Registry, Rfc8888Builder, RtcpRandom, RtcpSessionBuilder,
    RtcpSessionControl, Slot, StreamInfo, TaggedPacket, TwccReceiverBuilder, TwccSenderBuilder,
    convert_ccfb, convert_twcc,
};
use rtcp::transport_feedbacks::cc_feedback_report::CcFeedbackReport;
use rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::MarshalSize;
use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const MEDIA_SSRC: u32 = 0x00A0_0001;
const ONE_WAY_DELAY: Duration = Duration::from_millis(20);
const RUN: Duration = Duration::from_secs(40);
const WARM_UP: Duration = Duration::from_secs(10);

/// A repeatable source of the session's random numbers that still varies, so the report
/// intervals are randomised as RFC 3550 section 6.3.1 has them.
struct Lcg(u64);

impl RtcpRandom for Lcg {
    fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as u32 | 1
    }
}

fn stream(format: CongestionFeedbackFormat) -> StreamInfo {
    let mut rtcp_feedback = vec![RTCPFeedback {
        typ: "transport-cc".to_owned(),
        parameter: String::new(),
    }];
    if format == CongestionFeedbackFormat::Rfc8888 {
        rtcp_feedback.push(RTCPFeedback {
            typ: "ack".to_owned(),
            parameter: "ccfb".to_owned(),
        });
    }
    StreamInfo {
        ssrc: MEDIA_SSRC,
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        payload_type: 96,
        rtcp_feedback,
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: 5,
        }],
        ..Default::default()
    }
}

/// How the receiver's feedback generators are configured.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Generators {
    /// The interval is fixed at 100 ms, whatever the RTCP bandwidth is (the behaviour before
    /// the interval followed the bandwidth).
    Fixed,
    /// The defaults.
    Default,
}

fn endpoint(seed: u64, generators: Generators, reduced_size: bool) -> Box<dyn Interceptor> {
    let (twcc, rfc8888) = match generators {
        Generators::Fixed => (
            TwccReceiverBuilder::new()
                .with_interval(Duration::from_millis(100))
                .with_adaptive_interval(false),
            Rfc8888Builder::new()
                .with_interval(Duration::from_millis(100))
                .with_adaptive_interval(false),
        ),
        Generators::Default => (TwccReceiverBuilder::new(), Rfc8888Builder::new()),
    };
    Box::new(
        Registry::new()
            .with(
                Slot::RtcpSession,
                RtcpSessionBuilder::new()
                    .with_random(Lcg(seed))
                    // RFC 4585 section 3.4: T_rr_interval is zero unless `trr-int` says otherwise.
                    .with_t_rr_interval(Duration::ZERO)
                    .with_reduced_size(reduced_size)
                    .build(),
            )
            .with(Slot::TwccSender, TwccSenderBuilder::new().build())
            .with(Slot::TwccReceiver, twcc.build())
            .with(Slot::Rfc8888, rfc8888.build())
            .build(),
    )
}

struct Measured {
    /// RTCP datagrams with congestion control feedback, per second.
    feedback_datagrams_per_second: f64,
    /// Feedback packets (TWCC or RFC 8888) per second, however many shared a datagram.
    feedback_packets_per_second: f64,
    /// Mean size of a datagram that carried feedback, RTCP octets.
    mean_datagram_octets: f64,
    /// Mean size of one feedback packet, RTCP octets.
    mean_feedback_octets: f64,
    /// The longest time between two datagrams with feedback.
    longest_gap: Duration,
    /// The share of the media packets sent that some feedback reported as received.
    coverage: f64,
    /// The longest a media packet waited from its arrival to the departure of the feedback
    /// that reported it.
    longest_report_delay: Duration,
    /// All of the receiver's RTCP as a share of the media bit rate.
    rtcp_share: f64,
}

/// One engine sends media at `media_bitrate` to another, which reports it. Both run the RTCP
/// session; what crosses is delayed by 20 ms each way and nothing is lost.
fn measure(
    media_bitrate: f64,
    format: CongestionFeedbackFormat,
    generators: Generators,
    reduced_size: bool,
) -> Measured {
    let epoch = Instant::now();
    let mut sender = endpoint(1, generators, reduced_size);
    let mut receiver = endpoint(2, generators, reduced_size);
    for (chain, cname) in [(&mut sender, "sender"), (&mut receiver, "receiver")] {
        chain
            .handle_write(RtcpSessionControl::Cname(cname.to_owned()).into_packet(epoch))
            .unwrap();
        chain
            .handle_write(RtcpSessionControl::Start.into_packet(epoch))
            .unwrap();
    }
    let info = stream(format);
    sender.bind_local_stream(&info);
    receiver.bind_remote_stream(&info);

    // Fifty packets a second up to 1200 octets each, more packets above that: an audio
    // stream at the low end, video at the high end.
    let packet_octets = ((media_bitrate / 8.0 / 50.0) as usize).clamp(100, 1200);
    let spacing = Duration::from_secs_f64(packet_octets as f64 * 8.0 / media_bitrate);

    let mut to_receiver: VecDeque<(Instant, TaggedPacket)> = VecDeque::new();
    let mut to_sender: VecDeque<(Instant, TaggedPacket)> = VecDeque::new();
    let mut next_media = Duration::ZERO;
    let mut sequence_number = 0u16;
    let mut sent_in_window: HashSet<u16> = HashSet::new();
    let mut arrived_at: Vec<Option<Instant>> = vec![None; 1 << 16];
    let mut reported: HashSet<u16> = HashSet::new();

    let mut feedback_datagrams = 0u64;
    let mut feedback_packets = 0u64;
    let mut datagram_octets = 0u64;
    let mut feedback_octets = 0u64;
    let mut receiver_rtcp_octets = 0u64;
    let mut last_feedback: Option<Instant> = None;
    let mut longest_gap = Duration::ZERO;
    let mut longest_report_delay = Duration::ZERO;

    let step = Duration::from_millis(1);
    let mut elapsed = Duration::ZERO;
    while elapsed < RUN {
        let now = epoch + elapsed;
        let measuring = elapsed >= WARM_UP;

        // Media leaves the sender.
        while next_media <= elapsed {
            assert!(
                sequence_number < u16::MAX,
                "the run fits one sequence cycle"
            );
            let packet = rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    payload_type: 96,
                    sequence_number,
                    timestamp: (next_media.as_secs_f64() * 90_000.0) as u32,
                    ssrc: MEDIA_SSRC,
                    ..Default::default()
                },
                payload: vec![0u8; packet_octets - 20].into(),
            };
            if next_media >= WARM_UP && next_media < RUN - Duration::from_secs(2) {
                sent_in_window.insert(sequence_number);
            }
            sequence_number += 1;
            sender
                .handle_write(TaggedPacket {
                    now,
                    transport: TransportContext::default(),
                    message: AttributedPacket::new(Packet::Rtp(packet)),
                })
                .unwrap();
            next_media += spacing;
        }

        // What arrives.
        while to_receiver.front().is_some_and(|(at, _)| *at <= now) {
            let (_, mut packet) = to_receiver.pop_front().unwrap();
            packet.now = now;
            if let Packet::Rtp(rtp) = &packet.message.packet {
                arrived_at[usize::from(rtp.header.sequence_number)] = Some(now);
            }
            receiver.handle_read(packet).unwrap();
        }
        while to_sender.front().is_some_and(|(at, _)| *at <= now) {
            let (_, mut packet) = to_sender.pop_front().unwrap();
            packet.now = now;
            sender.handle_read(packet).unwrap();
        }
        while sender.poll_read().is_some() {}
        while receiver.poll_read().is_some() {}

        // Timers.
        for chain in [&mut sender, &mut receiver] {
            for _ in 0..64 {
                match chain.poll_timeout() {
                    Some(at) if at <= now => chain.handle_timeout(now).unwrap(),
                    _ => break,
                }
            }
        }

        // What leaves.
        while let Some(packet) = sender.poll_write() {
            if matches!(&packet.message.packet, Packet::Rtcp(packets) if packets.is_empty()) {
                continue;
            }
            to_receiver.push_back((now + ONE_WAY_DELAY, packet));
        }
        while let Some(packet) = receiver.poll_write() {
            let Packet::Rtcp(packets) = &packet.message.packet else {
                continue;
            };
            if packets.is_empty() {
                continue;
            }
            let octets: usize = packets.iter().map(|p| p.marshal_size()).sum();
            let mut feedback_in_datagram = 0u64;
            for rtcp_packet in packets {
                let any = rtcp_packet.as_any();
                let acknowledged: Vec<u16> =
                    if let Some(twcc) = any.downcast_ref::<TransportLayerCc>() {
                        feedback_in_datagram += 1;
                        if measuring {
                            feedback_octets += twcc.marshal_size() as u64;
                        }
                        // The run is one stream numbered from zero on both counters, so a
                        // transport-wide sequence number is the RTP sequence number.
                        convert_twcc(twcc)
                            .into_iter()
                            .filter(|ack| ack.arrived)
                            .map(|ack| ack.sequence_number)
                            .collect()
                    } else if let Some(ccfb) = any.downcast_ref::<CcFeedbackReport>() {
                        feedback_in_datagram += 1;
                        if measuring {
                            feedback_octets += ccfb.marshal_size() as u64;
                        }
                        convert_ccfb(ccfb)
                            .1
                            .into_values()
                            .flatten()
                            .filter(|ack| ack.arrived)
                            .map(|ack| ack.sequence_number)
                            .collect()
                    } else {
                        Vec::new()
                    };
                for sequence in acknowledged {
                    if reported.insert(sequence)
                        && measuring
                        && let Some(arrived) = arrived_at[usize::from(sequence)]
                    {
                        longest_report_delay =
                            longest_report_delay.max(now.saturating_duration_since(arrived));
                    }
                }
            }
            if measuring {
                receiver_rtcp_octets += octets as u64;
                if feedback_in_datagram > 0 {
                    feedback_datagrams += 1;
                    feedback_packets += feedback_in_datagram;
                    datagram_octets += octets as u64;
                    if let Some(last) = last_feedback {
                        longest_gap = longest_gap.max(now.saturating_duration_since(last));
                    }
                    last_feedback = Some(now);
                }
            }
            to_sender.push_back((now + ONE_WAY_DELAY, packet));
        }

        elapsed += step;
    }

    let window = (RUN - WARM_UP).as_secs_f64();
    let covered = sent_in_window
        .iter()
        .filter(|sequence| reported.contains(sequence))
        .count();
    Measured {
        feedback_datagrams_per_second: feedback_datagrams as f64 / window,
        feedback_packets_per_second: feedback_packets as f64 / window,
        mean_datagram_octets: datagram_octets as f64 / feedback_datagrams.max(1) as f64,
        mean_feedback_octets: feedback_octets as f64 / feedback_packets.max(1) as f64,
        longest_gap,
        coverage: covered as f64 / sent_in_window.len().max(1) as f64,
        longest_report_delay,
        rtcp_share: receiver_rtcp_octets as f64 * 8.0 / window / media_bitrate,
    }
}

const RATES: [f64; 4] = [64_000.0, 100_000.0, 300_000.0, 1_000_000.0];

fn table(title: &str, generators: Generators, reduced_size: bool) -> Vec<(f64, Measured)> {
    println!("\n{title}");
    println!(
        "{:>9} {:>8} | {:>9} {:>9} {:>9} {:>8} {:>8} {:>8} {:>9} {:>7}",
        "media",
        "format",
        "dgrams/s",
        "fb pkt/s",
        "dgram B",
        "fb B",
        "gap ms",
        "covered",
        "delay ms",
        "rtcp %"
    );
    let mut rows = Vec::new();
    for format in [
        CongestionFeedbackFormat::TransportCc,
        CongestionFeedbackFormat::Rfc8888,
    ] {
        for rate in RATES {
            let measured = measure(rate, format, generators, reduced_size);
            println!(
                "{:>9.0} {:>8} | {:>9.2} {:>9.2} {:>9.0} {:>8.0} {:>8} {:>8.3} {:>9} {:>7.2}",
                rate,
                match format {
                    CongestionFeedbackFormat::TransportCc => "twcc",
                    CongestionFeedbackFormat::Rfc8888 => "rfc8888",
                },
                measured.feedback_datagrams_per_second,
                measured.feedback_packets_per_second,
                measured.mean_datagram_octets,
                measured.mean_feedback_octets,
                measured.longest_gap.as_millis(),
                measured.coverage,
                measured.longest_report_delay.as_millis(),
                measured.rtcp_share * 100.0,
            );
            rows.push((rate, measured));
        }
    }
    rows
}

/// The numbers before: feedback generated every 100 ms whatever the RTCP bandwidth, handed to
/// a session that may not send it that often. At 64 and 100 kbit/s the session bundles five
/// and two and a half reports into each packet it may send, the packets leave at irregular
/// times, and the sender hears nothing for more than a second at a time: about a packet's
/// worth of media has been sent on an estimate that old. Measured in the container
/// (`rust:1.92`, virtual clock), compound RTCP:
///
/// ```text
///     media   format |  dgrams/s  fb pkt/s   dgram B     fb B   gap ms  covered  delay ms  rtcp %
///     64000     twcc |      2.07     10.13       177       28     1152    1.000      1132    4.58
///    100000     twcc |      4.03     10.00       109       28      608    1.000       588    3.53
///    300000     twcc |     10.00     10.00        64       28      150    1.000       130    2.52
///   1000000     twcc |     10.00     10.00        62       34      100    1.000        99    2.26
///     64000  rfc8888 |      1.87     10.20       215       32     1345    1.000      1325    5.01
///    100000  rfc8888 |      3.53      9.93       130       32      680    1.000       660    3.67
///    300000  rfc8888 |     10.00     10.00        69       32      156    1.000       136    2.58
///   1000000  rfc8888 |     10.00     10.00        70       42      100    1.000        99    2.29
/// ```
///
/// What is asserted is what makes the configuration unfit as a default: at 64 kbit/s the
/// sender waits more than a second for feedback.
#[test]
fn feedback_rate_with_a_fixed_generation_interval() {
    let compound = table(
        "fixed 100 ms generation, compound RTCP",
        Generators::Fixed,
        false,
    );
    table(
        "fixed 100 ms generation, reduced-size RTCP",
        Generators::Fixed,
        true,
    );
    for (rate, measured) in compound {
        if rate <= 64_000.0 {
            assert!(
                measured.longest_gap > Duration::from_secs(1),
                "{rate} bit/s: {:?}",
                measured.longest_gap
            );
        }
    }
}

/// The defaults: the generators stretch their interval to what the RTCP bandwidth holds one
/// report in (RFC 8888 sections 3.1 and 4; RFC 3550 section 6.2), up to 400 ms. At every
/// media rate from one audio stream up the sender hears at least two feedback reports a
/// second, every packet is reported, and none later than 0.9 s after it arrived. Measured
/// (compound RTCP):
///
/// ```text
///     media   format |  dgrams/s  fb pkt/s   dgram B     fb B   gap ms  covered  delay ms  rtcp %
///     64000     twcc |      2.50      2.50        82       44      658    1.000       638    3.04
///    100000     twcc |      3.10      3.10        75       40      496    1.000       491    2.73
///    300000     twcc |      9.97      9.97        64       28      149    1.000       141    2.55
///   1000000     twcc |     10.00     10.00        62       34      100    1.000        99    2.26
///     64000  rfc8888 |      2.50      2.50        99       60      788    1.000       768    3.34
///    100000  rfc8888 |      2.53      2.53        91       60      495    1.000       488    2.79
///    300000  rfc8888 |      9.77      9.77        68       32      166    1.000       163    2.57
///   1000000  rfc8888 |     10.00     10.00        70       42      100    1.000        99    2.29
/// ```
///
/// With `a=rtcp-rsize` negotiated the report travels without the receiver report and SDES
/// around it (RFC 8888 section 3.1, RFC 5506), and the same bandwidth holds more of them.
#[test]
fn the_default_feedback_rate_is_enough_for_the_congestion_controller() {
    let mut datagram_octets_at_the_lowest_rate = Vec::new();
    for (reduced_size, title) in [
        (false, "defaults, compound RTCP"),
        (true, "defaults, reduced-size RTCP (a=rtcp-rsize)"),
    ] {
        let rows = table(title, Generators::Default, reduced_size);
        datagram_octets_at_the_lowest_rate.push(rows[0].1.mean_datagram_octets);
        for (rate, measured) in rows {
            assert!(
                measured.feedback_datagrams_per_second >= 2.0,
                "{title}, {rate} bit/s: {:.2} feedback datagrams a second",
                measured.feedback_datagrams_per_second
            );
            assert!(
                measured.coverage >= 0.999,
                "{title}, {rate} bit/s: only {:.3} of the packets were reported",
                measured.coverage
            );
            assert!(
                measured.longest_report_delay <= Duration::from_millis(900),
                "{title}, {rate} bit/s: a packet waited {:?} for its report",
                measured.longest_report_delay
            );
            assert!(
                measured.longest_gap <= Duration::from_millis(900),
                "{title}, {rate} bit/s: {:?} without feedback",
                measured.longest_gap
            );
        }
    }
    // RFC 8888 section 3.1: with reduced-size RTCP negotiated the feedback leaves without a
    // compound packet around it.
    assert!(
        datagram_octets_at_the_lowest_rate[1] < datagram_octets_at_the_lowest_rate[0] - 10.0,
        "{datagram_octets_at_the_lowest_rate:?}"
    );
}
