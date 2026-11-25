//! Recovery probing: how long a sender that keeps up with its target takes to find a path
//! again after a limit on it has gone, with
//! [`CongestionControlBuilder::with_recovery_probing`] and without.
//!
//! A sender starts at 300 kbit/s on a path that carries 2.5 Mbit/s and sends what its target
//! allows. Ten seconds into the run the path drops to 300 kbit/s (a queue of 300 ms), and
//! twenty seconds later it carries 2.5 Mbit/s again. Without recovery probing nothing asks
//! the open path a question: the sender is not application limited, the probes after the drop
//! ended under the limit, and the estimate climbs 8% a second. With it, the rate before the
//! drop is remembered for a minute and a cluster at twice the target goes out every five
//! seconds while the estimator does not read over-use; the first one after the limit has gone
//! is carried, and its follow-ons find the path.
//!
//! Everything runs on a virtual clock through the chain the default interceptor set builds
//! for a sender: the congestion controller, the TWCC sender, the pacer and the NACK responder,
//! whose RTX stream fills the clusters with padding-only packets.
//!
//! Run with `--nocapture` to read the figures.

use rtci_interceptor::{
    AttributedPacket, CongestionControlBuilder, Gcc, Interceptor, NackResponderBuilder,
    PacerBuilder, Packet, ProbePacket, RTCPFeedback, RTPHeaderExtension, Registry, Slot,
    StreamInfo, TaggedPacket, TwccSenderBuilder,
};
use rtcp::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, SymbolTypeTcc,
    TransportLayerCc,
};
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::{MarshalSize, Unmarshal};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const TWCC_ID: u8 = 5;
const MEDIA_SSRC: u32 = 0x00A0_0001;
const RTX_SSRC: u32 = 0x00A0_0002;
const OPEN: f64 = 2_500_000.0;
const LIMITED: f64 = 300_000.0;
const START: f64 = 300_000.0;
const PACKET_OCTETS: usize = 1200;
/// When the limit comes and how long it stays.
const LIMIT_AT: Duration = Duration::from_secs(10);
const LIMIT_FOR: Duration = Duration::from_secs(20);
/// The queue before the narrow link, as time at its rate.
const QUEUE: Duration = Duration::from_millis(300);
const PROPAGATION: Duration = Duration::from_millis(20);

fn stream() -> StreamInfo {
    StreamInfo {
        ssrc: MEDIA_SSRC,
        ssrc_rtx: Some(RTX_SSRC),
        payload_type: 96,
        payload_type_rtx: Some(97),
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        rtcp_feedback: vec![
            RTCPFeedback {
                typ: "transport-cc".to_owned(),
                parameter: String::new(),
            },
            RTCPFeedback {
                typ: "nack".to_owned(),
                parameter: String::new(),
            },
        ],
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: u16::from(TWCC_ID),
        }],
        ..Default::default()
    }
}

/// What the far end saw of one packet: `None` when the queue dropped it.
#[derive(Clone, Copy)]
struct Arrival {
    twcc_sequence_number: u16,
    at: Option<Instant>,
}

/// A one-way link whose rate changes with time: one packet served at a time at the rate of
/// the instant its service begins, a tail-drop queue of [`QUEUE`] before it.
struct Link {
    epoch: Instant,
    /// When the link has served everything it holds.
    free_at: Instant,
    in_flight: VecDeque<(Instant, u16)>,
    seen: Vec<Arrival>,
}

impl Link {
    fn new(epoch: Instant) -> Self {
        Self {
            epoch,
            free_at: epoch,
            in_flight: VecDeque::new(),
            seen: Vec::new(),
        }
    }

    fn rate_at(&self, at: Instant) -> f64 {
        let elapsed = at.saturating_duration_since(self.epoch);
        if elapsed >= LIMIT_AT && elapsed < LIMIT_AT + LIMIT_FOR {
            LIMITED
        } else {
            OPEN
        }
    }

    /// Offers a packet at `now`; `false` when the queue is full.
    fn offer(&mut self, now: Instant, twcc_sequence_number: u16, octets: usize) -> bool {
        if self.free_at.saturating_duration_since(now) > QUEUE {
            self.seen.push(Arrival {
                twcc_sequence_number,
                at: None,
            });
            return false;
        }
        let begins = self.free_at.max(now);
        let served = begins + Duration::from_secs_f64(octets as f64 * 8.0 / self.rate_at(begins));
        self.free_at = served;
        self.in_flight
            .push_back((served + PROPAGATION, twcc_sequence_number));
        true
    }

    /// What has arrived or was dropped by `now`, since the last call.
    fn take_seen(&mut self, now: Instant) -> Vec<Arrival> {
        while let Some((at, twcc_sequence_number)) = self.in_flight.front().copied() {
            if at > now {
                break;
            }
            self.in_flight.pop_front();
            self.seen.push(Arrival {
                twcc_sequence_number,
                at: Some(at),
            });
        }
        std::mem::take(&mut self.seen)
    }
}

/// Transport-wide feedback that says exactly when each packet arrived (as in
/// `bandwidth_probing.rs`): the reference time is the 64 ms tick before the first arrival,
/// and every delta is the true gap.
fn feedback(now: Instant, epoch: Instant, arrivals: &[Arrival]) -> Option<TaggedPacket> {
    let base = arrivals.first()?.twcc_sequence_number;
    let first = arrivals.iter().find_map(|arrival| arrival.at)?;
    let reference_time = (first.saturating_duration_since(epoch).as_micros() / 64_000) as u32;
    let mut previous = Duration::from_micros(u64::from(reference_time) * 64_000);
    let mut packet_chunks = Vec::new();
    let mut recv_deltas = Vec::new();
    for arrival in arrivals {
        let symbol = match arrival.at {
            Some(at) => {
                let at = at.saturating_duration_since(epoch);
                let ticks = (at.saturating_sub(previous).as_micros() / 250) as i64;
                previous += Duration::from_micros(ticks as u64 * 250);
                let symbol = if ticks <= 255 {
                    SymbolTypeTcc::PacketReceivedSmallDelta
                } else {
                    SymbolTypeTcc::PacketReceivedLargeDelta
                };
                recv_deltas.push(RecvDelta {
                    type_tcc_packet: symbol,
                    delta: ticks * 250,
                });
                symbol
            }
            None => SymbolTypeTcc::PacketNotReceived,
        };
        packet_chunks.push(PacketStatusChunk::RunLengthChunk(RunLengthChunk {
            type_tcc: StatusChunkTypeTcc::RunLengthChunk,
            packet_status_symbol: symbol,
            run_length: 1,
        }));
    }
    Some(TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerCc {
            sender_ssrc: 0x5E5E_5E5E,
            media_ssrc: MEDIA_SSRC,
            base_sequence_number: base,
            packet_status_count: arrivals.len() as u16,
            reference_time,
            fb_pkt_count: 0,
            packet_chunks,
            recv_deltas,
        })])),
    })
}

struct Run {
    /// The target just before the limit came.
    before: f64,
    /// From the limit's end until the target first reached 1 Mbit/s.
    to_1000: Option<Duration>,
    /// From the limit's end until the target first reached 85% of the open path.
    to_open: Option<Duration>,
    /// The mean target under the limit, from 5 s after it came.
    under: f64,
    /// Probe packets that left under the limit, from 5 s after it came (the probes after the
    /// drop have ended by then), and after it had gone.
    probes_under: usize,
    probes_after: usize,
    /// Packets the queue dropped under the limit, from 5 s after it came.
    dropped_under: usize,
    /// The highest target seen.
    peak: f64,
}

fn run(recovery_probing: bool) -> Run {
    let epoch = Instant::now();
    let estimator = Gcc::new(START, 30_000.0, 20_000_000.0);
    let (controller, handle) = CongestionControlBuilder::new(estimator)
        .with_bandwidth_probing(true)
        .with_recovery_probing(recovery_probing)
        .build_with_handle();
    let mut chain = Registry::new()
        .with(Slot::CongestionControl, controller)
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .with(
            Slot::Pacer,
            PacerBuilder::new().with_target_bitrate(START).build(),
        )
        .with(Slot::NackResponder, NackResponderBuilder::new().build())
        .build();
    chain.bind_local_stream(&stream());

    let mut link = Link::new(epoch);
    let limit_ends = LIMIT_AT + LIMIT_FOR;
    let settled = LIMIT_AT + Duration::from_secs(5);
    let duration = limit_ends + Duration::from_secs(30);

    let mut sequence_number = 0u16;
    let mut next_media = Duration::ZERO;
    let mut next_feedback = Duration::from_millis(100);
    let mut pending: Vec<Arrival> = Vec::new();
    let mut outcome = Run {
        before: 0.0,
        to_1000: None,
        to_open: None,
        under: 0.0,
        probes_under: 0,
        probes_after: 0,
        dropped_under: 0,
        peak: 0.0,
    };
    let mut under_sum = 0.0;
    let mut under_steps = 0usize;

    let step = Duration::from_millis(1);
    let mut elapsed = Duration::ZERO;
    while elapsed < duration {
        let now = epoch + elapsed;
        let target = handle.target_bitrate();
        outcome.peak = outcome.peak.max(target);
        if elapsed < LIMIT_AT {
            outcome.before = target;
        }
        if elapsed >= settled && elapsed < limit_ends {
            under_sum += target;
            under_steps += 1;
        }
        if elapsed >= limit_ends {
            if outcome.to_1000.is_none() && target >= 1_000_000.0 {
                outcome.to_1000 = Some(elapsed - limit_ends);
            }
            if outcome.to_open.is_none() && target >= 0.85 * OPEN {
                outcome.to_open = Some(elapsed - limit_ends);
            }
        }

        // The application writes media at its target.
        while next_media <= elapsed {
            let packet = rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    payload_type: 96,
                    sequence_number,
                    timestamp: (next_media.as_secs_f64() * 90_000.0) as u32,
                    ssrc: MEDIA_SSRC,
                    ..Default::default()
                },
                payload: vec![0u8; PACKET_OCTETS - 20].into(),
            };
            sequence_number = sequence_number.wrapping_add(1);
            chain
                .handle_write(TaggedPacket {
                    now,
                    transport: TransportContext::default(),
                    message: AttributedPacket::new(Packet::Rtp(packet)),
                })
                .unwrap();
            next_media +=
                Duration::from_secs_f64(PACKET_OCTETS as f64 * 8.0 / target.max(30_000.0));
        }

        for _ in 0..64 {
            match chain.poll_timeout() {
                Some(at) if at <= now => chain.handle_timeout(now).unwrap(),
                _ => break,
            }
        }

        // What leaves goes onto the link.
        while let Some(out) = chain.poll_write() {
            let Packet::Rtp(packet) = &out.message.packet else {
                continue;
            };
            let size = packet.marshal_size();
            if out.message.custom::<ProbePacket>().is_some() {
                if elapsed >= settled && elapsed < limit_ends {
                    outcome.probes_under += 1;
                } else if elapsed >= limit_ends {
                    outcome.probes_after += 1;
                }
            }
            let mut extension = packet
                .header
                .get_extension(TWCC_ID)
                .expect("every packet is numbered transport-wide");
            let transport_sequence =
                rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(
                    &mut extension,
                )
                .expect("transport-cc extension")
                .transport_sequence;
            if !link.offer(out.now, transport_sequence, size)
                && elapsed >= settled
                && elapsed < limit_ends
            {
                outcome.dropped_under += 1;
            }
        }

        // The receiver reports every 100 ms on what has arrived, in transport-wide order.
        pending.extend(link.take_seen(now));
        if elapsed >= next_feedback {
            next_feedback += Duration::from_millis(100);
            pending.sort_by_key(|arrival| arrival.twcc_sequence_number);
            // Only a run without gaps can be reported: what is still on the link is not lost.
            let mut run_length = 0;
            for (index, arrival) in pending.iter().enumerate() {
                if index > 0
                    && arrival.twcc_sequence_number
                        != pending[index - 1].twcc_sequence_number.wrapping_add(1)
                {
                    break;
                }
                run_length = index + 1;
            }
            let reported: Vec<Arrival> = pending.drain(..run_length).collect();
            if let Some(feedback) = feedback(now, epoch, &reported) {
                chain.handle_read(feedback).unwrap();
            }
        }
        while chain.poll_read().is_some() {}

        elapsed += step;
    }
    outcome.under = under_sum / under_steps.max(1) as f64;
    outcome
}

fn print(title: &str, run: &Run) {
    println!(
        "MEASURE {title}: before the limit {:.0} kbit/s; under it {:.0} kbit/s with {} probe \
         packets and {} packets dropped at the queue; after it 1 Mbit/s in {:?}, 85% of the \
         path in {:?}, {} probe packets; peak {:.0} kbit/s",
        run.before / 1000.0,
        run.under / 1000.0,
        run.probes_under,
        run.dropped_under,
        run.to_1000,
        run.to_open,
        run.probes_after,
        run.peak / 1000.0,
    );
}

/// Without the setting (the default) a sender at its target is asked nothing once the path
/// is open again: no probe packet leaves from five seconds after the drop on, and 1 Mbit/s is
/// more than ten seconds away (8% a second from under 300 kbit/s).
#[test]
fn without_recovery_probing_the_open_path_is_climbed_to_at_the_controllers_pace() {
    let outcome = run(false);
    print("without recovery probing", &outcome);

    assert!(outcome.before > 2_000_000.0, "{}", outcome.before);
    assert!(
        outcome
            .to_1000
            .is_none_or(|after| after > Duration::from_secs(10)),
        "{:?}",
        outcome.to_1000
    );
}

/// With it, the cluster due within five seconds of the limit's end is carried and followed
/// up: 1 Mbit/s within six seconds and most of the path within seven. Under the limit a
/// cluster goes out about every five seconds (five packets each, so a dozen or two in
/// fifteen seconds), and the target under the limit is not lower for it by more than a tenth.
#[test]
fn recovery_probing_finds_the_open_path_within_seconds() {
    let outcome = run(true);
    print("with recovery probing", &outcome);
    let without = run(false);

    assert!(outcome.before > 2_000_000.0, "{}", outcome.before);
    let to_1000 = outcome.to_1000.expect("1 Mbit/s is reached");
    assert!(to_1000 <= Duration::from_secs(6), "{to_1000:?}");
    let to_open = outcome.to_open.expect("the open path is found");
    assert!(to_open <= Duration::from_secs(7), "{to_open:?}");
    assert!(
        outcome.probes_after >= 10,
        "the cluster that found the path and its follow-ons: {}",
        outcome.probes_after
    );
    assert!(
        outcome.under >= 0.9 * without.under,
        "target under the limit {:.0} against {:.0} without",
        outcome.under,
        without.under
    );
    assert!(
        outcome.peak <= 1.2 * OPEN,
        "the estimate stays near what the path carries: {}",
        outcome.peak
    );
}
