//! GCC against a rate-limited bottleneck, in virtual time.
//!
//! A sender paced at `Gcc`'s own target crosses a 600 kbit/s drop-tail queue (200 packets, 20 ms
//! of propagation, the shape the real-network environment builds with netem). The receiver
//! reports every 100 ms in TWCC feedback, quantised to TWCC's 250 µs deltas and read back through
//! `convert_twcc`, exactly as a peer connection would. The target must settle between 50% and
//! 110% of the link (draft-ietf-rmcat-gcc-02 5.5: the decrease backs off to 0.85 of the incoming
//! rate, so the rate oscillates just under the bottleneck).

mod path_simulator;

use path_simulator::{Arrival, Path, PathProfile};
use rtc_interceptor::{BandwidthEstimator, Gcc, PacketReport, convert_twcc};
use rtcp::transport_feedbacks::cc_feedback_report::Ecn;
use rtcp::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, SymbolTypeTcc,
    TransportLayerCc,
};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const LINK_BITS_PER_SECOND: f64 = 600_000.0;
const PACKET_BYTES: usize = 1_500;
const PACKET_BITS: f64 = (PACKET_BYTES * 8) as f64;
const FEEDBACK_INTERVAL: Duration = Duration::from_millis(100);
const RUN: Duration = Duration::from_secs(40);
const SSRC: u32 = 0x6cc0_0001;

fn bottleneck() -> PathProfile {
    PathProfile {
        propagation: Duration::from_millis(20),
        capacity_bits_per_second: LINK_BITS_PER_SECOND,
        // netem `limit 200`: 200 packets of queue.
        queue_capacity_bits: 200.0 * PACKET_BITS,
        drop_one_in: None,
    }
}

/// TWCC feedback for a contiguous run of packets starting at `base`, as a receiver writes it:
/// a 64 ms reference time, then each received packet's arrival as a delta from the one before,
/// in 250 µs ticks (small when it fits a byte, large otherwise).
fn twcc_feedback(base: u16, run: &[Option<Duration>]) -> TransportLayerCc {
    const TICK_MICROS: i64 = 250;

    let reference_ticks = run
        .iter()
        .flatten()
        .next()
        .map_or(0, |first| (first.as_millis() / 64) as u32);
    let mut previous_micros = i64::from(reference_ticks) * 64_000;

    let mut packet_chunks = Vec::with_capacity(run.len());
    let mut recv_deltas = Vec::new();
    for arrival in run {
        let symbol = match arrival {
            Some(at) => {
                let micros = at.as_micros() as i64;
                let ticks = (micros - previous_micros) / TICK_MICROS;
                previous_micros += ticks * TICK_MICROS;
                let symbol = if (0..=255).contains(&ticks) {
                    SymbolTypeTcc::PacketReceivedSmallDelta
                } else {
                    SymbolTypeTcc::PacketReceivedLargeDelta
                };
                recv_deltas.push(RecvDelta {
                    type_tcc_packet: symbol,
                    delta: ticks * TICK_MICROS,
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

    TransportLayerCc {
        sender_ssrc: 0,
        media_ssrc: SSRC,
        base_sequence_number: base,
        packet_status_count: run.len() as u16,
        reference_time: reference_ticks,
        fb_pkt_count: 0,
        packet_chunks,
        recv_deltas,
    }
}

/// Run the closed loop and return the target once a second.
fn run_bottleneck() -> Vec<f64> {
    let epoch = Instant::now();
    let mut path = Path::new(bottleneck(), epoch);
    let mut gcc = Gcc::default();

    let mut departures: HashMap<u16, Instant> = HashMap::new();
    // What the receiver knows about each packet: `Some(arrival)` or `None` for a drop.
    let mut observed: HashMap<u16, Option<Duration>> = HashMap::new();
    let mut next_to_report = 0u16;
    let mut next_to_send = 0u16;
    let mut budget_bits = 0.0f64;
    let mut last_feedback = epoch;
    let mut samples = Vec::new();

    for step in 0..RUN.as_millis() as u64 {
        let now = epoch + Duration::from_millis(step);

        // A pacer at the current target, one millisecond at a time, allowed one packet of burst.
        budget_bits = (budget_bits + gcc.target_bitrate() / 1_000.0).min(2.0 * PACKET_BITS);
        while budget_bits >= PACKET_BITS {
            budget_bits -= PACKET_BITS;
            departures.insert(next_to_send, now);
            path.offer(now, next_to_send, PACKET_BITS);
            next_to_send = next_to_send.wrapping_add(1);
        }
        path.drain_to(now);

        for Arrival {
            twcc_sequence_number,
            at,
        } in path.take_arrivals()
        {
            observed.insert(twcc_sequence_number, at.map(|at| at.duration_since(epoch)));
        }

        if now.duration_since(last_feedback) >= FEEDBACK_INTERVAL {
            last_feedback = now;

            // The contiguous run the receiver can account for.
            let base = next_to_report;
            let mut run = Vec::new();
            while let Some(arrival) = observed.remove(&next_to_report) {
                run.push(arrival);
                next_to_report = next_to_report.wrapping_add(1);
            }

            if !run.is_empty() {
                let reports: Vec<PacketReport> = convert_twcc(&twcc_feedback(base, &run))
                    .into_iter()
                    .map(|ack| PacketReport {
                        ssrc: SSRC,
                        id: u64::from(ack.sequence_number),
                        rtp_sequence_number: ack.sequence_number,
                        is_twcc: true,
                        twcc_sequence_number: ack.sequence_number,
                        size: PACKET_BYTES,
                        arrived: ack.arrived,
                        departure: departures
                            .remove(&ack.sequence_number)
                            .expect("every reported packet was sent"),
                        arrival: ack.arrival,
                        ecn: Ecn::default(),
                    })
                    .collect();
                gcc.on_reports(now, &reports);
            }
        }

        if step % 1_000 == 999 {
            samples.push(gcc.target_bitrate());
        }
    }

    samples
}

#[test]
fn gcc_settles_under_a_rate_limited_link() {
    let samples = run_bottleneck();
    let tail = &samples[samples.len() - 10..];
    let mean = tail.iter().sum::<f64>() / tail.len() as f64;

    assert!(
        (0.5 * LINK_BITS_PER_SECOND..=1.1 * LINK_BITS_PER_SECOND).contains(&mean),
        "GCC settled at {mean:.0} bit/s over a {LINK_BITS_PER_SECOND:.0} bit/s link; \
         target once a second: {samples:?}"
    );
}

/// The same schedule gives the same trajectory: the loop has no clock and no randomness.
#[test]
fn the_bottleneck_run_is_deterministic() {
    assert_eq!(run_bottleneck(), run_bottleneck());
}
