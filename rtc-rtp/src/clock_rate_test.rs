//! RFC 7160: several clock rates in one RTP session.

use super::*;

/// Appendix A's stream: capture time (ms), clock rate.
const CAPTURES: [(u64, u32); 9] = [
    (0, 8000),
    (20, 8000),
    (40, 8000),
    (60, 8000),
    (80, 16000),
    (100, 16000),
    (120, 16000),
    (140, 8000),
    (160, 8000),
];

/// Appendix A, Table 4 ("Recommended Method for RTP Sender (without RTCP)"): the timestamps.
const TABLE_4_TIMESTAMPS: [u32; 9] = [0, 160, 320, 480, 640, 960, 1280, 1600, 1760];
/// Appendix A, Table 3 ("Non-monotonic Timestamps"): capture time times the clock rate.
const TABLE_3_TIMESTAMPS: [u32; 9] = [0, 160, 320, 480, 1280, 1600, 1920, 1120, 1280];

fn ms(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

#[test]
fn the_sender_timestamps_of_rfc7160_table_4() {
    let mut clock = MultiRateTimestamp::new(0, ms(0), 8000);
    let timestamps: Vec<u32> = CAPTURES
        .iter()
        .map(|&(capture, rate)| clock.timestamp(ms(capture), rate))
        .collect();
    assert_eq!(TABLE_4_TIMESTAMPS.to_vec(), timestamps);
}

#[test]
fn the_sender_timestamp_starts_at_the_initial_offset_and_wraps() {
    let mut clock = MultiRateTimestamp::new(u32::MAX - 100, ms(1000), 8000);
    assert_eq!(u32::MAX - 100, clock.timestamp(ms(1000), 8000));
    assert_eq!(59, clock.timestamp(ms(1020), 8000), "wrapped past 2^32");
    // A change of rate continues from where the old rate left off.
    assert_eq!(219, clock.timestamp(ms(1040), 48000));
    assert_eq!(219 + 960, clock.timestamp(ms(1060), 48000));
}

#[test]
fn the_receiver_difference_is_zero_across_a_clock_rate_change_without_jitter() {
    // Table 4: every packet arrives 100 ms after its capture, so the jitter column is 0.
    let arrivals: Vec<Arrival> = CAPTURES
        .iter()
        .zip(TABLE_4_TIMESTAMPS)
        .map(|(&(capture, clock_rate), timestamp)| Arrival {
            arrival_time: ms(capture + 100),
            timestamp,
            clock_rate,
        })
        .collect();
    let mut estimator = JitterEstimator::new();
    for pair in arrivals.windows(2) {
        assert_eq!(0, interarrival_difference(pair[0], pair[1]));
    }
    for arrival in arrivals {
        assert_eq!(0, estimator.update(arrival));
    }
}

#[test]
fn the_receiver_difference_uses_the_clock_rate_of_the_earlier_packet() {
    // Table 3's timestamps are capture time times clock rate. At the 8000 to 16000 switch
    // (packets 4 and 5) the formula of section 4.3 gives
    // (0.18 * 8000 - 1280) - (0.16 * 8000 - 480) = 160 - 800 = -640.
    let i = Arrival {
        arrival_time: ms(160),
        timestamp: TABLE_3_TIMESTAMPS[3],
        clock_rate: 8000,
    };
    let j = Arrival {
        arrival_time: ms(180),
        timestamp: TABLE_3_TIMESTAMPS[4],
        clock_rate: 16000,
    };
    assert_eq!(-640, interarrival_difference(i, j));
    // With the later packet's clock rate it would have been 320 - 800 = -480.
}

#[test]
fn the_receiver_difference_handles_reordering_and_timestamp_wrap() {
    let i = Arrival {
        arrival_time: ms(1000),
        timestamp: u32::MAX - 79,
        clock_rate: 8000,
    };
    let j = Arrival {
        arrival_time: ms(1030),
        timestamp: 80,
        clock_rate: 8000,
    };
    // 30 ms apart on arrival (240 units), 20 ms apart when sent (160 units).
    assert_eq!(80, interarrival_difference(i, j));
    assert_eq!(-80, interarrival_difference(j, i));
}

#[test]
fn the_jitter_estimate_follows_rfc3550_appendix_a8() {
    let mut estimator = JitterEstimator::new();
    let packet = |arrival_ms: u64, timestamp: u32| Arrival {
        arrival_time: ms(arrival_ms),
        timestamp,
        clock_rate: 8000,
    };
    assert_eq!(0, estimator.update(packet(0, 0)));
    // 10 ms late: |D| = 80. J = 80 / 16 = 5.
    assert_eq!(5, estimator.update(packet(30, 160)));
    // On time again relative to the first, so 10 ms early relative to the last: |D| = 80.
    // J = 5 + (80 - 5) / 16 = 9.6875.
    assert_eq!(9, estimator.update(packet(40, 320)));
    assert_eq!(9, estimator.jitter());
}

#[test]
fn a_new_clock_rate_takes_a_new_ssrc_and_a_returning_one_a_bye_first() {
    let mut history = ClockRateHistory::new();
    assert_eq!(None, history.current());
    assert_eq!(
        SsrcForClockRate::Keep,
        history.switch_to(8000),
        "first packet"
    );
    assert_eq!(SsrcForClockRate::Keep, history.switch_to(8000));
    assert_eq!(SsrcForClockRate::New, history.switch_to(16000));
    assert_eq!(SsrcForClockRate::Keep, history.switch_to(16000));
    assert_eq!(SsrcForClockRate::New, history.switch_to(48000));
    assert_eq!(SsrcForClockRate::NewAfterBye, history.switch_to(8000));
    assert_eq!(Some(8000), history.current());
    // The SRs after the current rate's carry the other rates seen.
    assert_eq!(vec![16000, 48000], history.previous().collect::<Vec<_>>());
}
