//! Upstream webrtc-rs/webrtc v0.17.1 `sctp/src/timer/timer_test.rs`, ported to the sans-I/O
//! timer table: no task, no sleep, the caller hands each instant in. An upstream "callback"
//! is an expiry `is_expired` reports; upstream's `start` refusing a running timer is
//! `start_if_idle`; its "unlimited" `max_retrans: 0` is `usize::MAX` here.

use super::*;
use crate::association::state::AssociationState;
use crate::association::{Association, AssociationError};
use shared::error::Result;

const T1: Timer = Timer::T1Init;
const T3: Timer = Timer::T3RTX;

fn table(max_retrans: usize) -> TimerTable {
    TimerTable::new(TimerConfig {
        max_t1_init_retrans: max_retrans,
        max_t3_rtx_retrans: max_retrans,
        ..TimerConfig::default()
    })
}

/// Fires every due expiry until `until`, re-arming like the association does, and returns
/// how many expiries happened and whether the last one was a failure.
fn run(t: &mut TimerTable, timer: Timer, interval: u64, until: Instant) -> (usize, bool) {
    let mut fired = 0;
    let mut failed = false;
    while let Some(at) = t.get(timer) {
        if at > until {
            break;
        }
        let (expired, failure, _) = t.is_expired(timer, at);
        assert!(expired);
        fired += 1;
        t.set(timer, None);
        if failure {
            failed = true;
            break;
        }
        t.start(timer, at, interval);
    }
    (fired, failed)
}

#[test]
fn test_ack_timer_start_and_stop() {
    let now = Instant::now();
    let mut t = table(PATH_MAX_RETRANS);
    t.start(Timer::Ack, now, ACK_INTERVAL);
    assert!(t.get(Timer::Ack).is_some(), "should be running");
    t.stop(Timer::Ack);
    assert!(t.get(Timer::Ack).is_none(), "should not be running");
    assert_eq!(
        (false, false, 0),
        t.is_expired(Timer::Ack, now + Duration::from_secs(1)),
        "a stopped timer never expires"
    );
    t.start(Timer::Ack, now, ACK_INTERVAL);
    assert!(t.get(Timer::Ack).is_some(), "should be running again");
    t.stop(Timer::Ack);
    assert!(t.get(Timer::Ack).is_none(), "should not be running");
}

#[test]
fn test_rto_manager_initial_values() {
    let m = RtoManager::new();
    assert_eq!(m.rto, RTO_INITIAL);
    assert_eq!(m.get_rto(), RTO_INITIAL);
    assert_eq!(m.srtt, 0);
    assert_eq!(m.rttvar, 0.0);
}

#[test]
fn test_rto_manager_rto_calculation_small_rtt() {
    let mut m = RtoManager::new();
    for (i, expected) in [1800, 1500, 1275, 1106, 1000].into_iter().enumerate() {
        m.set_new_rtt(600);
        assert_eq!(expected, m.get_rto(), "measurement {i}");
    }
}

#[test]
fn test_rto_manager_rto_calculation_large_rtt() {
    let mut m = RtoManager::new();
    // The first three are capped at RTO.Max.
    for (i, expected) in [60000, 60000, 60000, 55312, 48984].into_iter().enumerate() {
        m.set_new_rtt(30000);
        assert_eq!(expected, m.get_rto(), "measurement {i}");
    }
}

#[test]
fn test_rto_manager_calculate_next_timeout() {
    assert_eq!(1, calculate_next_timeout(1, 0));
    assert_eq!(2, calculate_next_timeout(1, 1));
    assert_eq!(4, calculate_next_timeout(1, 2));
    assert_eq!(60000, calculate_next_timeout(1, 30));
    assert_eq!(60000, calculate_next_timeout(1, 63));
    assert_eq!(60000, calculate_next_timeout(1, 64));
}

#[test]
fn test_rto_manager_reset() {
    let mut m = RtoManager::new();
    for _ in 0..10 {
        m.set_new_rtt(200);
    }
    m.reset();
    assert_eq!(RTO_INITIAL, m.get_rto());
    assert_eq!(0, m.srtt);
    assert_eq!(0.0, m.rttvar);
}

/// T1 backs off by doubling (RFC 9260 6.3.3 E2): started at 30 ms it fires at 30, 90, 210
/// and 450 ms, four times within 650 ms, as upstream's callback count says.
#[test]
fn test_rtx_timer_callback_interval() {
    let now = Instant::now();
    let mut t = table(PATH_MAX_RETRANS);
    assert!(t.get(T1).is_none(), "should not be running");
    t.start(T1, now, 30);
    assert!(t.get(T1).is_some(), "should be running");
    let (fired, failed) = run(&mut t, T1, 30, now + Duration::from_millis(650));
    assert_eq!(4, fired);
    assert!(!failed);
}

#[test]
fn test_rtx_timer_last_start_wins() {
    let now = Instant::now();
    let mut t = table(PATH_MAX_RETRANS);
    t.start_if_idle(T3, now, 30);
    t.start_if_idle(T3, now, 30 * 99); // ignored: already running
    t.start_if_idle(T3, now, 30 * 99); // ignored
    assert_eq!(Some(now + Duration::from_millis(30)), t.get(T3));
    let (expired, _, _) = t.is_expired(T3, now + Duration::from_millis(45));
    assert!(expired, "fires once, at the first start's interval");
}

#[test]
fn test_rtx_timer_stop_right_after_start() {
    let now = Instant::now();
    let mut t = table(PATH_MAX_RETRANS);
    t.start(T3, now, 30);
    t.stop(T3);
    assert!(t.get(T3).is_none(), "should not be running");
    assert_eq!(
        (false, false, 0),
        t.is_expired(T3, now + Duration::from_millis(45)),
        "no expiry"
    );
}

#[test]
fn test_rtx_timer_start_stop_then_start() {
    let now = Instant::now();
    let mut t = table(PATH_MAX_RETRANS);
    t.start(T3, now, 30);
    t.stop(T3);
    assert!(t.get(T3).is_none(), "should not be running");
    t.start(T3, now, 30);
    assert!(t.get(T3).is_some(), "should be running");
    let (expired, failed, n) = t.is_expired(T3, now + Duration::from_millis(45));
    assert!(expired && !failed);
    assert_eq!(1, n, "fired once");
}

#[test]
fn test_rtx_timer_start_and_stop_in_atight_loop() {
    let now = Instant::now();
    let mut t = table(PATH_MAX_RETRANS);
    for _ in 0..1000 {
        t.start(T3, now, 30);
        assert!(t.get(T3).is_some(), "should be running");
        t.stop(T3);
        assert!(t.get(T3).is_none(), "should not be running");
    }
    assert_eq!(
        (false, false, 0),
        t.is_expired(T3, now + Duration::from_secs(1))
    );
}

/// With a limit of 4 retransmissions the fifth expiry is the failure, and the timer is not
/// re-armed after it.
#[test]
fn test_rtx_timer_should_stop_after_rtx_failure() {
    let now = Instant::now();
    let mut t = table(4);
    t.start(T1, now, 10);
    let (fired, failed) = run(&mut t, T1, 10, now + Duration::from_secs(60));
    assert_eq!(5, fired, "called 5 times");
    assert!(failed);
    assert!(t.get(T1).is_none(), "should not be running");
}

/// Upstream's unlimited retransmissions: the timer keeps firing (six times here) and never
/// fails.
#[test]
fn test_rtx_timer_should_not_stop_if_max_retrans_is_zero() {
    let now = Instant::now();
    let mut t = table(usize::MAX);
    t.start(T3, now, 10);
    let (fired, failed) = run(&mut t, T3, 10, now + Duration::from_millis(65));
    assert_eq!(6, fired, "called 6 times");
    assert!(!failed);
    assert!(t.get(T3).is_some(), "should still be running");
}

#[test]
fn test_rtx_timer_stop_timer_that_is_not_running_is_noop() {
    let now = Instant::now();
    let mut t = table(PATH_MAX_RETRANS);
    t.start(T3, now, 30);
    assert!(t.get(T3).is_some(), "must be running");
    t.stop(T3);
    t.stop(T3); // a no-op
    assert!(t.get(T3).is_none(), "must not be running");
}

/// A closed association arms no timer: whatever was running is stopped and nothing restarts
/// it, so it never fires.
#[test]
fn test_rtx_timer_closed_timer_wont_start() -> Result<()> {
    let now = Instant::now();
    let mut a = Association::default();
    a.set_state(AssociationState::Established);
    a.timers.start(T3, now, 30);
    assert!(a.timers.get(T3).is_some(), "must be running");
    a.close(AssociationError::LocallyClosed)?;
    assert!(a.poll_timeout().is_none(), "must not be running");
    a.handle_timeout(now + Duration::from_secs(10));
    assert!(
        a.poll_timeout().is_none(),
        "no RTO occurs, nothing restarts it"
    );
    Ok(())
}
