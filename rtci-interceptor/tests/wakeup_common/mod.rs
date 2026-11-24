//! The invariant a driver's event loop relies on (`poll_write`, `poll_event`, `poll_read`,
//! then `poll_timeout` and sleep): **when `poll_write` has something, `poll_timeout` is not
//! later than now**. Work the read leg makes for the write leg is otherwise found only when
//! something else wakes the driver. Used by `tests/read_work_is_due.rs`.

#![allow(dead_code)]

use rtci_interceptor::{Interceptor, TaggedPacket};
use std::time::Instant;

/// Reads `packet` as a driver does (`handle_read`, then `poll_read` until empty), then checks
/// the invariant at `now`: returns what `poll_write` had, and panics if anything was there
/// while `poll_timeout` named a later instant or none.
pub fn read_then_sleep(chain: &mut impl Interceptor, packet: TaggedPacket) -> Vec<TaggedPacket> {
    let now = packet.now;
    chain.handle_read(packet).expect("handle_read");
    while chain.poll_read().is_some() {}
    sleep(chain, now, "after the read")
}

/// A timeout as a driver handles one (`handle_timeout`, then `poll_write` until empty, then
/// `poll_read` until empty: what the timeout put on the read leg crosses it), then the
/// invariant at `now`, as [`read_then_sleep`].
pub fn timeout_then_sleep(chain: &mut impl Interceptor, now: Instant) -> Vec<TaggedPacket> {
    chain.handle_timeout(now).expect("handle_timeout");
    while chain.poll_write().is_some() {}
    while chain.poll_read().is_some() {}
    sleep(chain, now, "after the timeout's reads")
}

/// The driver is about to sleep at `now`: what `poll_write` has must be due.
pub fn sleep(chain: &mut impl Interceptor, now: Instant, when: &str) -> Vec<TaggedPacket> {
    let timeout = chain.poll_timeout();
    let mut written = Vec::new();
    while let Some(packet) = chain.poll_write() {
        written.push(packet);
    }
    assert!(
        written.is_empty() || timeout.is_some_and(|t| t <= now),
        "{when}: {} packet(s) waited for poll_write while poll_timeout said {:?} (now {now:?})",
        written.len(),
        timeout
    );
    written
}
