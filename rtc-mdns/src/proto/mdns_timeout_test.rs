//! Ported from webrtc-rs `mdns` v0.17 (`conn/conn_test.rs`).

use super::*;
use sansio::Protocol;

/// A query for a name nobody answers ends at its timeout. The async original bounded a
/// blocking `query()` with a channel; here the deadline is reported through `poll_timeout` and
/// the query ends as a `QueryTimeout` event when `handle_timeout` reaches it.
#[test]
fn test_query_respect_timeout() {
    let now = Instant::now();
    let mut conn = Mdns::new(
        now,
        MdnsConfig::default().with_query_timeout(Duration::from_millis(100)),
    );
    let id = conn.query_now(now, "invalid-host");
    while conn.poll_write().is_some() {}

    let mut t = now;
    let mut timed_out = false;
    for _ in 0..100 {
        let Some(next) = conn.poll_timeout() else {
            break;
        };
        t = next.max(t + Duration::from_millis(1));
        conn.handle_timeout(t).unwrap();
        while conn.poll_write().is_some() {}
        while let Some(event) = conn.poll_event() {
            if let MdnsEvent::QueryTimeout(qid) = event {
                assert_eq!(qid, id);
                timed_out = true;
            }
        }
        if timed_out {
            break;
        }
    }
    assert!(timed_out, "the query must time out");
    assert!(
        t - now >= Duration::from_millis(100),
        "not before its timeout"
    );
    assert!(!conn.is_query_pending(id));
}
