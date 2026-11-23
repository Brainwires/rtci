//! Every object the C ABI hands out is freed by its matching function: after a whole session
//! (handles, returned strings, error paths) the library's count of live objects is back to
//! where it started. One test in its own binary, so no other test's objects are counted.

mod abi;

use abi::*;
use std::ptr;

#[test]
fn a_whole_session_through_the_c_abi_leaves_no_object_alive() {
    let start = unsafe { rtc_debug_live_objects() };
    {
        let mut pair = Pair::new(r#"{"interceptors":"minimal"}"#);
        assert_eq!(
            unsafe { rtc_debug_live_objects() },
            start + 2,
            "two handles"
        );
        let mut id = 0u64;
        let label = c("leak-check");
        ok(unsafe {
            rtc_pc_create_data_channel(pair.offerer.pc, label.as_ptr(), ptr::null(), &mut id)
        });
        pair.negotiate();
        assert!(
            pair.run_until(|p| !p.offerer.events_of("open").is_empty()
                && !p.answerer.events_of("open").is_empty())
        );
        let now = pair.now_ns;
        pair.offerer.send(now, id, b"ping", true);
        assert!(pair.run_until(|p| !p.answerer.data_messages().is_empty()));
        // Strings handed out and freed.
        let _ = pair.offerer.states();
        let now = pair.now_ns;
        let _ = out_string(|out| unsafe { rtc_pc_get_stats(pair.offerer.pc, now, 0, 0, out) });
        // A string not taken: an error leaves `out` untouched.
        let mut out = ptr::null_mut();
        assert!(unsafe { rtc_pc_sender_info(pair.offerer.pc, 77, &mut out) } < 0);
        assert!(out.is_null());
        ok(unsafe { rtc_pc_close(pair.offerer.pc) });
        pair.run_for(1_000_000_000);
        pair.free();
    }
    assert_eq!(unsafe { rtc_debug_live_objects() }, start);
}
