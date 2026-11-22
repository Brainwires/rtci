#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_sctp::fuzzing::association_handle_chunks;

fuzz_target!(|data: &[u8]| {
    association_handle_chunks(data, std::time::Instant::now());
});
