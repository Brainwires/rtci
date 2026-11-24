#![no_main]

use libfuzzer_sys::fuzz_target;
use rtci_sctp::fuzzing::association_handle_chunks;

fuzz_target!(|data: &[u8]| {
    association_handle_chunks(data, std::time::Instant::now());
});
