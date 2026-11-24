#![no_main]

use libfuzzer_sys::fuzz_target;
use rtci_sctp::fuzzing::endpoint_handle_datagrams;

fuzz_target!(|data: &[u8]| {
    endpoint_handle_datagrams(data, std::time::Instant::now());
});
