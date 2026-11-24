#![no_main]

use libfuzzer_sys::fuzz_target;
use rtci_sctp::fuzzing::param_param_incoming_reset_request_unmarshal;

fuzz_target!(|data: &[u8]| {
    let _ = param_param_incoming_reset_request_unmarshal(data);
});
