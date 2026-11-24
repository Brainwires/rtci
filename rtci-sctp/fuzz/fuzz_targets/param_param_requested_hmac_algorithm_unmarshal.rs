#![no_main]

use libfuzzer_sys::fuzz_target;
use rtci_sctp::fuzzing::param_param_requested_hmac_algorithm_unmarshal;

fuzz_target!(|data: &[u8]| {
    let _ = param_param_requested_hmac_algorithm_unmarshal(data);
});
