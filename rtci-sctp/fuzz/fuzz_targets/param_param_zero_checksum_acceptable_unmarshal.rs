#![no_main]

use libfuzzer_sys::fuzz_target;
use rtci_sctp::fuzzing::param_param_zero_checksum_acceptable_unmarshal;

fuzz_target!(|data: &[u8]| {
    let _ = param_param_zero_checksum_acceptable_unmarshal(data);
});
