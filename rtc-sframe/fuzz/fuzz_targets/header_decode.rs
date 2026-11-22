#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_sframe::fuzzing::header_decode;

fuzz_target!(|data: &[u8]| {
    header_decode(data);
});
