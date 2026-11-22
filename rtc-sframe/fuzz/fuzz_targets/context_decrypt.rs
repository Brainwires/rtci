#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_sframe::fuzzing::context_decrypt;

fuzz_target!(|data: &[u8]| {
    context_decrypt(data);
});
