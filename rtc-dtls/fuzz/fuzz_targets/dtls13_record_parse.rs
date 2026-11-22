#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_dtls::fuzzing::dtls13_record_parse;

fuzz_target!(|data: &[u8]| {
    dtls13_record_parse(data);
});
