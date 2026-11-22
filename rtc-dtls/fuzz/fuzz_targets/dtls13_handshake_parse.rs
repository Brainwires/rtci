#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_dtls::fuzzing::dtls13_handshake_parse;

fuzz_target!(|data: &[u8]| {
    dtls13_handshake_parse(data);
});
