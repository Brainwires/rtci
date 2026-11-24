#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = rtci_rtcp::packet::unmarshal(&mut buf);
});
