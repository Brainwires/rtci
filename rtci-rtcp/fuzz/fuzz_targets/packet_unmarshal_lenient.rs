#![no_main]

use libfuzzer_sys::fuzz_target;

// The lenient reader keeps a malformed packet as raw bytes, so whatever it accepts it can
// write back, and it accepts everything the strict reader does.
fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let lenient = rtci_rtcp::packet::unmarshal_lenient(&mut buf);
    let mut buf = data;
    if rtci_rtcp::packet::unmarshal(&mut buf).is_ok() {
        assert!(lenient.is_ok());
    }
    if let Ok(packets) = lenient {
        for packet in &packets {
            let _ = packet.header();
            let _ = packet.destination_ssrc();
        }
    }
});
