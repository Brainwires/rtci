#![no_main]
use libfuzzer_sys::fuzz_target;
use rtci_sdp::SessionDescription;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _session = SessionDescription::unmarshal(&mut cursor);
});
