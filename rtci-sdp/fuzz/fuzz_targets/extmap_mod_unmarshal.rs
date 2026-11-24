#![no_main]
use libfuzzer_sys::fuzz_target;
use rtci_sdp::extmap::ExtMap;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = ExtMap::unmarshal(&mut cursor);
});
