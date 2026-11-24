#![no_main]

use libfuzzer_sys::fuzz_target;
use rtci_rtcp::Header;
use rtci_shared::marshal::Unmarshal;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = Header::unmarshal(&mut buf);
});
