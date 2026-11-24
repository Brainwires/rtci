#![no_main]

use libfuzzer_sys::fuzz_target;
use rtci_rtcp::compound_packet::CompoundPacket;
use rtci_shared::marshal::Unmarshal;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = CompoundPacket::unmarshal(&mut buf);
});
