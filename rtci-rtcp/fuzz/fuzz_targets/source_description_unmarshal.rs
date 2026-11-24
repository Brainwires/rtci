#![no_main]
//! Parser target: a whole RTCP SDES packet (RFC 3550 section 6.5): every chunk and item, marshalled back when it parses.

use libfuzzer_sys::fuzz_target;
use rtci_rtcp::source_description::SourceDescription;
use rtci_shared::marshal::{Marshal, Unmarshal};

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    if let Ok(packet) = SourceDescription::unmarshal(&mut buf) {
        let _ = packet.marshal();
    }
});
