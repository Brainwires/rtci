#![no_main]
//! Parser target: a whole RTCP extended report (RFC 3611) with every report block type, marshalled back when it parses.

use libfuzzer_sys::fuzz_target;
use rtci_rtcp::extended_report::ExtendedReport;
use rtci_shared::marshal::{Marshal, Unmarshal};

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    if let Ok(packet) = ExtendedReport::unmarshal(&mut buf) {
        let _ = packet.marshal();
    }
});
