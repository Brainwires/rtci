#![no_main]
//! Parser target: a whole transport-wide congestion control feedback packet (draft-holmer-rmcat-transport-wide-cc-extensions-01 section 3.1): status chunks, run lengths and receive deltas, marshalled back when it parses.

use libfuzzer_sys::fuzz_target;
use rtc_rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
use rtc_shared::marshal::{Marshal, Unmarshal};

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    if let Ok(packet) = TransportLayerCc::unmarshal(&mut buf) {
        let _ = packet.marshal();
    }
});
