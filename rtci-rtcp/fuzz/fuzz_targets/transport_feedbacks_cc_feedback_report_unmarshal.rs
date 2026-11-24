#![no_main]
//! Parser target: an RFC 8888 congestion control feedback report: report blocks and per-packet metric blocks, marshalled back when it parses.

use libfuzzer_sys::fuzz_target;
use rtci_rtcp::transport_feedbacks::cc_feedback_report::CcFeedbackReport;
use rtci_shared::marshal::{Marshal, Unmarshal};

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    if let Ok(packet) = CcFeedbackReport::unmarshal(&mut buf) {
        let _ = packet.marshal();
    }
});
