#![no_main]

use libfuzzer_sys::fuzz_target;
use rtci_rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtci_shared::marshal::Unmarshal;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = FullIntraRequest::unmarshal(&mut buf);
});
