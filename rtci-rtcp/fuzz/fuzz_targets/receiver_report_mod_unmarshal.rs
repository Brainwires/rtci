#![no_main]

use libfuzzer_sys::fuzz_target;
use rtci_rtcp::receiver_report::ReceiverReport;
use rtci_shared::marshal::Unmarshal;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = ReceiverReport::unmarshal(&mut buf);
});
