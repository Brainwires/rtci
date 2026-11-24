#![no_main]

use libfuzzer_sys::fuzz_target;
use rtci_rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtci_shared::marshal::Unmarshal;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = PictureLossIndication::unmarshal(&mut buf);
});
