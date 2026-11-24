#![no_main]

use libfuzzer_sys::fuzz_target;
use rtci_rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack;
use rtci_shared::marshal::Unmarshal;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = TransportLayerNack::unmarshal(&mut buf);
});
