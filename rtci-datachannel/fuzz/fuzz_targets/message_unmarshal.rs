#![no_main]
//! Parser target: a DCEP message (RFC 8832 section 5) as the peer sends it, then marshalled back
//! when it parses, which walks the label and protocol lengths a second time.

use libfuzzer_sys::fuzz_target;
use rtci_datachannel::message::Message;
use rtci_shared::marshal::{Marshal, Unmarshal};

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    if let Ok(message) = Message::unmarshal(&mut buf) {
        let _ = message.marshal();
    }
});
