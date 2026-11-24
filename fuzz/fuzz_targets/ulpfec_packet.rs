#![no_main]
//! The ULPFEC payload parser (RFC 5109 7.3, 7.4) and the RED reader that carries it (RFC 2198 3,
//! RFC 5109 14.2). Oracles: whatever parses, re-marshals to something that parses to the same
//! packet; every block the RED reader hands out lies inside the input.

use libfuzzer_sys::fuzz_target;
use rtci::interceptor::{UlpfecPacket, depacketize_red_for_ulpfec};

fuzz_target!(|data: &[u8]| {
    if let Ok(packet) = UlpfecPacket::parse(data) {
        let wire = packet.marshal();
        assert!(wire.len() <= data.len(), "marshal never grows a parsed packet");
        let again = UlpfecPacket::parse(&wire).expect("what was marshalled parses");
        assert_eq!(packet, again);
    }

    let Some((&fec_payload_type, red)) = data.split_first() else {
        return;
    };
    if let Ok(parsed) = depacketize_red_for_ulpfec(red, fec_payload_type & 0x7F) {
        let mut total: usize = parsed.fec.iter().map(|fec| fec.len()).sum();
        if let Some((_, primary)) = &parsed.primary {
            total += primary.len();
        }
        assert!(total < red.len().max(1), "blocks come out of the payload");
        for fec in &parsed.fec {
            let _ = UlpfecPacket::parse(fec);
        }
    }
});
