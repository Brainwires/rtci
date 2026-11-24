#![no_main]
//! Parser target: an ICE candidate line (RFC 8839 section 5.1) as it arrives in a remote
//! description or a trickled candidate: foundation, component, transport, priority, address
//! (an IP or an mDNS name), port, type, `raddr` / `rport`, `tcptype` and extensions. A candidate
//! that parses is marshalled and parsed again.

use libfuzzer_sys::fuzz_target;
use rtci_ice::candidate::unmarshal_candidate;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(candidate) = unmarshal_candidate(text) {
        let _ = unmarshal_candidate(&candidate.marshal());
    }
});
