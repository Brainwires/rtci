#![no_main]

use libfuzzer_sys::fuzz_target;
use rtci_rtcp::compound_packet::{validate_compound, validate_reduced_size};

// The header checks of RFC 3550 Appendix A.2 and RFC 5506. A datagram that is a compound
// packet is acceptable as reduced-size RTCP too, and parses.
fuzz_target!(|data: &[u8]| {
    let reduced = validate_reduced_size(data);
    if validate_compound(data).is_ok() {
        assert!(reduced.is_ok());
        let mut buf = data;
        assert!(rtci_rtcp::packet::unmarshal(&mut buf).is_ok());
    }
});
