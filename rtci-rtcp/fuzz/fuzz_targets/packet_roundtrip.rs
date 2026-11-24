#![no_main]

use libfuzzer_sys::fuzz_target;

// A datagram that parses is written back and read again: the second reading must be written
// as the same bytes, so the parser and the writers agree on one wire form for every input the
// parser accepts. This reaches every packet type through the dispatcher, with the padding and
// length handling in front of each.
fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    if let Ok(packets) = rtci_rtcp::packet::unmarshal(&mut buf)
        && let Ok(raw) = rtci_rtcp::packet::marshal(&packets)
    {
        let again = rtci_rtcp::packet::unmarshal(&mut raw.clone().freeze())
            .expect("what was written is read");
        assert_eq!(packets.len(), again.len());
        let rewritten = rtci_rtcp::packet::marshal(&again).expect("and written again");
        assert_eq!(raw, rewritten);
    }
});
