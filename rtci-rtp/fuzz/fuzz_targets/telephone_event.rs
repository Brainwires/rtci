#![no_main]
//! Parser and stateful target: RFC 4733 telephone-event payloads. The raw input is parsed as one
//! payload (and, when it parses, marshalled back and parsed again: the result must not change),
//! as an `events` fmtp list, and then as a sequence of packets fed to the receiver state
//! machine. Each packet is a flags byte (bit 0 is the marker), a four-byte RTP timestamp, a
//! one-byte length and the payload.

use libfuzzer_sys::fuzz_target;
use rtci_rtp::codec::telephone_event::{
    EventSet, TelephoneEventReceiver, marshal_telephone_events, parse_telephone_events,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(events) = parse_telephone_events(data) {
        let raw = marshal_telephone_events(&events).expect("a parsed payload marshals");
        assert_eq!(
            parse_telephone_events(&raw).expect("a marshalled payload parses"),
            events
        );
    }

    if let Ok(list) = std::str::from_utf8(data)
        && let Ok(set) = EventSet::parse(list)
    {
        assert_eq!(EventSet::parse(&set.to_string()).ok(), Some(set));
    }

    let mut receiver = TelephoneEventReceiver::new();
    let mut rest = data;
    let mut packets = 0;
    while rest.len() >= 6 && packets < 1024 {
        let marker = rest[0] & 0x01 != 0;
        let timestamp = u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]);
        let len = usize::from(rest[5]).min(rest.len() - 6);
        let payload = &rest[6..6 + len];
        rest = &rest[6 + len..];
        packets += 1;
        let _ = receiver.receive(timestamp, marker, payload);
        let _ = receiver.current();
    }
});
