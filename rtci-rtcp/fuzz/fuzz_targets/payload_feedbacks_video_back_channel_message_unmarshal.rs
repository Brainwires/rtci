#![no_main]

use libfuzzer_sys::fuzz_target;
use rtci_rtcp::payload_feedbacks::video_back_channel_message::VideoBackChannelMessage;
use rtci_shared::marshal::{Marshal, Unmarshal};

// Whatever parses is written back and read again: the second reading must be written as
// the same bytes, so the parser and the writer agree on one wire form for every input the
// parser accepts.
fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    if let Ok(packet) = VideoBackChannelMessage::unmarshal(&mut buf)
        && let Ok(raw) = packet.marshal()
    {
        let again =
            VideoBackChannelMessage::unmarshal(&mut raw.clone().freeze()).expect("what was written is read");
        assert_eq!(packet, again);
        assert_eq!(raw, again.marshal().expect("and written again"));
    }
});
