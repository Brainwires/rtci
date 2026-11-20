#![no_main]
//! Parser target: an SDP session description (RFC 8866), then everything the engine reads from a
//! parsed one: its attributes, each media section's attributes and codecs (`rtpmap`, `fmtp`,
//! `rtcp-fb`), the payload type lookups both ways, and a marshal and second parse of the result.

use libfuzzer_sys::fuzz_target;
use rtc_sdp::SessionDescription;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let Ok(session) = SessionDescription::unmarshal(&mut cursor) else {
        return;
    };
    for key in [
        "group",
        "fingerprint",
        "ice-ufrag",
        "ice-pwd",
        "ice-options",
        "extmap-allow-mixed",
    ] {
        let _ = session.has_attribute(key);
        let _ = session.attribute(key);
    }
    for media in &session.media_descriptions {
        for key in [
            "mid",
            "rtcp-mux",
            "setup",
            "sctp-port",
            "max-message-size",
            "ssrc-group",
            "rid",
            "simulcast",
            "cryptex",
        ] {
            let _ = media.has_attribute(key);
            let _ = media.attribute(key);
        }
        for (payload_type, codec) in media.codecs() {
            let _ = session.get_codec_for_payload_type(payload_type);
            let _ = session.get_payload_type_for_codec(&codec);
        }
    }
    let text = session.marshal();
    let _ = SessionDescription::unmarshal(&mut std::io::Cursor::new(text.as_bytes()));
});
