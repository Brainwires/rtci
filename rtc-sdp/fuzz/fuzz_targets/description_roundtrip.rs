#![no_main]
//! Parser target: an SDP session description (RFC 8866), then everything the engine reads from a
//! parsed one: its attributes, each media section's attributes and codecs (`rtpmap`, `fmtp`,
//! `rtcp-fb`), the payload type lookups both ways, every typed accessor, `validate`, and a
//! marshal and second parse of the result.
//!
//! Beyond "no panic", it checks two properties:
//!
//! * what the strict parser accepted is written as text the strict parser accepts again, and
//!   writing that again changes nothing (parse and marshal are a fixed point);
//! * the same for the lenient parser, with itself.

use libfuzzer_sys::fuzz_target;
use rtc_sdp::{ParseOptions, SessionDescription};

fn read_everything(session: &SessionDescription) {
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
    let _ = session.groups();
    let _ = session.bundle_groups();
    let _ = session.ice_lite();
    let _ = session.ice_pacing();
    let _ = session.identity();
    let _ = session.msid_semantic();
    let _ = session.direction();
    let _ = session.extmaps();
    let _ = session.extmap_allow_mixed();
    let _ = session.ice_ufrag();
    let _ = session.ice_pwd();
    let _ = session.ice_options();
    let _ = session.fingerprints();
    let _ = session.setup();
    let _ = session.tls_id();
    let _ = session.rtcp_xr();
    let _ = session.cryptex();
    let _ = session.validate();

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
        let _ = media.mid();
        let _ = media.msids();
        if let Ok(ssrcs) = media.ssrcs() {
            for ssrc in &ssrcs {
                let _ = ssrc.cname();
                let _ = ssrc.previous_ssrcs();
                let _ = ssrc.fmtp();
                let _ = ssrc.msid();
            }
        }
        let _ = media.ssrc_groups();
        if let Ok(rids) = media.rids() {
            for rid in &rids {
                let _ = (rid.max_width(), rid.max_height(), rid.max_fps(), rid.max_fs());
                let _ = (rid.max_br(), rid.max_pps(), rid.max_bpp(), rid.depend());
            }
        }
        let _ = media.simulcast();
        let _ = media.rtcp();
        let _ = media.rtcp_mux();
        let _ = media.rtcp_mux_only();
        let _ = media.rtcp_rsize();
        if let Ok(feedback) = media.rtcp_fbs() {
            for fb in &feedback {
                let _ = fb.kind();
                let _ = fb.feedback();
                let _ = rtc_sdp::attribute::mux::rtcp_fb(fb);
            }
        }
        let _ = media.rtpmaps();
        if let Ok(fmtps) = media.fmtps() {
            for fmtp in &fmtps {
                let _ = fmtp.parameter_list();
                let _ = fmtp.payload_type();
            }
        }
        let _ = media.ptime();
        let _ = media.maxptime();
        let _ = media.framerate();
        let _ = media.imageattrs();
        let _ = media.content();
        let _ = media.candidates();
        let _ = media.end_of_candidates();
        let _ = media.remote_candidates();
        let _ = media.sctp_port();
        let _ = media.max_message_size();
        let _ = media.sctpmap();
        let _ = media.bundle_only();
        let _ = media.direction();
        let _ = media.extmaps();
        let _ = media.fingerprints();
        let _ = media.setup();
        let _ = media.tls_id();
        for attribute in &media.attributes {
            let _ = rtc_sdp::attribute::mux::attribute(&attribute.key);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    if let Ok(session) = SessionDescription::unmarshal(&mut cursor) {
        read_everything(&session);
        let text = session.marshal();
        let again = SessionDescription::unmarshal(&mut std::io::Cursor::new(text.as_bytes()))
            .expect("what the strict parser accepted is written as valid SDP");
        assert_eq!(again.marshal(), text);
    }

    let lenient = ParseOptions::lenient();
    let mut cursor = std::io::Cursor::new(data);
    if let Ok(session) = SessionDescription::unmarshal_with_options(&mut cursor, &lenient) {
        read_everything(&session);
        let text = session.marshal();
        let again = SessionDescription::parse_with_options(&text, &lenient)
            .expect("what the lenient parser accepted is written as text it accepts");
        assert_eq!(again.marshal(), text);
    }
});
