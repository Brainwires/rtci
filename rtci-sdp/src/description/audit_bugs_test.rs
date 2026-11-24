//! One test per bug the RFC 8866 / RFC 8285 / RFC 9429 clause audit found in this crate. Each
//! failed before its fix.

use std::io::Cursor;

use crate::attribute::TypedAttribute;
use crate::description::session::SessionDescription;
use crate::extmap::ExtMap;

const HEAD: &str = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n";

fn parse(sdp: &str) -> shared::error::Result<SessionDescription> {
    SessionDescription::unmarshal(&mut Cursor::new(sdp.as_bytes()))
}

fn video(attributes: &str) -> String {
    format!("{HEAD}m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\nc=IN IP4 0.0.0.0\r\n{attributes}")
}

/// RFC 8866 5.14 / 6.15: the format-specific parameters are everything after the first space.
#[test]
fn fmtp_parameters_containing_spaces_are_kept() {
    let sdp = video(
        "a=rtpmap:96 H264/90000\r\n\
         a=fmtp:96 level-asymmetry-allowed=1; packetization-mode=1; profile-level-id=42e01f\r\n",
    );
    let codecs = parse(&sdp).unwrap().media_descriptions[0].codecs();
    assert_eq!(
        codecs[&96].fmtp,
        "level-asymmetry-allowed=1; packetization-mode=1; profile-level-id=42e01f"
    );
}

/// RFC 4585 4.2: `a=rtcp-fb:*` applies to every format of the media section.
#[test]
fn rtcp_fb_wildcard_applies_to_every_format() {
    let sdp = video(
        "a=rtpmap:96 VP8/90000\r\n\
         a=rtpmap:97 VP9/90000\r\n\
         a=rtcp-fb:* nack\r\n\
         a=rtcp-fb:96 nack pli\r\n\
         a=rtcp-fb:* transport-cc\r\n",
    );
    let codecs = parse(&sdp).unwrap().media_descriptions[0].codecs();
    assert_eq!(
        codecs[&96].rtcp_feedback,
        vec!["nack", "nack pli", "transport-cc"]
    );
    assert_eq!(codecs[&97].rtcp_feedback, vec!["nack", "transport-cc"]);
}

/// RFC 8866 9: `*email-field *phone-field`.
#[test]
fn several_email_and_phone_lines_are_parsed_and_written_back() {
    let sdp = "v=0\r\n\
               o=- 1 1 IN IP4 0.0.0.0\r\n\
               s=-\r\n\
               e=j.doe@example.com (Jane Doe)\r\n\
               e=Jane Doe <j.doe@example.com>\r\n\
               p=+1 617 555-6011\r\n\
               p=+44 20 7946 0000\r\n\
               t=0 0\r\n";
    assert_eq!(parse(sdp).unwrap().marshal(), sdp);
}

/// RFC 8866 5.3: `s= ` (one space) is the recommended name of a session without one, and
/// `s=` must not be empty; RFC 8866 9: a value is a byte-string, nothing is trimmed from it.
#[test]
fn values_are_not_trimmed() {
    let sdp = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns= \r\nt=0 0\r\na=tool: two  spaces \r\n";
    let parsed = parse(sdp).unwrap();
    assert_eq!(parsed.session_name, " ");
    assert_eq!(
        parsed.attribute("tool").map(String::as_str),
        Some(" two  spaces ")
    );
    assert_eq!(parsed.marshal(), sdp);
}

/// RFC 8866 5.12: `k=` is obsolete; it "MUST NOT be included" and is "discarded if received".
#[test]
fn key_lines_are_parsed_and_dropped() {
    let sdp = format!(
        "{HEAD}k=prompt\r\nm=audio 9 RTP/AVP 0\r\nc=IN IP4 0.0.0.0\r\nk=clear:secret\r\na=sendrecv\r\n"
    );
    let marshalled = parse(&sdp).unwrap().marshal();
    assert!(!marshalled.contains("k="), "{marshalled}");
    assert_eq!(
        marshalled,
        format!("{HEAD}m=audio 9 RTP/AVP 0\r\nc=IN IP4 0.0.0.0\r\na=sendrecv\r\n")
    );
}

/// RFC 8285 4.3 and 6: 1 to 256 is the valid range (256 names the appbits), 4096 to 4351
/// marks an extension the offerer leaves the answerer to number; nothing else is an id.
#[test]
fn extmap_accepts_the_4096_range_and_refuses_ids_rfc_8285_does_not_define() {
    const URI: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";
    for (id, ok) in [
        ("1", true),
        ("14", true),
        ("15", true),
        ("255", true),
        ("256", true),
        ("4096", true),
        ("4351/sendonly", true),
        ("0", false),
        ("257", false),
        ("4095", false),
        ("4352", false),
        ("65536", false),
        ("99999", false),
        ("100000", false),
        ("+1", false),
        ("", false),
    ] {
        let value = format!("{id} {URI}");
        let parsed = <ExtMap as TypedAttribute>::parse(&value);
        assert_eq!(parsed.is_ok(), ok, "{value}: {parsed:?}");
        if let Ok(parsed) = parsed {
            assert_eq!(parsed.to_string(), value);
        }
    }

    // A description with such lines parses, and the typed accessor tells the three kinds
    // of id apart.
    let sdp = video(&format!(
        "a=extmap:3 {URI}\r\na=extmap:256 urn:example:appbits\r\na=extmap:4096 urn:example:gps\r\n"
    ));
    let extmaps = parse(&sdp).unwrap().media_descriptions[0]
        .extmaps()
        .unwrap();
    let kinds: Vec<(u16, bool, bool)> = extmaps
        .iter()
        .map(|e| (e.value, e.is_element_id(), e.is_answerer_assigned()))
        .collect();
    assert_eq!(
        kinds,
        vec![(3, true, false), (256, false, false), (4096, false, true)]
    );
    assert!(extmaps[0].fits_one_byte_header());
}

/// `ExtMap::unmarshal` is the entry its callers use to get an id for RTP headers: it keeps
/// refusing the ids that cannot be one, so that none is cast into a header by mistake.
#[test]
fn extmap_unmarshal_returns_only_ids_that_identify_an_extension_element() {
    for (line, ok) in [
        ("extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid", true),
        (
            "a=extmap:255/recvonly urn:ietf:params:rtp-hdrext:sdes:mid",
            true,
        ),
        ("extmap:256 urn:ietf:params:rtp-hdrext:sdes:mid", false),
        ("extmap:4096 urn:ietf:params:rtp-hdrext:sdes:mid", false),
        ("extmap:0 urn:ietf:params:rtp-hdrext:sdes:mid", false),
        ("mid:1 urn:ietf:params:rtp-hdrext:sdes:mid", false),
    ] {
        let parsed = ExtMap::unmarshal(&mut Cursor::new(line.as_bytes()));
        assert_eq!(parsed.is_ok(), ok, "{line}: {parsed:?}");
    }
}

/// RFC 8285 5: the extension attributes are a byte-string: everything after the URI.
#[test]
fn extmap_extension_attributes_keep_their_spaces() {
    let line = "extmap:5 urn:example:ext first second  third";
    let parsed = ExtMap::unmarshal(&mut Cursor::new(line.as_bytes())).unwrap();
    assert_eq!(parsed.ext_attr.as_deref(), Some("first second  third"));
    assert_eq!(parsed.marshal(), line);

    // Without attributes there is nothing after the URI, not even a space.
    for bad in ["5 urn:example:ext ", "5  urn:example:ext", "5", "5 "] {
        assert!(<ExtMap as TypedAttribute>::parse(bad).is_err(), "{bad:?}");
    }
}

/// RFC 8866 6.6: `a=rtpmap:<pt> <name>/<clock rate>`: the clock rate is not optional.
#[test]
fn rtpmap_without_a_clock_rate_is_not_a_codec() {
    let sdp = video("a=rtpmap:96 VP8\r\na=rtpmap:97 VP9/90000\r\n");
    let codecs = parse(&sdp).unwrap().media_descriptions[0].codecs();
    assert!(!codecs.contains_key(&96), "{codecs:?}");
    assert_eq!(codecs[&97].clock_rate, 90000);
}

/// RFC 5576 4.1 / RFC 8866 5.13: the source attributes written are registered ones. The
/// Plan B leftovers `mslabel` and `label` are not.
#[test]
fn media_source_writes_only_registered_source_attributes() {
    let media = crate::MediaDescription::default().with_media_source(
        1234,
        "cname-1".to_owned(),
        "stream".to_owned(),
        "track".to_owned(),
    );
    let lines: Vec<String> = media.attributes.iter().map(|a| a.to_string()).collect();
    assert_eq!(
        lines,
        vec!["ssrc:1234 cname:cname-1", "ssrc:1234 msid:stream track"]
    );
    let ssrcs = media.ssrcs().unwrap();
    assert_eq!(ssrcs[0].cname(), Some("cname-1"));
    assert_eq!(
        ssrcs[1].msid().unwrap().unwrap().appdata.as_deref(),
        Some("track")
    );
}

/// RFC 8827 5: `a=identity` carries an assertion. The session template wrote a bare
/// `a=identity`, which is not SDP any peer can read.
#[test]
fn the_session_template_never_writes_an_identity_line_without_an_assertion() {
    for identity in [false, true] {
        let session = SessionDescription::new_jsep_session_description(identity);
        assert_eq!(session.identity().unwrap(), None);
        assert!(session.validate().is_ok());
        assert!(!session.marshal().contains("identity"));
    }
}
