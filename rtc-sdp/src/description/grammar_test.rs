//! The RFC 8866 section 9 grammar, line type by line type: what the default (strict) parse
//! accepts and refuses, what each `ParseOptions` leniency adds, and what is written back.

use std::io::Cursor;

use shared::error::{Error, Result};

use super::common::*;
use super::media::*;
use super::session::*;

const V: &str = "v=0\r\n";
const O: &str = "o=- 1 1 IN IP4 0.0.0.0\r\n";
const S: &str = "s=-\r\n";
const T: &str = "t=0 0\r\n";
const M: &str = "m=audio 9 RTP/AVP 0\r\n";

fn strict(sdp: &str) -> Result<SessionDescription> {
    SessionDescription::unmarshal(&mut Cursor::new(sdp.as_bytes()))
}

fn lenient(sdp: &str) -> Result<SessionDescription> {
    SessionDescription::parse_with_options(sdp, &ParseOptions::lenient())
}

/// A description whose session-level lines after `s=` are `lines`.
fn session(lines: &str) -> String {
    format!("{V}{O}{S}{lines}")
}

/// A description with one media section whose lines after `m=` are `lines`.
fn media(lines: &str) -> String {
    format!("{V}{O}{S}{T}{M}{lines}")
}

/// Each `good` description parses and is written back unchanged; each `bad` one is refused.
fn check(good: &[String], bad: &[String]) {
    for sdp in good {
        match strict(sdp) {
            Ok(parsed) => assert_eq!(&parsed.marshal(), sdp),
            Err(err) => panic!("should parse ({err}):\n{sdp}"),
        }
    }
    for sdp in bad {
        assert!(strict(sdp).is_err(), "should be refused:\n{sdp}");
    }
}

fn each(make: impl Fn(&str) -> String, lines: &[&str]) -> Vec<String> {
    lines.iter().map(|l| make(l)).collect()
}

// --- the description as a whole -------------------------------------------------------------

#[test]
fn the_smallest_description_is_v_o_s_t() {
    let sdp = format!("{V}{O}{S}{T}");
    assert_eq!(strict(&sdp).unwrap().marshal(), sdp);
    // Each of the four is required.
    for missing in [
        format!("{O}{S}{T}"),
        format!("{V}{S}{T}"),
        format!("{V}{O}{T}"),
        format!("{V}{O}{S}"),
        format!("{V}{O}{S}{M}"),
        format!("{V}{O}{S}a=x\r\n"),
        String::new(),
        "\r\n".to_owned(),
    ] {
        assert!(strict(&missing).is_err(), "{missing:?}");
        assert!(lenient(&missing).is_err(), "{missing:?}");
    }
}

#[test]
fn a_type_letter_rfc_8866_does_not_define_refuses_the_description() {
    // RFC 8866 section 5: a parser "MUST completely ignore or reject any session
    // description that contains a type letter that it does not understand".
    for line in [
        "x=1\r\n",
        "y=\r\n",
        "V=0\r\n",
        "A=x\r\n",
        "1=1\r\n",
        "\u{e9}=1\r\n",
    ] {
        for sdp in [
            format!("{V}{O}{S}{T}{line}"),
            format!("{V}{O}{S}{line}{T}"),
            format!("{V}{O}{S}{T}{M}{line}"),
            format!("{line}{V}{O}{S}{T}"),
        ] {
            assert!(
                matches!(strict(&sdp), Err(Error::SdpInvalidSyntax(_))),
                "{sdp:?}"
            );
            assert!(lenient(&sdp).is_err(), "{sdp:?}");
        }
    }
}

#[test]
fn a_line_is_a_type_letter_an_equal_sign_and_a_value() {
    for line in [
        "a\r\n", "a x\r\n", "a =x\r\n", " a=x\r\n", "aa=x\r\n", "=x\r\n", "a:x\r\n",
    ] {
        let sdp = format!("{V}{O}{S}{T}{line}");
        assert!(strict(&sdp).is_err(), "{line:?}");
        assert!(lenient(&sdp).is_err(), "{line:?}");
    }
}

#[test]
fn lines_end_in_crlf_or_lf_and_the_last_one_may_end_at_the_end_of_input() {
    let crlf = format!("{V}{O}{S}{T}{M}a=mid:0\r\n");
    let lf = crlf.replace("\r\n", "\n");
    // RFC 8866 section 5: "parsers SHOULD be tolerant and also accept lines terminated
    // with a single newline character". What is written is always CRLF.
    assert_eq!(strict(&lf).unwrap().marshal(), crlf);
    assert_eq!(strict(crlf.trim_end()).unwrap().marshal(), crlf);
    assert_eq!(
        strict(&format!("{crlf}\r\n\n\r\n")).unwrap().marshal(),
        crlf
    );
    // Mixed endings are fine line by line.
    assert_eq!(
        strict(&format!("v=0\n{O}s=-\n{T}{M}a=mid:0"))
            .unwrap()
            .marshal(),
        crlf
    );
    // A CR that does not end a line, and NUL, are not part of any value.
    for bad in [
        format!("{V}{O}{S}{T}a=x\ry\r\n"),
        format!("v=0\r{O}{S}{T}"),
        format!("{V}{O}{S}{T}a=x\0y\r\n"),
        format!("{V}{O}s=a\0\r\n{T}"),
    ] {
        assert!(strict(&bad).is_err(), "{bad:?}");
        assert!(lenient(&bad).is_err(), "{bad:?}");
    }
}

#[test]
fn text_that_is_not_utf_8_is_refused() {
    // `a=charset` is not supported: a description is UTF-8 (RFC 8866 section 5).
    let mut bytes = format!("{V}{O}").into_bytes();
    bytes.extend_from_slice(b"s=caf\xe9\r\n");
    bytes.extend_from_slice(T.as_bytes());
    assert!(SessionDescription::unmarshal(&mut Cursor::new(&bytes)).is_err());

    let utf8 = format!("{V}{O}s=caf\u{e9} \u{1F600}\r\ni=\u{65e5}\u{672c}\r\n{T}a=x:\u{e9}\r\n");
    assert_eq!(strict(&utf8).unwrap().marshal(), utf8);
}

#[test]
fn unmarshal_reads_from_the_position_of_the_reader() {
    let sdp = format!("{V}{O}{S}{T}");
    let prefixed = format!("garbage{sdp}");
    let mut reader = Cursor::new(prefixed.as_bytes());
    reader.set_position(7);
    assert_eq!(
        SessionDescription::unmarshal(&mut reader)
            .unwrap()
            .marshal(),
        sdp
    );
    // The same text through the other entry points.
    assert_eq!(sdp.parse::<SessionDescription>().unwrap().marshal(), sdp);
    assert_eq!(
        SessionDescription::try_from(sdp.clone()).unwrap().marshal(),
        sdp
    );
    assert_eq!(String::from(strict(&sdp).unwrap()), sdp);
}

// --- session-level order ----------------------------------------------------------------------

#[test]
fn session_level_lines_come_in_the_order_of_the_grammar() {
    let all = "i=info\r\nu=http://example.com/\r\ne=a@example.com\r\ne=b@example.com\r\np=+1 555\r\np=+2 555\r\nc=IN IP4 192.0.2.1\r\nb=AS:1\r\nb=CT:2\r\nt=0 0\r\nt=3724394400 3724398000\r\nr=7d 1h 0 25h\r\nr=1d 1h 0\r\nz=3724394400 -1h 3724480800 0\r\nt=0 0\r\na=x\r\na=y:1\r\n";
    let expected = "i=info\r\nu=http://example.com/\r\ne=a@example.com\r\ne=b@example.com\r\np=+1 555\r\np=+2 555\r\nc=IN IP4 192.0.2.1\r\nb=AS:1\r\nb=CT:2\r\nt=0 0\r\nt=3724394400 3724398000\r\nr=604800 3600 0 90000\r\nr=86400 3600 0\r\nz=3724394400 -3600 3724480800 0\r\nt=0 0\r\na=x\r\na=y:1\r\n";
    let parsed = strict(&session(all)).unwrap();
    assert_eq!(parsed.marshal(), session(expected));
    assert_eq!(parsed.time_descriptions.len(), 3);
    assert_eq!(parsed.time_descriptions[1].repeat_times.len(), 2);
    assert_eq!(parsed.time_descriptions[1].time_zones.len(), 2);
    assert!(parsed.time_descriptions[2].time_zones.is_empty());

    // Every line type moved one place too late or repeated when it may occur once.
    let bad = each(
        session,
        &[
            // i u e p c b t k a: a type after a later one
            "u=http://example.com/\r\ni=info\r\nt=0 0\r\n",
            "e=a@example.com\r\nu=http://example.com/\r\nt=0 0\r\n",
            "p=+1 555\r\ne=a@example.com\r\nt=0 0\r\n",
            "c=IN IP4 192.0.2.1\r\np=+1 555\r\nt=0 0\r\n",
            "b=AS:1\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n",
            "t=0 0\r\nb=AS:1\r\n",
            "t=0 0\r\nc=IN IP4 192.0.2.1\r\n",
            "t=0 0\r\ni=info\r\n",
            "t=0 0\r\na=x\r\nt=0 0\r\n",
            "t=0 0\r\na=x\r\nk=prompt\r\n",
            "t=0 0\r\na=x\r\nr=7d 1h 0\r\n",
            "t=0 0\r\na=x\r\nz=3724394400 0\r\n",
            "a=x\r\nt=0 0\r\n",
            "k=prompt\r\nt=0 0\r\n",
            // single lines given twice
            "i=a\r\ni=b\r\nt=0 0\r\n",
            "u=http://a.example/\r\nu=http://b.example/\r\nt=0 0\r\n",
            "c=IN IP4 192.0.2.1\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n",
            "t=0 0\r\nk=prompt\r\nk=prompt\r\n",
            // r= and z= belong to a time description
            "r=7d 1h 0\r\nt=0 0\r\n",
            "z=3724394400 0\r\nt=0 0\r\n",
            "t=0 0\r\nz=3724394400 0\r\nz=3724394400 0\r\n",
            "t=0 0\r\nz=3724394400 0\r\nr=7d 1h 0\r\n",
            // v=, o=, s= once each
            "v=0\r\nt=0 0\r\n",
            "o=- 1 1 IN IP4 0.0.0.0\r\nt=0 0\r\n",
            "s=-\r\nt=0 0\r\n",
            "t=0 0\r\nv=0\r\n",
        ],
    );
    check(&[], &bad);
    for sdp in &bad {
        // Session-level order is not something a leniency relaxes.
        assert!(lenient(sdp).is_err(), "{sdp}");
    }
}

#[test]
fn z_after_t_without_r_is_accepted_as_rfc_4566_wrote_it() {
    // RFC 8866 moved z= into the repeat description (after r=); RFC 4566 had it after the
    // time descriptions. The older form parses, and belongs to the t= line it follows.
    let sdp = session("t=3724394400 3724398000\r\nz=3724394400 -1h\r\na=x\r\n");
    let parsed = strict(&sdp).unwrap();
    assert_eq!(
        parsed.time_descriptions[0].time_zones,
        vec![TimeZone {
            adjustment_time: 3724394400,
            offset: -3600
        }]
    );
    assert_eq!(
        parsed.marshal(),
        session("t=3724394400 3724398000\r\nz=3724394400 -3600\r\na=x\r\n")
    );
}

// --- media-level order ------------------------------------------------------------------------

#[test]
fn media_level_lines_come_in_the_order_m_i_c_b_k_a() {
    let good = each(
        media,
        &[
            "",
            "i=title\r\n",
            "c=IN IP4 192.0.2.1\r\n",
            "b=AS:1\r\n",
            "a=x\r\n",
            "i=title\r\nc=IN IP4 192.0.2.1\r\nb=AS:1\r\nb=TIAS:2\r\na=x\r\na=y:1\r\n",
            "a=x\r\nm=video 9 RTP/AVP 96\r\ni=title\r\nc=IN IP4 192.0.2.1\r\na=y\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n",
        ],
    );
    let bad = each(
        media,
        &[
            "c=IN IP4 192.0.2.1\r\ni=title\r\n",
            "b=AS:1\r\ni=title\r\n",
            "b=AS:1\r\nc=IN IP4 192.0.2.1\r\n",
            "a=x\r\ni=title\r\n",
            "a=x\r\nc=IN IP4 192.0.2.1\r\n",
            "a=x\r\nb=AS:1\r\n",
            "a=x\r\nk=prompt\r\n",
            "k=prompt\r\nb=AS:1\r\n",
            "i=a\r\ni=b\r\n",
            "k=prompt\r\nk=prompt\r\n",
            // session-only line types
            "v=0\r\n",
            "o=- 1 1 IN IP4 0.0.0.0\r\n",
            "s=-\r\n",
            "u=http://example.com/\r\n",
            "e=a@example.com\r\n",
            "p=+1 555\r\n",
            "t=0 0\r\n",
            "r=7d 1h 0\r\n",
            "z=3724394400 0\r\n",
        ],
    );
    check(&good, &bad);
}

#[test]
fn unordered_media_lines_is_the_only_leniency_about_order() {
    let options = ParseOptions {
        unordered_media_lines: true,
        ..ParseOptions::strict()
    };
    let parse = |sdp: &str| SessionDescription::parse_with_options(sdp, &options);

    let sdp =
        media("a=x\r\nb=AS:1\r\nk=prompt\r\nc=IN IP4 192.0.2.1\r\na=y\r\ni=title\r\nb=TIAS:2\r\n");
    assert!(strict(&sdp).is_err());
    // Written back in the order of the grammar.
    assert_eq!(
        parse(&sdp).unwrap().marshal(),
        media("i=title\r\nc=IN IP4 192.0.2.1\r\nb=AS:1\r\nb=TIAS:2\r\na=x\r\na=y\r\n")
    );
    // Still one i= and one k= per media description, and no session-level line type.
    for bad in [
        "a=x\r\ni=a\r\ni=b\r\n",
        "k=prompt\r\na=x\r\nk=prompt\r\n",
        "a=x\r\nt=0 0\r\n",
        "a=x\r\ns=-\r\n",
    ] {
        assert!(parse(&media(bad)).is_err(), "{bad}");
    }
    // The other leniencies are not implied.
    assert!(parse(&media("\r\na=x\r\n")).is_err());
    assert!(parse(&format!("{V}{O}{S}{T}m=audio  9 RTP/AVP 0\r\n")).is_err());
}

#[test]
fn several_connection_lines_in_a_media_description_keep_the_last() {
    // RFC 8866 section 9: `*connection-field` in a media description (layered multicast).
    let sdp = media("c=IN IP4 233.252.0.1/127\r\nc=IN IP4 233.252.0.2/127\r\n");
    let parsed = strict(&sdp).unwrap();
    assert_eq!(
        parsed.media_descriptions[0]
            .connection_information
            .as_ref()
            .and_then(|c| c.address.as_ref())
            .map(|a| a.address.as_str()),
        Some("233.252.0.2")
    );
}

// --- v= ---------------------------------------------------------------------------------------

#[test]
fn the_version_is_zero() {
    for bad in [
        "v=1\r\n",
        "v=\r\n",
        "v=0 \r\n",
        "v= 0\r\n",
        "v=-0\r\n",
        "v=0.0\r\n",
        "v=x\r\n",
        "v=4294967296\r\n",
    ] {
        let sdp = format!("{bad}{O}{S}{T}");
        assert!(strict(&sdp).is_err(), "{bad:?}");
    }
    // `1*DIGIT`: leading zeroes are digits.
    assert_eq!(strict(&format!("v=00\r\n{O}{S}{T}")).unwrap().version, 0);
}

// --- o= ---------------------------------------------------------------------------------------

#[test]
fn origin_has_six_fields_with_the_grammar_of_each() {
    let o = |line: &str| format!("{V}{line}{S}{T}");
    let good = each(
        o,
        &[
            "o=- 1 1 IN IP4 0.0.0.0\r\n",
            "o=jdoe 3724394400 3724394405 IN IP4 198.51.100.1\r\n",
            "o=mozilla...THIS_IS_SDPARTA-99.0 8847547619928269125 0 IN IP4 0.0.0.0\r\n",
            "o=- 0 0 IN IP6 2001:db8::1\r\n",
            "o=- 18446744073709551615 18446744073709551615 IN IP4 host.example.com\r\n",
            "o=\u{e9}t\u{e9} 1 1 IN IP4 127.0.0.1\r\n",
            // RFC 8866 section 5.2: other network and address types may be registered.
            "o=- 1 1 ATM NSAP 47.0091.8100.0000.0060.3e64.fd01.0060.3e64.fd01.fe\r\n",
            "o=- 1 1 TN RFC2543 +15551234\r\n",
        ],
    );
    let bad = each(
        o,
        &[
            "o=\r\n",
            "o=- 1 1 IN IP4\r\n",
            "o=- 1 1 IN IP4 0.0.0.0 extra\r\n",
            "o=j doe 1 1 IN IP4 0.0.0.0\r\n",
            "o=- 1  1 IN IP4 0.0.0.0\r\n",
            "o= - 1 1 IN IP4 0.0.0.0\r\n",
            "o=- 1 1 IN IP4 0.0.0.0 \r\n",
            "o=-\t1 1 IN IP4 0.0.0.0\r\n",
            "o=- x 1 IN IP4 0.0.0.0\r\n",
            "o=- 1 x IN IP4 0.0.0.0\r\n",
            "o=- -1 1 IN IP4 0.0.0.0\r\n",
            "o=- 1.5 1 IN IP4 0.0.0.0\r\n",
            "o=- 18446744073709551616 1 IN IP4 0.0.0.0\r\n",
            "o=- 1 1 I/N IP4 0.0.0.0\r\n",
            "o=- 1 1 IN IP/4 0.0.0.0\r\n",
            "o=- 1 1 IN IP4 ::1\r\n",
            "o=- 1 1 IN IP4 256.0.0.1/1\r\n",
            "o=- 1 1 IN IP4 a_b\r\n",
            "o=- 1 1 IN IP6 [::1]\r\n",
            "o=- 1 1 IN IP6 fe80::1%eth0\r\n",
        ],
    );
    check(&good, &bad);

    let parsed = strict(&o("o=jdoe 3724394400 3724394405 IN IP4 198.51.100.1\r\n")).unwrap();
    assert_eq!(parsed.origin.username, "jdoe");
    assert_eq!(parsed.origin.session_id, 3724394400);
    assert_eq!(parsed.origin.session_version, 3724394405);
    assert_eq!(parsed.origin.unicast_address, "198.51.100.1");
}

// --- s=, i= -----------------------------------------------------------------------------------

#[test]
fn session_name_and_information_are_text_kept_as_written() {
    let s = |line: &str| format!("{V}{O}{line}{T}");
    let good = each(
        s,
        &[
            "s=-\r\n",
            // RFC 8866 section 5.3: `s= ` (one space) is the other recommended form.
            "s= \r\n",
            "s=  two leading and one trailing \r\n",
            "s=SDP Seminar\r\n",
            "s=a=b:c\r\n",
            "s=\t\r\n",
            "s=-\r\ni= \r\n",
            "s=-\r\ni=A Seminar on the session description protocol\r\n",
        ],
    );
    // RFC 8866 section 5.3: "The 's=' line MUST NOT be empty"; `text` is never empty.
    let bad = each(s, &["s=\r\n", "s=-\r\ni=\r\n"]);
    check(&good, &bad);
    assert_eq!(strict(&s("s= \r\n")).unwrap().session_name, " ");

    let m = media("i=\r\n");
    assert!(strict(&m).is_err());
    assert_eq!(
        strict(&media("i= title \r\n")).unwrap().media_descriptions[0]
            .media_title
            .as_deref(),
        Some(" title ")
    );
}

#[test]
fn an_empty_session_name_is_never_written() {
    // Accepted only with `loose_fields`, and written as `s=-` (RFC 8866 section 5.3).
    let sdp = format!("{V}{O}s=\r\n{T}");
    assert!(strict(&sdp).is_err());
    let parsed = lenient(&sdp).unwrap();
    assert_eq!(parsed.session_name, "");
    assert_eq!(parsed.marshal(), format!("{V}{O}{S}{T}"));

    // A description built without a name or a time description still has both lines.
    let built = SessionDescription {
        origin: Origin {
            username: "-".to_owned(),
            session_id: 1,
            session_version: 1,
            network_type: "IN".to_owned(),
            address_type: "IP4".to_owned(),
            unicast_address: "0.0.0.0".to_owned(),
        },
        ..Default::default()
    };
    assert_eq!(built.marshal(), format!("{V}{O}{S}{T}"));
    assert!(strict(&built.marshal()).is_ok());
}

// --- u=, e=, p= -------------------------------------------------------------------------------

#[test]
fn uri_email_and_phone_follow_their_grammars() {
    let good = each(
        session,
        &[
            "u=http://www.example.com/seminars/sdp.pdf\r\nt=0 0\r\n",
            "u=urn:example:a\r\nt=0 0\r\n",
            // RFC 8866 section 5.6.
            "e=j.doe@example.com (Jane Doe)\r\nt=0 0\r\n",
            "e=Jane Doe <j.doe@example.com>\r\nt=0 0\r\n",
            "e=j.doe@example.com\r\nt=0 0\r\n",
            "e=\"j doe\"@example.com\r\nt=0 0\r\n",
            "e=j.doe+tag@[192.0.2.1]\r\nt=0 0\r\n",
            "e=j.doe@example.com   (Jane   Doe)\r\nt=0 0\r\n",
            // RFC 8866 section 5.6: the free text is UTF-8.
            "e=j.doe@example.com (Jan\u{e9} D\u{f6}\u{e9})\r\nt=0 0\r\n",
            "p=+1 617 555-6011 (Jan\u{e9})\r\nt=0 0\r\n",
            "p=+1 617 555-6011\r\nt=0 0\r\n",
            "p=+1 617 555-6011 (Jane Doe)\r\nt=0 0\r\n",
            "p=+1 617 555-6011(Jane Doe)\r\nt=0 0\r\n",
            "p=Jane Doe <+1 617 555-6011>\r\nt=0 0\r\n",
            "p=16175556011\r\nt=0 0\r\n",
        ],
    );
    let bad = each(
        session,
        &[
            "u=\r\nt=0 0\r\n",
            "u=not a uri\r\nt=0 0\r\n",
            "e=\r\nt=0 0\r\n",
            "e=Jane Doe\r\nt=0 0\r\n",
            "e=@example.com\r\nt=0 0\r\n",
            "e=j.doe@\r\nt=0 0\r\n",
            "e=j..doe@example.com\r\nt=0 0\r\n",
            "e=j doe@example.com\r\nt=0 0\r\n",
            "e=j.doe@example.com(Jane Doe)\r\nt=0 0\r\n",
            "e=j.doe@example.com ()\r\nt=0 0\r\n",
            "e=j.doe@example.com (Jane (Doe))\r\nt=0 0\r\n",
            "e=Jane Doe<j.doe@example.com>\r\nt=0 0\r\n",
            "e=<j.doe@example.com>\r\nt=0 0\r\n",
            "e=Jane Doe <j.doe@example.com\r\nt=0 0\r\n",
            "p=\r\nt=0 0\r\n",
            "p=+\r\nt=0 0\r\n",
            "p=1\r\nt=0 0\r\n",
            "p=+1 617 555-6011 ()\r\nt=0 0\r\n",
            "p=phone\r\nt=0 0\r\n",
            "p=+1 (617) 555-6011\r\nt=0 0\r\n",
            "p=<+1 617 555-6011>\r\nt=0 0\r\n",
            "p=Jane Doe <617>x\r\nt=0 0\r\n",
        ],
    );
    check(&good, &bad);

    let parsed = strict(&session(
        "e=a@example.com\r\ne=b@example.com\r\np=+1 555\r\np=+2 555\r\nt=0 0\r\n",
    ))
    .unwrap();
    assert_eq!(
        parsed.email_addresses,
        vec!["a@example.com", "b@example.com"]
    );
    assert_eq!(parsed.phone_numbers, vec!["+1 555", "+2 555"]);

    // `loose_fields` keeps contact text it cannot check.
    let loose = lenient(&session("e=NONE\r\np=unlisted\r\nt=0 0\r\n")).unwrap();
    assert_eq!(loose.email_addresses, vec!["NONE"]);
    assert_eq!(loose.phone_numbers, vec!["unlisted"]);
}

// --- c= ---------------------------------------------------------------------------------------

#[test]
fn connection_data_follows_the_address_grammar_of_its_address_type() {
    const LONG_LABEL: &str =
        "c=IN IP4 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example\r\n";
    let c = |line: &str| session(&format!("{line}t=0 0\r\n"));
    let good = each(
        c,
        &[
            "c=IN IP4 0.0.0.0\r\n",
            "c=IN IP4 198.51.100.1\r\n",
            "c=IN IP4 223.255.255.255\r\n",
            "c=IN IP4 host.example.com\r\n",
            "c=IN IP6 2001:db8::1\r\n",
            "c=IN IP6 ::\r\n",
            "c=IN IP6 host.example.com\r\n",
            // RFC 8866 section 5: an internationalized name is in its ASCII (ACE) form.
            "c=IN IP4 xn--bcher-kva.example\r\n",
            // RFC 1034 / RFC 1035: a fully qualified name may end in the root's dot, and a
            // label may start with a digit (RFC 1123 section 2.1).
            "c=IN IP4 host.example.com.\r\n",
            "c=IN IP4 61b445d2-6503.local\r\n",
            // RFC 8866 section 5.7: multicast, with a TTL for IPv4 and never for IPv6.
            "c=IN IP4 233.252.0.1/127\r\n",
            "c=IN IP4 233.252.0.1/0\r\n",
            "c=IN IP4 233.252.0.1/255\r\n",
            "c=IN IP4 233.252.0.1/127/3\r\n",
            "c=IN IP6 ff15::101\r\n",
            "c=IN IP6 ff15::101/3\r\n",
            // Other registered network and address types: the address is opaque.
            "c=ATM NSAP 47.0091.8100.0000.0060.3e64.fd01.0060.3e64.fd01.fe\r\n",
            "c=PSTN E164 +15551234\r\n",
        ],
    );
    let bad = each(
        c,
        &[
            "c=\r\n",
            "c=IN\r\n",
            "c=IN IP4\r\n",
            "c=IN IP4 \r\n",
            "c=IN  IP4 0.0.0.0\r\n",
            "c=IN IP4 0.0.0.0 \r\n",
            "c=IN IP4 0.0.0.0 extra\r\n",
            "c=I/N IP4 0.0.0.0\r\n",
            "c=IN IP4 ::1\r\n",
            "c=IN IP4 a_b\r\n",
            // RFC 8866 section 5: names "MUST comply with" RFC 1034 / RFC 1035: no empty
            // label, none of more than 63 characters, no hyphen at either end of a label.
            "c=IN IP4 host..example\r\n",
            "c=IN IP4 -host.example\r\n",
            "c=IN IP4 host-.example\r\n",
            "c=IN IP6 host.-example\r\n",
            "c=IN IP4 .example\r\n",
            LONG_LABEL,
            "c=IN IP4 b\u{fc}cher.example\r\n",
            "c=IN IP6 b\u{fc}cher.example\r\n",
            "c=IN IP6 [::1]\r\n",
            // "The slash notation ... MUST NOT be used for IP unicast addresses."
            "c=IN IP4 198.51.100.1/127\r\n",
            "c=IN IP4 198.51.100.1/127/2\r\n",
            "c=IN IP6 2001:db8::1/2\r\n",
            "c=IN IP4 host.example.com/127\r\n",
            // The TTL is 0 to 255, without leading zeroes; IPv6 has none.
            "c=IN IP4 233.252.0.1/256\r\n",
            "c=IN IP4 233.252.0.1/0127\r\n",
            "c=IN IP4 233.252.0.1/\r\n",
            "c=IN IP4 233.252.0.1/127/0\r\n",
            "c=IN IP4 233.252.0.1/127/2/1\r\n",
            "c=IN IP6 ff15::101/127/3\r\n",
            "c=IN IP6 ff15::101/0\r\n",
            "c=PSTN E164 \r\n",
        ],
    );
    check(&good, &bad);

    let parsed = strict(&c("c=IN IP4 233.252.0.1/127/3\r\n")).unwrap();
    let address = parsed.connection_information.unwrap().address.unwrap();
    assert_eq!(
        (address.address.as_str(), address.ttl, address.range),
        ("233.252.0.1", Some(127), Some(3))
    );
    let parsed = strict(&c("c=IN IP6 ff15::101/3\r\n")).unwrap();
    let address = parsed.connection_information.unwrap().address.unwrap();
    assert_eq!((address.ttl, address.range), (None, Some(3)));

    // The same grammar at the media level.
    assert!(strict(&media("c=IN IP4 198.51.100.1/127\r\n")).is_err());
    assert!(strict(&media("c=IN IP4\r\n")).is_err());
    assert!(ConnectionInformation::parse("IN IP4 0.0.0.0").is_ok());
    assert!(ConnectionInformation::parse("IN IP4").is_err());
    assert!(Address::parse("IP4", "198.51.100.1").is_ok());
    assert!(Address::parse("IP4", "198.51.100.1/1").is_err());
}

// --- b= ---------------------------------------------------------------------------------------

#[test]
fn bandwidth_is_a_token_a_colon_and_digits() {
    let b = |line: &str| session(&format!("{line}t=0 0\r\n"));
    let good = each(
        b,
        &[
            "b=AS:64\r\n",
            "b=CT:1000\r\n",
            "b=TIAS:1400000\r\n",
            "b=RS:0\r\n",
            "b=RR:4000\r\n",
            "b=X-YZ:128\r\n",
            // RFC 8866 section 5.8: an unknown bwtype is ignored, not an error.
            "b=FUTURE:18446744073709551615\r\n",
            "b=AS:64\r\nb=TIAS:64000\r\n",
        ],
    );
    let bad = each(
        b,
        &[
            "b=\r\n",
            "b=AS\r\n",
            "b=AS:\r\n",
            "b=:64\r\n",
            "b=AS:64:1\r\n",
            "b=AS: 64\r\n",
            "b=AS :64\r\n",
            "b=A S:64\r\n",
            "b=A/S:64\r\n",
            "b=AS:-1\r\n",
            "b=AS:6.4\r\n",
            "b=AS:64kbps\r\n",
            "b=AS:18446744073709551616\r\n",
        ],
    );
    check(&good, &bad);
    assert!(strict(&media("b=AS:\r\n")).is_err());
    assert_eq!(
        strict(&media("b=AS:64\r\n")).unwrap().media_descriptions[0].bandwidth[0].bandwidth,
        64
    );
}

// --- t=, r=, z= -------------------------------------------------------------------------------

#[test]
fn times_are_zero_or_at_least_ten_digits() {
    let good = each(
        session,
        &[
            "t=0 0\r\n",
            "t=3724394400 3724398000\r\n",
            "t=3724394400 0\r\n",
            "t=0 3724398000\r\n",
            "t=18446744073709551615 0\r\n",
        ],
    );
    let bad = each(
        session,
        &[
            "t=\r\n",
            "t=0\r\n",
            "t=0 0 0\r\n",
            "t=0  0\r\n",
            "t= 0 0\r\n",
            "t=0 0 \r\n",
            "t=1 0\r\n",
            "t=372439440 0\r\n",
            "t=0 00\r\n",
            "t=0372439440 0\r\n",
            "t=-1 0\r\n",
            "t=now 0\r\n",
            "t=18446744073709551616 0\r\n",
        ],
    );
    check(&good, &bad);
    // `loose_fields`: any number, and what follows the stop time is ignored.
    let loose = lenient(&session("t=1  2 3\r\n")).unwrap();
    assert_eq!(
        loose.time_descriptions[0].timing,
        Timing {
            start_time: 1,
            stop_time: 2
        }
    );
}

#[test]
fn repeat_times_are_typed_times_in_seconds() {
    let parsed = strict(&session(
        "t=0 0\r\nr=604800 3600 0 90000\r\nr=7d 1h 0 25h\r\nr=10m 30s 0 5s 1m\r\n",
    ))
    .unwrap();
    assert_eq!(
        parsed.time_descriptions[0].repeat_times,
        vec![
            RepeatTime {
                interval: 604800,
                duration: 3600,
                offsets: vec![0, 90000]
            },
            RepeatTime {
                interval: 604800,
                duration: 3600,
                offsets: vec![0, 90000]
            },
            RepeatTime {
                interval: 600,
                duration: 30,
                offsets: vec![0, 5, 60]
            },
        ]
    );
    let bad = each(
        session,
        &[
            "t=0 0\r\nr=\r\n",
            "t=0 0\r\nr=7d\r\n",
            // `repeat-interval SP typed-time 1*(SP typed-time)`: at least one offset.
            "t=0 0\r\nr=7d 1h\r\n",
            "t=0 0\r\nr=7d  1h 0\r\n",
            // repeat-interval = POS-DIGIT *DIGIT [unit]
            "t=0 0\r\nr=0 1h 0\r\n",
            "t=0 0\r\nr=07d 1h 0\r\n",
            "t=0 0\r\nr=-7d 1h 0\r\n",
            "t=0 0\r\nr=7d -1h 0\r\n",
            "t=0 0\r\nr=7d 1h -1\r\n",
            // The units are d, h, m, s, case-sensitive.
            "t=0 0\r\nr=7D 1h 0\r\n",
            "t=0 0\r\nr=7w 1h 0\r\n",
            "t=0 0\r\nr=7d 1.5h 0\r\n",
            "t=0 0\r\nr=d 1h 0\r\n",
            "t=0 0\r\nr=106751991167301d 1h 0\r\n",
        ],
    );
    check(&[], &bad);
}

#[test]
fn zone_adjustments_come_in_pairs_with_an_optional_minus() {
    let parsed = strict(&session(
        "t=0 0\r\nr=7d 1h 0\r\nz=3724394400 -1h 3724480800 0 3724567200 2h\r\n",
    ))
    .unwrap();
    assert_eq!(
        parsed.time_descriptions[0].time_zones,
        vec![
            TimeZone {
                adjustment_time: 3724394400,
                offset: -3600
            },
            TimeZone {
                adjustment_time: 3724480800,
                offset: 0
            },
            TimeZone {
                adjustment_time: 3724567200,
                offset: 7200
            },
        ]
    );
    let bad = each(
        session,
        &[
            "t=0 0\r\nr=7d 1h 0\r\nz=\r\n",
            "t=0 0\r\nr=7d 1h 0\r\nz=3724394400\r\n",
            "t=0 0\r\nr=7d 1h 0\r\nz=3724394400 -1h 3724480800\r\n",
            // `time = POS-DIGIT 9*DIGIT`: not zero, at least ten digits.
            "t=0 0\r\nr=7d 1h 0\r\nz=0 -1h\r\n",
            "t=0 0\r\nr=7d 1h 0\r\nz=372439440 -1h\r\n",
            "t=0 0\r\nr=7d 1h 0\r\nz=3724394400 --1h\r\n",
            "t=0 0\r\nr=7d 1h 0\r\nz=3724394400 +1h\r\n",
            "t=0 0\r\nr=7d 1h 0\r\nz=3724394400 -\r\n",
            "t=0 0\r\nr=7d 1h 0\r\nz=3724394400  -1h\r\n",
        ],
    );
    check(&[], &bad);
}

// --- k= ---------------------------------------------------------------------------------------

#[test]
fn key_lines_are_checked_for_syntax_and_then_dropped() {
    // RFC 8866 section 5.12 (discard), RFC 9429 section 5.8.1 (check the syntax).
    for key in [
        "k=prompt\r\n",
        "k=clear:a password\r\n",
        "k=base64:cGFzc3dvcmQ=\r\n",
        "k=base64:\r\n",
        "k=uri:https://example.com/key\r\n",
    ] {
        let parsed = strict(&session(&format!("t=0 0\r\n{key}a=x\r\n"))).unwrap();
        assert_eq!(parsed.encryption_key, None, "{key}");
        assert_eq!(parsed.marshal(), session("t=0 0\r\na=x\r\n"));
        let parsed = strict(&media(key)).unwrap();
        assert_eq!(parsed.media_descriptions[0].encryption_key, None);
        assert_eq!(parsed.marshal(), media(""));
    }
    for key in [
        "k=\r\n",
        "k=Prompt\r\n",
        "k=prompt:x\r\n",
        "k=clear:\r\n",
        "k=clear\r\n",
        "k=base64:abc\r\n",
        "k=base64:ab=c\r\n",
        "k=uri:\r\n",
        "k=uri:a b\r\n",
        "k=pgp:x\r\n",
    ] {
        assert!(
            strict(&session(&format!("t=0 0\r\n{key}"))).is_err(),
            "{key}"
        );
        assert!(strict(&media(key)).is_err(), "{key}");
    }
    // The error does not repeat the key.
    let err = strict(&session("t=0 0\r\nk=clear\u{0}secret\r\n")).unwrap_err();
    assert!(!err.to_string().contains("secret"));
    let err = strict(&session("t=0 0\r\nk=base64:secret-key\r\n")).unwrap_err();
    assert!(!err.to_string().contains("secret"), "{err}");
}

// --- a= ---------------------------------------------------------------------------------------

#[test]
fn an_attribute_is_a_token_and_an_optional_value_after_the_first_colon() {
    let parsed = strict(&session(
        "t=0 0\r\na=flag\r\na=name:value\r\na=name:a:b:c\r\na=tool: lead and trail \r\na=x-custom_1.2:\u{e9}\r\na=empty:\r\n",
    ))
    .unwrap();
    let attributes: Vec<(&str, Option<&str>)> = parsed
        .attributes
        .iter()
        .map(|a| (a.key.as_str(), a.value.as_deref()))
        .collect();
    assert_eq!(
        attributes,
        vec![
            ("flag", None),
            ("name", Some("value")),
            ("name", Some("a:b:c")),
            ("tool", Some(" lead and trail ")),
            ("x-custom_1.2", Some("\u{e9}")),
            // RFC 3611 defines `a=rtcp-xr:` with nothing after the colon.
            ("empty", Some("")),
        ]
    );
    assert!(parsed.has_attribute("flag"));
    assert_eq!(parsed.attribute("name").map(String::as_str), Some("value"));
    assert_eq!(parsed.attribute("flag"), None);

    // RFC 8866 section 9: `attribute-name = token`.
    for bad in [
        "a=\r\n",
        "a=:value\r\n",
        "a=na me:value\r\n",
        "a=na me\r\n",
        "a= name\r\n",
        "a=n\u{e9}:v\r\n",
        "a=a/b\r\n",
        "a=a=b\r\n",
        "a=(x)\r\n",
    ] {
        assert!(
            strict(&session(&format!("t=0 0\r\n{bad}"))).is_err(),
            "{bad:?}"
        );
        assert!(strict(&media(bad)).is_err(), "{bad:?}");
        assert!(lenient(&media(bad)).is_err(), "{bad:?}");
    }
}

#[test]
fn attributes_that_are_not_understood_are_kept_at_both_levels() {
    // RFC 8866 section 5.13 and RFC 9429 section 5.8: ignored, which for a parser that
    // writes descriptions back means kept as they are.
    let sdp = format!(
        "{V}{O}{S}{T}a=cat:foo.bar\r\na=keywds:a b\r\na=tool:x 1.0\r\na=type:meeting\r\na=charset:UTF-8\r\na=sdplang:en\r\na=lang:fr\r\na=x-unknown:\u{1F600}\r\n{M}a=orient:portrait\r\na=quality:10\r\na=x-future\r\na=lang:de\r\n"
    );
    let parsed = strict(&sdp).unwrap();
    assert_eq!(parsed.marshal(), sdp);
    assert_eq!(parsed.attributes.len(), 8);
    assert_eq!(parsed.media_descriptions[0].attributes.len(), 4);
    // And they do not make the description invalid.
    assert!(
        strict(&format!(
            "{V}{O}{S}{T}a=x-unknown\r\n{M}c=IN IP4 0.0.0.0\r\na=x-future:1\r\n"
        ))
        .unwrap()
        .validate()
        .is_ok()
    );
}

// --- m= ---------------------------------------------------------------------------------------

#[test]
fn the_media_line_is_media_port_proto_and_formats() {
    let m = |line: &str| format!("{V}{O}{S}{T}{line}");
    let good = each(
        m,
        &[
            "m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8\r\n",
            "m=video 0 UDP/TLS/RTP/SAVPF 96\r\n",
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n",
            "m=audio 49170/2 RTP/AVP 0\r\n",
            "m=audio 65535 RTP/AVP 0\r\n",
            "m=text 9 RTP/AVP 98\r\n",
            "m=x-future 9 FOO *\r\n",
            "m=image 9 udptl t38\r\n",
        ],
    );
    let bad = each(
        m,
        &[
            "m=\r\n",
            "m=audio\r\n",
            "m=audio 9\r\n",
            "m=audio 9 RTP/AVP\r\n",
            "m=audio 9 RTP/AVP \r\n",
            "m=audio  9 RTP/AVP 0\r\n",
            "m= audio 9 RTP/AVP 0\r\n",
            "m=audio 9 RTP/AVP 0 \r\n",
            "m=audio 9 RTP/AVP 0  8\r\n",
            "m=au/dio 9 RTP/AVP 0\r\n",
            "m=audio x RTP/AVP 0\r\n",
            "m=audio -1 RTP/AVP 0\r\n",
            "m=audio 65536 RTP/AVP 0\r\n",
            "m=audio 9/ RTP/AVP 0\r\n",
            "m=audio 9/0 RTP/AVP 0\r\n",
            "m=audio 9/02 RTP/AVP 0\r\n",
            "m=audio 9/2/2 RTP/AVP 0\r\n",
            "m=audio 9 RTP//AVP 0\r\n",
            "m=audio 9 /RTP 0\r\n",
            "m=audio 9 RTP/ 0\r\n",
            "m=audio 9 RT:P 0\r\n",
            "m=audio 9 RTP/AVP 0,8\r\n",
            "m=audio 9 RTP/AVP a/b\r\n",
        ],
    );
    check(&good, &bad);

    let parsed = strict(&m("m=audio 49170/2 RTP/AVP 0 8\r\n")).unwrap();
    let name = &parsed.media_descriptions[0].media_name;
    assert_eq!(name.media, "audio");
    assert_eq!((name.port.value, name.port.range), (49170, Some(2)));
    assert_eq!(name.protos, vec!["RTP", "AVP"]);
    assert_eq!(name.formats, vec!["0", "8"]);
}

// --- loose_fields -----------------------------------------------------------------------------

#[test]
fn loose_fields_accepts_any_white_space_between_fields() {
    let options = ParseOptions {
        loose_fields: true,
        ..ParseOptions::strict()
    };
    let sdp = "v=0\r\no=-  1 1\tIN IP4 0.0.0.0 \r\ns=-\r\nc= IN IP4  0.0.0.0\r\nb= AS:64 \r\nt= 0  0 \r\nr=7d  1h 0\r\nz=3724394400  -1h\r\nm=audio  9 RTP/AVP  0 8 \r\n";
    assert!(strict(sdp).is_err());
    let parsed = SessionDescription::parse_with_options(sdp, &options).unwrap();
    assert_eq!(
        parsed.marshal(),
        "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nb=AS:64\r\nt=0 0\r\nr=604800 3600 0\r\nz=3724394400 -3600\r\nm=audio 9 RTP/AVP 0 8\r\n"
    );
    // It does not make a field optional or change what a field may contain.
    for bad in [
        "v=0\r\no=- 1 1 IN IP4\r\ns=-\r\nt=0 0\r\n",
        "v=0\r\no=- x 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n",
        "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0\r\n",
        "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\nm=audio 9 RTP/AVP\r\n",
        "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\nm=audio x RTP/AVP 0\r\n",
        "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nb=AS:x\r\nt=0 0\r\n",
        "v=1\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n",
    ] {
        assert!(
            SessionDescription::parse_with_options(bad, &options).is_err(),
            "{bad}"
        );
    }
    // Nor does it imply the other leniencies.
    assert!(SessionDescription::parse_with_options(&media("a=x\r\nb=AS:1\r\n"), &options).is_err());
    assert!(SessionDescription::parse_with_options(&media("\r\na=x\r\n"), &options).is_err());
}

#[test]
fn the_default_options_are_the_strict_ones() {
    assert_eq!(ParseOptions::default(), ParseOptions::strict());
    let lenient = ParseOptions::lenient();
    assert!(lenient.blank_lines && lenient.unordered_media_lines && lenient.loose_fields);
    let strict = ParseOptions::strict();
    assert!(!strict.blank_lines && !strict.unordered_media_lines && !strict.loose_fields);
}

// --- validate ---------------------------------------------------------------------------------

fn validate(session_lines: &str, media_lines: &str) -> Result<()> {
    strict(&format!(
        "{V}{O}{S}{T}{session_lines}m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\nc=IN IP4 0.0.0.0\r\n{media_lines}"
    ))?
    .validate()
}

#[test]
fn validate_requires_connection_data_for_every_media_description() {
    // RFC 8866 section 5.7: a c= line in each media description, or one at session level.
    let none = format!("{V}{O}{S}{T}{M}");
    assert!(matches!(
        strict(&none).unwrap().validate(),
        Err(Error::SdpInvalidSyntax(_))
    ));
    let media_level = format!("{V}{O}{S}{T}{M}c=IN IP4 0.0.0.0\r\n");
    assert!(strict(&media_level).unwrap().validate().is_ok());
    let session_level = format!("{V}{O}{S}c=IN IP4 0.0.0.0\r\n{T}{M}{M}");
    assert!(strict(&session_level).unwrap().validate().is_ok());
    let one_missing = format!("{V}{O}{S}{T}{M}c=IN IP4 0.0.0.0\r\n{M}");
    assert!(strict(&one_missing).unwrap().validate().is_err());
    // No media, nothing to connect.
    assert!(strict(&format!("{V}{O}{S}{T}")).unwrap().validate().is_ok());
}

#[test]
fn validate_checks_the_value_of_every_known_attribute() {
    assert!(validate("", "").is_ok());
    // One malformed value per attribute this crate has a type for.
    for (level, line) in [
        ("s", "a=group:BUNDLE  0\r\n"),
        ("s", "a=msid-semantic:\r\n"),
        ("s", "a=ice-pacing:x\r\n"),
        ("s", "a=identity:not base64\r\n"),
        ("s", "a=ice-lite:1\r\n"),
        ("s", "a=extmap-allow-mixed:1\r\n"),
        ("s", "a=sendrecv:1\r\n"),
        ("s", "a=fingerprint:sha-256 AB\r\n"),
        ("s", "a=setup:both\r\n"),
        ("s", "a=tls-id:short\r\n"),
        ("s", "a=ice-ufrag:abc\r\n"),
        ("s", "a=ice-pwd:short\r\n"),
        ("s", "a=ice-options:a,b\r\n"),
        ("s", "a=extmap:0 urn:example:a\r\n"),
        ("s", "a=rtcp-xr:rcvr-rtt\r\n"),
        ("s", "a=cryptex:1\r\n"),
        ("m", "a=mid:a b\r\n"),
        ("m", "a=msid:a b c\r\n"),
        ("m", "a=ssrc:x cname:y\r\n"),
        ("m", "a=ssrc-group:FID x\r\n"),
        ("m", "a=rid:1 both\r\n"),
        ("m", "a=simulcast:send\r\n"),
        ("m", "a=extmap:1\r\n"),
        ("m", "a=rtcp:x\r\n"),
        ("m", "a=rtcp-fb:96\r\n"),
        ("m", "a=rtpmap:96 VP8\r\n"),
        ("m", "a=fmtp:96\r\n"),
        ("m", "a=ptime:0\r\n"),
        ("m", "a=maxptime:x\r\n"),
        ("m", "a=framerate:30.0\r\n"),
        ("m", "a=imageattr:96 send\r\n"),
        ("m", "a=content:a b\r\n"),
        ("m", "a=candidate:1 1 UDP\r\n"),
        ("m", "a=remote-candidates:1\r\n"),
        ("m", "a=sctp-port:x\r\n"),
        ("m", "a=max-message-size:x\r\n"),
        ("m", "a=sctpmap:x\r\n"),
        ("m", "a=rtcp-mux:1\r\n"),
        ("m", "a=rtcp-mux-only:1\r\n"),
        ("m", "a=rtcp-rsize:1\r\n"),
        ("m", "a=end-of-candidates:1\r\n"),
        ("m", "a=bundle-only:1\r\n"),
        ("m", "a=mid\r\n"),
        ("m", "a=rtpmap\r\n"),
    ] {
        let result = if level == "s" {
            validate(line, "")
        } else {
            validate("", line)
        };
        assert!(result.is_err(), "{line:?} should not validate");
    }
}

#[test]
fn validate_checks_the_level_an_attribute_is_defined_for() {
    // Session-level attributes in a media description.
    for line in [
        "a=group:BUNDLE 0\r\n",
        "a=ice-lite\r\n",
        "a=identity:QUJD\r\n",
        "a=ice-pacing:50\r\n",
    ] {
        assert!(validate(line, "").is_ok(), "{line}");
        assert!(
            matches!(validate("", line), Err(Error::SdpInvalidValue(_))),
            "{line}"
        );
    }
    // Media-level attributes at the session level.
    for line in [
        "a=mid:0\r\n",
        "a=rtcp-mux\r\n",
        "a=rtcp-mux-only\r\n",
        "a=rtcp-rsize\r\n",
        "a=rtpmap:96 VP8/90000\r\n",
        "a=fmtp:96 x=1\r\n",
        "a=rtcp-fb:96 nack\r\n",
        "a=candidate:1 1 UDP 1 192.0.2.1 9 typ host\r\n",
        "a=msid:s t\r\n",
        "a=ssrc:1 cname:x\r\n",
        "a=ssrc-group:FID 1 2\r\n",
        "a=sctp-port:5000\r\n",
        "a=max-message-size:1\r\n",
        "a=bundle-only\r\n",
        "a=ptime:20\r\n",
    ] {
        assert!(validate("", line).is_ok(), "{line}");
        assert!(
            matches!(validate(line, ""), Err(Error::SdpInvalidValue(_))),
            "{line}"
        );
    }
    // Attributes defined for both levels, and the two JSEP reads at both.
    for line in [
        "a=sendrecv\r\n",
        "a=fingerprint:sha-1 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB\r\n",
        "a=setup:actpass\r\n",
        "a=ice-ufrag:abcd\r\n",
        "a=ice-pwd:abcdefghijklmnopqrstuv\r\n",
        "a=ice-options:trickle\r\n",
        "a=tls-id:abc3de65cddef001be82\r\n",
        "a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid\r\n",
        "a=extmap-allow-mixed\r\n",
        "a=cryptex\r\n",
        "a=rtcp-xr:voip-metrics\r\n",
        "a=end-of-candidates\r\n",
    ] {
        assert!(validate(line, "").is_ok(), "{line}");
        assert!(validate("", line).is_ok(), "{line}");
    }
    // A source attribute is not an attribute of either level.
    assert!(validate("a=cname:x\r\n", "").is_err());
    assert!(validate("", "a=previous-ssrc:1\r\n").is_err());
}

#[test]
fn validate_refuses_attributes_that_a_level_holds_once() {
    // RFC 8866 section 6.7: at most one direction attribute at each level.
    assert!(validate("a=sendrecv\r\n", "a=recvonly\r\n").is_ok());
    assert!(validate("a=sendrecv\r\na=inactive\r\n", "").is_err());
    assert!(validate("", "a=sendonly\r\na=sendonly\r\n").is_err());
    for line in [
        "a=mid:0\r\n",
        "a=setup:active\r\n",
        "a=ice-ufrag:abcd\r\n",
        "a=ice-pwd:abcdefghijklmnopqrstuv\r\n",
        "a=ice-options:trickle\r\n",
        "a=tls-id:abc3de65cddef001be82\r\n",
        "a=sctp-port:5000\r\n",
        "a=max-message-size:1\r\n",
        "a=rtcp:9\r\n",
        "a=ptime:20\r\n",
        "a=maxptime:20\r\n",
        "a=framerate:30\r\n",
    ] {
        assert!(validate("", line).is_ok(), "{line}");
        assert!(
            validate("", &format!("{line}{line}")).is_err(),
            "{line} twice"
        );
    }
    // Attributes that repeat by design.
    for line in [
        "a=msid:s t\r\n",
        "a=ssrc:1 cname:x\r\n",
        "a=rtcp-fb:96 nack\r\n",
        "a=fingerprint:sha-1 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB\r\n",
        "a=candidate:1 1 UDP 1 192.0.2.1 9 typ host\r\n",
        "a=x-unknown:1\r\n",
    ] {
        assert!(
            validate("", &format!("{line}{line}")).is_ok(),
            "{line} twice"
        );
    }
}

#[test]
fn validate_checks_mid_rid_and_simulcast_consistency() {
    // RFC 5888 section 4: the identification-tag is unique in the description.
    let two = |a: &str, b: &str| {
        strict(&format!(
            "{V}{O}{S}c=IN IP4 0.0.0.0\r\n{T}{M}a=mid:{a}\r\n{M}a=mid:{b}\r\n"
        ))
        .unwrap()
        .validate()
    };
    assert!(two("0", "1").is_ok());
    assert!(two("0", "0").is_err());

    // RFC 8851 section 4: a rid-id is unique in its media section; RFC 8853 section 5.2:
    // a=simulcast names a=rid lines.
    assert!(
        validate(
            "",
            "a=rid:h send\r\na=rid:l send\r\na=simulcast:send h;l\r\n"
        )
        .is_ok()
    );
    assert!(validate("", "a=rid:h send\r\na=rid:h send\r\n").is_err());
    assert!(validate("", "a=rid:h send\r\na=simulcast:send h;l\r\n").is_err());
    assert!(validate("", "a=simulcast:send h\r\n").is_err());
    assert!(
        validate(
            "",
            "a=rid:h send\r\na=simulcast:send h\r\na=simulcast:send h\r\n"
        )
        .is_err()
    );
}

#[test]
fn validate_requires_payload_types_as_the_formats_of_an_rtp_section() {
    let section = |m: &str| {
        strict(&format!("{V}{O}{S}{T}{m}c=IN IP4 0.0.0.0\r\n"))
            .unwrap()
            .validate()
    };
    assert!(section("m=audio 9 UDP/TLS/RTP/SAVPF 0 8 111 127\r\n").is_ok());
    assert!(section("m=audio 9 RTP/AVP 0\r\n").is_ok());
    assert!(section("m=audio 9 UDP/TLS/RTP/SAVPF 128\r\n").is_err());
    assert!(section("m=audio 9 UDP/TLS/RTP/SAVPF opus\r\n").is_err());
    assert!(section("m=audio 9 UDP/TLS/RTP/SAVPF *\r\n").is_err());
    // Other protos have formats of their own.
    assert!(section("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n").is_ok());
    assert!(section("m=image 9 udptl t38\r\n").is_ok());
}

// --- what the crate itself writes ---------------------------------------------------------------

#[test]
fn the_jsep_templates_write_the_lines_rfc_9429_section_5_2_1_gives() {
    let session = SessionDescription::new_jsep_session_description(false);
    let text = session.marshal();
    let lines: Vec<&str> = text.split("\r\n").collect();
    // v=0; o=- <sess-id> <sess-version> IN IP4 0.0.0.0; s=-; t=0 0; and none of
    // i= u= e= p= c= b= r= z= k=.
    assert_eq!(lines[0], "v=0");
    let origin: Vec<&str> = lines[1].strip_prefix("o=").unwrap().split(' ').collect();
    assert_eq!(origin[0], "-");
    assert!(origin[1].parse::<u64>().unwrap() < 1 << 63);
    assert!(origin[2].parse::<i64>().is_ok());
    assert_eq!(origin[3..], ["IN", "IP4", "0.0.0.0"]);
    assert_eq!(lines[2..], ["s=-", "t=0 0", ""]);

    // A media section: port 9, UDP/TLS/RTP/SAVPF, and c=IN IP4 0.0.0.0 right after m=.
    let media = MediaDescription::new_jsep_media_description("audio".to_owned(), vec![])
        .with_codec(
            111,
            "opus".to_owned(),
            48000,
            2,
            "minptime=10;useinbandfec=1".to_owned(),
        )
        .with_codec(0, "PCMU".to_owned(), 8000, 0, String::new());
    let text = session.with_media(media).marshal();
    assert!(
        text.ends_with(
            "t=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111 0\r\nc=IN IP4 0.0.0.0\r\na=rtpmap:111 opus/48000/2\r\na=fmtp:111 minptime=10;useinbandfec=1\r\na=rtpmap:0 PCMU/8000\r\n"
        ),
        "{text}"
    );
    // What the templates write is valid SDP.
    let parsed = strict(&text).unwrap();
    assert!(parsed.validate().is_ok());
    assert_eq!(parsed.marshal(), text);
}

#[test]
fn a_description_is_written_in_the_order_of_the_grammar_whatever_was_set() {
    // Every optional part set: the lines come out as v o s i u e p c b t r z a, m i c b a.
    let mut session = SessionDescription::new_jsep_session_description(false);
    session.origin.session_id = 1;
    session.origin.session_version = 2;
    session
        .attributes
        .push(Attribute::new("x".to_owned(), None));
    session.bandwidth.push(Bandwidth::parse("AS:1").unwrap());
    session.connection_information = ConnectionInformation::parse("IN IP4 192.0.2.1").ok();
    session.phone_numbers.push("+1 555".to_owned());
    session.email_addresses.push("a@example.com".to_owned());
    session.uri = url::Url::parse("http://example.com/").ok();
    session.session_information = Some("info".to_owned());
    session.time_descriptions[0].time_zones.push(TimeZone {
        adjustment_time: 3724394400,
        offset: -3600,
    });
    session.time_descriptions[0].repeat_times.push(RepeatTime {
        interval: 604800,
        duration: 3600,
        offsets: vec![0],
    });
    // RFC 8866 section 5.12: a key is never written.
    session.encryption_key = Some("prompt".to_owned());

    let mut media = MediaDescription::new_jsep_media_description("audio".to_owned(), vec![]);
    media.media_name.formats.push("0".to_owned());
    media.attributes.push(Attribute::new("y".to_owned(), None));
    media.bandwidth.push(Bandwidth::parse("TIAS:2").unwrap());
    media.media_title = Some("title".to_owned());
    media.encryption_key = Some("prompt".to_owned());

    let text = session.with_media(media).marshal();
    assert_eq!(
        text,
        "v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\ns=-\r\ni=info\r\nu=http://example.com/\r\ne=a@example.com\r\np=+1 555\r\nc=IN IP4 192.0.2.1\r\nb=AS:1\r\nt=0 0\r\nr=604800 3600 0\r\nz=3724394400 -3600\r\na=x\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\ni=title\r\nc=IN IP4 0.0.0.0\r\nb=TIAS:2\r\na=y\r\n"
    );
    assert_eq!(strict(&text).unwrap().marshal(), text);
}

#[test]
fn encoding_names_are_matched_without_regard_to_case() {
    // RFC 8866 section 6.6: the encoding name is a media subtype, compared case-insensitively.
    let sdp = strict(&format!(
        "{V}{O}{S}{T}m=video 9 RTP/AVP 96 97\r\na=rtpmap:96 vp8/90000\r\na=rtpmap:97 H264/90000\r\n"
    ))
    .unwrap();
    let wanted = |name: &str| crate::util::Codec {
        name: name.to_owned(),
        clock_rate: 90000,
        ..Default::default()
    };
    assert_eq!(sdp.get_payload_type_for_codec(&wanted("VP8")).unwrap(), 96);
    assert_eq!(sdp.get_payload_type_for_codec(&wanted("h264")).unwrap(), 97);
    assert!(sdp.get_payload_type_for_codec(&wanted("VP9")).is_err());
    assert_eq!(sdp.get_codec_for_payload_type(96).unwrap().name, "vp8");
    assert!(sdp.get_codec_for_payload_type(98).is_err());
}

/// W3C webrtc-pc section 11.1 (`sdpLineNumber`): a parse error says which line it is on,
/// from 1, blank lines counted; an error about the whole description says none.
#[test]
fn a_parse_error_names_the_line_it_is_on() {
    let located = |sdp: &str| {
        SessionDescription::parse_located(sdp, &ParseOptions::strict())
            .err()
            .map(|err| err.line_number)
    };
    // A line the grammar has no type for: line 4.
    assert_eq!(located(&format!("{V}{O}{S}x\r\n{T}")), Some(Some(4)));
    // A malformed value: the m= line, line 5.
    assert_eq!(
        located(&format!("{V}{O}{S}{T}m=audio nine RTP/AVP 0\r\n")),
        Some(Some(5))
    );
    // A line without `=`, after a blank line the lenient parse skips: line 6.
    assert_eq!(
        SessionDescription::parse_located(
            &format!("{V}{O}{S}{T}\r\nbogus\r\n"),
            &ParseOptions::lenient()
        )
        .err()
        .map(|err| err.line_number),
        Some(Some(6))
    );
    // The description ends before its t= line: about the whole description.
    assert_eq!(located(&format!("{V}{O}{S}")), Some(None));
    assert_eq!(located(&format!("{V}{O}{S}{T}")), None);
}
