//! RFC 9628 section 6: VP9's `profile-id`.

use super::super::parse;

fn matches(a: &str, b: &str) -> bool {
    let a = parse("video/VP9", a);
    let b = parse("video/VP9", b);
    a.match_fmtp(&*b) && b.match_fmtp(&*a)
}

/// RFC 9628 6: "If no profile-id is present, Profile 0 MUST be inferred." A VP9 format without
/// the parameter used to match every profile.
#[test]
fn an_absent_profile_id_is_profile_0() {
    assert!(matches("", "profile-id=0"));
    assert!(matches("", ""));
    assert!(!matches("", "profile-id=1"));
    assert!(!matches("", "profile-id=2"));
    assert!(!matches("max-fr=30", "profile-id=3"));
    assert!(matches("profile-id=2", "profile-id=2"));
    assert!(!matches("profile-id=0", "profile-id=2"));
}

/// RFC 9628 6.1.2: `max-fr` and `max-fs` are receiver capabilities, stated independently by
/// each side; different values are not a mismatch.
#[test]
fn max_fr_and_max_fs_are_declarative() {
    assert!(matches(
        "profile-id=0;max-fr=30;max-fs=3600",
        "max-fr=60;max-fs=8160"
    ));
    assert!(!matches("profile-id=1;max-fr=30", "profile-id=0;max-fr=30"));
}

/// The parameters stay readable, and a VP9 format is never the same as another codec's.
#[test]
fn parameters_are_kept_and_other_codecs_do_not_match() {
    let vp9 = parse("video/VP9", "profile-id=2;max-fs=3600");
    assert_eq!(vp9.mime_type(), "video/vp9");
    assert_eq!(vp9.parameter("max-fs").map(String::as_str), Some("3600"));
    assert!(!vp9.match_fmtp(&*parse("video/VP8", "")));
    assert!(!parse("video/VP8", "").match_fmtp(&*vp9));
    // An empty fmtp line parses to one empty key; it is still profile 0.
    assert!(parse("video/vp9", " ").match_fmtp(&*parse("VIDEO/VP9", "profile-id=00")));
}
