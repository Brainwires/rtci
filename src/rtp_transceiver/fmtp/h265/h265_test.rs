use super::*;

fn h265(line: &str) -> Box<dyn Fmtp> {
    parse("video/H265", line)
}

/// RFC 7798 section 7.1: absent parameters take their defaults (`profile-space` 0,
/// `profile-id` 1, `tier-flag` 0, `interop-constraints` progressive / non-packed /
/// frame-only, the compatibility bit of `profile-id`, `tx-mode` SRST), and section 7.2.2:
/// every configuration parameter but `level-id` is symmetric.
#[test]
fn h265_formats_match_by_their_configuration_with_the_section_7_1_defaults() {
    let none = h265("");
    assert!(none.match_fmtp(&*h265(
        "profile-space=0;profile-id=1;tier-flag=0;tx-mode=SRST"
    )));
    assert!(none.match_fmtp(&*h265(
        "interop-constraints=B00000000000;profile-compatibility-indicator=40000000"
    )));
    // level-id is not part of the configuration.
    assert!(h265("level-id=93").match_fmtp(&*h265("level-id=180")));
    // The sprop parameters describe a stream, not the format.
    assert!(none.match_fmtp(&*h265("sprop-vps=QAEMAf//;sprop-max-don-diff=2")));

    assert!(
        !none.match_fmtp(&*h265("profile-id=2")),
        "Main 10 is another format"
    );
    assert!(!none.match_fmtp(&*h265("tier-flag=1")));
    assert!(!none.match_fmtp(&*h265("profile-space=1")));
    assert!(!none.match_fmtp(&*h265("interop-constraints=000000000000")));
    assert!(!none.match_fmtp(&*h265("profile-compatibility-indicator=60000000")));
    assert!(
        !none.match_fmtp(&*h265("tx-mode=MRST")),
        "only SRST by default"
    );
    assert!(h265("tx-mode=mrst").match_fmtp(&*h265("tx-mode=MRST")));
    assert!(
        !h265("tx-mode=XYZ").match_fmtp(&*h265("tx-mode=XYZ")),
        "not a mode"
    );
}

/// RFC 7798 section 7.1: `level-id` 93 (level 3.1) when absent.
#[test]
fn an_absent_h265_level_id_is_93() {
    let fmtp = h265("");
    let fmtp = fmtp.as_any().downcast_ref::<H265Fmtp>().expect("H.265");
    assert_eq!(Some(93), fmtp.level_id());
    assert_eq!(Some("SRST"), fmtp.tx_mode());
}
