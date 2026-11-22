use super::*;

fn av1(line: &str) -> Box<dyn Fmtp> {
    parse("video/AV1", line)
}

/// AV1 RTP section 7.2: absent parameters are inferred (`profile` 0, `level-idx` 5, `tier`
/// 0), and only the profile makes two formats different (section 7.2.3).
#[test]
fn an_av1_format_is_its_profile_with_the_absent_parameters_inferred() {
    let none = av1("");
    let fmtp = none
        .as_any()
        .downcast_ref::<Av1Fmtp>()
        .expect("an AV1 fmtp");
    assert_eq!(
        (Some(0), Some(5), Some(0)),
        (fmtp.profile(), fmtp.level_idx(), fmtp.tier())
    );

    assert!(none.match_fmtp(&*av1("profile=0")));
    assert!(!none.match_fmtp(&*av1("profile=1")));
    assert!(av1("profile=1;level-idx=8;tier=1").match_fmtp(&*av1("profile=1;level-idx=5")));
    assert!(!av1("profile=2").match_fmtp(&*av1("profile=1")));
    assert!(!av1("profile=x").match_fmtp(&*av1("profile=x")));
}
