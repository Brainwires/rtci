use super::*;

#[test]
fn test_h264_fmtp_parse() {
    let tests: Vec<(&str, &str, Box<dyn Fmtp>)> = vec![
        (
            "OneParam",
            "key-name=value",
            Box::new(H264Fmtp {
                parameters: [("key-name".to_owned(), "value".to_owned())]
                    .iter()
                    .cloned()
                    .collect(),
            }),
        ),
        (
            "OneParamWithWhiteSpeces",
            "\tkey-name=value ",
            Box::new(H264Fmtp {
                parameters: [("key-name".to_owned(), "value".to_owned())]
                    .iter()
                    .cloned()
                    .collect(),
            }),
        ),
        (
            "TwoParams",
            "key-name=value;key2=value2",
            Box::new(H264Fmtp {
                parameters: [
                    ("key-name".to_owned(), "value".to_owned()),
                    ("key2".to_owned(), "value2".to_owned()),
                ]
                .iter()
                .cloned()
                .collect(),
            }),
        ),
        (
            "TwoParamsWithWhiteSpeces",
            "key-name=value;  \n\tkey2=value2 ",
            Box::new(H264Fmtp {
                parameters: [
                    ("key-name".to_owned(), "value".to_owned()),
                    ("key2".to_owned(), "value2".to_owned()),
                ]
                .iter()
                .cloned()
                .collect(),
            }),
        ),
    ];

    for (name, input, expected) in tests {
        let f = parse("video/h264", input);
        assert_eq!(&f, &expected, "{name} failed");

        assert_eq!(f.mime_type(), "video/h264");
    }
}

#[test]
fn test_h264_fmtp_compare() {
    let consist_string: HashMap<bool, String> = [
        (true, "consist".to_owned()),
        (false, "inconsist".to_owned()),
    ]
    .iter()
    .cloned()
    .collect();

    let tests = vec![
        (
            "Equal",
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
            true,
        ),
        (
            "EqualWithWhitespaceVariants",
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
            "  level-asymmetry-allowed=1;  \npacketization-mode=1;\t\nprofile-level-id=42e01f",
            true,
        ),
        (
            "EqualWithCase",
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
            "level-asymmetry-allowed=1;packetization-mode=1;PROFILE-LEVEL-ID=42e01f",
            true,
        ),
        (
            "OneHasExtraParam",
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
            "packetization-mode=1;profile-level-id=42e01f",
            true,
        ),
        (
            "DifferentProfileLevelIDVersions",
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
            "packetization-mode=1;profile-level-id=42e029",
            true,
        ),
        (
            "Inconsistent",
            "packetization-mode=1;profile-level-id=42e029",
            "packetization-mode=0;profile-level-id=42e029",
            false,
        ),
        (
            "Inconsistent_MissingPacketizationMode",
            "packetization-mode=1;profile-level-id=42e029",
            "profile-level-id=42e029",
            false,
        ),
        (
            "Inconsistent_MissingProfileLevelID",
            "packetization-mode=1;profile-level-id=42e029",
            "packetization-mode=1",
            false,
        ),
        (
            "Inconsistent_InvalidProfileLevelID",
            "packetization-mode=1;profile-level-id=42e029",
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=41e029",
            false,
        ),
    ];

    for (name, a, b, consist) in tests {
        let check = |a, b| {
            let aa = parse("video/h264", a);
            let bb = parse("video/h264", b);

            // test forward case here
            let c = aa.match_fmtp(&*bb);
            assert_eq!(
                c,
                consist,
                "{}: '{}' and '{}' are expected to be {:?}, but treated as {:?}",
                name,
                a,
                b,
                consist_string.get(&consist),
                consist_string.get(&c),
            );

            // test reverse case here
            let c = bb.match_fmtp(&*aa);
            assert_eq!(
                c,
                consist,
                "{}: '{}' and '{}' are expected to be {:?}, but treated as {:?}",
                name,
                a,
                b,
                consist_string.get(&consist),
                consist_string.get(&c),
            );
        };

        check(a, b);
    }
}

/// RFC 6184 section 8.1: an absent `packetization-mode` is 0 (single NAL unit mode), and an
/// absent `profile-level-id` is the Baseline profile "without additional constraints at
/// Level 1" (`42000a`). A format that leaves them out is that format.
#[test]
fn absent_h264_parameters_take_their_rfc_6184_defaults() {
    let h264 = |line: &str| parse("video/h264", line);
    assert!(h264("").match_fmtp(&*h264("packetization-mode=0;profile-level-id=42000a")));
    assert!(
        h264("profile-level-id=42001f")
            .match_fmtp(&*h264("packetization-mode=0;profile-level-id=42001f"))
    );
    assert!(
        h264("packetization-mode=1")
            .match_fmtp(&*h264("packetization-mode=1;profile-level-id=420029"))
    );
    assert!(!h264("").match_fmtp(&*h264("packetization-mode=1")));
    assert!(
        !h264("").match_fmtp(&*h264("profile-level-id=42e01f")),
        "Constrained Baseline is not Baseline"
    );
}

/// RFC 6184 section 8.1, Table 5: the `profile_idc` / `profile-iop` combinations that stand for
/// one profile are that profile, whatever the level (section 8.2.2).
#[test]
fn h264_profile_level_ids_of_one_table_5_profile_match() {
    let plid = |id: &str| {
        parse(
            "video/h264",
            &format!("packetization-mode=1;profile-level-id={id}"),
        )
    };
    for (a, b, same) in [
        // Constrained Baseline as Baseline, Main and Extended.
        ("42e01f", "4d801f", true),
        ("42e01f", "58c01f", true),
        ("424015", "4dc028", true),
        // Baseline as Baseline and Extended; not Constrained Baseline.
        ("42001f", "588029", true),
        ("42001f", "42e01f", false),
        // Main is not Constrained Baseline, nor High.
        ("4d001f", "4d801f", false),
        ("4d001f", "64001f", false),
        // High at two levels; High is not High 10 Intra.
        ("640032", "64001f", true),
        ("6e0032", "6e1032", false),
        // Combinations Table 5 does not list compare as their two bytes.
        ("640c1f", "640c34", true),
        ("640c1f", "64001f", false),
    ] {
        assert_eq!(same, plid(a).match_fmtp(&*plid(b)), "{a} and {b}");
    }
}
