//! The scalability modes of W3C webrtc-svc, section 5.

use super::*;

/// The specification's table: Scalability Mode Identifier, Spatial Layers, Resolution Ratio,
/// Temporal Layers, Inter-layer dependency.
const TABLE: [(&str, u8, &str, u8, &str); 36] = [
    ("L1T1", 1, "", 1, ""),
    ("L1T2", 1, "", 2, ""),
    ("L1T3", 1, "", 3, ""),
    ("L2T1", 2, "2:1", 1, "Yes"),
    ("L2T2", 2, "2:1", 2, "Yes"),
    ("L2T3", 2, "2:1", 3, "Yes"),
    ("L3T1", 3, "2:1", 1, "Yes"),
    ("L3T2", 3, "2:1", 2, "Yes"),
    ("L3T3", 3, "2:1", 3, "Yes"),
    ("L2T1h", 2, "1.5:1", 1, "Yes"),
    ("L2T2h", 2, "1.5:1", 2, "Yes"),
    ("L2T3h", 2, "1.5:1", 3, "Yes"),
    ("L3T1h", 3, "1.5:1", 1, "Yes"),
    ("L3T2h", 3, "1.5:1", 2, "Yes"),
    ("L3T3h", 3, "1.5:1", 3, "Yes"),
    ("S2T1", 2, "2:1", 1, "No"),
    ("S2T2", 2, "2:1", 2, "No"),
    ("S2T3", 2, "2:1", 3, "No"),
    ("S2T1h", 2, "1.5:1", 1, "No"),
    ("S2T2h", 2, "1.5:1", 2, "No"),
    ("S2T3h", 2, "1.5:1", 3, "No"),
    ("S3T1", 3, "2:1", 1, "No"),
    ("S3T2", 3, "2:1", 2, "No"),
    ("S3T3", 3, "2:1", 3, "No"),
    ("S3T1h", 3, "1.5:1", 1, "No"),
    ("S3T2h", 3, "1.5:1", 2, "No"),
    ("S3T3h", 3, "1.5:1", 3, "No"),
    ("L2T2_KEY", 2, "2:1", 2, "Yes"),
    ("L2T2_KEY_SHIFT", 2, "2:1", 2, "Yes"),
    ("L2T3_KEY", 2, "2:1", 3, "Yes"),
    ("L2T3_KEY_SHIFT", 2, "2:1", 3, "Yes"),
    ("L3T1_KEY", 3, "2:1", 1, "Yes"),
    ("L3T2_KEY", 3, "2:1", 2, "Yes"),
    ("L3T2_KEY_SHIFT", 3, "2:1", 2, "Yes"),
    ("L3T3_KEY", 3, "2:1", 3, "Yes"),
    ("L3T3_KEY_SHIFT", 3, "2:1", 3, "Yes"),
];

/// Section 5: every identifier of the table is a mode with the table's spatial layers,
/// resolution ratio, temporal layers and inter-layer dependency, and reads back as written.
#[test]
fn every_mode_of_the_table_has_the_tables_properties() {
    assert_eq!(ScalabilityMode::ALL.len(), TABLE.len());
    for (i, (name, spatial, ratio, temporal, dependency)) in TABLE.into_iter().enumerate() {
        let mode: ScalabilityMode = name.parse().unwrap_or_else(|_| panic!("{name}"));
        assert_eq!(mode, ScalabilityMode::ALL[i], "{name}: the table's order");
        assert_eq!(mode.to_string(), name);
        assert_eq!(mode.as_str(), name);
        assert_eq!(mode.spatial_layers(), spatial, "{name}");
        assert_eq!(mode.temporal_layers(), temporal, "{name}");
        let expected_ratio = match ratio {
            "2:1" => Some(ResolutionRatio::TwoToOne),
            "1.5:1" => Some(ResolutionRatio::OneAndAHalfToOne),
            _ => None,
        };
        assert_eq!(mode.resolution_ratio(), expected_ratio, "{name}");
        // "Yes": the spatial layers depend on each other, always or at a key frame; "No":
        // simulcast; blank: one spatial layer.
        let prediction = mode.inter_layer_prediction();
        match dependency {
            "Yes" => assert_ne!(prediction, InterLayerPrediction::None, "{name}"),
            "No" => assert_eq!(prediction, InterLayerPrediction::None, "{name}"),
            _ => assert_eq!(spatial, 1, "{name}"),
        }
        assert_eq!(mode.is_simulcast(), name.starts_with('S'), "{name}");
        assert_eq!(
            prediction == InterLayerPrediction::KeyPicture,
            name.contains("_KEY"),
            "{name}"
        );
        assert_eq!(
            mode.has_temporal_shift(),
            name.ends_with("_SHIFT"),
            "{name}"
        );
        assert_eq!(mode.is_single_layer(), name == "L1T1", "{name}");
    }
}

/// Section 3.1 and 5: the identifiers are case sensitive, and nothing outside the table is a
/// mode.
#[test]
fn only_the_tables_identifiers_are_modes() {
    for not_a_mode in [
        "",
        "l1t1",
        "L1t1",
        "L1T1 ",
        " L1T1",
        "L1T1H",
        "L2T1H",
        "l2t2_key",
        "L2T2_Key",
        "L2T2_KEY_shift",
        "L1T4",
        "L4T1",
        "L0T1",
        "S1T1",
        "S4T1",
        "L1T1h",
        "L2T1_KEY",
        "L3T1_KEY_SHIFT",
        "S2T2_KEY",
        "L2T2h_KEY",
        "L2T2_KEYh",
        "L2",
        "T3",
        "L3T3_KEY_SHIFT_",
    ] {
        assert!(
            not_a_mode.parse::<ScalabilityMode>().is_err(),
            "{not_a_mode:?}"
        );
    }
}

/// Section 5: "the AV1 and VP9 specifications support all the scalabilityMode values defined
/// in the table"; "VP8, H.264 and H.265 only support temporal scalability" and no "S" modes.
#[test]
fn codecs_support_the_modes_the_specification_says() {
    for mode in ScalabilityMode::ALL {
        for all in ["video/AV1", "video/VP9", "video/vp9", "VIDEO/av1"] {
            assert!(mode.supported_by(all), "{mode} with {all}");
        }
        let temporal_only = mode.spatial_layers() == 1;
        for codec in ["video/VP8", "video/H264", "video/H265", "video/vp8"] {
            assert_eq!(
                mode.supported_by(codec),
                temporal_only,
                "{mode} with {codec}"
            );
        }
        // Not a video codec with layers: only "no scalability", and for video only.
        assert_eq!(mode.supported_by("video/rtx"), mode.is_single_layer());
        assert!(!mode.supported_by("audio/opus"), "{mode} with audio");
    }
    let names = |mime: &str| {
        ScalabilityMode::supported_modes(mime)
            .into_iter()
            .map(|m| m.as_str())
            .collect::<Vec<_>>()
    };
    assert_eq!(names("video/VP8"), ["L1T1", "L1T2", "L1T3"]);
    assert_eq!(names("video/H264"), ["L1T1", "L1T2", "L1T3"]);
    assert_eq!(names("video/AV1").len(), 36);
    assert_eq!(names("video/VP9").len(), 36);
    assert!(names("audio/opus").is_empty());
}

/// Section 5: "LxTy ... x spatial layers using a 2:1 resolution ratio", "LxTyh ... a 1.5:1
/// resolution ratio": the resolution of each layer from the top layer's.
#[test]
fn layer_resolutions_follow_the_ratio() {
    let resolutions = |mode: ScalabilityMode| {
        (0..mode.spatial_layers())
            .map(|s| mode.layer_resolution(s, 1280, 720))
            .collect::<Vec<_>>()
    };
    assert_eq!(resolutions(ScalabilityMode::L1T3), [(1280, 720)]);
    assert_eq!(
        resolutions(ScalabilityMode::L2T1),
        [(640, 360), (1280, 720)]
    );
    assert_eq!(
        resolutions(ScalabilityMode::L3T3_KEY),
        [(320, 180), (640, 360), (1280, 720)]
    );
    assert_eq!(
        resolutions(ScalabilityMode::S3T1),
        [(320, 180), (640, 360), (1280, 720)]
    );
    assert_eq!(
        resolutions(ScalabilityMode::L2T2h),
        [(853, 480), (1280, 720)]
    );
    assert_eq!(
        resolutions(ScalabilityMode::S3T3h),
        [(568, 320), (853, 480), (1280, 720)]
    );
    // Never smaller than one pixel.
    assert_eq!(ScalabilityMode::L3T1.layer_resolution(0, 2, 2), (1, 1));
}
