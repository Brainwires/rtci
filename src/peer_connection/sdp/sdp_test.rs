//! Ported from the async `webrtc` crate's `sdp_test.rs` to the sans-IO internals.
//!
//! The old tests built transceivers through `APIBuilder`, `DtlsTransport` and
//! `TrackLocalStaticSample` and awaited `populate_sdp`; here a transceiver is a plain
//! [`RTCRtpTransceiverInternal`] and `populate_sdp` is a synchronous associated function of
//! [`RTCPeerConnection`] that takes the transceivers it describes. Each test keeps the behaviour
//! its predecessor asserted; where the current API changed shape the test says how.

use sdp::description::common::Attribute;

use super::*;
use crate::media_stream::MediaStreamTrack;
use crate::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_RTX, MIME_TYPE_VP8,
};
use crate::rtp_transceiver::RTCRtpTransceiverInit;
use crate::rtp_transceiver::rtp_sender::{
    RTCRtpCodingParameters, RTCRtpEncodingParameters, RTCRtpRtxParameters,
};

fn attr(key: &str, value: Option<&str>) -> Attribute {
    Attribute {
        key: key.to_owned(),
        value: value.map(str::to_owned),
    }
}

fn vp8() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: "".to_owned(),
        rtcp_feedback: vec![],
    }
}

fn default_media_engine() -> MediaEngine {
    let mut me = MediaEngine::default();
    me.register_default_codecs().expect("default codecs");
    me
}

fn recvonly_transceiver(kind: RtpCodecKind) -> RTCRtpTransceiverInternal {
    RTCRtpTransceiverInternal::new(
        kind,
        None,
        RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            streams: vec![],
            send_encodings: vec![],
        },
    )
}

fn sendonly_transceiver(
    kind: RtpCodecKind,
    encodings: Vec<RTCRtpEncodingParameters>,
) -> RTCRtpTransceiverInternal {
    let track = MediaStreamTrack::new(
        "webrtc-rs".to_owned(),
        "video".to_owned(),
        "video".to_owned(),
        kind,
        encodings.clone(),
    );
    RTCRtpTransceiverInternal::new(
        kind,
        Some(track),
        RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendonly,
            streams: vec![],
            send_encodings: encodings,
        },
    )
}

fn params(
    media_description_fingerprint: bool,
    match_bundle_group: Option<String>,
) -> PopulateSdpParams {
    PopulateSdpParams {
        media_description_fingerprint,
        is_ice_lite: false,
        is_extmap_allow_mixed: true,
        // DEFAULT_DTLS_ROLE_OFFER in the old crate: an offer is `actpass`.
        connection_role: ConnectionRole::Actpass,
        ice_gathering_state: RTCIceGatheringState::Complete,
        bundle: match match_bundle_group {
            None => BundleMode::Offer,
            Some(group) => {
                BundleMode::Answer(Some(group.split_whitespace().map(str::to_owned).collect()))
            }
        },
        offered_tag_rtcp_mux_only: false,
        rtcp_mux_only: true,
        sctp_max_message_size: 0,
        ignore_rid_pause_for_recv: false,
        write_ssrc_attributes_for_simulcast: false,
    }
}

fn media_section(mid: &str, transceiver_index: usize) -> MediaSection {
    MediaSection {
        mid: mid.to_owned(),
        transceiver_index,
        ..Default::default()
    }
}

fn populate(
    me: &MediaEngine,
    transceivers: &mut [RTCRtpTransceiverInternal],
    media_sections: &[MediaSection],
    params: PopulateSdpParams,
    fingerprints: &[RTCDtlsFingerprint],
) -> Result<SessionDescription> {
    RTCPeerConnection::populate_sdp(
        SessionDescription::default(),
        fingerprints,
        me,
        transceivers,
        &[],
        &RTCIceParameters::default(),
        media_sections,
        params,
    )
}

#[test]
fn test_extract_fingerprint() -> Result<()> {
    //"Good Session Fingerprint"
    {
        let s = SessionDescription {
            attributes: vec![attr("fingerprint", Some("foo bar"))],
            ..Default::default()
        };

        let fingerprints = extract_fingerprints(&s)?;
        assert_eq!(fingerprints.len(), 1);
        assert_eq!(fingerprints[0].value, "bar");
        assert_eq!(fingerprints[0].algorithm, "foo");
    }

    //"Good Media Fingerprint"
    {
        let s = SessionDescription {
            media_descriptions: vec![MediaDescription {
                attributes: vec![attr("fingerprint", Some("foo bar"))],
                ..Default::default()
            }],
            ..Default::default()
        };

        let fingerprints = extract_fingerprints(&s)?;
        assert_eq!(fingerprints.len(), 1);
        assert_eq!(fingerprints[0].value, "bar");
        assert_eq!(fingerprints[0].algorithm, "foo");
    }

    //"No Fingerprint"
    {
        let s = SessionDescription::default();

        assert_eq!(
            extract_fingerprints(&s).expect_err("fingerprint absence must be detected"),
            Error::ErrSessionDescriptionNoFingerprint
        );
    }

    //"Invalid Fingerprint"
    {
        let s = SessionDescription {
            attributes: vec![attr("fingerprint", Some("foo"))],
            ..Default::default()
        };

        assert_eq!(
            extract_fingerprints(&s).expect_err("invalid fingerprint text must be detected"),
            Error::ErrSessionDescriptionInvalidFingerprint
        );
    }

    //"Conflicting Fingerprint"
    //
    // The old case paired an unparsable session fingerprint ("foo") with a valid media one; every
    // level is now parsed before the levels are compared, so that input is the "Invalid" case
    // above. Two well-formed fingerprints that disagree are what a conflict is.
    {
        let s = SessionDescription {
            attributes: vec![attr("fingerprint", Some("foo baz"))],
            media_descriptions: vec![MediaDescription {
                attributes: vec![attr("fingerprint", Some("foo bar"))],
                ..Default::default()
            }],
            ..Default::default()
        };

        assert_eq!(
            extract_fingerprints(&s).expect_err("mismatching fingerprint texts must be detected"),
            Error::ErrSessionDescriptionConflictingFingerprints
        );
    }

    Ok(())
}

#[test]
fn test_extract_ice_details() -> Result<()> {
    // The old constants ("DEFAULT_PWD" / "DEFAULT_UFRAG", swapped) are not valid ICE
    // credentials: `_` is not an ice-char and the password is shorter than 22 characters
    // (RFC 8839 §5.4), which `extract_ice_details` now checks.
    const DEFAULT_UFRAG: &str = "DEFAULTufrag";
    const DEFAULT_PWD: &str = "DEFAULTpasswordDEFAULTpassword";
    // A section with port 0 is rejected (RFC 8843 §6) and sets up no transport, so every
    // section here has a real port; the old tests left it at the default 0.
    let in_use = || MediaName {
        media: "audio".to_owned(),
        port: RangedPort {
            value: 9,
            range: None,
        },
        ..Default::default()
    };

    //"Missing ice-pwd"
    {
        let s = SessionDescription {
            media_descriptions: vec![MediaDescription {
                media_name: in_use(),
                attributes: vec![attr("ice-ufrag", Some(DEFAULT_UFRAG))],
                ..Default::default()
            }],
            ..Default::default()
        };

        assert_eq!(
            extract_ice_details(&s).expect_err("ICE requires password for authentication"),
            Error::ErrSessionDescriptionMissingIcePwd
        );
    }

    //"Missing ice-ufrag"
    {
        let s = SessionDescription {
            media_descriptions: vec![MediaDescription {
                media_name: in_use(),
                attributes: vec![attr("ice-pwd", Some(DEFAULT_PWD))],
                ..Default::default()
            }],
            ..Default::default()
        };

        assert_eq!(
            extract_ice_details(&s).expect_err("ICE requires 'user fragment' for authentication"),
            Error::ErrSessionDescriptionMissingIceUfrag
        );
    }

    //"ice details at session level"
    {
        let s = SessionDescription {
            attributes: vec![
                attr("ice-ufrag", Some(DEFAULT_UFRAG)),
                attr("ice-pwd", Some(DEFAULT_PWD)),
            ],
            media_descriptions: vec![],
            ..Default::default()
        };

        let details = extract_ice_details(&s)?.expect("session credentials set up a transport");
        assert_eq!(details.ufrag, DEFAULT_UFRAG);
        assert_eq!(details.pwd, DEFAULT_PWD);
    }

    //"ice details at media level"
    {
        let s = SessionDescription {
            media_descriptions: vec![MediaDescription {
                media_name: in_use(),
                attributes: vec![
                    attr("ice-ufrag", Some(DEFAULT_UFRAG)),
                    attr("ice-pwd", Some(DEFAULT_PWD)),
                ],
                ..Default::default()
            }],
            ..Default::default()
        };

        let details = extract_ice_details(&s)?.expect("media credentials set up a transport");
        assert_eq!(details.ufrag, DEFAULT_UFRAG);
        assert_eq!(details.pwd, DEFAULT_PWD);
    }

    //"Conflict ufrag"
    {
        let s = SessionDescription {
            attributes: vec![attr("ice-ufrag", Some("invalidUfrag"))],
            media_descriptions: vec![MediaDescription {
                media_name: in_use(),
                attributes: vec![
                    attr("ice-ufrag", Some(DEFAULT_UFRAG)),
                    attr("ice-pwd", Some(DEFAULT_PWD)),
                ],
                ..Default::default()
            }],
            ..Default::default()
        };

        assert_eq!(
            extract_ice_details(&s).expect_err("mismatching ICE ufrags must be detected"),
            Error::ErrSessionDescriptionConflictingIceUfrag
        );
    }

    //"Conflict pwd"
    {
        let s = SessionDescription {
            attributes: vec![attr("ice-pwd", Some("invalidPasswordInvalidPassword"))],
            media_descriptions: vec![MediaDescription {
                media_name: in_use(),
                attributes: vec![
                    attr("ice-ufrag", Some(DEFAULT_UFRAG)),
                    attr("ice-pwd", Some(DEFAULT_PWD)),
                ],
                ..Default::default()
            }],
            ..Default::default()
        };

        assert_eq!(
            extract_ice_details(&s).expect_err("mismatching ICE passwords must be detected"),
            Error::ErrSessionDescriptionConflictingIcePwd
        );
    }

    //"Allow Conflict ufrag from inactive MediaDescription"
    {
        let s = SessionDescription {
            media_descriptions: vec![
                MediaDescription {
                    media_name: in_use(),
                    attributes: vec![
                        attr("ice-ufrag", Some(DEFAULT_UFRAG)),
                        attr("ice-pwd", Some(DEFAULT_PWD)),
                    ],
                    ..Default::default()
                },
                MediaDescription {
                    media_name: in_use(),
                    attributes: vec![
                        attr("ice-ufrag", Some("invalidUfrag")),
                        attr("ice-pwd", Some(DEFAULT_PWD)),
                        attr(ATTR_KEY_INACTIVE, None),
                    ],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let details = extract_ice_details(&s)
            .expect("should allow conflicting ICE ufrag when MediaDescription is inactive")
            .expect("a transport");
        assert_eq!(details.ufrag, DEFAULT_UFRAG);
        assert_eq!(details.pwd, DEFAULT_PWD);
    }

    Ok(())
}

fn media(kind: &str, attributes: Vec<Attribute>) -> MediaDescription {
    MediaDescription {
        media_name: MediaName {
            media: kind.to_owned(),
            ..Default::default()
        },
        attributes,
        ..Default::default()
    }
}

#[test]
fn test_track_details_from_sdp() -> Result<()> {
    //"Tracks unknown, audio and video with RTX"
    {
        let s = SessionDescription {
            media_descriptions: vec![
                media(
                    "foobar",
                    vec![
                        attr("mid", Some("0")),
                        attr("sendrecv", None),
                        attr("ssrc", Some("1000 msid:unknown_trk_label unknown_trk_guid")),
                    ],
                ),
                media(
                    "audio",
                    vec![
                        attr("mid", Some("1")),
                        attr("sendrecv", None),
                        attr("ssrc", Some("2000 msid:audio_trk_label audio_trk_guid")),
                    ],
                ),
                media(
                    "video",
                    vec![
                        attr("mid", Some("2")),
                        attr("sendrecv", None),
                        attr("ssrc", Some("3000 msid:video_trk_label video_trk_guid")),
                        attr("ssrc", Some("4000 msid:rtx_trk_label rtx_trck_guid")),
                        attr("ssrc-group", Some("FID 3000 4000")),
                    ],
                ),
                media(
                    "video",
                    vec![
                        attr("mid", Some("3")),
                        attr("sendonly", None),
                        attr("msid", Some("video_stream_id video_trk_id")),
                        attr("ssrc", Some("5000")),
                    ],
                ),
                // No mid: not a section a track can be bound to, so it is skipped.
                media(
                    "video",
                    vec![
                        attr("sendonly", None),
                        attr(
                            SDP_ATTRIBUTE_RID,
                            Some("f send pt=97;max-width=1280;max-height=720"),
                        ),
                    ],
                ),
            ],
            ..Default::default()
        };

        let tracks = track_details_from_sdp(&s);
        assert_eq!(tracks.len(), 3);
        if track_details_for_ssrc(&tracks, 1000).is_some() {
            panic!("got the unknown track ssrc:1000 which should have been skipped");
        }
        if let Some(track) = track_details_for_ssrc(&tracks, 2000) {
            assert_eq!(track.kind, RtpCodecKind::Audio);
            assert_eq!(track.ssrc, Some(2000));
            assert_eq!(track.stream_id, "audio_trk_label");
        } else {
            panic!("missing audio track with ssrc:2000");
        }
        if let Some(track) = track_details_for_ssrc(&tracks, 3000) {
            assert_eq!(track.kind, RtpCodecKind::Video);
            assert_eq!(track.ssrc, Some(3000));
            assert_eq!(track.stream_id, "video_trk_label");
            assert_eq!(track.rtx_ssrc, Some(4000));
        } else {
            panic!("missing video track with ssrc:3000");
        }
        if track_details_for_ssrc(&tracks, 4000).is_some() {
            panic!("got the rtx track ssrc:4000 which should have been skipped");
        }
        if let Some(track) = track_details_for_ssrc(&tracks, 5000) {
            assert_eq!(track.kind, RtpCodecKind::Video);
            assert_eq!(track.ssrc, Some(5000));
            assert_eq!(track.track_id, "video_trk_id");
            assert_eq!(track.stream_id, "video_stream_id");
        } else {
            panic!("missing video track with ssrc:5000");
        }
    }

    // Inactive and recvonly sections carry no incoming track. The old function took an
    // `exclude_inactive` flag and could be asked to keep inactive sections; the current one
    // always skips both, which was the flag's `true` case.
    {
        let s = SessionDescription {
            media_descriptions: vec![
                media(
                    "video",
                    vec![
                        attr("mid", Some("1")),
                        attr("inactive", None),
                        attr("ssrc", Some("6000")),
                    ],
                ),
                media(
                    "video",
                    vec![
                        attr("mid", Some("1")),
                        attr("recvonly", None),
                        attr("ssrc", Some("7000")),
                    ],
                ),
            ],
            ..Default::default()
        };
        assert_eq!(
            track_details_from_sdp(&s).len(),
            0,
            "inactive and recvonly tracks should be ignored"
        );
    }

    Ok(())
}

#[test]
fn test_have_application_media_section() -> Result<()> {
    //"Audio only"
    {
        let s = SessionDescription {
            media_descriptions: vec![media(
                "audio",
                vec![attr("sendrecv", None), attr("ssrc", Some("2000"))],
            )],
            ..Default::default()
        };

        assert!(get_application_media(&s).is_none());
    }

    //"Application"
    //
    // The data channel section is now recognised by its format (`webrtc-datachannel`, RFC 8841),
    // not by the media name alone, and the SCTP port is read from that section.
    {
        let s = SessionDescription {
            media_descriptions: vec![MediaDescription {
                media_name: MediaName {
                    media: MEDIA_SECTION_APPLICATION.to_owned(),
                    formats: vec!["webrtc-datachannel".to_owned()],
                    ..Default::default()
                },
                attributes: vec![attr("sctp-port", Some("5000"))],
                ..Default::default()
            }],
            ..Default::default()
        };

        let application = get_application_media(&s).expect("the data channel section");
        assert_eq!(
            get_application_media_section_sctp_port(application),
            Some(5000)
        );
    }

    Ok(())
}

fn fingerprint_test(
    fingerprints: &[RTCDtlsFingerprint],
    me: &MediaEngine,
    transceivers: &mut [RTCRtpTransceiverInternal],
    media: &[MediaSection],
    sdpmedia_description_fingerprints: bool,
    expected_fingerprint_count: usize,
) -> Result<()> {
    let mut p = params(sdpmedia_description_fingerprints, None);
    p.ice_gathering_state = RTCIceGatheringState::New;
    p.connection_role = ConnectionRole::Active;
    p.is_extmap_allow_mixed = false;

    let s = populate(me, transceivers, media, p, fingerprints)?;

    let sdparray = s.marshal();

    assert_eq!(
        sdparray.matches("sha-256").count(),
        expected_fingerprint_count
    );

    Ok(())
}

#[test]
fn test_media_description_fingerprints() -> Result<()> {
    let me = default_media_engine();

    // The old test generated a certificate for its fingerprint; what is under test is where the
    // fingerprint lines go, so one fixed sha-256 fingerprint stands in for it.
    let fingerprints = vec![RTCDtlsFingerprint {
        algorithm: "sha-256".to_owned(),
        value: "AB:CD:EF".to_owned(),
    }];

    let encoding = |ssrc| RTCRtpEncodingParameters {
        rtp_coding_parameters: RTCRtpCodingParameters {
            ssrc: Some(ssrc),
            ..Default::default()
        },
        codec: vp8(),
        ..Default::default()
    };

    // Both media transceivers send video, as the old test replaced each sender with one sending
    // a VP8 track and made the transceiver sendonly.
    let mut transceivers = vec![
        sendonly_transceiver(RtpCodecKind::Video, vec![encoding(1000)]),
        sendonly_transceiver(RtpCodecKind::Video, vec![encoding(2000)]),
    ];

    let media = vec![
        media_section("video", 0),
        media_section("audio", 1),
        MediaSection {
            mid: "application".to_owned(),
            data: true,
            transceiver_index: usize::MAX,
            ..Default::default()
        },
    ];

    //"Per-Media Description Fingerprints",
    fingerprint_test(&fingerprints, &me, &mut transceivers, &media, true, 3)?;

    //"Per-Session Description Fingerprints",
    fingerprint_test(&fingerprints, &me, &mut transceivers, &media, false, 1)?;

    Ok(())
}

#[test]
fn test_populate_sdp() -> Result<()> {
    //"Rid"
    {
        let me = default_media_engine();
        let mut transceivers = vec![recvonly_transceiver(RtpCodecKind::Video)];

        let rid_map = vec![
            SimulcastRid {
                id: "ridkey".to_owned(),
                direction: SimulcastDirection::Recv,
                params: "some".to_owned(),
                paused: false,
            },
            SimulcastRid {
                id: "ridpaused".to_owned(),
                direction: SimulcastDirection::Recv,
                params: "some2".to_owned(),
                paused: true,
            },
        ];
        let media_sections = vec![MediaSection {
            rid_map,
            ..media_section("video", 0)
        }];

        let offer_sdp = populate(
            &me,
            &mut transceivers,
            &media_sections,
            params(false, None),
            &[],
        )?;

        // Test contains rid map keys
        let mut found = 0;
        for desc in &offer_sdp.media_descriptions {
            if desc.media_name.media != "video" {
                continue;
            }

            let rid_map = get_rids(desc);
            if let Some(rid) = rid_map.iter().find(|rid| rid.id == "ridkey") {
                assert!(!rid.paused, "Rid should be active");
                assert_eq!(
                    rid.direction,
                    SimulcastDirection::Send,
                    "Rid should be send"
                );
                found += 1;
            }
            if let Some(rid) = rid_map.iter().find(|rid| rid.id == "ridpaused") {
                assert!(rid.paused, "Rid should be paused");
                assert_eq!(
                    rid.direction,
                    SimulcastDirection::Send,
                    "Rid should be send"
                );
                found += 1;
            }
        }
        assert_eq!(found, 2, "All Rid key should be present");
    }

    //"SetCodecPreferences"
    {
        let me = default_media_engine();
        let mut transceivers = vec![recvonly_transceiver(RtpCodecKind::Video)];
        transceivers[0].set_codec_preferences(
            vec![RTCRtpCodecParameters {
                rtp_codec: vp8(),
                payload_type: 96,
            }],
            &me,
        )?;

        let offer_sdp = populate(
            &me,
            &mut transceivers,
            &[media_section("video", 0)],
            params(false, None),
            &[],
        )?;

        // Test codecs
        let mut found_vp8 = false;
        for desc in &offer_sdp.media_descriptions {
            if desc.media_name.media != "video" {
                continue;
            }
            for a in &desc.attributes {
                if a.key.contains("rtpmap")
                    && let Some(value) = &a.value
                {
                    if value.contains("VP9") {
                        panic!("vp9 should not be present in sdp: {value}");
                    } else if value == "96 VP8/90000" {
                        found_vp8 = true;
                    }
                }
            }
        }
        assert!(found_vp8, "vp8 should be present in sdp");
    }

    //"Bundle all"
    {
        let me = default_media_engine();
        let mut transceivers = vec![recvonly_transceiver(RtpCodecKind::Video)];

        let offer_sdp = populate(
            &me,
            &mut transceivers,
            &[media_section("video", 0)],
            params(false, None),
            &[],
        )?;

        assert_eq!(
            offer_sdp.attribute(ATTR_KEY_GROUP),
            Some(&"BUNDLE video".to_owned())
        );

        assert!(offer_sdp.has_attribute(ATTR_KEY_EXTMAP_ALLOW_MIXED));
    }

    //"Bundle matched"
    {
        let me = default_media_engine();
        let mut transceivers = vec![
            recvonly_transceiver(RtpCodecKind::Video),
            recvonly_transceiver(RtpCodecKind::Audio),
        ];

        let offer_sdp = populate(
            &me,
            &mut transceivers,
            &[media_section("video", 0), media_section("audio", 1)],
            params(false, Some("audio".to_owned())),
            &[],
        )?;

        assert_eq!(
            offer_sdp.attribute(ATTR_KEY_GROUP),
            Some(&"BUNDLE audio".to_owned())
        );
    }

    //"empty bundle group"
    {
        let me = default_media_engine();
        let mut transceivers = vec![recvonly_transceiver(RtpCodecKind::Video)];

        let offer_sdp = populate(
            &me,
            &mut transceivers,
            &[media_section("video", 0)],
            params(false, Some("".to_owned())),
            &[],
        )?;

        assert_eq!(offer_sdp.attribute(ATTR_KEY_GROUP), None);
    }

    // "Sender RTX"
    {
        let mut me = default_media_engine();
        me.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_RTX.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: "apt=96".to_string(),
                    rtcp_feedback: vec![],
                },
                payload_type: 97,
            },
            RtpCodecKind::Video,
        )?;

        // Two simulcast layers, "f" and "h", each with its own RTX repair flow. The old test
        // added the second layer with `add_encoding`; a sender's layers are now its encodings.
        let layer = |rid: &str, ssrc: SSRC, rtx: SSRC| RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                rid: rid.to_owned(),
                ssrc: Some(ssrc),
                rtx: Some(RTCRtpRtxParameters { ssrc: rtx }),
                ..Default::default()
            },
            codec: vp8(),
            ..Default::default()
        };
        let mut transceivers = vec![sendonly_transceiver(
            RtpCodecKind::Video,
            vec![layer("f", 1000, 1001), layer("h", 2000, 2001)],
        )];

        // The old crate always wrote `a=ssrc` lines for a simulcast sender; that is now opt-in.
        let mut p = params(false, None);
        p.write_ssrc_attributes_for_simulcast = true;
        let offer_sdp = populate(&me, &mut transceivers, &[media_section("video", 0)], p, &[])?;

        // Test codecs and FID groups
        let mut found_vp8 = false;
        let mut found_rtx = false;
        let mut found_ssrcs: Vec<&str> = Vec::new();
        let mut found_fids = Vec::new();
        for desc in &offer_sdp.media_descriptions {
            if desc.media_name.media != "video" {
                continue;
            }
            for a in &desc.attributes {
                if a.key.contains("rtpmap") {
                    if let Some(value) = &a.value {
                        if value == "96 VP8/90000" {
                            found_vp8 = true;
                        } else if value == "97 rtx/90000" {
                            found_rtx = true;
                        }
                    }
                } else if a.key == "ssrc" {
                    if let Some((ssrc, _)) = a.value.as_ref().and_then(|v| v.split_once(' ')) {
                        found_ssrcs.push(ssrc);
                    }
                } else if a.key == "ssrc-group"
                    && let Some(group) = a.value.as_ref().and_then(|v| v.strip_prefix("FID "))
                {
                    let Some((a, b)) = group.split_once(" ") else {
                        panic!("invalid FID format in sdp")
                    };

                    found_fids.extend([a, b]);
                }
            }
        }

        found_fids.sort();

        found_ssrcs.sort();
        // the sdp may have multiple attributes for each ssrc
        found_ssrcs.dedup();

        assert!(found_vp8, "vp8 should be present in sdp");
        assert!(found_rtx, "rtx should be present in sdp");
        assert_eq!(found_ssrcs.len(), 4, "all ssrcs should be present in sdp");
        assert_eq!(found_fids.len(), 4, "all fids should be present in sdp");

        assert_eq!(found_ssrcs, found_fids);
    }

    Ok(())
}

#[test]
fn test_populate_sdp_reject() -> Result<()> {
    let mut me = MediaEngine::default();
    me.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: vp8(),
            payload_type: 2,
        },
        RtpCodecKind::Video,
    )?;

    let mut transceivers = vec![
        recvonly_transceiver(RtpCodecKind::Video),
        recvonly_transceiver(RtpCodecKind::Audio),
    ];

    let offer_sdp = populate(
        &me,
        &mut transceivers,
        &[media_section("video", 0), media_section("audio", 1)],
        params(false, None),
        &[],
    )?;

    let mut found_rejected_track = false;

    for desc in offer_sdp.media_descriptions {
        if desc.media_name.media != "audio" {
            continue;
        }
        found_rejected_track = true;

        assert!(
            desc.connection_information.is_some(),
            "connection_information should not be None, even for rejected tracks"
        );
        assert_eq!(
            desc.media_name.formats,
            vec!["0"],
            "Format for rejected track should be 0"
        );
        assert_eq!(
            desc.media_name.port.value, 0,
            "Port for rejected track should be 0"
        );
    }

    assert!(
        found_rejected_track,
        "There should've been a rejected track"
    );

    Ok(())
}

#[test]
fn test_get_rids() {
    let m = [media(
        "video",
        vec![
            attr("sendonly", None),
            attr(
                SDP_ATTRIBUTE_RID,
                Some("f send pt=97;max-width=1280;max-height=720"),
            ),
        ],
    )];

    let rids = get_rids(&m[0]);

    assert!(!rids.is_empty(), "Rid mapping should be present");

    let f = rids.iter().find(|rid| rid.id == "f");
    assert!(f.is_some(), "rid values should contain 'f'");
}

#[test]
fn test_codecs_from_media_description() -> Result<()> {
    //"Codec Only"
    {
        let codecs = codecs_from_media_description(&MediaDescription {
            media_name: MediaName {
                media: "audio".to_owned(),
                formats: vec!["111".to_owned()],
                ..Default::default()
            },
            attributes: vec![attr("rtpmap", Some("111 opus/48000/2"))],
            ..Default::default()
        })?;

        assert_eq!(
            codecs,
            vec![RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_OPUS.to_owned(),
                    clock_rate: 48000,
                    channels: 2,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 111,
            }],
        );
    }

    //"Codec with fmtp/rtcp-fb"
    {
        let codecs = codecs_from_media_description(&MediaDescription {
            media_name: MediaName {
                media: "audio".to_owned(),
                formats: vec!["111".to_owned()],
                ..Default::default()
            },
            attributes: vec![
                attr("rtpmap", Some("111 opus/48000/2")),
                attr("fmtp", Some("111 minptime=10;useinbandfec=1")),
                attr("rtcp-fb", Some("111 goog-remb")),
                attr("rtcp-fb", Some("111 ccm fir")),
            ],
            ..Default::default()
        })?;

        assert_eq!(
            codecs,
            vec![RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_OPUS.to_owned(),
                    clock_rate: 48000,
                    channels: 2,
                    sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
                    rtcp_feedback: vec![
                        RTCPFeedback {
                            typ: "goog-remb".to_owned(),
                            parameter: "".to_owned()
                        },
                        RTCPFeedback {
                            typ: "ccm".to_owned(),
                            parameter: "fir".to_owned()
                        }
                    ]
                },
                payload_type: 111,
            }],
        );
    }

    Ok(())
}

#[test]
fn test_rtp_extensions_from_media_description() -> Result<()> {
    let extensions = rtp_extensions_from_media_description(&MediaDescription {
        media_name: MediaName {
            media: "audio".to_owned(),
            formats: vec!["111".to_owned()],
            ..Default::default()
        },
        attributes: vec![
            attr(
                "extmap",
                Some(&("1 ".to_owned() + sdp::extmap::ABS_SEND_TIME_URI)),
            ),
            attr(
                "extmap",
                Some(&("3 ".to_owned() + sdp::extmap::SDES_MID_URI)),
            ),
        ],
        ..Default::default()
    })?;

    assert_eq!(extensions[sdp::extmap::ABS_SEND_TIME_URI], 1);
    assert_eq!(extensions[sdp::extmap::SDES_MID_URI], 3);

    Ok(())
}
