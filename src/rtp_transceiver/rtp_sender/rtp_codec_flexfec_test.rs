//! Two FlexFEC formats, two coders, and the codec name picks one exactly: `video/flexfec-03` is
//! draft-ietf-payload-flexible-fec-scheme-03, `video/flexfec` is RFC 8627. Their wire formats
//! are not compatible, so neither name may select the other's coder.

use super::*;

fn codec(payload_type: PayloadType, mime_type: &str) -> RTCRtpCodecParameters {
    codec_with_fmtp(payload_type, mime_type, "")
}

fn codec_with_fmtp(
    payload_type: PayloadType,
    mime_type: &str,
    fmtp: &str,
) -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime_type.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: fmtp.to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type,
    }
}

/// `video/flexfec` is found as a FEC format of its own, under its own name: the interceptors
/// select their coder by that name, so the draft-03 one never sees an RFC 8627 stream.
#[test]
fn rfc_8627_flexfec_is_not_the_draft_03_coder() {
    let format = find_fec_format(&[codec(96, "video/VP8"), codec(110, "video/flexfec")])
        .expect("RFC 8627 FlexFEC is a FEC format");

    assert_eq!(110, format.payload_type);
    assert_eq!("video/flexfec", format.mime_type);
    assert!(!is_flexfec03_mime_type(&format.mime_type));
    assert!(is_flexfec_mime_type(&format.mime_type));
}

/// With both negotiated the sender uses draft-03, the one browsers decode.
#[test]
fn draft_03_is_found_whatever_its_case() {
    assert_eq!(
        Some(111),
        find_fec_payload_type(&[codec(110, "video/flexfec"), codec(111, "video/FlexFEC-03"),])
    );
    assert_eq!(
        Some(111),
        find_fec_payload_type(&[codec(111, "video/FlexFEC-03"), codec(110, "video/flexfec"),])
    );
}

/// FLEXFEC03-5.1-5, a deliberate deviation: draft-03 names its subtype `flexfec`, and the
/// draft-03 coder answers to `flexfec-03` only (libwebrtc's name), because `flexfec` means RFC
/// 8627 now.
#[test]
fn the_mime_type_match_is_exact() {
    assert!(is_flexfec03_mime_type("video/flexfec-03"));
    assert!(!is_flexfec03_mime_type("video/flexfec"));
    assert!(!is_flexfec03_mime_type("video/flexfec-030"));
    assert!(!is_flexfec03_mime_type("audio/flexfec-03"));

    assert!(is_flexfec_mime_type("video/flexfec"));
    assert!(is_flexfec_mime_type("Video/FlexFEC"));
    assert!(!is_flexfec_mime_type("video/flexfec-03"));
    assert!(!is_flexfec_mime_type("video/flexfec2"));
    assert!(!is_flexfec_mime_type("audio/flexfec"));

    assert!(is_fec_mime_type("video/flexfec") && is_fec_mime_type("video/flexfec-03"));
    assert!(!is_fec_mime_type("video/ulpfec") && !is_fec_mime_type("video/rtx"));
}

/// The format carries its `a=fmtp` line: RFC 8627's required `repair-window` reaches the coder
/// through it (section 5.1).
#[test]
fn the_fec_format_carries_its_fmtp_line() {
    let format = find_fec_format(&[
        codec(96, "video/VP8"),
        codec_with_fmtp(110, "video/flexfec", "repair-window=200000"),
    ])
    .expect("found");
    assert_eq!("repair-window=200000", format.sdp_fmtp_line);

    assert_eq!(
        None,
        find_fec_format(&[codec(96, "video/VP8"), codec(97, "video/rtx")])
    );
}

/// RFC 5109 section 14.1 with RFC 5956 section 4.3: a remote `FEC-FR` repair flow in a section
/// with `video/ulpfec` and no FlexFEC is ULPFEC as a stream of its own; FlexFEC still wins
/// where both are listed. The send side's lookup is unchanged (ULPFEC is sent in RED).
#[test]
fn a_receive_fec_flow_falls_back_to_ulpfec_as_a_separate_stream() {
    let ulpfec_only = [codec(96, "video/VP8"), codec(117, "video/ulpfec")];
    assert_eq!(None, find_fec_format(&ulpfec_only));
    let format = find_receive_fec_format(&ulpfec_only).expect("ULPFEC");
    assert_eq!(
        (117, "video/ulpfec"),
        (format.payload_type, format.mime_type.as_str())
    );

    let both = [
        codec(96, "video/VP8"),
        codec(117, "video/ulpfec"),
        codec(118, "video/flexfec-03"),
    ];
    assert_eq!(118, find_receive_fec_format(&both).unwrap().payload_type);
}
