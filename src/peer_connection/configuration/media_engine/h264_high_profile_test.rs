//! The default codecs carry H.264 High profile at levels 4.0, 4.1, 4.2 and 5.1 besides 5.0
//! (`640032`), on the payload types webrtc-rs 0.17 uses. Upstream `webrtc` v0.17.1's
//! `test_h264_high_profile_codecs`, made synchronous.

use super::*;

#[test]
fn test_h264_high_profile_codecs() -> Result<()> {
    let mut m = MediaEngine::default();
    m.register_default_codecs()?;

    for (payload_type, profile_level_id) in [
        (118, "profile-level-id=640028"), // High Profile Level 4.0
        (119, "profile-level-id=640029"), // High Profile Level 4.1
        (120, "profile-level-id=64002a"), // High Profile Level 4.2
        (121, "profile-level-id=640033"), // High Profile Level 5.1
    ] {
        let (codec, kind) = m.get_codec_by_payload(payload_type)?;
        assert_eq!(kind, RtpCodecKind::Video);
        assert_eq!(codec.rtp_codec.mime_type, MIME_TYPE_H264);
        assert!(
            codec.rtp_codec.sdp_fmtp_line.contains(profile_level_id),
            "{payload_type}: {}",
            codec.rtp_codec.sdp_fmtp_line
        );
        assert!(
            codec
                .rtp_codec
                .sdp_fmtp_line
                .contains("packetization-mode=1")
        );
    }
    Ok(())
}
