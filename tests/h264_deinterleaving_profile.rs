//! RFC 6184 section 7.2.2: "Let PDON be a variable that is initialized to 0 at the beginning
//! of the RTP session", and a NAL unit whose DON is not larger than PDON is at DON distance
//! 65535 - PDON + DON + 1. A NAL unit whose DON is 0 is then at distance 65536, the largest,
//! so a stream numbered from DON 0 has its first NAL unit passed on last.
//!
//! This default does not follow RFC 6184 section 7.2 (owner decision 2026-11-26,
//! `docs/conformance.md`, "Standing departures from a MUST"): until a NAL unit has been passed
//! on, PDON is the DON just before the earliest one buffered, so such a stream leaves in
//! decoding order. The `StrictRfc` behaviour profile, and `MediaEngine::set_h264_literal_pdon`,
//! select the RFC's literal form for the H.264 depacketizers a connection builds.

use anyhow::Result;
use bytes::Bytes;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::BehaviourProfile;
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_H264, MediaEngine};
use rtci::rtp::codec::h264::{H264Packet, stap_b};
use rtci::rtp::packetizer::Depacketizer;
use rtci::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
use std::time::Instant;

/// An interleaved H.264 stream (`packetization-mode=2`) whose receiver buffers three VCL NAL
/// units (`sprop-interleaving-depth=2`).
fn interleaved_h264() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_H264.to_owned(),
        clock_rate: 90_000,
        sdp_fmtp_line: "packetization-mode=2;sprop-interleaving-depth=2".to_owned(),
        ..Default::default()
    }
}

/// Six slices numbered from DON 0, sent in the order 1, 0, 3, 2, 5, 4, one per STAP-B: the
/// tags of the NAL units in the order the depacketizer passes them on.
fn order(mut depacketizer: H264Packet) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut take = |annex_b: Bytes| {
        // Each NAL unit is a start code, the slice header octet 0x41 and its tag.
        for unit in annex_b.chunks(6) {
            assert_eq!(&unit[..5], &[0, 0, 0, 1, 0x41]);
            out.push(unit[5]);
        }
    };
    for don in [1u16, 0, 3, 2, 5, 4] {
        let packet = stap_b(don, &[Bytes::from(vec![0x41, don as u8])])?;
        take(depacketizer.depacketize(&packet)?);
    }
    take(depacketizer.flush_deinterleaving());
    Ok(out)
}

/// RFC 6184 section 7.2.2 as written, PDON 0: DON 0 is at distance 65536, after every other
/// NAL unit of the six.
const LITERAL_ORDER: [u8; 6] = [1, 2, 3, 4, 5, 0];
const DECODING_ORDER: [u8; 6] = [0, 1, 2, 3, 4, 5];

fn depacketizer_of(profile: BehaviourProfile) -> Result<H264Packet> {
    Ok(MediaEngine::for_profile(profile).h264_depacketizer(&interleaved_h264())?)
}

#[test]
fn by_default_a_stream_numbered_from_don_0_leaves_in_decoding_order() -> Result<()> {
    assert_eq!(
        order(interleaved_h264().h264_depacketizer()?)?,
        DECODING_ORDER
    );
    for profile in [
        BehaviourProfile::Rfc,
        BehaviourProfile::Chrome,
        BehaviourProfile::Performance,
    ] {
        assert_eq!(
            order(depacketizer_of(profile)?)?,
            DECODING_ORDER,
            "{profile:?}"
        );
    }
    Ok(())
}

#[test]
fn the_strict_rfc_profile_starts_pdon_at_0_as_rfc_6184_does() -> Result<()> {
    assert_eq!(
        order(depacketizer_of(BehaviourProfile::StrictRfc)?)?,
        LITERAL_ORDER
    );
    let mut media_engine = MediaEngine::for_profile(BehaviourProfile::Rfc);
    media_engine.set_h264_literal_pdon(true);
    assert_eq!(
        order(media_engine.h264_depacketizer(&interleaved_h264())?)?,
        LITERAL_ORDER
    );
    Ok(())
}

/// The receiver of a connection builds its H.264 depacketizer with the connection's media
/// engine settings.
#[test]
fn a_receiver_builds_its_h264_depacketizer_with_the_connections_profile() -> Result<()> {
    for (profile, expected) in [
        (BehaviourProfile::Rfc, DECODING_ORDER),
        (BehaviourProfile::StrictRfc, LITERAL_ORDER),
    ] {
        let mut media_engine = MediaEngine::for_profile(profile);
        media_engine.register_default_codecs()?;
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .build(Instant::now())?;
        let transceiver = pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
        let receiver = pc
            .rtp_transceiver(transceiver)
            .and_then(|t| t.receiver())
            .expect("a video transceiver has a receiver");
        let depacketizer = pc
            .rtp_receiver(receiver)
            .expect("receiver")
            .h264_depacketizer(&interleaved_h264())?;
        assert_eq!(order(depacketizer)?, expected, "{profile:?}");
    }
    Ok(())
}
