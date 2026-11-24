//! RFC 7741 section 3: "it is RECOMMENDED that the packetizer start each partition in a new
//! packet". The payloader a connection builds for a VP8 sender does so by default; under the
//! `Chrome` behaviour profile it cuts the frame as libwebrtc's `RtpPacketizerVp8` does, without
//! regard to partitions (`S` on the first packet only, `PID` 0), which section 4.4 also allows.

use anyhow::Result;
use bytes::Bytes;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::BehaviourProfile;
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtci::rtp::codec::vp8::Vp8Packet;
use rtci::rtp::packetizer::Depacketizer;
use rtci::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
use std::time::Instant;

/// The second frame of `examples/test-data/output_vp8.ivf` (libvpx, 176x144): a 331-byte
/// inter frame whose first partition is 152 bytes, followed by one token partition.
fn libvpx_inter_frame() -> Bytes {
    let data = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/test-data/output_vp8.ivf"),
    )
    .expect("the VP8 fixture");
    let header_len = usize::from(u16::from_le_bytes([data[6], data[7]]));
    let mut offset = header_len;
    let mut frames = Vec::new();
    while offset + 12 <= data.len() && frames.len() < 2 {
        let size = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        frames.push(Bytes::copy_from_slice(
            &data[offset + 12..offset + 12 + size],
        ));
        offset += 12 + size;
    }
    let frame = frames.pop().expect("two frames");
    assert_eq!(frame.len(), 331);
    assert_eq!(frame[0] & 0x01, 1, "an inter frame");
    frame
}

/// The `(S, PID)` of each packet a VP8 sender of a connection built with `media_engine` makes
/// of one frame.
fn packetization(mut media_engine: MediaEngine) -> Result<Vec<(u8, u8)>> {
    media_engine.register_default_codecs()?;
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;
    let transceiver = pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let sender = pc
        .rtp_transceiver(transceiver)
        .and_then(|t| t.sender())
        .expect("a video transceiver has a sender");
    let codec = RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90_000,
        ..Default::default()
    };
    let mut payloader = pc.rtp_sender(sender).expect("sender").payloader(&codec)?;
    let payloads = payloader.payload(1200, &libvpx_inter_frame())?;
    let mut descriptors = Vec::new();
    for payload in &payloads {
        let mut packet = Vp8Packet::default();
        packet.depacketize(payload)?;
        descriptors.push((packet.s, packet.pid));
    }
    Ok(descriptors)
}

#[test]
fn by_default_each_vp8_partition_starts_a_packet() -> Result<()> {
    assert_eq!(
        packetization(MediaEngine::for_profile(BehaviourProfile::Rfc))?,
        [(1, 0), (1, 1)]
    );
    assert_eq!(
        packetization(MediaEngine::for_profile(BehaviourProfile::StrictRfc))?,
        [(1, 0), (1, 1)]
    );
    Ok(())
}

#[test]
fn the_chrome_profile_packetizes_vp8_as_libwebrtc_does() -> Result<()> {
    assert_eq!(
        packetization(MediaEngine::for_profile(BehaviourProfile::Chrome))?,
        [(1, 0)]
    );
    let mut media_engine = MediaEngine::for_profile(BehaviourProfile::Rfc);
    media_engine.set_vp8_ignore_partitions(true);
    assert_eq!(packetization(media_engine)?, [(1, 0)]);
    Ok(())
}
