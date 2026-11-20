//! A remote description that fails to apply changes nothing: neither
//! the signaling state nor the codecs the media engine has negotiated.

use std::time::Instant;

use crate::peer_connection::RTCPeerConnectionBuilder;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::peer_connection::sdp::RTCSessionDescription;
use crate::peer_connection::state::RTCSignalingState;
use shared::error::Result;

fn offer(rtx_fmtp: &str) -> String {
    format!(
        "v=0\r\n\
o=- 4215775240449105457 2 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\n\
c=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:4ZcD\r\n\
a=ice-pwd:2/1muCWoOi3uLifh0NuRHlkwz\r\n\
a=fingerprint:sha-256 F2:1C:F2:9E:B4:BE:58:19:C9:48:1A:D9:C4:A7:5D:5A:1F:61:7C:17:6B:07:8E:39:A2:E2:B2:BB:BF:4B:D2:16\r\n\
a=setup:actpass\r\n\
a=mid:0\r\n\
a=sendrecv\r\n\
a=rtcp-mux\r\n\
a=rtpmap:96 VP8/90000\r\n\
a=rtpmap:97 rtx/90000\r\n\
a=fmtp:97 {rtx_fmtp}\r\n"
    )
}

#[test]
fn a_description_the_media_engine_refuses_changes_nothing() -> Result<()> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;

    // `apt` must name a payload type (RFC 4588 section 8.6).
    let refused = pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(offer("apt=not-a-number"))?,
    );
    assert!(refused.is_err());
    assert_eq!(pc.signaling_state, RTCSignalingState::Stable);
    assert!(pc.remote_description().is_none());
    assert!(
        !pc.media_engine.negotiated_video && pc.media_engine.negotiated_video_codecs.is_empty(),
        "the refused description negotiated no codecs"
    );

    // The same offer, well formed, applies.
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(offer("apt=96"))?,
    )?;
    assert_eq!(pc.signaling_state, RTCSignalingState::HaveRemoteOffer);
    assert!(pc.media_engine.negotiated_video);
    Ok(())
}
