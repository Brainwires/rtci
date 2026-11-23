//! RFC 5576 (source-specific media attributes): what a remote description's `a=ssrc` lines
//! do to the receivers, and how SSRCs are chosen.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::SSRC;

/// A remote offer (session version `version`) of one VP8 section, mid 0, whose source lines
/// are `sources`.
fn video_offer(
    version: u32,
    sources: &str,
) -> Result<RTCSessionDescription, Box<dyn std::error::Error>> {
    let session = SESSION.replace(" 2 IN IP4", &format!(" {version} IN IP4"));
    Ok(RTCSessionDescription::offer(crlf(&format!(
        "{session}a=group:BUNDLE 0\n\
         m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=sendrecv\n\
         a=msid:stream track\na=rtpmap:96 VP8/90000\n{sources}"
    )))?)
}

fn answer(pc: &mut RTCPeerConnection, offer: RTCSessionDescription) -> TestResult {
    let now = Instant::now();
    pc.set_remote_description(now, offer)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(now, answer)?;
    Ok(())
}

/// The SSRCs the receiver of the one transceiver expects.
fn receiver_ssrcs(pc: &mut RTCPeerConnection) -> Vec<SSRC> {
    let id = pc.get_receivers().next().expect("a receiver");
    let receiver = pc.rtp_receiver(id).expect("the receiver");
    let mut ssrcs: Vec<SSRC> = receiver.track().ssrcs().collect();
    ssrcs.sort_unstable();
    ssrcs
}

/// RFC 5576 section 5: "the source information signalled in SDP ... may be out of date"; a
/// receiver "MUST" treat it so. Each remote description rebuilds the bindings: the first
/// declares 1111 for the section, the next one 2222 instead, and the receiver then expects
/// 2222 alone; a third with no source lines leaves no declared SSRC behind (the streams are
/// placed by their MID as they arrive).
#[test]
fn source_bindings_are_rebuilt_from_each_remote_description() -> TestResult {
    let mut pc = default_peer()?;
    answer(&mut pc, video_offer(2, "a=ssrc:1111 cname:remote\n")?)?;
    assert_eq!(receiver_ssrcs(&mut pc), vec![1111]);

    answer(&mut pc, video_offer(3, "a=ssrc:2222 cname:remote\n")?)?;
    assert_eq!(receiver_ssrcs(&mut pc), vec![2222]);

    answer(
        &mut pc,
        video_offer(
            4,
            "a=ssrc-group:FID 3333 4444\na=ssrc:3333 cname:remote\na=ssrc:4444 cname:remote\n",
        )?,
    )?;
    assert!(
        !receiver_ssrcs(&mut pc).contains(&2222),
        "{:?}",
        receiver_ssrcs(&mut pc)
    );
    assert!(receiver_ssrcs(&mut pc).contains(&3333));

    answer(&mut pc, video_offer(5, "")?)?;
    assert!(
        receiver_ssrcs(&mut pc).is_empty(),
        "{:?}",
        receiver_ssrcs(&mut pc)
    );
    Ok(())
}
