//! The default AV1 codec is offered with the AV1 RTP payload format's own SDP parameter,
//! `profile` (AV1 RTP specification, section 7.2), not VP9's `profile-id`, which a peer reading
//! the offer ignores (so `av1-profile-asymmetry` checked nothing).

mod jsep_common;

use jsep_common::{TestResult, default_peer};
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;

#[test]
fn the_default_av1_codec_offers_profile_not_profile_id() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = pc.create_offer(None)?;
    let sdp = &offer.sdp;

    let av1_pt = sdp
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix("a=rtpmap:")?;
            let (pt, encoding) = rest.split_once(' ')?;
            encoding
                .to_ascii_uppercase()
                .starts_with("AV1/")
                .then(|| pt.to_owned())
        })
        .unwrap_or_else(|| panic!("the default codecs offer AV1:\n{sdp}"));

    let fmtp = sdp
        .lines()
        .find_map(|line| line.strip_prefix(&format!("a=fmtp:{av1_pt} ")))
        .unwrap_or_else(|| panic!("AV1 ({av1_pt}) has an a=fmtp line:\n{sdp}"));
    let parameters: Vec<&str> = fmtp.split(';').map(str::trim).collect();
    assert!(parameters.contains(&"profile=0"), "{fmtp}\n{sdp}");
    assert!(
        !parameters.iter().any(|p| p.starts_with("profile-id")),
        "profile-id is VP9's parameter: {fmtp}\n{sdp}"
    );
    Ok(())
}
