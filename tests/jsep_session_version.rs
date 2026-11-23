//! The `o=` line of generated descriptions (RFC 9429 sections 5.2.2 and 5.3.2, RFC 3264
//! section 8): it stays the same but for the session version, which goes up by one with each
//! description that differs from the one generated before.

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, default_peer, video_track};
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;

/// (everything of the `o=` line but the version, the version).
fn origin(sdp: &str) -> (String, u64) {
    let line = sdp
        .lines()
        .find(|l| l.starts_with("o="))
        .unwrap_or_else(|| panic!("an o= line in:\n{sdp}"));
    let fields: Vec<&str> = line.split(' ').collect();
    assert_eq!(fields.len(), 6, "{line}");
    let version = fields[2].parse().expect("a numeric session version");
    let mut rest = fields.clone();
    rest.remove(2);
    (rest.join(" "), version)
}

#[test]
fn the_session_version_goes_up_by_one_with_each_changed_description() -> TestResult {
    let mut a = default_peer()?;
    let mut b = default_peer()?;
    a.add_track(video_track("first", 0x0101_0101))?;

    let first = a.create_offer(None)?;
    let (session, version) = origin(&first.sdp);

    // The same offer again: the same text, version included.
    let again = a.create_offer(None)?;
    assert_eq!(again.sdp, first.sdp);

    // A changed offer: one more, same session.
    a.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(rtc::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;
    let second = a.create_offer(None)?;
    assert_eq!(origin(&second.sdp), (session.clone(), version + 1));

    a.set_local_description(Instant::now(), second.clone())?;
    b.set_remote_description(Instant::now(), second)?;
    let answer = b.create_answer(None)?;
    let (b_session, b_version) = origin(&answer.sdp);
    assert_ne!(b_session, session, "each endpoint has its own session id");
    b.set_local_description(Instant::now(), answer.clone())?;
    a.set_remote_description(Instant::now(), answer)?;

    // `b` now offers: its next description, one more than its answer.
    b.add_track(video_track("b", 0x0202_0202))?;
    let offer = b.create_offer(None)?;
    assert_eq!(origin(&offer.sdp), (b_session, b_version + 1));
    b.set_local_description(Instant::now(), offer.clone())?;
    a.set_remote_description(Instant::now(), offer)?;

    // `a` answers: its third description.
    let answer = a.create_answer(None)?;
    assert_eq!(origin(&answer.sdp), (session, version + 2));
    Ok(())
}

/// RFC 9429 section 5.8: compliant SDP is accepted even where it does not follow the
/// generation rules; `<sess-id>` and `<sess-version>` are `1*DIGIT` of any length (RFC 8866
/// section 9), so a remote offer whose values do not fit 64 bits is set and answered, and a
/// later offer of that session with the version one higher is set too.
#[test]
fn a_remote_origin_beyond_64_bits_is_accepted() -> TestResult {
    let mut a = default_peer()?;
    let mut b = default_peer()?;
    a.add_track(video_track("first", 0x0101_0101))?;
    let offer = a.create_offer(None)?;
    let line = offer
        .sdp
        .lines()
        .find(|l| l.starts_with("o="))
        .expect("an o= line")
        .to_owned();
    let long = |version: &str| {
        offer.sdp.replace(
            &line,
            &format!("o=- 98765432109876543210987654321 {version} IN IP4 0.0.0.0"),
        )
    };
    b.set_remote_description(
        Instant::now(),
        rtc::peer_connection::sdp::RTCSessionDescription::offer(long("18446744073709551616"))?,
    )?;
    let answer = b.create_answer(None)?;
    b.set_local_description(Instant::now(), answer)?;
    b.set_remote_description(
        Instant::now(),
        rtc::peer_connection::sdp::RTCSessionDescription::offer(long("18446744073709551617"))?,
    )?;
    let answer = b.create_answer(None)?;
    assert!(answer.sdp.contains("m=video"), "{}", answer.sdp);
    Ok(())
}
