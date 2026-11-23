//! `RTCRtpHeaderEncryptionPolicy::Require` is enforced by `set_remote_description`: a remote
//! description with an RTP section that doesn't signal Cryptex (RFC 9335 section 4) is
//! refused, before any of it is applied. It used to be applied, and the session sent its mid,
//! audio level and other header extensions in the clear with no error: `require` only took
//! effect once Cryptex was negotiated, which it then never was.

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, default_peer, video_track};
use rtc::peer_connection::cryptex::RTCRtpHeaderEncryptionPolicy;
use rtc::shared::error::Error;

#[test]
fn require_refuses_an_answer_without_cryptex() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.set_rtp_header_encryption_policy(RTCRtpHeaderEncryptionPolicy::Require)?;
    offerer.add_track(video_track("video", 0x0c0c_0001))?;
    let mut answerer = default_peer()?;
    // The answerer doesn't do Cryptex, so its answer has no a=cryptex.
    answerer.set_rtp_header_encryption_policy(RTCRtpHeaderEncryptionPolicy::Disable)?;

    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    assert!(offer.sdp.contains("a=cryptex"), "{}", offer.sdp);
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    assert!(!answer.sdp.contains("a=cryptex"), "{}", answer.sdp);

    let err = offerer
        .set_remote_description(now, answer)
        .expect_err("an answer without Cryptex under `Require`");
    assert_eq!(err, Error::ErrSessionDescriptionMissingCryptex);
    assert!(
        offerer.remote_description().is_none(),
        "nothing of the refused answer is applied"
    );
    assert!(offerer.pending_local_description().is_some());
    assert!(!offerer.cryptex_negotiated());
    Ok(())
}

#[test]
fn require_refuses_an_offer_without_cryptex() -> TestResult {
    let mut offerer = default_peer()?;
    // The default policy ("negotiate") offers Cryptex; this offerer does not do it.
    offerer.set_rtp_header_encryption_policy(RTCRtpHeaderEncryptionPolicy::Disable)?;
    offerer.add_track(video_track("video", 0x0c0c_0002))?;
    let offer = offerer.create_offer(None)?;
    assert!(!offer.sdp.contains("a=cryptex"), "{}", offer.sdp);

    let mut answerer = default_peer()?;
    answerer.set_rtp_header_encryption_policy(RTCRtpHeaderEncryptionPolicy::Require)?;
    let err = answerer
        .set_remote_description(Instant::now(), offer)
        .expect_err("an offer without Cryptex under `Require`");
    assert_eq!(err, Error::ErrSessionDescriptionMissingCryptex);
    assert!(answerer.remote_description().is_none());
    assert_eq!(answerer.get_transceivers().count(), 0);
    Ok(())
}

#[test]
fn require_accepts_cryptex_both_ways() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.set_rtp_header_encryption_policy(RTCRtpHeaderEncryptionPolicy::Require)?;
    offerer.add_track(video_track("video", 0x0c0c_0003))?;
    let mut answerer = default_peer()?;
    answerer.set_rtp_header_encryption_policy(RTCRtpHeaderEncryptionPolicy::Negotiate)?;

    jsep_common::exchange(&mut offerer, &mut answerer)?;
    assert!(offerer.cryptex_negotiated());
    assert!(answerer.cryptex_negotiated());
    Ok(())
}

/// RFC 9335 section 4: with BUNDLE, an `a=cryptex` "present for a media line ... MUST be
/// present for all RTP-based m= sections belonging to the same bundle group" (it is TRANSPORT
/// in RFC 8859's terms, but RFC 9335 asks for it on every RTP section, so that every
/// section's encrypted MID can be read). Which sections decide: an answer whose `a=cryptex`
/// is at the session level, or on every bundled RTP section, negotiates Cryptex; one with
/// `a=cryptex` on the tagged section alone does not.
#[test]
fn cryptex_is_negotiated_only_when_every_bundled_rtp_section_has_it() -> TestResult {
    for (placement, negotiated) in [("session", true), ("every", true), ("tagged", false)] {
        let mut offerer = default_peer()?;
        offerer.add_track(video_track("first", 0x0c0c_0010))?;
        offerer.add_track(video_track("second", 0x0c0c_0011))?;
        let mut answerer = default_peer()?;

        let now = Instant::now();
        let offer = offerer.create_offer(None)?;
        offerer.set_local_description(now, offer.clone())?;
        answerer.set_remote_description(now, offer)?;
        let answer = answerer.create_answer(None)?;
        answerer.set_local_description(now, answer.clone())?;
        assert!(answer.sdp.contains("a=cryptex"), "{}", answer.sdp);

        let mut munged = String::new();
        let mut sections = 0;
        for line in answer.sdp.lines() {
            if line == "a=cryptex" {
                continue;
            }
            if line.starts_with("m=") {
                sections += 1;
            }
            munged.push_str(line);
            munged.push_str("\r\n");
            // Attributes follow a section's c= line: after its a=mid.
            let add = match placement {
                "session" => line.starts_with("t="),
                "every" => line.starts_with("a=mid:"),
                _ => line.starts_with("a=mid:") && sections == 1,
            };
            if add {
                munged.push_str("a=cryptex\r\n");
            }
        }
        assert_eq!(sections, 2, "{}", answer.sdp);
        offerer.set_remote_description(
            now,
            rtc::peer_connection::sdp::RTCSessionDescription::answer(munged.clone())?,
        )?;
        assert_eq!(
            offerer.cryptex_negotiated(),
            negotiated,
            "a=cryptex on the {placement} level:\n{munged}"
        );
    }
    Ok(())
}
