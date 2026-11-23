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

/// RFC 9335 section 4: "the same procedure" for including `a=cryptex` applies to subsequent
/// offers and answers. Under the default policy (`negotiate`) a re-offer from either side and
/// its answer carry it again, and Cryptex stays negotiated after each exchange.
#[test]
fn later_offers_and_answers_keep_cryptex() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.add_track(video_track("video", 0x0c0c_0004))?;
    let mut answerer = default_peer()?;
    let (offer, answer) = jsep_common::exchange(&mut offerer, &mut answerer)?;
    assert!(offer.contains("a=cryptex") && answer.contains("a=cryptex"));
    assert!(offerer.cryptex_negotiated() && answerer.cryptex_negotiated());

    for turn in 0..2 {
        let (offer, answer) = if turn == 0 {
            jsep_common::exchange(&mut offerer, &mut answerer)?
        } else {
            jsep_common::exchange(&mut answerer, &mut offerer)?
        };
        assert!(offer.contains("a=cryptex"), "re-offer {turn}:\n{offer}");
        assert!(answer.contains("a=cryptex"), "answer {turn}:\n{answer}");
        assert!(offerer.cryptex_negotiated() && answerer.cryptex_negotiated());
    }
    Ok(())
}

/// A peer with the default codecs and the MID header extension for video.
fn peer_with_mid() -> Result<rtc::peer_connection::RTCPeerConnection, Box<dyn std::error::Error>> {
    use rtc::peer_connection::configuration::media_engine::MediaEngine;
    use rtc::rtp_transceiver::rtp_sender::{RTCRtpHeaderExtensionCapability, RtpCodecKind};
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: MID_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;
    Ok(rtc::peer_connection::RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?)
}

const MID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";

/// RFC 9335 section 5: with two-byte header extensions "the extension identifier with value
/// 256 MUST NOT be negotiated" (it names the `appbits`). An offer that maps the MID extension,
/// which the answerer knows, to 256 is applied, and the answer neither takes 256 nor maps the
/// extension (RFC 8285 section 6: it is passed over); the same offer with the extension at a
/// local identifier (here 200, two-byte) is answered with it.
#[test]
fn the_appbits_identifier_256_is_never_negotiated() -> TestResult {
    let mut offerer = peer_with_mid()?;
    offerer.add_track(video_track("video", 0x0c0c_0005))?;
    let offer = offerer.create_offer(None)?;
    let mid_line = offer
        .sdp
        .lines()
        .find(|l| l.starts_with("a=extmap:") && l.ends_with(&format!(" {MID_URI}")))
        .expect("the offer maps the MID extension")
        .to_owned();
    for (id, answered) in [("200", true), ("256", false)] {
        let edited = offer
            .sdp
            .replace(&mid_line, &format!("a=extmap:{id} {MID_URI}"));
        let mut answerer = peer_with_mid()?;
        answerer.set_remote_description(
            Instant::now(),
            rtc::peer_connection::sdp::RTCSessionDescription::offer(edited)?,
        )?;
        let answer = answerer.create_answer(None)?;
        assert_eq!(
            answer.sdp.contains(&format!("a=extmap:{id} {MID_URI}")),
            answered,
            "id {id}:\n{}",
            answer.sdp
        );
        if !answered {
            assert!(!answer.sdp.contains(MID_URI), "{}", answer.sdp);
        }
    }
    Ok(())
}

/// RFC 9335 section 9.1: `a=cryptex` is of the TRANSPORT category, so under BUNDLE the
/// BUNDLE-tagged section's attribute applies to every section of the group (RFC 8859 section
/// 4.5; RFC 9143 section 7.1.3 lets a description carry it there only). An offer with
/// `a=cryptex` in its tagged section alone satisfies a `Require` answerer, which answers with
/// it; the attribute in a section that is not the tagged one does not stand for the group.
#[test]
fn a_cryptex_attribute_in_the_bundle_tagged_section_applies_to_the_group() -> TestResult {
    use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
    let mut offerer = default_peer()?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = offerer.create_offer(None)?.sdp;
    assert!(offer.contains("a=group:BUNDLE 0 1"), "{offer}");
    let session_level = offer.replacen("a=cryptex\r\n", "", 1);
    assert!(!session_level.contains("a=cryptex"), "{offer}");
    for (mid, accepted) in [("0", true), ("1", false)] {
        let edited = session_level.replacen(
            &format!("a=mid:{mid}\r\n"),
            &format!("a=mid:{mid}\r\na=cryptex\r\n"),
            1,
        );
        let mut answerer = default_peer()?;
        answerer.set_rtp_header_encryption_policy(RTCRtpHeaderEncryptionPolicy::Require)?;
        let applied = answerer.set_remote_description(
            Instant::now(),
            rtc::peer_connection::sdp::RTCSessionDescription::offer(edited.clone())?,
        );
        if accepted {
            applied?;
            let answer = answerer.create_answer(None)?;
            assert!(answer.sdp.contains("a=cryptex"), "{}", answer.sdp);
        } else {
            assert_eq!(
                applied.expect_err("a=cryptex outside the tagged section only"),
                Error::ErrSessionDescriptionMissingCryptex,
                "{edited}"
            );
        }
    }
    Ok(())
}

/// RFC 7941 section 6: with RTCP encrypted, "the SDES item header extensions MUST also be
/// protected". `Require` is that form: no session sends MID or RID in the clear. A recorded
/// Firefox 152 offer (simulcast, three rids) signals neither `a=cryptex` nor any RFC 6904
/// encrypted extension, and carries its layers' RIDs only in the clear: `Require` refuses it,
/// while the default policy (`negotiate`) accepts it.
#[test]
fn require_refuses_the_recorded_firefox_offer() -> TestResult {
    const FIREFOX_OFFER: &str =
        include_str!("fixtures/browser-sdp/firefox-152--simulcast-three-rids-send--1-offer.sdp");
    let offer = || -> Result<_, Box<dyn std::error::Error>> {
        Ok(rtc::peer_connection::sdp::RTCSessionDescription::offer(
            FIREFOX_OFFER.replace("\r\n", "\n").replace('\n', "\r\n"),
        )?)
    };
    assert!(!FIREFOX_OFFER.contains("a=cryptex"));
    assert!(!FIREFOX_OFFER.contains("rtp-hdrext:encrypt"));

    let mut answerer = default_peer()?;
    answerer.set_rtp_header_encryption_policy(RTCRtpHeaderEncryptionPolicy::Require)?;
    let err = answerer
        .set_remote_description(Instant::now(), offer()?)
        .expect_err("Firefox's offer under `Require`");
    assert_eq!(err, Error::ErrSessionDescriptionMissingCryptex);

    let mut answerer = default_peer()?;
    answerer.set_remote_description(Instant::now(), offer()?)?;
    let answer = answerer.create_answer(None)?;
    assert!(answer.sdp.contains("m=video 9 "), "{}", answer.sdp);
    Ok(())
}
