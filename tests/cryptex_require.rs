//! `RTCRtpHeaderEncryptionPolicy::Require` is enforced by `set_remote_description`: a remote
//! description with an RTP section that doesn't signal Cryptex (RFC 9335 section 4) is
//! refused, before any of it is applied. It used to be applied, and the session sent its mid,
//! audio level and other header extensions in the clear with no error: `require` only took
//! effect once Cryptex was negotiated, which it then never was.

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, default_peer, video_track};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::cryptex::RTCRtpHeaderEncryptionPolicy;
use rtci::shared::error::Error;

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

/// A peer with the default codecs and the given setting engine.
fn peer_with(
    settings: rtci::peer_connection::configuration::setting_engine::SettingEngine,
) -> Result<rtci::peer_connection::RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine =
        rtci::peer_connection::configuration::media_engine::MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(rtci::peer_connection::RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(settings)
        .build(Instant::now())?)
}

/// Whether an offerer reading an answer with `a=cryptex` at the session level, on every
/// bundled section, or on the BUNDLE-tagged section alone negotiates Cryptex, for each
/// placement in turn.
fn negotiated_by_placement(
    strict: bool,
) -> Result<Vec<(&'static str, bool)>, Box<dyn std::error::Error>> {
    let mut negotiated = vec![];
    for placement in ["session", "every", "tagged", "other"] {
        let mut offerer = peer_with(
            SettingEngineBuilder::new()
                .with_cryptex_required_on_every_bundled_section(strict)
                .build(),
        )?;
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
        assert!(answer.sdp.contains("a=group:BUNDLE 0 1"), "{}", answer.sdp);

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
                // The tagged section is the first tag of the group, "0".
                "tagged" => line.starts_with("a=mid:") && sections == 1,
                _ => line.starts_with("a=mid:") && sections == 2,
            };
            if add {
                munged.push_str("a=cryptex\r\n");
            }
        }
        assert_eq!(sections, 2, "{}", answer.sdp);
        offerer.set_remote_description(
            now,
            rtci::peer_connection::sdp::RTCSessionDescription::answer(munged)?,
        )?;
        negotiated.push((placement, offerer.cryptex_negotiated()));
    }
    Ok(negotiated)
}

/// RFC 9335 section 4: "When used with BUNDLE, this attribute is assigned to the TRANSPORT
/// category [RFC8859]", whose value is the one "associated with the 'm=' line whose
/// information is used for setting up the underlying transport" (RFC 8859 section 4.5), the
/// BUNDLE-tagged section, the only one an RFC 9143 section 7.1.3 answerer writes it in. By
/// default an answer with `a=cryptex` at the session level, on every bundled section, or on
/// the tagged section alone negotiates Cryptex; on another section alone it does not.
#[test]
fn by_default_the_bundle_tagged_sections_cryptex_is_the_groups() -> TestResult {
    assert_eq!(
        negotiated_by_placement(false)?,
        [
            ("session", true),
            ("every", true),
            ("tagged", true),
            ("other", false)
        ]
    );
    Ok(())
}

/// RFC 9335 section 4, read strictly with
/// `SettingEngineBuilder::with_cryptex_required_on_every_bundled_section(true)`: with BUNDLE,
/// an `a=cryptex` "present for a media line ... MUST be present for all RTP-based m= sections
/// belonging to the same bundle group". An answer whose `a=cryptex` is at the session level,
/// or on every bundled RTP section, negotiates Cryptex; one with `a=cryptex` on the tagged
/// section alone (or another one alone) does not.
#[test]
fn cryptex_is_negotiated_only_when_every_bundled_rtp_section_has_it() -> TestResult {
    assert_eq!(
        negotiated_by_placement(true)?,
        [
            ("session", true),
            ("every", true),
            ("tagged", false),
            ("other", false)
        ]
    );
    Ok(())
}

/// RFC 9335 section 4, the writer's rule: with BUNDLE, `a=cryptex` "MUST be present for all
/// RTP-based 'm=' sections belonging to the same bundle group". Every offer and answer this
/// engine writes, initial and later, has it so (at the session level, which applies to every
/// section), whether the BUNDLE attributes are repeated in every bundled section (the default)
/// or written in the tagged section only (RFC 9143 section 7.1.3,
/// `with_bundle_attributes_repeated(false)`): the latter form does not take `a=cryptex` off
/// the other RTP sections.
#[test]
fn every_written_offer_and_answer_has_cryptex_for_every_bundled_rtp_section() -> TestResult {
    use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;
    for repeated in [true, false] {
        let settings = || {
            SettingEngineBuilder::new()
                .with_bundle_attributes_repeated(repeated)
                .build()
        };
        let mut a = peer_with(settings())?;
        let mut b = peer_with(settings())?;
        a.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
        a.add_track(video_track("first", 0x0c0c_0030))?;
        a.add_track(video_track("second", 0x0c0c_0031))?;
        let (offer, answer) = jsep_common::exchange(&mut a, &mut b)?;
        let (re_offer, re_answer) = jsep_common::exchange(&mut b, &mut a)?;
        for (what, sdp) in [
            ("offer", offer),
            ("answer", answer),
            ("later offer", re_offer),
            ("later answer", re_answer),
        ] {
            assert!(sdp.contains("a=group:BUNDLE 0 1 2"), "{what}:\n{sdp}");
            let session_level = sdp
                .lines()
                .take_while(|l| !l.starts_with("m="))
                .any(|l| l == "a=cryptex");
            let sections = jsep_common::media_sections(&sdp);
            let rtp: Vec<_> = sections
                .iter()
                .filter(|s| s[0].starts_with("m=audio") || s[0].starts_with("m=video"))
                .collect();
            assert_eq!(rtp.len(), 3, "{what}:\n{sdp}");
            assert!(
                session_level || rtp.iter().all(|s| s.iter().any(|l| l == "a=cryptex")),
                "{what}, repeated {repeated}: a=cryptex not present for every RTP section:\n{sdp}"
            );
        }
        assert!(a.cryptex_negotiated() && b.cryptex_negotiated());
    }
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

/// W3C webrtc-extensions 10.2: `rtpHeaderEncryptionPolicy` defaults to "negotiate": Cryptex
/// is offered and used when the peer signals it, and a peer that does not is accepted, the
/// header extensions (MID, RtpStreamId among them) then going in the clear. This is the
/// default; RFC 7941 section 6's form (SDES header extensions only protected) is the
/// "require" policy (`require_refuses_an_answer_without_cryptex`,
/// `require_refuses_an_offer_without_cryptex`).
#[test]
fn by_default_cryptex_is_negotiated_and_a_peer_without_it_is_accepted() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.add_track(video_track("video", 0x0c0c_0020))?;
    let mut with = default_peer()?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    assert!(offer.sdp.contains("a=cryptex"), "{}", offer.sdp);
    jsep_common::exchange(&mut offerer, &mut with)?;
    assert!(offerer.cryptex_negotiated() && with.cryptex_negotiated());

    let mut offerer = default_peer()?;
    offerer.add_track(video_track("video", 0x0c0c_0021))?;
    let mut without = default_peer()?;
    without.set_rtp_header_encryption_policy(RTCRtpHeaderEncryptionPolicy::Disable)?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    without.set_remote_description(now, offer)?;
    let answer = without.create_answer(None)?;
    without.set_local_description(now, answer.clone())?;
    offerer.set_remote_description(now, answer)?;
    assert!(offerer.remote_description().is_some(), "accepted");
    assert!(!offerer.cryptex_negotiated());
    Ok(())
}

/// A peer with the default codecs and the MID header extension for video.
fn peer_with_mid() -> Result<rtci::peer_connection::RTCPeerConnection, Box<dyn std::error::Error>> {
    use rtci::peer_connection::configuration::media_engine::MediaEngine;
    use rtci::rtp_transceiver::rtp_sender::{RTCRtpHeaderExtensionCapability, RtpCodecKind};
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: MID_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;
    Ok(rtci::peer_connection::RTCPeerConnectionBuilder::new()
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
            rtci::peer_connection::sdp::RTCSessionDescription::offer(edited)?,
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
    use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;
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
            rtci::peer_connection::sdp::RTCSessionDescription::offer(edited.clone())?,
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
        Ok(rtci::peer_connection::sdp::RTCSessionDescription::offer(
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

/// An initial offer whose first BUNDLE section is the data section, so that every RTP section
/// is bundle-only: Chromium's form under `max-bundle` when the data channel is created before
/// the tracks (its sections follow the order of creation). RFC 9429 section 7.2 has the data
/// section last, but a remote offer may have this order (RFC 9143 section 7.2.1 only keeps a
/// bundle-only section from being the tagged one). `a=cryptex` is at the session level
/// (RFC 9335 section 4). The audio section keeps `a=rtcp-mux`, as Chromium writes it.
const DATA_TAGGED_OFFER: &str = "v=0\r\n\
o=- 8490950831739317391 2 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0 1\r\n\
a=extmap-allow-mixed\r\n\
a=msid-semantic: WMS\r\n\
a=cryptex\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:QwQB\r\n\
a=ice-pwd:tOn0RB6FrcSYzfnZIDlWSXtF\r\n\
a=ice-options:trickle\r\n\
a=fingerprint:sha-256 B6:B6:C4:EF:FC:EF:D5:63:72:4D:C4:1C:AE:C1:E5:FC:D6:B4:B5:A0:1D:65:C0:D9:1E:20:CA:55:8D:F5:FB:6C\r\n\
a=setup:actpass\r\n\
a=mid:0\r\n\
a=sctp-port:5000\r\n\
a=max-message-size:262144\r\n\
m=audio 0 UDP/TLS/RTP/SAVPF 111\r\n\
c=IN IP4 0.0.0.0\r\n\
a=bundle-only\r\n\
a=mid:1\r\n\
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n\
a=sendrecv\r\n\
a=msid:- 96c45fbe-5e47-49b1-99eb-6ff28b2698ef\r\n\
a=rtcp-mux\r\n\
a=rtcp-rsize\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=fmtp:111 minptime=10;useinbandfec=1\r\n\
a=ssrc:3658638092 cname:YmhmZ0Dm8r6a5166\r\n";

/// RFC 9335 section 4 with RFC 9143 section 7.2: a bundle-only RTP section (port zero with
/// `a=bundle-only`) of an offer is a live RTP section of the BUNDLE group, so Cryptex applies to
/// it as to any other. With every RTP section bundle-only, the default answerer answers
/// `a=cryptex` and negotiates it, and a `Require` answerer takes the offer. 0.2.0 counted only
/// RTP sections with a port: such an offer had no RTP section, so no Cryptex; the answer
/// went without it and `Require` refused the offer (ErrSessionDescriptionMissingCryptex).
#[test]
fn cryptex_applies_to_bundle_only_rtp_sections_of_a_data_tagged_offer() -> TestResult {
    let offer =
        || rtci::peer_connection::sdp::RTCSessionDescription::offer(DATA_TAGGED_OFFER.to_owned());
    let now = Instant::now();

    let mut answerer = default_peer()?;
    answerer.set_remote_description(now, offer()?)?;
    let answer = answerer.create_answer(None)?;
    assert!(
        answer.sdp.contains("\r\nm=audio 9 "),
        "the bundle-only audio section is accepted: {}",
        answer.sdp
    );
    assert!(
        answer.sdp.contains("\r\na=cryptex\r\n"),
        "the offer has Cryptex for its only RTP section, which is bundle-only: {}",
        answer.sdp
    );
    answerer.set_local_description(now, answer)?;
    assert!(answerer.cryptex_negotiated());

    let mut required = default_peer()?;
    required.set_rtp_header_encryption_policy(RTCRtpHeaderEncryptionPolicy::Require)?;
    required.set_remote_description(now, offer()?)?;
    let answer = required.create_answer(None)?;
    assert!(answer.sdp.contains("\r\na=cryptex\r\n"), "{}", answer.sdp);
    Ok(())
}
