//! RFC 9429 clauses that hold by construction and had no test of their own: configuration
//! defaults, what is fixed after construction, the shape of offers and answers, and what a
//! received description may and may not carry.

mod jsep_common;

use std::time::Instant;

use jsep_common::{
    SESSION, TRANSPORT, TestResult, crlf, default_peer, exchange, media_sections, video_track,
};
use rtc::peer_connection::configuration::{
    RTCBundlePolicy, RTCConfigurationBuilder, RTCIceTransportPolicy, RTCRtcpMuxPolicy,
};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::RTCIceCandidateInit;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;

const HOST: &str = "candidate:1 1 udp 2130706431 10.0.0.9 5000 typ host";

/// RFC 9429 section 4.1.1: the ICE candidate policy is `all` by default, "the default size
/// of the ICE candidate pool MUST be zero", and the RTCP mux policy is `require` by default
/// (the bundle policy `balanced`).
#[test]
fn the_configuration_defaults_are_all_require_balanced_and_no_pool() -> TestResult {
    let pc = default_peer()?;
    let configuration = pc.get_configuration();
    assert_eq!(
        configuration.ice_transport_policy(),
        RTCIceTransportPolicy::All
    );
    assert_eq!(configuration.rtcp_mux_policy(), RTCRtcpMuxPolicy::Require);
    assert_eq!(configuration.bundle_policy(), RTCBundlePolicy::Balanced);
    assert_eq!(configuration.ice_candidate_pool_size(), 0);
    Ok(())
}

/// RFC 9429 section 4.1.18: the bundle and RTCP mux policies "MUST NOT" change after
/// construction: another value is refused, the same one taken.
#[test]
fn the_bundle_and_rtcp_mux_policies_cannot_change() -> TestResult {
    let mut pc = default_peer()?;
    let refused = pc.set_configuration(
        RTCConfigurationBuilder::new()
            .with_bundle_policy(RTCBundlePolicy::MaxBundle)
            .build(),
    );
    assert!(refused.is_err(), "{refused:?}");
    let refused = pc.set_configuration(
        RTCConfigurationBuilder::new()
            .with_rtcp_mux_policy(RTCRtcpMuxPolicy::Negotiate)
            .build(),
    );
    assert!(refused.is_err(), "{refused:?}");
    pc.set_configuration(RTCConfigurationBuilder::new().build())?;
    Ok(())
}

/// RFC 9429 section 4.1.19: "This method can only be called once a remote description has
/// been set": a candidate before one is refused.
#[test]
fn a_remote_candidate_needs_a_remote_description() -> TestResult {
    let mut pc = default_peer()?;
    let refused = pc.add_remote_candidate(RTCIceCandidateInit {
        candidate: HOST.to_owned(),
        sdp_mid: Some("0".to_owned()),
        ..Default::default()
    });
    assert!(refused.is_err());
    Ok(())
}

fn with_remote_video_offer()
-> Result<rtc::peer_connection::RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut pc = default_peer()?;
    let offer = crlf(&format!(
        "{SESSION}m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:v\na=sendrecv\n\
         a=rtpmap:96 VP8/90000\n"
    ));
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    Ok(pc)
}

/// RFC 9429 section 3.5.2.1: the MID "MUST" identify the m= section, ahead of the index; the
/// candidate's other fields are optional and a candidate "MUST NOT" be refused for lacking
/// them. A mid that names the section with an index that names none is taken; a candidate
/// with a mid and nothing else is taken; a mid that names no section is refused.
#[test]
fn a_candidates_mid_identifies_its_section_and_the_other_fields_are_optional() -> TestResult {
    let mut pc = with_remote_video_offer()?;
    pc.add_remote_candidate(RTCIceCandidateInit {
        candidate: HOST.to_owned(),
        sdp_mid: Some("v".to_owned()),
        sdp_mline_index: Some(7),
        ..Default::default()
    })?;
    pc.add_remote_candidate(RTCIceCandidateInit {
        candidate: "candidate:2 1 udp 2130706430 10.0.0.9 5001 typ host".to_owned(),
        sdp_mid: Some("v".to_owned()),
        ..Default::default()
    })?;
    let refused = pc.add_remote_candidate(RTCIceCandidateInit {
        candidate: "candidate:3 1 udp 2130706429 10.0.0.9 5002 typ host".to_owned(),
        sdp_mid: Some("nope".to_owned()),
        sdp_mline_index: Some(0),
        ..Default::default()
    });
    assert!(refused.is_err(), "the mid wins over a valid index");
    Ok(())
}

/// RFC 9429 section 5.1.1: "SDES keying MUST NOT be used": no `a=crypto` is offered, and an
/// offer that has one (beside the fingerprint) is answered with DTLS-SRTP and no `a=crypto`.
/// Section 5.2.1: "a=crypto", "a=key-mgmt" "MUST NOT be included".
#[test]
fn sdes_keying_is_never_offered_nor_answered() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = offerer.create_offer(None)?.sdp;
    assert!(
        !offer.contains("a=crypto") && !offer.contains("a=key-mgmt"),
        "{offer}"
    );

    let mut pc = default_peer()?;
    let offer = crlf(&format!(
        "{SESSION}m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=sendrecv\n\
         a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz\n\
         a=rtpmap:96 VP8/90000\n"
    ));
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = pc.create_answer(None)?.sdp;
    assert!(!answer.contains("a=crypto"), "{answer}");
    assert!(answer.contains("a=fingerprint:"), "{answer}");
    Ok(())
}

/// RFC 9429 section 5.1.2: whether a section is DTLS-SRTP is judged by `a=fingerprint`, not
/// by its profile: `RTP/AVPF` with a fingerprint is taken and answered with that profile
/// (section 5.1.2: the answer's profile "MUST exactly match"); without any fingerprint the
/// description cannot be secured and is refused.
#[test]
fn dtls_srtp_is_judged_by_the_fingerprint_not_the_profile() -> TestResult {
    let mut pc = default_peer()?;
    let offer = crlf(&format!(
        "{SESSION}m=video 9 RTP/AVPF 96\n{TRANSPORT}a=mid:0\na=sendrecv\na=rtpmap:96 VP8/90000\n"
    ));
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = pc.create_answer(None)?.sdp;
    assert!(
        media_sections(&answer)[0][0].starts_with("m=video 9 RTP/AVPF "),
        "{answer}"
    );

    let mut pc = default_peer()?;
    let unsecured = crlf(&format!(
        "{SESSION}m=video 9 UDP/TLS/RTP/SAVPF 96\n{}a=mid:0\na=sendrecv\na=rtpmap:96 VP8/90000\n",
        TRANSPORT
            .lines()
            .filter(|l| !l.starts_with("a=fingerprint"))
            .map(|l| format!("{l}\n"))
            .collect::<String>()
    ));
    assert!(
        pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(unsecured)?)
            .is_err()
    );
    Ok(())
}

/// RFC 9429 sections 5.2.1 and 5.3.1: before candidates the m= port is 9 (Discard), the m=
/// line is followed immediately by `c=IN IP4 0.0.0.0`, and an offer says
/// `a=setup:actpass`; an answer says `active` or `passive`.
#[test]
fn sections_start_with_port_9_and_the_null_connection_line() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("v", 0x0e0b_0101))?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    for (sdp, setup) in [(&offer, "a=setup:actpass"), (&answer, "a=setup:active")] {
        for section in media_sections(sdp) {
            let fields: Vec<&str> = section[0].split_whitespace().collect();
            assert_eq!(fields[1], "9", "{sdp}");
            assert_eq!(section[1], "c=IN IP4 0.0.0.0", "{sdp}");
            assert!(section.iter().any(|l| l == setup), "{sdp}");
        }
    }
    Ok(())
}

/// RFC 9429 sections 5.2.2 and 5.3.2: in a subsequent offer or answer "The <session-version>
/// field MUST be incremented ... The "s=" and "t=" lines MUST stay the same".
#[test]
fn subsequent_descriptions_keep_the_session_name_and_time() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("v", 0x0e0c_0101))?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let (reoffer, reanswer) = exchange(&mut offerer, &mut answerer)?;
    let line = |sdp: &str, prefix: &str| -> String {
        sdp.lines()
            .find(|l| l.starts_with(prefix))
            .unwrap_or_else(|| panic!("a {prefix} line in {sdp}"))
            .to_owned()
    };
    for (first, later) in [(&offer, &reoffer), (&answer, &reanswer)] {
        assert_eq!(line(first, "s="), line(later, "s="));
        assert_eq!(line(first, "t="), line(later, "t="));
    }
    Ok(())
}

/// RFC 9429 section 5.3.1: an answer has no `a=bundle-only` ("MUST NOT" add one), even to an
/// offer whose bundle-only section it accepts.
#[test]
fn answers_have_no_bundle_only_line() -> TestResult {
    let mut pc = default_peer()?;
    let offer = crlf(&format!(
        "{SESSION}a=group:BUNDLE 0 1\n\
         m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=sendrecv\na=rtpmap:96 VP8/90000\n\
         m=video 0 UDP/TLS/RTP/SAVPF 96\nc=IN IP4 0.0.0.0\na=bundle-only\na=mid:1\na=sendrecv\n\
         a=rtpmap:96 VP8/90000\n"
    ));
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = pc.create_answer(None)?.sdp;
    assert_eq!(media_sections(&answer).len(), 2, "{answer}");
    assert!(!answer.contains("a=bundle-only"), "{answer}");
    Ok(())
}

/// RFC 9429 section 5.3.1: "If no remote description has been set, an error MUST be
/// returned" by createAnswer.
#[test]
fn create_answer_without_a_remote_offer_is_an_error() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    assert!(pc.create_answer(None).is_err());
    Ok(())
}

/// RFC 9429 section 5.2.1: the <sess-id> "SHOULD" be "a 64-bit quantity with the highest bit
/// set to zero and the remaining 63 bits being cryptographically random": two connections'
/// ids fit in 63 bits and differ.
#[test]
fn the_session_id_is_63_random_bits() -> TestResult {
    let sess_id = || -> Result<u64, Box<dyn std::error::Error>> {
        let mut pc = default_peer()?;
        pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
        let offer = pc.create_offer(None)?.sdp;
        let origin = offer
            .lines()
            .find_map(|l| l.strip_prefix("o="))
            .expect("an o= line");
        Ok(origin.split_whitespace().nth(1).expect("sess-id").parse()?)
    };
    let (a, b) = (sess_id()?, sess_id()?);
    assert!(a < 1 << 63 && b < 1 << 63);
    assert_ne!(a, b);
    Ok(())
}
