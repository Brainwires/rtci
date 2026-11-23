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

/// RFC 9429 section 5.2.1: "the 'a=crypto', 'a=key-mgmt' and 'a=ice-lite' attributes MUST NOT
/// be included" in an offer, nor (section 5.3.1) in an answer. A default offer of audio,
/// video and a data channel, and the answer to it, have none of the three, at either level.
/// (`SettingEngineBuilder::with_lite(true)` is a server option outside JSEP; it writes
/// `a=ice-lite`.)
#[test]
fn a_default_offer_and_answer_have_no_crypto_key_mgmt_or_ice_lite() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    offerer.create_data_channel("data", None)?;
    let mut answerer = default_peer()?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    for (what, sdp) in [("offer", &offer), ("answer", &answer)] {
        for line in sdp.lines() {
            assert!(
                !["a=crypto", "a=key-mgmt", "a=ice-lite"]
                    .iter()
                    .any(|forbidden| line.starts_with(forbidden)),
                "the {what} has {line}:\n{sdp}"
            );
        }
    }
    Ok(())
}

/// RFC 8839 section 5.1: a candidate line is read by its grammar, also when it is trickled
/// (`addIceCandidate`) rather than in a description. Lines the rtc-ice reader would take but
/// the grammar refuses are refused: a foundation longer than 32 ice-chars or with another
/// character, a priority of more than 10 digits, `type` for `typ`, an extension without a
/// value, a second `raddr`. A line with `raddr` / `rport`, extensions and an mDNS name is
/// taken.
#[test]
fn a_trickled_candidate_is_checked_against_the_candidate_grammar() -> TestResult {
    let mut pc = with_remote_video_offer()?;
    let add = |pc: &mut rtc::peer_connection::RTCPeerConnection, line: &str| {
        pc.add_remote_candidate(RTCIceCandidateInit {
            candidate: line.to_owned(),
            sdp_mid: Some("v".to_owned()),
            ..Default::default()
        })
    };
    for line in [
        &format!(
            "candidate:{} 1 udp 2130706431 10.0.0.9 5000 typ host",
            "f".repeat(33)
        ),
        "candidate:f-1 1 udp 2130706431 10.0.0.9 5000 typ host",
        "candidate:1 1 udp 21307064310 10.0.0.9 5000 typ host",
        "candidate:1 1 udp 2130706431 10.0.0.9 5000 type host",
        "candidate:1 1 udp 2130706431 10.0.0.9 5000 typ host generation",
        "candidate:1 1 udp 1694498815 192.0.2.3 5000 typ srflx raddr 10.0.0.9 rport 5000 \
         raddr 10.0.0.8",
    ] {
        assert!(add(&mut pc, line).is_err(), "{line}");
    }
    add(
        &mut pc,
        "candidate:1 1 udp 1694498815 192.0.2.3 5000 typ srflx raddr 10.0.0.9 rport 5000 \
         generation 0 ufrag 4ZcD network-cost 10",
    )?;
    add(
        &mut pc,
        "candidate:2 1 udp 2130706431 61b445d2-6503-41ac-96ce-ee3edac00e9f.local 5002 typ host",
    )?;
    Ok(())
}

/// RFC 9429 section 5.3.1: the answer's session-level lines are generated "as specified in
/// Section 5.2.1": `v=0` first, then an `o=` line whose session id is below 2^63 - 1, `s=`
/// third, no `k=`, a `t=` line, and `a=ice-options` with `trickle` and `ice2` (RFC 8840
/// section 4.1.1, RFC 8445 section 10).
#[test]
fn the_answers_session_lines_follow_the_offer_rules() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    offerer.create_data_channel("data", None)?;
    let mut answerer = default_peer()?;
    let (_, answer) = exchange(&mut offerer, &mut answerer)?;
    let lines: Vec<&str> = answer.lines().collect();
    assert_eq!(lines[0], "v=0", "{answer}");
    let origin: Vec<&str> = lines[1]
        .strip_prefix("o=")
        .expect("o= second")
        .split(' ')
        .collect();
    assert_eq!(origin.len(), 6, "{answer}");
    let session_id: u64 = origin[1].parse()?;
    assert!(session_id < (1 << 63) - 1, "{answer}");
    assert!(lines[2].starts_with("s="), "{answer}");
    let session: Vec<&str> = lines
        .iter()
        .take_while(|l| !l.starts_with("m="))
        .copied()
        .collect();
    assert!(session.iter().any(|l| l.starts_with("t=")), "{answer}");
    assert!(!session.iter().any(|l| l.starts_with("k=")), "{answer}");
    let options: Vec<&str> = session
        .iter()
        .filter_map(|l| l.strip_prefix("a=ice-options:"))
        .flat_map(|v| v.split(' '))
        .collect();
    assert!(
        options.contains(&"trickle") && options.contains(&"ice2"),
        "{answer}"
    );
    Ok(())
}

/// RFC 9429 section 5.1.2: offered media sections say `UDP/TLS/RTP/SAVPF` or
/// `TCP/DTLS/RTP/SAVPF` (RFC 7850), "determined by the protocol associated with the current
/// default or selected ICE candidate". With only a TCP candidate gathered the offer's audio
/// section says `TCP/DTLS/RTP/SAVPF` (and its data section `TCP/DTLS/SCTP`), the answer repeats
/// the profile ("MUST exactly match"); once a UDP candidate is there it is the default and the
/// offer says `UDP/TLS/RTP/SAVPF`.
#[test]
fn the_offered_media_profile_follows_the_default_candidates_protocol() -> TestResult {
    let proto = |sdp: &str, media: &str| -> String {
        sdp.lines()
            .find(|l| l.starts_with(&format!("m={media} ")))
            .and_then(|l| l.split(' ').nth(2))
            .unwrap_or_else(|| panic!("an m={media} line in\n{sdp}"))
            .to_owned()
    };
    let mut pc = default_peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    pc.create_data_channel("data", None)?;
    pc.add_local_candidate(RTCIceCandidateInit {
        candidate: "candidate:1 1 tcp 1518280447 10.0.0.9 5000 typ host tcptype passive".to_owned(),
        ..Default::default()
    })?;
    let offer = pc.create_offer(None)?;
    assert_eq!(
        proto(&offer.sdp, "audio"),
        "TCP/DTLS/RTP/SAVPF",
        "{}",
        offer.sdp
    );
    assert_eq!(proto(&offer.sdp, "application"), "TCP/DTLS/SCTP");
    let mut answerer = default_peer()?;
    answerer.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.create_answer(None)?;
    assert_eq!(
        proto(&answer.sdp, "audio"),
        "TCP/DTLS/RTP/SAVPF",
        "{}",
        answer.sdp
    );

    pc.add_local_candidate(RTCIceCandidateInit {
        candidate: HOST.to_owned(),
        ..Default::default()
    })?;
    let offer = pc.create_offer(None)?;
    assert_eq!(
        proto(&offer.sdp, "audio"),
        "UDP/TLS/RTP/SAVPF",
        "{}",
        offer.sdp
    );
    Ok(())
}
