//! The default destination of a media section: `m=` port, `c=` address and `a=rtcp` (RFC
//! 8839 section 4.2.1.2, RFC 3605 section 2.1, RFC 9429 sections 5.2.1, 5.2.2, 5.3.1 and
//! 5.3.2, RFC 9143 section 7.2).

mod jsep_common;

use jsep_common::{TestResult, default_peer, exchange, media_sections, mid_of, port_of};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::transport::RTCIceCandidateInit;
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;

fn add_candidate(pc: &mut RTCPeerConnection, candidate: &str) -> TestResult {
    pc.add_local_candidate(RTCIceCandidateInit {
        candidate: candidate.to_owned(),
        ..Default::default()
    })?;
    Ok(())
}

const HOST: &str = "candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host";
const SRFLX: &str =
    "candidate:2 1 udp 1694498815 203.0.113.7 6000 typ srflx raddr 10.0.0.1 rport 5000";

/// The section's `c=` and `a=rtcp` lines.
fn destination(section: &[String]) -> (Option<&str>, Vec<&str>) {
    (
        section.iter().find_map(|l| l.strip_prefix("c=")),
        section
            .iter()
            .filter_map(|l| l.strip_prefix("a=rtcp:"))
            .collect(),
    )
}

/// RFC 9429 section 5.2.1: an initial offer has `a=rtcp:9 IN IP4 0.0.0.0` "because no
/// candidates have yet been gathered", with port 9 and `c=IN IP4 0.0.0.0`.
#[test]
fn an_initial_offer_without_candidates_has_the_dummy_destination() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let offer = pc.create_offer(None)?.sdp;
    for section in media_sections(&offer) {
        assert_eq!(9, port_of(&section), "{offer}");
        assert_eq!(
            (Some("IN IP4 0.0.0.0"), vec!["9 IN IP4 0.0.0.0"]),
            destination(&section),
            "{offer}"
        );
    }
    Ok(())
}

/// RFC 8839 section 4.2.1.2: the `m=` / `c=` lines carry the default candidate, "the
/// relayed candidate (if ...), server-reflexive candidates (if available), and finally host
/// candidates"; the `a=rtcp` line follows (RFC 5761 section 5.1.3). RFC 9143 section 7.2:
/// every bundled section that is not bundle-only has an address of its own: under `balanced`
/// the video section, the first of its type, is a transport of its own (RFC 9429 section
/// 5.2.1), which has gathered nothing, so it keeps the dummy destination.
#[test]
fn an_offer_with_candidates_states_the_default_candidate_in_each_bundled_section() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    add_candidate(&mut pc, HOST)?;
    let offer = pc.create_offer(None)?.sdp;
    let sections = media_sections(&offer);
    assert_eq!(5000, port_of(&sections[0]), "{offer}");
    assert_eq!(
        (Some("IN IP4 10.0.0.1"), vec!["5000 IN IP4 10.0.0.1"]),
        destination(&sections[0]),
        "{offer}"
    );
    assert_eq!(9, port_of(&sections[1]), "{offer}");
    assert_eq!(
        (Some("IN IP4 0.0.0.0"), vec!["9 IN IP4 0.0.0.0"]),
        destination(&sections[1]),
        "the video transport's own (dummy) destination: {offer}"
    );

    add_candidate(&mut pc, SRFLX)?;
    let offer = pc.create_offer(None)?.sdp;
    let section = &media_sections(&offer)[0];
    assert_eq!(6000, port_of(section), "server-reflexive wins: {offer}");
    assert_eq!(Some("IN IP4 203.0.113.7"), destination(section).0);
    Ok(())
}

/// RFC 9429 section 5.2.2: "The "a=rtcp" line MUST NOT be added if the most recent answer
/// included an "a=rtcp-mux" line"; section 5.3.1: an answer to an offer with `a=rtcp-mux`
/// has `a=rtcp-mux`, not `a=rtcp`. Both still carry the default candidate (section 5.3.2).
#[test]
fn answers_and_later_offers_have_no_rtcp_line_and_the_default_candidate() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let mut answerer = default_peer()?;
    add_candidate(&mut answerer, HOST)?;
    let (_, answer) = exchange(&mut offerer, &mut answerer)?;
    assert!(
        answer.contains("a=ice-options:trickle ice2\r\n"),
        "{answer}"
    );
    let sections = media_sections(&answer);
    assert_eq!(Some("0"), mid_of(&sections[0]));
    assert_eq!(5000, port_of(&sections[0]), "{answer}");
    assert_eq!(
        (Some("IN IP4 10.0.0.1"), vec![]),
        destination(&sections[0]),
        "{answer}"
    );

    let reoffer = offerer.create_offer(None)?.sdp;
    assert!(
        destination(&media_sections(&reoffer)[0]).1.is_empty(),
        "{reoffer}"
    );
    Ok(())
}
