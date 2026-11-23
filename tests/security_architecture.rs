//! Engine-level rows of the WebRTC security architecture (RFC 8827) and its security
//! considerations (RFC 8826) that hold by construction, pinned by a test each.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{
    Peer, World, attribute_values, keep, replace_lines, session_part, with_session_line,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::shared::error::Error;
use std::collections::HashSet;
use std::time::{Duration, Instant};

fn peer(addr: &str) -> Result<Peer> {
    Peer::new(addr, SettingEngineBuilder::new().build())
}

fn world() -> Result<World> {
    Ok(World::new(peer("10.0.0.1:5000")?, peer("10.0.0.2:5000")?))
}

/// RFC 8827 section 6.3 / RFC 8826 section 4.2.1: "implementations MUST NOT send any non-ICE
/// packets to a peer until that peer's consent has been verified via ICE". With the offer and
/// answer applied, candidates exchanged, a data channel waiting and a message queued on it,
/// but no connectivity check answered (the network is cut), every datagram either peer writes
/// is STUN: first byte 0 to 3 (RFC 7983), with the magic cookie. No DTLS ClientHello, no SCTP,
/// no RTP.
#[test]
fn only_stun_is_sent_before_ice_has_verified_consent() -> Result<()> {
    let mut world = world()?;
    world.peers[0].pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(rtc::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;
    world.peers[0].pc.create_data_channel("data", None)?;
    world.exchange(0)?;
    world.trickle()?;
    world.connected = false;
    world.run_for(Duration::from_secs(10), |_| false);
    for (i, peer) in world.peers.iter().enumerate() {
        assert!(!peer.written.is_empty(), "peer {i} sent its checks");
        for datagram in &peer.written {
            assert!(
                datagram.len() >= 20
                    && datagram[0] <= 3
                    && datagram[4..8] == [0x21, 0x12, 0xa4, 0x42],
                "peer {i} sent something that is not STUN before consent: {:02x?}",
                &datagram[..datagram.len().min(16)]
            );
        }
        assert!(!peer.connected(), "peer {i}");
    }
    Ok(())
}

/// RFC 8827 section 6.4: the API lets the application "suppress ICE negotiation (though perhaps
/// to allow candidate gathering) until the user has decided to answer the call". The engine
/// sends nothing at all, with its candidates gathered and its offer applied, until the remote
/// description is: the application decides when that is.
#[test]
fn nothing_is_sent_before_the_remote_description_is_applied() -> Result<()> {
    let mut world = world()?;
    world.peers[0].pc.create_data_channel("data", None)?;
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    let candidate = world.peers[0].candidate()?;
    world.peers[0].pc.add_local_candidate(candidate)?;
    // The called side has the offer and its own candidates, and has not answered.
    let candidate = world.peers[1].candidate()?;
    world.peers[1].pc.add_local_candidate(candidate)?;
    world.run_for(Duration::from_secs(10), |_| false);
    assert!(
        world.peers[0].written.is_empty(),
        "the offerer sent something"
    );
    assert!(
        world.peers[1].written.is_empty(),
        "the callee sent something"
    );
    Ok(())
}

/// RFC 8827 section 6.5: "the implementation MUST generate a new authentication key pair for
/// every new call by default". Every peer connection built without a certificate has its own:
/// no two of them announce the same fingerprint.
#[test]
fn every_connection_has_a_new_key_pair_by_default() -> Result<()> {
    let mut fingerprints = HashSet::new();
    for _ in 0..20 {
        let mut offerer = peer("10.0.0.1:5000")?;
        offerer.pc.create_data_channel("data", None)?;
        let offer = offerer.pc.create_offer(None)?.sdp;
        let mut values = attribute_values(&offer, "fingerprint");
        assert_eq!(values.len(), 1, "{offer}");
        fingerprints.insert(values.remove(0));
    }
    assert_eq!(fingerprints.len(), 20);
    Ok(())
}

/// RFC 8827 section 6.5: "Implementations MUST offer DTLS-SRTP for every media channel" and
/// "MUST NOT offer SDP security descriptions [RFC4568]": every media section of an offer and
/// of its answer is `UDP/TLS/RTP/SAVPF` (the data section `UDP/DTLS/SCTP`), with a fingerprint
/// and a setup attribute in force, and no `a=crypto` anywhere.
#[test]
fn dtls_srtp_is_offered_for_every_media_section() -> Result<()> {
    let mut world = world()?;
    world.peers[0].pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(rtc::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;
    world.peers[0].pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(rtc::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;
    world.peers[0].pc.create_data_channel("data", None)?;
    let (offer, answer) = world.exchange(0)?;
    // RFC 8859 puts `a=setup` and `a=fingerprint` in the TRANSPORT category: the one of the
    // tagged section of the BUNDLE group is in force for every bundled section (RFC 9143
    // section 7.1.3), whether or not the others repeat it. So the tagged section (the first:
    // `a=group:BUNDLE 0 ...`) states a role, every role stated is the same one, and so is
    // every fingerprint.
    for sdp in [offer, answer] {
        let sections: Vec<&str> = sdp.split("\r\nm=").skip(1).collect();
        assert!(sections[0].contains("\r\na=setup:"), "{sdp}");
        let roles = attribute_values(&sdp, "setup");
        assert!(roles.iter().all(|role| role == &roles[0]), "{sdp}");
        let media_lines: Vec<&str> = sdp.lines().filter(|line| line.starts_with("m=")).collect();
        assert_eq!(media_lines.len(), 3, "{sdp}");
        for line in media_lines {
            let proto = line.split(' ').nth(2).expect("a proto");
            if line.starts_with("m=application") {
                assert_eq!(proto, "UDP/DTLS/SCTP", "{line}");
            } else {
                assert_eq!(proto, "UDP/TLS/RTP/SAVPF", "{line}");
            }
        }
        assert!(!sdp.contains("a=crypto"), "{sdp}");
        // One certificate: every fingerprint line (one per section, RFC 9429 section 5.2.1's
        // media level) states the same one.
        let fingerprints = attribute_values(&sdp, "fingerprint");
        assert!(!fingerprints.is_empty(), "{sdp}");
        assert!(fingerprints.iter().all(|f| f == &fingerprints[0]), "{sdp}");
        assert!(sdp.contains("a=group:BUNDLE "), "{sdp}");
    }
    Ok(())
}

/// RFC 8827 section 6.5: SDP security descriptions are never selected. An offer that carries
/// `a=crypto` lines next to its fingerprint is answered with DTLS-SRTP and no `a=crypto`, and
/// the keys come from the DTLS handshake (the association is established and reports its SRTP
/// profile); an offer with `a=crypto` and no fingerprint is refused.
#[test]
fn sdp_security_descriptions_are_not_used() -> Result<()> {
    const CRYPTO: &str =
        "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj";
    let with_crypto =
        |sdp: &str| sdp.replace("a=rtcp-mux\r\n", &format!("a=rtcp-mux\r\n{CRYPTO}\r\n"));

    let mut world = world()?;
    world.peers[0].pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(rtc::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;
    world.peers[0].pc.create_data_channel("data", None)?;
    let (offer, answer) = world.exchange_with(0, with_crypto, keep)?;
    assert!(with_crypto(&offer).contains(CRYPTO));
    assert!(!answer.contains("a=crypto"), "{answer}");
    assert!(answer.contains("m=audio 9 UDP/TLS/RTP/SAVPF"), "{answer}");
    world.trickle()?;
    world.run("DTLS-SRTP", |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    let now = world.now;
    for i in 0..2 {
        assert_eq!(world.peers[i].srtp_cipher(now), "SRTP_AEAD_AES_128_GCM");
    }

    let mut offerer = peer("10.0.0.1:5000")?;
    offerer.pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(rtc::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;
    let offer = offerer.pc.create_offer(None)?.sdp;
    let sdes_only = replace_lines(&with_crypto(&offer), "a=fingerprint:", None);
    let mut answerer = peer("10.0.0.2:5000")?;
    assert_eq!(
        answerer
            .pc
            .set_remote_description(Instant::now(), RTCSessionDescription::offer(sdes_only)?),
        Err(Error::ErrSessionDescriptionNoFingerprint)
    );
    Ok(())
}

/// RFC 8827 section 5: the `a=identity` attribute is session-level, and "implementations
/// SHOULD only include a single 'identity' attribute in an offer or answer". The engine carries
/// the assertion the application gives it, in every offer and answer, once; the receiver reads
/// the first one ("Relying Parties MAY elect to ignore all but the first").
#[test]
fn the_identity_assertion_is_carried_in_offers_and_answers() -> Result<()> {
    // RFC 8827 section 5's example value.
    const ASSERTION: &str = "eyJpZHAiOnsiZG9tYWluIjoiZXhhbXBsZS5vcmciLCJwcm90b2NvbCI6ImJvZ3Vz\
        In0sImFzc2VydGlvbiI6IntcImlkZW50aXR5XCI6XCJib2JAZXhhbXBsZS5vcmdc\
        IixcImNvbnRlbnRzXCI6XCJhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3l6XCIsXCJz\
        aWduYXR1cmVcIjpcIjAxMDIwMzA0MDUwNlwifSJ9";
    const ANSWERER_ASSERTION: &str = "YW5zd2VyZXI=";

    let mut world = world()?;
    assert!(world.peers[0].pc.remote_identity_assertion().is_none());
    world.peers[0]
        .pc
        .set_identity_assertion(Some(ASSERTION.to_owned()))?;
    world.peers[1]
        .pc
        .set_identity_assertion(Some(ANSWERER_ASSERTION.to_owned()))?;
    let (offer, answer) = world.connect()?;
    for (sdp, assertion) in [(&offer, ASSERTION), (&answer, ANSWERER_ASSERTION)] {
        assert_eq!(attribute_values(sdp, "identity"), [assertion], "{sdp}");
        assert!(
            session_part(sdp).contains("a=identity:"),
            "session level:\n{sdp}"
        );
    }
    assert_eq!(
        world.peers[1].pc.remote_identity_assertion(),
        Some(ASSERTION)
    );
    assert_eq!(
        world.peers[0].pc.remote_identity_assertion(),
        Some(ANSWERER_ASSERTION)
    );

    // Section 5.1.4: the fingerprints are unchanged, so the same attribute is sent again; a
    // cleared assertion is no longer sent.
    let (offer, _) = world.exchange(0)?;
    assert_eq!(attribute_values(&offer, "identity"), [ASSERTION]);
    world.peers[0].pc.set_identity_assertion(None)?;
    let (offer, answer) = world.exchange(0)?;
    assert!(attribute_values(&offer, "identity").is_empty());
    assert_eq!(attribute_values(&answer, "identity"), [ANSWERER_ASSERTION]);
    assert!(world.peers[1].pc.remote_identity_assertion().is_none());

    // Of several attributes the first is the one read.
    let (_, _) = world.exchange_with(
        0,
        |sdp| {
            with_session_line(
                &with_session_line(sdp, "a=identity:Zmlyc3Q="),
                "a=identity:c2Vjb25k",
            )
        },
        keep,
    )?;
    assert_eq!(
        world.peers[1].pc.remote_identity_assertion(),
        Some("Zmlyc3Q=")
    );

    // A value that is not the attribute's syntax is refused, and could not smuggle a line.
    for invalid in ["", "not base64", "YWJj\r\na=setup:active"] {
        assert_eq!(
            world.peers[0]
                .pc
                .set_identity_assertion(Some(invalid.to_owned())),
            Err(Error::ErrInvalidIdentityAssertion),
            "{invalid:?}"
        );
    }
    let (offer, _) = world.exchange(0)?;
    assert!(attribute_values(&offer, "identity").is_empty());
    Ok(())
}
