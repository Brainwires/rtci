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
        assert_eq!(world.peers[i].srtp_cipher(now), "SRTP_AEAD_AES_256_GCM");
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

/// RFC 8827 section 6.3: the local ICE username fragment and password are the engine's, not
/// the application's: every peer connection draws its own, random (at least 24 bits of
/// ufrag and 128 bits of password in the ice-char alphabet, RFC 8445 section 5.3), and the
/// configuration (`RTCConfiguration`) has no way to set them. Setting them is a
/// `SettingEngine` option for native applications, off unless called, which a script-facing
/// binding must not expose.
#[test]
fn the_local_ice_credentials_are_drawn_by_the_engine() -> Result<()> {
    let ice_char = |c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/';
    let mut seen = HashSet::new();
    for _ in 0..20 {
        let mut offerer = peer("10.0.0.1:5000")?;
        offerer.pc.create_data_channel("data", None)?;
        let offer = offerer.pc.create_offer(None)?.sdp;
        let ufrag = attribute_values(&offer, "ice-ufrag").remove(0);
        let pwd = attribute_values(&offer, "ice-pwd").remove(0);
        assert!(ufrag.len() >= 4 && ufrag.chars().all(ice_char), "{ufrag}");
        assert!(pwd.len() >= 22 && pwd.chars().all(ice_char), "{pwd}");
        assert!(seen.insert(ufrag.clone()), "ufrag {ufrag} twice");
        assert!(seen.insert(pwd.clone()), "pwd {pwd} twice");
    }
    // Only the native option sets them.
    let mut chosen = Peer::new(
        "10.0.0.1:5000",
        SettingEngineBuilder::new()
            .with_ice_credentials("abcd".to_owned(), "a".repeat(22))
            .build(),
    )?;
    chosen.pc.create_data_channel("data", None)?;
    let offer = chosen.pc.create_offer(None)?.sdp;
    assert_eq!(
        attribute_values(&offer, "ice-ufrag"),
        vec!["abcd".to_owned()]
    );
    Ok(())
}

/// The `a=fingerprint` values of an SDP, as fingerprints.
fn fingerprints_of(sdp: &str) -> Vec<rtc::peer_connection::transport::RTCDtlsFingerprint> {
    attribute_values(sdp, "fingerprint")
        .into_iter()
        .map(|value| {
            let (algorithm, value) = value.split_once(' ').expect("algorithm and value");
            rtc::peer_connection::transport::RTCDtlsFingerprint {
                algorithm: algorithm.to_owned(),
                value: value.to_owned(),
            }
        })
        .collect()
}

/// RFC 8827 sections 5.1.4 and 7.4: the identity the application established (from its
/// identity provider's verification of the peer's assertion) covers every fingerprint of the
/// remote description and the certificate the DTLS association authenticated; it holds for
/// the associations made with those fingerprints, a newly established one replaces it, and
/// it is discarded when the remote description's fingerprints change.
#[test]
fn the_peer_identity_is_bound_to_the_fingerprints_and_the_certificate_in_use() -> Result<()> {
    use rtc::peer_connection::identity::RTCPeerIdentity;
    const ASSERTION: &str = "YWxpY2U=";
    let mut world = world()?;
    world.peers[0]
        .pc
        .set_identity_assertion(Some(ASSERTION.to_owned()))?;
    let verified = |identity: &str, fingerprints| RTCPeerIdentity {
        identity: identity.to_owned(),
        fingerprints,
    };

    // Nothing to verify yet.
    assert_eq!(
        world.peers[1]
            .pc
            .set_peer_identity(verified("alice@example.org", vec![])),
        Err(Error::ErrNoRemoteIdentityAssertion)
    );
    let (offer, _) = world.connect()?;
    let described = fingerprints_of(&offer);
    assert!(!described.is_empty());
    let bob = &mut world.peers[1].pc;
    assert_eq!(bob.peer_identity(), None);

    // Section 7.4: an identity that covers fewer fingerprints than the description has is
    // refused; one that covers them all, and so the certificate in use, is the peer's.
    let mut fewer = described.clone();
    fewer[0].value = fewer[0].value.replace(|c: char| c.is_ascii_hexdigit(), "0");
    assert_eq!(
        bob.set_peer_identity(verified("alice@example.org", fewer)),
        Err(Error::ErrIdentityFingerprintsNotCovered)
    );
    bob.set_peer_identity(verified("alice@example.org", described.clone()))?;
    assert_eq!(bob.peer_identity(), Some("alice@example.org"));

    // Section 5.1.4: a newly received identity applies to the existing association.
    bob.set_peer_identity(verified("alice@example.net", described.clone()))?;
    assert_eq!(bob.peer_identity(), Some("alice@example.net"));

    // A renegotiation with the same fingerprints keeps it.
    world.exchange(0)?;
    assert_eq!(world.peers[1].pc.peer_identity(), Some("alice@example.net"));

    // Fingerprints that change discard it: here a description that names another certificate
    // (the answerer does not verify fingerprints, so the association carries on).
    let other = "sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF";
    let line = format!("a=fingerprint:{other}");
    let changed = |sdp: &str| replace_lines(sdp, "a=fingerprint:", Some(&line));
    let _ = world.exchange_with(0, changed, keep);
    assert_eq!(world.peers[1].pc.peer_identity(), None);
    Ok(())
}

/// RFC 8827 section 7.4: "The RP browser MUST verify that the in-use certificate for a DTLS
/// connection is in the set of fingerprints returned from the IdP". With fingerprint checks
/// off at the answerer, the offerer's certificate is not the one its description names: an
/// identity that covers the description, and not that certificate, is refused once the
/// association is up.
#[test]
fn an_identity_that_does_not_cover_the_certificate_in_use_is_refused() -> Result<()> {
    use rtc::peer_connection::identity::RTCPeerIdentity;
    let unverified = Peer::new(
        "10.0.0.2:5000",
        SettingEngineBuilder::new()
            .with_disable_certificate_fingerprint_verification(true)
            .build(),
    )?;
    let mut world = World::new(peer("10.0.0.1:5000")?, unverified);
    world.peers[0]
        .pc
        .set_identity_assertion(Some("YWxpY2U=".to_owned()))?;
    let named = "sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF";
    let line = format!("a=fingerprint:{named}");
    world.peers[0].pc.create_data_channel("data", None)?;
    world.exchange_with(
        0,
        |sdp| replace_lines(sdp, "a=fingerprint:", Some(&line)),
        keep,
    )?;
    world.trickle()?;
    world.run("the connection", |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    let described = vec![rtc::peer_connection::transport::RTCDtlsFingerprint {
        algorithm: "sha-256".to_owned(),
        value: named.split_once(' ').unwrap().1.to_owned(),
    }];
    assert_eq!(
        world.peers[1].pc.set_peer_identity(RTCPeerIdentity {
            identity: "alice@example.org".to_owned(),
            fingerprints: described,
        }),
        Err(Error::ErrIdentityCertificateNotCovered)
    );
    assert_eq!(world.peers[1].pc.peer_identity(), None);
    Ok(())
}

/// The bytes of `needle` in the forms a `Debug` string could carry them: a byte list, and hex.
fn debug_forms(needle: &[u8]) -> Vec<String> {
    let list = format!("{needle:?}");
    let hex: String = needle.iter().map(|b| format!("{b:02x}")).collect();
    let hex_upper = hex.to_uppercase();
    vec![list[1..list.len() - 1].to_owned(), hex, hex_upper]
}

/// RFC 8827 section 6.3 and RFC 8826 section 4.2.1: the ICE (STUN) transaction ids are not
/// available to the application, diagnostics included. Two peers connect; the transaction id
/// of every Binding request either wrote appears in none of the events either raised and in
/// neither's statistics.
#[test]
fn stun_transaction_ids_reach_neither_events_nor_statistics() -> Result<()> {
    let mut world = world()?;
    world.connect()?;
    world.run_for(Duration::from_secs(10), |_| false);
    let now = world.now;
    let mut ids = HashSet::new();
    for peer in &world.peers {
        for datagram in &peer.written {
            // A STUN Binding request or response (RFC 8489 section 5): type 0x0001 / 0x0101,
            // the magic cookie, then the 96-bit transaction id.
            if datagram.len() >= 20 && datagram[0] < 2 && datagram[4..8] == [0x21, 0x12, 0xA4, 0x42]
            {
                ids.insert(datagram[8..20].to_vec());
            }
        }
    }
    assert!(!ids.is_empty(), "the peers ran connectivity checks");
    for peer in world.peers.iter_mut() {
        let stats = format!(
            "{:?}",
            peer.pc.get_stats(now, rtc::statistics::StatsSelector::None)
        );
        let events = peer.events.join("\n");
        for id in &ids {
            for form in debug_forms(id) {
                assert!(!stats.contains(&form), "a transaction id in the statistics");
                assert!(!events.contains(&form), "a transaction id in an event");
            }
        }
    }
    Ok(())
}

/// RFC 8827 section 5.1.4: when the fingerprints change, the next description carries a new
/// identity assertion or none. A connection's certificates are fixed when it is built, so its
/// fingerprints never change: not across renegotiations, and not when it asks for a new DTLS
/// association (`renew_dtls_association`, which changes the `tls-id` only). The assertion
/// set for the connection stays the one that covers them.
#[test]
fn a_new_dtls_association_keeps_the_fingerprints_the_identity_covers() -> Result<()> {
    let mut world = world()?;
    let (first_offer, _) = world.connect()?;
    world.peers[0].pc.renew_dtls_association();
    let (offer, _) = world.exchange(0)?;
    // RFC 8842 section 5.1: the new association runs on new 3-tuples.
    world.regather()?;
    assert_ne!(
        attribute_values(&offer, "tls-id"),
        attribute_values(&first_offer, "tls-id"),
        "a new association is asked for"
    );
    assert_eq!(fingerprints_of(&offer), fingerprints_of(&first_offer));
    world.run("the new association", |peers| {
        peers.iter().all(|p| p.connected())
    })?;
    world.ping_pong("after the new association")?;
    Ok(())
}

/// RFC 8827 section 6.5: "The API MUST NOT permit the JS to obtain the negotiated keying
/// material." No public function or field of the peer connection API (everything under
/// `src/`) hands out the DTLS exporter, the master secret, the SRTP master keys or the SRTP or
/// DTLS state that holds them: each public item is read from the source, and one whose
/// signature names any of them fails the test. (The sub-crates `rtc::dtls` and `rtc::srtp`
/// export their own state for a standalone DTLS or SRTP session; nothing in the peer
/// connection reaches the association's.)
#[test]
fn the_api_gives_the_application_no_keying_material() -> Result<()> {
    const FORBIDDEN: [&str; 10] = [
        "keying_material",
        "export_keying",
        "master_secret",
        "master_key",
        "master_salt",
        "SessionKeys",
        "SecretVec",
        "srtp::context::Context",
        "dtls::state::State",
        "DTLSConn",
    ];
    fn walk(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                walk(&path, files)?;
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
        Ok(())
    }
    let mut files = vec![];
    walk(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    )?;
    assert!(files.len() > 50, "the sources are found");
    let mut offending = vec![];
    for file in files {
        let name = file.display().to_string();
        if name.ends_with("_test.rs") || name.contains("/tests/") {
            continue;
        }
        let text = std::fs::read_to_string(&file)?;
        // A public item's signature: from `pub fn`, `pub ` field or `pub type` to the body or
        // the end of the line.
        for (number, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with("pub ") {
                continue;
            }
            let signature: String = text
                .lines()
                .skip(number)
                .take(8)
                .collect::<Vec<_>>()
                .join(" ");
            let signature = signature.split(['{', ';']).next().unwrap_or_default();
            if let Some(word) = FORBIDDEN.iter().find(|w| signature.contains(*w)) {
                offending.push(format!("{name}:{}: {word}: {}", number + 1, trimmed));
            }
        }
    }
    assert!(
        offending.is_empty(),
        "public items that expose keying material:\n{}",
        offending.join("\n")
    );
    Ok(())
}
