//! When a description asks for a new DTLS association, one is established (RFC 8842 section
//! 3.1), with or without an ICE restart:
//!
//! > A new DTLS association must be established between two endpoints after a successful SDP
//! > offer/answer exchange in the following cases: the negotiated DTLS setup roles change; or
//! > one or more fingerprint values are modified, added, or removed in either an SDP offer or
//! > answer; or the intent to establish a new DTLS association is explicitly signaled using
//! > SDP, by changing the value of the SDP "tls-id" attribute.
//!
//! The engine used to look at the remote fingerprints and role only together with an ICE
//! restart: a description that changed them on the same ICE session was accepted and ignored,
//! and the old fingerprint stayed the one a certificate was checked against.
//!
//! The certificates of a peer connection are fixed, so the peer that changes them is played by
//! a second peer connection that takes the first one's place: same address, same ICE
//! credentials (so that the exchange is not an ICE restart), and its own certificate, `tls-id`
//! or `a=setup`, as the test needs. It answers an offer of the peer that stays, so the ICE
//! roles stay as they were too.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World, attribute_values, keep, replace_lines};
use rtc::peer_connection::certificate::{CertificateParams, RTCCertificate};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::transport::{RTCDtlsRole, RTCDtlsTransportState};

const A: &str = "10.0.0.1:5000";
const B: &str = "10.0.0.2:5000";

fn certificate() -> Result<RTCCertificate> {
    let provider = rtc::crypto::default_provider()?;
    Ok(RTCCertificate::generate(
        provider.crypto(),
        rtc::crypto::SignatureScheme::EcdsaP256Sha256,
        CertificateParams::new(vec!["dtls-association".to_owned()])?,
    )?)
}

const B_UFRAG: &str = "bufragbufrag";
const B_PWD: &str = "bpasswordbpasswordbpassw";

/// A peer at `B` with the given certificate and B's ICE credentials.
fn peer_b(certificate: &RTCCertificate, answering_role: Option<RTCDtlsRole>) -> Result<Peer> {
    let mut setting_engine =
        SettingEngineBuilder::new().with_ice_credentials(B_UFRAG.to_owned(), B_PWD.to_owned());
    if let Some(role) = answering_role {
        setting_engine = setting_engine.with_answering_dtls_role(role);
    }
    Peer::with_configuration(
        B,
        RTCConfigurationBuilder::new()
            .with_certificates(vec![certificate.clone()])
            .build(),
        setting_engine.build(),
    )
}

fn without_tls_id(sdp: &str) -> String {
    replace_lines(sdp, "a=tls-id:", None)
}

/// A (peer 0) and B (peer 1) connected, A having offered: A is the DTLS server and B the
/// client, unless B is configured to answer as the server. `legacy` removes `a=tls-id` from
/// everything B sends, as a peer that predates RFC 8842 does.
fn connected(
    a_answering_role: Option<RTCDtlsRole>,
    b_answering_role: Option<RTCDtlsRole>,
    legacy: bool,
) -> Result<(World, RTCCertificate, String)> {
    let mut setting_engine = SettingEngineBuilder::new();
    if let Some(role) = a_answering_role {
        setting_engine = setting_engine.with_answering_dtls_role(role);
    }
    let b_certificate = certificate()?;
    let mut world = World::new(
        Peer::new(A, setting_engine.build())?,
        peer_b(&b_certificate, b_answering_role)?,
    );
    world.peers[0].pc.create_data_channel("data", None)?;
    let (a_offer, _) = if legacy {
        world.exchange_with(0, keep, without_tls_id)?
    } else {
        world.exchange(0)?
    };
    world.trickle()?;
    world.run("the first connection", |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    world.ping_pong("the first association")?;
    let now = world.now;
    assert_eq!(
        world.peers[0].dtls_role(now),
        if b_answering_role == Some(RTCDtlsRole::Server) {
            RTCDtlsRole::Client
        } else {
            RTCDtlsRole::Server
        }
    );
    assert_eq!(
        world.peers[0].remote_certificate().as_deref(),
        Some(b_certificate.dtls_certificate.certificate[0].as_ref())
    );
    Ok((world, b_certificate, a_offer))
}

/// Replaces B by `successor` (a new peer connection at B's address) and has it answer a new
/// offer of A. Returns the successor's answer as it wrote it.
fn successor_answers(
    world: &mut World,
    successor: Peer,
    munge_answer: impl Fn(&str) -> String,
) -> Result<String> {
    world.peers[1] = successor;
    let (_, answer) = world.exchange_with(0, keep, munge_answer)?;
    assert_eq!(
        attribute_values(&answer, "ice-ufrag"),
        [B_UFRAG],
        "the successor keeps B's ICE credentials: the exchange is no ICE restart"
    );
    let candidate = world.peers[0].candidate()?;
    world.peers[1].pc.add_remote_candidate(candidate)?;
    let candidate = world.peers[1].candidate()?;
    world.peers[1].pc.add_local_candidate(candidate)?;
    Ok(answer)
}

/// A new association was established with the successor: its handshake completed on both
/// sides, A checked the successor's certificate, and A has the role `a_role`.
fn assert_new_association(
    world: &mut World,
    what: &str,
    a_role: RTCDtlsRole,
    successor_certificate: &RTCCertificate,
) -> Result<()> {
    let written = [world.peers[0].written.len(), world.peers[1].written.len()];
    let established = world.run(&format!("{what}: the new association"), |peers| {
        peers.iter().all(|p| p.connected())
            && peers[1].remote_certificate().is_some()
            && peers[0].remote_certificate().as_deref()
                == Some(successor_certificate.dtls_certificate.certificate[0].as_ref())
    });
    if let Err(err) = established {
        // What each peer sent meanwhile, by kind (RFC 7983 first byte), for the failure message.
        let now = world.now;
        let mut sent = Vec::new();
        for (i, peer) in world.peers.iter_mut().enumerate() {
            let count = |range: std::ops::RangeInclusive<u8>| {
                peer.written[written[i]..]
                    .iter()
                    .filter(|d| d.first().is_some_and(|b| range.contains(b)))
                    .count()
            };
            let (stun, handshake, dtls) = (count(0..=3), count(22..=22), count(20..=63));
            sent.push(format!(
                "peer {i}: {stun} STUN, {handshake} DTLS handshake, {} other DTLS, DTLS {:?}",
                dtls - handshake,
                peer.dtls_state(now)
            ));
        }
        anyhow::bail!("{err}; {}", sent.join("; "));
    }
    let now = world.now;
    for i in 0..2 {
        assert_eq!(
            world.peers[i].dtls_state(now),
            RTCDtlsTransportState::Connected,
            "{what}: peer {i}"
        );
        assert!(!world.peers[i].failed(), "{what}: peer {i}");
    }
    assert_eq!(world.peers[0].dtls_role(now), a_role, "{what}");
    Ok(())
}

/// A changed fingerprint set (another certificate) on the same ICE session: A establishes a
/// new association and checks the new certificate against the new fingerprint. The successor
/// answers `active` as B did, so the roles stay: A, the DTLS server, accepts its ClientHello;
/// and with the roles the other way round (B and its successor answer `passive`) it is A,
/// whose ICE transport selects no new pair, that starts the handshake.
#[test]
fn a_changed_fingerprint_without_an_ice_restart_establishes_a_new_association() -> Result<()> {
    for (b_answering_role, a_role) in [
        (None, RTCDtlsRole::Server),
        (Some(RTCDtlsRole::Server), RTCDtlsRole::Client),
    ] {
        let what = format!("A is the DTLS {a_role}");
        let (mut world, b_certificate, _) = connected(None, b_answering_role, false)?;
        let new_certificate = certificate()?;
        assert_ne!(new_certificate, b_certificate);
        let successor = peer_b(&new_certificate, b_answering_role)?;
        successor_answers(&mut world, successor, keep)?;
        assert_new_association(&mut world, &what, a_role, &new_certificate)?;
    }
    Ok(())
}

/// A changed `tls-id` alone (same certificate, same roles, same ICE session) asks for a new
/// association (RFC 8842 section 3.1, third case).
#[test]
fn a_changed_tls_id_establishes_a_new_association() -> Result<()> {
    let (mut world, b_certificate, _) = connected(None, None, false)?;
    let successor = peer_b(&b_certificate, None)?;
    let answer = successor_answers(&mut world, successor, keep)?;
    assert_eq!(attribute_values(&answer, "tls-id").len(), 1);
    assert_new_association(
        &mut world,
        "a new tls-id",
        RTCDtlsRole::Server,
        &b_certificate,
    )?;
    Ok(())
}

/// Without `tls-id` (a peer that predates RFC 8842), a change of the setup roles asks for a
/// new association (RFC 8842 section 4): B was the DTLS client; its successor answers
/// `passive`, which takes the role A had. A becomes the client of a new association.
#[test]
fn a_changed_setup_role_without_tls_id_establishes_a_new_association() -> Result<()> {
    let (mut world, b_certificate, _) = connected(None, None, true)?;
    let successor = peer_b(&b_certificate, Some(RTCDtlsRole::Server))?;
    let answer = successor_answers(&mut world, successor, without_tls_id)?;
    assert_eq!(attribute_values(&answer, "setup"), ["passive"]);
    assert_new_association(
        &mut world,
        "a changed role",
        RTCDtlsRole::Client,
        &b_certificate,
    )?;
    Ok(())
}

/// The counterpart: a later description that changes none of the three (same fingerprints, no
/// `tls-id`, the same role) keeps the association (RFC 8842 section 5.4). A, the DTLS client
/// here, neither resets its DTLS transport nor starts a handshake.
#[test]
fn an_unchanged_description_keeps_the_association() -> Result<()> {
    let (mut world, b_certificate, _) = connected(None, Some(RTCDtlsRole::Server), true)?;
    let successor = peer_b(&b_certificate, Some(RTCDtlsRole::Server))?;
    let written = world.peers[0].written.len();
    successor_answers(&mut world, successor, without_tls_id)?;
    let now = world.now;
    assert_eq!(
        world.peers[0].dtls_state(now),
        RTCDtlsTransportState::Connected
    );
    // With the network cut, so that nothing the successor sends can provoke a reply: A sends
    // no handshake record. (DTLS handshake records have content type 22; what A still sends is
    // STUN and application data of the association it kept, type 23.)
    world.connected = false;
    world.run_for(std::time::Duration::from_secs(3), |_| false);
    let handshake_records = world.peers[0].written[written..]
        .iter()
        .filter(|datagram| datagram.first() == Some(&22))
        .count();
    assert_eq!(handshake_records, 0, "A started a handshake");
    let now = world.now;
    assert_eq!(
        world.peers[0].dtls_state(now),
        RTCDtlsTransportState::Connected
    );
    assert_eq!(world.peers[0].dtls_role(now), RTCDtlsRole::Client);
    assert_eq!(
        world.peers[0].remote_certificate().as_deref(),
        Some(b_certificate.dtls_certificate.certificate[0].as_ref())
    );
    Ok(())
}
