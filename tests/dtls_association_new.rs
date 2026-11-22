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
//! credentials (so that its offer is not an ICE restart), and its own certificate, `tls-id` or
//! `a=setup`, as the test needs.

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

/// Replaces B by `successor` (a new peer connection at B's address) and has it offer to A.
/// Returns A's answer.
fn successor_offers(
    world: &mut World,
    successor: Peer,
    munge_offer: impl Fn(&str) -> String,
) -> Result<String> {
    world.peers[1] = successor;
    world.peers[1].pc.create_data_channel("data", None)?;
    let (offer, answer) = world.exchange_with(1, munge_offer, keep)?;
    assert_eq!(
        attribute_values(&offer, "ice-ufrag"),
        [B_UFRAG],
        "the successor's offer keeps B's ICE credentials: it is no ICE restart"
    );
    let candidate = world.peers[0].candidate()?;
    world.peers[1].pc.add_remote_candidate(candidate)?;
    let candidate = world.peers[1].candidate()?;
    world.peers[1].pc.add_local_candidate(candidate)?;
    Ok(answer)
}

/// A new association was established with the successor: its handshake completed on both
/// sides, A checked the successor's certificate, and A has the role its answer stated.
fn assert_new_association(
    world: &mut World,
    what: &str,
    answer: &str,
    successor_certificate: &RTCCertificate,
) -> Result<()> {
    world.run(&format!("{what}: the new association"), |peers| {
        peers.iter().all(|p| p.connected())
            && peers[1].remote_certificate().is_some()
            && peers[0].remote_certificate().as_deref()
                == Some(successor_certificate.dtls_certificate.certificate[0].as_ref())
    })?;
    let now = world.now;
    for i in 0..2 {
        assert_eq!(
            world.peers[i].dtls_state(now),
            RTCDtlsTransportState::Connected,
            "{what}: peer {i}"
        );
        assert!(!world.peers[i].failed(), "{what}: peer {i}");
    }
    let stated = attribute_values(answer, "setup");
    let a_role = world.peers[0].dtls_role(now);
    assert_eq!(
        stated,
        [if a_role == RTCDtlsRole::Client {
            "active"
        } else {
            "passive"
        }],
        "{what}: A's answer states the role A has in the new association"
    );
    Ok(())
}

/// A changed fingerprint set (another certificate) on the same ICE session: A establishes a
/// new association and checks the new certificate against the new fingerprint. A answers
/// `active` by default, so it is A, whose ICE transport selects no new pair, that must start
/// the handshake; configured to answer `passive`, it accepts the successor's ClientHello.
#[test]
fn a_changed_fingerprint_without_an_ice_restart_establishes_a_new_association() -> Result<()> {
    for (a_answering_role, a_role) in [
        (None, RTCDtlsRole::Client),
        (Some(RTCDtlsRole::Server), RTCDtlsRole::Server),
    ] {
        let what = format!("A answers as {a_role}");
        let (mut world, b_certificate, a_offer) = connected(a_answering_role, None, false)?;
        let new_certificate = certificate()?;
        assert_ne!(new_certificate, b_certificate);
        let successor = peer_b(&new_certificate, None)?;
        let answer = successor_offers(&mut world, successor, keep)?;
        assert_new_association(&mut world, &what, &answer, &new_certificate)?;
        let now = world.now;
        assert_eq!(world.peers[0].dtls_role(now), a_role, "{what}");
        // RFC 8842 section 5.3: the answerer that establishes a new association gives it a new
        // `tls-id`.
        let (first, second) = (
            attribute_values(&a_offer, "tls-id"),
            attribute_values(&answer, "tls-id"),
        );
        assert_eq!((first.len(), second.len()), (1, 1), "{what}");
        assert_ne!(first, second, "{what}");
    }
    Ok(())
}

/// A changed `tls-id` alone (same certificate, same `actpass`, same ICE session) asks for a
/// new association (RFC 8842 section 3.1, third case).
#[test]
fn a_changed_tls_id_establishes_a_new_association() -> Result<()> {
    let (mut world, b_certificate, _) = connected(None, None, false)?;
    let successor = peer_b(&b_certificate, None)?;
    let answer = successor_offers(&mut world, successor, keep)?;
    assert_new_association(&mut world, "a new tls-id", &answer, &b_certificate)?;
    Ok(())
}

/// Without `tls-id` (a peer that predates RFC 8842), a change of the setup roles asks for a
/// new association (RFC 8842 section 4): B was the DTLS client; its successor's offer says
/// `passive`, which takes the role A had. A becomes the client of a new association.
#[test]
fn a_changed_setup_role_without_tls_id_establishes_a_new_association() -> Result<()> {
    let (mut world, b_certificate, _) = connected(None, None, true)?;
    let successor = peer_b(&b_certificate, None)?;
    let answer = successor_offers(&mut world, successor, |sdp| {
        without_tls_id(&replace_lines(sdp, "a=setup:", Some("a=setup:passive")))
    })?;
    // The successor wrote `actpass` and is told `active` by A's answer: it is the server, as
    // the offer A saw said.
    assert_eq!(attribute_values(&answer, "setup"), ["active"]);
    assert_new_association(&mut world, "a changed role", &answer, &b_certificate)?;
    let now = world.now;
    assert_eq!(world.peers[0].dtls_role(now), RTCDtlsRole::Client);
    Ok(())
}

/// The counterpart: a later description that changes none of the three (same fingerprints, no
/// `tls-id`, `actpass`) keeps the association (RFC 8842 section 5.4). A, the DTLS client here,
/// neither resets its DTLS transport nor starts a handshake, and its answer repeats its role.
#[test]
fn an_unchanged_description_keeps_the_association() -> Result<()> {
    let (mut world, b_certificate, _) = connected(None, Some(RTCDtlsRole::Server), true)?;
    let successor = peer_b(&b_certificate, None)?;
    let answer = successor_offers(&mut world, successor, without_tls_id)?;
    assert_eq!(
        attribute_values(&answer, "setup"),
        ["active"],
        "A, the DTLS client, keeps its role"
    );
    let now = world.now;
    assert_eq!(
        world.peers[0].dtls_state(now),
        RTCDtlsTransportState::Connected
    );
    // With the network cut, so that nothing the successor sends can provoke a reply: A sends
    // no handshake record. (DTLS handshake records have content type 22; what A still sends is
    // STUN and application data of the association it kept, type 23.)
    let written = world.peers[0].written.len();
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
    assert_eq!(
        world.peers[0].remote_certificate().as_deref(),
        Some(b_certificate.dtls_certificate.certificate[0].as_ref())
    );
    Ok(())
}
