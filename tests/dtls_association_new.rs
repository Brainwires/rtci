//! When a description asks for a new DTLS association, one is established (RFC 8842 section
//! 3.1):
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
//! or `a=setup`, as the test needs. B offers first and its successor offers again, so the ICE
//! roles stay as they were too (B's side controlling): the peer that stays restarts nothing.
//!
//! A new association on the same ICE session is RFC 8842 section 3.1 read alone: RFC 9429
//! sections 5.8.3 and 5.11 (and RFC 8842 section 6) ask for an ICE restart with it, and a peer
//! connection refuses such a description unless
//! `with_dtls_new_association_without_ice_restart(true)` is set. A uses that setting here; the
//! default is in `jsep_dtls_restart.rs`.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World, attribute_values, keep, replace_lines};
use rtc::peer_connection::certificate::{CertificateParams, RTCCertificate};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::transport::{RTCDtlsRole, RTCDtlsTransportState, RTCIceRole};

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
fn peer_b(certificate: &RTCCertificate) -> Result<Peer> {
    Peer::with_configuration(
        B,
        RTCConfigurationBuilder::new()
            .with_certificates(vec![certificate.clone()])
            .build(),
        SettingEngineBuilder::new()
            .with_ice_credentials(B_UFRAG.to_owned(), B_PWD.to_owned())
            .build(),
    )
}

fn without_tls_id(sdp: &str) -> String {
    replace_lines(sdp, "a=tls-id:", None)
}

/// A (peer 0) and B (peer 1) connected, B having offered: A answered, as the DTLS client
/// unless it is configured to answer as the server. `legacy` removes `a=tls-id` from what B
/// sends, as a peer that predates RFC 8842 does. Returns A's answer too.
fn connected(
    a_answering_role: Option<RTCDtlsRole>,
    legacy: bool,
) -> Result<(World, RTCCertificate, String)> {
    let mut setting_engine =
        SettingEngineBuilder::new().with_dtls_new_association_without_ice_restart(true);
    if let Some(role) = a_answering_role {
        setting_engine = setting_engine.with_answering_dtls_role(role);
    }
    let b_certificate = certificate()?;
    let mut world = World::new(
        Peer::new(A, setting_engine.build())?,
        peer_b(&b_certificate)?,
    );
    world.peers[1].pc.create_data_channel("data", None)?;
    let (_, a_answer) = if legacy {
        world.exchange_with(1, without_tls_id, keep)?
    } else {
        world.exchange(1)?
    };
    world.trickle()?;
    world.run("the first connection", |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    world.ping_pong("the first association")?;
    let now = world.now;
    assert_eq!(
        world.peers[0].dtls_role(now),
        a_answering_role.unwrap_or(RTCDtlsRole::Client)
    );
    assert_eq!(
        world.peers[0].remote_certificate().as_deref(),
        Some(b_certificate.dtls_certificate.certificate[0].as_ref())
    );
    Ok((world, b_certificate, a_answer))
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
/// new association and checks the new certificate against the new fingerprint. The offer is
/// `actpass`, so A keeps its role: as the DTLS client it is A, whose ICE transport selects no
/// new pair, that starts the handshake; as the server it accepts the successor's ClientHello.
#[test]
fn a_changed_fingerprint_without_an_ice_restart_establishes_a_new_association() -> Result<()> {
    for a_answering_role in [None, Some(RTCDtlsRole::Server)] {
        let a_role = a_answering_role.unwrap_or(RTCDtlsRole::Client);
        let what = format!("A is the DTLS {a_role}");
        let (mut world, b_certificate, first_answer) = connected(a_answering_role, false)?;
        let new_certificate = certificate()?;
        assert_ne!(new_certificate, b_certificate);
        let successor = peer_b(&new_certificate)?;
        let answer = successor_offers(&mut world, successor, keep)?;
        assert_new_association(&mut world, &what, a_role, &new_certificate)?;
        // RFC 8842 section 5.3: the answerer that establishes a new association gives it a new
        // `tls-id`, and its answer does not change the roles.
        let (first, second) = (
            attribute_values(&first_answer, "tls-id"),
            attribute_values(&answer, "tls-id"),
        );
        assert_eq!((first.len(), second.len()), (1, 1), "{what}");
        assert_ne!(first, second, "{what}");
        assert_eq!(
            attribute_values(&answer, "setup"),
            attribute_values(&first_answer, "setup"),
            "{what}"
        );
    }
    Ok(())
}

/// A changed `tls-id` alone (same certificate, same `actpass`, same ICE session) asks for a
/// new association (RFC 8842 section 3.1, third case).
#[test]
fn a_changed_tls_id_establishes_a_new_association() -> Result<()> {
    let (mut world, b_certificate, _) = connected(None, false)?;
    let successor = peer_b(&b_certificate)?;
    successor_offers(&mut world, successor, keep)?;
    assert_new_association(
        &mut world,
        "a new tls-id",
        RTCDtlsRole::Client,
        &b_certificate,
    )?;
    Ok(())
}

/// Without `tls-id` (a peer that predates RFC 8842), a change of the setup roles asks for a
/// new association (RFC 8842 section 4): B was the DTLS server; its successor's offer says
/// `active`, which takes the role A had. A becomes the server of a new association.
#[test]
fn a_changed_setup_role_without_tls_id_establishes_a_new_association() -> Result<()> {
    let (mut world, b_certificate, _) = connected(None, true)?;
    let successor = peer_b(&b_certificate)?;
    let answer = successor_offers(&mut world, successor, |sdp| {
        without_tls_id(&replace_lines(sdp, "a=setup:", Some("a=setup:active")))
    })?;
    // The successor wrote `actpass` and is told `passive` by A's answer: it is the client, as
    // the offer A saw said.
    assert_eq!(attribute_values(&answer, "setup"), ["passive"]);
    assert_new_association(
        &mut world,
        "a changed role",
        RTCDtlsRole::Server,
        &b_certificate,
    )?;
    Ok(())
}

/// The counterpart: a later description that changes none of the three (same fingerprints, no
/// `tls-id`, `actpass`) keeps the association (RFC 8842 section 5.4). A, the DTLS client,
/// neither resets its DTLS transport nor starts a handshake, and its answer repeats its role.
#[test]
fn an_unchanged_description_keeps_the_association() -> Result<()> {
    let (mut world, b_certificate, _) = connected(None, true)?;
    let successor = peer_b(&b_certificate)?;
    let written = world.peers[0].written.len();
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

/// The ICE side of the same takeover, when the roles do conflict. ICE roles "persist
/// throughout the lifetime of the session" (RFC 8445 section 6.1.1): A offered first, so A is
/// the controlling agent and stays it when the other side offers later. The successor, whose
/// own ICE session starts with its offer, takes the controlling role as well. Section 7.3.1.1
/// repairs that with the tiebreakers, and the session comes up whichever of the two is the
/// larger:
///
/// - the successor's: A switches to the controlled role, keeps its selected pair and takes
///   the successor's nomination of it;
/// - A's: the successor is told 487 and becomes the controlled agent. A nominated its pair
///   long before the successor existed, so A nominates that pair again (the successor, as the
///   DTLS client, starts its handshake when its ICE agent selects a pair: without the repeated
///   nomination it waited for ever).
///
/// W3C webrtc-pc 5.6: after the conflict each `RTCIceTransport.role` ([[IceRole]]) is the role
/// its agent took.
#[test]
fn a_successor_is_connected_whichever_agent_wins_the_ice_role_conflict() -> Result<()> {
    for (a_tie_breaker, successor_tie_breaker) in [(2u64, 1u64), (1, 2)] {
        let what = format!("tiebreakers {a_tie_breaker} (A) and {successor_tie_breaker}");
        let b_certificate = certificate()?;
        let mut world = World::new(
            Peer::new(
                A,
                SettingEngineBuilder::new()
                    .with_ice_tie_breaker(a_tie_breaker)
                    .with_dtls_new_association_without_ice_restart(true)
                    .build(),
            )?,
            peer_b(&b_certificate)?,
        );
        // A offers: A is the controlling agent.
        world.connect()?;
        world.ping_pong(&what)?;

        let new_certificate = certificate()?;
        let successor = Peer::with_configuration(
            B,
            RTCConfigurationBuilder::new()
                .with_certificates(vec![new_certificate.clone()])
                .build(),
            SettingEngineBuilder::new()
                .with_ice_credentials(B_UFRAG.to_owned(), B_PWD.to_owned())
                .with_ice_tie_breaker(successor_tie_breaker)
                .build(),
        )?;
        successor_offers(&mut world, successor, keep)?;
        world.run(&format!("{what}: the new association"), |peers| {
            peers.iter().all(|p| p.connected())
                && peers[1].remote_certificate().is_some()
                && peers[0].remote_certificate().as_deref()
                    == Some(new_certificate.dtls_certificate.certificate[0].as_ref())
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
        let role = |peer: &Peer| {
            peer.pc
                .sctp()
                .expect("the data channel's transport")
                .transport()
                .ice_transport()
                .role()
        };
        let (a_role, successor_role) = if successor_tie_breaker > a_tie_breaker {
            (RTCIceRole::Controlled, RTCIceRole::Controlling)
        } else {
            (RTCIceRole::Controlling, RTCIceRole::Controlled)
        };
        assert_eq!(role(&world.peers[0]), a_role, "{what}: A's [[IceRole]]");
        assert_eq!(
            role(&world.peers[1]),
            successor_role,
            "{what}: the successor's"
        );
    }
    Ok(())
}
