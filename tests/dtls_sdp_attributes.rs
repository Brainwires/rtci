//! How a remote description's `a=setup` and `a=fingerprint` are read (RFC 4145 section 4,
//! RFC 8122 section 5, RFC 8842 section 5).
//!
//! - Both attributes may sit at session level; a session-level `a=setup` was not read at all,
//!   so an offerer that took a role there and an answerer that did not see it both waited for
//!   a ClientHello.
//! - `setup:holdconn` is not used with DTLS (RFC 8842 section 5.1); it was read as "no
//!   preference".
//! - A fingerprint value that is not colon-separated hex of the hash function's length is a
//!   malformed description; it was accepted and only showed as a DTLS failure later.
//! - The fingerprint is written in upper-case hex.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{
    Peer, World, attribute_values, keep, replace_lines, session_part, with_session_line,
};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::transport::{RTCDtlsRole, RTCDtlsTransportState};
use std::time::Instant;

fn world() -> Result<World> {
    Ok(World::new(
        Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    ))
}

/// An offer with one data channel, from a fresh peer.
fn offer() -> Result<String> {
    let mut offerer = Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?;
    offerer.pc.create_data_channel("data", None)?;
    Ok(offerer.pc.create_offer(None)?.sdp)
}

/// What a fresh peer says to a remote offer.
fn apply_offer(sdp: String) -> Result<()> {
    let mut answerer = Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?;
    answerer
        .pc
        .set_remote_description(Instant::now(), RTCSessionDescription::offer(sdp)?)?;
    Ok(())
}

/// RFC 8122 section 5: `fingerprint = 2UHEX *(":" 2UHEX)`, and "the number of bytes is defined
/// by the hash function". A value that is not that is refused when the description is
/// applied, and the peer connection keeps its state.
#[test]
fn a_malformed_fingerprint_is_refused_by_set_remote_description() -> Result<()> {
    let offer = offer()?;
    let fingerprint = attribute_values(&offer, "fingerprint").remove(0);
    let value = fingerprint
        .strip_prefix("sha-256 ")
        .expect("a sha-256 fingerprint");
    assert_eq!(value.len(), 95, "32 bytes: {value}");

    apply_offer(offer.clone())?;
    for malformed in [
        "sha-256 zz".to_owned(),
        "sha-256".to_owned(),
        format!("sha-256 {}", &value[..92]),
        format!("sha-256 {value}:AB"),
        // `UHEX`: upper-case digits.
        format!("sha-256 {}", value.to_lowercase()),
        format!("sha-256 {}", value.replace(':', "")),
        format!("sha-256 {}", value.replacen(':', "::", 1)),
        format!("sha-256 {}G{}", &value[..1], &value[2..]),
        format!("sha-256  {value}"),
        format!("sha-256 {value} {value}"),
        format!("sha-512 {value}"),
        format!("sha-1 {value}"),
    ] {
        let sdp = replace_lines(
            &offer,
            "a=fingerprint:",
            Some(&format!("a=fingerprint:{malformed}")),
        );
        let mut answerer = Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?;
        let applied = answerer
            .pc
            .set_remote_description(Instant::now(), RTCSessionDescription::offer(sdp)?);
        assert!(applied.is_err(), "a=fingerprint:{malformed} was accepted");
        assert!(
            answerer.pc.remote_description().is_none(),
            "a=fingerprint:{malformed}: the refused description was kept"
        );
    }
    Ok(())
}

/// RFC 8122 section 5: "The hash value is represented as a sequence of uppercase hexadecimal
/// bytes, separated by colons."
#[test]
fn the_fingerprint_is_written_in_upper_case_hex() -> Result<()> {
    let mut world = world()?;
    world.peers[0].pc.create_data_channel("data", None)?;
    let (offer, answer) = world.exchange(0)?;
    for sdp in [offer, answer] {
        let fingerprints = attribute_values(&sdp, "fingerprint");
        assert!(!fingerprints.is_empty());
        for fingerprint in fingerprints {
            let (hash, value) = fingerprint
                .split_once(' ')
                .expect("hash-func SP fingerprint");
            assert_eq!(hash, "sha-256");
            let bytes: Vec<&str> = value.split(':').collect();
            assert_eq!(bytes.len(), 32, "{value}");
            assert!(
                bytes.iter().all(|byte| byte.len() == 2
                    && byte
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))),
                "{value}"
            );
        }
    }
    Ok(())
}

/// RFC 4145 section 4: `a=setup` "can be a session-level or a media-level attribute". An
/// offerer that states `active` at session level is answered `passive` and is the one that
/// sends the ClientHello; the association is established.
#[test]
fn a_session_level_setup_is_read() -> Result<()> {
    for (offered, answered, answerer_role) in [
        ("active", "passive", RTCDtlsRole::Server),
        ("passive", "active", RTCDtlsRole::Client),
    ] {
        // The offerer is built to take the role its (rewritten) offer states.
        let offerer_role = if offered == "active" {
            RTCDtlsRole::Client
        } else {
            RTCDtlsRole::Server
        };
        let mut world = World::new(
            Peer::new(
                "10.0.0.1:5000",
                SettingEngineBuilder::new()
                    .with_answering_dtls_role(offerer_role)
                    .build(),
            )?,
            Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
        );
        world.peers[0].pc.create_data_channel("data", None)?;
        let (_, answer) = world.exchange_with(
            0,
            |sdp| {
                with_session_line(
                    &replace_lines(sdp, "a=setup:", None),
                    &format!("a=setup:{offered}"),
                )
            },
            keep,
        )?;
        assert_eq!(
            attribute_values(&answer, "setup"),
            [answered],
            "an offer with a session-level a=setup:{offered}"
        );
        world.trickle()?;
        world.run(&format!("session-level a=setup:{offered}"), |peers| {
            peers.iter().all(|p| p.connected() && p.channel.is_some())
        })?;
        world.ping_pong(&format!("session-level a=setup:{offered}"))?;
        let now = world.now;
        assert_eq!(world.peers[1].dtls_role(now), answerer_role);
        assert_eq!(world.peers[0].dtls_role(now), offerer_role);
    }
    Ok(())
}

/// A media-level `a=setup` overrides the session-level one (RFC 4145 section 4 with RFC 8866
/// section 5.13: a media-level attribute overrides the session-level value).
#[test]
fn a_media_level_setup_overrides_the_session_level_one() -> Result<()> {
    let mut world = World::new(
        Peer::new(
            "10.0.0.1:5000",
            SettingEngineBuilder::new()
                .with_answering_dtls_role(RTCDtlsRole::Client)
                .build(),
        )?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    );
    world.peers[0].pc.create_data_channel("data", None)?;
    let (_, answer) = world.exchange_with(
        0,
        |sdp| {
            with_session_line(
                &replace_lines(sdp, "a=setup:", Some("a=setup:active")),
                "a=setup:passive",
            )
        },
        keep,
    )?;
    assert_eq!(attribute_values(&answer, "setup"), ["passive"]);
    world.trickle()?;
    world.run("a media-level a=setup", |peers| {
        peers.iter().all(|p| p.connected())
    })?;
    Ok(())
}

/// RFC 8842 section 5.1: "endpoints MUST NOT use the SDP 'setup' attribute 'holdconn' value
/// when negotiating a DTLS association". A description that does is refused, at either level,
/// in an offer and in an answer; so is a value RFC 4145 does not define.
#[test]
fn setup_holdconn_is_refused() -> Result<()> {
    let offer = offer()?;
    for value in ["holdconn", "sometimes"] {
        let media_level = replace_lines(&offer, "a=setup:", Some(&format!("a=setup:{value}")));
        assert!(
            apply_offer(media_level).is_err(),
            "an offer with a media-level a=setup:{value} was accepted"
        );
        let session_level = with_session_line(
            &replace_lines(&offer, "a=setup:", None),
            &format!("a=setup:{value}"),
        );
        assert!(
            apply_offer(session_level).is_err(),
            "an offer with a session-level a=setup:{value} was accepted"
        );

        let mut world = world()?;
        world.peers[0].pc.create_data_channel("data", None)?;
        let exchanged = world.exchange_with(0, keep, |sdp| {
            replace_lines(sdp, "a=setup:", Some(&format!("a=setup:{value}")))
        });
        assert!(
            exchanged.is_err(),
            "an answer with a=setup:{value} was accepted"
        );
        let now = world.now;
        assert!(
            matches!(
                world.peers[0].dtls_state(now),
                RTCDtlsTransportState::New | RTCDtlsTransportState::Unspecified
            ),
            "the offerer started DTLS on an answer with a=setup:{value}"
        );
    }
    Ok(())
}

/// RFC 8122 section 5: a session-level fingerprint "applies to all TLS sessions for which no
/// media-level fingerprint attribute is defined". Fingerprints given only at media level
/// (`sdp_media_level_fingerprints`, the default) and only at session level both establish the
/// association.
#[test]
fn fingerprints_are_read_at_session_and_at_media_level() -> Result<()> {
    for media_level in [false, true] {
        let peer = |addr: &str| {
            Peer::new(
                addr,
                SettingEngineBuilder::new()
                    .with_sdp_media_level_fingerprints(media_level)
                    .build(),
            )
        };
        let mut world = World::new(peer("10.0.0.1:5000")?, peer("10.0.0.2:5000")?);
        let (offer, _) = world.connect()?;
        assert_eq!(
            session_part(&offer).contains("a=fingerprint:"),
            !media_level,
            "media-level fingerprints: {media_level}"
        );
        world.ping_pong(&format!("media-level fingerprints: {media_level}"))?;
    }
    Ok(())
}

/// RFC 8842 section 5.2 / RFC 8122 section 6.2: what arrives before the answer, and so before
/// the answerer's fingerprint, is not taken as coming from a verified peer. The engine goes
/// further and takes nothing: while the offerer has no answer, the answerer's ClientHello
/// gets no reply (its connectivity checks do, RFC 8445 section 7.3), no handshake runs and
/// no channel opens. Once the answer
/// is applied the association is established (the answerer retransmits its ClientHello) and
/// the certificate it was established with is the one the answer's fingerprint names.
#[test]
fn nothing_is_accepted_before_the_fingerprint_arrives() -> Result<()> {
    let mut world = world()?;
    world.peers[0].pc.create_data_channel("data", None)?;
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1].pc.set_remote_description(now, offer)?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    assert_eq!(attribute_values(&answer.sdp, "setup"), ["active"]);
    // Candidates are known on both sides; only the answer has not reached the offerer.
    let offerer_candidate = world.peers[0].candidate()?;
    world.peers[0]
        .pc
        .add_local_candidate(offerer_candidate.clone())?;
    world.peers[1].pc.add_remote_candidate(offerer_candidate)?;
    let answerer_candidate = world.peers[1].candidate()?;
    world.peers[1]
        .pc
        .add_local_candidate(answerer_candidate.clone())?;

    world.run_for(std::time::Duration::from_secs(3), |_| false);
    assert!(
        !world.peers[1].written.is_empty(),
        "the answerer sent its checks"
    );
    // The ICE agent answers a Binding request that arrives before the remote description
    // (RFC 8445 section 7.3); what must not leave is anything else (RFC 7983: a first byte
    // of 0 to 3 is STUN): no DTLS record, no SRTP.
    assert!(
        world.peers[0]
            .written
            .iter()
            .all(|datagram| datagram.first().is_some_and(|first| *first <= 3)),
        "the offerer replied with more than STUN to a peer it has no fingerprint for"
    );
    let now = world.now;
    assert!(matches!(
        world.peers[0].dtls_state(now),
        RTCDtlsTransportState::New | RTCDtlsTransportState::Unspecified
    ));
    assert!(world.peers[0].channel.is_none() && world.peers[1].channel.is_none());
    assert!(world.peers[0].received.is_empty());

    world.peers[0].pc.set_remote_description(now, answer)?;
    world.peers[0].pc.add_remote_candidate(answerer_candidate)?;
    world.run("after the answer", |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    world.ping_pong("after the answer")?;
    Ok(())
}

/// RFC 8122 section 5: `UHEX = DIGIT / %x41-46`. A lower-case fingerprint is refused by default
/// (see `a_malformed_fingerprint_is_refused_by_set_remote_description`);
/// `SettingEngineBuilder::with_lowercase_fingerprints_accepted` reads it, as browsers do, and
/// the certificate is verified against it.
#[test]
fn lower_case_fingerprints_are_read_on_request() -> Result<()> {
    let mut world = World::new(
        Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?,
        Peer::new(
            "10.0.0.2:5000",
            SettingEngineBuilder::new()
                .with_lowercase_fingerprints_accepted(true)
                .build(),
        )?,
    );
    world.peers[0].pc.create_data_channel("data", None)?;
    world.exchange_with(
        0,
        |sdp| {
            let fingerprint = attribute_values(sdp, "fingerprint").remove(0);
            let (hash, value) = fingerprint
                .split_once(' ')
                .expect("hash-func SP fingerprint");
            replace_lines(
                sdp,
                "a=fingerprint:",
                Some(&format!("a=fingerprint:{hash} {}", value.to_lowercase())),
            )
        },
        keep,
    )?;
    world.trickle()?;
    world.run("a lower-case fingerprint", |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    world.ping_pong("a lower-case fingerprint")?;
    Ok(())
}

/// RFC 9429 section 5.8.3: the DTLS setup value "MUST be set according to the rules specified
/// in [RFC5763], Section 5", whose answerer "MUST use either a setup attribute value of
/// setup:active or setup:passive": an answer saying `actpass` is refused, and the offerer
/// stays in `have-local-offer`.
#[test]
fn an_answer_saying_actpass_is_refused() -> Result<()> {
    let mut world = world()?;
    world.peers[0].pc.create_data_channel("data", None)?;
    let refused = world.exchange_with(0, keep, |answer| {
        replace_lines(answer, "a=setup:", Some("a=setup:actpass"))
    });
    assert!(refused.is_err(), "{refused:?}");
    assert!(world.peers[0].pc.remote_description().is_none());
    Ok(())
}

/// RFC 9429 section 5.8.3: the setup value "MUST be consistent with the selected role of the
/// current DTLS connection, if one exists and is being continued". After the first exchange
/// the answerer is the DTLS client (`active`); a later answer that keeps the association (the
/// same `tls-id`, no ICE restart) but says `passive`, taking the offerer's server role, is
/// refused; the same answer saying `active` is taken.
#[test]
fn a_continued_association_keeps_its_roles() -> Result<()> {
    let mut world = world()?;
    world.connect()?;
    let now = world.now;
    assert_eq!(world.peers[1].dtls_role(now), RTCDtlsRole::Client);
    let refused = world.exchange_with(0, keep, |answer| {
        replace_lines(answer, "a=setup:", Some("a=setup:passive"))
    });
    assert!(refused.is_err(), "{refused:?}");
    world.peers[0]
        .pc
        .set_local_description(world.now, RTCSessionDescription::rollback(None)?)?;
    world.exchange(0)?;
    world.ping_pong("after the later exchange")?;
    Ok(())
}
