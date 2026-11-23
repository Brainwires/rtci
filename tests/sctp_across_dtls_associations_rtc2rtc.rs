//! The SCTP association and its data channels across changes of the DTLS association under
//! them, between two engines in memory on a virtual clock.
//!
//! RFC 8841 section 10.5: "if a DTLS association is closed and replaced with a new DTLS
//! association as a result of some other action [RFC8842], the state of the SCTP association
//! is not affected", and section 9.1: "The SCTP association, the DTLS association, and the
//! TCP connection are managed independently from each other." So when an offer/answer exchange
//! replaces the DTLS association (a changed `a=tls-id`, or changed `a=setup` roles, RFC 8842
//! section 3.1) the association goes on over the new one, with its channels open and what was
//! in flight delivered by retransmission.
//!
//! A DTLS transport the peer *closed* (its `close_notify`) is another matter: the SCTP
//! association ended with it, its channels are closed, and RFC 8841 section 9.3 applies ("SCTP
//! associations might be closed without SDP signaling ... New (different than the ones
//! currently used) SCTP ports MUST be used by both endpoints"): the next exchange negotiates
//! a new association, which both endpoints initiate once the new DTLS handshake completes.

mod dc_common;

use anyhow::Result;
use dc_common::{Pair, Peer};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{RTCDtlsRole, RTCDtlsTransportState, RTCSctpTransportState};
use rtc::sansio::Protocol;
use rtc::statistics::StatsSelector;
use std::time::Instant;

/// The value of the first `a=<key>:` line of `sdp`.
fn attribute(sdp: &str, key: &str) -> String {
    let prefix = format!("a={key}:");
    sdp.lines()
        .find_map(|line| line.trim_end().strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("a={key} in\n{sdp}"))
        .to_owned()
}

/// `sdp` with every line that starts with `prefix` replaced by `replacement`.
fn replace_lines(sdp: &str, prefix: &str, replacement: &str) -> String {
    let mut out = String::new();
    for line in sdp.lines() {
        let line = line.trim_end();
        out.push_str(if line.starts_with(prefix) {
            replacement
        } else {
            line
        });
        out.push_str("\r\n");
    }
    out
}

fn keep(sdp: &str) -> String {
    sdp.to_owned()
}

/// `RTCTransportStats.dtlsRole`: the role in the association whose handshake completed last.
fn dtls_role(peer: &mut Peer, now: Instant) -> RTCDtlsRole {
    peer.pc
        .get_stats(now, StatsSelector::None)
        .transport()
        .map(|transport| transport.dtls_role)
        .unwrap_or_default()
}

fn dtls_roles(pair: &mut Pair) -> (RTCDtlsRole, RTCDtlsRole) {
    let now = pair.now;
    (
        dtls_role(&mut pair.offerer, now),
        dtls_role(&mut pair.answerer, now),
    )
}

/// How often the peer connection went to `connecting`: once for the first DTLS association,
/// and once more for each one that replaced it.
fn times_connecting(peer: &Peer) -> usize {
    peer.connection_states
        .iter()
        .filter(|state| **state == RTCPeerConnectionState::Connecting)
        .count()
}

/// The events that open, fail or close a data channel, of all those the peer raised (the rest
/// report buffered amounts).
fn channel_lifecycle(peer: &Peer) -> Vec<RTCDataChannelEvent> {
    peer.events
        .iter()
        .filter(|event| {
            matches!(
                event,
                RTCDataChannelEvent::OnOpen(_)
                    | RTCDataChannelEvent::OnError(_)
                    | RTCDataChannelEvent::OnClosing(_)
                    | RTCDataChannelEvent::OnClose(_)
            )
        })
        .cloned()
        .collect()
}

fn lifecycle_events(pair: &Pair) -> (usize, usize) {
    (
        channel_lifecycle(&pair.offerer).len(),
        channel_lifecycle(&pair.answerer).len(),
    )
}

fn reconnected(peer: &Peer, connecting_before: usize) -> bool {
    times_connecting(peer) > connecting_before && peer.connected()
}

/// A connected pair with one open channel that has carried a message each way. Returns the
/// channel's handle on the offerer and on the answerer.
fn connected(
    answerer_role: RTCDtlsRole,
) -> Result<(
    Pair,
    rtc::data_channel::RTCDataChannelId,
    rtc::data_channel::RTCDataChannelId,
)> {
    // The exchanges below replace the DTLS association on the ICE session they have: RFC
    // 8842 section 3.1 alone, which a peer connection accepts only with this setting (RFC
    // 9429 sections 5.8.3 and 5.11 ask for an ICE restart with it).
    let engine = |role: RTCDtlsRole| {
        SettingEngineBuilder::new()
            .with_answering_dtls_role(role)
            .with_dtls_new_association_without_ice_restart(true)
    };
    let offerer_role = match answerer_role {
        RTCDtlsRole::Client => RTCDtlsRole::Server,
        _ => RTCDtlsRole::Client,
    };
    let mut pair = Pair::with_setting_engines(
        "127.0.0.1:50010",
        engine(offerer_role),
        "127.0.0.1:50011",
        engine(answerer_role),
    )?;
    let local = pair.offerer.pc.create_data_channel("data", None)?.id();
    pair.negotiate()?;
    assert!(
        pair.run_until(|p| !p.offerer.opened().is_empty() && !p.answerer.opened().is_empty())?,
        "the first channel never opened"
    );
    let remote = pair.answerer.opened()[0];
    // Records of the association being replaced may still arrive at its successor.
    pair.offerer.tolerate_read_errors = true;
    pair.answerer.tolerate_read_errors = true;
    assert!(pair.deliver(false, local, b"before, to the answerer")?);
    assert!(pair.deliver(true, remote, b"before, to the offerer")?);
    Ok((pair, local, remote))
}

/// The association and its channel after the DTLS association was replaced: no channel event
/// was raised, the transport never left `connected`, a message written while the new
/// handshake ran arrived, and data crosses in both directions.
fn assert_the_association_went_on(
    pair: &mut Pair,
    local: rtc::data_channel::RTCDataChannelId,
    remote: rtc::data_channel::RTCDataChannelId,
    events_before: (usize, usize),
    what: &str,
) -> Result<()> {
    assert!(
        pair.run_until(|p| p
            .answerer
            .received
            .iter()
            .any(|(_, _, data)| data == b"written during the change"))?,
        "{what}: the message in flight was not retransmitted over the new association"
    );
    assert!(
        pair.deliver(false, local, b"after, to the answerer")?,
        "{what}"
    );
    assert!(
        pair.deliver(true, remote, b"after, to the offerer")?,
        "{what}"
    );
    assert_eq!(
        lifecycle_events(pair),
        events_before,
        "{what}: no data channel was closed, failed or opened again: {:?} / {:?}",
        pair.offerer.events,
        pair.answerer.events
    );
    for peer in [&pair.offerer, &pair.answerer] {
        let sctp = peer.pc.sctp().expect("SCTP");
        assert_eq!(sctp.state(), RTCSctpTransportState::Connected, "{what}");
        assert_eq!(
            sctp.transport().state(),
            RTCDtlsTransportState::Connected,
            "{what}"
        );
    }
    Ok(())
}

/// A changed `a=tls-id` asks for a new DTLS association (RFC 8842 section 3.1), with the
/// roles the first one had. The SCTP association is not affected: same `a=sctp-port` on both
/// sides, the channel stays open and goes on carrying data, whichever DTLS role each side
/// has.
#[test]
fn a_new_dtls_association_with_the_same_roles_leaves_the_sctp_association_alone() -> Result<()> {
    for answerer_role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
        let what = format!("answerer as DTLS {answerer_role}");
        let (mut pair, local, remote) = connected(answerer_role)?;
        let roles = dtls_roles(&mut pair);
        let tls_ids = (
            attribute(
                &pair.offerer.pc.local_description().expect("offer").sdp,
                "tls-id",
            ),
            attribute(
                &pair.answerer.pc.local_description().expect("answer").sdp,
                "tls-id",
            ),
        );
        let events = lifecycle_events(&pair);
        let connecting = (
            times_connecting(&pair.offerer),
            times_connecting(&pair.answerer),
        );

        let now = pair.now;
        pair.offerer
            .pc
            .data_channel(local)
            .expect("the channel")
            .send(
                now,
                bytes::BytesMut::from(&b"written during the change"[..]),
            )?;
        // The answerer is shown another tls-id than the association's: a new association.
        let (offer, answer) = pair.exchange_with(
            false,
            |sdp| {
                replace_lines(
                    sdp,
                    "a=tls-id:",
                    "a=tls-id:AnotherDtlsAssociation0123456789",
                )
            },
            keep,
        )?;
        assert_eq!(attribute(&offer, "tls-id"), tls_ids.0, "{what}");
        assert_ne!(
            attribute(&answer, "tls-id"),
            tls_ids.1,
            "{what}: the answerer made a new association and says so"
        );
        assert_eq!(attribute(&offer, "sctp-port"), "5000", "{what}");
        assert_eq!(
            attribute(&answer, "sctp-port"),
            "5000",
            "{what}: the SCTP association is the one it was"
        );

        assert!(
            pair.run_until(
                |p| reconnected(&p.offerer, connecting.0) && reconnected(&p.answerer, connecting.1)
            )?,
            "{what}: no new DTLS association: {:?} / {:?}",
            pair.offerer.connection_states,
            pair.answerer.connection_states
        );
        assert_eq!(dtls_roles(&mut pair), roles, "{what}: the roles are kept");
        assert_the_association_went_on(&mut pair, local, remote, events, &what)?;
    }
    Ok(())
}

/// A description whose `a=setup` takes the role its receiver has asks for a new DTLS
/// association with the roles swapped (RFC 8842 section 3.1). The SCTP association is not
/// affected by that either: it does not depend on the DTLS roles (RFC 8841 section 9.3: both
/// endpoints initiate, whatever `a=setup` says). Channels opened afterwards, from either
/// side, take stream identifiers of the new parity (RFC 8832 section 6) and do not collide
/// with the one that is open.
#[test]
fn a_new_dtls_association_with_swapped_roles_leaves_the_sctp_association_alone() -> Result<()> {
    for answerer_role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
        let what = format!("answerer first as DTLS {answerer_role}");
        let (mut pair, local, remote) = connected(answerer_role)?;
        let roles = dtls_roles(&mut pair);
        assert_ne!(roles.0, roles.1);
        let events = lifecycle_events(&pair);
        let connecting = (
            times_connecting(&pair.offerer),
            times_connecting(&pair.answerer),
        );

        let now = pair.now;
        pair.offerer
            .pc
            .data_channel(local)
            .expect("the channel")
            .send(
                now,
                bytes::BytesMut::from(&b"written during the change"[..]),
            )?;
        // The offerer's description claims the role the answerer has.
        let claimed = if roles.1 == RTCDtlsRole::Client {
            "a=setup:active"
        } else {
            "a=setup:passive"
        };
        let (offer, answer) =
            pair.exchange_with(false, |sdp| replace_lines(sdp, "a=setup:", claimed), keep)?;
        assert_eq!(attribute(&offer, "sctp-port"), "5000", "{what}");
        assert_eq!(attribute(&answer, "sctp-port"), "5000", "{what}");

        assert!(
            pair.run_until(
                |p| reconnected(&p.offerer, connecting.0) && reconnected(&p.answerer, connecting.1)
            )?,
            "{what}: no new DTLS association: {:?} / {:?}",
            pair.offerer.connection_states,
            pair.answerer.connection_states
        );
        assert_eq!(
            dtls_roles(&mut pair),
            (roles.1, roles.0),
            "{what}: the roles are swapped"
        );
        assert_the_association_went_on(&mut pair, local, remote, events, &what)?;

        // A new channel from each side, on the association that went on.
        let from_offerer = pair
            .offerer
            .pc
            .create_data_channel("from the offerer", None)?
            .id();
        let from_answerer = pair
            .answerer
            .pc
            .create_data_channel("from the answerer", None)?
            .id();
        assert!(
            pair.run_until(|p| p.offerer.opened().len() == 3 && p.answerer.opened().len() == 3)?,
            "{what}: the new channels did not open: {:?} / {:?}",
            pair.offerer.events,
            pair.answerer.events
        );
        assert!(pair.deliver(false, from_offerer, b"on the offerer's new channel")?);
        assert!(pair.deliver(true, from_answerer, b"on the answerer's new channel")?);
        assert!(pair.deliver(false, local, b"and on the first one")?);
    }
    Ok(())
}

const UFRAG: &str = "successorufrag";
const PWD: &str = "successorpasswordsuccesso";

/// A peer at the offerer's address with the offerer's ICE credentials: the peer connection
/// that is closed, and the one that takes its place.
fn offerer_engine() -> SettingEngineBuilder {
    SettingEngineBuilder::new()
        .with_ice_credentials(UFRAG.to_owned(), PWD.to_owned())
        .with_answering_dtls_role(RTCDtlsRole::Server)
}

/// The peer closes its peer connection: its DTLS `close_notify` ends the SCTP association
/// here, and the data channels are closed (RFC 8831 section 6.2: closing the association
/// closes its channels), each with a `close` event. A peer connection that takes the closed
/// one's place then negotiates a new DTLS association, and with it a new SCTP association: the
/// endpoint that lost the old one answers with a new `a=sctp-port` (RFC 8841 section 9.3),
/// both initiate when the DTLS handshake completes, and a new channel opens and carries data.
/// The channels of the association that ended stay closed.
#[test]
fn after_the_peer_closed_dtls_the_channels_are_closed_and_a_new_association_is_initiated()
-> Result<()> {
    const A: &str = "127.0.0.1:50010";
    const B: &str = "127.0.0.1:50011";
    for answerer_role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
        let what = format!("the peer that stays answers as DTLS {answerer_role}");
        let mut pair = Pair::with_setting_engines(
            A,
            offerer_engine(),
            B,
            SettingEngineBuilder::new().with_answering_dtls_role(answerer_role),
        )?;
        let first = pair.open_channel("first")?;
        let first_remote = pair.answerer.opened()[0];
        assert!(pair.deliver(false, first, b"on the first association")?);
        assert!(pair.deliver(true, first_remote, b"and back")?);
        pair.answerer.tolerate_read_errors = true;

        pair.offerer.pc.close()?;
        assert!(
            pair.run_until(|p| p.answerer.closed(first_remote))?,
            "{what}: the channel was not closed: {:?}",
            pair.answerer.events
        );
        let sctp = pair.answerer.pc.sctp().expect("SCTP");
        assert_eq!(sctp.state(), RTCSctpTransportState::Closed, "{what}");
        assert_eq!(
            sctp.transport().state(),
            RTCDtlsTransportState::Closed,
            "{what}"
        );

        // Another peer connection takes the closed one's place, and offers.
        pair.offerer = Peer::with_setting_engine(A.parse()?, offerer_engine(), pair.now)?;
        pair.offerer.tolerate_read_errors = true;
        let second = pair.offerer.pc.create_data_channel("second", None)?.id();
        let (offer, answer) = pair.exchange_with(false, keep, keep)?;
        assert_eq!(attribute(&offer, "sctp-port"), "5000", "{what}");
        assert_eq!(
            attribute(&answer, "sctp-port"),
            "5001",
            "{what}: the association that ended is not taken up again"
        );

        assert!(
            pair.run_until(
                |p| p.offerer.opened().contains(&second) && p.answerer.opened().len() == 2
            )?,
            "{what}: no channel on the new association: {:?} / {:?}, {:?} / {:?}",
            pair.offerer.events,
            pair.answerer.events,
            pair.offerer.connection_states,
            pair.answerer.connection_states
        );
        let second_remote = pair.answerer.opened()[1];
        assert!(pair.deliver(false, second, b"on the second association")?);
        assert!(pair.deliver(true, second_remote, b"and back")?);
        for peer in [&pair.offerer, &pair.answerer] {
            assert_eq!(
                peer.pc.sctp().expect("SCTP").state(),
                RTCSctpTransportState::Connected,
                "{what}"
            );
        }
        assert!(
            pair.answerer.pc.data_channel(first_remote).is_none(),
            "{what}: the first channel stays closed"
        );
    }
    Ok(())
}
