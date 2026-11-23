//! RFC 8841 sections 9.3 and 10.5 between two engines, in memory on a virtual clock: an SCTP
//! association closed and replaced, or closed for good, by the `a=sctp-port` of a new
//! offer/answer exchange, over a DTLS transport that stays as it is.

mod dc_common;

use anyhow::Result;
use dc_common::Pair;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{RTCDtlsRole, RTCDtlsTransportState, RTCSctpTransportState};
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use std::time::Duration;

/// The `a=sctp-port` of the data section of `sdp`.
fn sctp_port(sdp: &str) -> String {
    sdp.lines()
        .find_map(|line| line.strip_prefix("a=sctp-port:"))
        .expect("a=sctp-port")
        .to_owned()
}

/// RFC 8841 section 9.3: "The existing SCTP association is closed, and the new SCTP
/// association is established, if one or both endpoints signal a new SCTP port", and
/// section 10.5: "This will not impact the underlying DTLS association". The channel of the
/// old association closes on both sides, and a channel created afterwards opens on the new
/// one and carries data both ways. Both sides initiate the new association, which neither
/// DTLS handshake triggers this time.
#[test]
fn a_new_sctp_port_replaces_the_association() -> Result<()> {
    for answerer_role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
        let (mut pair, first) = Pair::connected(answerer_role, "first")?;
        let first_remote = pair.answerer.opened()[0];

        let states_before = (
            pair.offerer.connection_states.len(),
            pair.answerer.connection_states.len(),
        );

        pair.offerer.pc.replace_sctp_association();
        let (offer, answer) = pair.negotiate()?;
        assert_eq!(sctp_port(&offer.sdp), "5001", "{answerer_role}");
        assert_eq!(
            sctp_port(&answer.sdp),
            "5001",
            "{answerer_role}: a new port for a new port"
        );

        let second = pair.offerer.pc.create_data_channel("second", None)?.id();
        assert!(
            pair.run_until(
                |p| p.offerer.opened().contains(&second) && p.answerer.opened().len() == 2
            )?,
            "{answerer_role}: no channel opened on the new association"
        );
        assert!(pair.offerer.closed(first), "{answerer_role}");
        assert!(pair.answerer.closed(first_remote), "{answerer_role}");
        assert_eq!(
            (
                pair.offerer.connection_states.len(),
                pair.answerer.connection_states.len()
            ),
            states_before,
            "{answerer_role}: the connection never left `connected`"
        );
        for peer in [&pair.offerer, &pair.answerer] {
            assert_eq!(
                peer.pc.sctp().expect("SCTP").state(),
                RTCSctpTransportState::Connected
            );
            assert_eq!(
                peer.connection_states.last(),
                Some(&RTCPeerConnectionState::Connected)
            );
            assert_eq!(
                peer.pc.sctp().expect("SCTP").transport().state(),
                RTCDtlsTransportState::Connected,
                "{answerer_role}: the DTLS transport is the one it was"
            );
        }

        let second_remote = pair.answerer.opened()[1];
        let now = pair.now;
        pair.offerer
            .pc
            .data_channel(second)
            .expect("second")
            .send_text(now, "ping")?;
        pair.answerer
            .pc
            .data_channel(second_remote)
            .expect("second")
            .send_text(now, "pong")?;
        assert!(
            pair.run_until(|p| !p.offerer.received.is_empty() && !p.answerer.received.is_empty())?
        );
        assert_eq!(
            pair.answerer.received,
            vec![(second_remote, true, b"ping".to_vec())]
        );
        assert_eq!(
            pair.offerer.received,
            vec![(second, true, b"pong".to_vec())]
        );
    }
    Ok(())
}

/// RFC 8841 section 9.3: "an SCTP association can be closed using the SDP 'sctp-port'
/// attribute with an attribute value of zero. Later, a new SCTP association can be
/// established". The association and its channels close on both sides, DTLS stays up, and a
/// data channel created later brings a new association with the next offer.
#[test]
fn sctp_port_zero_closes_the_association_and_a_later_offer_brings_one_back() -> Result<()> {
    for answerer_role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
        let (mut pair, first) = Pair::connected(answerer_role, "first")?;
        let first_remote = pair.answerer.opened()[0];

        pair.offerer.pc.close_sctp_association();
        let (offer, answer) = pair.negotiate()?;
        assert_eq!(sctp_port(&offer.sdp), "0");
        assert_eq!(sctp_port(&answer.sdp), "0");
        assert!(
            pair.run_until(|p| p.offerer.closed(first) && p.answerer.closed(first_remote))?,
            "{answerer_role}: the channel outlived its association"
        );
        pair.run_for(Duration::from_secs(5))?;
        for peer in [&pair.offerer, &pair.answerer] {
            assert!(peer.pc.sctp().is_none(), "{answerer_role}");
            assert_eq!(
                peer.connection_states.last(),
                Some(&RTCPeerConnectionState::Connected),
                "{answerer_role}: closing SCTP does not close DTLS"
            );
        }

        let again = pair.offerer.pc.create_data_channel("again", None)?.id();
        let (offer, answer) = pair.negotiate()?;
        assert_ne!(sctp_port(&offer.sdp), "0");
        assert_ne!(sctp_port(&answer.sdp), "0");
        assert!(
            pair.run_until(
                |p| p.offerer.opened().contains(&again) && p.answerer.opened().len() == 2
            )?,
            "{answerer_role}: no association came back"
        );
        let again_remote = pair.answerer.opened()[1];
        let now = pair.now;
        pair.offerer
            .pc
            .data_channel(again)
            .expect("again")
            .send_text(now, "back")?;
        assert!(pair.run_until(|p| !p.answerer.received.is_empty())?);
        assert_eq!(
            pair.answerer.received,
            vec![(again_remote, true, b"back".to_vec())]
        );
    }
    Ok(())
}

/// RFC 8841 section 10.4 with RFC 8261 section 6.1: an association is initiated once it is
/// negotiated and a DTLS connection exists, in whichever order the two happen. A session that
/// starts with media alone and gets its data section from a later offer has the DTLS
/// connection first: the association is initiated when the exchange completes. It used to
/// be initiated only by the DTLS handshake completing, which here was long over.
#[test]
fn a_data_channel_added_to_a_connected_session_gets_its_association() -> Result<()> {
    for answerer_role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
        let mut pair = Pair::new(answerer_role)?;
        pair.offerer.pc.add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(rtc::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
        )?;
        pair.negotiate()?;
        assert!(
            pair.run_until(|p| p.offerer.connected() && p.answerer.connected())?,
            "{answerer_role}: the media session never connected"
        );
        assert!(pair.offerer.pc.sctp().is_none());

        let channel = pair.offerer.pc.create_data_channel("later", None)?.id();
        pair.negotiate()?;
        assert!(
            pair.run_until(
                |p| p.offerer.opened().contains(&channel) && !p.answerer.opened().is_empty()
            )?,
            "{answerer_role}: the channel added later never opened"
        );
    }
    Ok(())
}

/// The value of the first `a=<key>:` line of `sdp`, if it has one.
fn attribute(sdp: &str, key: &str) -> Option<String> {
    let prefix = format!("a={key}:");
    sdp.lines()
        .find_map(|line| line.trim_end().strip_prefix(prefix.as_str()))
        .map(str::to_owned)
}

/// RFC 8841 section 10.5: "If the offerer wants to close an existing SCTP association and the
/// underlying DTLS association ..., it MUST assign a zero port value to the 'm=' line". The
/// data section, the only one of this session, is rejected in the offer and in the answer:
/// the association and its channels close on both sides, and so does the transport. A data
/// channel created later brings a new data section, and with it a new DTLS association (a
/// new `a=tls-id`, RFC 8842 section 5.5) and a new SCTP association on a new `a=sctp-port`,
/// which both sides initiate when the new DTLS handshake completes.
#[test]
fn rejecting_the_data_section_closes_sctp_and_dtls_and_a_later_channel_brings_new_ones()
-> Result<()> {
    for answerer_role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
        let (mut pair, first) = Pair::connected(answerer_role, "first")?;
        let first_remote = pair.answerer.opened()[0];
        // Records of the association that is closed may still arrive at the new one.
        pair.offerer.tolerate_read_errors = true;
        pair.answerer.tolerate_read_errors = true;
        let first_tls_id = attribute(
            &pair.offerer.pc.local_description().expect("offer").sdp,
            "tls-id",
        )
        .expect("a=tls-id");

        pair.offerer.pc.reject_data_section();
        let (offer, answer) = pair.negotiate()?;
        for sdp in [&offer.sdp, &answer.sdp] {
            assert!(
                sdp.contains("m=application 0 UDP/DTLS/SCTP webrtc-datachannel"),
                "{answerer_role}:\n{sdp}"
            );
            assert_eq!(attribute(sdp, "sctp-port"), None, "{answerer_role}");
            assert_eq!(
                attribute(sdp, "tls-id"),
                None,
                "{answerer_role}: a closed transport has no tls-id"
            );
        }
        assert!(
            pair.run_until(|p| p.offerer.closed(first) && p.answerer.closed(first_remote))?,
            "{answerer_role}: the channel outlived its association"
        );
        for peer in [&pair.offerer, &pair.answerer] {
            assert!(peer.pc.sctp().is_none(), "{answerer_role}");
        }

        let again = pair.offerer.pc.create_data_channel("again", None)?.id();
        let (offer, answer) = pair.negotiate()?;
        for sdp in [&offer.sdp, &answer.sdp] {
            assert_eq!(
                attribute(sdp, "sctp-port").as_deref(),
                Some("5001"),
                "{answerer_role}: a new association, on a new port"
            );
        }
        assert_ne!(
            attribute(&offer.sdp, "tls-id").expect("a=tls-id"),
            first_tls_id,
            "{answerer_role}: a new DTLS association"
        );
        // The offer that sets the transport up again restarts ICE, and the new association
        // runs on new 3-tuples (RFC 8842 section 5.1).
        assert!(pair.regather()?, "{answerer_role}: new candidates");
        assert!(
            pair.run_until(
                |p| p.offerer.opened().contains(&again) && p.answerer.opened().len() == 2
            )?,
            "{answerer_role}: no association came back: {:?} / {:?}, {:?} / {:?}",
            pair.offerer.events,
            pair.answerer.events,
            pair.offerer.connection_states,
            pair.answerer.connection_states
        );
        let again_remote = pair.answerer.opened()[1];
        assert!(pair.deliver(false, again, b"on the new association")?);
        assert!(pair.deliver(true, again_remote, b"and back")?);
        for peer in [&pair.offerer, &pair.answerer] {
            assert_eq!(
                peer.pc.sctp().expect("SCTP").state(),
                RTCSctpTransportState::Connected,
                "{answerer_role}"
            );
        }
    }
    Ok(())
}
