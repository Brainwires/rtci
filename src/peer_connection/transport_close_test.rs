//! What is left of the transports once an answer rejected every m= section (W3C webrtc-pc
//! 4.4.1.4, "close the RTCDtlsTransports and their associated RTCIceTransports"; RFC 9429
//! section 5.11): one transport, new and not started, with nothing of the closed ones.
//! The events and the traffic of the new transport are `tests/transport_close_rtc2rtc.rs`.

use std::time::Instant;

use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use crate::peer_connection::configuration::{RTCBundlePolicy, RTCConfigurationBuilder};
use crate::peer_connection::event::{RTCPeerConnectionEvent, RTCTransportEventKind};
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
use crate::peer_connection::transport::ice::state::RTCIceTransportState;
use crate::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit, RTCTransportId,
};
use crate::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use crate::rtp_transceiver::RTCRtpTransceiverId;
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use shared::error::Result;

fn peer(policy: RTCBundlePolicy, discard_candidates: bool) -> Result<RTCPeerConnection> {
    peer_with(policy, discard_candidates, false)
}

/// `peer`, a new DTLS association running on the previous addresses when
/// `previous_addresses` (`with_dtls_new_association_on_previous_addresses`).
fn peer_with(
    policy: RTCBundlePolicy,
    discard_candidates: bool,
    previous_addresses: bool,
) -> Result<RTCPeerConnection> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_bundle_policy(policy)
                .build(),
        )
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_discard_local_candidates_during_ice_restart(discard_candidates)
                .with_dtls_new_association_on_previous_addresses(previous_addresses)
                .build(),
        )
        .build(Instant::now())
}

fn host(port: u16) -> RTCIceCandidateInit {
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "127.0.0.1".to_owned(),
            port,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .expect("a host candidate");
    RTCIceCandidate::from(&candidate)
        .to_json()
        .expect("a candidate init")
}

fn exchange(offerer: &mut RTCPeerConnection, answerer: &mut RTCPeerConnection) -> Result<()> {
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    offerer.set_remote_description(now, answer)
}

/// What identifies the default transport: the ids of its ICE and DTLS transports and its
/// local ICE username fragment.
fn default_transport(pc: &RTCPeerConnection) -> (RTCTransportId, RTCTransportId, String) {
    (
        pc.ice_transport().id,
        pc.dtls_transport().id,
        pc.ice_transport()
            .agent
            .get_local_credentials()
            .ufrag
            .clone(),
    )
}

/// The (ICE transport, DTLS transport) ids of the queued events that close a transport: its
/// DTLS `statechange`, then its ICE one.
fn closed(pc: &RTCPeerConnection) -> Vec<(&'static str, RTCTransportId, RTCTransportId)> {
    pc.pipeline_context
        .event_outs
        .iter()
        .filter_map(|event| match event {
            RTCPeerConnectionEvent::OnTransportEvent(event) => match event.event {
                RTCTransportEventKind::DtlsStateChange(RTCDtlsTransportState::Closed) => {
                    Some(("dtls", event.ice_transport, event.dtls_transport))
                }
                RTCTransportEventKind::IceStateChange(RTCIceTransportState::Closed) => {
                    Some(("ice", event.ice_transport, event.dtls_transport))
                }
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn stop_everything(pc: &mut RTCPeerConnection, transceivers: &[RTCRtpTransceiverId]) -> Result<()> {
    for id in transceivers {
        pc.rtp_transceiver(*id).expect("transceiver").stop()?;
    }
    Ok(())
}

/// One transport: the answer that rejects its only section closes it (both events, at the
/// transport that was there) and leaves a new one in its place: other ids, other ICE
/// credentials, state "new", its role not determined, no m= section on it. The DTLS
/// association the next description sets up on it runs on a new 3-tuple (RFC 8842 section
/// 5.1): the local candidate the application gathered is not kept and its address is refused.
/// With `with_dtls_new_association_on_previous_addresses(true)` it is the new agent's too,
/// unless local candidates are discarded with an ICE generation.
#[test]
fn rejecting_the_only_section_leaves_one_new_transport() -> Result<()> {
    for (discard_candidates, previous_addresses) in [(false, true), (true, true), (false, false)] {
        let kept = previous_addresses && !discard_candidates;
        let mut offerer = peer_with(
            RTCBundlePolicy::default(),
            discard_candidates,
            previous_addresses,
        )?;
        let mut answerer = peer_with(
            RTCBundlePolicy::default(),
            discard_candidates,
            previous_addresses,
        )?;
        let audio = offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
        offerer.add_local_candidate(host(50000))?;
        answerer.add_local_candidate(host(50001))?;
        exchange(&mut offerer, &mut answerer)?;
        let before = [default_transport(&offerer), default_transport(&answerer)];
        assert!(offerer.ice_transport().role_determined);

        stop_everything(&mut offerer, &[audio])?;
        for pc in [&mut offerer, &mut answerer] {
            pc.pipeline_context.event_outs.clear();
        }
        exchange(&mut offerer, &mut answerer)?;

        for (pc, before) in [(&offerer, &before[0]), (&answerer, &before[1])] {
            assert_eq!(
                closed(pc),
                vec![("dtls", before.0, before.1), ("ice", before.0, before.1)],
                "the transport that was in use is closed"
            );
            let after = default_transport(pc);
            assert_eq!(pc.pipeline_context.transports.len(), 1);
            assert_ne!(after.0, before.0, "a new ICE transport");
            assert_ne!(after.1, before.1, "a new DTLS transport");
            assert_ne!(after.2, before.2, "credentials of a new generation");
            assert_eq!(pc.ice_transport().state(), RTCIceTransportState::New);
            assert_eq!(pc.dtls_transport().state(), RTCDtlsTransportState::New);
            assert!(!pc.ice_transport().role_determined, "a role to determine");
            let default = pc.pipeline_context.transports.default_id();
            assert!(pc.pipeline_context.transports.mids_on(default).is_empty());
            assert_eq!(
                pc.ice_transport().agent.get_local_candidates().len(),
                usize::from(kept),
                "the gathered candidate, discard {discard_candidates}, previous addresses \
                 {previous_addresses}"
            );
            assert!(
                pc.ice_transport().agent.get_remote_candidates().is_empty(),
                "the closed generation's remote candidates are gone"
            );
        }
        for (pc, port) in [(&mut offerer, 50000), (&mut answerer, 50001)] {
            assert_eq!(
                pc.add_local_candidate(host(port)).is_err(),
                !previous_addresses,
                "the previous address is refused for the new association unless \
                 previous addresses {previous_addresses}"
            );
        }
    }
    Ok(())
}

/// Several transports (`max-compat`, answered without BUNDLE): the answer that rejects every
/// section closes each of them, and one new transport is left.
#[test]
fn rejecting_every_section_closes_each_of_several_transports() -> Result<()> {
    let mut offerer = peer(RTCBundlePolicy::MaxCompat, false)?;
    let mut answerer = peer(RTCBundlePolicy::MaxCompat, false)?;
    let audio = offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let video = offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    let mut answer = answerer.create_answer(None)?;
    // An answerer that does not bundle: each section keeps its transport.
    answer.sdp = answer
        .sdp
        .lines()
        .filter(|l| !l.starts_with("a=group:BUNDLE"))
        .map(|l| format!("{l}\r\n"))
        .collect();
    offerer.set_remote_description(now, answer)?;
    assert_eq!(offerer.pipeline_context.transports.len(), 2);
    let before: Vec<(RTCTransportId, RTCTransportId)> = offerer
        .pipeline_context
        .transports
        .ids()
        .into_iter()
        .map(|id| {
            (
                offerer.ice_transport_of(id).id,
                offerer.dtls_transport_of(id).id,
            )
        })
        .collect();

    stop_everything(&mut offerer, &[audio, video])?;
    offerer.pipeline_context.event_outs.clear();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    // The answer to an offer that rejects everything rejects everything.
    let mut answer = offer;
    answer.sdp_type = crate::peer_connection::sdp::sdp_type::RTCSdpType::Answer;
    answer.sdp = answer.sdp.replace("a=setup:actpass", "a=setup:active");
    offerer.set_remote_description(now, answer)?;

    let mut closed_transports: Vec<(RTCTransportId, RTCTransportId)> = closed(&offerer)
        .into_iter()
        .map(|(_, ice, dtls)| (ice, dtls))
        .collect();
    closed_transports.dedup();
    let mut expected = before.clone();
    // The transports other than the default one go first; the default one is replaced.
    expected.rotate_left(1);
    assert_eq!(
        closed_transports, expected,
        "each transport is closed, once"
    );
    assert_eq!(offerer.pipeline_context.transports.len(), 1);
    let after = default_transport(&offerer);
    assert!(
        before
            .iter()
            .all(|(ice, dtls)| *ice != after.0 && *dtls != after.1),
        "the transport that is left is none of the closed ones"
    );
    Ok(())
}

/// `close()` wipes the connection's DTLS session (`with_dtls_session_resumption(true)`, RFC
/// 5764 section 3) at once, not when the connection is dropped: the tickets its DTLS client
/// side holds are dropped and none is kept after, and the keys its DTLS server side seals
/// tickets under are zeroized (review 2 of the session, R8). Every transport of the
/// connection shares that one session.
#[test]
fn closing_the_connection_wipes_its_dtls_session() -> Result<()> {
    use sansio::Protocol;
    let session_peer = |policy| -> Result<RTCPeerConnection> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_bundle_policy(policy)
                    .build(),
            )
            .with_media_engine(media_engine)
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_dtls_session_resumption(true)
                    .build(),
            )
            .build(Instant::now())
    };
    let mut offerer = session_peer(RTCBundlePolicy::MaxCompat)?;
    let mut answerer = session_peer(RTCBundlePolicy::MaxCompat)?;
    for kind in [RtpCodecKind::Audio, RtpCodecKind::Video] {
        offerer.add_transceiver_from_kind(kind, None)?;
    }
    exchange(&mut offerer, &mut answerer)?;
    for pc in [&mut offerer, &mut answerer] {
        let group = pc
            .dtls_transport()
            .resumption
            .clone()
            .expect("the connection has a session");
        for id in pc.pipeline_context.transports.ids() {
            let shared = pc.with_transport(id, |pc| pc.dtls_transport().resumption.clone());
            assert!(
                shared.is_some_and(|shared| std::sync::Arc::ptr_eq(&shared, &group)),
                "every transport has the connection's session"
            );
        }
        // (The store may be empty already: it is emptied as soon as no transport will take a
        // ticket from it any more. The keys stay for as long as the connection is open.)
        assert!(
            !group.ticket_keys_wiped(),
            "the ticket keys are held while the connection is open"
        );
        pc.close()?;
        assert!(group.store().is_emptied(), "the client side's tickets");
        assert!(group.ticket_keys_wiped(), "the server side's ticket keys");
    }
    Ok(())
}

/// Without the setting a connection has no DTLS session to wipe, and closes as before.
#[test]
fn a_connection_without_the_dtls_session_setting_has_none() -> Result<()> {
    use sansio::Protocol;
    let mut pc = peer(RTCBundlePolicy::MaxCompat, false)?;
    assert!(pc.dtls_transport().resumption.is_none());
    pc.close()?;
    Ok(())
}
