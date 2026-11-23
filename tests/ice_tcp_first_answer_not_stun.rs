//! RFC 6544 Section 7.1: "If the response to the first connectivity check on the established
//! TCP connection is something other than a STUN message, the remote candidate address
//! apparently was not one of the peer's addresses, and the agent SHOULD close the connection
//! and consider all pairs with that remote candidate as failed."
//!
//! Through the peer connection, which demultiplexes the connection: an active TCP candidate's
//! first check goes to the remote passive candidate, and what comes back is DTLS-looking data,
//! not STUN. The pair fails at once; it used to stay in progress and be retried until the
//! check's transaction ran out.

use anyhow::Result;
use bytes::BytesMut;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::StatsSelector;
use rtc::statistics::stats::ice_candidate_pair::RTCStatsIceCandidatePairState;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const REMOTE_PASSIVE: &str = "127.0.0.2:6002";

fn tcp_pc(now: Instant) -> Result<RTCPeerConnection> {
    Ok(RTCPeerConnectionBuilder::new()
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_network_types(vec![ice::network_type::NetworkType::Tcp4])
                .build(),
        )
        .build(now)?)
}

fn pair_states(pc: &mut RTCPeerConnection, now: Instant) -> Vec<RTCStatsIceCandidatePairState> {
    pc.get_stats(now, StatsSelector::None)
        .candidate_pairs()
        .map(|p| p.state)
        .collect()
}

#[test]
fn a_first_answer_that_is_not_stun_fails_the_pair_of_an_active_tcp_candidate() -> Result<()> {
    let mut now = Instant::now();
    let mut pc = tcp_pc(now)?;
    let mut peer = tcp_pc(now)?;
    pc.create_data_channel("tcp", None)?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(now, offer.clone())?;
    peer.set_remote_description(now, offer)?;
    let answer = peer.create_answer(None)?;
    peer.set_local_description(now, answer.clone())?;
    pc.set_remote_description(now, answer)?;

    let active = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "tcp".to_owned(),
            address: "127.0.0.1".to_owned(),
            port: 9,
            component: 1,
            ..Default::default()
        },
        tcp_type: ice::tcp_type::TcpType::Active,
    }
    .new_candidate_host()?;
    pc.add_local_candidate(RTCIceCandidate::from(&active).to_json()?)?;
    // The application takes the candidate's event to trickle it: only then is it paired (RFC
    // 8838 section 10).
    while pc.poll_event().is_some() {}
    pc.add_remote_candidate(RTCIceCandidateInit {
        sdp_mline_index: Some(0),
        candidate: "candidate:1 1 tcp 2128609279 127.0.0.2 6002 typ host tcptype passive"
            .to_owned(),
        ..Default::default()
    })?;

    // The first check leaves on the connection the application opens for it.
    let remote: SocketAddr = REMOTE_PASSIVE.parse()?;
    let until = now + Duration::from_secs(2);
    let mut checked = false;
    while now < until && !checked {
        pc.handle_timeout(now)?;
        while let Some(out) = pc.poll_write() {
            checked |= out.transport.peer_addr == remote
                && out.transport.transport_protocol == TransportProtocol::TCP;
        }
        now += Duration::from_millis(10);
    }
    assert!(checked, "no check to the passive candidate");
    assert_eq!(
        pair_states(&mut pc, now),
        vec![RTCStatsIceCandidatePairState::InProgress]
    );

    // The answer on that connection is a DTLS record, not STUN.
    let mut record = BytesMut::from(&[22u8, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0][..]);
    record.resize(40, 0);
    pc.handle_read(TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: "127.0.0.1:50000".parse()?,
            peer_addr: remote,
            ecn: None,
            transport_protocol: TransportProtocol::TCP,
        },
        message: record,
    })?;
    assert_eq!(
        pair_states(&mut pc, now),
        vec![RTCStatsIceCandidatePairState::Failed],
        "the pair of that remote candidate fails at once"
    );
    Ok(())
}
