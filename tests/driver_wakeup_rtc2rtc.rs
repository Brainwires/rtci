//! Nothing a peer connection writes waits for a later wake-up.
//!
//! The crate's event loop (`src/lib.rs`) calls `poll_write`, `poll_event`, `poll_read`, then
//! `poll_timeout`, and sleeps until that deadline or the next datagram. Work made while the
//! connection serves `poll_event` or `poll_read` (a handshake step an event starts, a probe
//! cluster a congestion controller's timer asked for, an answer to a request) comes after the
//! `poll_write` of that pass: `poll_timeout` has to say it is due, or it waits for the next
//! timer, which can be a long way off. Two peers run the whole life of a call here (ICE, DTLS,
//! SCTP and a data channel, video with RTX, RTCP, bandwidth probes) under a driver that checks
//! the invariant at every sleep (`wakeup_common`).

mod wakeup_common;

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use rtc::interceptor::Registry;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use wakeup_common::{Loop, Peer};

const SSRC: u32 = 0x00c0_ffee;

fn peer(addr: &str, now: Instant) -> Result<Peer> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    let pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(now)?;
    Ok(Peer::new(addr, pc))
}

fn candidate(peer: &Peer) -> Result<rtc::peer_connection::transport::RTCIceCandidateInit> {
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: peer.addr.ip().to_string(),
            port: peer.addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    Ok(RTCIceCandidate::from(&candidate).to_json()?)
}

#[test]
fn nothing_written_while_serving_events_or_reads_waits_for_a_later_wake() -> Result<()> {
    let start = Instant::now();
    let mut run = Loop::new(
        vec![peer("10.0.0.1:5000", start)?, peer("10.0.0.2:5000", start)?],
        start,
    );

    // Peer 1 sends video (with RTX, so probe clusters are filled with padding).
    let sender = run.peers[1].pc.add_track(MediaStreamTrack::new(
        "stream".to_owned(),
        "video".to_owned(),
        "video".to_owned(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(SSRC),
                ..Default::default()
            },
            active: true,
            ..Default::default()
        }],
    ))?;
    run.peers[0].pc.create_data_channel("data", None)?;
    let offer = run.peers[0].pc.create_offer(None)?;
    run.peers[0]
        .pc
        .set_local_description(start, offer.clone())?;
    run.peers[1]
        .pc
        .set_remote_description(start, RTCSessionDescription::offer(offer.sdp)?)?;
    let answer = run.peers[1].pc.create_answer(None)?;
    run.peers[1]
        .pc
        .set_local_description(start, answer.clone())?;
    run.peers[0]
        .pc
        .set_remote_description(start, RTCSessionDescription::answer(answer.sdp.clone())?)?;
    let vp8: u8 = answer
        .sdp
        .lines()
        .find_map(|l| {
            let (pt, name) = l.strip_prefix("a=rtpmap:")?.split_once(' ')?;
            name.eq_ignore_ascii_case("VP8/90000")
                .then(|| pt.parse().ok())?
        })
        .expect("VP8 in the answer");
    for i in 0..2 {
        let init = candidate(&run.peers[i])?;
        run.peers[i].pc.add_local_candidate(init.clone())?;
        run.peers[1 - i].pc.add_remote_candidate(init)?;
    }
    assert!(
        run.run_for(Duration::from_secs(20), |peers| peers
            .iter()
            .all(|p| p.connected())
            && peers.iter().any(|p| p.channel.is_some())),
        "connected"
    );

    // Eight seconds of 20 ms frames (past the five-second application-limited probe), and a
    // data channel message each second.
    for n in 0..400u16 {
        let now = run.now;
        run.peers[1]
            .pc
            .rtp_sender(sender)
            .expect("the sender")
            .write_rtp(
                now,
                rtc::rtp::Packet {
                    header: rtc::rtp::header::Header {
                        version: 2,
                        payload_type: vp8,
                        sequence_number: n,
                        timestamp: u32::from(n) * 1800,
                        ssrc: SSRC,
                        marker: true,
                        ..Default::default()
                    },
                    payload: Bytes::from(vec![0x10u8; 600]),
                },
            )?;
        if n % 50 == 0
            && let Some(channel) = run.peers[0].channel
        {
            run.peers[0]
                .pc
                .data_channel(channel)
                .expect("the channel")
                .send(now, BytesMut::from(&b"ping"[..]))?;
        }
        run.run_for(Duration::from_millis(20), |_| false);
    }
    run.run_for(Duration::from_secs(1), |_| false);
    assert!(
        run.peers[0].rtp >= 390,
        "media arrived: {}",
        run.peers[0].rtp
    );

    let mut by_kind: BTreeMap<(usize, String), (usize, Duration)> = BTreeMap::new();
    for late in &run.late {
        let entry = by_kind
            .entry((late.peer, late.kind.clone()))
            .or_insert((0, late.at));
        entry.0 += 1;
    }
    assert!(
        run.late.is_empty(),
        "datagrams waiting while poll_timeout said to sleep, by (peer, kind): (count, first at) \
         {by_kind:?}; first: {:?}",
        run.late.first()
    );
    Ok(())
}
