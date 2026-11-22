//! RFC 8841 section 12.2: "When transitioning between candidate pairs, different candidate
//! pairs can be currently active in different directions, and implementations MUST be ready to
//! receive data on any of the candidates".
//!
//! Two peers in memory on a virtual clock, each with two host candidates. Once the channel is
//! open, every datagram the answerer writes reaches the offerer on the offerer's other
//! candidate: the answerer sends on another pair than the one the offerer sends on. Data
//! channel messages, a large one among them, still cross both ways, over the one DTLS and SCTP
//! association there was (no handshake record is written after the switch).

mod dc_common;

use anyhow::{Result, ensure};
use bytes::BytesMut;
use dc_common::Peer;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

fn host(addr: SocketAddr) -> Result<RTCIceCandidateInit> {
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: addr.ip().to_string(),
            port: addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    Ok(RTCIceCandidate::from(&candidate).to_json()?)
}

#[derive(Default)]
struct Seen {
    opened: Vec<usize>,
    lifecycle: Vec<RTCDataChannelEvent>,
    received: Vec<Vec<u8>>,
}

fn collect(pc: &mut RTCPeerConnection, seen: &mut Seen) {
    while let Some(event) = pc.poll_event() {
        if let RTCPeerConnectionEvent::OnDataChannel(event) = event {
            match event {
                RTCDataChannelEvent::OnOpen(id) => seen.opened.push(id),
                RTCDataChannelEvent::OnBufferedAmountLow(_)
                | RTCDataChannelEvent::OnBufferedAmountHigh(_) => {}
                other => seen.lifecycle.push(other),
            }
        }
    }
    while let Some(read) = pc.poll_read() {
        if let RTCMessage::DataChannelMessage(_, message) = read.message {
            seen.received.push(message.data.to_vec());
        }
    }
}

#[test]
fn data_is_received_while_the_two_directions_take_different_candidate_pairs() -> Result<()> {
    let now = Instant::now();
    let offerer_addrs: [SocketAddr; 2] = ["127.0.0.1:50010".parse()?, "127.0.0.1:50012".parse()?];
    let answerer_addrs: [SocketAddr; 2] = ["127.0.0.1:50011".parse()?, "127.0.0.1:50013".parse()?];
    let mut offerer = Peer::new(offerer_addrs[0], RTCDtlsRole::Server, now)?.pc;
    let mut answerer = Peer::new(answerer_addrs[0], RTCDtlsRole::Client, now)?.pc;
    offerer.add_local_candidate(host(offerer_addrs[1])?)?;
    answerer.add_local_candidate(host(answerer_addrs[1])?)?;

    let channel = offerer.create_data_channel("both-ways", None)?.id();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    offerer.set_remote_description(now, answer)?;
    for addr in offerer_addrs {
        answerer.add_remote_candidate(host(addr)?)?;
    }
    for addr in answerer_addrs {
        offerer.add_remote_candidate(host(addr)?)?;
    }

    let mut now = now;
    let deadline = now + Duration::from_secs(60);
    let (mut seen_offerer, mut seen_answerer) = (Seen::default(), Seen::default());
    // Once set, what the answerer writes reaches the offerer on its other candidate.
    let mut asymmetric = false;
    let mut handshake_records_after_switch = 0usize;
    let big = vec![7u8; 60_000];
    let mut phase = 0;
    loop {
        ensure!(now < deadline, "phase {phase} did not complete");
        let to_answerer: Vec<_> = std::iter::from_fn(|| offerer.poll_write()).collect();
        let to_offerer: Vec<_> = std::iter::from_fn(|| answerer.poll_write()).collect();
        let quiet = to_answerer.is_empty() && to_offerer.is_empty();
        for d in to_answerer {
            if asymmetric && d.message.first() == Some(&22) {
                handshake_records_after_switch += 1;
            }
            answerer.handle_read(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: d.transport.peer_addr,
                    peer_addr: d.transport.local_addr,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: d.message,
            })?;
        }
        for d in to_offerer {
            if asymmetric && d.message.first() == Some(&22) {
                handshake_records_after_switch += 1;
            }
            let mut arrives_at = d.transport.peer_addr;
            if asymmetric {
                // The answerer's pair: to the offerer's other candidate.
                arrives_at = if arrives_at == offerer_addrs[0] {
                    offerer_addrs[1]
                } else {
                    offerer_addrs[0]
                };
            }
            offerer.handle_read(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: arrives_at,
                    peer_addr: d.transport.local_addr,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: d.message,
            })?;
        }
        collect(&mut offerer, &mut seen_offerer);
        collect(&mut answerer, &mut seen_answerer);

        match phase {
            // The channel opens over whatever pairs ICE selected.
            0 if seen_offerer.opened.contains(&channel) && !seen_answerer.opened.is_empty() => {
                asymmetric = true;
                let remote = seen_answerer.opened[0];
                offerer
                    .data_channel(channel)
                    .expect("open")
                    .send(now, BytesMut::from(&b"to the answerer"[..]))?;
                answerer
                    .data_channel(remote)
                    .expect("open")
                    .send(now, BytesMut::from(&b"to the offerer"[..]))?;
                offerer
                    .data_channel(channel)
                    .expect("open")
                    .send(now, BytesMut::from(&big[..]))?;
                answerer
                    .data_channel(remote)
                    .expect("open")
                    .send(now, BytesMut::from(&big[..]))?;
                phase = 1;
            }
            1 if seen_offerer.received.len() == 2 && seen_answerer.received.len() == 2 => break,
            _ => {}
        }

        if quiet {
            let next = [offerer.poll_timeout(), answerer.poll_timeout()]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(now + Duration::from_secs(1));
            now = now.max(next);
            offerer.handle_timeout(now)?;
            answerer.handle_timeout(now)?;
        }
    }

    assert_eq!(
        seen_offerer.received,
        vec![b"to the offerer".to_vec(), big.clone()]
    );
    assert_eq!(
        seen_answerer.received,
        vec![b"to the answerer".to_vec(), big]
    );
    assert_eq!(
        handshake_records_after_switch, 0,
        "one DTLS association: no handshake after the directions split"
    );
    assert!(
        seen_offerer.lifecycle.is_empty() && seen_answerer.lifecycle.is_empty(),
        "the channel stays open: {:?} / {:?}",
        seen_offerer.lifecycle,
        seen_answerer.lifecycle
    );
    assert_eq!(
        seen_offerer.opened,
        vec![channel],
        "one channel, opened once"
    );
    Ok(())
}
