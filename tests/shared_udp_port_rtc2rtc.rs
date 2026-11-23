//! One UDP port shared by two peer connections, as a server does it: both announce the same
//! host candidate, and what arrives on the port goes to the connection the first Binding
//! request from each remote address names by its ICE ufrag (`rtc-stream-driver`'s `UfragMux`,
//! fed `RTCPeerConnection::ice_username_fragment`). Two remote peers connect, one to each, on
//! a virtual clock; nothing crosses between the sessions.

use anyhow::{Result, bail};
use bytes::BytesMut;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::transport::RTCIceCandidateInit;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use stream_driver::sockets::UfragMux;

struct Node {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    received: Vec<Vec<u8>>,
    open: Option<rtc::data_channel::RTCDataChannelId>,
}

fn node(addr: &str) -> Node {
    let pc = RTCPeerConnectionBuilder::new()
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_tcp_candidate_gathering(false)
                .build(),
        )
        .build(Instant::now())
        .unwrap();
    Node {
        pc,
        addr: addr.parse().unwrap(),
        received: vec![],
        open: None,
    }
}

fn host(addr: SocketAddr) -> RTCIceCandidateInit {
    RTCIceCandidateInit {
        candidate: format!(
            "candidate:1 1 udp 2130706431 {} {} typ host",
            addr.ip(),
            addr.port()
        ),
        ..Default::default()
    }
}

#[test]
fn two_peer_connections_share_one_udp_port_routed_by_ufrag() -> Result<()> {
    // 0 and 1 share 10.0.0.1:4000; 2 talks to 0, 3 to 1.
    let mut nodes = vec![
        node("10.0.0.1:4000"),
        node("10.0.0.1:4000"),
        node("10.0.0.2:4000"),
        node("10.0.0.3:4000"),
    ];
    let pairs = [(0usize, 2usize), (1, 3)];
    let start = Instant::now();
    let mut now = start;
    let mut mux = UfragMux::new();
    for &(server, client) in &pairs {
        let channel = nodes[client].pc.create_data_channel("shared", None)?.id();
        let offer = nodes[client].pc.create_offer(None)?;
        nodes[client].pc.set_local_description(now, offer.clone())?;
        nodes[server].pc.set_remote_description(now, offer)?;
        let answer = nodes[server].pc.create_answer(None)?;
        nodes[server]
            .pc
            .set_local_description(now, answer.clone())?;
        nodes[client].pc.set_remote_description(now, answer)?;
        mux.register(&nodes[server].pc.ice_username_fragment(), server);
        for (a, b) in [(server, client), (client, server)] {
            let c = host(nodes[a].addr);
            nodes[a].pc.add_local_candidate(c.clone())?;
            nodes[b].pc.add_remote_candidate(c)?;
        }
        let _ = channel;
    }
    let shared: SocketAddr = "10.0.0.1:4000".parse().unwrap();
    let mut in_flight: Vec<(SocketAddr, SocketAddr, Vec<u8>)> = vec![];
    let mut sent = [false, false];
    let mut misrouted = 0;
    while now - start < Duration::from_secs(20) {
        for n in nodes.iter_mut() {
            while let Some(m) = n.pc.poll_write() {
                in_flight.push((
                    m.transport.local_addr,
                    m.transport.peer_addr,
                    m.message.to_vec(),
                ));
            }
        }
        for (from, to, data) in std::mem::take(&mut in_flight) {
            let target = if to == shared {
                match mux.route(from, &data) {
                    Some(i) => Some(i),
                    None => {
                        misrouted += 1;
                        None
                    }
                }
            } else {
                nodes.iter().position(|n| n.addr == to)
            };
            if let Some(i) = target {
                let _ = nodes[i].pc.handle_read(TaggedBytesMut {
                    now,
                    transport: TransportContext {
                        local_addr: to,
                        peer_addr: from,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&data[..]),
                });
            }
        }
        for n in nodes.iter_mut() {
            while let Some(e) = n.pc.poll_event() {
                if let RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) = e {
                    n.open = Some(id);
                }
            }
            while let Some(m) = n.pc.poll_read() {
                if let RTCMessage::DataChannelMessage(_, m) = m.message {
                    n.received.push(m.data.to_vec());
                }
            }
        }
        for (k, &(_, client)) in pairs.iter().enumerate() {
            if !sent[k]
                && let Some(id) = nodes[client].open
            {
                let mut dc = nodes[client].pc.data_channel(id).unwrap();
                dc.send(now, BytesMut::from(format!("for {k}").as_bytes()))?;
                sent[k] = true;
            }
        }
        if !nodes[0].received.is_empty() && !nodes[1].received.is_empty() {
            assert_eq!(nodes[0].received, vec![b"for 0".to_vec()]);
            assert_eq!(nodes[1].received, vec![b"for 1".to_vec()]);
            assert_eq!(
                misrouted, 0,
                "every datagram on the shared port had its connection"
            );
            return Ok(());
        }
        let next = nodes
            .iter_mut()
            .filter_map(|n| n.pc.poll_timeout())
            .min()
            .unwrap_or(now + Duration::from_millis(20))
            .min(now + Duration::from_millis(20));
        now = next.max(now + Duration::from_millis(1));
        for n in nodes.iter_mut() {
            let _ = n.pc.handle_timeout(now);
        }
    }
    bail!(
        "not connected: received {:?} / {:?}, misrouted {misrouted}",
        nodes[0].received,
        nodes[1].received
    )
}
