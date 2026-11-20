//! The `protocol` a data channel is created with must reach the peer that accepts it.
//!
//! Port of upstream webrtc v0.17.1's `test_data_channel_parameters_protocol_exchange`
//! (`webrtc/src/data_channel/data_channel_test.rs`): the opener's channel reports the protocol it
//! was created with, and the channel the peer accepts from the in-band `DATA_CHANNEL_OPEN`
//! (RFC 8832 §5.1, the Protocol field) reports the same one. A second channel created without a
//! protocol must arrive with the empty string, so the check cannot pass on a protocol that leaks
//! from one channel to another.
//!
//! The peers exchange datagrams in memory, on a virtual clock (the harness of
//! `data_channels_negotiated_first_message_rtc2rtc.rs`), so the outcome does not depend on
//! scheduling.

use anyhow::Result;
use rtc::data_channel::RTCDataChannelInit;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const EXPECTED_LABEL: &str = "data";
const PLAIN_LABEL: &str = "plain";
const PROTOCOL: &str = "json";

/// How far the virtual clock may run before the test gives up.
const DEADLINE: Duration = Duration::from_secs(30);

/// A bound on the turns, should a timer keep firing without the clock moving.
const MAX_TURNS: usize = 10_000;

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    /// Datagrams that reached this peer and that it has not read yet.
    inbox: Vec<TaggedBytesMut>,
    /// The protocol each channel reported when it opened, by label.
    opened: BTreeMap<String, String>,
}

impl Peer {
    fn new(addr: SocketAddr, answering_dtls_role: RTCDtlsRole, now: Instant) -> Result<Self> {
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_answering_dtls_role(answering_dtls_role)
                    .build(),
            )
            .build(now)?;
        let host = CandidateHostConfig {
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
        pc.add_local_candidate(RTCIceCandidate::from(&host).to_json()?)?;
        Ok(Self {
            pc,
            addr,
            inbox: Vec::new(),
            opened: BTreeMap::new(),
        })
    }

    /// One turn: everything that reached this peer, then its events and reads. Returns the
    /// datagrams it wrote.
    fn turn(&mut self) -> Result<Vec<TaggedBytesMut>> {
        for datagram in self.inbox.drain(..) {
            self.pc.handle_read(datagram)?;
        }
        while let Some(event) = self.pc.poll_event() {
            if let RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) = event {
                let dc = self.pc.data_channel(id).expect("an opened channel exists");
                let label = dc.label().to_owned();
                let protocol = dc.protocol().to_owned();
                self.opened.insert(label, protocol);
            }
        }
        while self.pc.poll_read().is_some() {}
        let mut written = Vec::new();
        while let Some(datagram) = self.pc.poll_write() {
            written.push(datagram);
        }
        Ok(written)
    }

    /// Hands this peer the datagrams `from` wrote to it, as its socket would.
    fn deliver(&mut self, from: SocketAddr, datagrams: Vec<TaggedBytesMut>, now: Instant) {
        for datagram in datagrams {
            assert_eq!(
                datagram.transport.peer_addr, self.addr,
                "{from} wrote to an address other than its peer's"
            );
            self.inbox.push(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: self.addr,
                    peer_addr: from,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: datagram.message,
            });
        }
    }
}

#[test]
fn test_data_channel_parameters_protocol_exchange() -> Result<()> {
    let start = Instant::now();
    let mut now = start;
    let mut offerer = Peer::new("127.0.0.1:50010".parse()?, RTCDtlsRole::Server, now)?;
    let mut answerer = Peer::new("127.0.0.1:50011".parse()?, RTCDtlsRole::Client, now)?;

    let with_protocol = offerer
        .pc
        .create_data_channel(
            EXPECTED_LABEL,
            Some(RTCDataChannelInit {
                protocol: PROTOCOL.to_owned(),
                ..Default::default()
            }),
        )?
        .id();
    let plain = offerer.pc.create_data_channel(PLAIN_LABEL, None)?.id();

    // The opener's channel reports the protocol it was created with, before any negotiation.
    assert_eq!(
        PROTOCOL,
        offerer
            .pc
            .data_channel(with_protocol)
            .expect("created channel")
            .protocol(),
        "Protocol should match DataChannelConfig"
    );
    assert_eq!(
        "",
        offerer
            .pc
            .data_channel(plain)
            .expect("created channel")
            .protocol(),
        "a channel created without a protocol has none"
    );

    let offer = offerer.pc.create_offer(None)?;
    offerer.pc.set_local_description(now, offer.clone())?;
    answerer.pc.set_remote_description(now, offer)?;
    let answer = answerer.pc.create_answer(None)?;
    answerer.pc.set_local_description(now, answer.clone())?;
    offerer.pc.set_remote_description(now, answer)?;

    let mut turns = 0;
    while answerer.opened.len() < 2 && now.duration_since(start) < DEADLINE && turns < MAX_TURNS {
        turns += 1;
        let written = offerer.turn()?;
        answerer.deliver(offerer.addr, written, now);
        let written = answerer.turn()?;
        offerer.deliver(answerer.addr, written, now);

        // Nothing in flight: move the clock to the next timer.
        if offerer.inbox.is_empty() && answerer.inbox.is_empty() {
            let next = [offerer.pc.poll_timeout(), answerer.pc.poll_timeout()]
                .into_iter()
                .flatten()
                .min();
            let Some(next) = next else { break };
            now = now.max(next);
            offerer.pc.handle_timeout(now)?;
            answerer.pc.handle_timeout(now)?;
        }
    }

    assert_eq!(
        answerer.opened.get(EXPECTED_LABEL).map(String::as_str),
        Some(PROTOCOL),
        "Protocol should match what channel creator declared (accepted channels: {:?})",
        answerer.opened
    );
    assert_eq!(
        answerer.opened.get(PLAIN_LABEL).map(String::as_str),
        Some(""),
        "a channel opened without a protocol arrives with none (accepted channels: {:?})",
        answerer.opened
    );
    assert_eq!(
        offerer
            .pc
            .data_channel(with_protocol)
            .expect("created channel")
            .protocol(),
        PROTOCOL,
        "the opener's channel keeps its protocol once open"
    );

    offerer.pc.close()?;
    answerer.pc.close()?;
    Ok(())
}
