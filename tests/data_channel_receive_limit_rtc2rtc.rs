//! RFC 8841 6.1: each side's `max-message-size` limits what the *other* side sends, so an
//! endpoint accepts messages up to the size it advertised itself.
//!
//! It used to receive by the negotiated minimum instead: advertising 256 KiB to a peer whose
//! own limit is 64 KiB (or whose SDP omits the attribute) and then receiving a 200 KB message
//! from it (allowed: it is within what this side advertised) failed the read with
//! `ErrShortBuffer`, losing the message after SCTP had acknowledged it.
//!
//! The peer here is this implementation too, so its answer is edited to advertise 64 KiB while
//! it still sends by the offerer's 256 KiB, the way a browser with a smaller receive limit does.

use anyhow::Result;
use bytes::BytesMut;
use rtci::data_channel::RTCDataChannelInit;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::setting_engine::{
    SctpMaxMessageSize, SettingEngineBuilder,
};
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const NEGOTIATED_ID: u16 = 1;
const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const MESSAGE_LEN: usize = 200_000;

struct Peer {
    pc: RTCPeerConnection,
    socket: UdpSocket,
    addr: SocketAddr,
    buf: Vec<u8>,
}

impl Peer {
    async fn new(role: RTCDtlsRole) -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;

        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_answering_dtls_role(role)
                    .with_sctp_max_message_size(SctpMaxMessageSize::Unbounded)
                    .build(),
            )
            .build(Instant::now())?;

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
        pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;

        Ok(Self {
            pc,
            socket,
            addr,
            buf: vec![0u8; 2048],
        })
    }

    fn handle_datagram(&mut self, n: usize, peer_addr: SocketAddr) {
        self.pc
            .handle_read(TaggedBytesMut {
                now: Instant::now(),
                transport: TransportContext {
                    local_addr: self.addr,
                    peer_addr,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: BytesMut::from(&self.buf[..n]),
            })
            .ok();
    }
}

/// Flushes both peers, then waits for one datagram or the next timer.
async fn pump(a: &mut Peer, b: &mut Peer) -> Result<()> {
    for p in [&mut *a, &mut *b] {
        while let Some(msg) = p.pc.poll_write() {
            p.socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }
    }

    let fallback = Instant::now() + Duration::from_secs(1);
    let next =
        a.pc.poll_timeout()
            .unwrap_or(fallback)
            .min(b.pc.poll_timeout().unwrap_or(fallback));
    let delay = next
        .saturating_duration_since(Instant::now())
        .min(Duration::from_millis(5));

    tokio::select! {
        _ = tokio::time::sleep(delay) => {
            a.pc.handle_timeout(Instant::now()).ok();
            b.pc.handle_timeout(Instant::now()).ok();
        }
        Ok((n, peer_addr)) = a.socket.recv_from(&mut a.buf) => a.handle_datagram(n, peer_addr),
        Ok((n, peer_addr)) = b.socket.recv_from(&mut b.buf) => b.handle_datagram(n, peer_addr),
    }
    Ok(())
}

/// Rewrites the `a=max-message-size` line of an SDP.
fn advertise_max_message_size(sdp: &str, size: u32) -> String {
    sdp.split("\r\n")
        .map(|line| {
            if line.starts_with("a=max-message-size:") {
                format!("a=max-message-size:{size}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

#[tokio::test]
async fn a_message_within_the_advertised_limit_is_received() -> Result<()> {
    let mut offer = Peer::new(RTCDtlsRole::Server).await?;
    let mut answer = Peer::new(RTCDtlsRole::Client).await?;

    let init = RTCDataChannelInit {
        ordered: true,
        negotiated: Some(NEGOTIATED_ID),
        ..Default::default()
    };
    let offer_dc = offer
        .pc
        .create_data_channel("limit", Some(init.clone()))?
        .id();
    let answer_dc = answer.pc.create_data_channel("limit", Some(init))?.id();

    let sdp = offer.pc.create_offer(None)?;
    offer
        .pc
        .set_local_description(Instant::now(), sdp.clone())?;
    answer.pc.set_remote_description(Instant::now(), sdp)?;
    let sdp = answer.pc.create_answer(None)?;
    answer
        .pc
        .set_local_description(Instant::now(), sdp.clone())?;
    // The offerer learns a 64 KiB limit for the answerer, so it sends at most 64 KiB; the
    // answerer still sends by the offerer's 256 KiB.
    let edited = RTCSessionDescription::answer(advertise_max_message_size(
        &sdp.sdp,
        SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE,
    ))?;
    offer.pc.set_remote_description(Instant::now(), edited)?;

    let mut connected = false;
    let mut open = false;
    let mut sent = false;
    let mut received = None;

    let start = Instant::now();
    while start.elapsed() < TEST_TIMEOUT && received.is_none() {
        pump(&mut offer, &mut answer).await?;

        while let Some(event) = answer.pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => connected = true,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id))
                    if id == answer_dc =>
                {
                    open = true
                }
                _ => {}
            }
        }
        while offer.pc.poll_event().is_some() {}
        while answer.pc.poll_read().is_some() {}
        while let Some(TaggedRTCMessage { message, .. }) = offer.pc.poll_read() {
            if let RTCMessage::DataChannelMessage(id, msg) = message
                && id == offer_dc
            {
                received = Some(msg.data.len());
            }
        }

        if connected && open && !sent {
            assert_eq!(
                Some(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE),
                offer.pc.sctp().and_then(|sctp| sctp.max_message_size()),
                "the offerer sends by the answerer's (edited) limit"
            );
            let mut dc = answer.pc.data_channel(answer_dc).expect("channel is open");
            dc.send(Instant::now(), BytesMut::zeroed(MESSAGE_LEN))?;
            sent = true;
        }
    }

    assert!(sent, "peers never opened the channel");
    assert_eq!(
        received,
        Some(MESSAGE_LEN),
        "a message within the offerer's advertised 256 KiB must be delivered"
    );

    offer.pc.close()?;
    answer.pc.close()?;
    Ok(())
}
