//! The SCTP association's RFC defaults against a peer that has none of them: the `webrtc` 0.17
//! crate, whose SCTP announces neither user message interleaving (RFC 8260) nor the zero
//! checksum (RFC 9653).
//!
//! `rtci` announces both by default and uses each only when the peer announces it too, so the
//! association with this peer runs on DATA chunks with a CRC32c: a packet of I-DATA chunks or a
//! zero checksum would be dropped or aborted by the peer, and no message would come back. RFC
//! 8831 section 6.6: "As long as message interleaving is not supported, the sender SHOULD limit
//! the maximum message size to 16 KB to avoid monopolization", so `rtci` reports and enforces a
//! 16 KB limit on this association, whatever larger size the peer's `a=max-message-size`
//! allows.
use anyhow::{Result, bail};
use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use rtci::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtci::peer_connection::transport::{CandidateConfig, CandidateHostConfig};

use webrtc::api::APIBuilder;
use webrtc::api::media_engine::MediaEngine;
use webrtc::peer_connection::RTCPeerConnection as WebrtcPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcRTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription as WebrtcRTCSessionDescription;

mod common;

/// RFC 8831 section 6.6's limit for an association without interleaving.
const LIMIT_WITHOUT_INTERLEAVING: usize = 16 * 1024;

/// How long the whole exchange may take in wall-clock time.
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// An `rtci` offerer with its default settings and a `webrtc` 0.17 answerer that echoes every
/// message: the channel opens, the transport reports the 16 KB limit, a message one byte over it
/// is refused, and a message of exactly 16 KB and a short one each come back intact.
#[tokio::test]
async fn the_default_association_falls_back_for_a_peer_without_interleaving_or_zero_checksum()
-> Result<()> {
    common::install_crypto_provider();
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    let mut rtc_pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(SettingEngineBuilder::new().build())
        .build(Instant::now())?;
    rtc_pc.create_data_channel("defaults", None)?;
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: local_addr.ip().to_string(),
            port: local_addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    rtc_pc.add_local_candidate(
        rtci::peer_connection::transport::RTCIceCandidate::from(&candidate).to_json()?,
    )?;
    let offer = rtc_pc.create_offer(None)?;
    rtc_pc.set_local_description(Instant::now(), offer.clone())?;

    let webrtc_pc = echoing_webrtc_peer().await?;
    webrtc_pc
        .set_remote_description(WebrtcRTCSessionDescription::offer(offer.sdp)?)
        .await?;
    let answer = webrtc_pc.create_answer(None).await?;
    webrtc_pc.set_local_description(answer).await?;
    let mut gathering_done = webrtc_pc.gathering_complete_promise().await;
    let _ = timeout(Duration::from_secs(5), gathering_done.recv()).await;
    let answer = webrtc_pc
        .local_description()
        .await
        .expect("local description should be set");
    rtc_pc.set_remote_description(
        Instant::now(),
        rtci::peer_connection::sdp::RTCSessionDescription::answer(answer.sdp)?,
    )?;

    let mut io = Io {
        socket,
        local_addr,
        buf: vec![0u8; 2000],
        received: Vec::new(),
        opened: None,
    };
    let deadline = Instant::now() + TEST_TIMEOUT;

    let channel = loop {
        if let Some(channel) = io.opened {
            break channel;
        }
        io.turn(&mut rtc_pc, deadline).await?;
    };

    let max_message_size = rtc_pc
        .sctp()
        .expect("the SCTP transport")
        .max_message_size()
        .expect("negotiated");
    assert_eq!(
        max_message_size as usize, LIMIT_WITHOUT_INTERLEAVING,
        "the peer does not interleave: the send limit is 16 KB"
    );
    assert!(
        rtc_pc
            .data_channel(channel)
            .expect("the channel")
            .send(
                Instant::now(),
                BytesMut::from(&vec![0u8; LIMIT_WITHOUT_INTERLEAVING + 1][..])
            )
            .is_err(),
        "a message over 16 KB is refused"
    );

    for message in [vec![7u8; LIMIT_WITHOUT_INTERLEAVING], b"short".to_vec()] {
        let before = io.received.len();
        rtc_pc
            .data_channel(channel)
            .expect("the channel")
            .send(Instant::now(), BytesMut::from(&message[..]))?;
        while io.received.len() == before {
            io.turn(&mut rtc_pc, deadline).await?;
        }
        assert_eq!(
            io.received[before],
            message,
            "the echo of a {}-byte message",
            message.len()
        );
    }

    webrtc_pc.close().await?;
    rtc_pc.close()?;
    Ok(())
}

/// RFC 3758 4.1 TR3 against a peer that numbers messages the old way: an ordered channel with a
/// 20 ms lifetime to the `webrtc` 0.17 echo peer. Thirty messages are written and left in the
/// queue past their lifetime, so `rtci` drops each one it had not sent yet without a TSN or a
/// stream sequence number; the three written after that take the next numbers. The peer must
/// deliver those three, in order, and nothing out of order: a gap in the stream's sequence
/// numbers without a FORWARD TSN would stall the ordered stream on the peer for good.
#[tokio::test]
async fn an_ordered_lifetime_channel_goes_on_after_messages_expire_unsent() -> Result<()> {
    common::install_crypto_provider();
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    let mut rtc_pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(SettingEngineBuilder::new().build())
        .build(Instant::now())?;
    rtc_pc.create_data_channel(
        "lifetime",
        Some(RTCDataChannelInit {
            ordered: true,
            max_packet_life_time: Some(20),
            ..Default::default()
        }),
    )?;
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: local_addr.ip().to_string(),
            port: local_addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    rtc_pc.add_local_candidate(
        rtci::peer_connection::transport::RTCIceCandidate::from(&candidate).to_json()?,
    )?;
    let offer = rtc_pc.create_offer(None)?;
    rtc_pc.set_local_description(Instant::now(), offer.clone())?;
    let webrtc_pc = echoing_webrtc_peer().await?;
    webrtc_pc
        .set_remote_description(WebrtcRTCSessionDescription::offer(offer.sdp)?)
        .await?;
    let answer = webrtc_pc.create_answer(None).await?;
    webrtc_pc.set_local_description(answer).await?;
    let mut gathering_done = webrtc_pc.gathering_complete_promise().await;
    let _ = timeout(Duration::from_secs(5), gathering_done.recv()).await;
    let answer = webrtc_pc
        .local_description()
        .await
        .expect("local description should be set");
    rtc_pc.set_remote_description(
        Instant::now(),
        rtci::peer_connection::sdp::RTCSessionDescription::answer(answer.sdp)?,
    )?;

    let mut io = Io {
        socket,
        local_addr,
        buf: vec![0u8; 2000],
        received: Vec::new(),
        opened: None,
    };
    let deadline = Instant::now() + TEST_TIMEOUT;
    let channel = loop {
        if let Some(channel) = io.opened {
            break channel;
        }
        io.turn(&mut rtc_pc, deadline).await?;
    };

    let message = |n: u32| {
        let mut m = n.to_be_bytes().to_vec();
        m.resize(1000, n as u8);
        m
    };
    for n in 0..30 {
        rtc_pc
            .data_channel(channel)
            .expect("the channel")
            .send(Instant::now(), BytesMut::from(&message(n)[..]))?;
    }
    // Nothing is written meanwhile: every message still queued outlives its 20 ms.
    tokio::time::sleep(Duration::from_millis(100)).await;
    for n in 30..33 {
        rtc_pc
            .data_channel(channel)
            .expect("the channel")
            .send(Instant::now(), BytesMut::from(&message(n)[..]))?;
    }
    while !io
        .received
        .iter()
        .any(|m| m.len() == 1000 && m[..4] == 32u32.to_be_bytes())
    {
        io.turn(&mut rtc_pc, deadline).await?;
    }
    let numbers: Vec<u32> = io
        .received
        .iter()
        .map(|m| {
            assert_eq!(m.len(), 1000, "an echoed message is whole");
            u32::from_be_bytes([m[0], m[1], m[2], m[3]])
        })
        .collect();
    assert!(
        numbers.windows(2).all(|w| w[0] < w[1]),
        "the ordered stream is delivered in order: {numbers:?}"
    );
    assert!(
        numbers.ends_with(&[30, 31, 32]),
        "the three messages written after the expiry come back: {numbers:?}"
    );

    webrtc_pc.close().await?;
    rtc_pc.close()?;
    Ok(())
}

/// The `rtci` peer's socket and what its application saw.
struct Io {
    socket: UdpSocket,
    local_addr: std::net::SocketAddr,
    buf: Vec<u8>,
    received: Vec<Vec<u8>>,
    opened: Option<RTCDataChannelId>,
}

impl Io {
    /// Writes what `pc` has to write, takes its events and messages, then waits for one
    /// datagram or its next timer.
    async fn turn(&mut self, pc: &mut RTCPeerConnection, deadline: Instant) -> Result<()> {
        if Instant::now() >= deadline {
            bail!("timed out; received {} messages", self.received.len());
        }
        while let Some(msg) = pc.poll_write() {
            // The peer's non-loopback candidates cannot be reached from a loopback socket.
            let _ = self
                .socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await;
        }
        while let Some(event) = pc.poll_event() {
            if let RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) = event {
                self.opened = Some(id);
            }
        }
        while let Some(TaggedRTCMessage { message, .. }) = pc.poll_read() {
            if let RTCMessage::DataChannelMessage(_, message) = message {
                self.received.push(message.data.to_vec());
            }
        }
        let wake = pc
            .poll_timeout()
            .unwrap_or(deadline)
            .min(deadline)
            .max(Instant::now());
        tokio::select! {
            _ = tokio::time::sleep(wake - Instant::now()) => {
                pc.handle_timeout(Instant::now())?;
            }
            res = self.socket.recv_from(&mut self.buf) => {
                match res {
                    Ok((n, peer_addr)) => pc.handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr: self.local_addr,
                            peer_addr,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: BytesMut::from(&self.buf[..n]),
                    })?,
                    Err(err) if common::udp_recv_error_is_lost_datagram(&err) => {}
                    Err(err) => return Err(err.into()),
                }
            }
        }
        Ok(())
    }
}

/// A `webrtc` 0.17 answerer that sends back every message on the channel it is offered.
async fn echoing_webrtc_peer() -> Result<Arc<WebrtcPeerConnection>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let api = APIBuilder::new()
        .with_setting_engine(common::webrtc_setting_engine())
        .with_media_engine(media_engine)
        .build();
    let pc = Arc::new(
        api.new_peer_connection(WebrtcRTCConfiguration::default())
            .await?,
    );
    pc.on_data_channel(Box::new(move |dc| {
        Box::pin(async move {
            let sender = dc.clone();
            dc.on_message(Box::new(move |msg| {
                let sender = sender.clone();
                Box::pin(async move {
                    if let Err(err) = sender.send(&msg.data).await {
                        log::error!("webrtc echo failed: {err}");
                    }
                })
            }));
        })
    }));
    Ok(pc)
}
