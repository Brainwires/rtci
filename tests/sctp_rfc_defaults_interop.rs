//! The SCTP association's RFC defaults against a peer that has none of them: the `webrtc` 0.17
//! crate, whose SCTP announces neither user message interleaving (RFC 8260) nor the zero
//! checksum (RFC 9653).
//!
//! `rtc` announces both by default and uses each only when the peer announces it too, so the
//! association with this peer runs on DATA chunks with a CRC32c: a packet of I-DATA chunks or a
//! zero checksum would be dropped or aborted by the peer, and no message would come back. RFC
//! 8831 section 6.6: "As long as message interleaving is not supported, the sender SHOULD limit
//! the maximum message size to 16 KB to avoid monopolization", so `rtc` reports and enforces a
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

use rtc::data_channel::RTCDataChannelId;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig};

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

/// An `rtc` offerer with its default settings and a `webrtc` 0.17 answerer that echoes every
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
        rtc::peer_connection::transport::RTCIceCandidate::from(&candidate).to_json()?,
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
        rtc::peer_connection::sdp::RTCSessionDescription::answer(answer.sdp)?,
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

/// The `rtc` peer's socket and what its application saw.
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
