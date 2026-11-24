/// Interop: a data channel closed in the middle of a transfer and the next one opened at once on
/// the same stream, with webrtc 0.17 sending.
///
/// rtc (the offerer, DTLS server) opens `file-1`; webrtc writes 64 KiB messages to it under
/// back-pressure; after a few of them rtc closes it (the stream is reset in both directions,
/// RFC 8831 6.7) and, once the close is done, opens `file-2`, which takes the same stream id
/// (the lowest free one of its parity, RFC 8832 6). webrtc writes fifteen messages to `file-2`;
/// rtc must get every one of them, in order. A sender that resets its direction of the stream
/// before the message it is sending on it has all its TSNs sends the rest after the reset,
/// where it waits in front of the next channel's message with the same sequence number; this
/// checks the receiver against another stack as well as the close and reopen themselves.
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use rtc::data_channel::RTCDataChannelId;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCDataChannelEvent;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig};

use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::RTCPeerConnection as WebrtcPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcRTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription as WebrtcRTCSessionDescription;

mod common;

const SIZE: usize = 64 * 1024;
const CLOSE_AFTER: usize = 3;
const SECOND: u32 = 15;

/// A message's bytes: its number, then a pattern that depends on it.
fn msg(id: u32) -> Bytes {
    Bytes::from(
        (0..SIZE)
            .map(|i| {
                if i < 4 {
                    id.to_be_bytes()[i]
                } else {
                    (i as u32).wrapping_mul(31).wrapping_add(id) as u8
                }
            })
            .collect::<Vec<u8>>(),
    )
}

/// webrtc's application: on each channel it is offered, it writes `total` messages numbered
/// from `first` while fewer than eight of them are buffered, and stops when the channel
/// refuses or closes.
async fn create_webrtc_sender() -> Result<Arc<WebrtcPeerConnection>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut media_engine)?;
    let api = APIBuilder::new()
        .with_setting_engine(common::webrtc_setting_engine())
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();
    let pc = Arc::new(
        api.new_peer_connection(WebrtcRTCConfiguration::default())
            .await?,
    );
    pc.on_data_channel(Box::new(move |dc| {
        Box::pin(async move {
            let (first, total) = match dc.label() {
                "file-1" => (1000u32, 40u32),
                "file-2" => (2000, SECOND),
                _ => return,
            };
            let sender = Arc::clone(&dc);
            dc.on_open(Box::new(move || {
                let dc = Arc::clone(&sender);
                Box::pin(async move {
                    tokio::spawn(async move {
                        let mut next = 0;
                        while next < total {
                            if dc.ready_state() != RTCDataChannelState::Open {
                                return;
                            }
                            if dc.buffered_amount().await >= 8 * SIZE {
                                tokio::time::sleep(Duration::from_millis(2)).await;
                                continue;
                            }
                            if dc.send(&msg(first + next)).await.is_err() {
                                return;
                            }
                            next += 1;
                        }
                    });
                })
            }));
        })
    }));
    Ok(pc)
}

#[tokio::test]
async fn a_channel_reopened_on_the_stream_of_one_closed_mid_transfer_gets_every_message()
-> Result<()> {
    common::install_crypto_provider();
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    let setting_engine = SettingEngineBuilder::new()
        .with_answering_dtls_role(RTCDtlsRole::Server)
        .build();
    let mut rtc_pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(setting_engine)
        .build(Instant::now())?;
    let file1 = rtc_pc.create_data_channel("file-1", None)?.id();
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

    let webrtc_pc = create_webrtc_sender().await?;
    webrtc_pc
        .set_remote_description(WebrtcRTCSessionDescription::offer(offer.sdp.clone())?)
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
        rtc::peer_connection::sdp::RTCSessionDescription::answer(answer.sdp.clone())?,
    )?;

    let mut buf = vec![0u8; 2000];
    let mut received: Vec<(RTCDataChannelId, Vec<u8>)> = vec![];
    let mut file1_closing = false;
    let mut file1_closed = false;
    let mut file2: Option<RTCDataChannelId> = None;
    let mut stream_ids = (None, None);
    let start = Instant::now();
    let result = loop {
        if start.elapsed() > Duration::from_secs(60) {
            let got = file2.map_or(0, |ch| received.iter().filter(|(id, _)| *id == ch).count());
            break Err(anyhow::anyhow!(
                "timed out: file-1 closed {file1_closed}, file-2 opened {}, file-2 got {got} of \
                 {SECOND} messages",
                file2.is_some()
            ));
        }
        while let Some(datagram) = rtc_pc.poll_write() {
            let _ = socket
                .send_to(&datagram.message, datagram.transport.peer_addr)
                .await;
        }
        while let Some(event) = rtc_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    if state == RTCPeerConnectionState::Failed {
                        return Err(anyhow::anyhow!("rtc peer connection failed"));
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id))
                    if id == file1 =>
                {
                    stream_ids.0 = rtc_pc.data_channel(id).and_then(|dc| dc.stream_id());
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id))
                    if Some(id) == file2 =>
                {
                    stream_ids.1 = rtc_pc.data_channel(id).and_then(|dc| dc.stream_id());
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(id))
                    if id == file1 =>
                {
                    file1_closed = true;
                }
                _ => {}
            }
        }
        while let Some(TaggedRTCMessage { message, .. }) = rtc_pc.poll_read() {
            if let RTCMessage::DataChannelMessage(id, m) = message {
                received.push((id, m.data.to_vec()));
            }
        }
        let on_file1 = received.iter().filter(|(id, _)| *id == file1).count();
        if !file1_closing && on_file1 >= CLOSE_AFTER {
            // The receiver refuses the transfer.
            rtc_pc.data_channel(file1).expect("file-1").close()?;
            file1_closing = true;
        }
        if file1_closed && file2.is_none() {
            // And opens the next channel at once.
            file2 = Some(rtc_pc.create_data_channel("file-2", None)?.id());
        }
        if let Some(ch) = file2 {
            let got: Vec<&Vec<u8>> = received
                .iter()
                .filter(|(id, _)| *id == ch)
                .map(|(_, data)| data)
                .collect();
            if got.len() >= SECOND as usize {
                for (i, data) in got.iter().enumerate() {
                    assert!(
                        data[..] == msg(2000 + i as u32)[..],
                        "file-2's message {i} is not the one sent"
                    );
                }
                break Ok(());
            }
        }

        let next = rtc_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + Duration::from_millis(50))
            .min(Instant::now() + Duration::from_millis(50));
        let delay = next
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        if delay.is_zero() {
            rtc_pc.handle_timeout(Instant::now())?;
            continue;
        }
        tokio::select! {
            _ = tokio::time::sleep(delay) => {
                rtc_pc.handle_timeout(Instant::now())?;
            }
            res = socket.recv_from(&mut buf) => {
                match res {
                    Ok((n, peer_addr)) => {
                        rtc_pc.handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr,
                                peer_addr,
                                ecn: None,
                                transport_protocol: TransportProtocol::UDP,
                            },
                            message: BytesMut::from(&buf[..n]),
                        })?;
                    }
                    Err(err) if common::udp_recv_error_is_lost_datagram(&err) => {}
                    Err(err) => return Err(err.into()),
                }
            }
        }
    };
    log::info!(
        "file-1 on stream {:?}, file-2 on stream {:?}",
        stream_ids.0,
        stream_ids.1
    );
    webrtc_pc.close().await?;
    rtc_pc.close()?;
    result?;
    assert_eq!(
        stream_ids.0, stream_ids.1,
        "file-2 takes the stream file-1 freed"
    );
    Ok(())
}
