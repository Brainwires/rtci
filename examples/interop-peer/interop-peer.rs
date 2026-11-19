//! interop-peer: the Rust side of the browser interop tests (`scripts/test-env/interop`).
//!
//! It serves WebSocket signaling; each connection is one peer connection on its own UDP socket.
//! The browser drives it with JSON messages:
//!
//! - `{"type":"offer","sdp":..., "scenario":{...}}` / `{"type":"answer","sdp":...}`
//! - `{"type":"candidate","candidate":{RTCIceCandidateInit}}`
//! - `{"type":"request-offer"}`: the Rust side opens a data channel `from-rust` and offers
//!   (renegotiation started from this side); it sends `hello-from-rust` once that opens.
//! - `{"type":"report"}`: replies `{"type":"report", ...}` with what it received.
//!
//! The scenario (sent with the first offer) chooses what the peer does with media:
//! `{"media":"reflect","video":"VP8|VP9|H264","audio":true}` sends back what it receives;
//! `{"media":"send","video":...,"audio":...}` streams the GStreamer fixtures from
//! `--media-dir` (vp8.ivf, vp9.ivf, h264.h264, opus.ogg); `{"media":"count"}` only counts
//! (simulcast: packets per RID). `"negotiated":[{"label":..,"id":..,"ordered":..}]` creates
//! pre-negotiated data channels. Every data channel message is echoed on its channel.

use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use rtc::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtc::interceptor::Registry;
use rtc::media::io::h26x_reader::H26xSampleReader;
use rtc::media::io::ivf_reader::IVFReader;
use rtc::media::io::ogg_reader::OggReader;
use rtc::media_stream::{MediaStreamTrack, MediaStreamTrackId};
use rtc::peer_connection::configuration::interceptor_registry::{
    configure_simulcast_extension_headers, register_default_interceptors,
};
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_H264, MIME_TYPE_OPUS, MIME_TYPE_VP8, MIME_TYPE_VP9, MediaEngine,
};
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp::packetizer::Packetizer;
use rtc::rtp_transceiver::RTCRtpSenderId;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, UdpSocket};
use tokio_tungstenite::tungstenite::Message;

#[derive(Parser)]
#[command(
    name = "interop-peer",
    about = "Rust peer for the browser interop tests"
)]
struct Cli {
    /// WebSocket signaling address.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    /// The address ICE binds and advertises (its host candidate).
    #[arg(long, default_value = "127.0.0.1")]
    ice_ip: IpAddr,
    /// Directory with the media fixtures for the "send" scenario.
    #[arg(long, default_value = ".")]
    media_dir: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    let listener = TcpListener::bind(cli.listen).await?;
    println!("interop-peer listening on ws://{}", cli.listen);
    loop {
        let (stream, from) = listener.accept().await?;
        let (ip, dir) = (cli.ice_ip, cli.media_dir.clone());
        tokio::spawn(async move {
            match tokio_tungstenite::accept_async(stream).await {
                Ok(ws) => {
                    if let Err(e) = Session::run(ws, ip, dir).await {
                        eprintln!("session {from}: {e:#}");
                    }
                }
                Err(e) => eprintln!("handshake {from}: {e}"),
            }
        });
    }
}

fn codec(name: &str) -> Option<(RTCRtpCodec, RtpCodecKind)> {
    let video = |mime: &str, fmtp: &str| RTCRtpCodec {
        mime_type: mime.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: fmtp.to_owned(),
        rtcp_feedback: vec![],
    };
    Some(match name.to_ascii_uppercase().as_str() {
        "VP8" => (video(MIME_TYPE_VP8, ""), RtpCodecKind::Video),
        "VP9" => (video(MIME_TYPE_VP9, "profile-id=0"), RtpCodecKind::Video),
        "H264" => (
            video(
                MIME_TYPE_H264,
                "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
            ),
            RtpCodecKind::Video,
        ),
        "OPUS" => (
            RTCRtpCodec {
                mime_type: MIME_TYPE_OPUS.to_owned(),
                clock_rate: 48000,
                channels: 2,
                sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
                rtcp_feedback: vec![],
            },
            RtpCodecKind::Audio,
        ),
        _ => return None,
    })
}

/// A media file streamed to the browser, paced in real time.
enum Source {
    Ivf(IVFReader<BufReader<File>>),
    H264(H26xSampleReader<BufReader<File>>),
    Ogg(Box<OggReader<BufReader<File>>>, u64),
}

struct Outgoing {
    sender: RTCRtpSenderId,
    ssrc: u32,
    codec: RTCRtpCodec,
    source: Option<Source>,
    packetizer: Option<Box<dyn Packetizer + Send>>,
    next: Instant,
    sent_frames: u64,
}

struct Session {
    pc: RTCPeerConnection,
    sock: UdpSocket,
    local: SocketAddr,
    out: Vec<Value>,
    media: String,
    scenario: Value,
    media_dir: String,
    outgoing: Vec<Outgoing>,
    /// track id -> (receiver kind, rid)
    tracks: HashMap<
        MediaStreamTrackId,
        (
            RtpCodecKind,
            Option<String>,
            rtc::rtp_transceiver::RTCRtpReceiverId,
        ),
    >,
    /// Simulcast layers share one track; each layer's SSRC names its RID.
    rid_by_ssrc: HashMap<u32, String>,
    rtp_by_key: BTreeMap<String, u64>,
    dc_echoed: u64,
    rust_dc: Option<RTCDataChannelId>,
    connected: bool,
    errors: Vec<String>,
}

impl Session {
    async fn run(
        ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        ip: IpAddr,
        media_dir: String,
    ) -> Result<()> {
        let (mut ws_tx, mut ws_rx) = ws.split();
        let sock = UdpSocket::bind(SocketAddr::new(ip, 0)).await?;
        let local = sock.local_addr()?;
        let mut me = MediaEngine::default();
        me.register_default_codecs()?;
        configure_simulcast_extension_headers(&mut me)?;
        let registry = register_default_interceptors(Registry::new(), &mut me)?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(me)
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        let mut s = Session {
            pc,
            sock,
            local,
            out: vec![],
            media: String::new(),
            scenario: Value::Null,
            media_dir,
            outgoing: vec![],
            tracks: HashMap::new(),
            rid_by_ssrc: HashMap::new(),
            rtp_by_key: BTreeMap::new(),
            dc_echoed: 0,
            rust_dc: None,
            connected: false,
            errors: vec![],
        };
        let host = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: local.ip().to_string(),
                port: local.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        s.pc.add_local_candidate(RTCIceCandidate::from(&host).to_json()?)?;

        let mut buf = vec![0u8; 2048];
        loop {
            s.drive()?;
            for v in s.out.drain(..) {
                ws_tx.send(Message::Text(v.to_string().into())).await?;
            }
            let now = Instant::now();
            let mut wake =
                s.pc.poll_timeout()
                    .unwrap_or(now + Duration::from_millis(100));
            for o in &s.outgoing {
                if o.source.is_some() {
                    wake = wake.min(o.next);
                }
            }
            let delay = wake
                .saturating_duration_since(now)
                .min(Duration::from_millis(100));
            tokio::select! {
                msg = ws_rx.next() => match msg {
                    Some(Ok(Message::Text(t))) => {
                        let v: Value = serde_json::from_str(&t)?;
                        if let Err(e) = s.on_signal(v) {
                            s.errors.push(format!("{e:#}"));
                            s.out.push(json!({"type": "error", "error": format!("{e:#}")}));
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(e.into()),
                },
                res = s.sock.recv_from(&mut buf) => {
                    let (n, peer) = res?;
                    let _ = s.pc.handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr: s.local,
                            peer_addr: peer,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: BytesMut::from(&buf[..n]),
                    });
                }
                _ = tokio::time::sleep(delay) => {
                    let _ = s.pc.handle_timeout(Instant::now());
                }
            }
        }
        let _ = s.pc.close();
        Ok(())
    }

    fn on_signal(&mut self, v: Value) -> Result<()> {
        match v["type"].as_str().unwrap_or_default() {
            "offer" => {
                if self.scenario.is_null() && !v["scenario"].is_null() {
                    self.scenario = v["scenario"].clone();
                    self.setup_scenario()?;
                }
                let offer =
                    RTCSessionDescription::offer(v["sdp"].as_str().unwrap_or_default().to_owned())?;
                self.pc.set_remote_description(Instant::now(), offer)?;
                let answer = self.pc.create_answer(None)?;
                self.pc
                    .set_local_description(Instant::now(), answer.clone())?;
                self.out.push(json!({"type": "answer", "sdp": answer.sdp}));
            }
            "answer" => {
                let answer = RTCSessionDescription::answer(
                    v["sdp"].as_str().unwrap_or_default().to_owned(),
                )?;
                self.pc.set_remote_description(Instant::now(), answer)?;
            }
            "candidate" => {
                if v["candidate"].is_null() || v["candidate"]["candidate"].as_str() == Some("") {
                    return Ok(()); // end of candidates
                }
                let c: RTCIceCandidateInit = serde_json::from_value(v["candidate"].clone())?;
                self.pc.add_remote_candidate(c)?;
            }
            "request-offer" => {
                let dc = self.pc.create_data_channel("from-rust", None)?;
                self.rust_dc = Some(dc.id());
                let offer = self.pc.create_offer(None)?;
                self.pc
                    .set_local_description(Instant::now(), offer.clone())?;
                self.out.push(json!({"type": "offer", "sdp": offer.sdp}));
            }
            "report" => {
                let sent: Vec<Value> = self
                    .outgoing
                    .iter()
                    .map(|o| json!({"mime": o.codec.mime_type, "frames": o.sent_frames}))
                    .collect();
                self.out.push(json!({
                    "type": "report",
                    "rtp": self.rtp_by_key,
                    "dc_echoed": self.dc_echoed,
                    "sent": sent,
                    "errors": self.errors,
                }));
            }
            other => return Err(anyhow!("unknown message type {other:?}")),
        }
        Ok(())
    }

    fn setup_scenario(&mut self) -> Result<()> {
        let sc = self.scenario.clone();
        for n in sc["negotiated"].as_array().cloned().unwrap_or_default() {
            let init = RTCDataChannelInit {
                ordered: n["ordered"].as_bool().unwrap_or(true),
                negotiated: n["id"].as_u64().map(|id| id as u16),
                ..Default::default()
            };
            self.pc
                .create_data_channel(n["label"].as_str().unwrap_or("negotiated"), Some(init))?;
        }
        self.media = sc["media"].as_str().unwrap_or("").to_owned();
        if self.media != "reflect" && self.media != "send" {
            return Ok(());
        }
        let mut names = vec![];
        if let Some(v) = sc["video"].as_str() {
            names.push(v.to_owned());
        }
        if sc["audio"].as_bool().unwrap_or(false) {
            names.push("OPUS".to_owned());
        }
        for name in names {
            let (c, kind) = codec(&name).ok_or_else(|| anyhow!("unknown codec {name}"))?;
            let ssrc = rand::random::<u32>();
            let sender = self.pc.add_track(MediaStreamTrack::new(
                format!("rust-stream-{kind}"),
                format!("rust-track-{kind}"),
                format!("rust-track-{kind}"),
                kind,
                vec![RTCRtpEncodingParameters {
                    rtp_coding_parameters: RTCRtpCodingParameters {
                        ssrc: Some(ssrc),
                        ..Default::default()
                    },
                    codec: c.clone(),
                    ..Default::default()
                }],
            ))?;
            let source = if self.media == "send" {
                let dir = &self.media_dir;
                let open = |f: &str| File::open(format!("{dir}/{f}")).map(BufReader::new);
                Some(match name.as_str() {
                    "VP8" => Source::Ivf(IVFReader::new(open("vp8.ivf")?)?.0),
                    "VP9" => Source::Ivf(IVFReader::new(open("vp9.ivf")?)?.0),
                    "H264" => {
                        Source::H264(H26xSampleReader::new(open("h264.h264")?, 1 << 20, false))
                    }
                    _ => Source::Ogg(Box::new(OggReader::new(open("opus.ogg")?, true)?.0), 0),
                })
            } else {
                None
            };
            self.outgoing.push(Outgoing {
                sender,
                ssrc,
                codec: c,
                source,
                packetizer: None,
                next: Instant::now(),
                sent_frames: 0,
            });
        }
        Ok(())
    }

    fn connected(&self) -> bool {
        self.connected
    }

    fn drive(&mut self) -> Result<()> {
        while let Some(m) = self.pc.poll_write() {
            let _ = self.sock.try_send_to(&m.message, m.transport.peer_addr);
        }
        while let Some(e) = self.pc.poll_event() {
            match e {
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    let kind = self
                        .pc
                        .rtp_receiver(init.receiver_id)
                        .map(|r| r.track().kind())
                        .unwrap_or(RtpCodecKind::Video);
                    if let Some(rid) = &init.rid {
                        self.rid_by_ssrc.insert(init.ssrc, rid.to_string());
                    }
                    self.tracks.insert(
                        init.track_id,
                        (kind, init.rid.map(|r| r.to_string()), init.receiver_id),
                    );
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id))
                    if Some(id) == self.rust_dc =>
                {
                    if let Some(mut dc) = self.pc.data_channel(id) {
                        let _ = dc.send_text(Instant::now(), "hello-from-rust");
                    }
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(st) => {
                    self.connected =
                        st == rtc::peer_connection::state::RTCPeerConnectionState::Connected;
                }
                _ => {}
            }
        }
        while let Some(TaggedRTCMessage { message, .. }) = self.pc.poll_read() {
            match message {
                RTCMessage::DataChannelMessage(id, msg) => {
                    if Some(id) == self.rust_dc {
                        continue;
                    }
                    if let Some(mut dc) = self.pc.data_channel(id) {
                        let r = if msg.is_string {
                            dc.send_text(
                                Instant::now(),
                                String::from_utf8_lossy(&msg.data).into_owned(),
                            )
                        } else {
                            dc.send(Instant::now(), msg.data)
                        };
                        if r.is_ok() {
                            self.dc_echoed += 1;
                        }
                    }
                }
                RTCMessage::RtpPacket(track_id, pkt) => self.on_rtp(track_id, pkt),
                _ => {}
            }
        }
        if self.connected() {
            self.send_media()?;
        }
        Ok(())
    }

    fn on_rtp(&mut self, track_id: MediaStreamTrackId, mut pkt: rtc::rtp::Packet) {
        let Some((kind, rid, receiver_id)) = self.tracks.get(&track_id).cloned() else {
            return;
        };
        let mime = self
            .pc
            .rtp_receiver(receiver_id)
            .and_then(|mut r| {
                r.get_parameters()
                    .rtp_parameters
                    .codecs
                    .iter()
                    .find(|c| c.payload_type == pkt.header.payload_type)
                    .map(|c| c.rtp_codec.mime_type.clone())
            })
            .unwrap_or_else(|| format!("pt{}", pkt.header.payload_type));
        let rid = self.rid_by_ssrc.get(&pkt.header.ssrc).cloned().or(rid);
        let key = format!("{kind}:{}:{}", rid.unwrap_or_else(|| "-".into()), mime);
        *self.rtp_by_key.entry(key).or_default() += 1;
        if self.media != "reflect" {
            return;
        }
        let Some(o) = self.outgoing.iter().find(|o| {
            codec_kind(&o.codec) == kind && o.codec.mime_type.eq_ignore_ascii_case(&mime)
        }) else {
            return;
        };
        let (sender, ssrc, want) = (o.sender, o.ssrc, o.codec.mime_type.clone());
        if let Some(mut s) = self.pc.rtp_sender(sender) {
            let pt = s
                .get_parameters()
                .rtp_parameters
                .codecs
                .iter()
                .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case(&want))
                .map(|c| c.payload_type);
            if let Some(pt) = pt {
                pkt.header.payload_type = pt;
                pkt.header.ssrc = ssrc;
                pkt.header.extensions.clear();
                pkt.header.extension = false;
                let _ = s.write_rtp(Instant::now(), pkt);
            }
        }
    }

    fn send_media(&mut self) -> Result<()> {
        let now = Instant::now();
        for i in 0..self.outgoing.len() {
            let o = &mut self.outgoing[i];
            if o.source.is_none() || o.next > now {
                continue;
            }
            let pt = self
                .pc
                .rtp_sender(o.sender)
                .and_then(|mut s| {
                    s.get_parameters()
                        .rtp_parameters
                        .codecs
                        .iter()
                        .find(|c| {
                            c.rtp_codec
                                .mime_type
                                .eq_ignore_ascii_case(&o.codec.mime_type)
                        })
                        .map(|c| c.payload_type)
                })
                .ok_or_else(|| anyhow!("{} was not negotiated", o.codec.mime_type))?;
            let o = &mut self.outgoing[i];
            let pk = o.packetizer.get_or_insert_with(|| {
                Box::new(rtc::rtp::packetizer::new_packetizer(
                    Instant::now(),
                    1200,
                    pt,
                    o.ssrc,
                    o.codec.payloader().expect("payloader"),
                    Box::new(rtc::rtp::sequence::new_random_sequencer()),
                    o.codec.clock_rate,
                ))
            });
            // One frame (or Ogg page) per turn, rewinding at the end of the file.
            let (data, samples, step): (Bytes, u32, Duration) = match o.source.as_mut().unwrap() {
                Source::Ivf(r) => match r.parse_next_frame() {
                    Ok((f, _)) => (f.freeze(), 3000, Duration::from_millis(33)),
                    Err(_) => {
                        o.source = None;
                        continue;
                    }
                },
                Source::H264(r) => match r.next_sample() {
                    Ok(s) => {
                        let timed = s.timed;
                        (
                            s.data,
                            if timed { 3000 } else { 0 },
                            if timed {
                                Duration::from_millis(33)
                            } else {
                                Duration::ZERO
                            },
                        )
                    }
                    Err(_) => {
                        o.source = None;
                        continue;
                    }
                },
                Source::Ogg(r, last) => match next_audio_page(r) {
                    Ok((d, h)) => {
                        let n = h.granule_position.saturating_sub(*last);
                        *last = h.granule_position;
                        (
                            d.freeze(),
                            n as u32,
                            Duration::from_millis(n * 1000 / 48000),
                        )
                    }
                    Err(_) => {
                        o.source = None;
                        continue;
                    }
                },
            };
            let packets = pk.packetize(now, &data, samples)?;
            o.sent_frames += 1;
            o.next = now + step;
            let sender = o.sender;
            if let Some(mut s) = self.pc.rtp_sender(sender) {
                for p in packets {
                    let _ = s.write_rtp(now, p);
                }
            }
        }
        Ok(())
    }
}

/// The next Ogg page that carries audio: OpusHead and OpusTags are stream headers, not packets
/// to send (RFC 7845 section 3).
fn next_audio_page(
    r: &mut OggReader<BufReader<File>>,
) -> rtc::shared::error::Result<(BytesMut, rtc::media::io::ogg_reader::OggPageHeader)> {
    loop {
        let (d, h) = r.parse_next_page()?;
        if h.opus_header_type(&d).is_none() {
            return Ok((d, h));
        }
    }
}

fn codec_kind(c: &RTCRtpCodec) -> RtpCodecKind {
    if c.mime_type.to_ascii_lowercase().starts_with("audio/") {
        RtpCodecKind::Audio
    } else {
        RtpCodecKind::Video
    }
}
