//! interop-peer: the Rust side of the browser interop tests (`scripts/test-env/interop`).
//!
//! It serves WebSocket signaling; each connection is one peer connection on its own UDP socket
//! (plus, when asked, a TCP listener for ICE-TCP and an mDNS socket). The browser drives it
//! with JSON messages:
//!
//! - `{"type":"offer","sdp":..., "scenario":{...}}` / `{"type":"answer","sdp":...}`
//! - `{"type":"candidate","candidate":{RTCIceCandidateInit}}`
//! - `{"type":"request-offer"}`: the Rust side opens a data channel `from-rust` and offers
//!   (renegotiation started from this side); it sends `hello-from-rust` once that opens. With
//!   `"tracks":["VP8","OPUS",...]` it adds those send tracks (streaming the fixtures) instead,
//!   so the browser answers for media.
//! - `{"type":"report"}`: replies `{"type":"report", ...}` with what it received, its
//!   connection state, its W3C stats counters and per-stream sequence coverage.
//!
//! The scenario (sent with the first offer) chooses what the peer does with media:
//! `{"media":"reflect","video":"VP8|VP9|H264|H265|AV1","audio":true}` sends back what it
//! receives; `{"media":"send","video":...,"audio":...}` streams the GStreamer fixtures from
//! `--media-dir` (vp8.ivf, vp9.ivf, h264.h264, h265.h265, av1.ivf, opus.ogg; `"fixture":
//! {"video":"h264-slices.h264","audio":"opus-multi.ogg"}` picks others); `{"media":"count"}`
//! only counts (simulcast: packets per RID). `"negotiated":[{"label":..,"id":..,"ordered":..}]`
//! creates pre-negotiated data channels. `"ice_tcp":true` adds a passive TCP candidate (RFC
//! 6544) and `"udp":false` leaves out the UDP one. `"cryptex":"negotiate"|"require"` sets the
//! RTCRtpHeaderEncryptionPolicy (RFC 9335). Every data channel message is echoed on its channel.
//!
//! An offer that arrives while this side has an offer outstanding (glare) is handled as the
//! polite peer of perfect negotiation: it rolls its own offer back, answers, then offers again.

use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use rtc::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtc::ice::mdns::MulticastDnsMode;
use rtc::ice::tcp_type::TcpType;
use rtc::interceptor::Registry;
use rtc::media::io::h26x_reader::H26xSampleReader;
use rtc::media::io::ivf_reader::IVFReader;
use rtc::media::io::ogg_reader::OggReader;
use rtc::media_stream::{MediaStreamTrack, MediaStreamTrackId};
use rtc::peer_connection::configuration::interceptor_registry::{
    configure_simulcast_extension_headers, register_default_interceptors,
};
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_AV1, MIME_TYPE_H264, MIME_TYPE_HEVC, MIME_TYPE_OPUS, MIME_TYPE_VP8, MIME_TYPE_VP9,
    MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::{
    SctpMaxMessageSize, SettingEngineBuilder,
};
use rtc::peer_connection::cryptex::RTCRtpHeaderEncryptionPolicy;
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
use rtc::shared::tcp_framing::{TcpFrameDecoder, frame_packet};
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::StatsSelector;
use rtc::statistics::report::RTCStatsReportEntry;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
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
        "H265" => (video(MIME_TYPE_HEVC, ""), RtpCodecKind::Video),
        "AV1" => (video(MIME_TYPE_AV1, "profile=0"), RtpCodecKind::Video),
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

/// The fixture a codec streams by default (`--media-dir`).
fn default_fixture(name: &str) -> &'static str {
    match name {
        "VP8" => "vp8.ivf",
        "VP9" => "vp9.ivf",
        "H264" => "h264.h264",
        "H265" => "h265.h265",
        "AV1" => "av1.ivf",
        _ => "opus.ogg",
    }
}

/// A media file streamed to the browser, paced in real time.
enum Source {
    Ivf(IVFReader<BufReader<File>>),
    /// H.264 or H.265 access units.
    H26x(H26xSampleReader<BufReader<File>>),
    Ogg(Box<OggReader<BufReader<File>>>),
}

/// The sequence numbers received on one SSRC, extended past wrap-around (RFC 3550 A.1), so
/// a test can tell what is still missing after NACK / RTX recovery.
#[derive(Default)]
struct SeqCoverage {
    key: String,
    cycles: u64,
    last: Option<u16>,
    seen: HashSet<u64>,
    min: u64,
    max: u64,
}

impl SeqCoverage {
    fn add(&mut self, seq: u16) {
        let ext = match self.last {
            None => {
                self.cycles = 1 << 16;
                self.cycles | u64::from(seq)
            }
            Some(last) => {
                let diff = seq.wrapping_sub(last);
                if diff < 0x8000 {
                    if seq < last {
                        self.cycles += 1 << 16;
                    }
                    self.cycles | u64::from(seq)
                } else if seq > last {
                    // A late packet from before the last wrap.
                    (self.cycles - (1 << 16)) | u64::from(seq)
                } else {
                    self.cycles | u64::from(seq)
                }
            }
        };
        if self.last.is_none_or(|l| seq.wrapping_sub(l) < 0x8000) {
            self.last = Some(seq);
        }
        if self.seen.is_empty() {
            self.min = ext;
            self.max = ext;
        }
        self.min = self.min.min(ext);
        self.max = self.max.max(ext);
        self.seen.insert(ext);
    }

    /// The span from the first to the last sequence number and how many in it never arrived,
    /// leaving out the newest `tail` (still in flight or being repaired).
    fn report(&self, tail: u64) -> Value {
        let end = self.max.saturating_sub(tail);
        let span = if end >= self.min {
            end - self.min + 1
        } else {
            0
        };
        let missing = (self.min..=end)
            .filter(|s| span > 0 && !self.seen.contains(s))
            .count();
        json!({"key": self.key, "span": span, "missing": missing, "received": self.seen.len()})
    }
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

/// An accepted ICE-TCP connection: frames for it go to its writer task.
type TcpOut = mpsc::UnboundedSender<Vec<u8>>;

struct Session {
    pc: RTCPeerConnection,
    sock: UdpSocket,
    local: SocketAddr,
    /// One UDP socket per further transport (an m= section outside the BUNDLE group, RFC
    /// 9429 section 5.2.1), with the mid its candidate was gathered for.
    transport_socks: Vec<(UdpSocket, SocketAddr, String)>,
    ice_ip: IpAddr,
    /// The mDNS socket (5353, joined to 224.0.0.251): the peer connection resolves a
    /// browser's `.local` host candidates through it.
    mdns: Option<UdpSocket>,
    /// ICE-TCP (scenario `ice_tcp`): the passive candidate's listener and its connections.
    tcp_listener: Option<TcpListener>,
    tcp_local: Option<SocketAddr>,
    tcp_out: HashMap<SocketAddr, TcpOut>,
    tcp_in: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    candidates_added: bool,
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
    coverage: HashMap<u32, SeqCoverage>,
    dc_echoed: u64,
    rust_dc: Option<RTCDataChannelId>,
    /// This side's offer is outstanding (have-local-offer).
    have_local_offer: bool,
    rollbacks: u64,
    connected: bool,
    state: String,
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
        // 256 KiB messages (what Chromium and WebKit state; RFC 8841 6.1), `.local` remote
        // candidates resolved over mDNS (a browser hides its host address by default).
        // Browsers do not announce SCTP message interleaving, and the engine's default then
        // holds what it sends to 16 KB (RFC 8831 section 6.6); the scenarios echo 64 KiB and
        // 256 KiB messages to a browser, so this peer sends as browsers do.
        let setting_engine = SettingEngineBuilder::new()
            .with_sctp_max_message_size(SctpMaxMessageSize::Bounded(
                SctpMaxMessageSize::MAX_MESSAGE_SIZE,
            ))
            .with_sctp_message_size_limit_without_interleaving(false)
            .with_multicast_dns_mode(MulticastDnsMode::QueryOnly)
            .build();
        let pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(me)
            .with_setting_engine(setting_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())?;
        let mdns = match ip {
            IpAddr::V4(v4) => match rtc::mdns::MulticastSocket::new()
                .with_interface(v4)
                .into_std()
                .and_then(|s| {
                    s.set_nonblocking(true)?;
                    UdpSocket::from_std(s)
                }) {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("no mDNS socket ({e}); .local candidates will not resolve");
                    None
                }
            },
            IpAddr::V6(_) => None,
        };
        let (tcp_in, mut tcp_in_rx) = mpsc::unbounded_channel();
        let mut s = Session {
            pc,
            sock,
            local,
            transport_socks: vec![],
            ice_ip: ip,
            mdns,
            tcp_listener: None,
            tcp_local: None,
            tcp_out: HashMap::new(),
            tcp_in,
            candidates_added: false,
            out: vec![],
            media: String::new(),
            scenario: Value::Null,
            media_dir,
            outgoing: vec![],
            tracks: HashMap::new(),
            rid_by_ssrc: HashMap::new(),
            rtp_by_key: BTreeMap::new(),
            coverage: HashMap::new(),
            dc_echoed: 0,
            rust_dc: None,
            have_local_offer: false,
            rollbacks: 0,
            connected: false,
            state: "new".to_owned(),
            errors: vec![],
        };

        let mut buf = vec![0u8; 2048];
        let mut mbuf = vec![0u8; 2048];
        let mut tbuf = vec![0u8; 2048];
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
                    let local = s.local;
                    s.feed(local, peer, TransportProtocol::UDP, &buf[..n]);
                }
                res = recv_any(&s.transport_socks, &mut tbuf) => {
                    if let Ok((n, peer, local)) = res {
                        s.feed(local, peer, TransportProtocol::UDP, &tbuf[..n]);
                    }
                }
                res = recv_opt(&s.mdns, &mut mbuf) => {
                    if let Ok((n, peer)) = res
                        && let Some(local) = s.mdns.as_ref().and_then(|m| m.local_addr().ok())
                    {
                        s.feed(local, peer, TransportProtocol::UDP, &mbuf[..n]);
                    }
                }
                res = accept_opt(&s.tcp_listener) => {
                    if let Ok((stream, from)) = res {
                        s.on_tcp_connection(stream, from);
                    }
                }
                Some((from, frame)) = tcp_in_rx.recv() => {
                    if let Some(local) = s.tcp_local {
                        s.feed(local, from, TransportProtocol::TCP, &frame);
                    }
                }
                _ = tokio::time::sleep(delay) => {
                    let _ = s.pc.handle_timeout(Instant::now());
                }
            }
        }
        let _ = s.pc.close();
        Ok(())
    }

    fn feed(&mut self, local: SocketAddr, peer: SocketAddr, proto: TransportProtocol, data: &[u8]) {
        let _ = self.pc.handle_read(TaggedBytesMut {
            now: Instant::now(),
            transport: TransportContext {
                local_addr: local,
                peer_addr: peer,
                ecn: None,
                transport_protocol: proto,
            },
            message: BytesMut::from(data),
        });
    }

    /// A browser's active ICE-TCP connection to our passive candidate: RFC 4571 frames in both
    /// directions, each read frame handed to the session loop.
    fn on_tcp_connection(&mut self, stream: tokio::net::TcpStream, from: SocketAddr) {
        let _ = stream.set_nodelay(true);
        let (mut rd, mut wr) = stream.into_split();
        let tx = self.tcp_in.clone();
        tokio::spawn(async move {
            let mut decoder = TcpFrameDecoder::new();
            let mut b = vec![0u8; 16384];
            loop {
                match rd.read(&mut b).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        decoder.extend_from_slice(&b[..n]);
                        while let Some(frame) = decoder.next_packet() {
                            if tx.send((from, frame)).is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        });
        let (otx, mut orx) = mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move {
            while let Some(f) = orx.recv().await {
                if wr.write_all(&f).await.is_err() {
                    break;
                }
            }
        });
        self.tcp_out.insert(from, otx);
    }

    /// Adds this side's host candidates (before the first answer or offer, so the description
    /// carries them): UDP unless the scenario says `"udp": false`, and a passive TCP one with
    /// `"ice_tcp": true`.
    fn add_candidates(&mut self) -> Result<()> {
        if self.candidates_added {
            return Ok(());
        }
        self.candidates_added = true;
        if self.scenario["udp"].as_bool().unwrap_or(true) {
            let host = CandidateHostConfig {
                base_config: CandidateConfig {
                    network: "udp".to_owned(),
                    address: self.local.ip().to_string(),
                    port: self.local.port(),
                    component: 1,
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host()?;
            self.pc
                .add_local_candidate(RTCIceCandidate::from(&host).to_json()?)?;
        }
        if self.scenario["ice_tcp"].as_bool().unwrap_or(false) {
            let std_listener = std::net::TcpListener::bind(SocketAddr::new(self.ice_ip, 0))?;
            std_listener.set_nonblocking(true)?;
            let listener = TcpListener::from_std(std_listener)?;
            let addr = listener.local_addr()?;
            let host = CandidateHostConfig {
                base_config: CandidateConfig {
                    network: "tcp".to_owned(),
                    address: addr.ip().to_string(),
                    port: addr.port(),
                    component: 1,
                    ..Default::default()
                },
                tcp_type: TcpType::Passive,
            }
            .new_candidate_host()?;
            self.pc
                .add_local_candidate(RTCIceCandidate::from(&host).to_json()?)?;
            self.tcp_listener = Some(listener);
            self.tcp_local = Some(addr);
        }
        Ok(())
    }

    /// A host candidate, on a socket of its own, for each transport but the first: the
    /// sections a browser offers outside a BUNDLE group (`bundlePolicy: "max-compat"` with the
    /// group removed) each have one (RFC 9429 section 5.3.1).
    fn add_transport_candidates(&mut self) -> Result<()> {
        for (mid, index) in self.pc.ice_transport_sections().into_iter().skip(1) {
            if self.transport_socks.iter().any(|(_, _, m)| *m == mid) {
                continue;
            }
            let std_sock = std::net::UdpSocket::bind(SocketAddr::new(self.ice_ip, 0))?;
            std_sock.set_nonblocking(true)?;
            let sock = UdpSocket::from_std(std_sock)?;
            let local = sock.local_addr()?;
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
            let mut candidate = RTCIceCandidate::from(&host).to_json()?;
            candidate.sdp_mid = Some(mid.clone());
            candidate.sdp_mline_index = Some(index);
            self.pc.add_local_candidate(candidate)?;
            self.transport_socks.push((sock, local, mid));
        }
        Ok(())
    }

    fn send_offer(&mut self) -> Result<()> {
        self.add_candidates()?;
        let offer = self.pc.create_offer(None)?;
        self.pc
            .set_local_description(Instant::now(), offer.clone())?;
        self.have_local_offer = true;
        self.out.push(json!({"type": "offer", "sdp": offer.sdp}));
        Ok(())
    }

    fn on_signal(&mut self, v: Value) -> Result<()> {
        match v["type"].as_str().unwrap_or_default() {
            "offer" => {
                if self.scenario.is_null() && !v["scenario"].is_null() {
                    self.scenario = v["scenario"].clone();
                    self.setup_scenario()?;
                }
                self.add_candidates()?;
                // Glare: as the polite peer (RFC 9429 4.1.8.2, perfect negotiation), roll our
                // own offer back, answer theirs, then offer again.
                let reoffer = self.have_local_offer;
                if reoffer {
                    self.pc.set_local_description(
                        Instant::now(),
                        RTCSessionDescription::rollback(None)?,
                    )?;
                    self.have_local_offer = false;
                    self.rollbacks += 1;
                }
                let offer =
                    RTCSessionDescription::offer(v["sdp"].as_str().unwrap_or_default().to_owned())?;
                self.pc.set_remote_description(Instant::now(), offer)?;
                self.add_transport_candidates()?;
                let answer = self.pc.create_answer(None)?;
                self.pc
                    .set_local_description(Instant::now(), answer.clone())?;
                self.out.push(json!({"type": "answer", "sdp": answer.sdp}));
                if reoffer {
                    self.send_offer()?;
                }
            }
            "answer" => {
                let answer = RTCSessionDescription::answer(
                    v["sdp"].as_str().unwrap_or_default().to_owned(),
                )?;
                self.pc.set_remote_description(Instant::now(), answer)?;
                self.have_local_offer = false;
            }
            "candidate" => {
                if v["candidate"].is_null() || v["candidate"]["candidate"].as_str() == Some("") {
                    return Ok(()); // end of candidates
                }
                let c: RTCIceCandidateInit = serde_json::from_value(v["candidate"].clone())?;
                self.pc.add_remote_candidate(c)?;
            }
            "request-offer" => {
                let tracks: Vec<String> = v["tracks"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|t| t.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default();
                if tracks.is_empty() {
                    let dc = self.pc.create_data_channel("from-rust", None)?;
                    self.rust_dc = Some(dc.id());
                }
                for name in tracks {
                    self.add_send_track(&name.to_ascii_uppercase(), true)?;
                }
                self.send_offer()?;
            }
            "report" => {
                let sent: Vec<Value> = self
                    .outgoing
                    .iter()
                    .map(|o| json!({"mime": o.codec.mime_type, "frames": o.sent_frames, "ssrc": o.ssrc}))
                    .collect();
                let coverage: Vec<Value> = self.coverage.values().map(|c| c.report(50)).collect();
                let answer = self
                    .pc
                    .local_description()
                    .map(|d| d.sdp)
                    .unwrap_or_default();
                let stats = self.stats();
                self.out.push(json!({
                    "type": "report",
                    "rtp": self.rtp_by_key,
                    "dc_echoed": self.dc_echoed,
                    "sent": sent,
                    "coverage": coverage,
                    "state": self.state,
                    "cryptex": self.pc.cryptex_negotiated(),
                    "rollbacks": self.rollbacks,
                    "local_sdp": answer,
                    "stats": stats,
                    "errors": self.errors,
                }));
            }
            other => return Err(anyhow!("unknown message type {other:?}")),
        }
        Ok(())
    }

    /// The W3C stats a test compares with the browser's: RTP counters per SSRC, the remote
    /// candidates and the candidate pairs. A remote `.local` candidate keeps its name as its
    /// stats address after it resolves (the resolved address is not exposed,
    /// draft-ietf-mmusic-mdns-ice-candidates); the agent pairs it only once the name resolved,
    /// so a pair whose remote is that candidate shows the resolution.
    fn stats(&mut self) -> Value {
        let report = self.pc.get_stats(Instant::now(), StatsSelector::None);
        let inbound: Vec<Value> = report
            .inbound_rtp_streams()
            .map(|i| {
                let r = &i.received_rtp_stream_stats;
                json!({
                    "ssrc": r.rtp_stream_stats.ssrc,
                    "kind": r.rtp_stream_stats.kind.to_string(),
                    "packetsReceived": r.packets_received,
                })
            })
            .collect();
        let outbound: Vec<Value> = report
            .outbound_rtp_streams()
            .map(|o| {
                let r = &o.sent_rtp_stream_stats;
                json!({
                    "ssrc": r.rtp_stream_stats.ssrc,
                    "kind": r.rtp_stream_stats.kind.to_string(),
                    "packetsSent": r.packets_sent,
                })
            })
            .collect();
        let remote_candidates: Vec<Value> = report
            .iter()
            .filter_map(|e| match e {
                RTCStatsReportEntry::RemoteCandidate(c) => Some(json!({
                    "type": c.candidate_type.to_string(),
                    "address": c.address,
                    "port": c.port,
                    "protocol": c.protocol,
                })),
                _ => None,
            })
            .collect();
        let candidate_pairs: Vec<Value> = report
            .candidate_pairs()
            .map(|p| {
                let remote = report.iter().find_map(|e| match e {
                    RTCStatsReportEntry::RemoteCandidate(c)
                        if c.stats.id == p.remote_candidate_id =>
                    {
                        Some(c)
                    }
                    _ => None,
                });
                json!({
                    "state": p.state,
                    "nominated": p.nominated,
                    "remoteType": remote.map(|c| c.candidate_type.to_string()),
                    "remoteAddress": remote.map(|c| c.address.clone()),
                    "remotePort": remote.map(|c| c.port),
                })
            })
            .collect();
        json!({
            "inbound": inbound,
            "outbound": outbound,
            "remoteCandidates": remote_candidates,
            "candidatePairs": candidate_pairs,
        })
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
        // A scenario that names no policy keeps headers in the clear, as before the W3C
        // default ("negotiate") became the engine's.
        let policy = match sc["cryptex"].as_str() {
            Some("negotiate") => RTCRtpHeaderEncryptionPolicy::Negotiate,
            Some("require") => RTCRtpHeaderEncryptionPolicy::Require,
            _ => RTCRtpHeaderEncryptionPolicy::Disable,
        };
        self.pc.set_rtp_header_encryption_policy(policy)?;
        self.media = sc["media"].as_str().unwrap_or("").to_owned();
        if self.media != "reflect" && self.media != "send" {
            return Ok(());
        }
        let mut names = vec![];
        if let Some(v) = sc["video"].as_str() {
            names.push(v.to_ascii_uppercase());
        }
        if sc["audio"].as_bool().unwrap_or(false) {
            names.push("OPUS".to_owned());
        }
        let with_source = self.media == "send";
        for name in names {
            self.add_send_track(&name, with_source)?;
        }
        Ok(())
    }

    /// Adds a send track for codec `name`; with `with_source` it streams that codec's fixture
    /// (the scenario's `fixture` may name another file).
    fn add_send_track(&mut self, name: &str, with_source: bool) -> Result<()> {
        let (c, kind) = codec(name).ok_or_else(|| anyhow!("unknown codec {name}"))?;
        let ssrc = rand::random::<u32>();
        let sender = self.pc.add_track(MediaStreamTrack::new(
            format!("rust-stream-{kind}"),
            format!("rust-track-{kind}-{name}"),
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
        let source = if with_source {
            let kind_key = if kind == RtpCodecKind::Audio {
                "audio"
            } else {
                "video"
            };
            let file = self.scenario["fixture"][kind_key]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| default_fixture(name).to_owned());
            let path = format!("{}/{file}", self.media_dir);
            let open = || File::open(&path).map(BufReader::new);
            Some(match name {
                "VP8" | "VP9" | "AV1" => Source::Ivf(IVFReader::new(open()?)?.0),
                "H264" => Source::H26x(H26xSampleReader::new(open()?, 1 << 20, false)),
                "H265" => Source::H26x(H26xSampleReader::new(open()?, 1 << 20, true)),
                _ => Source::Ogg(Box::new(OggReader::new(open()?, true)?.0)),
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
        Ok(())
    }

    fn connected(&self) -> bool {
        self.connected
    }

    fn drive(&mut self) -> Result<()> {
        while let Some(m) = self.pc.poll_write() {
            let peer = m.transport.peer_addr;
            if m.transport.transport_protocol == TransportProtocol::TCP {
                if let Some(out) = self.tcp_out.get(&peer) {
                    let _ = out.send(frame_packet(&m.message));
                }
            } else if peer.port() == rtc::mdns::MDNS_PORT
                && let Some(mdns) = &self.mdns
            {
                let _ = mdns.try_send_to(&m.message, peer);
            } else if let Some((sock, _, _)) = self
                .transport_socks
                .iter()
                .find(|(_, local, _)| *local == m.transport.local_addr)
            {
                let _ = sock.try_send_to(&m.message, peer);
            } else {
                let _ = self.sock.try_send_to(&m.message, peer);
            }
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
                    self.state = st.to_string();
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
        *self.rtp_by_key.entry(key.clone()).or_default() += 1;
        let cov = self.coverage.entry(pkt.header.ssrc).or_default();
        cov.key = key;
        cov.add(pkt.header.sequence_number);
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
            // A track added by a renegotiation is not sent until its answer names a payload
            // type for it.
            let Some(pt) = self.pc.rtp_sender(o.sender).and_then(|mut s| {
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
            }) else {
                continue;
            };
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
            // One frame (an H.264 / H.265 access unit, or an Opus packet) per turn.
            let (data, samples, step): (Bytes, u32, Duration) = match o.source.as_mut().unwrap() {
                Source::Ivf(r) => match r.parse_next_frame() {
                    Ok((f, _)) => (f.freeze(), 3000, Duration::from_millis(33)),
                    Err(_) => {
                        o.source = None;
                        continue;
                    }
                },
                Source::H26x(r) => match r.next_sample() {
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
                Source::Ogg(r) => match next_audio_packet(r) {
                    Ok(d) => {
                        let n = opus_packet_samples(&d);
                        (
                            d.freeze(),
                            n,
                            Duration::from_micros(u64::from(n) * 1_000_000 / 48_000),
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

/// The next datagram on any of the transports' own sockets, with the local address it
/// arrived on.
async fn recv_any(
    socks: &[(UdpSocket, SocketAddr, String)],
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, SocketAddr)> {
    if socks.is_empty() {
        return std::future::pending().await;
    }
    let readable = socks.iter().map(|(sock, _, _)| Box::pin(sock.readable()));
    let (_, index, _) = futures_util::future::select_all(readable).await;
    let (sock, local, _) = &socks[index];
    let (n, peer) = sock.try_recv_from(buf)?;
    Ok((n, peer, *local))
}

async fn recv_opt(
    sock: &Option<UdpSocket>,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    match sock {
        Some(s) => s.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

async fn accept_opt(
    listener: &Option<TcpListener>,
) -> std::io::Result<(tokio::net::TcpStream, SocketAddr)> {
    match listener {
        Some(l) => l.accept().await,
        None => std::future::pending().await,
    }
}

/// The next Opus packet: one RTP payload (RFC 7587 4.2). A page may hold several packets and a
/// packet may span pages (RFC 3533 section 6), so packets are read, not pages. OpusHead and
/// OpusTags are stream headers, not packets to send (RFC 7845 section 3).
fn next_audio_packet(r: &mut OggReader<BufReader<File>>) -> rtc::shared::error::Result<BytesMut> {
    loop {
        let (d, _) = r.next_packet()?;
        if !d.starts_with(b"OpusHead") && !d.starts_with(b"OpusTags") {
            return Ok(d);
        }
    }
}

/// The number of 48 kHz samples in an Opus packet, read from its TOC byte (RFC 6716 section
/// 3.1): the frame size its configuration gives, times its frame count.
fn opus_packet_samples(packet: &[u8]) -> u32 {
    let Some(&toc) = packet.first() else {
        return 0;
    };
    let config = toc >> 3;
    let frame: u32 = match config {
        // SILK-only: 10, 20, 40, 60 ms.
        0..=11 => [480, 960, 1920, 2880][usize::from(config % 4)],
        // Hybrid: 10, 20 ms.
        12..=15 => [480, 960][usize::from(config % 2)],
        // CELT-only: 2.5, 5, 10, 20 ms.
        _ => [120, 240, 480, 960][usize::from(config % 4)],
    };
    let frames: u32 = match toc & 0x03 {
        0 => 1,
        1 | 2 => 2,
        _ => packet.get(1).map_or(0, |b| u32::from(b & 0x3f)),
    };
    frame * frames
}

fn codec_kind(c: &RTCRtpCodec) -> RtpCodecKind {
    if c.mime_type.to_ascii_lowercase().starts_with("audio/") {
        RtpCodecKind::Audio
    } else {
        RtpCodecKind::Video
    }
}
