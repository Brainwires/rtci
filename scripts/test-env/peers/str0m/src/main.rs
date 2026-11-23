//! str0m-peer: the str0m (sans-I/O WebRTC, Rust) peer of the interop matrix. It runs one plan
//! (scripts/test-env/peers/README.md) against examples/interop-peer over the browser page's
//! WebSocket signalling and prints the result as the last line of stdout.
//!
//! str0m does no I/O: this program owns the UDP socket, the TCP connections of its active
//! ICE-TCP candidate (RFC 4571 framing) and the clock, and drives the `Rtc` the way str0m's
//! README asks: every mutation is followed by draining `poll_output` to its timeout.

use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};
use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use str0m::config::DtlsVersion;
use str0m::format::Codec;
use str0m::media::{
    Direction, Frequency, KeyframeRequestKind, MediaKind, MediaTime, Mid, Rid, Simulcast,
    SimulcastLayer,
};
use str0m::net::{Protocol, Receive, TcpType};
use str0m::rtp::RawPacket;
use str0m::rtp::rtcp::Rtcp;
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc, RtcConfig};
use tungstenite::{Message, WebSocket};

type Res<T> = Result<T, String>;

fn err<E: std::fmt::Display>(what: &str) -> impl FnOnce(E) -> String + '_ {
    move |e| format!("{what}: {e}")
}

// ---- media sources: the environment's fixtures, looped ----

/// VP8 / VP9 frames from an IVF file (a 32-byte header, then a 12-byte header per frame).
fn ivf_frames(path: &str) -> Res<Vec<Vec<u8>>> {
    let b = std::fs::read(path).map_err(err(path))?;
    if b.len() < 32 || &b[..4] != b"DKIF" {
        return Err(format!("{path}: not IVF"));
    }
    let header = u16::from_le_bytes([b[6], b[7]]) as usize;
    let (mut i, mut out) = (header, vec![]);
    while i + 12 <= b.len() {
        let n = u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as usize;
        i += 12;
        if i + n > b.len() {
            break;
        }
        out.push(b[i..i + n].to_vec());
        i += n;
    }
    Ok(out)
}

/// H.264 access units from an Annex B file with one slice per picture: the NAL units up to
/// and including each coded slice, as Annex B again.
fn h264_access_units(path: &str) -> Res<Vec<Vec<u8>>> {
    let b = std::fs::read(path).map_err(err(path))?;
    let mut starts = vec![];
    let mut i = 0;
    while i + 3 <= b.len() {
        if b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 1 {
            starts.push(i + 3);
            i += 3;
        } else {
            i += 1;
        }
    }
    let (mut out, mut au) = (vec![], vec![]);
    for (k, &s) in starts.iter().enumerate() {
        let mut e = starts.get(k + 1).map(|n| n - 3).unwrap_or(b.len());
        while e > s && b[e - 1] == 0 {
            e -= 1;
        }
        if s >= e {
            continue;
        }
        let nal = &b[s..e];
        au.extend_from_slice(&[0, 0, 0, 1]);
        au.extend_from_slice(nal);
        if matches!(nal[0] & 0x1f, 1 | 5) {
            out.push(std::mem::take(&mut au));
        }
    }
    Ok(out)
}

/// Opus packets from an Ogg file (RFC 3533 pages, packets from the lacing values), without
/// the OpusHead and OpusTags headers.
fn ogg_packets(path: &str) -> Res<Vec<Vec<u8>>> {
    let b = std::fs::read(path).map_err(err(path))?;
    let (mut i, mut out, mut packet) = (0, vec![], vec![]);
    while i + 27 <= b.len() && &b[i..i + 4] == b"OggS" {
        let segments = b[i + 26] as usize;
        let table = &b[i + 27..i + 27 + segments];
        let mut p = i + 27 + segments;
        for &lace in table {
            let n = lace as usize;
            packet.extend_from_slice(&b[p..p + n]);
            p += n;
            if lace < 255 {
                let done = std::mem::take(&mut packet);
                if !done.starts_with(b"OpusHead") && !done.starts_with(b"OpusTags") {
                    out.push(done);
                }
            }
        }
        i = p;
    }
    Ok(out)
}

/// The 48 kHz samples in an Opus packet, from its TOC byte (RFC 6716 3.1).
fn opus_samples(p: &[u8]) -> u64 {
    let Some(&toc) = p.first() else { return 960 };
    let config = toc >> 3;
    let frame = match config {
        0..=11 => [480, 960, 1920, 2880][usize::from(config % 4)],
        12..=15 => [480, 960][usize::from(config % 2)],
        _ => [120, 240, 480, 960][usize::from(config % 4)],
    };
    let frames = match toc & 3 {
        0 => 1,
        1 | 2 => 2,
        _ => p.get(1).map_or(1, |b| u64::from(b & 0x3f)),
    };
    frame * frames
}

struct Track {
    kind: MediaKind,
    codec: String,
    rids: Vec<Rid>,
    mid: Option<Mid>,
    /// Sent on the section Rust's offer has for this kind (the plan asks Rust to offer first).
    attach: bool,
    frames: Vec<Vec<u8>>,
    next_frame: usize,
    rtp_time: u64,
    next: Instant,
    stopped: bool,
}

enum Change {
    Media(usize),
    Recv(MediaKind, Direction),
    Channel(String, ChannelConfig),
    Direction(Mid, Direction),
    Restart,
}

/// Sequence numbers received on one stream (str0m extends them to 64 bits).
#[derive(Default)]
struct Coverage {
    kind: String,
    seen: HashSet<u64>,
    min: u64,
    max: u64,
}

struct TcpConn {
    stream: TcpStream,
    local: SocketAddr,
    buf: Vec<u8>,
}

struct Peer {
    plan: Value,
    rtc: Rtc,
    udp: UdpSocket,
    local: SocketAddr,
    ws: WebSocket<TcpStream>,
    stdin: BufReader<std::io::Stdin>,
    deadline: Instant,
    next_timeout: Instant,
    trickle: bool,
    tcp: HashMap<SocketAddr, TcpConn>,
    local_candidates: Vec<Candidate>,
    candidates_added: bool,
    scenario_sent: bool,
    sent_description: bool,
    pending: Option<SdpPendingOffer>,
    queue: Vec<Change>,
    in_flight: Vec<Change>,
    impolite: bool,
    munge_remote: String,
    tracks: Vec<Track>,
    kind_by_mid: HashMap<Mid, MediaKind>,
    remote_video: Vec<Mid>,
    sctp_negotiated: bool,
    channels: HashMap<String, ChannelId>,
    labels: HashMap<ChannelId, String>,
    open: HashSet<ChannelId>,
    local_labels: HashSet<String>,
    connected: bool,
    /// The transport protocol and peer of the last datagram str0m took (what the session
    /// runs on when its stats name no selected pair).
    last_path: Option<(Protocol, SocketAddr)>,
    ice_state: String,
    answers_got: u32,
    answers_sent: u32,
    reports: u32,
    // the result
    steps: Vec<Value>,
    echo: BTreeMap<String, (Vec<Value>, Vec<usize>)>,
    remote_channels: BTreeMap<String, String>,
    rtp: BTreeMap<String, (u64, u64, String)>,
    rtp_sent: BTreeMap<String, (u64, u64)>,
    coverage: BTreeMap<String, Coverage>,
    rtcp: BTreeMap<String, u64>,
    rtcp_sent: BTreeMap<String, u64>,
    selected: Value,
    descriptions: Vec<Value>,
    remote_offers: u32,
    ignored_offers: u32,
    trickled: u32,
    candidate_lines: Vec<String>,
    rust: Value,
    rust_errors: Vec<String>,
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_default()
}

fn n(v: &Value, k: &str, def: u64) -> u64 {
    v[k].as_u64().unwrap_or(def)
}

fn ms(v: &Value, def: u64) -> Instant {
    Instant::now() + Duration::from_millis(n(v, "ms", def))
}

fn strip_bundle(sdp: &str) -> String {
    sdp.split_inclusive('\n')
        .filter(|l| !l.starts_with("a=group:BUNDLE"))
        .collect()
}

fn ufrag_of(sdp: &str) -> Option<String> {
    sdp.lines()
        .find_map(|l| l.strip_prefix("a=ice-ufrag:"))
        .map(|u| u.trim().to_owned())
}

fn first_mid(sdp: &str) -> Option<String> {
    sdp.lines()
        .find_map(|l| l.strip_prefix("a=mid:"))
        .map(|u| u.trim().to_owned())
}

/// The UDP port of Rust's host candidate in a description (what netem filters on).
fn rust_port(sdp: &str) -> u64 {
    sdp.lines()
        .filter(|l| l.starts_with("a=candidate:"))
        .find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() > 7 && f[2].eq_ignore_ascii_case("udp") && f[7] == "host")
                .then(|| f[5].parse().ok())
                .flatten()
        })
        .unwrap_or(0)
}

fn rtcp_name(r: &Rtcp) -> String {
    match r {
        Rtcp::SenderReport(_) => "sr",
        Rtcp::ReceiverReport(_) => "rr",
        Rtcp::SourceDescription(_) => "sdes",
        Rtcp::Goodbye(_) => "bye",
        Rtcp::Nack(_) => "nack",
        Rtcp::Pli(_) => "pli",
        Rtcp::Fir(_) => "fir",
        Rtcp::Twcc(_) => "twcc",
        Rtcp::Remb(_) => "remb",
        Rtcp::ExtendedReport(_) => "xr",
        _ => "other",
    }
    .to_owned()
}

fn kind_name(k: MediaKind) -> &'static str {
    if k == MediaKind::Audio {
        "audio"
    } else {
        "video"
    }
}

fn codec_of(name: &str) -> Option<Codec> {
    Some(match name.to_ascii_lowercase().as_str() {
        "opus" => Codec::Opus,
        "vp8" => Codec::Vp8,
        "vp9" => Codec::Vp9,
        "h264" => Codec::H264,
        _ => return None,
    })
}

impl Peer {
    fn new(plan: Value) -> Res<Peer> {
        let ws_url = s(&plan, "ws").to_owned();
        let host = ws_url
            .trim_start_matches("ws://")
            .split('/')
            .next()
            .unwrap_or_default()
            .to_owned();
        let ws_addr: SocketAddr = host.parse().map_err(err("the plan's ws address"))?;
        // The address this host reaches Rust from: the host candidate's.
        let probe = UdpSocket::bind("0.0.0.0:0").map_err(err("udp"))?;
        probe.connect(ws_addr).map_err(err("udp route"))?;
        let ip: IpAddr = probe.local_addr().map_err(err("udp"))?.ip();
        let udp = UdpSocket::bind(SocketAddr::new(ip, 0)).map_err(err("udp bind"))?;
        udp.set_nonblocking(true).map_err(err("udp"))?;
        let local = udp.local_addr().map_err(err("udp"))?;

        // The plan's codecs only, so every description names the codec the cell is about.
        let mut codecs: HashSet<String> = HashSet::new();
        for st in plan["steps"].as_array().cloned().unwrap_or_default() {
            match s(&st, "op") {
                "track" => {
                    codecs.insert(s(&st, "codec").to_ascii_lowercase());
                }
                "request-offer" => {
                    for t in st["tracks"].as_array().cloned().unwrap_or_default() {
                        codecs.insert(t.as_str().unwrap_or_default().to_ascii_lowercase());
                    }
                }
                _ => {}
            }
        }
        if let Some(v) = plan["scenario"]["video"].as_str() {
            codecs.insert(v.to_ascii_lowercase());
        }
        let video = ["vp8", "vp9", "h264"].iter().any(|c| codecs.contains(*c));
        let mut cfg = RtcConfig::new()
            .clear_codecs()
            .enable_opus(true, false)
            .enable_vp8(codecs.contains("vp8") || !video)
            .enable_vp9(codecs.contains("vp9"))
            .enable_h264(codecs.contains("h264"))
            .set_stats_interval(Some(Duration::from_millis(500)))
            .enable_raw_packets(true)
            // Room for a 256 KiB message in the send buffer (the default is 128 KiB).
            .set_sctp_max_buffered_amount(4 << 20);
        if plan["config"]["dtls13"].as_bool().unwrap_or(false) {
            // DTLS 1.3 preferred: a client sends a ClientHello for both versions, a server
            // takes whichever the ClientHello offers (dimpl `Dtls::new_auto`).
            cfg = cfg.set_dtls_version(DtlsVersion::Auto);
        }
        let rtc = cfg.build(Instant::now());

        let stream = TcpStream::connect(ws_addr).map_err(err("websocket connect"))?;
        let (ws, _) = tungstenite::client(ws_url.as_str(), stream).map_err(err("websocket"))?;
        ws.get_ref()
            .set_nonblocking(true)
            .map_err(err("websocket"))?;
        let timeout = n(&plan, "timeout_ms", 60000);
        let trickle = plan["config"]["trickle"].as_bool().unwrap_or(true);
        Ok(Peer {
            rtc,
            udp,
            local,
            ws,
            stdin: BufReader::new(std::io::stdin()),
            deadline: Instant::now() + Duration::from_millis(timeout),
            next_timeout: Instant::now(),
            trickle,
            tcp: HashMap::new(),
            local_candidates: vec![],
            candidates_added: false,
            scenario_sent: false,
            sent_description: false,
            pending: None,
            queue: vec![],
            in_flight: vec![],
            impolite: false,
            munge_remote: String::new(),
            tracks: vec![],
            kind_by_mid: HashMap::new(),
            remote_video: vec![],
            sctp_negotiated: false,
            channels: HashMap::new(),
            labels: HashMap::new(),
            open: HashSet::new(),
            local_labels: HashSet::new(),
            connected: false,
            last_path: None,
            ice_state: "new".into(),
            answers_got: 0,
            answers_sent: 0,
            reports: 0,
            steps: vec![],
            echo: BTreeMap::new(),
            remote_channels: BTreeMap::new(),
            rtp: BTreeMap::new(),
            rtp_sent: BTreeMap::new(),
            coverage: BTreeMap::new(),
            rtcp: BTreeMap::new(),
            rtcp_sent: BTreeMap::new(),
            selected: Value::Null,
            descriptions: vec![],
            remote_offers: 0,
            ignored_offers: 0,
            trickled: 0,
            candidate_lines: vec![],
            rust: Value::Null,
            rust_errors: vec![],
            plan,
        })
    }

    // ---- the run loop ----

    /// Drains `poll_output` to its timeout: transmits go out, events are recorded.
    fn drain(&mut self) -> Res<()> {
        loop {
            match self.rtc.poll_output().map_err(err("poll_output"))? {
                Output::Timeout(t) => {
                    self.next_timeout = t;
                    return Ok(());
                }
                Output::Transmit(t) => match t.proto {
                    Protocol::Udp => {
                        let _ = self.udp.send_to(&t.contents, t.destination);
                    }
                    _ => self.tcp_send(t.destination, &t.contents),
                },
                Output::Event(e) => self.on_event(e),
            }
        }
    }

    fn input(&mut self, proto: Protocol, source: SocketAddr, destination: SocketAddr, data: &[u8]) {
        let Ok(contents) = data.try_into() else {
            return;
        };
        let input = Input::Receive(
            Instant::now(),
            Receive {
                proto,
                source,
                destination,
                contents,
            },
        );
        if self.rtc.accepts(&input) {
            if self.connected {
                self.last_path = Some((proto, source));
            }
            let _ = self.rtc.handle_input(input);
            let _ = self.drain();
        }
    }

    /// An ICE-TCP frame (RFC 4571: a 16-bit length, then the packet) to `to`, on a connection
    /// this side opens (its candidate is active, RFC 6544 4.1).
    fn tcp_send(&mut self, to: SocketAddr, data: &[u8]) {
        if !self.tcp.contains_key(&to) {
            let Ok(stream) = TcpStream::connect_timeout(&to, Duration::from_secs(2)) else {
                eprintln!("ICE-TCP connect to {to} failed");
                return;
            };
            let _ = stream.set_nodelay(true);
            let _ = stream.set_nonblocking(true);
            let local = stream.local_addr().unwrap_or(self.local);
            self.tcp.insert(
                to,
                TcpConn {
                    stream,
                    local,
                    buf: vec![],
                },
            );
        }
        let conn = self.tcp.get_mut(&to).unwrap();
        let mut frame = (data.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(data);
        let mut off = 0;
        while off < frame.len() {
            match conn.stream.write(&frame[off..]) {
                Ok(k) => off += k,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(_) => return,
            }
        }
    }

    /// Reads what the sockets and the signalling have, hands it on, streams media and fires
    /// the timeout; true when something happened.
    fn turn(&mut self) -> Res<bool> {
        let mut busy = false;
        let mut buf = [0u8; 2048];
        while let Ok((k, from)) = self.udp.recv_from(&mut buf) {
            busy = true;
            let local = self.local;
            self.input(Protocol::Udp, from, local, &buf[..k]);
        }
        let peers: Vec<SocketAddr> = self.tcp.keys().copied().collect();
        for peer in peers {
            let mut frames = vec![];
            let local;
            {
                let conn = self.tcp.get_mut(&peer).unwrap();
                local = conn.local;
                let mut b = [0u8; 4096];
                loop {
                    match conn.stream.read(&mut b) {
                        Ok(0) => break,
                        Ok(k) => conn.buf.extend_from_slice(&b[..k]),
                        Err(_) => break,
                    }
                }
                while conn.buf.len() >= 2 {
                    let len = u16::from_be_bytes([conn.buf[0], conn.buf[1]]) as usize;
                    if conn.buf.len() < 2 + len {
                        break;
                    }
                    frames.push(conn.buf[2..2 + len].to_vec());
                    conn.buf.drain(..2 + len);
                }
            }
            for f in frames {
                busy = true;
                // A request or response belongs to the local candidate it arrived on, by its
                // address (is Agent: `v.addr() == req.destination`): the active candidate's,
                // announced with the discard port 9 (RFC 6544 4.5), not the connection's own.
                let dest = SocketAddr::new(local.ip(), 9);
                self.input(Protocol::Tcp, peer, dest, &f);
            }
        }
        loop {
            match self.ws.read() {
                Ok(Message::Text(t)) => {
                    busy = true;
                    let m: Value = serde_json::from_str(&t).map_err(err("signalling"))?;
                    self.handle(m)?;
                }
                Ok(Message::Close(_)) => return Err("the signalling connection closed".into()),
                Ok(_) => {}
                Err(tungstenite::Error::Io(e)) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(format!("signalling: {e}")),
            }
        }
        if self.send_media()? {
            busy = true;
        }
        let now = Instant::now();
        if now >= self.next_timeout {
            self.rtc
                .handle_input(Input::Timeout(now))
                .map_err(err("timeout"))?;
            self.drain()?;
        }
        Ok(busy)
    }

    /// Runs the loop until `cond` holds, failing at `until`.
    fn pump(
        &mut self,
        until: Instant,
        what: &str,
        mut cond: impl FnMut(&mut Peer) -> Res<bool>,
    ) -> Res<()> {
        let until = until.min(self.deadline);
        loop {
            self.drain()?;
            if cond(self)? {
                return Ok(());
            }
            if Instant::now() > until {
                return Err(format!("timed out waiting for {what}"));
            }
            if !self.turn()? {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    fn wait(&mut self, d: u64) -> Res<()> {
        let until = Instant::now() + Duration::from_millis(d);
        match self.pump(until, "", |_| Ok(false)) {
            Err(e) if e.starts_with("timed out") => Ok(()),
            r => r,
        }
    }

    fn on_event(&mut self, e: Event) {
        match e {
            Event::Connected => self.connected = true,
            Event::IceConnectionStateChange(st) => {
                self.ice_state = format!("{st:?}").to_ascii_lowercase();
                if st == IceConnectionState::Disconnected {
                    self.connected = false;
                }
            }
            Event::MediaAdded(m) => {
                self.kind_by_mid.insert(m.mid, m.kind);
                if let Some(t) = self
                    .tracks
                    .iter_mut()
                    .find(|t| t.attach && t.mid.is_none() && t.kind == m.kind)
                {
                    t.mid = Some(m.mid);
                }
            }
            Event::MediaData(d) => {
                let kind = self
                    .kind_by_mid
                    .get(&d.mid)
                    .copied()
                    .map(kind_name)
                    .unwrap_or("video");
                if kind == "video" && !self.remote_video.contains(&d.mid) {
                    self.remote_video.push(d.mid);
                }
                let (a, b) = (**d.seq_range.start(), **d.seq_range.end());
                let e = self.rtp.entry(kind.into()).or_default();
                e.0 += b.saturating_sub(a) + 1;
                e.1 += d.data.len() as u64;
                e.2 = format!("{}/{}", kind, d.params.spec().codec).to_ascii_lowercase();
                let key = format!(
                    "{}:{}",
                    d.mid,
                    d.rid.map(|r| r.to_string()).unwrap_or_default()
                );
                let c = self.coverage.entry(key).or_default();
                c.kind = kind.into();
                if c.seen.is_empty() {
                    c.min = a;
                    c.max = b;
                }
                c.min = c.min.min(a);
                c.max = c.max.max(b);
                for s in a..=b {
                    c.seen.insert(s);
                }
            }
            Event::ChannelOpen(id, label) => {
                self.open.insert(id);
                self.labels.insert(id, label.clone());
                self.channels.entry(label).or_insert(id);
            }
            Event::ChannelData(d) => {
                let label = self.labels.get(&d.id).cloned().unwrap_or_default();
                if !self.local_labels.contains(&label) && !self.remote_channels.contains_key(&label)
                {
                    self.remote_channels
                        .insert(label.clone(), String::from_utf8_lossy(&d.data).into_owned());
                }
                let e = self.echo.entry(label).or_default();
                if d.binary {
                    let v = if d.data.len() >= 4 {
                        json!(u32::from_be_bytes([
                            d.data[0], d.data[1], d.data[2], d.data[3]
                        ]))
                    } else {
                        json!(-1)
                    };
                    e.0.push(v);
                } else {
                    e.0.push(json!(String::from_utf8_lossy(&d.data)));
                }
                e.1.push(d.data.len());
            }
            Event::PeerStats(st) => {
                if let Some(p) = st.selected_candidate_pair {
                    let proto = format!("{:?}", p.protocol).to_ascii_lowercase();
                    let proto = if proto == "udp" { "udp" } else { "tcp" };
                    self.selected = json!({
                        "local": {"candidateType": "host", "protocol": proto, "address": p.local.addr.ip().to_string(), "port": p.local.addr.port(), "relayProtocol": null},
                        "remote": {"candidateType": null, "protocol": proto, "address": p.remote.addr.ip().to_string(), "port": p.remote.addr.port()},
                    });
                }
            }
            Event::RawPacket(raw) => {
                if let RawPacket::RtcpRx(r) = &*raw {
                    *self.rtcp.entry(rtcp_name(r)).or_default() += 1;
                }
            }
            _ => {}
        }
    }

    // ---- signalling ----

    fn send(&mut self, mut m: Value) -> Res<()> {
        let t = s(&m, "type").to_owned();
        if (t == "offer" || t == "request-offer") && !self.scenario_sent {
            m["scenario"] = if self.plan["scenario"].is_null() {
                json!({})
            } else {
                self.plan["scenario"].clone()
            };
            self.scenario_sent = true;
        }
        let text = m.to_string();
        let mut msg = Some(Message::Text(text.into()));
        loop {
            let r = match msg.take() {
                Some(mm) => self.ws.send(mm),
                None => self.ws.flush(),
            };
            match r {
                Ok(()) => return Ok(()),
                Err(tungstenite::Error::Io(e)) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => return Err(format!("signalling send: {e}")),
            }
        }
    }

    fn record(&mut self, dir: &str, typ: &str, sdp: &str) {
        self.descriptions.push(json!([dir, typ, sdp]));
    }

    /// The host candidates: UDP, and an active TCP one when the plan asks for ICE-TCP.
    fn add_candidates(&mut self) -> Res<()> {
        if self.candidates_added {
            return Ok(());
        }
        self.candidates_added = true;
        let mut list = vec![Candidate::host(self.local, "udp").map_err(err("candidate"))?];
        if self.plan["config"]["tcp"].as_bool().unwrap_or(false) {
            list.push(
                Candidate::builder()
                    .tcp()
                    .host(SocketAddr::new(self.local.ip(), 9))
                    .tcptype(TcpType::Active)
                    .build()
                    .map_err(err("tcp candidate"))?,
            );
        }
        for c in list {
            self.candidate_lines.push(c.to_sdp_string());
            if let Some(c) = self.rtc.add_local_candidate(c) {
                self.local_candidates.push(c.clone());
            }
            self.drain()?;
        }
        Ok(())
    }

    /// Sends a description; with trickle, the candidates follow it the first time (they are
    /// added only now, so the description carries none).
    fn send_description(&mut self, typ: &str, sdp: String) -> Res<()> {
        self.record("sent", typ, &sdp);
        self.send(json!({"type": typ, "sdp": sdp}))?;
        if typ == "answer" {
            self.answers_sent += 1;
        }
        if self.trickle && !self.sent_description {
            self.sent_description = true;
            self.add_candidates()?;
            let mid = first_mid(&sdp);
            let ufrag = ufrag_of(&sdp);
            let lines: Vec<String> = self
                .local_candidates
                .iter()
                .map(|c| c.to_sdp_string())
                .collect();
            for line in lines {
                self.send(json!({"type": "candidate", "candidate": {
                    "candidate": line, "sdpMid": mid, "sdpMLineIndex": 0, "usernameFragment": ufrag,
                }}))?;
                self.trickled += 1;
            }
        }
        self.sent_description = true;
        Ok(())
    }

    fn before_description(&mut self) -> Res<()> {
        if !self.trickle {
            self.add_candidates()?;
        }
        Ok(())
    }

    fn handle(&mut self, m: Value) -> Res<()> {
        match s(&m, "type") {
            "answer" => {
                let sdp = s(&m, "sdp").to_owned();
                self.record("received", "answer", &sdp);
                let Some(pending) = self.pending.take() else {
                    return Err("an answer without an offer of ours".into());
                };
                let answer = SdpAnswer::from_sdp_string(&sdp).map_err(err("Rust's answer"))?;
                self.rtc
                    .sdp_api()
                    .accept_answer(pending, answer)
                    .map_err(err("accepting Rust's answer"))?;
                self.drain()?;
                self.in_flight.clear();
                if sdp.contains("m=application") {
                    self.sctp_negotiated = true;
                }
                self.answers_got += 1;
            }
            "offer" => {
                let sdp = s(&m, "sdp").to_owned();
                self.remote_offers += 1;
                if self.impolite && self.pending.is_some() {
                    self.ignored_offers += 1;
                    self.record("ignored", "offer", &sdp);
                    return Ok(());
                }
                let sdp = if self.munge_remote == "strip-bundle" {
                    strip_bundle(&sdp)
                } else {
                    sdp
                };
                self.munge_remote.clear();
                self.record("received", "offer", &sdp);
                // Accepting an offer rolls back a pending one of ours (str0m SdpApi::accept_offer).
                if self.pending.take().is_some() {
                    self.queue.splice(0..0, self.in_flight.drain(..));
                }
                self.before_description()?;
                let offer = SdpOffer::from_sdp_string(&sdp).map_err(err("Rust's offer"))?;
                let answer = self
                    .rtc
                    .sdp_api()
                    .accept_offer(offer)
                    .map_err(err("accepting Rust's offer"))?;
                self.drain()?;
                if sdp.contains("m=application") {
                    self.sctp_negotiated = true;
                    self.open_queued_channels()?;
                }
                self.send_description("answer", answer.to_sdp_string())?;
            }
            "candidate" => {
                let line = m["candidate"]["candidate"].as_str().unwrap_or_default();
                if !line.is_empty() {
                    let c = Candidate::from_sdp_string(line).map_err(err("Rust's candidate"))?;
                    self.rtc.add_remote_candidate(c);
                    self.drain()?;
                }
            }
            "report" => {
                self.rust = m;
                self.reports += 1;
            }
            "error" => self.rust_errors.push(m["error"].to_string()),
            _ => {}
        }
        Ok(())
    }

    /// Channels created before an association existed, once one is negotiated.
    fn open_queued_channels(&mut self) -> Res<()> {
        let mut keep = vec![];
        for c in std::mem::take(&mut self.queue) {
            match c {
                Change::Channel(label, cfg) => {
                    let id = self.rtc.direct_api().create_data_channel(cfg);
                    self.drain()?;
                    self.channels.insert(label.clone(), id);
                    self.labels.insert(id, label);
                }
                other => keep.push(other),
            }
        }
        self.queue = keep;
        Ok(())
    }

    /// Makes an offer from the queued changes and applies it locally; None when nothing needs
    /// negotiating.
    fn make_offer(&mut self) -> Res<Option<String>> {
        self.before_description()?;
        let changes = std::mem::take(&mut self.queue);
        let mut api = self.rtc.sdp_api();
        let mut mids = vec![];
        let mut chans = vec![];
        for c in &changes {
            match c {
                Change::Media(i) => {
                    let t = &self.tracks[*i];
                    let sim = (!t.rids.is_empty()).then(|| {
                        let mut s = Simulcast::new();
                        for r in &t.rids {
                            s.add_send_layer(SimulcastLayer::new(r));
                        }
                        s
                    });
                    let mid = api.add_media(
                        t.kind,
                        Direction::SendRecv,
                        Some("str0m".into()),
                        Some(t.codec.clone()),
                        sim,
                    );
                    mids.push((*i, mid));
                }
                Change::Recv(kind, dir) => {
                    api.add_media(*kind, *dir, None, None, None);
                }
                Change::Channel(label, cfg) => {
                    chans.push((label.clone(), api.add_channel_with_config(cfg.clone())));
                }
                Change::Direction(mid, dir) => api.set_direction(*mid, *dir),
                Change::Restart => {
                    api.ice_restart(true);
                }
            }
        }
        let applied = api.apply();
        self.drain()?;
        for (i, mid) in mids {
            self.tracks[i].mid = Some(mid);
            self.kind_by_mid.insert(mid, self.tracks[i].kind);
        }
        for (label, id) in chans {
            self.channels.insert(label.clone(), id);
            self.labels.insert(id, label);
        }
        match applied {
            Some((offer, pending)) => {
                self.pending = Some(pending);
                self.in_flight = changes;
                let sdp = offer.to_sdp_string();
                self.record("local", "offer", &sdp);
                Ok(Some(sdp))
            }
            None => Ok(None),
        }
    }

    fn offer(&mut self, st: &Value) -> Res<Value> {
        let Some(sdp) = self.make_offer()? else {
            // str0m opens a channel on an existing association without a negotiation.
            return Ok(json!({"note": "nothing to negotiate"}));
        };
        let sdp = if s(st, "munge") == "strip-bundle" {
            strip_bundle(&sdp)
        } else {
            sdp
        };
        let got = self.answers_got;
        self.send_description("offer", sdp)?;
        self.pump(ms(st, 15000), "the answer", |p| Ok(p.answers_got > got))?;
        Ok(json!({}))
    }

    // ---- media ----

    fn add_track(&mut self, st: &Value, index: usize) -> Res<()> {
        let codec = s(st, "codec").to_ascii_lowercase();
        let kind = if s(st, "kind") == "audio" {
            MediaKind::Audio
        } else {
            MediaKind::Video
        };
        let dir = s(&self.plan, "media").to_owned();
        let frames = match codec.as_str() {
            "vp8" => ivf_frames(&format!("{dir}/vp8.ivf"))?,
            "vp9" => ivf_frames(&format!("{dir}/vp9.ivf"))?,
            "h264" => h264_access_units(&format!("{dir}/h264.h264"))?,
            _ => ogg_packets(&format!("{dir}/opus.ogg"))?,
        };
        if frames.is_empty() {
            return Err(format!("no frames in the {codec} fixture"));
        }
        // Whether Rust offers first: then the track goes on the section Rust's offer has.
        let steps = self.plan["steps"].as_array().cloned().unwrap_or_default();
        let attach = steps
            .iter()
            .skip(index + 1)
            .map(|x| s(x, "op").to_owned())
            .find(|op| op == "offer" || op == "request-offer")
            .is_some_and(|op| op == "request-offer")
            && self.kind_by_mid.is_empty();
        let rids: Vec<Rid> = st["simulcast"]
            .as_array()
            .map(|a| a.iter().filter_map(|r| r.as_str()).map(Rid::from).collect())
            .unwrap_or_default();
        self.tracks.push(Track {
            kind,
            codec,
            rids,
            mid: None,
            attach,
            frames,
            next_frame: 0,
            rtp_time: 0,
            next: Instant::now(),
            stopped: false,
        });
        if !attach {
            self.queue.push(Change::Media(self.tracks.len() - 1));
        }
        Ok(())
    }

    /// One frame per track whose time has come, once connected.
    fn send_media(&mut self) -> Res<bool> {
        if !self.connected {
            return Ok(false);
        }
        let now = Instant::now();
        let mut sent = false;
        for i in 0..self.tracks.len() {
            let (mid, codec, frame, ticks, freq, step, rids, kind) = {
                let t = &mut self.tracks[i];
                let Some(mid) = t.mid else { continue };
                if t.stopped || t.next > now {
                    continue;
                }
                let frame = t.frames[t.next_frame % t.frames.len()].clone();
                t.next_frame += 1;
                let (ticks, freq) = if t.kind == MediaKind::Audio {
                    (opus_samples(&frame), Frequency::FORTY_EIGHT_KHZ)
                } else {
                    (3000, Frequency::NINETY_KHZ)
                };
                let step = Duration::from_micros(ticks * 1_000_000 / u64::from(freq.get()));
                (
                    mid,
                    t.codec.clone(),
                    frame,
                    ticks,
                    freq,
                    step,
                    t.rids.clone(),
                    t.kind,
                )
            };
            let want = codec_of(&codec);
            let pt = self.rtc.writer(mid).and_then(|w| {
                w.payload_params()
                    .find(|p| {
                        let spec = p.spec();
                        Some(spec.codec) == want
                            && (spec.codec != Codec::H264
                                || spec.format.packetization_mode == Some(1))
                    })
                    .map(|p| p.pt())
            });
            let t = &mut self.tracks[i];
            t.next = now + step;
            let rtp_time = t.rtp_time;
            t.rtp_time += ticks;
            let Some(pt) = pt else { continue };
            let layers: Vec<Option<Rid>> = if rids.is_empty() {
                vec![None]
            } else {
                rids.into_iter().map(Some).collect()
            };
            for rid in layers {
                if let Some(mut w) = self.rtc.writer(mid) {
                    if let Some(r) = rid {
                        w = w.rid(r);
                    }
                    if let Err(e) = w.write(pt, now, MediaTime::new(rtp_time, freq), frame.clone())
                    {
                        eprintln!("write {codec}: {e}");
                    }
                }
                self.drain()?;
            }
            let e = self.rtp_sent.entry(kind_name(kind).into()).or_default();
            e.0 += 1;
            e.1 += frame.len() as u64;
            sent = true;
        }
        Ok(sent)
    }

    fn rust_rtp(&self, kind: &str) -> u64 {
        self.rust["rtp"]
            .as_object()
            .map(|m| {
                m.iter()
                    .filter(|(k, _)| k.starts_with(&format!("{kind}:")))
                    .filter_map(|(_, v)| v.as_u64())
                    .sum()
            })
            .unwrap_or(0)
    }

    fn report(&mut self) -> Res<()> {
        let n0 = self.reports;
        self.send(json!({"type": "report"}))?;
        self.pump(
            Instant::now() + Duration::from_secs(5),
            "Rust's report",
            |p| Ok(p.reports > n0),
        )
    }

    fn control(&mut self, ev: Value) -> Res<Value> {
        println!("{ev}");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        self.stdin.read_line(&mut line).map_err(err("the runner"))?;
        let reply: Value = serde_json::from_str(&line).map_err(err("the runner's reply"))?;
        if reply["ok"].as_bool() != Some(true) {
            return Err(format!(
                "the runner refused {}: {}",
                ev["event"], reply["error"]
            ));
        }
        Ok(reply)
    }

    fn echo(&mut self, st: &Value) -> Res<()> {
        let label = s(st, "label").to_owned();
        let (count, size) = (n(st, "count", 1) as usize, n(st, "size", 0) as usize);
        let until = ms(st, 20000);
        self.pump(until, &format!("channel {label} to open"), |p| {
            Ok(p.channels.get(&label).is_some_and(|id| p.open.contains(id)))
        })?;
        let id = self.channels[&label];
        let base = self.echo.get(&label).map_or(0, |e| e.0.len());
        for i in 0..count {
            let (binary, data) = if size > 0 {
                let mut b = vec![(i % 251) as u8; size];
                b[..4].copy_from_slice(&(i as u32).to_be_bytes());
                (true, b)
            } else {
                (false, format!("msg-{i}").into_bytes())
            };
            // A write the send buffer cannot take now is retried as it drains.
            let start = Instant::now();
            loop {
                let ok = match self.rtc.channel(id) {
                    Some(mut ch) => ch.write(binary, &data).map_err(err("channel write"))?,
                    None => return Err(format!("channel {label} is gone")),
                };
                self.drain()?;
                if ok {
                    break;
                }
                if start.elapsed() > Duration::from_secs(10) {
                    return Err(format!(
                        "channel {label} did not take message {i} ({} bytes)",
                        data.len()
                    ));
                }
                if !self.turn()? {
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
        self.pump(until, &format!("{count} echoed messages on {label}"), |p| {
            Ok(p.echo.get(&label).map_or(0, |e| e.0.len()) >= base + count)
        })
    }

    fn step(&mut self, index: usize, st: &Value) -> Res<Value> {
        let mut extra = json!({});
        match s(st, "op") {
            "dc" => {
                let label = s(st, "label").to_owned();
                let reliability = if !st["maxRetransmits"].is_null() {
                    Reliability::MaxRetransmits {
                        retransmits: n(st, "maxRetransmits", 0) as u16,
                    }
                } else if !st["maxPacketLifeTime"].is_null() {
                    Reliability::MaxPacketLifetime {
                        lifetime: n(st, "maxPacketLifeTime", 0) as u16,
                    }
                } else {
                    Reliability::Reliable
                };
                let cfg = ChannelConfig {
                    label: label.clone(),
                    ordered: st["ordered"].as_bool().unwrap_or(true),
                    reliability,
                    negotiated: st["negotiated"].as_u64().map(|v| v as u16),
                    protocol: String::new(),
                };
                self.local_labels.insert(label.clone());
                if self.sctp_negotiated {
                    let id = self.rtc.direct_api().create_data_channel(cfg);
                    self.drain()?;
                    self.channels.insert(label.clone(), id);
                    self.labels.insert(id, label);
                } else {
                    self.queue.push(Change::Channel(label, cfg));
                }
            }
            "track" => self.add_track(st, index)?,
            "transceiver" => {
                let kind = if s(st, "kind") == "audio" {
                    MediaKind::Audio
                } else {
                    MediaKind::Video
                };
                let dir = match s(st, "direction") {
                    "sendonly" => Direction::SendOnly,
                    "sendrecv" => Direction::SendRecv,
                    "inactive" => Direction::Inactive,
                    _ => Direction::RecvOnly,
                };
                self.queue.push(Change::Recv(kind, dir));
            }
            "remove-track" => {
                let kind = if s(st, "kind") == "audio" {
                    MediaKind::Audio
                } else {
                    MediaKind::Video
                };
                let t = self
                    .tracks
                    .iter_mut()
                    .find(|t| t.kind == kind && !t.stopped)
                    .ok_or("no track of that kind to remove")?;
                t.stopped = true;
                if let Some(mid) = t.mid {
                    self.queue.push(Change::Direction(mid, Direction::RecvOnly));
                }
            }
            "offer" => {
                if st["iceRestart"].as_bool().unwrap_or(false) {
                    self.queue.push(Change::Restart);
                }
                extra = self.offer(st)?;
            }
            "request-offer" => {
                let mut m = json!({"type": "request-offer"});
                if let Some(t) = st["tracks"].as_array().filter(|t| !t.is_empty()) {
                    m["tracks"] = json!(t);
                }
                if st["iceRestart"].as_bool().unwrap_or(false) {
                    m["ice_restart"] = json!(true);
                }
                self.munge_remote = s(st, "munge").to_owned();
                let before = self.answers_sent;
                self.send(m)?;
                self.pump(ms(st, 15000), "Rust's offer, answered", |p| {
                    Ok(p.answers_sent > before)
                })?;
            }
            "connected" => self.pump(ms(st, 30000), "the connection", |p| Ok(p.connected))?,
            "echo" => self.echo(st)?,
            "await-channel" => {
                let label = s(st, "label").to_owned();
                self.pump(
                    ms(st, 15000),
                    &format!("channel {label} and its first message"),
                    |p| Ok(p.remote_channels.contains_key(&label)),
                )?;
            }
            "await-rtp" => {
                let kind = s(st, "kind").to_owned();
                let have = self.rtp.get(&kind).map_or(0, |c| c.0);
                let want = if st["more"].is_null() {
                    n(st, "packets", 0)
                } else {
                    have + n(st, "more", 0)
                };
                self.pump(
                    ms(st, 20000),
                    &format!("{want} {kind} packets from Rust"),
                    |p| Ok(p.rtp.get(&kind).map_or(0, |c| c.0) >= want),
                )?;
            }
            "await-rust-rtp" => {
                let kind = s(st, "kind").to_owned();
                let want = n(st, "packets", 0);
                let until = ms(st, 20000);
                while self.rust_rtp(&kind) < want {
                    if Instant::now() > until {
                        return Err(format!(
                            "Rust has {} of {want} {kind} packets",
                            self.rust_rtp(&kind)
                        ));
                    }
                    self.report()?;
                    self.wait(300)?;
                }
            }
            "rtcp" => {
                let mids = self.remote_video.clone();
                if mids.is_empty() {
                    return Err("no video from Rust to send feedback about".into());
                }
                // One kind at a time: str0m keeps one pending keyframe request per stream, and
                // a FIR asked for in the same turn as a PLI replaces it.
                for t in st["types"].as_array().cloned().unwrap_or_default() {
                    let (name, kind) = match t.as_str() {
                        Some("fir") => ("fir", KeyframeRequestKind::Fir),
                        _ => ("pli", KeyframeRequestKind::Pli),
                    };
                    for _ in 0..3 {
                        for mid in &mids {
                            let ok = self
                                .rtc
                                .writer(*mid)
                                .is_some_and(|mut w| w.request_keyframe(None, kind).is_ok());
                            self.drain()?;
                            if ok {
                                *self.rtcp_sent.entry(name.into()).or_default() += 1;
                            }
                        }
                        self.wait(300)?;
                    }
                }
            }
            "impair" => {
                let sdp = self
                    .descriptions
                    .iter()
                    .rev()
                    .find(|d| d[0] == "received")
                    .and_then(|d| d[2].as_str())
                    .unwrap_or_default()
                    .to_owned();
                self.control(json!({"event": "impair", "direction": s(st, "direction"), "rustPort": rust_port(&sdp)}))?;
                let r = self.wait(n(st, "ms", 10000));
                let u = self.control(json!({"event": "unimpair"}));
                r?;
                u?;
            }
            "rollback" => {
                // str0m's rollback: the pending offer is dropped, its changes are not applied
                // (SdpApi: an offer takes effect only with its answer).
                if self.make_offer()?.is_some() {
                    self.pending = None;
                    self.queue.splice(0..0, self.in_flight.drain(..));
                }
                extra = json!({"signalingState": "stable"});
            }
            "glare" => {
                self.impolite = true;
                let Some(sdp) = self.make_offer()? else {
                    return Err("nothing to offer for the glare".into());
                };
                self.send(json!({"type": "request-offer"}))?;
                let got = self.answers_got;
                self.send_description("offer", sdp)?;
                self.pump(ms(st, 20000), "the answer to our colliding offer", |p| {
                    Ok(p.answers_got > got)
                })?;
            }
            "wait" => self.wait(n(st, "ms", 1000))?,
            "report" => self.report()?,
            other => return Err(format!("unknown step {other:?}")),
        }
        Ok(extra)
    }

    fn run(&mut self) -> Res<()> {
        let steps = self.plan["steps"].as_array().cloned().unwrap_or_default();
        for (i, st) in steps.iter().enumerate() {
            let start = Instant::now();
            let r = self.step(i, st);
            let mut entry = json!({"op": s(st, "op"), "ok": r.is_ok(), "ms": start.elapsed().as_millis() as u64});
            match &r {
                Ok(extra) => {
                    if let Some(o) = extra.as_object() {
                        for (k, v) in o {
                            entry[k] = v.clone();
                        }
                    }
                }
                Err(e) => entry["error"] = json!(e),
            }
            self.steps.push(entry);
            if let Err(e) = r {
                return Err(format!("step {i} ({}): {e}", s(st, "op")));
            }
        }
        Ok(())
    }

    fn result(&mut self, r: Res<()>) -> Value {
        let version = self.rtc.direct_api().dtls_protocol_version();
        let coverage: Vec<Value> = self
            .coverage
            .values()
            .map(|c| {
                let end = c.max.saturating_sub(50);
                let span = if c.seen.is_empty() || end < c.min {
                    0
                } else {
                    end - c.min + 1
                };
                let missing = if span == 0 {
                    0
                } else {
                    (c.min..=end).filter(|s| !c.seen.contains(s)).count()
                };
                json!({"kind": c.kind, "span": span, "missing": missing, "received": c.seen.len()})
            })
            .collect();
        let answer = self
            .descriptions
            .iter()
            .rev()
            .find(|d| d[0] == "received")
            .and_then(|d| d[2].as_str())
            .unwrap_or_default()
            .to_owned();
        // str0m's stats name the selected pair every stats interval; a session shorter than
        // that has none, and then the path its last datagrams came over is the one in use.
        let selected = match (&self.selected, self.last_path) {
            (Value::Null, Some((proto, from))) => {
                let proto = if proto == Protocol::Udp { "udp" } else { "tcp" };
                json!({
                    "local": {"candidateType": "host", "protocol": proto, "relayProtocol": null},
                    "remote": {"candidateType": null, "protocol": proto, "address": from.ip().to_string(), "port": from.port()},
                })
            }
            (s, _) => s.clone(),
        };
        json!({
            "ok": r.is_ok(),
            "error": r.err(),
            "na": null,
            "version": "str0m 0.26.0 (dimpl 0.9.0, rust-crypto)",
            "connectionState": if self.connected { "connected".to_owned() } else { self.ice_state.clone() },
            "steps": self.steps,
            "datachannels": self.echo.iter().map(|(k, (g, z))| (k.clone(), json!({"got": g, "sizes": z}))).collect::<serde_json::Map<_, _>>(),
            "remoteChannels": self.remote_channels,
            "rtp": self.rtp.iter().map(|(k, (p, b, c))| (k.clone(), json!({"packets": p, "bytes": b, "codec": c}))).collect::<serde_json::Map<_, _>>(),
            "rtpSent": self.rtp_sent.iter().map(|(k, (p, b))| (k.clone(), json!({"packets": p, "bytes": b}))).collect::<serde_json::Map<_, _>>(),
            "coverage": coverage,
            "rtcp": self.rtcp,
            "rtcpSent": self.rtcp_sent,
            "twccSent": answer.contains("transport-wide-cc"),
            "selectedPair": selected,
            "dtls": version.map(|v| json!({"version": format!("{:04X}", v.as_u16()), "cipher": null, "srtpProfile": null, "role": null})),
            "sctp": {"maxMessageSize": 262144},
            "localCandidates": self.candidate_lines,
            "trickled": self.trickled,
            "descriptions": self.descriptions,
            "remoteOffers": self.remote_offers,
            "ignoredOffers": self.ignored_offers,
            "rust": self.rust,
            "rustErrors": self.rust_errors,
        })
    }
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: str0m-peer <plan.json>");
    let plan: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("plan")).expect("plan json");
    let out = match Peer::new(plan) {
        Ok(mut p) => {
            let r = p.run();
            let out = p.result(r);
            // A closing handshake, so Rust's side sees the session end cleanly.
            let _ = p.ws.close(None);
            for _ in 0..50 {
                if p.ws.flush().is_ok() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            out
        }
        Err(e) => {
            json!({"ok": false, "error": e, "na": null, "steps": [], "descriptions": [], "localCandidates": [], "rustErrors": []})
        }
    };
    println!("{}", json!({ "result": out }));
}
