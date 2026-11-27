//! Behaviour profiles (`docs/behaviour-profiles.md`) end to end:
//!
//! - under `Chrome`, the engine's offer and answer compared structurally with the Chromium
//!   descriptions of `tests/fixtures/browser-sdp/` (recorded by the browser matrix): the
//!   attributes, header extensions, feedback types, codecs and candidate lines Chromium writes
//!   are written by the engine too, but for the documented residual differences; what the
//!   engine writes beyond them is its superset (capabilities Chrome lacks, which the profile
//!   keeps), listed here;
//! - two `rtci` peer connections under every pair of profiles connect and carry data and media
//!   both ways, with a renegotiation;
//! - what `StrictRfc` refuses that `Chrome` takes.
//!
//! Every peer names its profile explicitly, so the file passes with the `chrome-defaults`
//! feature on or off.

use anyhow::{Result, bail};
use bytes::{Bytes, BytesMut};
use rtci::interceptor::Registry;
use rtci::peer_connection::configuration::BehaviourProfile;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp::header::Header;
use rtci::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
use rtci::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const CONNECT_WITHIN: Duration = Duration::from_secs(15);

fn peer_connection(profile: BehaviourProfile) -> Result<RTCPeerConnection> {
    let mut media_engine = MediaEngine::for_profile(profile);
    media_engine.register_default_codecs()?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_behaviour_profile(profile)
                .build(),
        )
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(Instant::now())?)
}

fn host_candidate(addr: SocketAddr) -> Result<RTCIceCandidateInit> {
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

// ---------------------------------------------------------------------------------------------
// Structural comparison with the Chromium descriptions
// ---------------------------------------------------------------------------------------------

/// One m= section (or the session part, kind `session`) of a description.
#[derive(Debug, Default)]
struct Section {
    kind: String,
    /// Attribute names in the order of their first line.
    keys: Vec<String>,
    /// `a=extmap` URIs.
    extensions: BTreeSet<String>,
    /// Encoding names of `a=rtpmap`, in order.
    codecs: Vec<String>,
    /// `a=rtcp-fb` types (with their parameter) of the first codec.
    first_codec_feedback: BTreeSet<String>,
    /// The `a=candidate` lines.
    candidates: Vec<String>,
}

fn sections(sdp: &str) -> Vec<Section> {
    let mut out = vec![Section {
        kind: "session".to_owned(),
        ..Default::default()
    }];
    let mut first_payload_type: Option<String> = None;
    for line in sdp.lines().map(str::trim_end) {
        if let Some(media) = line.strip_prefix("m=") {
            let mut fields = media.split_whitespace();
            out.push(Section {
                kind: fields.next().unwrap_or_default().to_owned(),
                ..Default::default()
            });
            first_payload_type = fields.nth(2).map(str::to_owned);
            continue;
        }
        let Some(attribute) = line.strip_prefix("a=") else {
            continue;
        };
        let (key, value) = attribute.split_once(':').unwrap_or((attribute, ""));
        let section = out.last_mut().expect("the session part");
        if !section.keys.iter().any(|k| k == key) {
            section.keys.push(key.to_owned());
        }
        match key {
            "extmap" => {
                if let Some(uri) = value.split_whitespace().nth(1) {
                    section.extensions.insert(uri.to_owned());
                }
            }
            "rtpmap" => {
                if let Some(name) = value.split_whitespace().nth(1) {
                    let name = name
                        .split('/')
                        .next()
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    section.codecs.push(name);
                }
            }
            "rtcp-fb" => {
                let mut fields = value.splitn(2, ' ');
                if fields.next() == first_payload_type.as_deref() {
                    section
                        .first_codec_feedback
                        .insert(fields.next().unwrap_or_default().trim().to_owned());
                }
            }
            "candidate" => section.candidates.push(value.to_owned()),
            _ => {}
        }
    }
    out
}

fn fixture(name: &str) -> Result<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/browser-sdp")
        .join(name);
    Ok(std::fs::read_to_string(path)?)
}

/// Attributes that depend on the scenario, not on the writer: directions, the sender's
/// identity, candidates (compared on their own), and the DTLS role an offer or answer takes.
const SCENARIO_KEYS: &[&str] = &[
    "sendrecv",
    "sendonly",
    "recvonly",
    "inactive",
    "msid",
    "ssrc",
    "ssrc-group",
    "candidate",
    "end-of-candidates",
    "rid",
    "simulcast",
];

/// What Chromium writes and the engine does not, by section kind: the residual differences of
/// the `Chrome` profile. Each is "not expressible" in `docs/behaviour-profiles.md` or an
/// attribute without effect.
fn residual_missing(kind: &str, key: &str) -> bool {
    matches!(
        (kind, key),
        // Chromium's own `a=msid-semantic: WMS` line (draft-ietf-mmusic-msid's, removed from
        // RFC 8830): the engine writes the RFC 8830 form or none.
        ("session", "msid-semantic")
        // `a=rtcp:9 IN IP4 0.0.0.0`: the RFC 5761 port of a section that muxes RTCP, which
        // Chromium writes for old peers; the engine writes `a=rtcp-mux` alone.
        | (_, "rtcp")
    )
}

/// Header extensions Chromium offers that the engine does not implement (`not expressible`).
const UNIMPLEMENTED_EXTENSIONS: &[&str] = &[
    "urn:ietf:params:rtp-hdrext:toffset",
    "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay",
    "http://www.webrtc.org/experiments/rtp-hdrext/video-content-type",
    "http://www.webrtc.org/experiments/rtp-hdrext/video-timing",
    "http://www.webrtc.org/experiments/rtp-hdrext/color-space",
];

/// Audio formats Chromium offers that the default codecs do not have: RED for Opus (RFC 2198),
/// which an application registers.
const UNREGISTERED_CODECS: &[&str] = &["red"];

/// Compares the sections of `engine` with those of the Chromium description `chromium`, kind
/// by kind: everything Chromium writes must be in the engine's section of that kind, but for
/// the residual differences. Returns what the engine writes beyond Chromium (its superset).
fn compare(engine: &str, chromium: &str, what: &str) -> Result<BTreeMap<String, Vec<String>>> {
    let engine_sections = sections(engine);
    let mut extras = BTreeMap::new();
    let mut problems = vec![];
    for theirs in sections(chromium) {
        let Some(ours) = engine_sections.iter().find(|s| s.kind == theirs.kind) else {
            problems.push(format!(
                "no {} section in the engine's description",
                theirs.kind
            ));
            continue;
        };
        for key in &theirs.keys {
            if SCENARIO_KEYS.contains(&key.as_str()) || residual_missing(&theirs.kind, key) {
                continue;
            }
            // Under `Chrome` every attribute is where Chromium writes it: `a=ice-options` too
            // is in each section (`ice.options-in-media-sections`), not at session level.
            if !ours.keys.contains(key) {
                problems.push(format!("{}: a={key} missing", theirs.kind));
            }
        }
        for uri in &theirs.extensions {
            if !ours.extensions.contains(uri) && !UNIMPLEMENTED_EXTENSIONS.contains(&uri.as_str()) {
                problems.push(format!("{}: extension {uri} missing", theirs.kind));
            }
        }
        for codec in &theirs.codecs {
            if !ours.codecs.contains(codec) && !UNREGISTERED_CODECS.contains(&codec.as_str()) {
                problems.push(format!("{}: codec {codec} missing", theirs.kind));
            }
        }
        // The preferred format comes first in both.
        if let (Some(first), Some(ours_first)) = (theirs.codecs.first(), ours.codecs.first())
            && first != ours_first
            && ours.codecs.contains(first)
        {
            problems.push(format!(
                "{}: the engine prefers {ours_first}, Chromium {first}",
                theirs.kind
            ));
        }
        // The feedback of the preferred format, when it is the same format.
        if theirs.codecs.first() == ours.codecs.first() {
            for feedback in &theirs.first_codec_feedback {
                if !ours.first_codec_feedback.contains(feedback) {
                    problems.push(format!("{}: a=rtcp-fb {feedback} missing", theirs.kind));
                }
            }
        }
        let mut superset: Vec<String> = ours
            .keys
            .iter()
            .filter(|k| !theirs.keys.contains(k) && !SCENARIO_KEYS.contains(&k.as_str()))
            .map(|k| format!("a={k}"))
            .collect();
        superset.extend(
            ours.extensions
                .difference(&theirs.extensions)
                .map(|uri| format!("extmap {uri}")),
        );
        extras.insert(theirs.kind.clone(), superset);
    }
    if !problems.is_empty() {
        bail!("{what}: {problems:#?}\nengine:\n{engine}");
    }
    Ok(extras)
}

/// What the engine writes beyond Chromium is its superset: capabilities Chrome lacks, which
/// the `Chrome` profile keeps (section 2 of `docs/behaviour-profiles.md`). Anything else is a
/// difference nobody has looked at.
fn documented_superset(item: &str) -> bool {
    const KEYS: &[&str] = &[
        // RFC 8842; Chromium ignores it.
        "a=tls-id",
        // RFC 8843 / RFC 8853: rid and simulcast receive support.
        "a=rid",
        "a=simulcast",
        // RFC 6679 / RFC 8888 ECN negotiation, when ECN is on.
        "a=ecn-capable-rtp",
        // RFC 3611 extended reports.
        "a=rtcp-xr",
        // RFC 8841 data channel attributes the engine writes on its own sections.
        "a=max-message-size",
        "a=sctp-port",
        // RFC 9605 / Cryptex negotiation.
        "a=cryptex",
        // RFC 3264 / RFC 5576 forms of the engine's own sections.
        "a=fmtp",
        "a=rtcp-fb",
        "a=rtpmap",
        "a=extmap",
        "a=extmap-allow-mixed",
        "a=rtcp-rsize",
        "a=rtcp-mux",
        "a=rtcp-mux-only",
        "a=mid",
        "a=group",
    ];
    if KEYS.contains(&item) {
        return true;
    }
    let Some(uri) = item.strip_prefix("extmap ") else {
        return false;
    };
    [
        // RFC 8285 extensions the engine implements and Chromium does not offer here.
        "urn:ietf:params:rtp-hdrext:ntp-64",
        "urn:ietf:params:rtp-hdrext:csrc-audio-level",
        "urn:ietf:params:rtp-hdrext:ssrc-audio-level",
        "urn:3gpp:video-orientation",
        "https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension",
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
        "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
        "urn:ietf:params:rtp-hdrext:sdes:mid",
        "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
        "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
        "http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time",
        "urn:ietf:params:rtp-hdrext:encrypt",
    ]
    .iter()
    .any(|known| uri == *known || uri.starts_with("urn:ietf:params:rtp-hdrext:encrypt"))
}

fn check_superset(extras: &BTreeMap<String, Vec<String>>, what: &str) -> Result<()> {
    let undocumented: Vec<String> = extras
        .iter()
        .flat_map(|(kind, items)| {
            items
                .iter()
                .filter(|item| !documented_superset(item))
                .map(move |item| format!("{kind}: {item}"))
        })
        .collect();
    if !undocumented.is_empty() {
        bail!("{what}: the engine writes beyond Chromium, undocumented: {undocumented:#?}");
    }
    Ok(())
}

/// An offer of the engine under `Chrome` with audio, video and a data channel, and a host
/// candidate gathered, written as `create_offer` and the local description give it.
fn chrome_profile_offer() -> Result<String> {
    let now = Instant::now();
    let mut pc = peer_connection(BehaviourProfile::Chrome)?;
    for kind in [RtpCodecKind::Audio, RtpCodecKind::Video] {
        pc.add_transceiver_from_kind(
            kind,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendrecv,
                streams: vec![],
                send_encodings: vec![RTCRtpEncodingParameters {
                    active: true,
                    ..Default::default()
                }],
            }),
        )?;
    }
    pc.create_data_channel("data", None)?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(now, offer)?;
    pc.add_local_candidate(host_candidate("10.0.0.1:5000".parse()?)?)?;
    while pc.poll_event().is_some() {}
    Ok(pc.local_description().expect("a local description").sdp)
}

/// Under `Chrome` the engine's offer writes what Chromium's audio, video and data offers write
/// (attributes, header extensions, codecs and the preferred codec's feedback), but for the
/// residual differences, and its extras are the documented superset.
#[test]
fn the_chrome_profiles_offer_has_what_chromiums_offers_have() -> Result<()> {
    let offer = chrome_profile_offer()?;
    for name in [
        "chromium--reflect-audio-opus--1-offer.sdp",
        "chromium--reflect-video-vp8--1-offer.sdp",
        "chromium--data-channel-ordered--1-offer.sdp",
    ] {
        let extras = compare(&offer, &fixture(name)?, name)?;
        check_superset(&extras, name)?;
    }
    Ok(())
}

/// Under `Chrome` the engine's candidate lines have Chromium's form up to the type
/// (`<foundation> 1 udp <priority> <address> <port> typ host`); Chromium appends `generation`
/// and `network-cost`, which the engine cannot know and libwebrtc does not need from it
/// (`not expressible`).
#[test]
fn the_chrome_profiles_candidate_lines_have_chromiums_form() -> Result<()> {
    let offer = chrome_profile_offer()?;
    let ours: Vec<String> = sections(&offer)
        .into_iter()
        .flat_map(|s| s.candidates)
        .collect();
    let answer =
        fixture("chromium--rust-offers-media-the-browser-answers-and-decodes-it--2-answer.sdp")?;
    let theirs: Vec<String> = sections(&answer)
        .into_iter()
        .flat_map(|s| s.candidates)
        .collect();
    assert!(!ours.is_empty() && !theirs.is_empty(), "{offer}");
    let head = |line: &str| -> Vec<String> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        vec![
            fields.len().min(8).to_string(),
            fields.get(1).copied().unwrap_or_default().to_owned(),
            fields
                .get(2)
                .copied()
                .unwrap_or_default()
                .to_ascii_lowercase(),
            fields.get(6).copied().unwrap_or_default().to_owned(),
            fields.get(7).copied().unwrap_or_default().to_owned(),
        ]
    };
    for line in &ours {
        assert_eq!(
            head(line),
            head(&theirs[0]),
            "ours: {line}, Chromium's: {}",
            theirs[0]
        );
    }
    Ok(())
}

/// Under `Chrome` the engine answers a Chromium offer with what Chromium's own answer writes,
/// and its feedback and extensions follow the offer's.
#[test]
fn the_chrome_profiles_answer_has_what_chromiums_answer_has() -> Result<()> {
    let now = Instant::now();
    let chromium_answer =
        fixture("chromium--rust-offers-media-the-browser-answers-and-decodes-it--2-answer.sdp")?;
    for name in [
        "chromium--reflect-video-vp8--1-offer.sdp",
        "chromium--reflect-audio-opus--1-offer.sdp",
        "chromium--data-channel-ordered--1-offer.sdp",
    ] {
        let mut pc = peer_connection(BehaviourProfile::Chrome)?;
        pc.set_remote_description(now, RTCSessionDescription::offer(fixture(name)?)?)?;
        let answer = pc.create_answer(None)?;
        pc.set_local_description(now, answer.clone())?;
        // Compare only the kinds this offer has.
        let kinds: BTreeSet<String> = sections(&fixture(name)?)
            .into_iter()
            .map(|s| s.kind)
            .collect();
        let reference: String = {
            let mut text = String::new();
            let mut keep = true;
            for line in chromium_answer.lines() {
                if let Some(media) = line.strip_prefix("m=") {
                    keep = kinds.contains(media.split_whitespace().next().unwrap_or_default());
                }
                if keep {
                    text.push_str(line);
                    text.push('\n');
                }
            }
            text
        };
        // An answer names nothing the offer did not (RFC 3264 6.1, RFC 8285 5): Chromium's
        // answer to the engine's offer has extensions this Chromium offer lacks.
        let offered: BTreeSet<String> = sections(&fixture(name)?)
            .into_iter()
            .flat_map(|s| s.extensions)
            .collect();
        let reference: String = reference
            .lines()
            .filter(|line| {
                line.strip_prefix("a=extmap:")
                    .and_then(|v| v.split_whitespace().nth(1))
                    .is_none_or(|uri| offered.contains(uri))
            })
            .map(|line| format!("{line}\n"))
            .collect();
        let extras = compare(&answer.sdp, &reference, name)?;
        check_superset(&extras, name)?;
        for section in sections(&answer.sdp) {
            for uri in &section.extensions {
                assert!(offered.contains(uri), "{name}: answered {uri} unoffered");
            }
        }
    }
    Ok(())
}

/// The governed SDP forms of the `Chrome` profile are Chromium's: max-message-size 262144,
/// the BUNDLE attributes in every bundled section, `a=msid` with the track id, VP9 without
/// receiver limits.
#[test]
fn the_chrome_profile_writes_chromiums_governed_forms() -> Result<()> {
    let offer = chrome_profile_offer()?;
    assert!(offer.contains("a=max-message-size:262144"), "{offer}");
    let chromium = fixture("chromium--data-channel-ordered--1-offer.sdp")?;
    assert!(chromium.contains("a=max-message-size:262144"));
    for section in sections(&offer).iter().skip(1) {
        for key in ["ice-ufrag", "ice-pwd", "fingerprint", "setup"] {
            assert!(
                section.keys.iter().any(|k| k == key),
                "{key} in every section: {offer}"
            );
        }
    }
    let msid = offer
        .lines()
        .find(|l| l.starts_with("a=msid:"))
        .expect("an a=msid line");
    assert_eq!(
        msid.split_whitespace().count(),
        2,
        "{msid}: stream and track id"
    );
    for line in offer.lines().filter(|l| l.starts_with("a=fmtp:")) {
        if line.contains("profile-id=") {
            assert!(!line.contains("max-fs"), "{line}");
        }
    }
    // `a=ice-options` in every section after `a=ice-pwd`, as Chromium's, and none at session
    // level; no `a=ice-pacing` for the default Ta, as Chromium writes none.
    let session = &sections(&offer)[0];
    assert!(!session.keys.iter().any(|k| k == "ice-options"), "{offer}");
    assert!(!offer.contains("a=ice-pacing"), "{offer}");
    assert!(!chromium.contains("a=ice-pacing"));
    let mut in_section = false;
    let mut after_pwd = None;
    for line in offer.lines() {
        if line.starts_with("m=") {
            assert_ne!(
                after_pwd,
                Some(false),
                "a=ice-options after a=ice-pwd: {offer}"
            );
            in_section = true;
            after_pwd = None;
        } else if in_section && line.starts_with("a=ice-pwd:") {
            after_pwd = Some(false);
        } else if after_pwd == Some(false) {
            assert_eq!(line, "a=ice-options:trickle ice2", "{offer}");
            after_pwd = Some(true);
        }
    }
    assert_eq!(after_pwd, Some(true), "{offer}");
    Ok(())
}

/// The `Rfc` profile writes `a=ice-options` once at session level and states the default Ta;
/// the two `Chrome` forms are settings, not a change of what is negotiated: an `Rfc` peer
/// reads the `Chrome` peer's media-level options (`trickle`, `ice2`).
#[test]
fn the_rfc_profile_keeps_session_level_ice_options_and_the_stated_pacing() -> Result<()> {
    let mut rfc = peer_connection(BehaviourProfile::Rfc)?;
    rfc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let offer = rfc.create_offer(None)?;
    let session: String = offer
        .sdp
        .split("\r\nm=")
        .next()
        .unwrap_or_default()
        .to_owned();
    assert!(
        session.contains("a=ice-options:trickle ice2"),
        "{}",
        offer.sdp
    );
    assert!(session.contains("a=ice-pacing:50"), "{}", offer.sdp);
    assert_eq!(
        offer.sdp.matches("a=ice-options:").count(),
        1,
        "{}",
        offer.sdp
    );

    let now = Instant::now();
    let chrome_offer = chrome_profile_offer()?;
    let mut answerer = peer_connection(BehaviourProfile::Rfc)?;
    answerer.set_remote_description(now, RTCSessionDescription::offer(chrome_offer)?)?;
    let options = answerer.remote_ice_options();
    assert!(options.contains(&"trickle".to_owned()), "{options:?}");
    assert!(options.contains(&"ice2".to_owned()), "{options:?}");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// rtc to rtc under every pair of profiles
// ---------------------------------------------------------------------------------------------

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    connected: bool,
    states: Vec<RTCPeerConnectionState>,
    open_channels: Vec<rtci::data_channel::RTCDataChannelId>,
    data: Vec<Vec<u8>>,
    rtp: Vec<Header>,
}

struct World {
    peers: [Peer; 2],
    now: Instant,
}

impl World {
    fn new(profiles: [BehaviourProfile; 2]) -> Result<Self> {
        let peer = |profile, addr: &str| -> Result<Peer> {
            Ok(Peer {
                pc: peer_connection(profile)?,
                addr: addr.parse()?,
                connected: false,
                states: vec![],
                open_channels: vec![],
                data: vec![],
                rtp: vec![],
            })
        };
        Ok(Self {
            peers: [
                peer(profiles[0], "10.0.0.1:5000")?,
                peer(profiles[1], "10.0.0.2:5000")?,
            ],
            now: Instant::now(),
        })
    }

    fn pump(&mut self) -> Result<()> {
        loop {
            let mut in_flight = vec![];
            for peer in self.peers.iter_mut() {
                while let Some(msg) = peer.pc.poll_write() {
                    in_flight.push((
                        msg.transport.local_addr,
                        msg.transport.peer_addr,
                        msg.message,
                    ));
                }
            }
            if in_flight.is_empty() {
                break;
            }
            for (from, to, data) in in_flight {
                let Some(peer) = self.peers.iter_mut().find(|p| p.addr == to) else {
                    continue;
                };
                let _ = peer.pc.handle_read(TaggedBytesMut {
                    now: self.now,
                    transport: TransportContext {
                        local_addr: to,
                        peer_addr: from,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: data,
                });
            }
        }
        for peer in self.peers.iter_mut() {
            while let Some(event) = peer.pc.poll_event() {
                match event {
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                        if state == RTCPeerConnectionState::Failed {
                            bail!("a peer's connection failed: {:?}", peer.states);
                        }
                        peer.connected = state == RTCPeerConnectionState::Connected;
                        peer.states.push(state);
                    }
                    RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                        peer.open_channels.push(id);
                    }
                    _ => {}
                }
            }
            while let Some(message) = peer.pc.poll_read() {
                match message.message {
                    RTCMessage::RtpPacket(_, packet) => peer.rtp.push(packet.header),
                    RTCMessage::DataChannelMessage(_, message) => {
                        peer.data.push(message.data.to_vec())
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn run_for(&mut self, duration: Duration) -> Result<()> {
        let until = self.now + duration;
        while self.now < until {
            let mut next = until;
            for peer in self.peers.iter_mut() {
                if let Some(deadline) = peer.pc.poll_timeout() {
                    next = next.min(deadline);
                }
            }
            self.now = next.max(self.now + Duration::from_millis(1)).min(until);
            for peer in self.peers.iter_mut() {
                peer.pc.handle_timeout(self.now)?;
            }
            self.pump()?;
        }
        Ok(())
    }

    fn run_until(&mut self, what: &str, done: impl Fn(&[Peer; 2]) -> bool) -> Result<()> {
        let start = self.now;
        while !done(&self.peers) {
            if self.now.duration_since(start) >= CONNECT_WITHIN {
                bail!(
                    "{what}: not within {CONNECT_WITHIN:?}: {:?} / {:?}",
                    self.peers[0].states,
                    self.peers[1].states
                );
            }
            self.run_for(Duration::from_millis(10))?;
        }
        Ok(())
    }

    /// `offerer` adds a sending audio and video transceiver (and, the first time, a data
    /// channel) and negotiates; the other side answers.
    fn negotiate(&mut self, offerer: usize, data: bool) -> Result<Vec<RTCRtpSenderId>> {
        let answerer = 1 - offerer;
        let mut senders = vec![];
        for kind in [RtpCodecKind::Audio, RtpCodecKind::Video] {
            let transceiver = self.peers[offerer].pc.add_transceiver_from_kind(
                kind,
                Some(RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Sendonly,
                    streams: vec![],
                    send_encodings: vec![RTCRtpEncodingParameters {
                        active: true,
                        ..Default::default()
                    }],
                }),
            )?;
            senders.push(
                self.peers[offerer]
                    .pc
                    .rtp_transceiver(transceiver)
                    .and_then(|t| t.sender())
                    .expect("a sendonly transceiver has a sender"),
            );
        }
        if data {
            self.peers[offerer].pc.create_data_channel("data", None)?;
        }
        let now = self.now;
        let offer = self.peers[offerer].pc.create_offer(None)?;
        self.peers[offerer]
            .pc
            .set_local_description(now, offer.clone())?;
        self.peers[answerer].pc.set_remote_description(now, offer)?;
        let answer = self.peers[answerer].pc.create_answer(None)?;
        self.peers[answerer]
            .pc
            .set_local_description(now, answer.clone())?;
        self.peers[offerer].pc.set_remote_description(now, answer)?;
        Ok(senders)
    }

    fn exchange_candidates(&mut self) -> Result<()> {
        for i in 0..2 {
            let candidate = host_candidate(self.peers[i].addr)?;
            self.peers[i].pc.add_local_candidate(candidate.clone())?;
            self.peers[1 - i].pc.add_remote_candidate(candidate)?;
        }
        Ok(())
    }

    fn send_rtp(&mut self, from: usize, sender: RTCRtpSenderId, seq: u16) -> Result<()> {
        let now = self.now;
        let mut rtp_sender = self.peers[from].pc.rtp_sender(sender).expect("sender");
        let parameters = rtp_sender.get_parameters();
        let header = Header {
            version: 2,
            payload_type: parameters.rtp_parameters.codecs[0].payload_type,
            sequence_number: seq,
            timestamp: u32::from(seq) * 960,
            ssrc: parameters.encodings[0]
                .rtp_coding_parameters
                .ssrc
                .expect("an SSRC"),
            marker: true,
            ..Default::default()
        };
        rtp_sender.write_rtp(
            now,
            rtci::rtp::Packet {
                header,
                payload: Bytes::from(vec![0x10u8; 100]),
            },
        )?;
        Ok(())
    }

    fn send_data(&mut self, from: usize, text: &str) -> Result<()> {
        let now = self.now;
        let id = *self.peers[from]
            .open_channels
            .first()
            .expect("an open channel");
        self.peers[from]
            .pc
            .data_channel(id)
            .expect("the channel")
            .send(now, BytesMut::from(text.as_bytes()))?;
        Ok(())
    }

    /// Sends ten packets on each sender of `from` and waits until the other side has read
    /// RTP of every SSRC.
    fn media(&mut self, from: usize, senders: &[RTCRtpSenderId]) -> Result<()> {
        let mut ssrcs = BTreeSet::new();
        for sender in senders {
            ssrcs.insert(
                self.peers[from]
                    .pc
                    .rtp_sender(*sender)
                    .expect("sender")
                    .get_parameters()
                    .encodings[0]
                    .rtp_coding_parameters
                    .ssrc
                    .expect("an SSRC"),
            );
        }
        for seq in 0..10u16 {
            for sender in senders {
                self.send_rtp(from, *sender, 1000 + seq)?;
            }
            self.run_for(Duration::from_millis(20))?;
        }
        let to = 1 - from;
        self.run_until("media", |peers| {
            ssrcs
                .iter()
                .all(|ssrc| peers[to].rtp.iter().any(|h| h.ssrc == *ssrc))
        })
    }
}

/// Two `rtci` peers under `profiles` connect, open a data channel and send on it both ways,
/// send audio and video one way, renegotiate from the other side and send media back.
fn data_and_media_both_ways(profiles: [BehaviourProfile; 2]) -> Result<()> {
    let what = format!("{} -> {}", profiles[0], profiles[1]);
    let mut world = World::new(profiles)?;
    let forward = world.negotiate(0, true)?;
    world.exchange_candidates()?;
    world.run_until(&format!("{what}: connected"), |peers| {
        peers.iter().all(|p| p.connected)
    })?;
    world.run_until(&format!("{what}: channel open"), |peers| {
        peers.iter().all(|p| !p.open_channels.is_empty())
    })?;
    world.send_data(0, "ping")?;
    world.send_data(1, "pong")?;
    world.run_until(&format!("{what}: data"), |peers| {
        peers[1].data.iter().any(|d| d == b"ping") && peers[0].data.iter().any(|d| d == b"pong")
    })?;
    world.media(0, &forward)?;
    // The other side re-offers with media of its own.
    let back = world.negotiate(1, false)?;
    world.run_for(Duration::from_millis(200))?;
    world.media(1, &back)?;
    assert!(world.peers.iter().all(|p| p.connected), "{what}");
    Ok(())
}

#[test]
fn rfc_and_chrome_profiles_carry_data_and_media_both_ways() -> Result<()> {
    data_and_media_both_ways([BehaviourProfile::Rfc, BehaviourProfile::Chrome])?;
    data_and_media_both_ways([BehaviourProfile::Chrome, BehaviourProfile::Rfc])
}

#[test]
fn chrome_and_chrome_profiles_carry_data_and_media_both_ways() -> Result<()> {
    data_and_media_both_ways([BehaviourProfile::Chrome, BehaviourProfile::Chrome])
}

#[test]
fn strict_rfc_and_strict_rfc_profiles_carry_data_and_media_both_ways() -> Result<()> {
    data_and_media_both_ways([BehaviourProfile::StrictRfc, BehaviourProfile::StrictRfc])
}

/// Between two `rtci` engines `StrictRfc` and `Chrome` interoperate: the engine reads either
/// BUNDLE form, takes a new `a=tls-id`, and has no lenient form of its own to send. The
/// refusals of `StrictRfc` are of what browsers write (below).
#[test]
fn strict_rfc_and_chrome_profiles_carry_data_and_media_both_ways() -> Result<()> {
    data_and_media_both_ways([BehaviourProfile::StrictRfc, BehaviourProfile::Chrome])?;
    data_and_media_both_ways([BehaviourProfile::Chrome, BehaviourProfile::StrictRfc])
}

// ---------------------------------------------------------------------------------------------
// What StrictRfc refuses that Chrome takes
// ---------------------------------------------------------------------------------------------

/// A fingerprint in lower-case hex (RFC 8122 section 5: upper case), as some writers send:
/// `Chrome` takes it, `StrictRfc` (and `Rfc`) refuse the description.
#[test]
fn strict_rfc_refuses_a_lowercase_fingerprint_that_chrome_takes() -> Result<()> {
    let now = Instant::now();
    let offer = fixture("chromium--data-channel-ordered--1-offer.sdp")?;
    let lowercase: String = offer
        .lines()
        .map(|line| match line.strip_prefix("a=fingerprint:sha-256 ") {
            Some(hex) => format!("a=fingerprint:sha-256 {}\r\n", hex.to_ascii_lowercase()),
            None => format!("{line}\n"),
        })
        .collect();
    let mut chrome = peer_connection(BehaviourProfile::Chrome)?;
    chrome.set_remote_description(now, RTCSessionDescription::offer(lowercase.clone())?)?;
    for profile in [BehaviourProfile::StrictRfc, BehaviourProfile::Rfc] {
        let mut pc = peer_connection(profile)?;
        assert!(
            pc.set_remote_description(now, RTCSessionDescription::offer(lowercase.clone())?)
                .is_err(),
            "{profile} takes a lower-case fingerprint"
        );
    }
    Ok(())
}

/// A rollback with SDP in it (RFC 9429 4.1.10: its contents "MUST be empty"; W3C: unused):
/// `Chrome` rolls back, `StrictRfc` refuses it and keeps the remote offer.
#[test]
fn strict_rfc_refuses_a_rollback_with_contents_that_chrome_ignores() -> Result<()> {
    let now = Instant::now();
    let offer = fixture("chromium--data-channel-ordered--1-offer.sdp")?;
    let mut chrome = peer_connection(BehaviourProfile::Chrome)?;
    chrome.set_remote_description(now, RTCSessionDescription::offer(offer.clone())?)?;
    chrome.set_remote_description(now, RTCSessionDescription::rollback(Some(offer.clone()))?)?;
    let mut strict = peer_connection(BehaviourProfile::StrictRfc)?;
    strict.set_remote_description(now, RTCSessionDescription::offer(offer.clone())?)?;
    assert!(
        strict
            .set_remote_description(now, RTCSessionDescription::rollback(Some(offer))?)
            .is_err()
    );
    Ok(())
}

/// `StrictRfc` answers a Chromium offer with the BUNDLE attributes in the tagged section only
/// (RFC 9143 7.1.3): the form Chromium refuses ("rtcp-mux must be enabled when BUNDLE is
/// enabled", browser matrix 2026-11-22), so a `StrictRfc` peer does not interoperate with a
/// browser. `Chrome` repeats them, as Chromium does.
#[test]
fn strict_rfc_answers_chromium_in_the_form_browsers_refuse() -> Result<()> {
    let now = Instant::now();
    let offer =
        fixture("chromium--rust-offers-media-the-browser-answers-and-decodes-it--2-answer.sdp")?
            // Chromium's answer to a Rust offer, turned around: an offer with three bundled
            // sections, the first tagged.
            .replace("a=setup:passive", "a=setup:actpass")
            .replace("a=recvonly", "a=sendrecv");
    for (profile, repeated) in [
        (BehaviourProfile::StrictRfc, false),
        (BehaviourProfile::Chrome, true),
    ] {
        let mut pc = peer_connection(profile)?;
        pc.set_remote_description(now, RTCSessionDescription::offer(offer.clone())?)?;
        let answer = pc.create_answer(None)?;
        let bundled = sections(&answer.sdp);
        let later = &bundled[2];
        assert_eq!(
            later.keys.iter().any(|k| k == "rtcp-mux"),
            repeated,
            "{profile}: {}",
            answer.sdp
        );
    }
    Ok(())
}

/// `rtp.audio-level-encryption`: RFC 8834 sections 5.2.2 and 5.2.3 make RFC 6904 encryption
/// of the audio level extensions RECOMMENDED, so `Rfc` offers them best-effort (clear and
/// `urn:ietf:params:rtp-hdrext:encrypt`, RFC 6904 section 4.1); Chromium offers them in the
/// clear unless the application asks (libwebrtc pc/media_session.cc, `preferred_encrypt`),
/// and so does `Chrome`.
#[test]
fn audio_levels_are_offered_encrypted_under_rfc_and_in_the_clear_under_chrome() -> Result<()> {
    for (profile, encrypted) in [
        (BehaviourProfile::Rfc, true),
        (BehaviourProfile::StrictRfc, true),
        (BehaviourProfile::Chrome, false),
    ] {
        let mut pc = peer_connection(profile)?;
        pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
        let offer = pc.create_offer(None)?.sdp;
        for uri in [
            "urn:ietf:params:rtp-hdrext:ssrc-audio-level",
            "urn:ietf:params:rtp-hdrext:csrc-audio-level",
        ] {
            let clear = offer.lines().any(|l| {
                l.starts_with("a=extmap:")
                    && l.ends_with(&format!(" {uri}"))
                    && !l.contains("encrypt")
            });
            let encrypt = offer.lines().any(|l| {
                l.starts_with("a=extmap:")
                    && l.contains(&format!("urn:ietf:params:rtp-hdrext:encrypt {uri}"))
            });
            if !clear || encrypt != encrypted {
                bail!(
                    "{profile:?}: {uri} clear {clear}, encrypted {encrypt} (want {encrypted}):\n{offer}"
                );
            }
        }
    }
    Ok(())
}
