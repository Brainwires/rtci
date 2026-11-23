//! The JSON shapes of the C ABI: what goes in (configuration, settings, inits) and what comes
//! out (events, stream commands, statistics, object info). Names follow the W3C dictionaries
//! (camelCase); unknown members are refused so that a binding learns of a typo or of a member
//! this version does not have, instead of having it ignored.

use crate::{FfiError, FfiResult};
use rtc::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtc::interceptor::Registry;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::{SettingEngine, SettingEngineBuilder};
use rtc::peer_connection::configuration::{
    RTCAnswerOptions, RTCBundlePolicy, RTCConfiguration, RTCConfigurationBuilder, RTCIceServer,
    RTCIceTransportPolicy, RTCOfferOptions, RTCRtcpMuxPolicy,
};
use rtc::peer_connection::event::{
    RTCDataChannelEvent, RTCPeerConnectionEvent, RTCTrackEvent, RTCTransportEventKind,
};
use rtc::peer_connection::transport::{RTCDtlsRole, RTCIceCandidateType};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc::shared::stream::{
    DnsRecord, ListenerId, RecordKind, StreamCommand, StreamEvent, StreamId,
};
use rtc::statistics::report::{RTCStatsReport, RTCStatsReportEntry};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::net::SocketAddr;
use std::time::Duration;

/// Parses an optional JSON argument; null or empty is the type's default.
pub(crate) fn parse<T: for<'de> Deserialize<'de> + Default>(text: Option<&str>) -> FfiResult<T> {
    match text.map(str::trim) {
        None | Some("") | Some("null") => Ok(T::default()),
        Some(text) => Ok(serde_json::from_str(text)?),
    }
}

/// One URL or a list of them (W3C `RTCIceServer.urls`).
#[derive(Deserialize)]
#[serde(untagged)]
enum Urls {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IceServerJson {
    urls: Urls,
    #[serde(default)]
    username: String,
    #[serde(default)]
    credential: String,
}

/// W3C `RTCConfiguration` (webrtc-pc 4.2.1), less `certificates` and `peerIdentity`.
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConfigurationJson {
    #[serde(default)]
    ice_servers: Vec<IceServerJson>,
    ice_transport_policy: Option<RTCIceTransportPolicy>,
    bundle_policy: Option<RTCBundlePolicy>,
    rtcp_mux_policy: Option<RTCRtcpMuxPolicy>,
    ice_candidate_pool_size: Option<u8>,
}

impl ConfigurationJson {
    pub(crate) fn build(self) -> RTCConfiguration {
        let servers = self
            .ice_servers
            .into_iter()
            .map(|s| RTCIceServer {
                urls: match s.urls {
                    Urls::One(url) => vec![url],
                    Urls::Many(urls) => urls,
                },
                username: s.username,
                credential: s.credential,
            })
            .collect();
        let mut builder = RTCConfigurationBuilder::new().with_ice_servers(servers);
        if let Some(policy) = self.ice_transport_policy {
            builder = builder.with_ice_transport_policy(policy);
        }
        if let Some(policy) = self.bundle_policy {
            builder = builder.with_bundle_policy(policy);
        }
        if let Some(policy) = self.rtcp_mux_policy {
            builder = builder.with_rtcp_mux_policy(policy);
        }
        if let Some(size) = self.ice_candidate_pool_size {
            builder = builder.with_ice_candidate_pool_size(size);
        }
        builder.build()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IceCredentialsJson {
    username_fragment: String,
    password: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IceTimeoutsJson {
    disconnected_ms: Option<u64>,
    failed_ms: Option<u64>,
    keep_alive_ms: Option<u64>,
}

/// Which interceptors a peer connection gets.
#[derive(Default, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Interceptors {
    /// The default set: RTCP reports, NACK, TWCC, congestion control (as browsers).
    #[default]
    Default,
    /// Only what the engine always installs: the RTCP session and key-frame requests.
    Minimal,
}

/// The engine settings that are not W3C configuration (`SettingEngineBuilder`), the ones a
/// binding needs: ICE-lite, 1:1 NAT addresses, the answering DTLS role, the engine's own TCP
/// candidates, fixed ICE credentials, ICE timeouts, and the interceptor set.
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SettingsJson {
    pub(crate) ice_lite: Option<bool>,
    #[serde(rename = "nat1to1Ips")]
    pub(crate) nat_1to1_ips: Option<Vec<String>>,
    #[serde(rename = "nat1to1CandidateType")]
    pub(crate) nat_1to1_candidate_type: Option<RTCIceCandidateType>,
    answering_dtls_role: Option<RTCDtlsRole>,
    pub(crate) tcp_candidate_gathering: Option<bool>,
    ice_credentials: Option<IceCredentialsJson>,
    ice_timeouts: Option<IceTimeoutsJson>,
    disable_certificate_fingerprint_verification: Option<bool>,
    #[serde(default)]
    pub(crate) interceptors: Interceptors,
}

impl SettingsJson {
    pub(crate) fn build(&mut self) -> SettingEngine {
        let mut b = SettingEngineBuilder::new();
        if let Some(lite) = self.ice_lite {
            b = b.with_lite(lite);
        }
        if let Some(ips) = self.nat_1to1_ips.take() {
            b = b.with_nat_1to1_ips(
                ips,
                self.nat_1to1_candidate_type
                    .unwrap_or(RTCIceCandidateType::Host),
            );
        }
        if let Some(role) = self.answering_dtls_role {
            b = b.with_answering_dtls_role(role);
        }
        if let Some(tcp) = self.tcp_candidate_gathering {
            b = b.with_tcp_candidate_gathering(tcp);
        }
        if let Some(credentials) = self.ice_credentials.take() {
            b = b.with_ice_credentials(credentials.username_fragment, credentials.password);
        }
        if let Some(t) = self.ice_timeouts.take() {
            b = b.with_ice_timeouts(
                t.disconnected_ms.map(Duration::from_millis),
                t.failed_ms.map(Duration::from_millis),
                t.keep_alive_ms.map(Duration::from_millis),
            );
        }
        if let Some(disabled) = self.disable_certificate_fingerprint_verification {
            b = b.with_disable_certificate_fingerprint_verification(disabled);
        }
        b.build()
    }
}

/// The media engine (the default codecs) and the interceptor registry for `interceptors`.
pub(crate) fn media(interceptors: Interceptors) -> FfiResult<(MediaEngine, Registry)> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let registry = match interceptors {
        Interceptors::Default => register_default_interceptors(Registry::new(), &mut media_engine)?,
        Interceptors::Minimal => Registry::new(),
    };
    Ok((media_engine, registry))
}

/// W3C `RTCOfferOptions`.
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OfferOptionsJson {
    #[serde(default)]
    ice_restart: bool,
    voice_activity_detection: Option<bool>,
    offer_to_receive_audio: Option<bool>,
    offer_to_receive_video: Option<bool>,
}

impl OfferOptionsJson {
    pub(crate) fn build(self) -> RTCOfferOptions {
        RTCOfferOptions {
            ice_restart: self.ice_restart,
            voice_activity_detection: self.voice_activity_detection,
            offer_to_receive_audio: self.offer_to_receive_audio,
            offer_to_receive_video: self.offer_to_receive_video,
        }
    }
}

/// W3C `RTCAnswerOptions`.
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AnswerOptionsJson {
    voice_activity_detection: Option<bool>,
}

impl AnswerOptionsJson {
    pub(crate) fn build(self) -> RTCAnswerOptions {
        RTCAnswerOptions {
            voice_activity_detection: self.voice_activity_detection,
        }
    }
}

/// A priority: the W3C name or the DCEP number.
#[derive(Deserialize)]
#[serde(untagged)]
enum PriorityJson {
    Name(rtc::peer_connection::priority::RTCPriorityType),
    Number(u16),
}

/// W3C `RTCDataChannelInit`.
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DataChannelInitJson {
    ordered: Option<bool>,
    max_packet_life_time: Option<u16>,
    max_retransmits: Option<u16>,
    protocol: Option<String>,
    #[serde(default)]
    negotiated: bool,
    id: Option<u16>,
    priority: Option<PriorityJson>,
}

impl DataChannelInitJson {
    pub(crate) fn build(self) -> FfiResult<RTCDataChannelInit> {
        let mut init = RTCDataChannelInit::default();
        if let Some(ordered) = self.ordered {
            init.ordered = ordered;
        }
        init.max_packet_life_time = self.max_packet_life_time;
        init.max_retransmits = self.max_retransmits;
        if let Some(protocol) = self.protocol {
            init.protocol = protocol;
        }
        if self.negotiated {
            init.negotiated = Some(self.id.ok_or_else(|| {
                FfiError::invalid("a negotiated data channel needs an id (W3C TypeError)")
            })?);
        }
        match self.priority {
            Some(PriorityJson::Name(p)) => init.priority = p.dcep_priority(),
            Some(PriorityJson::Number(n)) => init.priority = n,
            None => {}
        }
        Ok(init)
    }
}

/// W3C `RTCRtpCodec`.
#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CodecJson {
    mime_type: String,
    clock_rate: u32,
    #[serde(default)]
    channels: u16,
    #[serde(default)]
    sdp_fmtp_line: String,
}

impl CodecJson {
    fn build(self) -> RTCRtpCodec {
        RTCRtpCodec {
            mime_type: self.mime_type,
            clock_rate: self.clock_rate,
            channels: self.channels,
            sdp_fmtp_line: self.sdp_fmtp_line,
            rtcp_feedback: vec![],
        }
    }
}

/// W3C `RTCRtpEncodingParameters` (the members the engine takes at creation).
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EncodingJson {
    rid: Option<String>,
    /// Non-standard: the SSRC to send with (generated when absent).
    ssrc: Option<u32>,
    active: Option<bool>,
    max_bitrate: Option<u32>,
    max_framerate: Option<f64>,
    scale_resolution_down_by: Option<f64>,
    codec: Option<CodecJson>,
}

impl EncodingJson {
    fn build(self) -> RTCRtpEncodingParameters {
        RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                rid: self.rid.unwrap_or_default(),
                ssrc: self.ssrc,
                ..Default::default()
            },
            active: self.active.unwrap_or(true),
            codec: self.codec.map(CodecJson::build).unwrap_or_default(),
            max_bitrate: self.max_bitrate.unwrap_or_default(),
            max_framerate: self.max_framerate,
            scale_resolution_down_by: self.scale_resolution_down_by,
            ..Default::default()
        }
    }
}

/// W3C `RTCRtpTransceiverInit`.
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TransceiverInitJson {
    direction: Option<String>,
    #[serde(default)]
    streams: Vec<String>,
    #[serde(default)]
    send_encodings: Vec<EncodingJson>,
}

impl TransceiverInitJson {
    pub(crate) fn build(self) -> FfiResult<RTCRtpTransceiverInit> {
        let direction = match self.direction.as_deref() {
            None => RTCRtpTransceiverDirection::Sendrecv,
            Some(d) => direction(d)?,
        };
        let mut init = RTCRtpTransceiverInit::with_direction(direction);
        init.streams = self.streams;
        init.send_encodings = self
            .send_encodings
            .into_iter()
            .map(EncodingJson::build)
            .collect();
        Ok(init)
    }
}

/// A transceiver direction from its W3C name.
pub(crate) fn direction(name: &str) -> FfiResult<RTCRtpTransceiverDirection> {
    match RTCRtpTransceiverDirection::from(name) {
        RTCRtpTransceiverDirection::Unspecified => Err(FfiError::invalid(format!(
            "not a transceiver direction: {name}"
        ))),
        d => Ok(d),
    }
}

/// A media kind from its name.
pub(crate) fn kind(name: &str) -> FfiResult<RtpCodecKind> {
    match RtpCodecKind::from(name) {
        RtpCodecKind::Audio => Ok(RtpCodecKind::Audio),
        RtpCodecKind::Video => Ok(RtpCodecKind::Video),
        _ => Err(FfiError::invalid(format!("not a media kind: {name}"))),
    }
}

/// A local track to send (`MediaStreamTrack` plus its encodings), non-standard: the engine has
/// no capture, so a track is a kind, ids and how it is sent.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TrackJson {
    pub(crate) kind: String,
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) label: String,
    #[serde(default)]
    pub(crate) stream_ids: Vec<String>,
    /// The SSRC to send with (generated when absent).
    pub(crate) ssrc: Option<u32>,
    /// The codec to send; Opus or VP8 when absent.
    pub(crate) codec: Option<CodecJson>,
}

impl TrackJson {
    /// The track and the streams beyond its first.
    pub(crate) fn build(self) -> FfiResult<(rtc::media_stream::MediaStreamTrack, Vec<String>)> {
        let kind = kind(&self.kind)?;
        let codec = match self.codec {
            Some(codec) => codec.build(),
            None => default_codec(kind),
        };
        let mut streams = self.stream_ids.into_iter();
        let stream_id = streams.next().unwrap_or_default();
        let track = rtc::media_stream::MediaStreamTrack::new(
            stream_id,
            self.id,
            self.label,
            kind,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    ssrc: self.ssrc,
                    ..Default::default()
                },
                codec,
                ..Default::default()
            }],
        );
        Ok((track, streams.collect()))
    }
}

fn default_codec(kind: RtpCodecKind) -> RTCRtpCodec {
    match kind {
        RtpCodecKind::Audio => RTCRtpCodec {
            mime_type: MIME_TYPE_OPUS.to_owned(),
            clock_rate: 48000,
            channels: 2,
            sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
            rtcp_feedback: vec![],
        },
        _ => RTCRtpCodec {
            mime_type: MIME_TYPE_VP8.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: String::new(),
            rtcp_feedback: vec![],
        },
    }
}

pub(crate) fn codec_json(codec: &RTCRtpCodecParameters) -> Value {
    json!({
        "payloadType": codec.payload_type,
        "mimeType": codec.rtp_codec.mime_type,
        "clockRate": codec.rtp_codec.clock_rate,
        "channels": codec.rtp_codec.channels,
        "sdpFmtpLine": codec.rtp_codec.sdp_fmtp_line,
    })
}

fn transport_id(id: impl std::fmt::Debug) -> String {
    format!("{id:?}")
}

/// A data channel's W3C attributes.
pub(crate) fn data_channel_json(pc: &mut RTCPeerConnection, id: RTCDataChannelId) -> Value {
    match pc.data_channel(id) {
        Some(dc) => json!({
            "channel": id,
            "label": dc.label(),
            "protocol": dc.protocol(),
            "ordered": dc.ordered(),
            "maxPacketLifeTime": dc.max_packet_life_time(),
            "maxRetransmits": dc.max_retransmits(),
            "negotiated": dc.negotiated(),
            "id": dc.stream_id(),
            "priority": dc.priority_type(),
            "readyState": dc.ready_state().to_string(),
            "bufferedAmount": dc.buffered_amount(),
            "bufferedAmountLowThreshold": dc.buffered_amount_low_threshold(),
        }),
        None => match pc.closed_data_channel(id) {
            Some(closed) => json!({
                "channel": id,
                "label": closed.label(),
                "readyState": "closed",
            }),
            None => json!({ "channel": id, "readyState": "closed" }),
        },
    }
}

/// An event of the peer connection as `{"type": <W3C event name>, ...}`. Events with no W3C
/// name keep a name of this interface; an event this version does not know is
/// `{"type": "other", "debug": ...}`.
pub(crate) fn event_json(pc: &mut RTCPeerConnection, event: RTCPeerConnectionEvent) -> Value {
    use RTCPeerConnectionEvent as E;
    match event {
        E::OnNegotiationNeededEvent => json!({ "type": "negotiationneeded" }),
        E::OnIceCandidateEvent(e) => {
            let candidate = e
                .candidate
                .as_ref()
                .and_then(|c| c.to_json().ok())
                .and_then(|init| serde_json::to_value(init).ok());
            json!({ "type": "icecandidate", "candidate": candidate, "url": e.url })
        }
        E::OnIceCandidateErrorEvent(e) => json!({
            "type": "icecandidateerror",
            "address": e.address,
            "port": e.port,
            "url": e.url,
            "errorCode": e.error_code,
            "errorText": e.error_text,
        }),
        E::OnSignalingStateChangeEvent(s) => {
            json!({ "type": "signalingstatechange", "state": s.to_string() })
        }
        E::OnIceConnectionStateChangeEvent(s) => {
            json!({ "type": "iceconnectionstatechange", "state": s.to_string() })
        }
        E::OnIceGatheringStateChangeEvent(s) => {
            json!({ "type": "icegatheringstatechange", "state": s.to_string() })
        }
        E::OnConnectionStateChangeEvent(s) => {
            json!({ "type": "connectionstatechange", "state": s.to_string() })
        }
        E::OnDataChannel(e) => data_channel_event_json(pc, e),
        E::OnTrack(e) => track_event_json(e),
        E::OnSsrcCollision(ssrc) => json!({ "type": "ssrccollision", "ssrc": ssrc }),
        E::OnUnassociatedRtpDiscarded(ssrc) => {
            json!({ "type": "unassociatedrtpdiscarded", "ssrc": ssrc })
        }
        E::OnIceTransportStateChange(s) => {
            json!({ "type": "icetransportstatechange", "state": s.to_string() })
        }
        E::OnIceGathererStateChange(s) => {
            json!({ "type": "icegathererstatechange", "state": s.to_string() })
        }
        E::OnSelectedCandidatePairChange(p) => {
            json!({ "type": "selectedcandidatepairchange", "pair": p.to_string() })
        }
        E::OnDtlsTransportStateChange(s) => {
            json!({ "type": "dtlsstatechange", "state": s.to_string() })
        }
        E::OnDtlsTransportError(e) => json!({ "type": "dtlserror", "message": e.message }),
        E::OnSctpTransportStateChange(s) => {
            json!({ "type": "sctpstatechange", "state": s.to_string() })
        }
        E::OnDtmfToneChange(e) => json!({
            "type": "tonechange",
            "sender": usize::from(e.sender_id),
            "tone": e.tone,
        }),
        E::OnTransportEvent(e) => {
            let mut v = match e.event {
                RTCTransportEventKind::IceStateChange(s) => {
                    json!({ "type": "icetransportstatechange", "state": s.to_string() })
                }
                RTCTransportEventKind::GatheringStateChange(s) => {
                    json!({ "type": "icegathererstatechange", "state": s.to_string() })
                }
                RTCTransportEventKind::SelectedCandidatePairChange(p) => {
                    json!({ "type": "selectedcandidatepairchange", "pair": p.to_string() })
                }
                RTCTransportEventKind::DtlsStateChange(s) => {
                    json!({ "type": "dtlsstatechange", "state": s.to_string() })
                }
                other => json!({ "type": "transportevent", "debug": format!("{other:?}") }),
            };
            v["iceTransport"] = json!(transport_id(e.ice_transport));
            v["dtlsTransport"] = json!(transport_id(e.dtls_transport));
            v
        }
        other => json!({ "type": "other", "debug": format!("{other:?}") }),
    }
}

fn data_channel_event_json(pc: &mut RTCPeerConnection, e: RTCDataChannelEvent) -> Value {
    use RTCDataChannelEvent as D;
    let (kind, id) = match e {
        D::OnDataChannel(id) => {
            let mut v = data_channel_json(pc, id);
            v["type"] = json!("datachannel");
            return v;
        }
        D::OnOpen(id) => ("open", id),
        D::OnError(id) => ("error", id),
        D::OnClosing(id) => ("closing", id),
        D::OnClose(id) => ("close", id),
        D::OnBufferedAmountLow(id) => ("bufferedamountlow", id),
        D::OnBufferedAmountHigh(id) => ("bufferedamounthigh", id),
        other => return json!({ "type": "other", "debug": format!("{other:?}") }),
    };
    json!({ "type": kind, "target": "datachannel", "channel": id })
}

fn track_event_json(e: RTCTrackEvent) -> Value {
    use RTCTrackEvent as T;
    match e {
        // W3C `track`: a remote description made the transceiver receive.
        T::OnRemoteTrack(init) => json!({
            "type": "track",
            "receiver": usize::from(init.receiver_id),
            "transceiver": init.transceiver_id,
            "track": init.track_id,
            "streams": init.stream_ids,
        }),
        // The first RTP of a stream of the track arrived.
        T::OnOpen(init) => json!({
            "type": "trackopen",
            "receiver": usize::from(init.receiver_id),
            "track": init.track_id,
            "streams": init.stream_ids,
            "ssrc": init.ssrc,
            "rid": init.rid,
        }),
        T::OnError(track) => json!({ "type": "error", "target": "track", "track": track }),
        T::OnClosing(track) => json!({ "type": "closing", "target": "track", "track": track }),
        T::OnClose(track) => json!({ "type": "ended", "target": "track", "track": track }),
        T::OnMute(track) => json!({ "type": "mute", "target": "track", "track": track }),
        T::OnUnmute(track) => json!({ "type": "unmute", "target": "track", "track": track }),
        T::OnStreamsChanged(change) => json!({
            "type": "streamschange",
            "target": "track",
            "track": change.track_id,
            "removed": change.removed,
            "added": change.added,
        }),
        other => json!({ "type": "other", "debug": format!("{other:?}") }),
    }
}

/// A statistics report as a JSON object keyed by stats id (the `RTCStatsReport` maplike).
pub(crate) fn stats_json(report: &RTCStatsReport) -> Value {
    let mut out = Map::new();
    for entry in report.iter() {
        use RTCStatsReportEntry as S;
        let value = match entry {
            S::PeerConnection(s) => serde_json::to_value(s),
            S::Transport(s) => serde_json::to_value(s),
            S::IceCandidatePair(s) => serde_json::to_value(s),
            S::LocalCandidate(s) | S::RemoteCandidate(s) => serde_json::to_value(s),
            S::Certificate(s) => serde_json::to_value(s),
            S::Codec(s) => serde_json::to_value(s),
            S::DataChannel(s) => serde_json::to_value(s),
            S::InboundRtp(s) => serde_json::to_value(s),
            S::OutboundRtp(s) => serde_json::to_value(s),
            S::RemoteInboundRtp(s) => serde_json::to_value(s),
            S::RemoteOutboundRtp(s) => serde_json::to_value(s),
            S::AudioSource(s) => serde_json::to_value(s),
            S::VideoSource(s) => serde_json::to_value(s),
            S::AudioPlayout(s) => serde_json::to_value(s),
            _ => Ok(json!({ "id": entry.id(), "type": entry.stats_type() })),
        };
        let value = value.unwrap_or_else(|e| json!({ "id": entry.id(), "error": e.to_string() }));
        out.insert(entry.id().to_owned(), value);
    }
    Value::Object(out)
}

/// A stream command of the engine for the application's driver.
pub(crate) fn stream_command_json(command: StreamCommand) -> Value {
    match command {
        StreamCommand::Listen {
            listener,
            local,
            reuse_address,
        } => json!({
            "type": "listen",
            "listener": listener.0,
            "local": local.to_string(),
            "reuseAddress": reuse_address,
        }),
        StreamCommand::StopListening { listener } => {
            json!({ "type": "stopListening", "listener": listener.0 })
        }
        StreamCommand::Connect {
            id,
            local,
            remote,
            reuse_address,
        } => json!({
            "type": "connect",
            "id": id.0,
            "local": local.to_string(),
            "remote": remote.to_string(),
            "reuseAddress": reuse_address,
        }),
        StreamCommand::Close { id } => json!({ "type": "close", "id": id.0 }),
        StreamCommand::Reset { id } => json!({ "type": "reset", "id": id.0 }),
        StreamCommand::Resolve { query, host, port } => {
            json!({ "type": "resolve", "query": query, "host": host, "port": port })
        }
        StreamCommand::ResolveRecords { query, name, kind } => json!({
            "type": "resolveRecords",
            "query": query,
            "name": name,
            "kind": match kind {
                RecordKind::Srv => "srv",
                RecordKind::Naptr => "naptr",
                _ => "other",
            },
        }),
        other => json!({ "type": "other", "debug": format!("{other:?}") }),
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
enum DnsRecordJson {
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Naptr {
        order: u16,
        preference: u16,
        flags: String,
        services: String,
        regexp: String,
        replacement: String,
    },
}

/// What a socket did, from the application's driver to the engine.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
enum StreamEventJson {
    Listening {
        listener: u64,
        local: SocketAddr,
    },
    ListenFailed {
        listener: u64,
    },
    Connected {
        id: u64,
        local: SocketAddr,
    },
    ConnectFailed {
        id: u64,
    },
    Written {
        id: u64,
        bytes: usize,
    },
    Closed {
        id: u64,
    },
    Reset {
        id: u64,
    },
    Resolved {
        query: u64,
        addresses: Vec<SocketAddr>,
    },
    ResolvedFamily {
        query: u64,
        ipv6: bool,
        addresses: Vec<SocketAddr>,
    },
    ResolvedRecords {
        query: u64,
        records: Vec<DnsRecordJson>,
    },
}

/// Parses a stream event for `handle_stream_event`.
pub(crate) fn stream_event(text: &str) -> FfiResult<StreamEvent> {
    let event: StreamEventJson = serde_json::from_str(text)?;
    Ok(match event {
        StreamEventJson::Listening { listener, local } => StreamEvent::Listening {
            listener: ListenerId(listener),
            local,
        },
        StreamEventJson::ListenFailed { listener } => StreamEvent::ListenFailed {
            listener: ListenerId(listener),
        },
        StreamEventJson::Connected { id, local } => StreamEvent::Connected {
            id: StreamId(id),
            local,
        },
        StreamEventJson::ConnectFailed { id } => StreamEvent::ConnectFailed { id: StreamId(id) },
        StreamEventJson::Written { id, bytes } => StreamEvent::Written {
            id: StreamId(id),
            bytes,
        },
        StreamEventJson::Closed { id } => StreamEvent::Closed { id: StreamId(id) },
        StreamEventJson::Reset { id } => StreamEvent::Reset { id: StreamId(id) },
        StreamEventJson::Resolved { query, addresses } => {
            StreamEvent::Resolved { query, addresses }
        }
        StreamEventJson::ResolvedFamily {
            query,
            ipv6,
            addresses,
        } => StreamEvent::ResolvedFamily {
            query,
            ipv6,
            addresses,
        },
        StreamEventJson::ResolvedRecords { query, records } => StreamEvent::ResolvedRecords {
            query,
            records: records
                .into_iter()
                .map(|r| match r {
                    DnsRecordJson::Srv {
                        priority,
                        weight,
                        port,
                        target,
                    } => DnsRecord::Srv {
                        priority,
                        weight,
                        port,
                        target,
                    },
                    DnsRecordJson::Naptr {
                        order,
                        preference,
                        flags,
                        services,
                        regexp,
                        replacement,
                    } => DnsRecord::Naptr {
                        order,
                        preference,
                        flags,
                        services,
                        regexp,
                        replacement,
                    },
                })
                .collect(),
        },
    })
}
