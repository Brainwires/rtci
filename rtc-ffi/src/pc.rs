//! The sans-I/O layer: `rtc_pc_*`, one to one with `rtc::peer_connection::RTCPeerConnection`.
//!
//! The caller owns the sockets and the clock. A loop looks like the Rust one:
//!
//! ```c
//! for (;;) {
//!     while (rtc_pc_poll_write(pc, &transport, buf, sizeof buf, &len) == RTC_OK) send(...);
//!     while (rtc_pc_poll_event(pc, json, sizeof json, &len) == RTC_OK) on_event(json);
//!     while (rtc_pc_poll_read(pc, &message, buf, sizeof buf) == RTC_OK) on_message(...);
//!     if (rtc_pc_poll_timeout(pc, &deadline) == RTC_OK && deadline <= now) {
//!         rtc_pc_handle_timeout(pc, now);
//!         continue;
//!     }
//!     // wait for a datagram or the deadline, then rtc_pc_handle_read(...)
//! }
//! ```

use crate::json::{self, AnswerOptionsJson, ConfigurationJson, OfferOptionsJson, SettingsJson};
use crate::{
    FfiError, FfiResult, RTC_EMPTY, RTC_ERR_CLOSED, RTC_OK, bytes_arg, clock, copy_out,
    give_string, guard, object_created, object_freed, opt_str, req_str,
};
use bytes::{Bytes, BytesMut};
use rtc::data_channel::RTCDataChannelId;
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::sdp::{RTCSdpType, RTCSessionDescription};
use rtc::peer_connection::transport::RTCIceCandidateInit;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp::packetizer::Packetizer;
use rtc::rtp_transceiver::{RTCRtpReceiverId, RTCRtpSenderId};
use rtc::sansio::Protocol;
use rtc::shared::marshal::{Marshal, Unmarshal};
use rtc::shared::stream::{ListenerId, StreamId, StreamTransmit};
use rtc::shared::{EcnCodepoint, TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::StatsSelector;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::ffi::c_char;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// A message for the application: an RTP packet.
pub const RTC_MESSAGE_RTP: u32 = 1;
/// A message for the application: an RTCP compound packet.
pub const RTC_MESSAGE_RTCP: u32 = 2;
/// A message for the application: a data channel message.
pub const RTC_MESSAGE_DATA: u32 = 3;

/// The transport protocol of a datagram: UDP.
pub const RTC_PROTOCOL_UDP: u8 = 0;
/// The transport protocol of a datagram: TCP (framed by the application, RFC 4571).
pub const RTC_PROTOCOL_TCP: u8 = 1;

const MAGIC: u64 = 0x7274_635f_7063_0001; // "rtc_pc" + 1

/// A socket address: `family` 4 or 6 (0: none), the address in network order (an IPv4 one in
/// the first four bytes), the port in host order.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RtcAddr {
    /// 4 (IPv4), 6 (IPv6) or 0 (no address).
    pub family: u8,
    /// The address bytes, network order; IPv4 uses the first four.
    pub ip: [u8; 16],
    /// The port, host order.
    pub port: u16,
}

impl RtcAddr {
    /// The C form of `addr`.
    pub fn from_socket(addr: SocketAddr) -> Self {
        let mut ip = [0u8; 16];
        let family = match addr.ip() {
            IpAddr::V4(v4) => {
                ip[..4].copy_from_slice(&v4.octets());
                4
            }
            IpAddr::V6(v6) => {
                ip.copy_from_slice(&v6.octets());
                6
            }
        };
        Self {
            family,
            ip,
            port: addr.port(),
        }
    }

    /// The Rust form; `None` for family 0 or an unknown family.
    pub fn to_socket(self) -> Option<SocketAddr> {
        let ip = match self.family {
            4 => IpAddr::V4(Ipv4Addr::new(
                self.ip[0], self.ip[1], self.ip[2], self.ip[3],
            )),
            6 => IpAddr::V6(Ipv6Addr::from(self.ip)),
            _ => return None,
        };
        Some(SocketAddr::new(ip, self.port))
    }
}

/// The 5-tuple of a datagram: where it arrived or leaves from (`local`), the other end
/// (`peer`), [`RTC_PROTOCOL_UDP`] or [`RTC_PROTOCOL_TCP`], and its ECN codepoint (the two
/// bits of the IP header: 0 Not-ECT, 1 ECT(1), 2 ECT(0), 3 CE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RtcTransport {
    /// The local address.
    pub local: RtcAddr,
    /// The remote address.
    pub peer: RtcAddr,
    /// [`RTC_PROTOCOL_UDP`] or [`RTC_PROTOCOL_TCP`].
    pub protocol: u8,
    /// The ECN codepoint (0 when not ECN-capable).
    pub ecn: u8,
}

impl RtcTransport {
    fn from_context(t: &TransportContext) -> Self {
        Self {
            local: RtcAddr::from_socket(t.local_addr),
            peer: RtcAddr::from_socket(t.peer_addr),
            protocol: match t.transport_protocol {
                TransportProtocol::TCP => RTC_PROTOCOL_TCP,
                _ => RTC_PROTOCOL_UDP,
            },
            ecn: t.ecn.map_or(0, |e| e as u8),
        }
    }

    fn to_context(self) -> FfiResult<TransportContext> {
        let local = self
            .local
            .to_socket()
            .ok_or_else(|| FfiError::invalid("the local address has no family"))?;
        let peer = self
            .peer
            .to_socket()
            .ok_or_else(|| FfiError::invalid("the peer address has no family"))?;
        Ok(TransportContext {
            local_addr: local,
            peer_addr: peer,
            transport_protocol: match self.protocol {
                RTC_PROTOCOL_UDP => TransportProtocol::UDP,
                RTC_PROTOCOL_TCP => TransportProtocol::TCP,
                _ => return Err(FfiError::invalid("not a transport protocol")),
            },
            ecn: match self.ecn & 0b11 {
                0b01 => Some(EcnCodepoint::Ect1),
                0b10 => Some(EcnCodepoint::Ect0),
                0b11 => Some(EcnCodepoint::Ce),
                _ => None,
            },
        })
    }
}

/// A message for the application, from [`rtc_pc_poll_read`]: its kind
/// ([`RTC_MESSAGE_RTP`], [`RTC_MESSAGE_RTCP`], [`RTC_MESSAGE_DATA`]), the receiver (RTP, RTCP)
/// or data channel it is for, whether a data channel message is a string, when the packet
/// arrived (the `now_ns` of its `handle_read`), and its length in the buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RtcMessage {
    /// The message kind.
    pub kind: u32,
    /// 1 for a data channel string message, 0 otherwise.
    pub is_string: u32,
    /// The receiver id (RTP, RTCP) or data channel id.
    pub id: u64,
    /// When the packet carrying it arrived, in the caller's nanoseconds.
    pub now_ns: u64,
    /// The length of the message in the caller's buffer.
    pub len: usize,
}

/// A peer connection of the sans-I/O layer (C: `rtc_pc`). Not thread-safe: calls on one handle
/// must not overlap.
pub struct PcHandle {
    magic: u64,
    /// Set while a call runs: a call that panics leaves it set, and the handle refuses the
    /// calls after it.
    busy: bool,
    pub(crate) pc: RTCPeerConnection,
    pending_write: Option<TaggedBytesMut>,
    pending_read: Option<(RtcMessage, Vec<u8>)>,
    pending_event: Option<String>,
    pending_command: Option<String>,
    pending_transmit: Option<StreamTransmit>,
    /// Packetizers of `rtc_pc_sender_write_frame`, by sender, with the payload type and SSRC
    /// they were made for.
    packetizers: HashMap<usize, (u8, u32, Box<dyn Packetizer>)>,
    /// Receiver ids by track id, filled as RTP arrives.
    receivers_by_track: HashMap<String, usize>,
}

impl PcHandle {
    pub(crate) fn new(
        configuration: Option<&str>,
        settings: Option<&str>,
        now_ns: u64,
    ) -> FfiResult<Self> {
        Self::with_settings(configuration, json::parse(settings)?, now_ns)
    }

    /// As [`new`](Self::new) with the settings already parsed.
    pub(crate) fn with_settings(
        configuration: Option<&str>,
        mut settings: SettingsJson,
        now_ns: u64,
    ) -> FfiResult<Self> {
        let configuration: ConfigurationJson = json::parse(configuration)?;
        let (media_engine, registry) = json::media(settings.interceptors)?;
        let pc = RTCPeerConnectionBuilder::new()
            .with_configuration(configuration.build())
            .with_setting_engine(settings.build())
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(clock::instant(now_ns))?;
        Ok(Self {
            magic: MAGIC,
            busy: false,
            pc,
            pending_write: None,
            pending_read: None,
            pending_event: None,
            pending_command: None,
            pending_transmit: None,
            packetizers: HashMap::new(),
            receivers_by_track: HashMap::new(),
        })
    }

    fn receiver_of_track(&mut self, track: &str) -> u64 {
        if let Some(id) = self.receivers_by_track.get(track) {
            return *id as u64;
        }
        let receivers: Vec<RTCRtpReceiverId> = self.pc.get_receivers().collect();
        for id in receivers {
            if let Some(receiver) = self.pc.rtp_receiver(id)
                && receiver.track().track_id() == track
            {
                let id = usize::from(id);
                self.receivers_by_track.insert(track.to_owned(), id);
                return id as u64;
            }
        }
        u64::MAX
    }

    pub(crate) fn next_read(&mut self) -> FfiResult<Option<(RtcMessage, Vec<u8>)>> {
        let Some(TaggedRTCMessage { now, message }) = self.pc.poll_read() else {
            return Ok(None);
        };
        let now_ns = clock::nanos(now);
        let (meta, data) = match message {
            RTCMessage::RtpPacket(track, packet) => {
                let data = packet.marshal()?.to_vec();
                let id = self.receiver_of_track(&track);
                (
                    RtcMessage {
                        kind: RTC_MESSAGE_RTP,
                        id,
                        ..Default::default()
                    },
                    data,
                )
            }
            RTCMessage::RtcpPacket(track, packets) => {
                let data = rtc::rtcp::packet::marshal(&packets)?.to_vec();
                let id = self.receiver_of_track(&track);
                (
                    RtcMessage {
                        kind: RTC_MESSAGE_RTCP,
                        id,
                        ..Default::default()
                    },
                    data,
                )
            }
            RTCMessage::DataChannelMessage(channel, message) => (
                RtcMessage {
                    kind: RTC_MESSAGE_DATA,
                    is_string: u32::from(message.is_string),
                    id: channel as u64,
                    ..Default::default()
                },
                message.data.to_vec(),
            ),
            // A kind of message this version does not know: passed over.
            _ => return self.next_read(),
        };
        Ok(Some((
            RtcMessage {
                now_ns,
                len: data.len(),
                ..meta
            },
            data,
        )))
    }
}

/// Runs `f` on a live, unpoisoned handle.
unsafe fn with_pc(handle: *mut PcHandle, f: impl FnOnce(&mut PcHandle) -> FfiResult) -> i32 {
    guard(|| {
        // SAFETY: the caller passes a handle from `rtc_pc_new` that is not freed, or null.
        let h = unsafe { handle.as_mut() }
            .ok_or_else(|| FfiError::invalid("the peer connection handle is null"))?;
        if h.magic != MAGIC {
            return Err(FfiError::invalid("not a live peer connection handle"));
        }
        if h.busy {
            return Err(FfiError::new(
                RTC_ERR_CLOSED,
                "the peer connection is poisoned: an earlier call panicked (or calls overlap)",
            ));
        }
        h.busy = true;
        let result = f(h);
        h.busy = false;
        result
    })
}

fn description(text: &str) -> FfiResult<RTCSessionDescription> {
    #[derive(serde::Deserialize)]
    struct Init {
        #[serde(rename = "type")]
        sdp_type: RTCSdpType,
        #[serde(default)]
        sdp: String,
    }
    let init: Init = serde_json::from_str(text)?;
    Ok(match init.sdp_type {
        RTCSdpType::Offer => RTCSessionDescription::offer(init.sdp)?,
        RTCSdpType::Answer => RTCSessionDescription::answer(init.sdp)?,
        RTCSdpType::Pranswer => RTCSessionDescription::pranswer(init.sdp)?,
        RTCSdpType::Rollback => RTCSessionDescription::rollback(Some(init.sdp))?,
        _ => return Err(FfiError::invalid("a description needs a type")),
    })
}

fn description_json(d: &RTCSessionDescription) -> String {
    json!({ "type": d.sdp_type.to_string(), "sdp": d.sdp }).to_string()
}

fn candidate(text: Option<&str>) -> FfiResult<RTCIceCandidateInit> {
    json::parse(text)
}

unsafe fn write_u64(out: *mut u64, value: u64) -> FfiResult {
    if out.is_null() {
        return Err(FfiError::invalid("the output pointer is null"));
    }
    // SAFETY: a valid `uint64_t *` (checked non-null).
    unsafe { *out = value };
    Ok(RTC_OK)
}

/// Creates a peer connection. `configuration_json` is a W3C `RTCConfiguration` (`iceServers`,
/// `iceTransportPolicy`, `bundlePolicy`, `rtcpMuxPolicy`, `iceCandidatePoolSize`) and
/// `settings_json` the engine settings (`iceLite`, `nat1to1Ips`, `nat1to1CandidateType`,
/// `answeringDtlsRole`, `tcpCandidateGathering`, `iceCredentials`, `iceTimeouts`,
/// `disableCertificateFingerprintVerification`, `interceptors`: `"default"` or
/// `"minimal"`); either may be null. `now_ns` is the caller's clock at creation. The handle is
/// written to `out` and freed with [`rtc_pc_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_new(
    configuration_json: *const c_char,
    settings_json: *const c_char,
    now_ns: u64,
    out: *mut *mut PcHandle,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return Err(FfiError::invalid("the output pointer is null"));
        }
        // SAFETY: NUL-terminated strings or null, borrowed for the call.
        let (configuration, settings) =
            unsafe { (opt_str(configuration_json)?, opt_str(settings_json)?) };
        let handle = Box::new(PcHandle::new(configuration, settings, now_ns)?);
        object_created();
        // SAFETY: `out` is a valid pointer (checked non-null).
        unsafe { *out = Box::into_raw(handle) };
        Ok(RTC_OK)
    })
}

/// Frees a peer connection (without closing it first: call [`rtc_pc_close`] and drain
/// [`rtc_pc_poll_write`] to tell the remote). Null is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_free(pc: *mut PcHandle) {
    if pc.is_null() {
        return;
    }
    let _ = guard(|| {
        // SAFETY: a handle from `rtc_pc_new`, freed once.
        let h = unsafe { &mut *pc };
        if h.magic != MAGIC {
            return Err(FfiError::invalid("not a live peer connection handle"));
        }
        h.magic = 0;
        // SAFETY: as above; the box came from `Box::into_raw`.
        drop(unsafe { Box::from_raw(pc) });
        object_freed();
        Ok(RTC_OK)
    });
}

/// W3C `createOffer`: the offer as `{"type":"offer","sdp":...}` in `out_json` (free with
/// `rtc_string_free`). `options_json` is a W3C `RTCOfferOptions` or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_create_offer(
    pc: *mut PcHandle,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let options: OfferOptionsJson = json::parse(opt_str(options_json)?)?;
            let offer = h.pc.create_offer(Some(options.build()))?;
            give_string(out_json, description_json(&offer))
        })
    }
}

/// W3C `createAnswer`, as [`rtc_pc_create_offer`]; `options_json` is a W3C
/// `RTCAnswerOptions` or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_create_answer(
    pc: *mut PcHandle,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let options: AnswerOptionsJson = json::parse(opt_str(options_json)?)?;
            let answer = h.pc.create_answer(Some(options.build()))?;
            give_string(out_json, description_json(&answer))
        })
    }
}

/// W3C `setLocalDescription` with a `{"type", "sdp"}` description.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_set_local_description(
    pc: *mut PcHandle,
    now_ns: u64,
    description_json: *const c_char,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let d = description(req_str(description_json, "the description")?)?;
            h.pc.set_local_description(clock::instant(now_ns), d)?;
            Ok(RTC_OK)
        })
    }
}

/// W3C `setRemoteDescription` with a `{"type", "sdp"}` description.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_set_remote_description(
    pc: *mut PcHandle,
    now_ns: u64,
    description_json: *const c_char,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let d = description(req_str(description_json, "the description")?)?;
            h.pc.set_remote_description(clock::instant(now_ns), d)?;
            Ok(RTC_OK)
        })
    }
}

/// W3C `localDescription` (`which` 0), `currentLocalDescription` (1),
/// `pendingLocalDescription` (2), `remoteDescription` (3), `currentRemoteDescription` (4),
/// `pendingRemoteDescription` (5), as `{"type","sdp"}`; [`RTC_EMPTY`] when there is none.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_description(
    pc: *mut PcHandle,
    which: u32,
    out_json: *mut *mut c_char,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let d = match which {
                0 => h.pc.local_description(),
                1 => h.pc.current_local_description(),
                2 => h.pc.pending_local_description(),
                3 => h.pc.remote_description().cloned(),
                4 => h.pc.current_remote_description().cloned(),
                5 => h.pc.pending_remote_description().cloned(),
                _ => return Err(FfiError::invalid("not a description selector")),
            };
            match d {
                Some(d) => give_string(out_json, description_json(&d)),
                None => Ok(RTC_EMPTY),
            }
        })
    }
}

/// Adds a local ICE candidate (W3C `RTCIceCandidateInit` JSON, plus `url` and
/// `relayProtocol` for a server-gathered one). Null, or an empty `candidate`, ends gathering.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_add_local_candidate(
    pc: *mut PcHandle,
    candidate_json: *const c_char,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            h.pc.add_local_candidate(candidate(opt_str(candidate_json)?)?)?;
            Ok(RTC_OK)
        })
    }
}

/// W3C `addIceCandidate` (a remote candidate, `RTCIceCandidateInit` JSON). Null, or an empty
/// `candidate`, is the remote's end of candidates.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_add_remote_candidate(
    pc: *mut PcHandle,
    candidate_json: *const c_char,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            h.pc.add_remote_candidate(candidate(opt_str(candidate_json)?)?)?;
            Ok(RTC_OK)
        })
    }
}

/// W3C `restartIce`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_restart_ice(pc: *mut PcHandle) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            h.pc.restart_ice();
            Ok(RTC_OK)
        })
    }
}

/// W3C `setConfiguration` with an `RTCConfiguration` JSON.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_set_configuration(
    pc: *mut PcHandle,
    configuration_json: *const c_char,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let c: ConfigurationJson = json::parse(opt_str(configuration_json)?)?;
            h.pc.set_configuration(c.build())?;
            Ok(RTC_OK)
        })
    }
}

/// The connection's states as `{"signalingState", "iceConnectionState", "iceGatheringState",
/// "connectionState", "canTrickleIceCandidates"}`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_states(pc: *mut PcHandle, out_json: *mut *mut c_char) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let v = json!({
                "signalingState": h.pc.signaling_state().to_string(),
                "iceConnectionState": h.pc.ice_connection_state().to_string(),
                "iceGatheringState": h.pc.ice_gathering_state().to_string(),
                "connectionState": h.pc.connection_state().to_string(),
                "canTrickleIceCandidates": h.pc.can_trickle_ice_candidates(),
            });
            give_string(out_json, v.to_string())
        })
    }
}

/// The local ICE username fragments, one per transport, as a JSON array: what a shared port
/// routes by (`examples/stream-driver`'s `UfragMux`). Ask again after each local description.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_ice_username_fragments(
    pc: *mut PcHandle,
    out_json: *mut *mut c_char,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            give_string(out_json, json!(h.pc.ice_username_fragments()).to_string())
        })
    }
}

/// W3C `createDataChannel`: `init_json` is an `RTCDataChannelInit` or null. The channel's id
/// (not its SCTP stream id: see [`rtc_pc_data_channel_info`]) goes to `out_id`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_create_data_channel(
    pc: *mut PcHandle,
    label: *const c_char,
    init_json: *const c_char,
    out_id: *mut u64,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let label = req_str(label, "the label")?;
            let init: json::DataChannelInitJson = json::parse(opt_str(init_json)?)?;
            let id = h.pc.create_data_channel(label, Some(init.build()?))?.id();
            write_u64(out_id, id as u64)
        })
    }
}

fn channel_id(id: u64) -> FfiResult<RTCDataChannelId> {
    usize::try_from(id).map_err(|_| FfiError::not_found("data channel", id))
}

/// W3C `RTCDataChannel.send`: `is_string` non-zero sends `data` (UTF-8) as a string message.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_data_channel_send(
    pc: *mut PcHandle,
    now_ns: u64,
    id: u64,
    data: *const u8,
    len: usize,
    is_string: u8,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let bytes = bytes_arg(data, len)?;
            let mut dc =
                h.pc.data_channel(channel_id(id)?)
                    .ok_or_else(|| FfiError::not_found("data channel", id))?;
            let now = clock::instant(now_ns);
            if is_string != 0 {
                let text = std::str::from_utf8(bytes)
                    .map_err(|_| FfiError::invalid("a string message is not UTF-8"))?;
                dc.send_text(now, text.to_owned())?;
            } else {
                dc.send(now, BytesMut::from(bytes))?;
            }
            Ok(RTC_OK)
        })
    }
}

/// W3C `RTCDataChannel.close`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_data_channel_close(pc: *mut PcHandle, id: u64) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            h.pc.data_channel(channel_id(id)?)
                .ok_or_else(|| FfiError::not_found("data channel", id))?
                .close()?;
            Ok(RTC_OK)
        })
    }
}

/// W3C `RTCDataChannel.bufferedAmountLowThreshold`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_data_channel_set_buffered_amount_low_threshold(
    pc: *mut PcHandle,
    id: u64,
    threshold: u32,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            h.pc.data_channel(channel_id(id)?)
                .ok_or_else(|| FfiError::not_found("data channel", id))?
                .set_buffered_amount_low_threshold(threshold);
            Ok(RTC_OK)
        })
    }
}

/// A data channel's attributes as JSON (`label`, `protocol`, `ordered`, `maxPacketLifeTime`,
/// `maxRetransmits`, `negotiated`, `id` (the SCTP stream id), `priority`, `readyState`,
/// `bufferedAmount`, `bufferedAmountLowThreshold`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_data_channel_info(
    pc: *mut PcHandle,
    id: u64,
    out_json: *mut *mut c_char,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let v = json::data_channel_json(&mut h.pc, channel_id(id)?);
            give_string(out_json, v.to_string())
        })
    }
}

/// W3C `addTrack` for a local track described as `{"kind", "id", "label", "streamIds",
/// "ssrc", "codec"}` (the engine captures nothing: the application writes the media). The
/// sender's id goes to `out_sender`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_add_track(
    pc: *mut PcHandle,
    track_json: *const c_char,
    out_sender: *mut u64,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let track: json::TrackJson = serde_json::from_str(req_str(track_json, "the track")?)?;
            let (track, more_streams) = track.build()?;
            let stream = track.stream_id().clone();
            let sender = h.pc.add_track(track)?;
            if !more_streams.is_empty() {
                let mut streams = vec![stream];
                streams.extend(more_streams);
                if let Some(mut s) = h.pc.rtp_sender(sender) {
                    s.set_streams(streams)?;
                }
            }
            write_u64(out_sender, usize::from(sender) as u64)
        })
    }
}

/// W3C `removeTrack`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_remove_track(pc: *mut PcHandle, sender: u64) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            h.pc.remove_track(sender_id(sender)?)?;
            Ok(RTC_OK)
        })
    }
}

fn sender_id(id: u64) -> FfiResult<RTCRtpSenderId> {
    usize::try_from(id)
        .map(RTCRtpSenderId::from)
        .map_err(|_| FfiError::not_found("sender", id))
}

fn receiver_id(id: u64) -> FfiResult<RTCRtpReceiverId> {
    usize::try_from(id)
        .map(RTCRtpReceiverId::from)
        .map_err(|_| FfiError::not_found("receiver", id))
}

/// W3C `addTransceiver(kind, init)`: `kind` is `"audio"` or `"video"`, `init_json` an
/// `RTCRtpTransceiverInit` (`direction`, `streams`, `sendEncodings`) or null. The
/// transceiver's id goes to `out_transceiver`; its sender and receiver have the same id.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_add_transceiver(
    pc: *mut PcHandle,
    kind: *const c_char,
    init_json: *const c_char,
    out_transceiver: *mut u64,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let kind = json::kind(req_str(kind, "the kind")?)?;
            let init: json::TransceiverInitJson = json::parse(opt_str(init_json)?)?;
            let id = h.pc.add_transceiver_from_kind(kind, Some(init.build()?))?;
            write_u64(out_transceiver, id as u64)
        })
    }
}

/// W3C `getTransceivers`, as a JSON array of `{"id", "mid", "kind", "direction",
/// "currentDirection", "stopped", "sender", "receiver"}`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_transceivers(pc: *mut PcHandle, out_json: *mut *mut c_char) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let ids: Vec<usize> = h.pc.get_transceivers().collect();
            let mut out = Vec::new();
            for id in ids {
                let Some(t) = h.pc.rtp_transceiver(id) else {
                    continue;
                };
                let mid = t.mid().clone();
                let direction = t.direction().to_string();
                let current = t.current_direction().map(|d| d.to_string());
                let stopped = t.stopped();
                let sender = t.sender().map(usize::from);
                let receiver = t.receiver().map(usize::from);
                let kind = receiver
                    .and_then(|r| h.pc.rtp_receiver(RTCRtpReceiverId::from(r)))
                    .map(|r| r.track().kind().to_string());
                out.push(json!({
                    "id": id,
                    "mid": mid,
                    "kind": kind,
                    "direction": direction,
                    "currentDirection": current,
                    "stopped": stopped,
                    "sender": sender,
                    "receiver": receiver,
                }));
            }
            give_string(out_json, Value::Array(out).to_string())
        })
    }
}

/// W3C `RTCRtpTransceiver.direction` setter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_transceiver_set_direction(
    pc: *mut PcHandle,
    transceiver: u64,
    direction: *const c_char,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let d = json::direction(req_str(direction, "the direction")?)?;
            let id = usize::try_from(transceiver)
                .map_err(|_| FfiError::not_found("transceiver", transceiver))?;
            h.pc.rtp_transceiver(id)
                .ok_or_else(|| FfiError::not_found("transceiver", transceiver))?
                .set_direction(d)?;
            Ok(RTC_OK)
        })
    }
}

/// W3C `RTCRtpTransceiver.stop`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_transceiver_stop(pc: *mut PcHandle, transceiver: u64) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let id = usize::try_from(transceiver)
                .map_err(|_| FfiError::not_found("transceiver", transceiver))?;
            h.pc.rtp_transceiver(id)
                .ok_or_else(|| FfiError::not_found("transceiver", transceiver))?
                .stop()?;
            Ok(RTC_OK)
        })
    }
}

/// A sender as JSON: `{"track", "kind", "ssrcs", "streams", "codecs"}` (the negotiated codecs
/// with their payload types, empty before negotiation).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_sender_info(
    pc: *mut PcHandle,
    sender: u64,
    out_json: *mut *mut c_char,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let mut s =
                h.pc.rtp_sender(sender_id(sender)?)
                    .ok_or_else(|| FfiError::not_found("sender", sender))?;
            let track = s.track().map(|t| t.track_id().clone());
            let kind = s.track().map(|t| t.kind().to_string());
            let ssrcs: Vec<u32> = s.ssrcs().collect();
            let streams = s.streams().to_vec();
            let codecs: Vec<Value> = s
                .get_parameters()
                .rtp_parameters
                .codecs
                .iter()
                .map(json::codec_json)
                .collect();
            let v = json!({
                "track": track,
                "kind": kind,
                "ssrcs": ssrcs,
                "streams": streams,
                "codecs": codecs,
            });
            give_string(out_json, v.to_string())
        })
    }
}

/// A receiver as JSON: `{"track", "kind", "streams", "codecs"}`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_receiver_info(
    pc: *mut PcHandle,
    receiver: u64,
    out_json: *mut *mut c_char,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let mut r =
                h.pc.rtp_receiver(receiver_id(receiver)?)
                    .ok_or_else(|| FfiError::not_found("receiver", receiver))?;
            let track = r.track().track_id().clone();
            let kind = r.track().kind().to_string();
            let streams = r.streams().to_vec();
            let codecs: Vec<Value> = r
                .get_parameters()
                .rtp_parameters
                .codecs
                .iter()
                .map(json::codec_json)
                .collect();
            let v = json!({ "track": track, "kind": kind, "streams": streams, "codecs": codecs });
            give_string(out_json, v.to_string())
        })
    }
}

/// Sends one RTP packet (its wire form) on a sender. The engine stamps the negotiated payload
/// type when the packet's is not negotiated, the MID and RID header extensions when they are,
/// and protects it with SRTP; the SSRC is the caller's (see `ssrcs` in
/// [`rtc_pc_sender_info`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_sender_write_rtp(
    pc: *mut PcHandle,
    now_ns: u64,
    sender: u64,
    packet: *const u8,
    len: usize,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let mut bytes = bytes_arg(packet, len)?;
            let packet = rtc::rtp::Packet::unmarshal(&mut bytes)?;
            h.pc.rtp_sender(sender_id(sender)?)
                .ok_or_else(|| FfiError::not_found("sender", sender))?
                .write_rtp(clock::instant(now_ns), packet)?;
            Ok(RTC_OK)
        })
    }
}

/// Packetizes one encoded frame (an Opus packet, a VP8 / VP9 / AV1 frame, H.264 / H.265 access
/// unit in Annex B form, ...) with the sender's negotiated codec and sends it: sequence numbers
/// continue from the last frame, the RTP timestamp advances by `samples` (the frame's duration
/// in the codec's clock rate) after it, and the marker bit follows the payload format.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_sender_write_frame(
    pc: *mut PcHandle,
    now_ns: u64,
    sender: u64,
    frame: *const u8,
    len: usize,
    samples: u32,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let frame = Bytes::copy_from_slice(bytes_arg(frame, len)?);
            let now = clock::instant(now_ns);
            let id = sender_id(sender)?;
            let mut s =
                h.pc.rtp_sender(id)
                    .ok_or_else(|| FfiError::not_found("sender", sender))?;
            let ssrc = s
                .ssrcs()
                .next()
                .ok_or_else(|| FfiError::invalid("the sender has no SSRC"))?;
            let codec = s
                .get_parameters()
                .rtp_parameters
                .codecs
                .first()
                .cloned()
                .ok_or_else(|| FfiError::invalid("the sender has no negotiated codec yet"))?;
            let key = usize::from(id);
            let fresh = !matches!(h.packetizers.get(&key),
                Some((pt, s, _)) if *pt == codec.payload_type && *s == ssrc);
            if fresh {
                let packetizer = rtc::rtp::packetizer::new_packetizer(
                    now,
                    1200,
                    codec.payload_type,
                    ssrc,
                    codec.rtp_codec.payloader()?,
                    Box::new(rtc::rtp::sequence::new_random_sequencer()),
                    codec.rtp_codec.clock_rate,
                );
                h.packetizers
                    .insert(key, (codec.payload_type, ssrc, Box::new(packetizer)));
            }
            let (_, _, packetizer) = h
                .packetizers
                .get_mut(&key)
                .ok_or_else(|| FfiError::invalid("no packetizer"))?;
            let packets = packetizer.packetize(now, &frame, samples)?;
            let mut s =
                h.pc.rtp_sender(id)
                    .ok_or_else(|| FfiError::not_found("sender", sender))?;
            for packet in packets {
                s.write_rtp(now, packet)?;
            }
            Ok(RTC_OK)
        })
    }
}

/// Feeds one received datagram (`sansio::Protocol::handle_read`), with its 5-tuple and the
/// caller's clock when it arrived.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_handle_read(
    pc: *mut PcHandle,
    now_ns: u64,
    transport: *const RtcTransport,
    data: *const u8,
    len: usize,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let t = transport
                .as_ref()
                .ok_or_else(|| FfiError::invalid("the transport is null"))?;
            let bytes = bytes_arg(data, len)?;
            h.pc.handle_read(TaggedBytesMut {
                now: clock::instant(now_ns),
                transport: t.to_context()?,
                message: BytesMut::from(bytes),
            })?;
            Ok(RTC_OK)
        })
    }
}

/// Takes the next datagram to send (`poll_write`): its 5-tuple to `out_transport` (send from
/// `local` to `peer`), its bytes to `buf`, its length to `out_len`. [`RTC_EMPTY`] when there is
/// none; [`RTC_ERR_BUFFER_TOO_SMALL`] keeps it for the next call. Drain until [`RTC_EMPTY`]
/// after every other call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_poll_write(
    pc: *mut PcHandle,
    out_transport: *mut RtcTransport,
    buf: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            if h.pending_write.is_none() {
                h.pending_write = h.pc.poll_write();
            }
            let Some(msg) = h.pending_write.as_ref() else {
                return Ok(RTC_EMPTY);
            };
            if let Some(t) = out_transport.as_mut() {
                *t = RtcTransport::from_context(&msg.transport);
            }
            let code = copy_out(&msg.message, buf, cap, out_len);
            if code == RTC_OK {
                h.pending_write = None;
            }
            Ok(code)
        })
    }
}

/// Takes the next message for the application (`poll_read`): RTP and RTCP in their wire form
/// (decrypted), data channel messages as sent. Its description goes to `out`, its bytes to
/// `buf`. [`RTC_EMPTY`] when there is none; [`RTC_ERR_BUFFER_TOO_SMALL`] (with `out->len` the
/// size needed) keeps it. Not polling is the data channels' back-pressure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_poll_read(
    pc: *mut PcHandle,
    out: *mut RtcMessage,
    buf: *mut u8,
    cap: usize,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            if out.is_null() {
                return Err(FfiError::invalid("the output pointer is null"));
            }
            if h.pending_read.is_none() {
                h.pending_read = h.next_read()?;
            }
            let Some((meta, data)) = h.pending_read.as_ref() else {
                return Ok(RTC_EMPTY);
            };
            *out = *meta;
            let code = copy_out(data, buf, cap, std::ptr::null_mut());
            if code == RTC_OK {
                h.pending_read = None;
            }
            Ok(code)
        })
    }
}

/// Takes the next event as JSON (`{"type": ...}`; see the README of `rtc-ffi` for the shapes)
/// into `buf` (not NUL-terminated; `out_len` is its length). [`RTC_EMPTY`] when there is none;
/// [`RTC_ERR_BUFFER_TOO_SMALL`] keeps it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_poll_event(
    pc: *mut PcHandle,
    buf: *mut c_char,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            if h.pending_event.is_none()
                && let Some(event) = h.pc.poll_event()
            {
                h.pending_event = Some(json::event_json(&mut h.pc, event).to_string());
            }
            let Some(event) = h.pending_event.as_ref() else {
                return Ok(RTC_EMPTY);
            };
            let code = copy_out(event.as_bytes(), buf.cast(), cap, out_len);
            if code == RTC_OK {
                h.pending_event = None;
            }
            Ok(code)
        })
    }
}

/// The next deadline (`poll_timeout`) in the caller's nanoseconds to `out_ns`; [`RTC_EMPTY`]
/// when nothing is pending.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_poll_timeout(pc: *mut PcHandle, out_ns: *mut u64) -> i32 {
    unsafe {
        with_pc(pc, |h| match h.pc.poll_timeout() {
            Some(at) => write_u64(out_ns, clock::nanos(at)),
            None => Ok(RTC_EMPTY),
        })
    }
}

/// Tells the connection the time is `now_ns` (`handle_timeout`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_handle_timeout(pc: *mut PcHandle, now_ns: u64) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            h.pc.handle_timeout(clock::instant(now_ns))?;
            Ok(RTC_OK)
        })
    }
}

/// W3C `close`. What it queues (SCTP ABORT, DTLS close_notify) still comes out of
/// [`rtc_pc_poll_write`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_close(pc: *mut PcHandle) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            h.pc.close()?;
            Ok(RTC_OK)
        })
    }
}

/// W3C `getStats`: the report as a JSON object keyed by stats id. `selector` 0 is the whole
/// connection, 1 a sender (`id`), 2 a receiver (`id`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_get_stats(
    pc: *mut PcHandle,
    now_ns: u64,
    selector: u32,
    id: u64,
    out_json: *mut *mut c_char,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let selector = match selector {
                0 => StatsSelector::None,
                1 => StatsSelector::Sender(sender_id(id)?),
                2 => StatsSelector::Receiver(receiver_id(id)?),
                _ => return Err(FfiError::invalid("not a stats selector")),
            };
            let report = h.pc.get_stats(clock::instant(now_ns), selector);
            give_string(out_json, json::stats_json(&report).to_string())
        })
    }
}

/// The next command of the engine's stream interface (ICE-TCP, TURN over TCP / TLS) as JSON:
/// `listen`, `stopListening`, `connect`, `close`, `reset`, `resolve`, `resolveRecords`.
/// [`RTC_EMPTY`] when there is none; [`RTC_ERR_BUFFER_TOO_SMALL`] keeps it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_poll_stream_command(
    pc: *mut PcHandle,
    buf: *mut c_char,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            if h.pending_command.is_none()
                && let Some(command) = h.pc.poll_stream_command()
            {
                h.pending_command = Some(json::stream_command_json(command).to_string());
            }
            let Some(command) = h.pending_command.as_ref() else {
                return Ok(RTC_EMPTY);
            };
            let code = copy_out(command.as_bytes(), buf.cast(), cap, out_len);
            if code == RTC_OK {
                h.pending_command = None;
            }
            Ok(code)
        })
    }
}

/// The next bytes to write on one of the engine's connections: its id to `out_id`, the bytes
/// to `buf`. [`RTC_EMPTY`] when there are none; [`RTC_ERR_BUFFER_TOO_SMALL`] keeps them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_poll_stream_transmit(
    pc: *mut PcHandle,
    out_id: *mut u64,
    buf: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            if h.pending_transmit.is_none() {
                h.pending_transmit = h.pc.poll_stream_transmit();
            }
            let Some(t) = h.pending_transmit.as_ref() else {
                return Ok(RTC_EMPTY);
            };
            write_u64(out_id, t.id.0)?;
            let code = copy_out(&t.data, buf, cap, out_len);
            if code == RTC_OK {
                h.pending_transmit = None;
            }
            Ok(code)
        })
    }
}

/// What a socket of the stream interface did, as JSON: `{"type": "listening", "listener",
/// "local"}`, `listenFailed`, `connected` (`id`, `local`), `connectFailed`, `written` (`id`,
/// `bytes`), `closed`, `reset`, `resolved` (`query`, `addresses`), `resolvedFamily` (`query`,
/// `ipv6`, `addresses`), `resolvedRecords` (`query`, `records`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_handle_stream_event(
    pc: *mut PcHandle,
    now_ns: u64,
    event_json: *const c_char,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let event = json::stream_event(req_str(event_json, "the event")?)?;
            h.pc.handle_stream_event(clock::instant(now_ns), event)?;
            Ok(RTC_OK)
        })
    }
}

/// A connection accepted on one of the engine's listeners (`"ip:port"` addresses): the
/// connection's id to `out_id`, or [`RTC_EMPTY`] when the engine refuses it (close the socket).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_handle_stream_accepted(
    pc: *mut PcHandle,
    now_ns: u64,
    listener: u64,
    local: *const c_char,
    remote: *const c_char,
    out_id: *mut u64,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let parse = |s: &str| {
                s.parse::<SocketAddr>()
                    .map_err(|_| FfiError::invalid(format!("not a socket address: {s}")))
            };
            let local = parse(req_str(local, "the local address")?)?;
            let remote = parse(req_str(remote, "the remote address")?)?;
            match h.pc.handle_stream_accepted(
                clock::instant(now_ns),
                ListenerId(listener),
                local,
                remote,
            ) {
                Some(id) => write_u64(out_id, id.0),
                None => Ok(RTC_EMPTY),
            }
        })
    }
}

/// Bytes read from one of the engine's connections, in whatever pieces the socket gave.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_pc_handle_stream_read(
    pc: *mut PcHandle,
    now_ns: u64,
    id: u64,
    data: *const u8,
    len: usize,
) -> i32 {
    unsafe {
        with_pc(pc, |h| {
            let bytes = bytes_arg(data, len)?;
            h.pc.handle_stream_read(clock::instant(now_ns), StreamId(id), bytes)?;
            Ok(RTC_OK)
        })
    }
}
