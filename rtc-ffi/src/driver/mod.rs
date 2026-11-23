//! The driven layer (feature `driver`): a browser-like peer connection that owns its sockets
//! and a background thread (C: `rtc_driven`).
//!
//! The thread runs a tokio current-thread runtime with the sans-I/O peer connection, its UDP
//! sockets (or a share of a [`mux`] port), and the reference stream driver
//! (`examples/stream-driver`) for the engine's own TCP. The caller talks to it with
//! [`rtc_driven_call`] (a method name and JSON parameters, the same operations as the
//! sans-I/O layer, carried out by that layer's own entry points on the thread) and receives
//! what happens either through a callback ([`rtc_driven_set_callback`], called on the thread)
//! or from a queue ([`rtc_driven_wait`], [`rtc_driven_next`]).
//!
//! An item is a JSON header and, for media and data, a payload:
//!
//! * every event of `rtc_pc_poll_event` (`{"type": "icecandidate", ...}`, ...);
//! * `{"type": "message", "channel", "isString", "nowNs"}` with the data channel message;
//! * `{"type": "rtp", "receiver", "nowNs"}` and `{"type": "rtcp", ...}` with the packet;
//! * `{"type": "error", "message"}` when a datagram or a timer was refused;
//! * `{"type": "closed"}`, the last item, when the thread ends.
//!
//! A `rtc_driven` handle is thread-safe: calls may come from any thread, except from inside
//! the callback (which runs on the driver's thread: [`rtc_driven_call`] refuses there), and
//! [`rtc_driven_free`] must not overlap any other call on the handle.

pub mod mux;

use crate::json::SettingsJson;
use crate::pc::{
    PcHandle, RTC_MESSAGE_DATA, RTC_MESSAGE_RTCP, RTC_MESSAGE_RTP, rtc_pc_add_remote_candidate,
    rtc_pc_add_track, rtc_pc_add_transceiver, rtc_pc_close, rtc_pc_create_answer,
    rtc_pc_create_data_channel, rtc_pc_create_offer, rtc_pc_data_channel_close,
    rtc_pc_data_channel_info, rtc_pc_data_channel_send,
    rtc_pc_data_channel_set_buffered_amount_low_threshold, rtc_pc_description, rtc_pc_free,
    rtc_pc_get_stats, rtc_pc_ice_username_fragments, rtc_pc_receiver_info, rtc_pc_remove_track,
    rtc_pc_restart_ice, rtc_pc_sender_info, rtc_pc_sender_write_frame, rtc_pc_sender_write_rtp,
    rtc_pc_set_configuration, rtc_pc_set_local_description, rtc_pc_set_remote_description,
    rtc_pc_states, rtc_pc_transceiver_set_direction, rtc_pc_transceiver_stop, rtc_pc_transceivers,
};
use crate::{
    FfiError, FfiResult, RTC_EMPTY, RTC_ERR_BUFFER_TOO_SMALL, RTC_ERR_CLOSED, RTC_ERR_IO, RTC_OK,
    clock, give_string, guard, json, object_created, object_freed, opt_str, req_str,
};
use mux::{MuxHandle, MuxInput, MuxShared};
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::ffi::{CStr, CString, c_char, c_void};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{JoinHandle, ThreadId};
use std::time::Duration;
use stream_driver::sockets::{AddressFilter, PortRange, SharedAccept};
use stream_driver::{DriverConfig, DriverInput, StreamDriver};
use tokio::sync::mpsc;

const MAGIC: u64 = 0x7274_635f_6472_7601; // "rtc_drv" + 1

/// The callback of [`rtc_driven_set_callback`]: the user pointer, the item's JSON header (not
/// NUL-terminated) and its payload. Both buffers are valid for the call only.
pub type RtcDrivenCallback = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        json: *const c_char,
        json_len: usize,
        data: *const u8,
        data_len: usize,
    ),
>;

struct Callback {
    f: unsafe extern "C" fn(*mut c_void, *const c_char, usize, *const u8, usize),
    user: *mut c_void,
}

// SAFETY: the caller hands the user pointer to the driver's thread knowingly (the callback
// runs there); the library never dereferences it.
unsafe impl Send for Callback {}

struct Item {
    json: String,
    data: Vec<u8>,
}

#[derive(Default)]
struct Queue {
    items: VecDeque<Item>,
    callback: Option<Callback>,
    closed: bool,
}

#[derive(Default)]
struct Shared {
    queue: Mutex<Queue>,
    ready: Condvar,
}

impl Shared {
    fn push(&self, json: String, data: Vec<u8>) {
        let Ok(mut q) = self.queue.lock() else {
            return;
        };
        if let Some(cb) = q.callback.as_ref() {
            let (f, user) = (cb.f, cb.user);
            drop(q);
            // SAFETY: the caller's function, with buffers valid for the call.
            unsafe {
                f(
                    user,
                    json.as_ptr().cast(),
                    json.len(),
                    data.as_ptr(),
                    data.len(),
                )
            };
            return;
        }
        q.items.push_back(Item { json, data });
        drop(q);
        self.ready.notify_all();
    }

    fn close(&self) {
        if let Ok(mut q) = self.queue.lock() {
            q.closed = true;
        }
        self.ready.notify_all();
    }
}

type Reply = std::sync::mpsc::Sender<Result<String, FfiError>>;

enum Request {
    Call {
        method: String,
        params: Option<String>,
        data: Vec<u8>,
        reply: Reply,
    },
    Close,
}

/// A driven peer connection (C: `rtc_driven`).
pub struct DrivenHandle {
    magic: u64,
    shared: Arc<Shared>,
    requests: mpsc::UnboundedSender<Request>,
    thread: Mutex<Option<JoinHandle<()>>>,
    thread_id: ThreadId,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(deny_unknown_fields)]
struct RangeJson {
    min: u16,
    max: u16,
}

/// The driven layer's options: the server choices of the reference driver.
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DriverOptions {
    /// Only these local addresses get candidates (empty: every interface address).
    #[serde(default)]
    bind_addresses: Vec<IpAddr>,
    /// Loopback addresses too (off by default, RFC 8445 section 5.1.1.1).
    #[serde(default)]
    include_loopback: bool,
    /// IPv6 link-local addresses too.
    #[serde(default)]
    include_link_local: bool,
    /// UDP sockets and ICE-TCP listeners take ports of this range.
    port_range: Option<RangeJson>,
    /// The engine's own TCP (ICE-TCP candidates, TURN over TCP / TLS); on by default.
    tcp: Option<bool>,
    /// 1:1 NAT: the public addresses of this host (`nat1to1Ips` of the settings).
    nat_ips: Option<Vec<String>>,
    /// `"host"` (replace the host candidates' address, the default) or `"srflx"`.
    nat_candidate_type: Option<rtc::peer_connection::transport::RTCIceCandidateType>,
    /// ICE-lite (a server with a public address).
    ice_lite: Option<bool>,
}

static NEXT_KEY: AtomicU64 = AtomicU64::new(1);

/// The state of the driver's thread.
struct Driven {
    pc: *mut PcHandle,
    key: u64,
    sockets: Vec<(SocketAddr, Arc<tokio::net::UdpSocket>)>,
    mux: Option<Arc<MuxShared>>,
    stream: Option<StreamDriver>,
    shared: Arc<Shared>,
}

/// The status and message of an error the sans-I/O layer reported on this thread.
fn last(code: i32) -> FfiError {
    let mut buf = vec![0 as c_char; 4096];
    // SAFETY: a buffer of `buf.len()` bytes.
    unsafe { crate::rtc_last_error(buf.as_mut_ptr(), buf.len()) };
    // SAFETY: `rtc_last_error` NUL-terminates.
    let message = unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    FfiError::new(code, message)
}

fn check(code: i32) -> FfiResult<i32> {
    if code < 0 { Err(last(code)) } else { Ok(code) }
}

/// Calls a `char **out` entry point; `null` for RTC_EMPTY.
fn string_out(f: impl FnOnce(*mut *mut c_char) -> i32) -> FfiResult<String> {
    let mut out: *mut c_char = std::ptr::null_mut();
    if check(f(&mut out))? == RTC_EMPTY || out.is_null() {
        return Ok("null".to_owned());
    }
    // SAFETY: a string the library returned, freed once here.
    let s = unsafe { CStr::from_ptr(out) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: as above.
    unsafe { crate::rtc_string_free(out) };
    Ok(s)
}

fn cstring(s: &str) -> FfiResult<CString> {
    CString::new(s).map_err(|_| FfiError::invalid("a string with a NUL byte"))
}

fn opt_cstring(v: Option<&Value>) -> FfiResult<Option<CString>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => cstring(s).map(Some),
        Some(other) => cstring(&other.to_string()).map(Some),
    }
}

fn ptr_of(c: &Option<CString>) -> *const c_char {
    c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr())
}

fn u64_param(params: &Value, name: &str) -> FfiResult<u64> {
    params[name]
        .as_u64()
        .ok_or_else(|| FfiError::invalid(format!("the parameter `{name}` is missing")))
}

impl Driven {
    fn now(&self) -> u64 {
        clock::now_ns()
    }

    fn h(&mut self) -> &mut PcHandle {
        // SAFETY: the thread owns the handle from creation to `rtc_pc_free` at its end.
        unsafe { &mut *self.pc }
    }

    fn emit(&self, json: Value, data: Vec<u8>) {
        self.shared.push(json.to_string(), data);
    }

    /// Hands out everything the connection has: stream commands and transmits to the driver,
    /// datagrams to the sockets, events and messages to the caller.
    fn pump(&mut self) {
        loop {
            let mut progress = false;
            if self.stream.is_some() {
                while let Some(command) = self.h().pc.poll_stream_command() {
                    if let Some(s) = self.stream.as_mut() {
                        s.execute(command);
                    }
                    progress = true;
                }
                while let Some(transmit) = self.h().pc.poll_stream_transmit() {
                    if let Some(s) = self.stream.as_mut() {
                        s.write(transmit);
                    }
                    progress = true;
                }
            }
            while let Some(msg) = self.h().pc.poll_write() {
                self.send(msg);
                progress = true;
            }
            while let Some(event) = self.h().pc.poll_event() {
                let v = json::event_json(&mut self.h().pc, event);
                self.emit(v, vec![]);
                progress = true;
            }
            loop {
                match self.h().next_read() {
                    Ok(Some((meta, data))) => {
                        let v = match meta.kind {
                            RTC_MESSAGE_DATA => json!({
                                "type": "message",
                                "channel": meta.id,
                                "isString": meta.is_string != 0,
                                "nowNs": meta.now_ns,
                            }),
                            RTC_MESSAGE_RTP => {
                                json!({ "type": "rtp", "receiver": meta.id, "nowNs": meta.now_ns })
                            }
                            RTC_MESSAGE_RTCP => {
                                json!({ "type": "rtcp", "receiver": meta.id, "nowNs": meta.now_ns })
                            }
                            _ => continue,
                        };
                        self.emit(v, data);
                        progress = true;
                    }
                    Ok(None) => break,
                    Err(e) => {
                        self.emit(json!({ "type": "error", "message": e.message }), vec![]);
                        break;
                    }
                }
            }
            if !progress {
                break;
            }
        }
        self.register_ufrags();
    }

    fn register_ufrags(&mut self) {
        if let Some(mux) = self.mux.clone() {
            for ufrag in self.h().pc.ice_username_fragments() {
                mux.register(&ufrag, self.key);
            }
        }
    }

    fn send(&self, msg: TaggedBytesMut) {
        if msg.transport.transport_protocol != TransportProtocol::UDP {
            return;
        }
        let (local, peer) = (msg.transport.local_addr, msg.transport.peer_addr);
        if let Some(mux) = &self.mux
            && mux.udp_addr == local
        {
            let _ = mux.udp.send_to(&msg.message, peer);
            return;
        }
        if let Some((_, socket)) = self.sockets.iter().find(|(a, _)| *a == local) {
            // UDP: a datagram the socket cannot take now is lost, as on the wire.
            let _ = socket.try_send_to(&msg.message, peer);
        }
    }

    fn read(&mut self, local: SocketAddr, peer: SocketAddr, data: &[u8]) {
        let now = clock::instant(self.now());
        let result = self.h().pc.handle_read(TaggedBytesMut {
            now,
            transport: TransportContext {
                local_addr: local,
                peer_addr: peer,
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: data.into(),
        });
        if let Err(e) = result {
            self.emit(json!({ "type": "error", "message": e.to_string() }), vec![]);
        }
    }

    fn on_mux(&mut self, input: MuxInput) {
        match input {
            MuxInput::Datagram { local, peer, data } => self.read(local, peer, &data),
            MuxInput::Tcp {
                stream,
                local,
                remote,
                ufrag,
                read,
            } => {
                let now = clock::instant(self.now());
                let Some(listener) = self.stream.as_ref().and_then(|s| s.shared_listener()) else {
                    return;
                };
                let Ok(stream) = stream
                    .set_nonblocking(true)
                    .and_then(|_| tokio::net::TcpStream::from_std(stream))
                else {
                    return;
                };
                if let Some(id) = self
                    .h()
                    .pc
                    .handle_stream_accepted(now, listener, local, remote)
                    && let Some(driver) = self.stream.as_mut()
                {
                    driver.adopt_shared(
                        id,
                        SharedAccept {
                            stream,
                            local,
                            remote,
                            ufrag,
                            read,
                        },
                    );
                }
            }
        }
    }

    fn on_stream(&mut self, input: DriverInput) {
        let now = clock::instant(self.now());
        let result = match input {
            DriverInput::Event(event) => self.h().pc.handle_stream_event(now, event),
            DriverInput::Read { id, data } => self.h().pc.handle_stream_read(now, id, &data),
            DriverInput::Accepted(accepted) => {
                if let Some(id) = self.h().pc.handle_stream_accepted(
                    now,
                    accepted.listener,
                    accepted.local,
                    accepted.remote,
                ) && let Some(driver) = self.stream.as_mut()
                {
                    driver.adopt(id, accepted);
                }
                Ok(())
            }
        };
        if let Err(e) = result {
            self.emit(json!({ "type": "error", "message": e.to_string() }), vec![]);
        }
    }

    fn local_addresses(&self) -> Value {
        json!({
            "udp": self.sockets.iter().map(|(a, _)| a.to_string()).collect::<Vec<_>>(),
            "mux": self.mux.as_ref().map(|m| m.udp_addr.to_string()),
            "muxTcp": self.mux.as_ref().and_then(|m| m.tcp_addr).map(|a| a.to_string()),
        })
    }

    /// One call of the caller: the sans-I/O layer's entry point of that name, on this thread.
    fn dispatch(&mut self, method: &str, params: Option<&str>, data: &[u8]) -> FfiResult<String> {
        let params: Value = match params.map(str::trim) {
            None | Some("") => Value::Null,
            Some(text) => serde_json::from_str(text)?,
        };
        let pc = self.pc;
        let now = self.now();
        let none = |code: i32| check(code).map(|_| "null".to_owned());
        // SAFETY (every call below): `pc` is this thread's live handle; the strings outlive
        // the calls.
        unsafe {
            match method {
                "createOffer" => {
                    let o = opt_cstring(Some(&params))?;
                    string_out(|out| rtc_pc_create_offer(pc, ptr_of(&o), out))
                }
                "createAnswer" => {
                    let o = opt_cstring(Some(&params))?;
                    string_out(|out| rtc_pc_create_answer(pc, ptr_of(&o), out))
                }
                "setLocalDescription" | "setRemoteDescription" => {
                    let d = cstring(&params.to_string())?;
                    let code = if method == "setLocalDescription" {
                        rtc_pc_set_local_description(pc, now, d.as_ptr())
                    } else {
                        rtc_pc_set_remote_description(pc, now, d.as_ptr())
                    };
                    none(code)
                }
                "addIceCandidate" => {
                    let c = opt_cstring(Some(&params))?;
                    none(rtc_pc_add_remote_candidate(pc, ptr_of(&c)))
                }
                "restartIce" => none(rtc_pc_restart_ice(pc)),
                "setConfiguration" => {
                    let c = opt_cstring(Some(&params))?;
                    none(rtc_pc_set_configuration(pc, ptr_of(&c)))
                }
                "states" => string_out(|out| rtc_pc_states(pc, out)),
                "description" => {
                    let which = params["which"].as_u64().unwrap_or(0) as u32;
                    string_out(|out| rtc_pc_description(pc, which, out))
                }
                "iceUsernameFragments" => string_out(|out| rtc_pc_ice_username_fragments(pc, out)),
                "createDataChannel" => {
                    let label = cstring(params["label"].as_str().unwrap_or(""))?;
                    let init = opt_cstring(params.get("init"))?;
                    let mut id = 0u64;
                    check(rtc_pc_create_data_channel(
                        pc,
                        label.as_ptr(),
                        ptr_of(&init),
                        &mut id,
                    ))?;
                    Ok(json!({ "channel": id }).to_string())
                }
                "dataChannelSend" => none(rtc_pc_data_channel_send(
                    pc,
                    now,
                    u64_param(&params, "channel")?,
                    data.as_ptr(),
                    data.len(),
                    u8::from(params["isString"].as_bool().unwrap_or(false)),
                )),
                "dataChannelClose" => none(rtc_pc_data_channel_close(
                    pc,
                    u64_param(&params, "channel")?,
                )),
                "dataChannelInfo" => {
                    let id = u64_param(&params, "channel")?;
                    string_out(|out| rtc_pc_data_channel_info(pc, id, out))
                }
                "setBufferedAmountLowThreshold" => {
                    none(rtc_pc_data_channel_set_buffered_amount_low_threshold(
                        pc,
                        u64_param(&params, "channel")?,
                        u64_param(&params, "threshold")? as u32,
                    ))
                }
                "addTrack" => {
                    let t = cstring(&params.to_string())?;
                    let mut id = 0u64;
                    check(rtc_pc_add_track(pc, t.as_ptr(), &mut id))?;
                    Ok(json!({ "sender": id }).to_string())
                }
                "removeTrack" => none(rtc_pc_remove_track(pc, u64_param(&params, "sender")?)),
                "addTransceiver" => {
                    let kind = cstring(params["kind"].as_str().unwrap_or(""))?;
                    let init = opt_cstring(params.get("init"))?;
                    let mut id = 0u64;
                    check(rtc_pc_add_transceiver(
                        pc,
                        kind.as_ptr(),
                        ptr_of(&init),
                        &mut id,
                    ))?;
                    Ok(json!({ "transceiver": id }).to_string())
                }
                "transceivers" => string_out(|out| rtc_pc_transceivers(pc, out)),
                "setDirection" => {
                    let d = cstring(params["direction"].as_str().unwrap_or(""))?;
                    none(rtc_pc_transceiver_set_direction(
                        pc,
                        u64_param(&params, "transceiver")?,
                        d.as_ptr(),
                    ))
                }
                "stopTransceiver" => none(rtc_pc_transceiver_stop(
                    pc,
                    u64_param(&params, "transceiver")?,
                )),
                "senderInfo" => {
                    let id = u64_param(&params, "sender")?;
                    string_out(|out| rtc_pc_sender_info(pc, id, out))
                }
                "receiverInfo" => {
                    let id = u64_param(&params, "receiver")?;
                    string_out(|out| rtc_pc_receiver_info(pc, id, out))
                }
                "writeRtp" => none(rtc_pc_sender_write_rtp(
                    pc,
                    now,
                    u64_param(&params, "sender")?,
                    data.as_ptr(),
                    data.len(),
                )),
                "writeFrame" => none(rtc_pc_sender_write_frame(
                    pc,
                    now,
                    u64_param(&params, "sender")?,
                    data.as_ptr(),
                    data.len(),
                    u64_param(&params, "samples")? as u32,
                )),
                "getStats" => {
                    let (selector, id) = match params["selector"].as_str() {
                        Some("sender") => (1, u64_param(&params, "id")?),
                        Some("receiver") => (2, u64_param(&params, "id")?),
                        _ => (0, 0),
                    };
                    string_out(|out| rtc_pc_get_stats(pc, now, selector, id, out))
                }
                "localAddresses" => Ok(self.local_addresses().to_string()),
                "close" => none(rtc_pc_close(pc)),
                other => Err(FfiError::invalid(format!("no method `{other}`"))),
            }
        }
    }

    /// Binds the sockets and gives the engine its host candidates.
    fn gather(&mut self, options: &DriverOptions) -> FfiResult<()> {
        let io = |e: std::io::Error| FfiError::new(RTC_ERR_IO, e.to_string());
        let mut addresses = vec![];
        if let Some(mux) = &self.mux {
            addresses.push(mux.udp_addr);
        } else {
            let filter = AddressFilter {
                bind_addresses: options.bind_addresses.clone(),
                include_loopback: options.include_loopback,
                include_link_local: options.include_link_local,
                ..Default::default()
            };
            let range = match options.port_range {
                Some(r) => Some(PortRange::new(r.min, r.max).map_err(io)?),
                None => None,
            };
            for ip in filter.local_addresses().map_err(io)? {
                let socket = match range {
                    Some(range) => stream_driver::sockets::bind_udp_in_range(ip, range),
                    None => std::net::UdpSocket::bind(SocketAddr::new(ip, 0)),
                }
                .map_err(io)?;
                socket.set_nonblocking(true).map_err(io)?;
                let socket = Arc::new(tokio::net::UdpSocket::from_std(socket).map_err(io)?);
                let local = socket.local_addr().map_err(io)?;
                addresses.push(local);
                self.sockets.push((local, socket));
            }
        }
        if addresses.is_empty() {
            return Err(FfiError::new(
                RTC_ERR_IO,
                "no local address passed the filter (bindAddresses, includeLoopback)",
            ));
        }
        for local in addresses {
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
            let init = RTCIceCandidate::from(&host).to_json()?;
            self.h().pc.add_local_candidate(init)?;
        }
        // The end of this gathering: the engine holds it back until its own (TCP,
        // server-reflexive) gathering is done.
        self.h().pc.add_local_candidate(Default::default())?;
        Ok(())
    }
}

async fn next_stream(stream: &mut Option<StreamDriver>) -> DriverInput {
    match stream {
        Some(s) => s.next().await,
        None => std::future::pending().await,
    }
}

struct Setup {
    configuration: Option<String>,
    settings: Option<String>,
    options: Option<String>,
    mux: Option<Arc<MuxShared>>,
}

fn build(setup: &Setup, shared: Arc<Shared>, key: u64) -> FfiResult<(Driven, bool)> {
    let options: DriverOptions = json::parse(setup.options.as_deref())?;
    let mut settings: SettingsJson = json::parse(setup.settings.as_deref())?;
    if options.nat_ips.is_some() {
        settings.nat_1to1_ips = options.nat_ips.clone();
        settings.nat_1to1_candidate_type = options.nat_candidate_type;
    }
    if options.ice_lite.is_some() {
        settings.ice_lite = options.ice_lite;
    }
    let tcp = options.tcp.unwrap_or(true);
    settings.tcp_candidate_gathering = Some(tcp && settings.tcp_candidate_gathering != Some(false));
    let pc = Box::into_raw(Box::new(PcHandle::with_settings(
        setup.configuration.as_deref(),
        settings,
        clock::now_ns(),
    )?));
    object_created();
    let stream = tcp.then(|| {
        StreamDriver::new(DriverConfig {
            tcp_port_range: options
                .port_range
                .and_then(|r| PortRange::new(r.min, r.max).ok()),
            shared_passive: setup.mux.as_ref().and_then(|m| m.tcp_addr),
            ..Default::default()
        })
    });
    let mut driven = Driven {
        pc,
        key,
        sockets: vec![],
        mux: setup.mux.clone(),
        stream,
        shared,
    };
    if let Err(e) = driven.gather(&options) {
        // SAFETY: the handle made above, freed once.
        unsafe { rtc_pc_free(pc) };
        return Err(e);
    }
    Ok((driven, tcp))
}

fn run(
    setup: Setup,
    shared: Arc<Shared>,
    mut requests: mpsc::UnboundedReceiver<Request>,
    started: std::sync::mpsc::Sender<FfiResult<()>>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            let _ = started.send(Err(FfiError::new(RTC_ERR_IO, e.to_string())));
            shared.close();
            return;
        }
    };
    let key = NEXT_KEY.fetch_add(1, Ordering::Relaxed);
    runtime.block_on(async move {
        let (mut driven, _) = match build(&setup, shared.clone(), key) {
            Ok(d) => d,
            Err(e) => {
                let _ = started.send(Err(e));
                shared.close();
                return;
            }
        };
        let (inbound_tx, mut inbound) = mpsc::unbounded_channel::<MuxInput>();
        if let Some(mux) = &driven.mux {
            mux.join(key, inbound_tx.clone());
        }
        for (local, socket) in &driven.sockets {
            let (local, socket, tx) = (*local, socket.clone(), inbound_tx.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match socket.recv_from(&mut buf).await {
                        Ok((n, peer)) => {
                            let input = MuxInput::Datagram {
                                local,
                                peer,
                                data: buf[..n].to_vec(),
                            };
                            if tx.send(input).is_err() {
                                return;
                            }
                        }
                        // An ICMP error reported on a read (Windows): the socket goes on.
                        Err(_) => tokio::task::yield_now().await,
                    }
                }
            });
        }
        drop(inbound_tx);
        let _ = started.send(Ok(()));
        loop {
            driven.pump();
            let deadline = driven.h().pc.poll_timeout();
            let sleep = async {
                match deadline {
                    Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                request = requests.recv() => match request {
                    Some(Request::Call { method, params, data, reply }) => {
                        let result = driven.dispatch(&method, params.as_deref(), &data);
                        let _ = reply.send(result);
                    }
                    Some(Request::Close) | None => break,
                },
                Some(input) = inbound.recv() => driven.on_mux(input),
                input = next_stream(&mut driven.stream) => driven.on_stream(input),
                _ = sleep => {
                    let now = clock::instant(driven.now());
                    if let Err(e) = driven.h().pc.handle_timeout(now) {
                        driven.emit(json!({ "type": "error", "message": e.to_string() }), vec![]);
                    }
                }
            }
        }
        // Tell the remote (SCTP ABORT, DTLS close_notify) before the sockets go.
        let _ = driven.h().pc.close();
        driven.pump();
        if let Some(mux) = &driven.mux {
            mux.leave(key);
        }
        // SAFETY: the thread's handle, freed once.
        unsafe { rtc_pc_free(driven.pc) };
        driven.emit(json!({ "type": "closed" }), vec![]);
        shared.close();
    });
}

/// Borrows a live driven handle.
unsafe fn driven_ref<'a>(h: *const DrivenHandle) -> FfiResult<&'a DrivenHandle> {
    // SAFETY: a handle from `rtc_driven_new` that is not freed, or null.
    match unsafe { h.as_ref() } {
        Some(d) if d.magic == MAGIC => Ok(d),
        Some(_) => Err(FfiError::invalid(
            "not a live driven peer connection handle",
        )),
        None => Err(FfiError::invalid(
            "the driven peer connection handle is null",
        )),
    }
}

/// Creates a driven peer connection: `configuration_json` and `settings_json` as for
/// `rtc_pc_new`, `options_json` the driver's options (`bindAddresses`, `includeLoopback`,
/// `includeLinkLocal`, `portRange` `{"min","max"}`, `tcp`, `natIps`, `natCandidateType`,
/// `iceLite`), `mux` a shared port or null. The sockets are bound and the host candidates given
/// before it returns. Free with [`rtc_driven_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_driven_new(
    configuration_json: *const c_char,
    settings_json: *const c_char,
    options_json: *const c_char,
    mux: *const MuxHandle,
    out: *mut *mut DrivenHandle,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return Err(FfiError::invalid("the output pointer is null"));
        }
        // SAFETY: NUL-terminated strings or null; a mux handle or null.
        let setup = unsafe {
            Setup {
                configuration: opt_str(configuration_json)?.map(str::to_owned),
                settings: opt_str(settings_json)?.map(str::to_owned),
                options: opt_str(options_json)?.map(str::to_owned),
                mux: mux::mux_ref(mux)?.map(|m| m.shared.clone()),
            }
        };
        let shared = Arc::new(Shared::default());
        let (requests, rx) = mpsc::unbounded_channel();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let s = shared.clone();
        let thread = std::thread::Builder::new()
            .name("rtc-driven".into())
            .spawn(move || run(setup, s, rx, started_tx))
            .map_err(|e| FfiError::new(RTC_ERR_IO, e.to_string()))?;
        let thread_id = thread.thread().id();
        match started_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = thread.join();
                return Err(e);
            }
            Err(_) => {
                let _ = thread.join();
                return Err(FfiError::new(
                    RTC_ERR_IO,
                    "the driver thread ended at start",
                ));
            }
        }
        let handle = Box::new(DrivenHandle {
            magic: MAGIC,
            shared,
            requests,
            thread: Mutex::new(Some(thread)),
            thread_id,
        });
        object_created();
        // SAFETY: `out` is valid (checked non-null).
        unsafe { *out = Box::into_raw(handle) };
        Ok(RTC_OK)
    })
}

/// Calls `method` with `params_json` (and `data` for `dataChannelSend`, `writeRtp`,
/// `writeFrame`) on the driver's thread and waits for it; the result's JSON goes to
/// `out_json` (free with `rtc_string_free`; `null` for a method that returns nothing).
///
/// Methods: `createOffer` (`RTCOfferOptions`), `createAnswer`, `setLocalDescription` and
/// `setRemoteDescription` (`{"type","sdp"}`), `addIceCandidate` (`RTCIceCandidateInit` or
/// null), `restartIce`, `setConfiguration`, `states`, `description` (`{"which"}` as
/// `rtc_pc_description`), `iceUsernameFragments`, `createDataChannel` (`{"label","init"}` →
/// `{"channel"}`), `dataChannelSend` (`{"channel","isString"}`), `dataChannelClose`,
/// `dataChannelInfo`, `setBufferedAmountLowThreshold` (`{"channel","threshold"}`),
/// `addTrack` (a track → `{"sender"}`), `removeTrack` (`{"sender"}`), `addTransceiver`
/// (`{"kind","init"}` → `{"transceiver"}`), `transceivers`, `setDirection`
/// (`{"transceiver","direction"}`), `stopTransceiver`, `senderInfo` (`{"sender"}`),
/// `receiverInfo` (`{"receiver"}`), `writeRtp` (`{"sender"}`), `writeFrame`
/// (`{"sender","samples"}`), `getStats` (`{"selector": null | "sender" | "receiver", "id"}`),
/// `localAddresses`, `close`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_driven_call(
    driven: *const DrivenHandle,
    method: *const c_char,
    params_json: *const c_char,
    data: *const u8,
    len: usize,
    out_json: *mut *mut c_char,
) -> i32 {
    guard(|| {
        // SAFETY: as `driven_ref`; strings and bytes borrowed for the call.
        let (d, method, params, data) = unsafe {
            (
                driven_ref(driven)?,
                req_str(method, "the method")?,
                opt_str(params_json)?,
                crate::bytes_arg(data, len)?,
            )
        };
        if std::thread::current().id() == d.thread_id {
            return Err(FfiError::invalid(
                "rtc_driven_call from inside the callback (the driver's thread) would wait on itself",
            ));
        }
        let (reply, result) = std::sync::mpsc::channel();
        d.requests
            .send(Request::Call {
                method: method.to_owned(),
                params: params.map(str::to_owned),
                data: data.to_vec(),
                reply,
            })
            .map_err(|_| FfiError::new(RTC_ERR_CLOSED, "the driven peer connection is closed"))?;
        let value = result
            .recv()
            .map_err(|_| FfiError::new(RTC_ERR_CLOSED, "the driven peer connection is closed"))??;
        // SAFETY: `out_json` is checked by `give_string`.
        unsafe { give_string(out_json, value) }
    })
}

/// Delivers every later item to `callback` on the driver's thread instead of the queue (null
/// returns to the queue). Items already queued stay there for [`rtc_driven_next`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_driven_set_callback(
    driven: *const DrivenHandle,
    callback: RtcDrivenCallback,
    user: *mut c_void,
) -> i32 {
    guard(|| {
        // SAFETY: as `driven_ref`.
        let d = unsafe { driven_ref(driven) }?;
        let mut q = d
            .shared
            .queue
            .lock()
            .map_err(|_| FfiError::invalid("the queue is poisoned"))?;
        q.callback = callback.map(|f| Callback { f, user });
        Ok(RTC_OK)
    })
}

/// Waits up to `timeout_ms` for an item: [`RTC_OK`] when one is queued, [`RTC_EMPTY`] on
/// timeout, [`RTC_ERR_CLOSED`] when the thread ended and the queue is empty. Blocking: from
/// Deno, declare it `nonblocking`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_driven_wait(driven: *const DrivenHandle, timeout_ms: u32) -> i32 {
    guard(|| {
        // SAFETY: as `driven_ref`.
        let d = unsafe { driven_ref(driven) }?;
        let q = d
            .shared
            .queue
            .lock()
            .map_err(|_| FfiError::invalid("the queue is poisoned"))?;
        let (q, _) = d
            .shared
            .ready
            .wait_timeout_while(q, Duration::from_millis(u64::from(timeout_ms)), |q| {
                q.items.is_empty() && !q.closed
            })
            .map_err(|_| FfiError::invalid("the queue is poisoned"))?;
        Ok(if !q.items.is_empty() {
            RTC_OK
        } else if q.closed {
            RTC_ERR_CLOSED
        } else {
            RTC_EMPTY
        })
    })
}

/// Takes the next queued item: its JSON header to `buf[0..*json_len]` and its payload right
/// after it (`buf[*json_len..*json_len + *data_len]`). [`RTC_EMPTY`] when the queue is empty;
/// [`RTC_ERR_BUFFER_TOO_SMALL`] (with both lengths) keeps it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_driven_next(
    driven: *const DrivenHandle,
    buf: *mut u8,
    cap: usize,
    json_len: *mut usize,
    data_len: *mut usize,
) -> i32 {
    guard(|| {
        // SAFETY: as `driven_ref`.
        let d = unsafe { driven_ref(driven) }?;
        let mut q = d
            .shared
            .queue
            .lock()
            .map_err(|_| FfiError::invalid("the queue is poisoned"))?;
        let Some(item) = q.items.front() else {
            return Ok(RTC_EMPTY);
        };
        let (j, n) = (item.json.len(), item.data.len());
        // SAFETY: valid `size_t *` or null.
        unsafe {
            if let Some(out) = json_len.as_mut() {
                *out = j;
            }
            if let Some(out) = data_len.as_mut() {
                *out = n;
            }
        }
        if j + n > cap || buf.is_null() {
            return Ok(RTC_ERR_BUFFER_TOO_SMALL);
        }
        // SAFETY: `buf` has room for `cap >= j + n` bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(item.json.as_ptr(), buf, j);
            std::ptr::copy_nonoverlapping(item.data.as_ptr(), buf.add(j), n);
        }
        q.items.pop_front();
        Ok(RTC_OK)
    })
}

impl DrivenHandle {
    fn stop(&self) {
        let _ = self.requests.send(Request::Close);
        let thread = self.thread.lock().ok().and_then(|mut t| t.take());
        if let Some(thread) = thread
            && thread.thread().id() != std::thread::current().id()
        {
            let _ = thread.join();
        }
    }
}

/// Closes the connection (telling the remote), stops the thread and closes the sockets; the
/// handle stays valid (waits return [`RTC_ERR_CLOSED`] once the queue is drained) until
/// [`rtc_driven_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_driven_close(driven: *const DrivenHandle) -> i32 {
    guard(|| {
        // SAFETY: as `driven_ref`.
        unsafe { driven_ref(driven) }?.stop();
        Ok(RTC_OK)
    })
}

/// Closes (as [`rtc_driven_close`]) and frees a driven peer connection. Null is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_driven_free(driven: *mut DrivenHandle) {
    if driven.is_null() {
        return;
    }
    let _ = guard(|| {
        // SAFETY: a handle from `rtc_driven_new`, freed once.
        let d = unsafe { &mut *driven };
        if d.magic != MAGIC {
            return Err(FfiError::invalid(
                "not a live driven peer connection handle",
            ));
        }
        d.stop();
        d.magic = 0;
        // SAFETY: as above.
        drop(unsafe { Box::from_raw(driven) });
        object_freed();
        Ok(RTC_OK)
    });
}
