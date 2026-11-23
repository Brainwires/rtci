//! Two peer connections driven only through the C ABI: the functions are declared here as C
//! declares them (not imported from the crate), the structs re-declared with `#[repr(C)]`, and
//! the datagrams carried in memory on a virtual clock: no socket, no wall-clock wait.

#![allow(dead_code)]

use serde_json::Value;
use std::ffi::{CStr, CString, c_char};
use std::ptr;

// Links the library whose symbols the declarations below name.
use rtc_ffi as _;

pub const RTC_OK: i32 = 0;
pub const RTC_EMPTY: i32 = 1;
pub const RTC_ERR_INVALID_ARGUMENT: i32 = -1;
pub const RTC_ERR_BUFFER_TOO_SMALL: i32 = -2;
pub const RTC_ERR_ENGINE: i32 = -3;
pub const RTC_ERR_JSON: i32 = -4;
pub const RTC_ERR_NOT_FOUND: i32 = -6;
pub const RTC_MESSAGE_RTP: u32 = 1;
pub const RTC_MESSAGE_RTCP: u32 = 2;
pub const RTC_MESSAGE_DATA: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Addr {
    pub family: u8,
    pub ip: [u8; 16],
    pub port: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Transport {
    pub local: Addr,
    pub peer: Addr,
    pub protocol: u8,
    pub ecn: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Message {
    pub kind: u32,
    pub is_string: u32,
    pub id: u64,
    pub now_ns: u64,
    pub len: usize,
}

#[repr(C)]
pub struct Pc {
    _opaque: [u8; 0],
}

unsafe extern "C" {
    pub fn rtc_abi_version() -> u32;
    pub fn rtc_last_error(buf: *mut c_char, cap: usize) -> usize;
    pub fn rtc_string_free(s: *mut c_char);
    pub fn rtc_debug_live_objects() -> i64;
    pub fn rtc_pc_new(
        configuration: *const c_char,
        settings: *const c_char,
        now_ns: u64,
        out: *mut *mut Pc,
    ) -> i32;
    pub fn rtc_pc_free(pc: *mut Pc);
    pub fn rtc_pc_create_offer(pc: *mut Pc, options: *const c_char, out: *mut *mut c_char) -> i32;
    pub fn rtc_pc_create_answer(pc: *mut Pc, options: *const c_char, out: *mut *mut c_char) -> i32;
    pub fn rtc_pc_set_local_description(pc: *mut Pc, now_ns: u64, d: *const c_char) -> i32;
    pub fn rtc_pc_set_remote_description(pc: *mut Pc, now_ns: u64, d: *const c_char) -> i32;
    pub fn rtc_pc_description(pc: *mut Pc, which: u32, out: *mut *mut c_char) -> i32;
    pub fn rtc_pc_add_local_candidate(pc: *mut Pc, c: *const c_char) -> i32;
    pub fn rtc_pc_add_remote_candidate(pc: *mut Pc, c: *const c_char) -> i32;
    pub fn rtc_pc_states(pc: *mut Pc, out: *mut *mut c_char) -> i32;
    pub fn rtc_pc_create_data_channel(
        pc: *mut Pc,
        label: *const c_char,
        init: *const c_char,
        out_id: *mut u64,
    ) -> i32;
    pub fn rtc_pc_data_channel_send(
        pc: *mut Pc,
        now_ns: u64,
        id: u64,
        data: *const u8,
        len: usize,
        is_string: u8,
    ) -> i32;
    pub fn rtc_pc_data_channel_close(pc: *mut Pc, id: u64) -> i32;
    pub fn rtc_pc_data_channel_info(pc: *mut Pc, id: u64, out: *mut *mut c_char) -> i32;
    pub fn rtc_pc_add_track(pc: *mut Pc, track: *const c_char, out_sender: *mut u64) -> i32;
    pub fn rtc_pc_add_transceiver(
        pc: *mut Pc,
        kind: *const c_char,
        init: *const c_char,
        out: *mut u64,
    ) -> i32;
    pub fn rtc_pc_transceivers(pc: *mut Pc, out: *mut *mut c_char) -> i32;
    pub fn rtc_pc_sender_info(pc: *mut Pc, sender: u64, out: *mut *mut c_char) -> i32;
    pub fn rtc_pc_receiver_info(pc: *mut Pc, receiver: u64, out: *mut *mut c_char) -> i32;
    pub fn rtc_pc_sender_write_rtp(
        pc: *mut Pc,
        now_ns: u64,
        sender: u64,
        packet: *const u8,
        len: usize,
    ) -> i32;
    pub fn rtc_pc_sender_write_frame(
        pc: *mut Pc,
        now_ns: u64,
        sender: u64,
        frame: *const u8,
        len: usize,
        samples: u32,
    ) -> i32;
    pub fn rtc_pc_handle_read(
        pc: *mut Pc,
        now_ns: u64,
        t: *const Transport,
        data: *const u8,
        len: usize,
    ) -> i32;
    pub fn rtc_pc_poll_write(
        pc: *mut Pc,
        t: *mut Transport,
        buf: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> i32;
    pub fn rtc_pc_poll_read(pc: *mut Pc, out: *mut Message, buf: *mut u8, cap: usize) -> i32;
    pub fn rtc_pc_poll_event(pc: *mut Pc, buf: *mut c_char, cap: usize, len: *mut usize) -> i32;
    pub fn rtc_pc_poll_timeout(pc: *mut Pc, out_ns: *mut u64) -> i32;
    pub fn rtc_pc_handle_timeout(pc: *mut Pc, now_ns: u64) -> i32;
    pub fn rtc_pc_close(pc: *mut Pc) -> i32;
    pub fn rtc_pc_get_stats(
        pc: *mut Pc,
        now_ns: u64,
        selector: u32,
        id: u64,
        out: *mut *mut c_char,
    ) -> i32;
}

/// This thread's last error.
pub fn last_error() -> String {
    let mut buf = vec![0 as c_char; 1024];
    let n = unsafe { rtc_last_error(buf.as_mut_ptr(), buf.len()) };
    let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert!(n >= s.to_bytes().len());
    s.to_string_lossy().into_owned()
}

/// Panics with the last error unless `code` is `RTC_OK`.
#[track_caller]
pub fn ok(code: i32) {
    assert_eq!(code, RTC_OK, "status {code}: {}", last_error());
}

pub fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// Takes a string the library returned and frees it.
pub fn take(s: *mut c_char) -> String {
    assert!(!s.is_null());
    let out = unsafe { CStr::from_ptr(s) }.to_string_lossy().into_owned();
    unsafe { rtc_string_free(s) };
    out
}

/// Calls a `char **out` function and returns the string.
pub fn out_string(f: impl FnOnce(*mut *mut c_char) -> i32) -> String {
    let mut out: *mut c_char = ptr::null_mut();
    ok(f(&mut out));
    take(out)
}

pub fn json(s: &str) -> Value {
    serde_json::from_str(s).unwrap_or_else(|e| panic!("not JSON ({e}): {s}"))
}

pub fn addr(port: u16) -> Addr {
    let mut ip = [0u8; 16];
    ip[..4].copy_from_slice(&[127, 0, 0, 1]);
    Addr {
        family: 4,
        ip,
        port,
    }
}

/// An RTP packet's wire form.
pub fn rtp(pt: u8, seq: u16, ts: u32, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x80, pt & 0x7f];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ts.to_be_bytes());
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

/// The payload of an RTP packet (fixed header, CSRCs and header extension skipped).
pub fn rtp_payload(p: &[u8]) -> &[u8] {
    let cc = (p[0] & 0x0f) as usize;
    let mut at = 12 + 4 * cc;
    if p[0] & 0x10 != 0 {
        let words = u16::from_be_bytes([p[at + 2], p[at + 3]]) as usize;
        at += 4 + 4 * words;
    }
    let end = if p[0] & 0x20 != 0 {
        p.len() - p[p.len() - 1] as usize
    } else {
        p.len()
    };
    &p[at..end]
}

pub struct Peer {
    pub pc: *mut Pc,
    pub port: u16,
    inbox: Vec<(Transport, Vec<u8>)>,
    pub events: Vec<Value>,
    pub received: Vec<(Message, Vec<u8>)>,
}

impl Peer {
    pub fn new(port: u16, settings: &str, now_ns: u64) -> Self {
        let mut pc = ptr::null_mut();
        let settings = c(settings);
        ok(unsafe { rtc_pc_new(ptr::null(), settings.as_ptr(), now_ns, &mut pc) });
        let candidate = c(&format!(
            r#"{{"candidate":"candidate:1 1 udp 2130706431 127.0.0.1 {port} typ host"}}"#
        ));
        ok(unsafe { rtc_pc_add_local_candidate(pc, candidate.as_ptr()) });
        Self {
            pc,
            port,
            inbox: vec![],
            events: vec![],
            received: vec![],
        }
    }

    /// One turn: what arrived, then events and reads; returns what it wrote.
    fn turn(&mut self, now_ns: u64) -> Vec<(Transport, Vec<u8>)> {
        for (t, data) in self.inbox.drain(..) {
            ok(unsafe { rtc_pc_handle_read(self.pc, now_ns, &t, data.as_ptr(), data.len()) });
        }
        // A deliberately small first buffer: events larger than it come back
        // RTC_ERR_BUFFER_TOO_SMALL with the length needed, and are kept for the retry.
        let mut buf = vec![0u8; 64];
        loop {
            let mut len = 0usize;
            let code =
                unsafe { rtc_pc_poll_event(self.pc, buf.as_mut_ptr().cast(), buf.len(), &mut len) };
            match code {
                RTC_OK => self
                    .events
                    .push(json(std::str::from_utf8(&buf[..len]).unwrap())),
                RTC_EMPTY => break,
                RTC_ERR_BUFFER_TOO_SMALL => buf.resize(len, 0),
                other => panic!("poll_event {other}: {}", last_error()),
            }
        }
        let mut data = vec![0u8; 256];
        loop {
            let mut m = Message::default();
            let code = unsafe { rtc_pc_poll_read(self.pc, &mut m, data.as_mut_ptr(), data.len()) };
            match code {
                RTC_OK => self.received.push((m, data[..m.len].to_vec())),
                RTC_EMPTY => break,
                RTC_ERR_BUFFER_TOO_SMALL => data.resize(m.len, 0),
                other => panic!("poll_read {other}: {}", last_error()),
            }
        }
        let mut written = vec![];
        let mut buf = vec![0u8; 1500];
        loop {
            let mut t = Transport::default();
            let mut len = 0usize;
            let code = unsafe {
                rtc_pc_poll_write(self.pc, &mut t, buf.as_mut_ptr(), buf.len(), &mut len)
            };
            match code {
                RTC_OK => written.push((t, buf[..len].to_vec())),
                RTC_EMPTY => break,
                RTC_ERR_BUFFER_TOO_SMALL => buf.resize(len, 0),
                other => panic!("poll_write {other}: {}", last_error()),
            }
        }
        written
    }

    fn deliver(&mut self, datagrams: Vec<(Transport, Vec<u8>)>) {
        for (t, data) in datagrams {
            assert_eq!(
                t.peer.port, self.port,
                "written to an address the peer never had"
            );
            self.inbox.push((
                Transport {
                    local: t.peer,
                    peer: t.local,
                    protocol: t.protocol,
                    ecn: 0,
                },
                data,
            ));
        }
    }

    pub fn timeout(&self) -> Option<u64> {
        let mut at = 0u64;
        match unsafe { rtc_pc_poll_timeout(self.pc, &mut at) } {
            RTC_OK => Some(at),
            RTC_EMPTY => None,
            other => panic!("poll_timeout {other}: {}", last_error()),
        }
    }

    pub fn states(&self) -> Value {
        json(&out_string(|out| unsafe { rtc_pc_states(self.pc, out) }))
    }

    /// The events of `type`, in order.
    pub fn events_of(&self, kind: &str) -> Vec<&Value> {
        self.events.iter().filter(|e| e["type"] == kind).collect()
    }

    pub fn data_messages(&self) -> Vec<(bool, Vec<u8>)> {
        self.received
            .iter()
            .filter(|(m, _)| m.kind == RTC_MESSAGE_DATA)
            .map(|(m, d)| (m.is_string != 0, d.clone()))
            .collect()
    }

    pub fn rtp_payloads(&self, receiver: u64) -> Vec<Vec<u8>> {
        self.received
            .iter()
            .filter(|(m, _)| m.kind == RTC_MESSAGE_RTP && m.id == receiver)
            .map(|(_, d)| rtp_payload(d).to_vec())
            .collect()
    }

    pub fn send(&self, now_ns: u64, channel: u64, data: &[u8], is_string: bool) {
        ok(unsafe {
            rtc_pc_data_channel_send(
                self.pc,
                now_ns,
                channel,
                data.as_ptr(),
                data.len(),
                u8::from(is_string),
            )
        });
    }

    pub fn free(&mut self) {
        unsafe { rtc_pc_free(self.pc) };
        self.pc = ptr::null_mut();
    }
}

pub struct Pair {
    pub offerer: Peer,
    pub answerer: Peer,
    pub now_ns: u64,
}

/// How far the virtual clock may run in one wait.
pub const DEADLINE_NS: u64 = 60_000_000_000;

impl Pair {
    pub fn new(settings: &str) -> Self {
        let now_ns = 1_000_000_000;
        Self {
            offerer: Peer::new(50100, settings, now_ns),
            answerer: Peer::new(50101, settings, now_ns),
            now_ns,
        }
    }

    /// An offer/answer exchange started by the offerer, through the JSON descriptions.
    pub fn negotiate(&mut self) {
        let now = self.now_ns;
        let (o, a) = (self.offerer.pc, self.answerer.pc);
        let offer = out_string(|out| unsafe { rtc_pc_create_offer(o, ptr::null(), out) });
        assert_eq!(json(&offer)["type"], "offer");
        let offer = c(&offer);
        ok(unsafe { rtc_pc_set_local_description(o, now, offer.as_ptr()) });
        ok(unsafe { rtc_pc_set_remote_description(a, now, offer.as_ptr()) });
        let answer = out_string(|out| unsafe { rtc_pc_create_answer(a, ptr::null(), out) });
        assert_eq!(json(&answer)["type"], "answer");
        let answer = c(&answer);
        ok(unsafe { rtc_pc_set_local_description(a, now, answer.as_ptr()) });
        ok(unsafe { rtc_pc_set_remote_description(o, now, answer.as_ptr()) });
    }

    /// Runs both peers, moving the clock to the next deadline whenever nothing is in flight,
    /// until `done` holds. Whether it came to hold within [`DEADLINE_NS`].
    pub fn run_until(&mut self, done: impl Fn(&Pair) -> bool) -> bool {
        let deadline = self.now_ns + DEADLINE_NS;
        for _ in 0..50_000 {
            if done(self) {
                return true;
            }
            if self.now_ns >= deadline {
                return false;
            }
            let written = self.offerer.turn(self.now_ns);
            self.answerer.deliver(written);
            let written = self.answerer.turn(self.now_ns);
            self.offerer.deliver(written);
            if self.offerer.inbox.is_empty() && self.answerer.inbox.is_empty() && !done(self) {
                let next = [self.offerer.timeout(), self.answerer.timeout()]
                    .into_iter()
                    .flatten()
                    .min();
                let Some(next) = next else {
                    return done(self);
                };
                self.now_ns = self.now_ns.max(next);
                ok(unsafe { rtc_pc_handle_timeout(self.offerer.pc, self.now_ns) });
                ok(unsafe { rtc_pc_handle_timeout(self.answerer.pc, self.now_ns) });
            }
        }
        done(self)
    }

    /// Runs for `span_ns` of virtual time whatever happens.
    pub fn run_for(&mut self, span_ns: u64) {
        let until = self.now_ns + span_ns;
        let _ = self.run_until(|p| p.now_ns >= until);
    }

    pub fn connected(&self) -> bool {
        self.offerer.states()["connectionState"] == "connected"
            && self.answerer.states()["connectionState"] == "connected"
    }

    pub fn free(&mut self) {
        self.offerer.free();
        self.answerer.free();
    }
}
