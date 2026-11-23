//! The driven layer through its C declarations: two peer connections that own their sockets
//! and threads, on loopback, one delivering to a callback and the other to its queue, one on a
//! shared UDP and TCP port (with the engine's ICE-TCP on), exchanging a data channel message and
//! Opus frames. One test in its own binary, so the live-object count is this test's alone.

use serde_json::{Value, json};
use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rtc_ffi as _;

const RTC_OK: i32 = 0;
const RTC_EMPTY: i32 = 1;
const RTC_ERR_INVALID_ARGUMENT: i32 = -1;

#[repr(C)]
struct Driven {
    _opaque: [u8; 0],
}
#[repr(C)]
struct Mux {
    _opaque: [u8; 0],
}

type Callback = unsafe extern "C" fn(*mut c_void, *const c_char, usize, *const u8, usize);

unsafe extern "C" {
    fn rtc_last_error(buf: *mut c_char, cap: usize) -> usize;
    fn rtc_string_free(s: *mut c_char);
    fn rtc_debug_live_objects() -> i64;
    fn rtc_mux_new(options: *const c_char, out: *mut *mut Mux) -> i32;
    fn rtc_mux_addresses(mux: *const Mux, out: *mut *mut c_char) -> i32;
    fn rtc_mux_free(mux: *mut Mux);
    fn rtc_driven_new(
        configuration: *const c_char,
        settings: *const c_char,
        options: *const c_char,
        mux: *const Mux,
        out: *mut *mut Driven,
    ) -> i32;
    fn rtc_driven_call(
        d: *const Driven,
        method: *const c_char,
        params: *const c_char,
        data: *const u8,
        len: usize,
        out: *mut *mut c_char,
    ) -> i32;
    fn rtc_driven_set_callback(d: *const Driven, cb: Option<Callback>, user: *mut c_void) -> i32;
    fn rtc_driven_wait(d: *const Driven, timeout_ms: u32) -> i32;
    fn rtc_driven_next(
        d: *const Driven,
        buf: *mut u8,
        cap: usize,
        json_len: *mut usize,
        data_len: *mut usize,
    ) -> i32;
    fn rtc_driven_free(d: *mut Driven);
}

fn last_error() -> String {
    let mut buf = vec![0 as c_char; 1024];
    unsafe { rtc_last_error(buf.as_mut_ptr(), buf.len()) };
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn call(d: *const Driven, method: &str, params: Value, data: &[u8]) -> Value {
    let (method, params) = (c(method), c(&params.to_string()));
    let mut out = ptr::null_mut();
    let code = unsafe {
        rtc_driven_call(
            d,
            method.as_ptr(),
            params.as_ptr(),
            data.as_ptr(),
            data.len(),
            &mut out,
        )
    };
    assert_eq!(code, RTC_OK, "{method:?}: {}", last_error());
    let s = unsafe { CStr::from_ptr(out) }
        .to_string_lossy()
        .into_owned();
    unsafe { rtc_string_free(out) };
    serde_json::from_str(&s).unwrap()
}

type Items = Mutex<Vec<(Value, Vec<u8>)>>;

unsafe extern "C" fn collect(
    user: *mut c_void,
    json: *const c_char,
    json_len: usize,
    data: *const u8,
    data_len: usize,
) {
    let items = unsafe { &*(user as *const Items) };
    let header = unsafe { std::slice::from_raw_parts(json.cast::<u8>(), json_len) };
    let payload = if data_len == 0 {
        vec![]
    } else {
        unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec()
    };
    items
        .lock()
        .unwrap()
        .push((serde_json::from_slice(header).unwrap(), payload));
}

/// Moves what the queue of `d` holds into `into`.
fn drain(d: *const Driven, into: &mut Vec<(Value, Vec<u8>)>) {
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let (mut j, mut n) = (0usize, 0usize);
        let code = unsafe { rtc_driven_next(d, buf.as_mut_ptr(), buf.len(), &mut j, &mut n) };
        if code == RTC_EMPTY {
            return;
        }
        assert_eq!(code, RTC_OK, "{}", last_error());
        into.push((
            serde_json::from_slice(&buf[..j]).unwrap(),
            buf[j..j + n].to_vec(),
        ));
    }
}

#[test]
fn driven_peer_connections_exchange_data_and_media_over_loopback_and_free_everything() {
    let start = unsafe { rtc_debug_live_objects() };
    let mut mux = ptr::null_mut();
    let options = c(r#"{"udp":"127.0.0.1:0","tcp":"127.0.0.1:0"}"#);
    assert_eq!(
        unsafe { rtc_mux_new(options.as_ptr(), &mut mux) },
        RTC_OK,
        "{}",
        last_error()
    );
    let mut out = ptr::null_mut();
    assert_eq!(unsafe { rtc_mux_addresses(mux, &mut out) }, RTC_OK);
    let addresses: Value =
        serde_json::from_str(&unsafe { CStr::from_ptr(out) }.to_string_lossy()).unwrap();
    unsafe { rtc_string_free(out) };
    assert!(addresses["tcp"].as_str().unwrap().starts_with("127.0.0.1:"));

    // An unspecified address cannot be a shared port: candidates carry it.
    let bad = c(r#"{"udp":"0.0.0.0:0"}"#);
    let mut nothing = ptr::null_mut();
    assert_eq!(
        unsafe { rtc_mux_new(bad.as_ptr(), &mut nothing) },
        RTC_ERR_INVALID_ARGUMENT
    );

    let settings = c(r#"{"interceptors":"minimal"}"#);
    let own = c(
        r#"{"bindAddresses":["127.0.0.1"],"includeLoopback":true,"portRange":{"min":42000,"max":42999}}"#,
    );
    let shared = c("{}");
    let (mut offerer, mut answerer) = (ptr::null_mut(), ptr::null_mut());
    assert_eq!(
        unsafe {
            rtc_driven_new(
                ptr::null(),
                settings.as_ptr(),
                own.as_ptr(),
                ptr::null(),
                &mut offerer,
            )
        },
        RTC_OK,
        "{}",
        last_error()
    );
    assert_eq!(
        unsafe {
            rtc_driven_new(
                ptr::null(),
                settings.as_ptr(),
                shared.as_ptr(),
                mux,
                &mut answerer,
            )
        },
        RTC_OK,
        "{}",
        last_error()
    );
    let local = call(offerer, "localAddresses", Value::Null, &[]);
    let port: u16 = local["udp"][0]
        .as_str()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!((42000..=42999).contains(&port), "{local}");
    assert_eq!(
        call(answerer, "localAddresses", Value::Null, &[])["mux"],
        addresses["udp"]
    );

    // The offerer delivers to a callback; the answerer to its queue.
    let items: &'static Items = Box::leak(Box::new(Mutex::new(Vec::new())));
    assert_eq!(
        unsafe {
            rtc_driven_set_callback(offerer, Some(collect), items as *const Items as *mut c_void)
        },
        RTC_OK
    );

    let unknown = c("noSuchMethod");
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe {
            rtc_driven_call(
                offerer,
                unknown.as_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                &mut out,
            )
        },
        RTC_ERR_INVALID_ARGUMENT
    );
    assert!(last_error().contains("noSuchMethod"));

    let channel = call(
        offerer,
        "createDataChannel",
        json!({ "label": "driven" }),
        &[],
    )["channel"]
        .as_u64()
        .unwrap();
    let sender = call(
        offerer,
        "addTrack",
        json!({ "kind": "audio", "id": "mic", "streamIds": ["s"] }),
        &[],
    )["sender"]
        .as_u64()
        .unwrap();
    let offer = call(offerer, "createOffer", Value::Null, &[]);
    call(offerer, "setLocalDescription", offer.clone(), &[]);
    call(answerer, "setRemoteDescription", offer, &[]);
    let answer = call(answerer, "createAnswer", Value::Null, &[]);
    call(answerer, "setLocalDescription", answer.clone(), &[]);
    call(offerer, "setRemoteDescription", answer, &[]);

    let mut at_answerer: Vec<(Value, Vec<u8>)> = vec![];
    let mut seen_offerer = 0usize;
    let (mut sent, mut frames) = (false, 0u32);
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut done = false;
    while Instant::now() < deadline && !done {
        unsafe { rtc_driven_wait(answerer, 20) };
        drain(answerer, &mut at_answerer);
        // Trickle both ways.
        let offerer_items: Vec<(Value, Vec<u8>)> = items.lock().unwrap()[seen_offerer..].to_vec();
        seen_offerer += offerer_items.len();
        for (item, _) in &offerer_items {
            if item["type"] == "icecandidate" && !item["candidate"].is_null() {
                let (m, p) = (c("addIceCandidate"), c(&item["candidate"].to_string()));
                let mut out = ptr::null_mut();
                if unsafe {
                    rtc_driven_call(answerer, m.as_ptr(), p.as_ptr(), ptr::null(), 0, &mut out)
                } == RTC_OK
                {
                    unsafe { rtc_string_free(out) };
                }
            }
            if item["type"] == "open" && item["channel"] == channel && !sent {
                call(
                    offerer,
                    "dataChannelSend",
                    json!({ "channel": channel, "isString": false }),
                    b"\x00\x01binary",
                );
                sent = true;
            }
        }
        let connected = items
            .lock()
            .unwrap()
            .iter()
            .any(|(i, _)| i["type"] == "connectionstatechange" && i["state"] == "connected");
        if connected && frames < 20 {
            call(
                offerer,
                "writeFrame",
                json!({ "sender": sender, "samples": 960 }),
                &[0xfc, frames as u8, 1, 2],
            );
            frames += 1;
        }
        let got_message = at_answerer.iter().any(|(i, d)| {
            i["type"] == "message" && i["isString"] == false && d == b"\x00\x01binary"
        });
        let got_rtp = at_answerer.iter().any(|(i, _)| i["type"] == "rtp");
        done = got_message && got_rtp;
    }
    assert!(
        done,
        "answerer items: {:?}",
        at_answerer
            .iter()
            .map(|(i, _)| i.clone())
            .collect::<Vec<_>>()
    );
    assert!(at_answerer.iter().any(|(i, _)| i["type"] == "track"));
    assert!(
        at_answerer
            .iter()
            .any(|(i, _)| i["type"] == "datachannel" && i["label"] == "driven")
    );
    let rtp = at_answerer
        .iter()
        .find(|(i, _)| i["type"] == "rtp")
        .unwrap();
    assert_eq!(rtp.1[0] >> 6, 2, "an RTP packet in its wire form");

    let stats = call(answerer, "getStats", Value::Null, &[]);
    assert!(
        stats
            .as_object()
            .unwrap()
            .values()
            .any(|s| s["type"] == "inbound-rtp"),
        "{stats}"
    );

    // Free: each thread closes its connection, says closed, and ends.
    unsafe { rtc_driven_free(offerer) };
    unsafe { rtc_driven_free(answerer) };
    unsafe { rtc_mux_free(mux) };
    assert!(
        items
            .lock()
            .unwrap()
            .iter()
            .any(|(i, _)| i["type"] == "closed")
    );
    assert_eq!(unsafe { rtc_debug_live_objects() }, start);
}
