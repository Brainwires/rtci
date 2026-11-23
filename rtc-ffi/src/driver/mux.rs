//! A UDP port, and optionally a passive ICE-TCP port, shared by many driven peer connections
//! (C: `rtc_mux`): what arrives is routed by the ICE ufrag its first Binding request names
//! (`rtc_stream_driver::sockets::UfragMux`, RFC 8445 section 7.2.2), then by its address.

use crate::{
    FfiError, FfiResult, RTC_ERR_IO, RTC_OK, give_string, guard, object_created, object_freed,
    opt_str,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::ffi::c_char;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use stream_driver::sockets::UfragMux;
use tokio::sync::mpsc::UnboundedSender;

const MAGIC: u64 = 0x7274_635f_6d75_7801; // "rtc_mux" + 1

/// What a shared port brought for one peer connection.
pub(crate) enum MuxInput {
    /// A datagram that arrived on the shared UDP port.
    Datagram {
        local: SocketAddr,
        peer: SocketAddr,
        data: Vec<u8>,
    },
    /// A connection accepted on the shared TCP port, with what was read to route it.
    Tcp {
        stream: std::net::TcpStream,
        local: SocketAddr,
        remote: SocketAddr,
        ufrag: String,
        read: Vec<u8>,
    },
}

/// The state the mux's threads and its peer connections share.
pub(crate) struct MuxShared {
    pub(crate) udp: UdpSocket,
    pub(crate) udp_addr: SocketAddr,
    pub(crate) tcp_addr: Option<SocketAddr>,
    routes: Mutex<UfragMux<u64>>,
    peers: Mutex<HashMap<u64, UnboundedSender<MuxInput>>>,
    stop: AtomicBool,
}

impl MuxShared {
    /// Joins peer connection `key`: what is routed to it goes to `tx`.
    pub(crate) fn join(&self, key: u64, tx: UnboundedSender<MuxInput>) {
        if let Ok(mut peers) = self.peers.lock() {
            peers.insert(key, tx);
        }
    }

    /// `key` answers to `ufrag`.
    pub(crate) fn register(&self, ufrag: &str, key: u64) {
        if let Ok(mut routes) = self.routes.lock()
            && routes.lookup_ufrag(ufrag) != Some(&key)
        {
            routes.register(ufrag, key);
        }
    }

    /// `key` leaves: its ufrags and addresses are forgotten.
    pub(crate) fn leave(&self, key: u64) {
        if let Ok(mut routes) = self.routes.lock() {
            routes.unregister(&key);
        }
        if let Ok(mut peers) = self.peers.lock() {
            peers.remove(&key);
        }
    }

    fn send_to(&self, key: u64, input: MuxInput) {
        if let Ok(peers) = self.peers.lock()
            && let Some(tx) = peers.get(&key)
        {
            let _ = tx.send(input);
        }
    }
}

/// A shared port (C: `rtc_mux`). Thread-safe; free it after the peer connections using it.
pub struct MuxHandle {
    magic: u64,
    pub(crate) shared: Arc<MuxShared>,
    threads: Vec<JoinHandle<()>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MuxOptions {
    /// The UDP address to bind (a concrete address: candidates carry it).
    udp: SocketAddr,
    /// The passive ICE-TCP address to bind, if any.
    tcp: Option<SocketAddr>,
}

fn udp_loop(shared: Arc<MuxShared>) {
    let mut buf = vec![0u8; 65536];
    while !shared.stop.load(Ordering::SeqCst) {
        let (n, from) = match shared.udp.recv_from(&mut buf) {
            Ok(got) => got,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                        // Windows reports an ICMP port unreachable on the next read.
                        | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                continue;
            }
            Err(_) => return,
        };
        let key = shared
            .routes
            .lock()
            .ok()
            .and_then(|mut routes| routes.route(from, &buf[..n]));
        if let Some(key) = key {
            shared.send_to(
                key,
                MuxInput::Datagram {
                    local: shared.udp_addr,
                    peer: from,
                    data: buf[..n].to_vec(),
                },
            );
        }
    }
}

fn tcp_loop(shared: Arc<MuxShared>, listener: std::net::TcpListener) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    runtime.block_on(async move {
        let Ok(listener) = tokio::net::TcpListener::from_std(listener) else {
            return;
        };
        while !shared.stop.load(Ordering::SeqCst) {
            let accepted = tokio::time::timeout(
                Duration::from_millis(200),
                stream_driver::sockets::accept_by_ufrag(&listener, Duration::from_secs(5)),
            )
            .await;
            let Ok(Ok(accepted)) = accepted else {
                continue;
            };
            let key = shared
                .routes
                .lock()
                .ok()
                .and_then(|routes| routes.lookup_ufrag(&accepted.ufrag).copied());
            let (Some(key), Ok(stream)) = (key, accepted.stream.into_std()) else {
                continue;
            };
            shared.send_to(
                key,
                MuxInput::Tcp {
                    stream,
                    local: accepted.local,
                    remote: accepted.remote,
                    ufrag: accepted.ufrag,
                    read: accepted.read,
                },
            );
        }
    });
}

impl MuxHandle {
    fn new(options: &str) -> FfiResult<Self> {
        let options: MuxOptions = serde_json::from_str(options)?;
        if options.udp.ip().is_unspecified() || options.tcp.is_some_and(|t| t.ip().is_unspecified())
        {
            return Err(FfiError::invalid(
                "bind a shared port to a concrete address: its candidates carry it",
            ));
        }
        let io = |e: std::io::Error| FfiError::new(RTC_ERR_IO, e.to_string());
        let udp = UdpSocket::bind(options.udp).map_err(io)?;
        udp.set_read_timeout(Some(Duration::from_millis(200)))
            .map_err(io)?;
        let udp_addr = udp.local_addr().map_err(io)?;
        let listener = match options.tcp {
            Some(addr) => {
                let l = std::net::TcpListener::bind(addr).map_err(io)?;
                l.set_nonblocking(true).map_err(io)?;
                Some(l)
            }
            None => None,
        };
        let tcp_addr = match &listener {
            Some(l) => Some(l.local_addr().map_err(io)?),
            None => None,
        };
        let shared = Arc::new(MuxShared {
            udp,
            udp_addr,
            tcp_addr,
            routes: Mutex::new(UfragMux::new()),
            peers: Mutex::new(HashMap::new()),
            stop: AtomicBool::new(false),
        });
        let mut threads = Vec::new();
        let s = shared.clone();
        threads.push(
            std::thread::Builder::new()
                .name("rtc-mux-udp".into())
                .spawn(move || udp_loop(s))
                .map_err(io)?,
        );
        if let Some(listener) = listener {
            let s = shared.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("rtc-mux-tcp".into())
                    .spawn(move || tcp_loop(s, listener))
                    .map_err(io)?,
            );
        }
        Ok(Self {
            magic: MAGIC,
            shared,
            threads,
        })
    }
}

/// Borrows a live mux handle.
pub(crate) unsafe fn mux_ref<'a>(mux: *const MuxHandle) -> FfiResult<Option<&'a MuxHandle>> {
    // SAFETY: a handle from `rtc_mux_new` that is not freed, or null.
    match unsafe { mux.as_ref() } {
        None => Ok(None),
        Some(m) if m.magic == MAGIC => Ok(Some(m)),
        Some(_) => Err(FfiError::invalid("not a live mux handle")),
    }
}

/// Opens a shared port: `options_json` is `{"udp": "ip:port", "tcp": "ip:port"}` (`tcp`
/// optional; port 0 picks one). Pass the handle to [`rtc_driven_new`](super::rtc_driven_new) of
/// every peer connection that is to share it; free it with [`rtc_mux_free`] after them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_mux_new(options_json: *const c_char, out: *mut *mut MuxHandle) -> i32 {
    guard(|| {
        if out.is_null() {
            return Err(FfiError::invalid("the output pointer is null"));
        }
        // SAFETY: a NUL-terminated string or null.
        let options = unsafe { opt_str(options_json) }?
            .ok_or_else(|| FfiError::invalid("the mux options are null"))?;
        let handle = Box::new(MuxHandle::new(options)?);
        object_created();
        // SAFETY: `out` is valid (checked non-null).
        unsafe { *out = Box::into_raw(handle) };
        Ok(RTC_OK)
    })
}

/// The bound addresses of a shared port: `{"udp": "ip:port", "tcp": "ip:port" or null}`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_mux_addresses(
    mux: *const MuxHandle,
    out_json: *mut *mut c_char,
) -> i32 {
    guard(|| {
        // SAFETY: as `mux_ref`.
        let m = unsafe { mux_ref(mux) }?.ok_or_else(|| FfiError::invalid("the mux is null"))?;
        let v = json!({
            "udp": m.shared.udp_addr.to_string(),
            "tcp": m.shared.tcp_addr.map(|a| a.to_string()),
        });
        // SAFETY: `out_json` is checked by `give_string`.
        unsafe { give_string(out_json, v.to_string()) }
    })
}

/// Closes a shared port and joins its threads. Null is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_mux_free(mux: *mut MuxHandle) {
    if mux.is_null() {
        return;
    }
    let _ = guard(|| {
        // SAFETY: a handle from `rtc_mux_new`, freed once.
        let m = unsafe { &mut *mux };
        if m.magic != MAGIC {
            return Err(FfiError::invalid("not a live mux handle"));
        }
        m.magic = 0;
        // SAFETY: as above.
        let mut m = unsafe { Box::from_raw(mux) };
        m.shared.stop.store(true, Ordering::SeqCst);
        for thread in m.threads.drain(..) {
            let _ = thread.join();
        }
        object_freed();
        Ok(RTC_OK)
    });
}
