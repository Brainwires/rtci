//! Shared helpers for the interop tests.

/// Installs a process-wide rustls `CryptoProvider` if one is not already installed.
///
/// The interop tests drive the published `webrtc` crate alongside this one, and its `dtls 0.13`
/// dependency asks rustls to infer the provider from crate features. That inference only works
/// when exactly one of rustls' `ring`/`aws-lc-rs` features is enabled — but in a test build both
/// are: `dtls 0.13` turns on `rustls/ring` while `rtci` turns on whichever its own feature selects.
/// Cargo unifies the two, rustls finds an ambiguity, and the old crate panics.
///
/// Naming a provider here resolves it for that crate. `rtci` itself no longer consults this
/// default — it passes its provider explicitly (see `rtci_dtls::config`) — so which one we install
/// only has to satisfy the old code. `ring` is always available in a test build: either `rtci`
/// selected it, or `dtls 0.13` pulled it in.
///
/// Idempotent, and safe to call from every test: `install_default` returns `Err` once a provider
/// is set, which is ignored here, so the first caller wins and an application that installed its
/// own is unaffected.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// The `webrtc` crate's `SettingEngine` for an upstream peer that talks to an `rtci` peer whose
/// only host candidate is on `127.0.0.1`.
///
/// Upstream leaves loopback addresses out of gathering by default, so its host candidates are the
/// machine's LAN addresses only. Whether the loopback-bound `rtci` socket can reach those depends
/// on the OS: Linux routes `127.0.0.1` → own LAN address locally, macOS refuses it
/// (`EADDRNOTAVAIL`) and Windows refuses it (`WSAENETUNREACH`, os error 10051). Where it is refused
/// the connection hangs on whether the upstream peer's checks to `127.0.0.1` arrive first and
/// leave a peer-reflexive pair behind, which races media and the controlling side's nomination.
/// A loopback host candidate on the upstream side gives both peers a pair that works everywhere.
#[allow(dead_code)]
pub fn webrtc_setting_engine() -> webrtc::api::setting_engine::SettingEngine {
    let mut setting_engine = webrtc::api::setting_engine::SettingEngine::default();
    setting_engine.set_include_loopback_candidate(true);
    setting_engine
}

/// Whether a UDP `recv_from` error only means a datagram was lost.
///
/// On Windows a UDP socket reports an ICMP port-unreachable for an earlier `send_to` as
/// `WSAECONNRESET` (os error 10054) on its next receive. A connectivity check sent to a candidate
/// port that is gone (the other peer closed it, for instance after an ICE restart) is just a lost
/// datagram; the socket is still good and the next receive works.
#[allow(dead_code)]
pub fn udp_recv_error_is_lost_datagram(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::ConnectionReset
}
