//! A DTLS client or server on a UDP socket, for interoperability runs against another
//! implementation (`openssl s_server -dtls1_3`, `openssl s_client -dtls1_3`, ...).
//!
//! Usage:
//!
//! ```text
//! dtls_interop server <port>
//! dtls_interop client <host:port>
//! ```
//!
//! Environment:
//!
//! * `DTLS_MIN`, `DTLS_MAX`: `1.2` or `1.3` (default 1.2 to 1.3).
//! * `DTLS_SUITE`: one cipher suite by its IANA name (default: the default lists).
//! * `DTLS_COOKIE=0`: a server without the cookie exchange.
//! * `DTLS_KEY_UPDATE=1`: start a key update, asking the peer for one too, after the
//!   handshake (DTLS 1.3).
//! * `DTLS_SECONDS`: how long to run after starting (default 6).
//! * `DTLS_TICKETS=<n>`: a server that sends `n` session tickets after each handshake
//!   (DTLS 1.3), and takes them back in later ones.
//! * `DTLS_RESUME=1`: a client that keeps the tickets it is sent and, 1.5 s after its first
//!   handshake, closes the association and makes a second one from the same port, which
//!   offers one of them.
//! * `DTLS_PHA=1`: a client that offers post-handshake authentication, with a self-signed
//!   certificate to answer with (DTLS 1.3).
//! * `DTLS_REQUEST_CERT=1`: a server that asks for the client's certificate 300 ms after the
//!   handshake (post-handshake authentication, DTLS 1.3).
//!
//! It prints one line per event: `complete version=.. suite=.. resumed=.. exporter=..` (60
//! bytes of
//! keying material for the label `EXTRACTOR-dtls_srtp`), `data <text>` for application data
//! received, `closed` for the peer's close_notify, `failed` when the association failed. The
//! server uses a self-signed certificate; the client accepts any.

use bytes::BytesMut;
use rtc_dtls::cipher_suite::CipherSuiteId;
use rtc_dtls::config::{ConfigBuilder, DtlsVersion};
use rtc_dtls::crypto::Certificate;
use rtc_dtls::endpoint::{Endpoint, EndpointEvent};
use rtc_dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use shared::TransportProtocol;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn version(name: &str, default: DtlsVersion) -> DtlsVersion {
    match std::env::var(name).as_deref() {
        Ok("1.2") => DtlsVersion::Dtls1_2,
        Ok("1.3") => DtlsVersion::Dtls1_3,
        _ => default,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let role = args.next().unwrap_or_default();
    let target = args.next().unwrap_or_default();
    let is_client = match role.as_str() {
        "client" => true,
        "server" => false,
        _ => return Err("usage: dtls_interop <client host:port | server port>".into()),
    };

    let provider = crypto::default_provider()?;
    let mut builder = ConfigBuilder::default()
        .with_crypto_provider(provider.clone())
        .with_insecure_skip_verify(true)
        .with_srtp_protection_profiles(vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80])
        .with_protocol_versions(
            version("DTLS_MIN", DtlsVersion::Dtls1_2),
            version("DTLS_MAX", DtlsVersion::Dtls1_3),
        )
        .with_cookie_exchange(std::env::var("DTLS_COOKIE").as_deref() != Ok("0"));
    if let Ok(suite) = std::env::var("DTLS_SUITE") {
        builder = builder.with_cipher_suites(vec![CipherSuiteId::from(suite.as_str())]);
    }
    let resume = is_client && std::env::var("DTLS_RESUME").as_deref() == Ok("1");
    if resume {
        builder = builder
            .with_session_store(Some(Arc::new(rtc_dtls::session::MemorySessionStore::new())));
    }
    if let Some(tickets) = std::env::var("DTLS_TICKETS")
        .ok()
        .and_then(|count| count.parse().ok())
    {
        builder = builder.with_session_tickets(tickets);
    }
    if !is_client || std::env::var("DTLS_PHA").as_deref() == Ok("1") {
        builder = builder.with_certificates(vec![Certificate::generate_self_signed(
            vec![if is_client { "client" } else { "localhost" }.to_owned()],
            provider.crypto(),
        )?]);
    }
    if is_client && std::env::var("DTLS_PHA").as_deref() == Ok("1") {
        builder = builder.with_post_handshake_auth(true);
    }
    let request_certificate =
        !is_client && std::env::var("DTLS_REQUEST_CERT").as_deref() == Ok("1");
    let mut certificate_requested = false;
    let config = Arc::new(builder.build(is_client, None)?);

    let (socket, mut remote): (UdpSocket, Option<SocketAddr>) = if is_client {
        let remote = target
            .to_socket_addrs()?
            .next()
            .ok_or("no address for the server")?;
        (UdpSocket::bind("127.0.0.1:0")?, Some(remote))
    } else {
        (UdpSocket::bind(format!("127.0.0.1:{target}"))?, None)
    };
    let local = socket.local_addr()?;
    let mut endpoint = Endpoint::new(
        local,
        TransportProtocol::UDP,
        (!is_client).then(|| config.clone()),
    );
    if let Some(remote) = remote {
        endpoint.connect(Instant::now(), remote, config.clone(), None)?;
    }
    let mut reconnected = false;

    let seconds = std::env::var("DTLS_SECONDS")
        .ok()
        .and_then(|seconds| seconds.parse().ok())
        .unwrap_or(6);
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let key_update = std::env::var("DTLS_KEY_UPDATE").as_deref() == Ok("1");
    let mut complete_at = None;
    let mut key_update_sent = false;
    let mut after_key_update_sent = false;
    let mut buffer = vec![0u8; 65536];

    loop {
        while let Some(transmit) = endpoint.poll_transmit() {
            socket.send_to(&transmit.message, transmit.transport.peer_addr)?;
        }
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        // A server that authenticates its client after the handshake.
        if let (Some(at), Some(remote)) = (complete_at, remote)
            && request_certificate
            && !certificate_requested
            && now >= at + Duration::from_millis(300)
        {
            certificate_requested = true;
            match endpoint.request_client_certificate(now, remote) {
                Ok(()) => println!("certificate requested"),
                Err(err) => println!("certificate request failed: {err}"),
            }
            continue;
        }
        // A resuming client makes its second association once the tickets are in.
        if let (Some(at), Some(remote)) = (complete_at, remote)
            && resume
            && !reconnected
            && now >= at + Duration::from_millis(1500)
        {
            reconnected = true;
            complete_at = None;
            let _ = endpoint.stop(now, remote);
            while let Some(transmit) = endpoint.poll_transmit() {
                socket.send_to(&transmit.message, transmit.transport.peer_addr)?;
            }
            println!("reconnecting");
            endpoint.connect(now, remote, config.clone(), None)?;
            continue;
        }
        // After the handshake: say something, and then, if asked, update the keys and say
        // something under the new ones.
        if let (Some(at), Some(remote)) = (complete_at, remote)
            && key_update
        {
            if !key_update_sent && now >= at + Duration::from_millis(300) {
                key_update_sent = true;
                endpoint.update_keys(now, remote, true)?;
                println!("key update sent");
                continue;
            }
            // A second later the peer has acknowledged it: this goes out under the new keys.
            if key_update_sent && !after_key_update_sent && now >= at + Duration::from_millis(1300)
            {
                after_key_update_sent = true;
                endpoint.write(now, remote, b"after the key update\n")?;
                let epoch = endpoint.poll_transmit().map(|transmit| {
                    let first = transmit.message[0];
                    socket
                        .send_to(&transmit.message, transmit.transport.peer_addr)
                        .ok();
                    first & 3
                });
                println!("sent after the key update, epoch bits {epoch:?}");
                continue;
            }
        }

        let timer = remote.and_then(|remote| endpoint.poll_timeout(&remote));
        let wait = timer
            .map_or(Duration::from_millis(200), |at| {
                at.saturating_duration_since(now)
            })
            .clamp(Duration::from_millis(1), Duration::from_millis(200));
        socket.set_read_timeout(Some(wait))?;
        let events = match socket.recv_from(&mut buffer) {
            Ok((length, from)) => {
                // A server follows its latest client: one after the other.
                if is_client {
                    remote.get_or_insert(from);
                } else {
                    remote = Some(from);
                }
                match endpoint.read(
                    Instant::now(),
                    from,
                    None,
                    BytesMut::from(&buffer[..length]),
                ) {
                    Ok(events) => events,
                    Err(err) => {
                        println!("read error: {err}");
                        vec![]
                    }
                }
            }
            Err(_) => {
                if let Some(remote) = remote {
                    let now = Instant::now();
                    if endpoint.poll_timeout(&remote).is_some_and(|at| now >= at)
                        && let Err(err) = endpoint.handle_timeout(remote, now)
                    {
                        println!("timeout: {err}");
                    }
                }
                vec![]
            }
        };
        let Some(remote) = remote else { continue };
        for event in events {
            match event {
                EndpointEvent::HandshakeComplete => {
                    let state = endpoint
                        .get_connection_state(remote)
                        .ok_or("no association")?;
                    let version = state
                        .negotiated_version()
                        .map(|version| version.protocol_version());
                    println!(
                        "complete version={} suite={} srtp={:?} resumed={} exporter={}",
                        version.map_or("?".to_owned(), |v| format!(
                            "{:02X}{:02X}",
                            v.major, v.minor
                        )),
                        state
                            .cipher_suite()
                            .map_or("?".to_owned(), |s| s.to_string()),
                        state.srtp_protection_profile(),
                        state.resumed(),
                        hex(state
                            .export_keying_material("EXTRACTOR-dtls_srtp", &[], 60)?
                            .as_ref()),
                    );
                    complete_at = Some(Instant::now());
                    let greeting = if is_client {
                        &b"hello from the rtc-dtls client\n"[..]
                    } else {
                        &b"hello from the rtc-dtls server\n"[..]
                    };
                    endpoint.write(Instant::now(), remote, greeting)?;
                }
                EndpointEvent::ApplicationData(data) => {
                    println!("data {}", String::from_utf8_lossy(&data).trim_end());
                }
                EndpointEvent::PeerClosed => println!("closed"),
                EndpointEvent::PeerAuthenticated => {
                    let chain = endpoint
                        .get_connection_state(remote)
                        .map_or(0, |state| state.peer_certificates.len());
                    println!("peer authenticated certificates={chain}");
                }
                _ => {}
            }
        }
        if endpoint.is_connection_failed(&remote) {
            println!("failed");
            while let Some(transmit) = endpoint.poll_transmit() {
                socket.send_to(&transmit.message, transmit.transport.peer_addr)?;
            }
            break;
        }
    }
    endpoint.close(Instant::now())?;
    while let Some(transmit) = endpoint.poll_transmit() {
        socket.send_to(&transmit.message, transmit.transport.peer_addr)?;
    }
    Ok(())
}
