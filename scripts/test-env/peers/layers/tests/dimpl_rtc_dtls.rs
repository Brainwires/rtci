//! rtci-dtls against dimpl 0.9.0 (str0m's DTLS, an independent implementation), DTLS 1.2
//! (RFC 6347) and 1.3 (RFC 9147), each stack in each role, in memory with virtual time:
//! the handshake, the DTLS-SRTP exporter (RFC 5764 4.2) giving both sides the same keys and
//! profile, application data both ways, close_notify (RFC 5246 7.2.1), the stateless cookie
//! exchange (HelloVerifyRequest in 1.2, RFC 6347 4.2.1; a HelloRetryRequest with a cookie in
//! 1.3, RFC 9147 5.1) and a flight lost and retransmitted (RFC 6347 4.2.4, RFC 9147 5.8).

use bytes::BytesMut;
use dimpl::{Dtls, DtlsCertificate, Output, SrtpProfile};
use dtls::config::{ClientAuthType, ConfigBuilder, DtlsVersion};
use dtls::crypto::Certificate;
use dtls::endpoint::{Endpoint, EndpointEvent};
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use shared::TransportProtocol;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Version {
    V12,
    V13,
}

/// The 32-byte ServerHello.random of a HelloRetryRequest (RFC 8446 4.1.3).
const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

fn dimpl_certificate() -> R<DtlsCertificate> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = rcgen::CertificateParams::new(vec!["dimpl".to_owned()])?.self_signed(&key)?;
    Ok(DtlsCertificate {
        certificate: cert.der().to_vec(),
        private_key: key.serialize_der(),
    })
}

struct Pair {
    rtc: Endpoint,
    dimpl: Dtls,
    rtc_addr: SocketAddr,
    dimpl_addr: SocketAddr,
    now: Instant,
    dimpl_timeout: Option<Instant>,
    // what each side reported
    rtc_complete: bool,
    rtc_data: Vec<Vec<u8>>,
    rtc_peer_closed: bool,
    dimpl_connected: bool,
    dimpl_keys: Option<(Vec<u8>, SrtpProfile)>,
    dimpl_data: Vec<Vec<u8>>,
    dimpl_close_notify: bool,
    /// rtci-dtls closed: its endpoint has dropped the association (Endpoint::close), so the
    /// close_notify the peer answers with (RFC 5246 7.2.1) finds none, and is dropped.
    rtc_closed: bool,
    // the wire, each datagram in order, and which to drop (by index in its direction)
    to_dimpl: Vec<Vec<u8>>,
    to_rtc: Vec<Vec<u8>>,
    drop_to_dimpl: Vec<usize>,
    drop_to_rtc: Vec<usize>,
}

impl Pair {
    /// `rtc_client`: rtci-dtls is the client. `rtc_cookie` / `dimpl_cookie`: the server's
    /// stateless cookie exchange.
    fn new(version: Version, rtc_client: bool, rtc_cookie: bool, dimpl_cookie: bool) -> R<Pair> {
        let provider = crypto::default_provider()?;
        let certificate =
            Certificate::generate_self_signed(vec!["rtc".to_owned()], provider.crypto())?;
        let v = match version {
            Version::V12 => DtlsVersion::Dtls1_2,
            Version::V13 => DtlsVersion::Dtls1_3,
        };
        let config = ConfigBuilder::default()
            .with_crypto_provider(provider)
            .with_certificates(vec![certificate])
            // dimpl's certificate is self-signed; WebRTC authenticates by fingerprint.
            .with_insecure_skip_verify(true)
            .with_client_auth(ClientAuthType::RequireAnyClientCert)
            .with_srtp_protection_profiles(vec![
                SrtpProtectionProfile::Srtp_Aead_Aes_256_Gcm,
                SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
                SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
            ])
            .with_cookie_exchange(rtc_cookie)
            // The version under test only: each stack then has to speak it.
            .with_protocol_versions(v, v);
        let rtc_addr: SocketAddr = "127.0.0.1:41001".parse()?;
        let dimpl_addr: SocketAddr = "127.0.0.1:41002".parse()?;
        let now = Instant::now();
        let dimpl_config = Arc::new(
            dimpl::Config::builder()
                .use_server_cookie(dimpl_cookie)
                .require_client_certificate(true)
                .build()?,
        );
        let cert = dimpl_certificate()?;
        let mut d = match version {
            Version::V12 => Dtls::new_12(dimpl_config, cert, now),
            Version::V13 => Dtls::new_13(dimpl_config, cert, now),
        };
        let rtc = if rtc_client {
            let mut e = Endpoint::new(rtc_addr, TransportProtocol::UDP, None);
            e.connect(now, dimpl_addr, Arc::new(config.build(true, None)?), None)?;
            e
        } else {
            d.set_active(true);
            Endpoint::new(
                rtc_addr,
                TransportProtocol::UDP,
                Some(Arc::new(config.build(false, None)?)),
            )
        };
        Ok(Pair {
            rtc,
            dimpl: d,
            rtc_addr,
            dimpl_addr,
            now,
            dimpl_timeout: None,
            rtc_complete: false,
            rtc_data: vec![],
            rtc_peer_closed: false,
            dimpl_connected: false,
            dimpl_keys: None,
            dimpl_data: vec![],
            dimpl_close_notify: false,
            rtc_closed: false,
            to_dimpl: vec![],
            to_rtc: vec![],
            drop_to_dimpl: vec![],
            drop_to_rtc: vec![],
        })
    }

    fn rtc_events(&mut self, events: Vec<EndpointEvent>) {
        for e in events {
            match e {
                EndpointEvent::HandshakeComplete => self.rtc_complete = true,
                EndpointEvent::ApplicationData(d) => self.rtc_data.push(d.to_vec()),
                EndpointEvent::PeerClosed => self.rtc_peer_closed = true,
                _ => {}
            }
        }
    }

    /// Moves every datagram each side has until neither has any; true if any moved.
    fn exchange(&mut self) -> R<bool> {
        let mut moved = false;
        loop {
            let mut this_round = false;
            while let Some(t) = self.rtc.poll_transmit() {
                this_round = true;
                let i = self.to_dimpl.len();
                self.to_dimpl.push(t.message.to_vec());
                if !self.drop_to_dimpl.contains(&i) {
                    self.dimpl.handle_packet(&t.message)?;
                }
            }
            let mut buf = vec![0u8; 4096];
            loop {
                let packet = match self.dimpl.poll_output(&mut buf) {
                    Output::Packet(p) => Some(p.to_vec()),
                    Output::BufferTooSmall { needed } => {
                        buf.resize(needed, 0);
                        continue;
                    }
                    Output::Timeout(t) => {
                        self.dimpl_timeout = Some(t);
                        break;
                    }
                    Output::Connected => {
                        self.dimpl_connected = true;
                        None
                    }
                    Output::KeyingMaterial(km, profile) => {
                        self.dimpl_keys = Some((km.to_vec(), profile));
                        None
                    }
                    Output::ApplicationData(d) => {
                        self.dimpl_data.push(d.to_vec());
                        None
                    }
                    Output::CloseNotify => {
                        self.dimpl_close_notify = true;
                        None
                    }
                    _ => None,
                };
                if let Some(p) = packet {
                    this_round = true;
                    let i = self.to_rtc.len();
                    self.to_rtc.push(p.clone());
                    if !self.drop_to_rtc.contains(&i) {
                        match self
                            .rtc
                            .read(self.now, self.dimpl_addr, None, BytesMut::from(&p[..]))
                        {
                            Ok(events) => self.rtc_events(events),
                            // The initiator need not wait for the answering close_notify
                            // (RFC 5246 7.2.1): after rtci-dtls closed, its read is refused.
                            Err(_) if self.rtc_closed => {}
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
            }
            if !this_round {
                return Ok(moved);
            }
            moved = true;
        }
    }

    /// Advances virtual time by `step`, firing both sides' timers.
    fn tick(&mut self, step: Duration) -> R {
        self.now += step;
        if self.dimpl_timeout.is_some_and(|t| t <= self.now) {
            self.dimpl.handle_timeout(self.now)?;
        }
        if self
            .rtc
            .poll_timeout(&self.dimpl_addr)
            .is_some_and(|t| t <= self.now)
        {
            self.rtc.handle_timeout(self.dimpl_addr, self.now)?;
        }
        Ok(())
    }

    fn run_until(&mut self, what: &str, mut done: impl FnMut(&Pair) -> bool) -> R {
        // Starts the dimpl client (its first flight goes out on the first timeout).
        self.dimpl.handle_timeout(self.now)?;
        for _ in 0..3000 {
            self.exchange()?;
            if done(self) {
                return Ok(());
            }
            self.tick(Duration::from_millis(10))?;
        }
        Err(format!("{what} within 30 s of virtual time").into())
    }

    fn handshake(&mut self) -> R {
        self.run_until("the handshake", |p| p.rtc_complete && p.dimpl_connected)
    }

    fn rtc_state(&self) -> R<&dtls::state::State> {
        Ok(self
            .rtc
            .get_connection_state(self.dimpl_addr)
            .ok_or("rtci-dtls has no connection")?)
    }
}

fn rtc_profile(p: SrtpProtectionProfile) -> &'static str {
    match p {
        SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm => "AEAD_AES_128_GCM",
        SrtpProtectionProfile::Srtp_Aead_Aes_256_Gcm => "AEAD_AES_256_GCM",
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80 => "AES128_CM_SHA1_80",
        _ => "other",
    }
}

fn dimpl_profile(p: SrtpProfile) -> &'static str {
    match p {
        SrtpProfile::AEAD_AES_128_GCM => "AEAD_AES_128_GCM",
        SrtpProfile::AEAD_AES_256_GCM => "AEAD_AES_256_GCM",
        SrtpProfile::AES128_CM_SHA1_80 => "AES128_CM_SHA1_80",
        #[allow(unreachable_patterns)]
        _ => "other",
    }
}

/// The handshake, the exported SRTP keys, data both ways and a close_notify from the client.
fn handshake_keys_data_close(version: Version, rtc_client: bool) -> R {
    let mut p = Pair::new(version, rtc_client, false, false)?;
    p.handshake()?;

    let state = p.rtc_state()?;
    let want = match version {
        Version::V12 => DtlsVersion::Dtls1_2,
        Version::V13 => DtlsVersion::Dtls1_3,
    };
    assert_eq!(state.negotiated_version(), Some(want));
    let wire = match version {
        Version::V12 => dimpl::ProtocolVersion::DTLS1_2,
        Version::V13 => dimpl::ProtocolVersion::DTLS1_3,
    };
    assert_eq!(p.dimpl.protocol_version(), Some(wire));

    // RFC 5764 4.2: both ends export the same keying material for the same profile.
    let (keys, profile) = p.dimpl_keys.clone().ok_or("dimpl exported no SRTP keys")?;
    assert_eq!(
        rtc_profile(state.srtp_protection_profile()),
        dimpl_profile(profile)
    );
    let exported = state.export_keying_material("EXTRACTOR-dtls_srtp", &[], keys.len())?;
    assert_eq!(
        exported.as_ref(),
        &keys[..],
        "the DTLS-SRTP exporter differs"
    );

    p.rtc.write(p.now, p.dimpl_addr, b"from rtci-dtls")?;
    p.dimpl.send_application_data(b"from dimpl")?;
    p.run_until("application data both ways", |p| {
        !p.rtc_data.is_empty() && !p.dimpl_data.is_empty()
    })?;
    assert_eq!(p.dimpl_data, vec![b"from rtci-dtls".to_vec()]);
    assert_eq!(p.rtc_data, vec![b"from dimpl".to_vec()]);

    if rtc_client {
        p.rtc.close(p.now)?;
        p.rtc_closed = true;
        p.run_until("dimpl to see close_notify", |p| p.dimpl_close_notify)?;
    } else {
        p.dimpl.close()?;
        p.run_until("rtci-dtls to see close_notify", |p| p.rtc_peer_closed)?;
    }
    Ok(())
}

/// The server's stateless cookie round trip, then the full handshake.
fn cookie_exchange(version: Version, rtc_client: bool) -> R {
    // The server under test sends the cookie: dimpl when rtci-dtls is the client.
    let mut p = Pair::new(version, rtc_client, !rtc_client, rtc_client)?;
    p.handshake()?;
    let from_server = if rtc_client { &p.to_rtc } else { &p.to_dimpl };
    let first = from_server.first().ok_or("the server sent nothing")?;
    match version {
        // A plaintext handshake record (type 22) holding a HelloVerifyRequest (type 3).
        Version::V12 => assert_eq!(
            (first[0], first[13]),
            (22, 3),
            "no HelloVerifyRequest first"
        ),
        // A HelloRetryRequest: a ServerHello with the special random.
        Version::V13 => assert!(
            first.windows(32).any(|w| w == HRR_RANDOM),
            "the server's first datagram is no HelloRetryRequest"
        ),
    }
    // The client's second ClientHello echoes the cookie and the handshake goes on.
    let from_client = if rtc_client { &p.to_dimpl } else { &p.to_rtc };
    assert!(from_client.len() >= 2);
    Ok(())
}

/// The server's first flight answering the ClientHello is lost once: the client's timer
/// sends its flight again, the server's answers again, and the handshake completes.
fn lost_flight(version: Version, rtc_client: bool) -> R {
    let mut p = Pair::new(version, rtc_client, false, false)?;
    // Datagram 0 from the server: the first of its ServerHello flight.
    if rtc_client {
        p.drop_to_rtc.push(0);
    } else {
        p.drop_to_dimpl.push(0);
    }
    p.handshake()?;
    // The lost datagram was sent again: a later datagram from the server carries the same
    // handshake message (its handshake header, after the 13-byte record header, is the same:
    // type, length, message_seq, fragment; RFC 6347 4.2.2, RFC 9147 5.2), whichever side's
    // timer fired first (RFC 6347 4.2.4).
    let from_server = if rtc_client { &p.to_rtc } else { &p.to_dimpl };
    let lost = from_server.first().ok_or("the server sent nothing")?;
    assert!(
        lost.len() > 25 && lost[0] == 22,
        "the lost datagram is no plaintext handshake record"
    );
    let header = &lost[13..25];
    assert!(
        from_server[1..]
            .iter()
            .any(|d| d.len() > 25 && &d[13..25] == header),
        "the lost {} handshake message was never sent again",
        lost[13]
    );
    Ok(())
}

#[test]
fn dtls12_rtc_client_dimpl_server_handshake_keys_data_close() -> R {
    handshake_keys_data_close(Version::V12, true)
}

#[test]
fn dtls12_dimpl_client_rtc_server_handshake_keys_data_close() -> R {
    handshake_keys_data_close(Version::V12, false)
}

#[test]
fn dtls13_rtc_client_dimpl_server_handshake_keys_data_close() -> R {
    handshake_keys_data_close(Version::V13, true)
}

#[test]
fn dtls13_dimpl_client_rtc_server_handshake_keys_data_close() -> R {
    handshake_keys_data_close(Version::V13, false)
}

#[test]
fn dtls12_hello_verify_request_from_dimpl_to_rtc_client() -> R {
    cookie_exchange(Version::V12, true)
}

#[test]
fn dtls12_hello_verify_request_from_rtc_to_dimpl_client() -> R {
    cookie_exchange(Version::V12, false)
}

#[test]
fn dtls13_hello_retry_request_from_dimpl_to_rtc_client() -> R {
    cookie_exchange(Version::V13, true)
}

#[test]
fn dtls13_hello_retry_request_from_rtc_to_dimpl_client() -> R {
    cookie_exchange(Version::V13, false)
}

#[test]
fn dtls12_lost_server_flight_is_retransmitted_rtc_client() -> R {
    lost_flight(Version::V12, true)
}

#[test]
fn dtls12_lost_server_flight_is_retransmitted_dimpl_client() -> R {
    lost_flight(Version::V12, false)
}

#[test]
fn dtls13_lost_server_flight_is_retransmitted_rtc_client() -> R {
    lost_flight(Version::V13, true)
}

#[test]
fn dtls13_lost_server_flight_is_retransmitted_dimpl_client() -> R {
    lost_flight(Version::V13, false)
}

/// The engine's default (DTLS 1.3 preferred, 1.2 accepted) against a dimpl that speaks 1.2
/// only, in either role: they settle on 1.2.
#[test]
fn rtc_preferring_dtls13_falls_back_to_dimpl_dtls12_in_both_roles() -> R {
    for rtc_client in [true, false] {
        let provider = crypto::default_provider()?;
        let certificate =
            Certificate::generate_self_signed(vec!["rtc".to_owned()], provider.crypto())?;
        let config = ConfigBuilder::default()
            .with_crypto_provider(provider)
            .with_certificates(vec![certificate])
            .with_insecure_skip_verify(true)
            .with_srtp_protection_profiles(vec![SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm])
            .with_cookie_exchange(false)
            .with_protocol_versions(DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_3);
        let mut p = Pair::new(Version::V12, rtc_client, false, false)?;
        let now = p.now;
        if rtc_client {
            p.rtc = Endpoint::new(p.rtc_addr, TransportProtocol::UDP, None);
            p.rtc
                .connect(now, p.dimpl_addr, Arc::new(config.build(true, None)?), None)?;
        } else {
            p.rtc = Endpoint::new(
                p.rtc_addr,
                TransportProtocol::UDP,
                Some(Arc::new(config.build(false, None)?)),
            );
        }
        p.handshake()?;
        assert_eq!(
            p.rtc_state()?.negotiated_version(),
            Some(DtlsVersion::Dtls1_2)
        );
        assert_eq!(
            p.dimpl.protocol_version(),
            Some(dimpl::ProtocolVersion::DTLS1_2)
        );
    }
    Ok(())
}
