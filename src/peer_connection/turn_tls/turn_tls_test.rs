use super::*;
use shared::stream::{Framing, StreamCommand, StreamConfig, StreamEvent, StreamId, StreamTable};

/// A server certificate for `name`, self-signed, and the client roots that trust it.
fn server(name: &str) -> (Arc<rustls::ServerConfig>, Arc<rustls::RootCertStore>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let der = cert.der().clone();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der.clone()).unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(rustls_provider().unwrap())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![der],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .unwrap();
    config.alpn_protocols = vec![ALPN_STUN_TURN.to_vec()];
    (Arc::new(config), Arc::new(roots))
}

/// A STUN message of 20 + `n` bytes.
fn stun(n: u16, fill: u8) -> Vec<u8> {
    let mut m = vec![0x01, 0x01];
    m.extend_from_slice(&n.to_be_bytes());
    m.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
    m.extend_from_slice(&[fill; 12]);
    m.extend(std::iter::repeat_n(fill, n as usize));
    m
}

struct Pipe {
    table: StreamTable,
    id: StreamId,
    server: rustls::ServerConnection,
    seed: u64,
}

impl Pipe {
    fn new(client: Arc<rustls::ClientConfig>, server: Arc<rustls::ServerConfig>) -> Self {
        let mut table = StreamTable::new(StreamConfig::default());
        let layer = TlsLayer::new(client, "turn.rtc.test").unwrap();
        let id = table
            .connect(
                "10.0.0.1:0".parse().unwrap(),
                "203.0.113.10:5349".parse().unwrap(),
                Framing::Turn,
                2,
                false,
                Some(Box::new(layer)),
            )
            .unwrap();
        table
            .handle_event(StreamEvent::Connected {
                id,
                local: "10.0.0.1:40000".parse().unwrap(),
            })
            .unwrap();
        Self {
            table,
            id,
            server: rustls::ServerConnection::new(server).unwrap(),
            seed: 0x51_7cc1_b727_220a,
        }
    }

    fn piece(&mut self, max: usize) -> usize {
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 7;
        self.seed ^= self.seed << 17;
        1 + (self.seed as usize) % max
    }

    /// Moves bytes both ways, cut into random pieces, until nothing moves. Returns the
    /// messages the client got and the plaintext the server got.
    fn pump(&mut self) -> shared::error::Result<(Vec<Vec<u8>>, Vec<u8>)> {
        let mut client_got = vec![];
        let mut server_got = vec![];
        for _ in 0..200 {
            let mut moved = false;
            while let Some(t) = self.table.poll_transmit() {
                let len = t.data.len();
                let mut rest = &t.data[..];
                while !rest.is_empty() {
                    let n = self.piece(97).min(rest.len());
                    let mut chunk = &rest[..n];
                    while !chunk.is_empty() {
                        self.server.read_tls(&mut chunk).unwrap();
                    }
                    self.server.process_new_packets().map_err(tls_error)?;
                    rest = &rest[n..];
                }
                self.table
                    .handle_event(StreamEvent::Written {
                        id: self.id,
                        bytes: len,
                    })
                    .unwrap();
                moved = true;
            }
            let _ = self.server.reader().read_to_end(&mut server_got);
            let mut wire = vec![];
            while self.server.wants_write() {
                self.server.write_tls(&mut wire).unwrap();
            }
            let mut rest = &wire[..];
            while !rest.is_empty() {
                let n = self.piece(131).min(rest.len());
                client_got.extend(self.table.read(self.id, &rest[..n])?);
                rest = &rest[n..];
                moved = true;
            }
            if !moved {
                break;
            }
        }
        Ok((client_got, server_got))
    }
}

#[test]
fn turn_messages_cross_tls_with_alpn_stun_turn_whatever_the_segmentation() {
    let (server_config, roots) = server("turn.rtc.test");
    let client = TurnTlsConfig {
        roots: Some(roots),
        ..Default::default()
    }
    .client_config()
    .unwrap()
    .expect("a client configuration");
    let mut pipe = Pipe::new(client, server_config);
    // Sent before the handshake: it waits for it.
    let allocate = stun(40, 7);
    pipe.table.send(pipe.id, &allocate).unwrap();
    let (_, server_got) = pipe.pump().unwrap();
    assert_eq!(
        pipe.server.alpn_protocol(),
        Some(ALPN_STUN_TURN),
        "RFC 7443"
    );
    assert_eq!(server_got, allocate);
    // The server's answer, two messages in one write.
    let (a, b) = (stun(8, 1), stun(0, 2));
    pipe.server
        .writer()
        .write_all(&[a.clone(), b.clone()].concat())
        .unwrap();
    let (client_got, _) = pipe.pump().unwrap();
    assert_eq!(client_got, vec![a, b]);
}

#[test]
fn a_server_the_roots_do_not_vouch_for_resets_the_connection() {
    let (server_config, _) = server("turn.rtc.test");
    let (_, other_roots) = server("turn.rtc.test");
    let client = TurnTlsConfig {
        roots: Some(other_roots),
        ..Default::default()
    }
    .client_config()
    .unwrap()
    .unwrap();
    let mut pipe = Pipe::new(client, server_config);
    pipe.table.send(pipe.id, &stun(0, 0)).unwrap();
    assert!(pipe.pump().is_err(), "the certificate is refused");
    let mut reset = false;
    while let Some(c) = pipe.table.poll_command() {
        reset |= c == StreamCommand::Reset { id: pipe.id };
    }
    assert!(reset);
}

#[test]
fn without_roots_or_a_verifier_no_tls_configuration_is_made() {
    assert!(TurnTlsConfig::default().client_config().unwrap().is_none());
    #[cfg(not(feature = "turn-tls-webpki-roots"))]
    assert!(
        TurnTlsConfig {
            webpki_roots: true,
            ..Default::default()
        }
        .client_config()
        .unwrap()
        .is_none()
    );
}

/// The parts of a TLS ClientHello that RFC 9325 (BCP 195, which RFC 8656 section 3.1 asks
/// for through RFC 7525) puts requirements on.
struct Hello {
    legacy_version: u16,
    suites: Vec<u16>,
    compression: Vec<u8>,
    /// (type, body) of every extension.
    extensions: Vec<(u16, Vec<u8>)>,
}

fn client_hello(config: Arc<rustls::ClientConfig>, name: &str) -> Hello {
    let mut layer = TlsLayer::new(config, name).unwrap();
    let mut wire = vec![];
    layer.write_wire(&mut wire).unwrap();
    assert_eq!(wire[0], 22, "a handshake record");
    let h = &wire[5..];
    assert_eq!(h[0], 1, "a ClientHello");
    let body = &h[4..];
    let legacy_version = u16::from_be_bytes([body[0], body[1]]);
    let mut at = 2 + 32;
    at += 1 + body[at] as usize; // session id
    let n = u16::from_be_bytes([body[at], body[at + 1]]) as usize;
    let suites = body[at + 2..at + 2 + n]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    at += 2 + n;
    let n = body[at] as usize;
    let compression = body[at + 1..at + 1 + n].to_vec();
    at += 1 + n;
    let end = at + 2 + u16::from_be_bytes([body[at], body[at + 1]]) as usize;
    at += 2;
    let mut extensions = vec![];
    while at < end {
        let kind = u16::from_be_bytes([body[at], body[at + 1]]);
        let len = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
        extensions.push((kind, body[at + 4..at + 4 + len].to_vec()));
        at += 4 + len;
    }
    Hello {
        legacy_version,
        suites,
        compression,
        extensions,
    }
}

/// RFC 8656 section 3.1 (RFC 7525 / RFC 9325) for what this client sends: TLS 1.3 and 1.2
/// only (`supported_versions`, 9325 3.1.1; with `disable_tls12` 1.3 alone), no compression
/// (3.3), SNI with the URI's host (3.7), only forward-secret AEAD suites (4.1: ECDHE with GCM
/// or ChaCha20-Poly1305 for 1.2, no NULL / RC4 / CBC / static RSA), and the renegotiation
/// signal of RFC 5746 (3.5: rustls never renegotiates; it sends the SCSV or extension).
#[test]
fn the_turn_tls_client_hello_meets_bcp_195() {
    let (_, roots) = server("turn.rtc.test");
    for disable_tls12 in [false, true] {
        let config = TurnTlsConfig {
            roots: Some(roots.clone()),
            disable_tls12,
            ..Default::default()
        }
        .client_config()
        .unwrap()
        .unwrap();
        let hello = client_hello(config, "turn.rtc.test");
        assert_eq!(hello.legacy_version, 0x0303, "legacy_version TLS 1.2");
        let versions = hello
            .extensions
            .iter()
            .find(|(k, _)| *k == 43)
            .map(|(_, b)| {
                b[1..]
                    .chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect::<Vec<_>>()
            })
            .expect("supported_versions");
        let expected = if disable_tls12 {
            vec![0x0304]
        } else {
            vec![0x0304, 0x0303]
        };
        assert_eq!(versions, expected, "nothing below TLS 1.2");
        assert_eq!(
            hello.compression,
            vec![0],
            "the null compression method only"
        );
        let sni = hello
            .extensions
            .iter()
            .find(|(k, _)| *k == 0)
            .map(|(_, b)| b[5..].to_vec())
            .expect("server_name");
        assert_eq!(sni, b"turn.rtc.test");
        // TLS 1.3 suites (0x13xx) and ECDHE AEAD TLS 1.2 suites only, or the SCSVs.
        const ALLOWED_TLS12: [u16; 6] = [0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9];
        for s in &hello.suites {
            assert!(
                (0x1301..=0x1305).contains(s) || ALLOWED_TLS12.contains(s) || *s == 0x00ff,
                "suite {s:#06x} is not a forward-secret AEAD one"
            );
        }
        if !disable_tls12 {
            assert!(
                hello.suites.contains(&0xc02f),
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (RFC 7350 section 4, RFC 9325 4.2)"
            );
            assert!(
                hello.suites.contains(&0x00ff)
                    || hello.extensions.iter().any(|(k, _)| *k == 0xff01),
                "RFC 5746 signalled"
            );
        }
    }
}
