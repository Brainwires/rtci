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
