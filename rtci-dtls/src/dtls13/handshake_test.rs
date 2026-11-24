//! DTLS 1.3 handshakes between two endpoints of this crate: version negotiation, the cookie
//! exchange, every suite and group, client authentication, and what each authentication step
//! refuses.

use super::conn::*;
use super::messages::alert;
use super::record::*;
use crate::cipher_suite::CipherSuiteId;
use crate::config::{ClientAuthType, ConfigBuilder, DtlsVersion, HandshakeConfig};
use crate::crypto::Certificate;
use crate::endpoint::{Endpoint, EndpointEvent};
use crate::extension::extension_use_srtp::SrtpProtectionProfile;
use bytes::BytesMut;
use crypto::RTCCryptoProvider;
use shared::TransportProtocol;
use shared::error::{Error, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) fn client_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 6444))
}

pub(crate) fn server_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 6445))
}

pub(crate) fn provider() -> Arc<dyn RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider is enabled for tests")
}

pub(crate) fn client_builder() -> ConfigBuilder {
    ConfigBuilder::default()
        .with_crypto_provider(provider())
        .with_insecure_skip_verify(true)
        // The hybrid key share makes a ClientHello two datagrams long, with the provider
        // that has it; the tests that look at flights are written for one. It has its own
        // tests below.
        .with_post_quantum_key_share(false)
}

pub(crate) fn server_builder() -> ConfigBuilder {
    let provider = provider();
    ConfigBuilder::default()
        .with_crypto_provider(provider.clone())
        .with_insecure_skip_verify(true)
        .with_certificates(vec![
            Certificate::generate_self_signed(vec!["localhost".to_owned()], provider.crypto())
                .expect("a self-signed certificate"),
        ])
}

/// A client and a server endpoint, the client connected (its ClientHello is queued).
pub(crate) struct Pair {
    pub(crate) client: Endpoint,
    pub(crate) server: Endpoint,
    pub(crate) now: Instant,
    pub(crate) client_complete: bool,
    pub(crate) server_complete: bool,
    pub(crate) client_error: Option<Error>,
    pub(crate) server_error: Option<Error>,
    pub(crate) to_client: Vec<EndpointEvent>,
    pub(crate) to_server: Vec<EndpointEvent>,
}

pub(crate) fn take(endpoint: &mut Endpoint) -> Vec<BytesMut> {
    let mut datagrams = vec![];
    while let Some(transmit) = endpoint.poll_transmit() {
        datagrams.push(transmit.message);
    }
    datagrams
}

impl Pair {
    pub(crate) fn new(client: ConfigBuilder, server: ConfigBuilder) -> Result<Self> {
        Self::with(
            Arc::new(client.build(true, None)?),
            Arc::new(server.build(false, None)?),
        )
    }

    pub(crate) fn with(client: Arc<HandshakeConfig>, server: Arc<HandshakeConfig>) -> Result<Self> {
        let now = Instant::now();
        let mut pair = Self {
            client: Endpoint::new(client_addr(), TransportProtocol::UDP, None),
            server: Endpoint::new(server_addr(), TransportProtocol::UDP, Some(server)),
            now,
            client_complete: false,
            server_complete: false,
            client_error: None,
            server_error: None,
            to_client: vec![],
            to_server: vec![],
        };
        pair.client.connect(now, server_addr(), client, None)?;
        Ok(pair)
    }

    pub(crate) fn deliver_to_server(&mut self, datagrams: Vec<BytesMut>) {
        for datagram in datagrams {
            match self.server.read(self.now, client_addr(), None, datagram) {
                Ok(events) => {
                    for event in events {
                        self.server_complete |= matches!(event, EndpointEvent::HandshakeComplete);
                        self.to_server.push(event);
                    }
                }
                Err(err) => self.server_error = Some(err),
            }
        }
    }

    pub(crate) fn deliver_to_client(&mut self, datagrams: Vec<BytesMut>) {
        for datagram in datagrams {
            match self.client.read(self.now, server_addr(), None, datagram) {
                Ok(events) => {
                    for event in events {
                        self.client_complete |= matches!(event, EndpointEvent::HandshakeComplete);
                        self.to_client.push(event);
                    }
                }
                Err(err) => self.client_error = Some(err),
            }
        }
    }

    /// One exchange: what the client has queued goes to the server, and its answer back.
    /// Returns the datagrams of each direction.
    pub(crate) fn round(&mut self) -> (Vec<BytesMut>, Vec<BytesMut>) {
        let up = take(&mut self.client);
        self.deliver_to_server(up.clone());
        let down = take(&mut self.server);
        self.deliver_to_client(down.clone());
        (up, down)
    }

    /// Exchanges datagrams until nothing more is sent.
    pub(crate) fn run(&mut self) {
        for _ in 0..32 {
            let (up, down) = self.round();
            if up.is_empty() && down.is_empty() {
                return;
            }
        }
        panic!("the endpoints never stopped talking");
    }

    pub(crate) fn complete(mut self) -> Self {
        self.run();
        assert!(
            self.client_complete && self.server_complete,
            "the handshake did not complete (client: {} {:?}, server: {} {:?})",
            self.client_complete,
            self.client_error,
            self.server_complete,
            self.server_error
        );
        self
    }

    pub(crate) fn client_conn(&mut self) -> &mut Conn13 {
        self.client
            .connection_mut(&server_addr())
            .and_then(|conn| conn.v13.as_deref_mut())
            .expect("the client's association is DTLS 1.3")
    }

    pub(crate) fn server_conn(&mut self) -> &mut Conn13 {
        self.server
            .connection_mut(&client_addr())
            .and_then(|conn| conn.v13.as_deref_mut())
            .expect("the server's association is DTLS 1.3")
    }

    pub(crate) fn versions(&self) -> (Option<DtlsVersion>, Option<DtlsVersion>) {
        (
            self.client
                .get_connection_state(server_addr())
                .and_then(|state| state.negotiated_version()),
            self.server
                .get_connection_state(client_addr())
                .and_then(|state| state.negotiated_version()),
        )
    }

    /// Sends `data` from the client and returns what the server delivers.
    pub(crate) fn client_sends(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        self.to_server.clear();
        self.client
            .write(self.now, server_addr(), data)
            .expect("the client writes");
        self.run();
        application_data(&self.to_server)
    }

    pub(crate) fn server_sends(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        self.to_client.clear();
        self.server
            .write(self.now, client_addr(), data)
            .expect("the server writes");
        self.run();
        application_data(&self.to_client)
    }
}

pub(crate) fn application_data(events: &[EndpointEvent]) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|event| match event {
            EndpointEvent::ApplicationData(data) => Some(data.to_vec()),
            _ => None,
        })
        .collect()
}

/// The first byte of every record of `datagram`: the content type of a plaintext record, the
/// unified header's first byte for a protected one.
pub(crate) fn record_first_bytes(datagram: &[u8]) -> Vec<u8> {
    let mut rest = datagram;
    let mut first_bytes = vec![];
    while !rest.is_empty() {
        let (_, taken) = next_record(rest, 0).expect("a datagram of whole records");
        first_bytes.push(rest[0]);
        rest = &rest[taken..];
    }
    first_bytes
}

/// The alerts in the plaintext records of `datagrams`: (level, description).
pub(crate) fn plaintext_alerts(datagrams: &[BytesMut]) -> Vec<(u8, u8)> {
    let mut alerts = vec![];
    for datagram in datagrams {
        let mut rest = &datagram[..];
        while let Ok((record, taken)) = next_record(rest, 0) {
            if let DatagramRecord::Plaintext {
                content_type: CONTENT_TYPE_ALERT,
                fragment: [level, description],
                ..
            } = record
            {
                alerts.push((*level, *description));
            }
            rest = &rest[taken..];
        }
    }
    alerts
}

const SRTP_LABEL: &str = "EXTRACTOR-dtls_srtp";

#[test]
fn the_default_configuration_negotiates_dtls_1_3() -> Result<()> {
    let profile = SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm;
    let mut pair = Pair::new(
        client_builder().with_srtp_protection_profiles(vec![profile]),
        server_builder().with_srtp_protection_profiles(vec![profile]),
    )?
    .complete();
    assert_eq!(
        pair.versions(),
        (Some(DtlsVersion::Dtls1_3), Some(DtlsVersion::Dtls1_3))
    );
    assert_eq!(DtlsVersion::Dtls1_3.protocol_version().major, 0xfe);
    assert_eq!(DtlsVersion::Dtls1_3.protocol_version().minor, 0xfc);

    assert_eq!(
        pair.client_sends(b"to the server"),
        vec![b"to the server".to_vec()]
    );
    assert_eq!(
        pair.server_sends(b"to the client"),
        vec![b"to the client".to_vec()]
    );

    let client = pair.client.get_connection_state(server_addr()).unwrap();
    let server = pair.server.get_connection_state(client_addr()).unwrap();
    for state in [client, server] {
        assert_eq!(
            state.cipher_suite().map(|suite| suite.id()),
            Some(CipherSuiteId::Tls_Aes_128_Gcm_Sha256)
        );
        assert_eq!(state.srtp_protection_profile(), profile);
    }
    assert_eq!(client.peer_certificates.len(), 1);
    assert!(client.is_client() && !server.is_client());

    // RFC 8446 section 7.5, RFC 5764 section 4.2: both ends export the same keying material,
    // and it depends on the label and the context.
    let exported = client.export_keying_material(SRTP_LABEL, &[], 60)?;
    assert_eq!(exported.len(), 60);
    assert_eq!(
        exported.as_ref(),
        server.export_keying_material(SRTP_LABEL, &[], 60)?.as_ref()
    );
    assert_ne!(
        exported.as_ref(),
        client
            .export_keying_material(SRTP_LABEL, b"context", 60)?
            .as_ref()
    );
    assert_ne!(
        exported.as_ref(),
        client
            .export_keying_material("EXTRACTOR-other", &[], 60)?
            .as_ref()
    );
    // The serialized form is a DTLS 1.2 session; a DTLS 1.3 association has none.
    assert!(client.marshal_binary().is_err());
    Ok(())
}

/// RFC 9147 sections 5.1 and 6.1: ClientHello, HelloRetryRequest with a cookie, ClientHello
/// again, the server's flight (ServerHello in the clear, the rest in epoch 2), the client's
/// (epoch 2), and the server's ACK in epoch 3.
#[test]
fn the_flights_of_a_handshake_with_the_cookie_exchange() -> Result<()> {
    let mut pair = Pair::new(client_builder(), server_builder())?;

    let (client_hello, hello_retry_request) = pair.round();
    assert_eq!(client_hello.len(), 1);
    assert_eq!(
        record_first_bytes(&client_hello[0]),
        [CONTENT_TYPE_HANDSHAKE]
    );
    // ClientHello (1): legacy_version {254, 253}, an empty legacy_cookie after the empty
    // session id.
    assert_eq!(client_hello[0][13], 1);
    assert_eq!(&client_hello[0][25..27], &[254, 253]);
    assert_eq!(&client_hello[0][59..61], &[0, 0]);
    assert_eq!(hello_retry_request.len(), 1);
    assert_eq!(
        record_first_bytes(&hello_retry_request[0]),
        [CONTENT_TYPE_HANDSHAKE]
    );
    // A ServerHello (2) with message_seq 0 whose random is the HelloRetryRequest's, in a
    // record that takes the ClientHello's sequence number.
    assert_eq!(hello_retry_request[0][13], 2);
    assert_eq!(&hello_retry_request[0][17..19], &[0, 0]);
    assert_eq!(
        &hello_retry_request[0][27..59],
        &super::messages::HELLO_RETRY_REQUEST_RANDOM
    );
    assert_eq!(hello_retry_request[0][5..11], client_hello[0][5..11]);
    // The server kept nothing for the client.
    assert!(pair.server.connection_mut(&client_addr()).is_none());
    assert!(hello_retry_request[0].len() < client_hello[0].len());

    let (second_client_hello, server_flight) = pair.round();
    assert_eq!(second_client_hello.len(), 1);
    assert_eq!(second_client_hello[0][13], 1);
    assert_eq!(&second_client_hello[0][17..19], &[0, 1], "message_seq 1");
    assert!(
        second_client_hello[0].len() > client_hello[0].len(),
        "the cookie is added"
    );
    let server_records: Vec<u8> = server_flight
        .iter()
        .flat_map(|datagram| record_first_bytes(datagram))
        .collect();
    // ServerHello, then EncryptedExtensions, Certificate, CertificateVerify and Finished,
    // each in a record of epoch 2 with a 16-bit sequence number and a length.
    assert_eq!(
        server_records,
        [CONTENT_TYPE_HANDSHAKE, 0x2e, 0x2e, 0x2e, 0x2e]
    );
    assert_eq!(
        &server_flight[0][17..19],
        &[0, 1],
        "ServerHello has message_seq 1"
    );
    assert!(
        pair.client_complete,
        "the client completes on the server's Finished"
    );
    assert!(!pair.server_complete);

    let (client_flight, ack) = pair.round();
    let client_records: Vec<u8> = client_flight
        .iter()
        .flat_map(|datagram| record_first_bytes(datagram))
        .collect();
    assert_eq!(client_records, [0x2e], "the client's Finished, in epoch 2");
    assert!(pair.server_complete);
    assert_eq!(ack.len(), 1);
    assert_eq!(record_first_bytes(&ack[0]), [0x2f], "an ACK, in epoch 3");

    // The ACK ends the client's retransmission.
    assert!(pair.client_conn().flight.is_none());
    assert_eq!(pair.client.poll_timeout(&server_addr()), None);
    let (up, down) = pair.round();
    assert!(up.is_empty() && down.is_empty());
    Ok(())
}

/// The ClientHello in `datagram` (one plaintext record, the whole message): its message_seq,
/// random and whether it carries a cookie extension.
fn client_hello_of(datagram: &[u8]) -> (u16, Vec<u8>, bool) {
    assert_eq!(datagram[13], 1, "a ClientHello");
    let length = usize::from(datagram[14]) << 16
        | usize::from(datagram[15]) << 8
        | usize::from(datagram[16]);
    let hello = super::messages::ClientHello::parse(&datagram[25..25 + length])
        .expect("the ClientHello parses");
    (
        u16::from_be_bytes([datagram[17], datagram[18]]),
        hello.random.to_vec(),
        hello.extension(super::messages::EXT_COOKIE).is_some(),
    )
}

/// The cookie exchange of `pair` up to the second ClientHello, which reaches the server
/// `late` after its first: the server's answer to it.
fn second_client_hello_arrives_late(pair: &mut Pair, late: Duration) -> Vec<BytesMut> {
    let (client_hello, hello_retry_request) = pair.round();
    assert_eq!(client_hello.len(), 1);
    assert_eq!(hello_retry_request.len(), 1);
    let second = take(&mut pair.client);
    assert!(
        client_hello_of(&second[0]).2,
        "the second ClientHello has the cookie"
    );
    pair.now += late;
    pair.deliver_to_server(second);
    take(&mut pair.server)
}

/// RFC 9147 section 5.1: "If the server receives a ClientHello with an invalid cookie [...]
/// it SHOULD terminate the handshake with an "illegal_parameter" alert. This allows the
/// client to restart the connection from scratch without a cookie." A server endpoint's
/// cookie is good for one to two lifetimes of its secret (60 to 120 s): a second ClientHello
/// that reaches it later is refused. The client starts over with a new ClientHello (message
/// 0, a new random, no cookie), and the handshake completes.
#[test]
fn a_client_whose_cookie_expired_starts_over_with_a_new_client_hello() -> Result<()> {
    use crate::cookie::COOKIE_SECRET_LIFETIME;

    let mut pair = Pair::new(client_builder(), server_builder())?;
    let first = take(&mut pair.client);
    let (_, first_random, _) = client_hello_of(&first[0]);
    pair.deliver_to_server(first);
    let hello_retry_request = take(&mut pair.server);
    pair.deliver_to_client(hello_retry_request);
    let second = take(&mut pair.client);
    pair.now += 2 * COOKIE_SECRET_LIFETIME + Duration::from_secs(1);
    pair.deliver_to_server(second);
    let refusal = take(&mut pair.server);
    assert_eq!(
        plaintext_alerts(&refusal),
        vec![(2, alert::ILLEGAL_PARAMETER)],
        "the expired cookie is refused"
    );

    pair.deliver_to_client(refusal);
    assert!(pair.client_error.is_none(), "{:?}", pair.client_error);
    let fresh = take(&mut pair.client);
    assert_eq!(fresh.len(), 1, "a new ClientHello");
    let (message_seq, random, cookie) = client_hello_of(&fresh[0]);
    assert_eq!(message_seq, 0, "from scratch");
    assert!(!cookie, "without a cookie");
    assert_ne!(random, first_random, "a new random");

    pair.deliver_to_server(fresh);
    let mut pair = pair.complete();
    assert_eq!(pair.versions().0, Some(DtlsVersion::Dtls1_3));
    assert_eq!(pair.client_sends(b"fresh"), vec![b"fresh".to_vec()]);
    Ok(())
}

/// The illegal_parameter that makes a client start over comes in the clear, so it is taken
/// a bounded number of times (`MAX_FRESH_CLIENT_HELLOS`); one more and the handshake fails as
/// before.
#[test]
fn a_client_starts_over_a_bounded_number_of_times() -> Result<()> {
    use crate::conn::MAX_FRESH_CLIENT_HELLOS;
    use crate::cookie::COOKIE_SECRET_LIFETIME;

    let late = 2 * COOKIE_SECRET_LIFETIME + Duration::from_secs(1);
    let mut pair = Pair::new(client_builder(), server_builder())?;
    for attempt in 0..=MAX_FRESH_CLIENT_HELLOS {
        let refusal = second_client_hello_arrives_late(&mut pair, late);
        assert_eq!(
            plaintext_alerts(&refusal),
            vec![(2, alert::ILLEGAL_PARAMETER)]
        );
        pair.deliver_to_client(refusal);
        if attempt < MAX_FRESH_CLIENT_HELLOS {
            assert!(pair.client_error.is_none(), "attempt {attempt}");
        }
    }
    assert!(
        pair.client_error.is_some(),
        "the last refusal ends the handshake"
    );
    assert!(take(&mut pair.client).is_empty(), "no further ClientHello");
    assert!(!pair.client_complete);
    Ok(())
}

/// RFC 9147 section 5.1: where the application says the client's address is verified (ICE
/// does that), the cookie exchange can be switched off, and the handshake is one round trip.
#[test]
fn without_the_cookie_exchange_the_handshake_is_one_round_trip() -> Result<()> {
    let mut pair = Pair::new(
        client_builder(),
        server_builder().with_cookie_exchange(false),
    )?;
    let (_, server_flight) = pair.round();
    assert_eq!(server_flight[0][13], 2);
    assert_ne!(
        &server_flight[0][27..59],
        &super::messages::HELLO_RETRY_REQUEST_RANDOM
    );
    assert_eq!(
        &server_flight[0][17..19],
        &[0, 0],
        "ServerHello has message_seq 0"
    );
    assert!(pair.client_complete);
    pair.round();
    assert!(pair.server_complete);
    assert_eq!(pair.client_sends(b"data"), vec![b"data".to_vec()]);
    Ok(())
}

#[test]
fn every_tls_1_3_suite_completes_and_carries_data() -> Result<()> {
    for suite in [
        CipherSuiteId::Tls_Aes_128_Gcm_Sha256,
        CipherSuiteId::Tls_Aes_256_Gcm_Sha384,
        CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256,
        CipherSuiteId::Tls_Aes_128_Ccm_Sha256,
        CipherSuiteId::Tls_Aes_128_Ccm_8_Sha256,
    ] {
        let mut pair = Pair::new(
            client_builder().with_cipher_suites(vec![suite]),
            server_builder().with_cipher_suites(vec![suite]),
        )?
        .complete();
        let state = pair.client.get_connection_state(server_addr()).unwrap();
        assert_eq!(state.cipher_suite().map(|s| s.id()), Some(suite));
        assert_eq!(
            state.cipher_suite().map(|s| s.to_string()),
            Some(format!("{suite}"))
        );
        assert_eq!(pair.client_sends(b"x"), vec![b"x".to_vec()], "{suite}");
        assert_eq!(
            pair.server_sends(&[7; 1000]),
            vec![vec![7; 1000]],
            "{suite}"
        );
        let exported = state_export(&mut pair);
        assert_eq!(exported.0, exported.1, "{suite}");
    }
    Ok(())
}

fn state_export(pair: &mut Pair) -> (Vec<u8>, Vec<u8>) {
    let export = |endpoint: &Endpoint, remote| {
        endpoint
            .get_connection_state(remote)
            .unwrap()
            .export_keying_material(SRTP_LABEL, &[], 60)
            .unwrap()
            .as_ref()
            .to_vec()
    };
    (
        export(&pair.client, server_addr()),
        export(&pair.server, client_addr()),
    )
}

/// RFC 9147 section 5.3, RFC 8446 section 4.2.1: the version is the highest both ends have.
#[test]
fn the_version_is_negotiated_between_dtls_1_2_and_1_3() -> Result<()> {
    use DtlsVersion::{Dtls1_2, Dtls1_3};
    // (client min, client max, server min, server max, the version negotiated)
    let cases = [
        (Dtls1_2, Dtls1_3, Dtls1_2, Dtls1_3, Some(Dtls1_3)),
        (Dtls1_2, Dtls1_3, Dtls1_2, Dtls1_2, Some(Dtls1_2)),
        (Dtls1_2, Dtls1_2, Dtls1_2, Dtls1_3, Some(Dtls1_2)),
        (Dtls1_3, Dtls1_3, Dtls1_2, Dtls1_3, Some(Dtls1_3)),
        (Dtls1_2, Dtls1_3, Dtls1_3, Dtls1_3, Some(Dtls1_3)),
        (Dtls1_2, Dtls1_2, Dtls1_2, Dtls1_2, Some(Dtls1_2)),
        (Dtls1_3, Dtls1_3, Dtls1_2, Dtls1_2, None),
        (Dtls1_2, Dtls1_2, Dtls1_3, Dtls1_3, None),
    ];
    for (client_min, client_max, server_min, server_max, expected) in cases {
        for cookie_exchange in [true, false] {
            let mut pair = Pair::new(
                client_builder().with_protocol_versions(client_min, client_max),
                server_builder()
                    .with_protocol_versions(server_min, server_max)
                    .with_cookie_exchange(cookie_exchange),
            )?;
            pair.run();
            let case = format!(
                "client {client_min:?}..{client_max:?}, server {server_min:?}..{server_max:?}, cookies {cookie_exchange}"
            );
            match expected {
                Some(version) => {
                    assert!(pair.client_complete && pair.server_complete, "{case}");
                    assert_eq!(pair.versions(), (Some(version), Some(version)), "{case}");
                    assert_eq!(pair.client_sends(b"data"), vec![b"data".to_vec()], "{case}");
                }
                None => {
                    assert!(!pair.client_complete && !pair.server_complete, "{case}");
                    assert!(
                        pair.client.is_connection_failed(&server_addr()),
                        "{case}: the client was told (protocol_version)"
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn a_configuration_that_cannot_negotiate_its_versions_is_refused() {
    use DtlsVersion::{Dtls1_2, Dtls1_3};
    // The minimum above the maximum.
    assert!(
        client_builder()
            .with_protocol_versions(Dtls1_3, Dtls1_2)
            .build(true, None)
            .is_err()
    );
    // DTLS 1.3 only, with nothing but DTLS 1.2 suites, or with a pre-shared key.
    assert!(
        client_builder()
            .with_protocol_versions(Dtls1_3, Dtls1_3)
            .with_cipher_suites(vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256])
            .build(true, None)
            .is_err()
    );
    assert!(
        client_builder()
            .with_protocol_versions(Dtls1_3, Dtls1_3)
            .with_psk(Some(Arc::new(|_| Ok(vec![1, 2, 3]))))
            .with_psk_identity_hint(Some(b"hint".to_vec()))
            .build(true, None)
            .is_err()
    );
    // A list of suites is exact: the versions are those its suites belong to.
    let only_1_2 = client_builder()
        .with_cipher_suites(vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256])
        .build(true, None)
        .unwrap();
    assert!(only_1_2.supports_dtls12() && !only_1_2.supports_dtls13());
    let only_1_3 = client_builder()
        .with_cipher_suites(vec![CipherSuiteId::Tls_Aes_128_Gcm_Sha256])
        .build(true, None)
        .unwrap();
    assert!(!only_1_3.supports_dtls12() && only_1_3.supports_dtls13());
    let both = client_builder().build(true, None).unwrap();
    assert!(both.supports_dtls12() && both.supports_dtls13());
    // The CCM suites are never defaults (RFC 9147 section 4.5.3 for CCM_8).
    assert!(
        !both
            .local_tls13_cipher_suites
            .contains(&CipherSuiteId::Tls_Aes_128_Ccm_8_Sha256)
    );
}

/// A server asks for a key share of a group the client sent none for with a
/// HelloRetryRequest (RFC 8446 section 4.1.4), with or without the cookie exchange.
#[test]
fn a_hello_retry_request_asks_for_another_key_share() -> Result<()> {
    use crate::curve::named_curve::NamedCurve;
    for cookie_exchange in [true, false] {
        let client = Arc::new(client_builder().build(true, None)?);
        let mut server = server_builder()
            .with_cookie_exchange(cookie_exchange)
            .build(false, None)?;
        // The client sends shares for its first two groups; the server has the third only.
        assert_eq!(client.local_tls13_groups.len(), 3);
        server.local_tls13_groups = vec![NamedCurve::P384];
        let mut pair = Pair::with(client, Arc::new(server))?;
        let (_, hello_retry_request) = pair.round();
        assert_eq!(
            &hello_retry_request[0][27..59],
            &super::messages::HELLO_RETRY_REQUEST_RANDOM
        );
        let mut pair = pair.complete();
        assert_eq!(pair.client_sends(b"p384"), vec![b"p384".to_vec()]);
    }
    Ok(())
}

#[test]
fn a_client_certificate_is_requested_and_verified() -> Result<()> {
    let certificate =
        Certificate::generate_self_signed(vec!["client".to_owned()], provider().crypto())?;
    let der = certificate.certificate[0].as_ref().to_vec();
    let mut pair = Pair::new(
        client_builder().with_certificates(vec![certificate]),
        server_builder().with_client_auth(ClientAuthType::RequireAnyClientCert),
    )?
    .complete();
    let state = pair.server.get_connection_state(client_addr()).unwrap();
    assert_eq!(state.peer_certificates, vec![der]);

    // A client that authenticates is not done at its own Finished: the server can still
    // refuse its certificate. It completes when the server has acknowledged the flight.
    let certificate =
        Certificate::generate_self_signed(vec!["client".to_owned()], provider().crypto())?;
    let mut waiting = Pair::new(
        client_builder().with_certificates(vec![certificate]),
        server_builder()
            .with_cookie_exchange(false)
            .with_client_auth(ClientAuthType::RequireAnyClientCert),
    )?;
    let client_hello = take(&mut waiting.client);
    waiting.deliver_to_server(client_hello);
    let flight = take(&mut waiting.server);
    waiting.deliver_to_client(flight);
    assert!(
        !waiting.client_complete,
        "the server has not seen the certificate yet"
    );
    waiting.client.write(waiting.now, server_addr(), b"held")?;
    let client_flight = take(&mut waiting.client);
    assert_eq!(client_flight.len(), 1, "no application data before that");
    waiting.deliver_to_server(client_flight);
    assert!(waiting.server_complete);
    let ack = take(&mut waiting.server);
    waiting.deliver_to_client(ack);
    assert!(waiting.client_complete);
    waiting.run();
    assert_eq!(application_data(&waiting.to_server), vec![b"held".to_vec()]);
    assert_eq!(
        pair.client_sends(b"authenticated"),
        vec![b"authenticated".to_vec()]
    );

    // RFC 8446 section 4.4.2.4: a client without a certificate sends an empty Certificate,
    // which a server that requires one answers with certificate_required; one that only
    // asks goes on.
    let mut pair = Pair::new(
        client_builder(),
        server_builder().with_client_auth(ClientAuthType::RequestClientCert),
    )?
    .complete();
    assert!(
        pair.server
            .get_connection_state(client_addr())
            .unwrap()
            .peer_certificates
            .is_empty()
    );
    assert_eq!(pair.client_sends(b"anonymous"), vec![b"anonymous".to_vec()]);

    let mut pair = Pair::new(
        client_builder(),
        server_builder().with_client_auth(ClientAuthType::RequireAnyClientCert),
    )?;
    pair.run();
    assert!(!pair.server_complete);
    assert!(pair.server.is_connection_failed(&client_addr()));
    assert!(matches!(
        pair.server_error,
        Some(Error::ErrClientCertificateRequired)
    ));
    // The alert reached the client, protected, and failed its association too.
    assert!(pair.client.is_connection_failed(&server_addr()));
    assert_eq!(
        pair.client_conn().fatal_alerts().1,
        Some(alert::CERTIFICATE_REQUIRED)
    );

    // RFC 8122 section 6.2 (the SDP offer/answer model, as the peer connection sets it):
    // bad_certificate instead.
    let mut pair = Pair::new(
        client_builder(),
        server_builder()
            .with_client_auth(ClientAuthType::RequireAnyClientCert)
            .with_bad_certificate_for_a_missing_client_certificate(true),
    )?;
    pair.run();
    assert!(matches!(
        pair.server_error,
        Some(Error::ErrClientCertificateRequired)
    ));
    assert_eq!(
        pair.client_conn().fatal_alerts().1,
        Some(alert::BAD_CERTIFICATE)
    );
    Ok(())
}

#[test]
fn the_certificate_can_be_ed25519_or_ecdsa() -> Result<()> {
    let provider = provider();
    for alg in [&rcgen::PKCS_ED25519, &rcgen::PKCS_ECDSA_P256_SHA256] {
        let certificate = Certificate::generate_self_signed_with_alg(
            vec!["localhost".to_owned()],
            alg,
            provider.crypto(),
        )?;
        let mut pair = Pair::new(
            client_builder(),
            ConfigBuilder::default()
                .with_crypto_provider(provider.clone())
                .with_certificates(vec![certificate]),
        )?
        .complete();
        assert_eq!(pair.versions().0, Some(DtlsVersion::Dtls1_3));
        assert_eq!(pair.client_sends(b"signed"), vec![b"signed".to_vec()]);
    }
    Ok(())
}

#[test]
fn the_peer_certificate_callback_decides() -> Result<()> {
    // The WebRTC fingerprint check: the callback sees the certificate and its word is final.
    let seen = Arc::new(std::sync::Mutex::new(vec![]));
    let record = seen.clone();
    let mut pair = Pair::new(
        client_builder().with_verify_peer_certificate(Some(Arc::new(move |certificates, _| {
            record.lock().unwrap().extend_from_slice(certificates);
            Ok(())
        }))),
        server_builder(),
    )?
    .complete();
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert_eq!(pair.client_sends(b"ok"), vec![b"ok".to_vec()]);

    let mut pair = Pair::new(
        client_builder().with_verify_peer_certificate(Some(Arc::new(|_, _| {
            Err(Error::Other("fingerprint mismatch".to_owned()))
        }))),
        server_builder(),
    )?;
    pair.run();
    assert!(!pair.client_complete && !pair.server_complete);
    assert!(pair.client.is_connection_failed(&server_addr()));
    // bad_certificate, protected under the handshake keys, ends the server's side too.
    assert!(pair.server.is_connection_failed(&client_addr()));

    // Without the callback and without insecure_skip_verify, a self-signed certificate does
    // not chain to anything.
    let mut pair = Pair::new(
        ConfigBuilder::default()
            .with_crypto_provider(provider())
            .with_server_name("localhost".to_owned()),
        server_builder(),
    )?;
    pair.run();
    assert!(!pair.client_complete);
    assert!(pair.client.is_connection_failed(&server_addr()));
    Ok(())
}

/// What `tamper` does to the association that is about to verify its peer's Finished makes
/// the verify_data it expects differ: decrypt_error (RFC 8446 section 4.4.4).
#[test]
fn a_finished_that_does_not_verify_is_a_decrypt_error() -> Result<()> {
    // The client's view of the server's Finished.
    let mut pair = Pair::new(
        client_builder(),
        server_builder().with_cookie_exchange(false),
    )?;
    let client_hello = take(&mut pair.client);
    pair.deliver_to_server(client_hello);
    let flight = take(&mut pair.server);
    // The ServerHello alone first, so that the client holds the handshake secrets.
    let split = 13 + u16::from_be_bytes([flight[0][11], flight[0][12]]) as usize;
    pair.deliver_to_client(vec![BytesMut::from(&flight[0][..split])]);
    let schedule = pair.client_conn().schedule.as_mut().unwrap();
    schedule.server_handshake_traffic = Some(crypto::SecretVec::new(vec![0x5a; 32]));
    pair.deliver_to_client(vec![BytesMut::from(&flight[0][split..])]);
    assert!(!pair.client_complete);
    assert!(matches!(
        pair.client_error,
        Some(Error::ErrVerifyDataMismatch)
    ));
    assert!(pair.client.is_connection_failed(&server_addr()));
    let alerts = take(&mut pair.client);
    assert_eq!(alerts.len(), 1);
    pair.deliver_to_server(alerts);
    assert!(pair.server.is_connection_failed(&client_addr()));

    // The server's view of the client's Finished.
    let mut pair = Pair::new(
        client_builder(),
        server_builder().with_cookie_exchange(false),
    )?;
    let client_hello = take(&mut pair.client);
    pair.deliver_to_server(client_hello);
    let schedule = pair.server_conn().schedule.as_mut().unwrap();
    schedule.client_handshake_traffic = Some(crypto::SecretVec::new(vec![0x5a; 32]));
    pair.run();
    assert!(pair.client_complete && !pair.server_complete);
    assert!(matches!(
        pair.server_error,
        Some(Error::ErrVerifyDataMismatch)
    ));
    assert!(pair.server.is_connection_failed(&client_addr()));
    assert!(
        pair.client.is_connection_failed(&server_addr()),
        "told by the alert"
    );
    let _ = alert::DECRYPT_ERROR;
    Ok(())
}

#[test]
fn the_handshake_survives_a_small_mtu() -> Result<()> {
    let mut pair = Pair::new(
        client_builder().with_mtu(200),
        server_builder().with_mtu(200),
    )?;
    for _ in 0..32 {
        let (up, down) = pair.round();
        for datagram in up.iter().chain(down.iter()) {
            assert!(
                datagram.len() <= 200,
                "a datagram of {} bytes",
                datagram.len()
            );
        }
        if up.is_empty() && down.is_empty() {
            break;
        }
    }
    assert!(pair.client_complete && pair.server_complete);
    assert_eq!(
        pair.client_sends(b"fragmented"),
        vec![b"fragmented".to_vec()]
    );
    Ok(())
}

#[test]
fn a_handshake_nobody_answers_fails_at_its_deadline() -> Result<()> {
    let mut pair = Pair::new(
        client_builder().with_handshake_timeout(Some(Duration::from_secs(5))),
        server_builder(),
    )?;
    let _lost = take(&mut pair.client);
    let mut now = pair.now;
    let mut failed = false;
    for _ in 0..16 {
        let Some(at) = pair.client.poll_timeout(&server_addr()) else {
            break;
        };
        now = at;
        if pair.client.handle_timeout(server_addr(), now).is_err() {
            failed = true;
            break;
        }
    }
    assert!(failed && pair.client.is_connection_failed(&server_addr()));
    assert!(now.duration_since(pair.now) >= Duration::from_secs(5));
    Ok(())
}

/// A self-signed certificate over the RSA test key.
fn rsa_certificate() -> Certificate {
    let key_pair = rcgen::KeyPair::from_pem(include_str!("testdata/rsa-2048.pkcs8.pem"))
        .expect("an RSA key pair");
    let certificate = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .expect("certificate parameters")
        .self_signed(&key_pair)
        .expect("a self-signed certificate");
    Certificate {
        certificate: vec![certificate.der().to_owned()],
        private_key: crate::crypto::CryptoPrivateKey::from_key_pair(&key_pair, provider().crypto())
            .expect("the key imports"),
    }
}

/// RFC 8446 section 4.2.3: an RSA key signs the handshake with RSASSA-PSS, always in DTLS 1.3
/// and, where both ends list it and the server prefers it, in DTLS 1.2.
#[test]
fn an_rsa_certificate_signs_with_rsassa_pss() -> Result<()> {
    use crate::signature_hash_algorithm::{SignatureAlgorithm, SignatureScheme};

    let server = || {
        ConfigBuilder::default()
            .with_crypto_provider(provider())
            .with_certificates(vec![rsa_certificate()])
    };
    let mut pair = Pair::new(client_builder(), server())?.complete();
    assert_eq!(pair.versions().0, Some(DtlsVersion::Dtls1_3));
    assert_eq!(
        pair.client_conn()
            .peer_signature_scheme
            .map(|scheme| scheme.signature),
        Some(SignatureAlgorithm::RsaPssRsaeSha256)
    );
    assert_eq!(pair.client_sends(b"pss"), vec![b"pss".to_vec()]);

    // A client that lists only PKCS#1 v1.5 for RSA cannot be served in DTLS 1.3, which has
    // no such CertificateVerify: handshake_failure.
    let mut pair = Pair::new(
        client_builder()
            .with_protocol_versions(DtlsVersion::Dtls1_3, DtlsVersion::Dtls1_3)
            .with_signature_schemes(vec![
                SignatureScheme::Pkcs1WithSha256,
                SignatureScheme::EcdsaWithP256AndSha256,
            ]),
        server().with_cookie_exchange(false),
    )?;
    let client_hello = take(&mut pair.client);
    pair.deliver_to_server(client_hello);
    let answer = take(&mut pair.server);
    assert_eq!(plaintext_alerts(&answer), [(2, alert::HANDSHAKE_FAILURE)]);
    pair.deliver_to_client(answer);
    assert!(!pair.client_complete && !pair.server_complete);
    assert!(pair.client.is_connection_failed(&server_addr()));

    // DTLS 1.2, ECDHE_RSA: the ServerKeyExchange is signed with the pair the server prefers
    // among those the client lists.
    let suite = CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256;
    for (schemes, expected) in [
        (
            vec![
                SignatureScheme::PssWithSha256,
                SignatureScheme::Pkcs1WithSha256,
            ],
            SignatureAlgorithm::RsaPssRsaeSha256,
        ),
        (
            vec![
                SignatureScheme::Pkcs1WithSha256,
                SignatureScheme::PssWithSha256,
            ],
            SignatureAlgorithm::Rsa,
        ),
    ] {
        let mut pair = Pair::new(
            client_builder().with_cipher_suites(vec![suite]),
            server()
                .with_cipher_suites(vec![suite])
                .with_signature_schemes(schemes),
        )?
        .complete();
        assert_eq!(pair.versions().0, Some(DtlsVersion::Dtls1_2));
        let scheme = pair
            .server
            .connection_mut(&client_addr())
            .unwrap()
            .state
            .local_signature_scheme;
        assert_eq!(scheme.map(|scheme| scheme.signature), Some(expected));
        assert_eq!(pair.client_sends(b"rsa"), vec![b"rsa".to_vec()]);
    }
    Ok(())
}

/// RFC 8446 section 4.4.2.2: of its certificates a server sends one whose chain is signed
/// with algorithms the client lists, when it has one, and otherwise one the client can at
/// least verify the handshake signature of.
#[test]
fn the_server_sends_a_chain_signed_with_algorithms_the_client_lists() -> Result<()> {
    use crate::signature_hash_algorithm::SignatureScheme;

    let provider = provider();
    // A P-256 leaf issued by an Ed25519 authority, and a self-signed P-256 certificate.
    let authority_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let authority = rcgen::Issuer::new(
        rcgen::CertificateParams::new(vec!["authority".to_owned()]).unwrap(),
        authority_key,
    );
    let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &authority)
        .unwrap();
    let issued = Certificate {
        certificate: vec![leaf.der().to_owned()],
        private_key: crate::crypto::CryptoPrivateKey::from_key_pair(&leaf_key, provider.crypto())?,
    };
    let self_signed =
        Certificate::generate_self_signed(vec!["localhost".to_owned()], provider.crypto())?;
    let issued_der = issued.certificate[0].as_ref().to_vec();
    let self_signed_der = self_signed.certificate[0].as_ref().to_vec();
    let server = |certificates: Vec<Certificate>| {
        ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_certificates(certificates)
    };
    let ecdsa_only =
        || client_builder().with_signature_schemes(vec![SignatureScheme::EcdsaWithP256AndSha256]);
    let sent = |pair: &Pair| {
        pair.client
            .get_connection_state(server_addr())
            .unwrap()
            .peer_certificates
            .clone()
    };

    // The client does not list Ed25519: the certificate issued under it is passed over for
    // the one signed with ECDSA, although it comes first.
    let pair = Pair::new(ecdsa_only(), server(vec![issued.clone(), self_signed]))?.complete();
    assert_eq!(sent(&pair), vec![self_signed_der]);
    // A client that lists Ed25519 too gets the first.
    let pair = Pair::new(client_builder(), server(vec![issued.clone()]))?.complete();
    assert_eq!(sent(&pair), vec![issued_der.clone()]);
    // With nothing better to offer the server sends what it has, and the client decides.
    let pair = Pair::new(ecdsa_only(), server(vec![issued]))?.complete();
    assert_eq!(sent(&pair), vec![issued_der]);
    Ok(())
}

/// X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem, 0x11EC) with a provider that has ML-KEM: it is
/// offered first and negotiated, its 1216-byte share makes the ClientHello two fragments,
/// and a peer without it still gets a handshake.
#[cfg(feature = "crypto-aws-lc-rs")]
#[test]
fn the_hybrid_post_quantum_group_is_negotiated_where_the_provider_has_it() -> Result<()> {
    use crate::curve::named_curve::NamedCurve;

    let aws: Arc<dyn RTCCryptoProvider> = Arc::new(crypto::providers::AwsLcRsProvider::new());
    let client = |provider: &Arc<dyn RTCCryptoProvider>| {
        ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_insecure_skip_verify(true)
    };
    let server = |provider: &Arc<dyn RTCCryptoProvider>| {
        ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_insecure_skip_verify(true)
            .with_certificates(vec![
                Certificate::generate_self_signed(vec!["localhost".to_owned()], provider.crypto())
                    .expect("a certificate"),
            ])
    };
    let config = client(&aws).build(true, None)?;
    assert_eq!(config.local_tls13_groups[0], NamedCurve::X25519MlKem768);
    assert_eq!(config.local_tls13_groups.len(), 4);
    // Not a curve of DTLS 1.2.
    assert!(
        !config
            .local_named_curves
            .contains(&NamedCurve::X25519MlKem768)
    );
    let off = client(&aws)
        .with_post_quantum_key_share(false)
        .build(true, None)?;
    assert!(!off.local_tls13_groups.contains(&NamedCurve::X25519MlKem768));

    for cookie_exchange in [true, false] {
        let mut pair = Pair::new(
            client(&aws),
            server(&aws).with_cookie_exchange(cookie_exchange),
        )?;
        let client_hello = take(&mut pair.client);
        // Two fragments of one ClientHello (message_seq 0), each within the MTU.
        assert_eq!(client_hello.len(), 2, "cookies: {cookie_exchange}");
        for datagram in &client_hello {
            assert!(datagram.len() <= 1200);
            assert_eq!((datagram[13], &datagram[17..19]), (1, &[0u8, 0][..]));
        }
        assert!(client_hello[0].len() + client_hello[1].len() > 1216 + 65);
        pair.deliver_to_server(client_hello);
        let mut pair = pair.complete();
        assert_eq!(pair.versions().0, Some(DtlsVersion::Dtls1_3));
        // The ServerHello's key share was the hybrid's: an ML-KEM ciphertext and an X25519
        // key. The secret both ends derived from it carries data.
        assert_eq!(pair.client_sends(b"hybrid"), vec![b"hybrid".to_vec()]);
        assert_eq!(pair.server_sends(b"back"), vec![b"back".to_vec()]);
    }

    // A server that does not have the group takes the client's other share (P-256), with
    // no HelloRetryRequest for it.
    let mut pair = Pair::new(
        client(&aws),
        server(&aws)
            .with_cookie_exchange(false)
            .with_post_quantum_key_share(false),
    )?;
    let client_hello = take(&mut pair.client);
    pair.deliver_to_server(client_hello);
    let flight = take(&mut pair.server);
    assert_ne!(
        &flight[0][27..59],
        &super::messages::HELLO_RETRY_REQUEST_RANDOM
    );
    pair.deliver_to_client(flight);
    let mut pair = pair.complete();
    assert_eq!(pair.client_sends(b"p256"), vec![b"p256".to_vec()]);

    // A client that has only curves and a server that prefers the hybrid.
    let mut pair = Pair::new(
        client(&aws).with_post_quantum_key_share(false),
        server(&aws),
    )?
    .complete();
    assert_eq!(pair.client_sends(b"curve"), vec![b"curve".to_vec()]);

    // DTLS 1.2 with the same ClientHello: the group is not one of its curves.
    let mut pair = Pair::new(
        client(&aws),
        server(&aws).with_protocol_versions(DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_2),
    )?
    .complete();
    assert_eq!(pair.versions().0, Some(DtlsVersion::Dtls1_2));
    assert_eq!(pair.client_sends(b"1.2"), vec![b"1.2".to_vec()]);
    Ok(())
}

/// The provider without ML-KEM does not offer the group, whatever the setting.
#[cfg(feature = "crypto-ring")]
#[test]
fn the_hybrid_group_is_not_offered_without_a_provider_for_it() -> Result<()> {
    use crate::curve::named_curve::NamedCurve;

    let ring: Arc<dyn RTCCryptoProvider> = Arc::new(crypto::providers::RingProvider::new());
    let config = ConfigBuilder::default()
        .with_crypto_provider(ring)
        .with_insecure_skip_verify(true)
        .with_post_quantum_key_share(true)
        .build(true, None)?;
    assert!(
        !config
            .local_tls13_groups
            .contains(&NamedCurve::X25519MlKem768)
    );
    assert_eq!(config.local_tls13_groups, config.local_named_curves);
    Ok(())
}

/// A provider that wraps another and passes `supports` and the older operations through,
/// but leaves the operations only DTLS 1.3 uses at the trait's defaults unless told to
/// forward them: what an application's wrapper written before DTLS 1.3 looks like.
struct PassThrough {
    inner: Arc<dyn RTCCryptoProvider>,
    header_mask: bool,
    respond: bool,
}

impl RTCCryptoProvider for PassThrough {
    fn name(&self) -> &'static str {
        "pass-through"
    }
    fn crypto(&self) -> &dyn crypto::RTCCrypto {
        self
    }
    fn random(&self) -> &dyn crypto::RTCRandom {
        self.inner.random()
    }
}

impl crypto::RTCCrypto for PassThrough {
    fn supports(&self, algorithm: crypto::CryptoAlgorithm) -> bool {
        self.inner.crypto().supports(algorithm)
    }
    fn hash(
        &self,
        algorithm: crypto::HashAlgorithm,
        data: &[u8],
    ) -> std::result::Result<Vec<u8>, crypto::CryptoError> {
        self.inner.crypto().hash(algorithm, data)
    }
    fn block_encrypt(
        &self,
        algorithm: crypto::BlockCipherAlgorithm,
        key: &[u8],
        block: &mut [u8],
    ) -> std::result::Result<(), crypto::CryptoError> {
        self.inner.crypto().block_encrypt(algorithm, key, block)
    }
    fn new_hmac(
        &self,
        algorithm: crypto::HmacAlgorithm,
        key: &[u8],
    ) -> std::result::Result<Box<dyn crypto::Mac>, crypto::CryptoError> {
        self.inner.crypto().new_hmac(algorithm, key)
    }
    fn new_stream_cipher(
        &self,
        algorithm: crypto::StreamCipherAlgorithm,
        key: &[u8],
    ) -> std::result::Result<Box<dyn crypto::StreamCipher>, crypto::CryptoError> {
        self.inner.crypto().new_stream_cipher(algorithm, key)
    }
    fn new_aead(
        &self,
        algorithm: crypto::AeadAlgorithm,
        key: &[u8],
    ) -> std::result::Result<Box<dyn crypto::AeadCipher>, crypto::CryptoError> {
        self.inner.crypto().new_aead(algorithm, key)
    }
    fn new_header_mask(
        &self,
        algorithm: crypto::HeaderMaskAlgorithm,
        key: &[u8],
    ) -> std::result::Result<Box<dyn crypto::HeaderMask>, crypto::CryptoError> {
        if !self.header_mask {
            return Err(crypto::CryptoError::UnsupportedAlgorithm(
                crypto::CryptoAlgorithm::HeaderMask(algorithm),
            ));
        }
        self.inner.crypto().new_header_mask(algorithm, key)
    }
    fn new_cbc(
        &self,
        algorithm: crypto::CbcAlgorithm,
        key: &[u8],
    ) -> std::result::Result<Box<dyn crypto::CbcCipher>, crypto::CryptoError> {
        self.inner.crypto().new_cbc(algorithm, key)
    }
    fn start_key_exchange(
        &self,
        algorithm: crypto::KeyExchangeAlgorithm,
    ) -> std::result::Result<Box<dyn crypto::ActiveKeyExchange>, crypto::CryptoError> {
        self.inner.crypto().start_key_exchange(algorithm)
    }
    fn key_exchange_respond(
        &self,
        algorithm: crypto::KeyExchangeAlgorithm,
        peer_share: &[u8],
    ) -> std::result::Result<(Vec<u8>, crypto::SecretVec), crypto::CryptoError> {
        if self.respond {
            return self
                .inner
                .crypto()
                .key_exchange_respond(algorithm, peer_share);
        }
        // The trait's default: a key pair and an agreement.
        let exchange = self.start_key_exchange(algorithm)?;
        let share = exchange.public_key().to_vec();
        Ok((share, exchange.complete(peer_share)?))
    }
    fn generate_signing_key(
        &self,
        scheme: crypto::SignatureScheme,
    ) -> std::result::Result<Arc<dyn crypto::SigningKey>, crypto::CryptoError> {
        self.inner.crypto().generate_signing_key(scheme)
    }
    fn import_signing_key(
        &self,
        scheme: crypto::SignatureScheme,
        pkcs8_der: &[u8],
    ) -> std::result::Result<Arc<dyn crypto::SigningKey>, crypto::CryptoError> {
        self.inner.crypto().import_signing_key(scheme, pkcs8_der)
    }
    fn verify_signature(
        &self,
        scheme: crypto::SignatureScheme,
        public_key: crypto::PublicKey<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> std::result::Result<(), crypto::CryptoError> {
        self.inner
            .crypto()
            .verify_signature(scheme, public_key, message, signature)
    }
}

/// A provider that says it has a TLS 1.3 suite's algorithms but cannot make its
/// record-number mask is not offered DTLS 1.3, and connects with DTLS 1.2, rather than
/// negotiating DTLS 1.3 and failing every record (the train's
/// `isolates_crypto_providers_across_simultaneous_peer_connections` did that).
#[test]
fn a_provider_without_record_number_masks_falls_back_to_dtls_1_2() -> Result<()> {
    for header_mask in [false, true] {
        let wrapped: Arc<dyn RTCCryptoProvider> = Arc::new(PassThrough {
            inner: provider(),
            header_mask,
            respond: true,
        });
        let client = client_builder().with_crypto_provider(wrapped);
        assert_eq!(
            client
                .clone()
                .build(true, None)?
                .local_tls13_cipher_suites
                .is_empty(),
            !header_mask
        );
        let pair = Pair::new(client, server_builder())?.complete();
        let expected = if header_mask {
            DtlsVersion::Dtls1_3
        } else {
            DtlsVersion::Dtls1_2
        };
        assert_eq!(pair.versions(), (Some(expected), Some(expected)));
    }
    Ok(())
}

/// Likewise a provider that says it has X25519MLKEM768 but answers a share with the
/// Diffie-Hellman default of `key_exchange_respond` is not offered the group.
#[cfg(feature = "crypto-aws-lc-rs")]
#[test]
fn a_provider_that_cannot_answer_a_hybrid_share_is_not_offered_the_group() -> Result<()> {
    use crate::curve::named_curve::NamedCurve;
    for respond in [false, true] {
        let wrapped: Arc<dyn RTCCryptoProvider> = Arc::new(PassThrough {
            inner: Arc::new(crypto::providers::AwsLcRsProvider::new()),
            header_mask: true,
            respond,
        });
        let config = ConfigBuilder::default()
            .with_crypto_provider(wrapped)
            .with_insecure_skip_verify(true)
            .build(true, None)?;
        assert_eq!(
            config
                .local_tls13_groups
                .contains(&NamedCurve::X25519MlKem768),
            respond
        );
    }
    Ok(())
}
