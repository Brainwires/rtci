//! The record layer and the handshake transport of RFC 6347 (4.1.1, 4.1.2, 4.2.3, 4.2.4, 4.2.7)
//! and the record and alert rules of RFC 5246 (6.2, 7.2) it inherits, on the production
//! connection.

use super::conn_conformance_test::{
    Exchange, builder, client, drain, feed, plaintext_alerts, server,
};
use super::*;
use crate::cipher_suite::{CipherSuite, CipherSuiteHash, CipherSuiteId};
use crate::client_certificate_type::ClientCertificateType;
use crate::config::{ClientAuthType, ConfigBuilder};
use std::sync::atomic::{AtomicUsize, Ordering};

const ALERT_FATAL: u8 = 2;
const ALERT_UNEXPECTED_MESSAGE: u8 = 10;
const ALERT_HANDSHAKE_FAILURE: u8 = 40;

fn completed_pair(client_builder: ConfigBuilder, server_builder: ConfigBuilder) -> Exchange {
    let exchange = Exchange::run(client(client_builder), server(server_builder));
    assert!(
        exchange.completed(),
        "client: {:?}, server: {:?}",
        exchange.client_err,
        exchange.server_err
    );
    exchange
}

/// One application-data record from `conn`, protected under record sequence number
/// `sequence_number` of its current epoch.
fn application_record(conn: &mut DTLSConn, sequence_number: u64, payload: &[u8]) -> Vec<u8> {
    let epoch = conn.get_local_epoch() as usize;
    conn.state.local_sequence_number[epoch] = sequence_number;
    conn.write(payload).unwrap();
    let mut datagrams = drain(conn);
    assert_eq!(datagrams.len(), 1);
    datagrams.remove(0)
}

/// A record of `content_type` around `payload`, protected by `conn` as its next record.
fn protected_record(conn: &mut DTLSConn, content_type: ContentType, payload: &[u8]) -> Vec<u8> {
    let epoch = conn.get_local_epoch();
    let sequence_number = conn.state.local_sequence_number[epoch as usize];
    conn.state.local_sequence_number[epoch as usize] += 1;
    let header = RecordLayerHeader {
        content_type,
        protocol_version: PROTOCOL_VERSION1_2,
        epoch,
        sequence_number,
        content_len: payload.len() as u16,
    };
    let mut raw = vec![];
    header.marshal(&mut raw).unwrap();
    raw.extend_from_slice(payload);
    conn.state
        .cipher_suite
        .as_mut()
        .unwrap()
        .encrypt(&header, &raw)
        .unwrap()
}

// ---------------------------------------------------------------------------------------------
// Record sizes (RFC 5246 6.2.1, 6.2.3; RFC 6347 4.1.1.1)
// ---------------------------------------------------------------------------------------------

/// RFC 5246 6.2.1: a record that authenticates and opens to more than 2^14 bytes is the
/// peer's error: fatal record_overflow. One whose header merely announces more than a
/// protected record may hold authenticates nothing and is discarded.
#[test]
fn a_record_larger_than_the_protocol_allows_is_refused() {
    let Exchange {
        mut client,
        mut server,
        ..
    } = completed_pair(builder(), builder());

    // The largest record a peer may send is taken.
    let largest = protected_record(
        &mut client,
        ContentType::ApplicationData,
        &vec![0x11; MAX_RECORD_PAYLOAD],
    );
    server.read(&largest).unwrap();
    assert_eq!(
        server.incoming_application_data().map(|data| data.len()),
        Some(MAX_RECORD_PAYLOAD)
    );

    // An unauthenticated header that announces 2^14 + 2049 bytes.
    let mut announced = vec![23, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 9];
    announced.extend_from_slice(&((MAX_PROTECTED_RECORD_PAYLOAD + 1) as u16).to_be_bytes());
    announced.resize(
        RECORD_LAYER_HEADER_SIZE + MAX_PROTECTED_RECORD_PAYLOAD + 1,
        0xee,
    );
    server.read(&announced).unwrap();
    assert!(!server.is_failed());
    assert!(drain(&mut server).is_empty());

    // One byte too many, authenticated.
    let too_large = protected_record(
        &mut client,
        ContentType::ApplicationData,
        &vec![0x22; MAX_RECORD_PAYLOAD + 1],
    );
    assert_eq!(server.read(&too_large), Err(Error::ErrAlertFatalOrClose));
    assert!(server.is_failed());
    assert_eq!(
        server.fatal_alert_sent.map(|(alert, _)| alert),
        Some(Alert {
            alert_level: AlertLevel::Fatal,
            alert_description: AlertDescription::RecordOverflow,
        })
    );
    // The alert is protected: the client reads it and fails too.
    let alert = drain(&mut server);
    assert_eq!(alert.len(), 1);
    assert_eq!(client.read(&alert[0]), Err(Error::ErrAlertFatalOrClose));
    assert!(client.is_failed());
}

/// A plaintext record that announces more than 2^14 bytes is discarded during the handshake.
#[test]
fn an_oversize_plaintext_record_is_discarded() {
    let now = Instant::now();
    let mut client = client(builder());
    client.handshake(now).unwrap();
    drain(&mut client);

    let mut record = vec![22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0];
    record.extend_from_slice(&((MAX_RECORD_PAYLOAD + 1) as u16).to_be_bytes());
    record.resize(RECORD_LAYER_HEADER_SIZE + MAX_RECORD_PAYLOAD + 1, 0);
    feed(&mut client, now, &record).unwrap();
    assert!(!client.is_failed());
    assert!(drain(&mut client).is_empty());
}

/// RFC 6347 4.1.1.1: the upper layer can learn what DTLS adds to its datagrams: the 13-byte
/// header plus the suite's record expansion.
#[test]
fn the_record_expansion_of_each_suite_is_what_its_records_add() {
    let psk = |builder: ConfigBuilder| builder.with_psk(Some(Arc::new(|_| Ok(vec![0xab, 0xcd]))));
    let cases: Vec<(CipherSuiteId, bool, Option<usize>)> = vec![
        (
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
            false,
            Some(24),
        ),
        (
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
            false,
            Some(16),
        ),
        (
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm,
            false,
            Some(24),
        ),
        (
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8,
            false,
            Some(16),
        ),
        (
            CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256,
            true,
            Some(24),
        ),
        // CBC pads to the block: at most the expansion.
        (
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
            false,
            None,
        ),
    ];
    for (suite, is_psk, exact) in cases {
        let config = |is_client: bool| {
            let mut builder = ConfigBuilder::default()
                .with_crypto_provider(super::conn_conformance_test::provider())
                .with_cipher_suites(vec![suite])
                .with_insecure_skip_verify(true);
            if is_psk {
                builder = psk(builder);
                if is_client {
                    builder = builder.with_psk_identity_hint(Some(b"hint".to_vec()));
                }
            } else if !is_client {
                builder =
                    builder.with_certificates(vec![super::conn_conformance_test::self_signed()]);
            }
            DTLSConn::new(
                Arc::new(builder.build(is_client, None).unwrap()),
                is_client,
                None,
            )
        };
        let exchange = Exchange::run(config(true), config(false));
        assert!(exchange.completed(), "{suite}");
        let mut client = exchange.client;

        let expansion = client
            .connection_state()
            .cipher_suite()
            .expect("a negotiated suite")
            .record_expansion();
        for len in [0usize, 1, 100, 1000] {
            let record = application_record(&mut client, 10 + len as u64, &vec![0x33; len]);
            let added = record.len() - RECORD_LAYER_HEADER_SIZE - len;
            match exact {
                Some(exact) => {
                    assert_eq!(expansion, exact, "{suite}");
                    assert_eq!(added, expansion, "{suite}, {len} bytes");
                }
                None => assert!(added <= expansion, "{suite}, {len} bytes: {added}"),
            }
        }
    }
}

/// RFC 5246 7.3: no application data is sent before the handshake completes. An early write is
/// held and goes out, protected, once it has.
#[test]
fn a_write_before_the_handshake_completes_is_held_until_it_does() {
    let now = Instant::now();
    let mut client = client(builder());
    let mut server = server(builder());
    client.handshake(now).unwrap();
    client.write(b"early").unwrap();

    let mut delivered = None;
    for _ in 0..16 {
        for datagram in drain(&mut client) {
            for record in unpack_datagram(&datagram).unwrap() {
                let epoch = u16::from_be_bytes([record[3], record[4]]);
                assert!(
                    record[0] != 23 || (epoch == 1 && client.is_handshake_completed()),
                    "application data only after completion, in epoch 1"
                );
            }
            feed(&mut server, now, &datagram).unwrap();
        }
        for datagram in drain(&mut server) {
            feed(&mut client, now, &datagram).unwrap();
        }
        if let Some(data) = server.incoming_application_data() {
            delivered = Some(data);
            break;
        }
    }
    assert_eq!(delivered.as_deref(), Some(&b"early"[..]));
}

// ---------------------------------------------------------------------------------------------
// Anti-replay (RFC 6347 4.1.2.6)
// ---------------------------------------------------------------------------------------------

/// Whether `server` delivers a record `client` protects under `sequence_number`.
fn delivers(client: &mut DTLSConn, server: &mut DTLSConn, sequence_number: u64) -> bool {
    let record = application_record(client, sequence_number, b"x");
    server.read(&record).unwrap();
    server.incoming_application_data().is_some()
}

/// RFC 6347 4.1.2.6: the default window is 64; a window of at least 32 is supported (a smaller
/// one is raised to 32) and a larger one may be chosen. A record is accepted when it is ahead
/// of the window or inside it and not seen before, and rejected when behind it.
#[test]
fn the_replay_window_is_64_by_default_and_never_below_32() {
    for (configured, window) in [
        (None, 64u64),
        (Some(8), 32),
        (Some(32), 32),
        (Some(200), 200),
    ] {
        let server_builder = match configured {
            Some(size) => builder().with_replay_protection_window(size),
            None => builder(),
        };
        let Exchange {
            mut client,
            mut server,
            ..
        } = completed_pair(builder(), server_builder);

        let latest = 1000;
        assert!(delivers(&mut client, &mut server, latest), "{window}");
        assert!(
            !delivers(&mut client, &mut server, latest),
            "{window}: a repeat"
        );
        assert!(
            delivers(&mut client, &mut server, latest - (window - 1)),
            "{window}: the oldest record inside the window"
        );
        assert!(
            !delivers(&mut client, &mut server, latest - window),
            "{window}: the first record behind the window"
        );
        assert!(
            delivers(&mut client, &mut server, latest + 5000),
            "{window}: a record far ahead moves the window"
        );
        assert!(
            !delivers(&mut client, &mut server, latest + 1),
            "{window}: now behind it"
        );
    }
}

/// A cipher suite that counts the records it is asked to open.
struct CountingSuite {
    inner: Box<dyn CipherSuite>,
    decrypts: Arc<AtomicUsize>,
}

impl CipherSuite for CountingSuite {
    fn to_string(&self) -> String {
        self.inner.to_string()
    }
    fn id(&self) -> CipherSuiteId {
        self.inner.id()
    }
    fn certificate_type(&self) -> ClientCertificateType {
        self.inner.certificate_type()
    }
    fn hash_func(&self) -> CipherSuiteHash {
        self.inner.hash_func()
    }
    fn is_psk(&self) -> bool {
        self.inner.is_psk()
    }
    fn is_initialized(&self) -> bool {
        self.inner.is_initialized()
    }
    fn record_expansion(&self) -> usize {
        self.inner.record_expansion()
    }
    fn init(
        &mut self,
        provider: Arc<dyn crypto::RTCCryptoProvider>,
        master_secret: &[u8],
        client_random: &[u8],
        server_random: &[u8],
        is_client: bool,
    ) -> Result<()> {
        self.inner.init(
            provider,
            master_secret,
            client_random,
            server_random,
            is_client,
        )
    }
    fn encrypt(&mut self, pkt_rlh: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>> {
        self.inner.encrypt(pkt_rlh, raw)
    }
    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.decrypts.fetch_add(1, Ordering::SeqCst);
        self.inner.decrypt(input)
    }
}

/// RFC 6347 4.1.2.6: the duplicate check comes before the MAC check, so a replayed record
/// costs no decryption; and the window only moves for a record that authenticated, so a
/// forged one with a far-ahead sequence number does not shut the genuine ones out.
#[test]
fn a_replayed_record_is_rejected_before_it_is_decrypted() {
    let Exchange {
        mut client,
        mut server,
        ..
    } = completed_pair(builder(), builder());
    let decrypts = Arc::new(AtomicUsize::new(0));
    let inner = server.state.cipher_suite.take().unwrap();
    server.state.cipher_suite = Some(Box::new(CountingSuite {
        inner,
        decrypts: decrypts.clone(),
    }));

    let record = application_record(&mut client, 50, b"once");
    server.read(&record).unwrap();
    assert!(server.incoming_application_data().is_some());
    assert_eq!(decrypts.load(Ordering::SeqCst), 1);

    server.read(&record).unwrap();
    assert!(server.incoming_application_data().is_none());
    assert_eq!(
        decrypts.load(Ordering::SeqCst),
        1,
        "the replay was not opened"
    );

    // A forged record far ahead: opened (it could be genuine), rejected, and without effect
    // on the window.
    let mut forged = application_record(&mut client, 1_000_000, b"forged");
    let last = forged.len() - 1;
    forged[last] ^= 0x01;
    server.read(&forged).unwrap();
    assert!(server.incoming_application_data().is_none());
    assert_eq!(decrypts.load(Ordering::SeqCst), 2);
    assert!(delivers(&mut client, &mut server, 51));
}

// ---------------------------------------------------------------------------------------------
// Alerts (RFC 5246 6, 7.2, 7.4; RFC 6347 4.2.7)
// ---------------------------------------------------------------------------------------------

/// RFC 5246 6: a record type other than the four defined, once authenticated, is answered
/// with unexpected_message.
#[test]
fn an_authenticated_record_of_an_unknown_type_is_an_unexpected_message() {
    let Exchange {
        mut client,
        mut server,
        ..
    } = completed_pair(builder(), builder());

    let record = protected_record(&mut client, ContentType::Invalid, &[1, 2, 3]);
    assert_eq!(server.read(&record), Err(Error::ErrAlertFatalOrClose));
    assert_eq!(
        server.fatal_alert_sent.map(|(alert, _)| alert),
        Some(Alert {
            alert_level: AlertLevel::Fatal,
            alert_description: AlertDescription::UnexpectedMessage,
        })
    );
}

/// RFC 5246 7.4: a handshake message out of place is fatal when it is the peer's doing. After
/// ChangeCipherSpec the only message is Finished: an authenticated record with another one is
/// answered with unexpected_message.
#[test]
fn a_protected_handshake_message_other_than_finished_is_an_unexpected_message() {
    let now = Instant::now();
    let mut client = client(builder());
    let mut server = server(builder());
    client.handshake(now).unwrap();

    let mut server_result = Ok(());
    let mut answered = vec![];
    'handshake: for _ in 0..16 {
        for datagram in drain(&mut client) {
            let records = unpack_datagram(&datagram).unwrap();
            let is_last_flight = records.iter().any(|record| record[0] == 20);
            if !is_last_flight {
                feed(&mut server, now, &datagram).unwrap();
                continue;
            }
            // The client's last flight: everything up to ChangeCipherSpec as it is, and in
            // place of the Finished a ClientKeyExchange under its message sequence number,
            // protected with the client's keys.
            let finished_sequence = (client.state.handshake_send_sequence - 1) as u16;
            let mut message = vec![16, 0, 0, 1];
            message.extend_from_slice(&finished_sequence.to_be_bytes());
            message.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0]);
            client.state.local_sequence_number[1] = 0;
            let out_of_place = protected_record(&mut client, ContentType::Handshake, &message);
            for record in records.iter().filter(|record| record[3..5] == [0, 0]) {
                feed(&mut server, now, record).unwrap();
            }
            server_result = feed(&mut server, now, &out_of_place);
            answered = drain(&mut server);
            break 'handshake;
        }
        for datagram in drain(&mut server) {
            feed(&mut client, now, &datagram).unwrap();
        }
    }

    assert_eq!(server_result, Err(Error::ErrAlertFatalOrClose));
    assert!(server.is_failed());
    assert_eq!(
        plaintext_alerts(&answered),
        vec![(ALERT_FATAL, ALERT_UNEXPECTED_MESSAGE)]
    );
}

/// In epoch 0 anyone can send a handshake message, so one that is out of place (here a
/// Finished in the clear, under the sequence number of the server's next message) is dropped
/// without an alert and without taking the genuine message's place.
#[test]
fn an_out_of_place_plaintext_handshake_message_does_not_block_the_genuine_one() {
    let now = Instant::now();
    let mut client = client(builder());
    let mut server = server(builder());
    client.handshake(now).unwrap();
    for datagram in drain(&mut client) {
        feed(&mut server, now, &datagram).unwrap();
    }
    let hello_verify_request = drain(&mut server);

    // Message sequence 0 is what the client expects next (the HelloVerifyRequest).
    let mut forged = vec![22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 77, 0, 24];
    forged.extend_from_slice(&[20, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 12]);
    forged.extend_from_slice(&[0xee; 12]);
    feed(&mut client, now, &forged).unwrap();
    assert!(!client.is_failed());
    assert!(drain(&mut client).is_empty(), "no alert, no answer");

    let exchange = {
        for datagram in &hello_verify_request {
            feed(&mut client, now, datagram).unwrap();
        }
        let mut done = false;
        for _ in 0..16 {
            for datagram in drain(&mut client) {
                feed(&mut server, now, &datagram).unwrap();
            }
            for datagram in drain(&mut server) {
                feed(&mut client, now, &datagram).unwrap();
            }
            done = client.is_handshake_completed() && server.is_handshake_completed();
            if done {
                break;
            }
        }
        done
    };
    assert!(exchange, "the handshake completes");
}

/// RFC 6347 4.2.7: an alert is not retransmitted on a timer, but when the peer sends the
/// offending flight again a new alert is generated. A bounded number of times, and only for
/// handshake records.
#[test]
fn a_fatal_alert_is_sent_again_when_the_offending_flight_is_repeated() {
    // The server requires a client certificate; the client has none.
    let exchange = Exchange::run(
        client(builder()),
        server(builder().with_client_auth(ClientAuthType::RequireAnyClientCert)),
    );
    let mut failed = exchange.server;
    assert!(failed.is_failed());
    assert_eq!(
        plaintext_alerts(&exchange.from_server),
        vec![(ALERT_FATAL, ALERT_HANDSHAKE_FAILURE)]
    );
    // No timer is left to retransmit anything.
    assert_eq!(failed.next_timeout(), None);

    // The client's last flight again: the datagram that holds its ChangeCipherSpec.
    let last_flight = exchange
        .from_client
        .iter()
        .rev()
        .find(|datagram| {
            unpack_datagram(datagram)
                .unwrap()
                .iter()
                .any(|record| record[0] == 22)
        })
        .expect("the client sent handshake records")
        .clone();
    let budget = failed.maximum_retransmit_number;
    for repeat in 0..budget + 3 {
        assert_eq!(failed.read(&last_flight), Err(Error::ErrConnClosed));
        let answer = drain(&mut failed);
        if repeat < budget {
            assert_eq!(
                plaintext_alerts(&answer),
                vec![(ALERT_FATAL, ALERT_HANDSHAKE_FAILURE)],
                "repeat {repeat}"
            );
        } else {
            assert!(answer.is_empty(), "repeat {repeat}: the budget is spent");
        }
    }

    // Something that is not a handshake record draws nothing.
    let mut other = Exchange::run(
        client(builder()),
        server(builder().with_client_auth(ClientAuthType::RequireAnyClientCert)),
    )
    .server;
    let application_data = [23, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0];
    assert_eq!(other.read(&application_data), Err(Error::ErrConnClosed));
    assert!(drain(&mut other).is_empty());
}

/// RFC 5246 7.2.2, 8.1: the premaster secret is forgotten once the master secret exists, and
/// the master secret when the association fails. Nothing is exported afterwards.
#[test]
fn secrets_are_forgotten_when_no_longer_needed() {
    let Exchange {
        mut client,
        mut server,
        ..
    } = completed_pair(builder(), builder());
    assert!(client.state.pre_master_secret.is_empty());
    assert!(server.state.pre_master_secret.is_empty());
    assert_eq!(client.state.master_secret.len(), 48);
    assert_eq!(server.state.master_secret.len(), 48);

    // The client ends the association with a fatal alert.
    client.notify(AlertLevel::Fatal, AlertDescription::InternalError);
    for datagram in drain(&mut client) {
        assert_eq!(server.read(&datagram), Err(Error::ErrAlertFatalOrClose));
    }
    for conn in [&client, &server] {
        assert!(conn.is_failed());
        assert!(conn.state.master_secret.is_empty());
        assert_eq!(
            conn.state
                .export_keying_material("EXTRACTOR-dtls_srtp", &[], 60)
                .err(),
            Some(Error::ErrConnClosed)
        );
    }
}

// ---------------------------------------------------------------------------------------------
// HelloVerifyRequest, sequence numbers (RFC 6347 4.2.1; RFC 5246 6.1)
// ---------------------------------------------------------------------------------------------

/// RFC 6347 4.2.1: the version in a HelloVerifyRequest only says how the packet is formatted.
/// A client answers one of version 1.0 (what OpenSSL sends) with the same DTLS 1.2
/// ClientHello plus the cookie, and does not conclude that DTLS 1.0 was negotiated.
#[test]
fn a_hello_verify_request_of_version_1_0_is_only_packet_format() {
    let now = Instant::now();
    let mut client = client(builder());
    client.handshake(now).unwrap();
    drain(&mut client);

    // Record version 1.0, server_version 1.0, a 20-byte cookie: as OpenSSL 3.5 writes it.
    let cookie = [0x3f; 20];
    let mut hello_verify_request = vec![22, 0xfe, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35];
    hello_verify_request.extend_from_slice(&[3, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 23]);
    hello_verify_request.extend_from_slice(&[0xfe, 0xff, 20]);
    hello_verify_request.extend_from_slice(&cookie);
    feed(&mut client, now, &hello_verify_request).unwrap();

    let second = drain(&mut client);
    assert_eq!(second.len(), 1);
    let body = &second[0][RECORD_LAYER_HEADER_SIZE + HANDSHAKE_HEADER_LENGTH..];
    assert_eq!(
        &body[..2],
        &[0xfe, 0xfd],
        "client_version is still DTLS 1.2"
    );
    assert_eq!(body[34], 0, "an empty session id");
    assert_eq!(body[35], 20);
    assert_eq!(&body[36..56], &cookie);
    // message_seq 1: the second ClientHello (RFC 6347 4.2.2).
    assert_eq!(
        &second[0][RECORD_LAYER_HEADER_SIZE + 4..RECORD_LAYER_HEADER_SIZE + 6],
        &[0, 1]
    );
}

/// RFC 5246 6.1: sequence numbers start at zero when a connection state becomes active. Each
/// side's Finished, the first record of its epoch 1, is record 0 of that epoch.
#[test]
fn the_first_protected_record_of_each_side_has_sequence_number_zero() {
    let exchange = completed_pair(builder(), builder());
    for datagrams in [&exchange.from_client, &exchange.from_server] {
        let first_protected = datagrams
            .iter()
            .flat_map(|datagram| unpack_datagram(datagram).unwrap())
            .find(|record| record[3..5] == [0, 1])
            .expect("a record in epoch 1");
        assert_eq!(first_protected[0], 22, "the Finished");
        assert_eq!(&first_protected[5..11], &[0; 6]);
    }
}

// ---------------------------------------------------------------------------------------------
// Renegotiation is refused (RFC 5246 7.2.2, 7.4.1.1; RFC 5746 4.2, 4.4)
// ---------------------------------------------------------------------------------------------

/// The (level, description) of the protected alert records `from` sent, as `to` opens them.
fn protected_alerts(datagrams: &[Vec<u8>], to: &mut DTLSConn) -> Vec<(u8, u8)> {
    let mut alerts = vec![];
    for datagram in datagrams {
        for record in unpack_datagram(datagram).unwrap() {
            if record[0] == 21 && record[3..5] == [0, 1] {
                let opened = to
                    .state
                    .cipher_suite
                    .as_mut()
                    .unwrap()
                    .decrypt(&record)
                    .expect("the alert is protected with the session keys");
                alerts.push((opened[13], opened[14]));
            }
        }
    }
    alerts
}

/// RFC 5746 4.2, 4.4 and RFC 5246 7.2.2: a request to renegotiate (a HelloRequest to a client,
/// a ClientHello to a server, in the established epoch) is refused with a no_renegotiation
/// warning, and the association goes on as before.
#[test]
fn a_renegotiation_request_is_refused_with_a_no_renegotiation_warning() {
    const ALERT_WARNING: u8 = 1;
    const ALERT_NO_RENEGOTIATION: u8 = 100;
    let Exchange {
        mut client,
        mut server,
        ..
    } = completed_pair(builder(), builder());

    // The server asks the client to renegotiate: HelloRequest, an empty message of type 0.
    let hello_request = protected_record(
        &mut server,
        ContentType::Handshake,
        &[0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0],
    );
    client.read(&hello_request).unwrap();
    let answer = drain(&mut client);
    assert_eq!(
        protected_alerts(&answer, &mut server),
        vec![(ALERT_WARNING, ALERT_NO_RENEGOTIATION)]
    );
    assert!(!client.is_failed());
    // The same record again is a replay and draws nothing.
    client.read(&hello_request).unwrap();
    assert!(drain(&mut client).is_empty());

    // The client starts a renegotiation: a ClientHello in the established epoch.
    let mut client_hello = vec![1, 0, 0, 42, 0, 9, 0, 0, 0, 0, 0, 42, 0xfe, 0xfd];
    client_hello.extend_from_slice(&[0x77; 32]);
    client_hello.extend_from_slice(&[0, 0, 0, 2, 0xc0, 0x2b, 1, 0]);
    let renegotiation = protected_record(&mut client, ContentType::Handshake, &client_hello);
    server.read(&renegotiation).unwrap();
    let answer = drain(&mut server);
    assert_eq!(
        protected_alerts(&answer, &mut client),
        vec![(ALERT_WARNING, ALERT_NO_RENEGOTIATION)]
    );
    assert!(!server.is_failed());

    // Both directions still carry data, and the warning itself changes nothing at the peer.
    for datagram in &answer {
        client.read(datagram).unwrap();
    }
    assert!(!client.is_failed());
    let record = application_record(&mut client, 500, b"still here");
    server.read(&record).unwrap();
    assert_eq!(
        server.incoming_application_data().as_deref(),
        Some(&b"still here"[..])
    );
}

/// RFC 5246 7.4: a HelloRequest that arrives while a handshake is in progress is ignored. RFC
/// 5246 7.4.1.1: it is not part of the handshake hashes, so the handshake still completes.
#[test]
fn a_hello_request_during_the_handshake_is_ignored() {
    let now = Instant::now();
    let mut client = client(builder());
    let mut server = server(builder());
    client.handshake(now).unwrap();

    let mut injected = 0;
    for _ in 0..16 {
        for datagram in drain(&mut client) {
            feed(&mut server, now, &datagram).unwrap();
        }
        for datagram in drain(&mut server) {
            // A HelloRequest under the message sequence number the client expects next.
            let expected = client.state.handshake_recv_sequence as u16;
            let mut hello_request = vec![22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 1, injected, 0, 12];
            hello_request.extend_from_slice(&[0, 0, 0, 0]);
            hello_request.extend_from_slice(&expected.to_be_bytes());
            hello_request.extend_from_slice(&[0; 6]);
            feed(&mut client, now, &hello_request).unwrap();
            injected += 1;
            assert!(!client.is_failed());
            feed(&mut client, now, &datagram).unwrap();
        }
        if client.is_handshake_completed() && server.is_handshake_completed() {
            break;
        }
    }
    assert!(injected >= 2);
    assert!(client.is_handshake_completed() && server.is_handshake_completed());
}
