//! The connection tests that sat in `conn_test.rs`'s block comment, written for the async
//! `DTLSConn` that owned a socket. They keep their names and what they check, and drive the
//! sans-I/O connection instead: datagrams are handed between two `DTLSConn`s in memory, as
//! `Endpoint::read` does, and time is a virtual `Instant` that only the test moves.
//!
//! Where an async test raced a spawned peer against a wall-clock timeout, the port advances the
//! virtual clock through the retransmit timer instead.

use super::*;
use crate::cipher_suite::CipherSuiteId;
use crate::compression_methods::default_compression_methods;
use crate::config::{ClientAuthType, ConfigBuilder, ExtendedMasterSecretType};
use crate::crypto::Certificate;
use crate::extension::Extension;
use crate::extension::extension_supported_elliptic_curves::ExtensionSupportedEllipticCurves;
use crate::extension::extension_supported_point_formats::{
    ELLIPTIC_CURVE_POINT_FORMAT_UNCOMPRESSED, ExtensionSupportedPointFormats,
};
use crate::extension::extension_supported_signature_algorithms::ExtensionSupportedSignatureAlgorithms;
use crate::handshake::handshake_message_certificate::HandshakeMessageCertificate;
use crate::handshake::handshake_message_client_hello::HandshakeMessageClientHello;
use crate::handshake::handshake_message_hello_verify_request::HandshakeMessageHelloVerifyRequest;
use crate::handshake::handshake_message_server_hello::HandshakeMessageServerHello;
use crate::handshake::handshake_message_server_hello_done::HandshakeMessageServerHelloDone;
use crate::handshake::handshake_message_server_key_exchange::HandshakeMessageServerKeyExchange;
use crate::handshake::handshake_random::{HandshakeRandom, RANDOM_BYTES_LENGTH};
use crate::signature_hash_algorithm::{
    HashAlgorithm, SignatureAlgorithm, SignatureHashAlgorithm, SignatureScheme,
};
use std::time::SystemTime;

const ERR_PSK_REJECTED: &str = "PSK Rejected";
const ERR_NOT_EXPECTED_CHAIN: &str = "not expected chain";
const ERR_EXPECTED_CHAIN: &str = "expected chain";
const ERR_WRONG_CERT: &str = "wrong cert";

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider is enabled for tests")
}

fn self_signed(name: &str) -> Certificate {
    Certificate::generate_self_signed(vec![name.to_owned()], provider().crypto())
        .expect("a self-signed certificate is generated")
}

fn builder() -> ConfigBuilder {
    // These are the tests of the DTLS 1.2 handshake; DTLS 1.3 has its own in `dtls13`.
    ConfigBuilder::default()
        .with_crypto_provider(provider())
        .with_protocol_versions(
            crate::config::DtlsVersion::Dtls1_2,
            crate::config::DtlsVersion::Dtls1_2,
        )
}

/// What `create_test_client` did: a self-signed certificate when asked, and no CA check.
fn test_client(builder: ConfigBuilder, generate_certificate: bool) -> Result<DTLSConn> {
    let mut builder = builder.with_insecure_skip_verify(true);
    if generate_certificate {
        builder = builder.with_certificates(vec![self_signed("localhost")]);
    }
    Ok(DTLSConn::new(
        Arc::new(builder.build(true, None)?),
        true,
        None,
    ))
}

/// What `create_test_server` did: a self-signed certificate when asked.
fn test_server(builder: ConfigBuilder, generate_certificate: bool) -> Result<DTLSConn> {
    let mut builder = builder;
    if generate_certificate {
        builder = builder.with_certificates(vec![self_signed("localhost")]);
    }
    Ok(DTLSConn::new(
        Arc::new(builder.build(false, None)?),
        false,
        None,
    ))
}

/// A connection built from `builder` as it stands, as `DTLSConn::new` did.
fn plain(builder: ConfigBuilder, is_client: bool) -> Result<DTLSConn> {
    Ok(DTLSConn::new(
        Arc::new(builder.build(is_client, None)?),
        is_client,
        None,
    ))
}

/// One received datagram, handled as `Endpoint::read` handles it.
fn feed(conn: &mut DTLSConn, now: Instant, datagram: &[u8]) -> Result<()> {
    conn.read(datagram)?;
    if !conn.is_handshake_completed() {
        conn.handshake(now)?;
        if conn.handle_incoming_queued_packets()? && !conn.is_handshake_completed() {
            conn.handshake(now)?;
        }
    }
    Ok(())
}

/// Every datagram `conn` wants to send.
fn drain(conn: &mut DTLSConn) -> Vec<BytesMut> {
    let mut datagrams = vec![];
    while let Some(datagram) = conn.outgoing_raw_packet() {
        datagrams.push(datagram);
    }
    datagrams
}

/// Runs a handshake between `client` and `server` and returns each side as the async
/// constructor did: the connection once its handshake completed, or the first error it met. A
/// side whose configuration was rejected is returned as it is, and the other side then never
/// hears from it. A side that neither completes nor fails is an error too.
fn run_handshake(
    client: Result<DTLSConn>,
    server: Result<DTLSConn>,
) -> (Result<DTLSConn>, Result<DTLSConn>) {
    let (mut client, mut server) = match (client, server) {
        (Ok(client), Ok(server)) => (client, server),
        (client, server) => return (client, server),
    };
    let now = Instant::now();
    let mut client_err = client.handshake(now).err();
    let mut server_err = None;
    for _ in 0..64 {
        let to_server = drain(&mut client);
        for datagram in &to_server {
            if server_err.is_none()
                && let Err(err) = feed(&mut server, now, datagram)
            {
                server_err = Some(err);
            }
        }
        let to_client = drain(&mut server);
        for datagram in &to_client {
            if client_err.is_none()
                && let Err(err) = feed(&mut client, now, datagram)
            {
                client_err = Some(err);
            }
        }
        let settled =
            |conn: &DTLSConn, err: &Option<Error>| conn.is_handshake_completed() || err.is_some();
        if settled(&client, &client_err)
            && settled(&server, &server_err)
            && to_server.is_empty()
            && to_client.is_empty()
        {
            break;
        }
    }
    let outcome = |conn: DTLSConn, err: Option<Error>| match err {
        Some(err) => Err(err),
        None if conn.is_handshake_completed() => Ok(conn),
        None => Err(Error::Other("handshake did not complete".to_owned())),
    };
    (outcome(client, client_err), outcome(server, server_err))
}

/// A completed client and server.
fn completed_pair() -> Result<(DTLSConn, DTLSConn)> {
    let profiles = vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80];
    let (client, server) = run_handshake(
        test_client(
            builder().with_srtp_protection_profiles(profiles.clone()),
            true,
        ),
        test_server(builder().with_srtp_protection_profiles(profiles), true),
    );
    Ok((client?, server?))
}

fn record_bytes(record: &RecordLayer) -> Result<Vec<u8>> {
    let mut packet = vec![];
    record.marshal(&mut packet)?;
    Ok(packet)
}

/// The first record of `datagram`, parsed.
fn first_record(datagram: &[u8]) -> Result<RecordLayer> {
    let records = unpack_datagram(datagram)?;
    let mut reader = records[0].as_slice();
    RecordLayer::unmarshal(&mut reader)
}

fn random_at(seconds: u64) -> HandshakeRandom {
    HandshakeRandom {
        gmt_unix_time: SystemTime::UNIX_EPOCH
            .checked_add(Duration::new(seconds, 0))
            .expect("a time after the epoch"),
        random_bytes: [0u8; RANDOM_BYTES_LENGTH],
    }
}

fn assert_error(result: &Result<DTLSConn>, expected: &Error, what: &str) {
    match result {
        Err(err) => assert_eq!(err, expected, "{what}"),
        Ok(_) => panic!("{what}: expected {expected}, got a completed handshake"),
    }
}

/// Fires `conn`'s next timer (retransmission or handshake deadline), as
/// `Endpoint::handle_timeout` does, returning the instant it fired at, or `None` when no timer
/// is armed.
fn fire_timer(conn: &mut DTLSConn) -> Option<(Instant, Result<()>)> {
    let at = conn.next_timeout()?;
    Some((at, conn.handle_timeout(at)))
}

// ---------------------------------------------------------------------------------------------
// The ported tests
// ---------------------------------------------------------------------------------------------

#[test]
fn test_sequence_number_overflow_on_application_data() -> Result<()> {
    let (mut client, mut server) = completed_pair()?;
    client.state.local_sequence_number[1] = MAX_SEQUENCE_NUMBER;

    let buf_a = vec![0xFA; 100];
    client.write(&buf_a)?;
    client.handle_outgoing_packets()?;
    let now = Instant::now();
    while let Some(datagram) = client.outgoing_compacted_raw_packets.pop_front() {
        feed(&mut server, now, &datagram)?;
    }
    let buf_b = server
        .incoming_application_data()
        .expect("the record at the last sequence number is delivered");
    assert_eq!(&buf_a[..], &buf_b[..]);

    client.write(&buf_a)?;
    assert_eq!(
        client.handle_outgoing_packets(),
        Err(Error::ErrSequenceNumberOverflow),
        "the record past the last sequence number is refused"
    );
    Ok(())
}

#[test]
fn test_sequence_number_overflow_on_handshake() -> Result<()> {
    let (mut client, _server) = completed_pair()?;
    client.state.local_sequence_number[0] = MAX_SEQUENCE_NUMBER + 1;

    // Try to send handshake packet.
    client.write_packets(vec![Packet {
        record: RecordLayer::new(
            PROTOCOL_VERSION1_2,
            0,
            Content::Handshake(Handshake::new(HandshakeMessage::ClientHello(
                HandshakeMessageClientHello {
                    version: PROTOCOL_VERSION1_2,
                    random: HandshakeRandom::default(),
                    cookie: vec![0; 64],

                    cipher_suites: vec![CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256],
                    compression_methods: default_compression_methods(),
                    extensions: vec![],
                },
            ))),
        ),
        should_encrypt: false,
        reset_local_sequence_number: false,
    }]);
    assert_eq!(
        client.handle_outgoing_packets(),
        Err(Error::ErrSequenceNumberOverflow)
    );
    Ok(())
}

#[test]
fn test_handshake_with_alert() -> Result<()> {
    // CipherSuiteNoIntersection: the server finds no common suite and says so.
    let (client, server) = run_handshake(
        test_client(
            builder()
                .with_cipher_suites(vec![CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256]),
            true,
        ),
        test_server(
            builder()
                .with_cipher_suites(vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256]),
            true,
        ),
    );
    assert_error(
        &server,
        &Error::ErrCipherSuiteNoIntersection,
        "CipherSuiteNoIntersection server",
    );
    assert_error(
        &client,
        &Error::ErrAlertFatalOrClose,
        "CipherSuiteNoIntersection client",
    );

    // SignatureSchemesNoIntersection: the client accepts no signature the server can make.
    // Where the provider cannot verify P-521 at all, the client's configuration is already
    // refused with the same error, and the server is never contacted.
    let client = test_client(
        builder()
            .with_cipher_suites(vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256])
            .with_signature_schemes(vec![SignatureScheme::EcdsaWithP521AndSha512]),
        true,
    );
    let client_configured = client.is_ok();
    let (client, server) = run_handshake(
        client,
        test_server(
            builder()
                .with_cipher_suites(vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256])
                .with_signature_schemes(vec![SignatureScheme::EcdsaWithP256AndSha256]),
            true,
        ),
    );
    assert_error(
        &client,
        &Error::ErrNoAvailableSignatureSchemes,
        "SignatureSchemesNoIntersection client",
    );
    if client_configured {
        assert_error(
            &server,
            &Error::ErrAlertFatalOrClose,
            "SignatureSchemesNoIntersection server",
        );
    }
    Ok(())
}

#[test]
fn test_export_keying_material() -> Result<()> {
    let export_label = "EXTRACTOR-dtls_srtp";
    let expected_server_key = vec![0x61, 0x09, 0x9d, 0x7d, 0xcb, 0x08, 0x52, 0x2c, 0xe7, 0x7b];
    let expected_client_key = vec![0x87, 0xf0, 0x40, 0x02, 0xf6, 0x1c, 0xf1, 0xfe, 0x8c, 0x77];

    let mut c = DTLSConn::new(Arc::new(HandshakeConfig::new(provider())), false, None);
    c.state.local_random = random_at(500);
    c.state.remote_random = random_at(1000);
    c.state.local_sequence_number = vec![0, 0];
    // RFC 7627 5.4: only a session with the extended master secret exports key material.
    c.state.extended_master_secret = true;
    c.state.cipher_suite = Some(Box::new(
        crate::cipher_suite::cipher_suite_aes_128_gcm_sha256::CipherSuiteAes128GcmSha256::new(
            false,
        ),
    ));

    c.set_local_epoch(0);
    assert_eq!(
        c.connection_state()
            .export_keying_material(export_label, &[], 0)
            .err(),
        Some(Error::HandshakeInProgress),
        "ExportKeyingMaterial when epoch == 0"
    );

    c.set_local_epoch(1);
    assert_eq!(
        c.connection_state()
            .export_keying_material(export_label, &[0x00], 0)
            .err(),
        Some(Error::ContextUnsupported),
        "ExportKeyingMaterial with context"
    );

    for k in INVALID_KEYING_LABELS.iter() {
        assert_eq!(
            c.connection_state().export_keying_material(k, &[], 0).err(),
            Some(Error::ReservedExportKeyingMaterial),
            "ExportKeyingMaterial reserved label {k}"
        );
    }

    let keying_material = c
        .connection_state()
        .export_keying_material(export_label, &[], 10)?;
    assert_eq!(
        keying_material.as_ref(),
        &expected_server_key[..],
        "ExportKeyingMaterial server export"
    );

    c.state.is_client = true;
    let keying_material = c
        .connection_state()
        .export_keying_material(export_label, &[], 10)?;
    assert_eq!(
        keying_material.as_ref(),
        &expected_client_key[..],
        "ExportKeyingMaterial client export"
    );
    Ok(())
}

fn psk_callback_client(_hint: &[u8]) -> Result<Vec<u8>> {
    Ok(vec![0xAB, 0xC1, 0x23])
}

fn psk_callback_server(_hint: &[u8]) -> Result<Vec<u8>> {
    Ok(vec![0xAB, 0xC1, 0x23])
}

fn psk_callback_hint_fail(_hint: &[u8]) -> Result<Vec<u8>> {
    Err(Error::Other(ERR_PSK_REJECTED.to_owned()))
}

#[test]
fn test_psk() -> Result<()> {
    let tests = vec![
        (
            "Server identity specified",
            Some("Test Identity".as_bytes().to_vec()),
        ),
        ("Server identity nil", None),
    ];

    for (name, server_identity) in tests {
        let client_identity = "Client Identity".as_bytes();
        let (client, server) = run_handshake(
            test_client(
                builder()
                    .with_psk(Some(Arc::new(psk_callback_client)))
                    .with_psk_identity_hint(Some(client_identity.to_vec()))
                    .with_cipher_suites(vec![CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8]),
                false,
            ),
            test_server(
                builder()
                    .with_psk(Some(Arc::new(psk_callback_server)))
                    .with_psk_identity_hint(server_identity)
                    .with_cipher_suites(vec![CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8]),
                false,
            ),
        );
        let server = server?;
        assert!(client.is_ok(), "{name}: the client completes");
        assert_eq!(
            server.connection_state().identity_hint,
            client_identity,
            "TestPSK: Server ClientPSKIdentity Mismatch '{name}'"
        );
    }
    Ok(())
}

#[test]
fn test_psk_hint_fail() -> Result<()> {
    let (client, server) = run_handshake(
        test_client(
            builder()
                .with_psk(Some(Arc::new(psk_callback_hint_fail)))
                .with_psk_identity_hint(Some(vec![]))
                .with_cipher_suites(vec![CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8]),
            false,
        ),
        test_server(
            builder()
                .with_psk(Some(Arc::new(psk_callback_hint_fail)))
                .with_psk_identity_hint(Some(vec![]))
                .with_cipher_suites(vec![CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8]),
            false,
        ),
    );
    match client {
        Err(err) => assert!(
            err.to_string().contains(ERR_PSK_REJECTED),
            "TestPSK: Client error exp({ERR_PSK_REJECTED}) failed({err})"
        ),
        Ok(_) => panic!("Expected client error, but got OK"),
    }
    assert!(server.is_err(), "the server does not complete either");
    Ok(())
}

/// No server: the client retransmits on its timer until the configured handshake deadline,
/// then fails.
#[test]
fn test_client_timeout() -> Result<()> {
    let mut client = test_client(
        builder().with_handshake_timeout(Some(Duration::from_secs(30))),
        true,
    )?;
    client.handshake(Instant::now())?;
    drain(&mut client);

    let mut result = Ok(());
    for _ in 0..16 {
        let Some((_, fired)) = fire_timer(&mut client) else {
            break;
        };
        drain(&mut client);
        result = fired;
        if result.is_err() {
            break;
        }
    }
    assert_eq!(result, Err(Error::ErrHandshakeTimeout));
    assert!(client.is_failed());
    assert!(!client.is_handshake_completed());
    Ok(())
}

#[test]
fn test_srtp_configuration() -> Result<()> {
    #[allow(clippy::type_complexity)]
    let tests: Vec<(
        &str,
        Vec<SrtpProtectionProfile>,
        Vec<SrtpProtectionProfile>,
        SrtpProtectionProfile,
        Option<Error>,
        Option<Error>,
    )> = vec![
        (
            "No SRTP in use",
            vec![],
            vec![],
            SrtpProtectionProfile::Unsupported,
            None,
            None,
        ),
        (
            "SRTP both ends",
            vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80],
            vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80],
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
            None,
            None,
        ),
        (
            // RFC 5764 4.1.1: a server that does not do DTLS-SRTP ignores use_srtp; it is the
            // client, which asked for SRTP, that refuses a ServerHello without it.
            "SRTP client only",
            vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80],
            vec![],
            SrtpProtectionProfile::Unsupported,
            Some(Error::ErrRequestedButNoSrtpExtension),
            Some(Error::ErrAlertFatalOrClose),
        ),
        (
            // RFC 5764 section 4.1.1: with no shared profile the server leaves the extension
            // out (the association would fall back to plain DTLS); this client did not allow
            // going without and aborts.
            "No shared profile",
            vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80],
            vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32],
            SrtpProtectionProfile::Unsupported,
            Some(Error::ErrRequestedButNoSrtpExtension),
            Some(Error::ErrAlertFatalOrClose),
        ),
        (
            "SRTP server only",
            vec![],
            vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80],
            SrtpProtectionProfile::Unsupported,
            None,
            None,
        ),
        (
            "Multiple Suites",
            vec![
                SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
                SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32,
            ],
            vec![
                SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
                SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32,
            ],
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
            None,
            None,
        ),
        (
            "Multiple Suites, Client Chooses",
            vec![
                SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
                SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32,
            ],
            vec![
                SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32,
                SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
            ],
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
            None,
            None,
        ),
    ];

    for (name, client_srtp, server_srtp, expected_profile, want_client_err, want_server_err) in
        tests
    {
        let (client, server) = run_handshake(
            test_client(builder().with_srtp_protection_profiles(client_srtp), true),
            test_server(builder().with_srtp_protection_profiles(server_srtp), true),
        );
        for (side, result, want_err) in [
            ("Server", server, want_server_err),
            ("Client", client, want_client_err),
        ] {
            match (result, want_err) {
                (Err(err), Some(expected)) => {
                    assert_eq!(err, expected, "{name}: {side} error")
                }
                (Ok(conn), None) => assert_eq!(
                    conn.selected_srtp_protection_profile(),
                    expected_profile,
                    "test_srtp_configuration: {side} SRTPProtectionProfile Mismatch '{name}'"
                ),
                (Err(err), None) => panic!("{name}: {side} expected no error: {err}"),
                (Ok(_), Some(expected)) => panic!("{name}: {side} expected {expected}, got ok"),
            }
        }
    }
    Ok(())
}

/// RFC 5764 section 4.1.1: with no shared profile the server omits `use_srtp` and a client
/// that allows it gets an association without SRTP; a server for which that is not acceptable
/// (`with_use_srtp_required`) answers with a fatal alert instead.
#[test]
fn a_server_without_a_shared_srtp_profile_falls_back_or_refuses() -> Result<()> {
    let offered = vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80];
    let other = vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32];

    let (client, server) = run_handshake(
        test_client(
            builder()
                .with_srtp_protection_profiles(offered.clone())
                .with_use_srtp_optional(true),
            true,
        ),
        test_server(builder().with_srtp_protection_profiles(other.clone()), true),
    );
    for conn in [client?, server?] {
        assert_eq!(
            conn.selected_srtp_protection_profile(),
            SrtpProtectionProfile::Unsupported
        );
    }

    let (client, server) = run_handshake(
        test_client(
            builder()
                .with_srtp_protection_profiles(offered)
                .with_use_srtp_optional(true),
            true,
        ),
        test_server(
            builder()
                .with_srtp_protection_profiles(other)
                .with_use_srtp_required(true),
            true,
        ),
    );
    assert_eq!(server.err(), Some(Error::ErrServerNoMatchingSrtpProfile));
    assert_eq!(client.err(), Some(Error::ErrAlertFatalOrClose));
    Ok(())
}

fn ca_pool(cert: &Certificate) -> Result<rustls::RootCertStore> {
    let mut pool = rustls::RootCertStore::empty();
    pool.add(cert.certificate[0].clone())
        .map_err(|_err| Error::Other("add cert error".to_owned()))?;
    Ok(pool)
}

#[test]
fn test_client_certificate() -> Result<()> {
    let server_name = "localhost".to_owned();
    let srv_cert = self_signed("localhost");
    let srv_ca_pool = ca_pool(&srv_cert)?;
    let cert = self_signed("localhost");
    let ca_pool = ca_pool(&cert)?;

    let client_builder = |with_cert: bool| {
        let builder = builder()
            .with_roots_cas(srv_ca_pool.clone())
            .with_server_name(server_name.clone());
        if with_cert {
            builder.with_certificates(vec![cert.clone()])
        } else {
            builder
        }
    };
    let server_builder = |client_auth: ClientAuthType,
                          client_cas: Option<rustls::RootCertStore>| {
        let builder = builder()
            .with_certificates(vec![srv_cert.clone()])
            .with_client_auth(client_auth);
        match client_cas {
            Some(pool) => builder.with_client_cas(pool),
            None => builder,
        }
    };

    let tests = vec![
        (
            "NoClientCert",
            false,
            ClientAuthType::NoClientCert,
            None,
            false,
        ),
        (
            "NoClientCert_cert",
            true,
            ClientAuthType::RequireAnyClientCert,
            None,
            false,
        ),
        (
            "RequestClientCert_cert",
            true,
            ClientAuthType::RequestClientCert,
            None,
            false,
        ),
        (
            "RequestClientCert_no_cert",
            false,
            ClientAuthType::RequestClientCert,
            None,
            false,
        ),
        (
            "RequireAnyClientCert",
            true,
            ClientAuthType::RequireAnyClientCert,
            None,
            false,
        ),
        (
            "RequireAnyClientCert_error",
            false,
            ClientAuthType::RequireAnyClientCert,
            None,
            true,
        ),
        (
            "VerifyClientCertIfGiven_no_cert",
            false,
            ClientAuthType::VerifyClientCertIfGiven,
            Some(ca_pool.clone()),
            false,
        ),
        (
            "VerifyClientCertIfGiven_cert",
            true,
            ClientAuthType::VerifyClientCertIfGiven,
            Some(ca_pool.clone()),
            false,
        ),
        (
            "VerifyClientCertIfGiven_error",
            true,
            ClientAuthType::VerifyClientCertIfGiven,
            None,
            true,
        ),
        (
            "RequireAndVerifyClientCert",
            true,
            ClientAuthType::RequireAndVerifyClientCert,
            Some(ca_pool.clone()),
            false,
        ),
    ];

    for (name, client_has_cert, client_auth, client_cas, want_err) in tests {
        let (client_result, result) = run_handshake(
            plain(client_builder(client_has_cert), true),
            plain(server_builder(client_auth, client_cas), false),
        );

        if want_err {
            assert!(result.is_err(), "{name} Error expected");
            continue;
        }

        let server = result.map_err(|err| Error::Other(format!("{name} Server failed({err})")))?;
        let client =
            client_result.map_err(|err| Error::Other(format!("{name} Client failed({err})")))?;

        let actual_client_cert = &server.connection_state().peer_certificates;
        if client_auth == ClientAuthType::RequireAnyClientCert
            || client_auth == ClientAuthType::RequireAndVerifyClientCert
        {
            assert!(
                !actual_client_cert.is_empty(),
                "{name} Client did not provide a certificate"
            );
            assert_eq!(
                actual_client_cert[0],
                cert.certificate[0].as_ref(),
                "{name} Client certificate was not communicated correctly"
            );
        }
        if client_auth == ClientAuthType::NoClientCert {
            assert!(
                actual_client_cert.is_empty(),
                "{name} Client certificate wasn't expected"
            );
        }

        let actual_server_cert = &client.connection_state().peer_certificates;
        assert!(
            !actual_server_cert.is_empty(),
            "{name} Server did not provide a certificate"
        );
        assert_eq!(
            actual_server_cert[0],
            srv_cert.certificate[0].as_ref(),
            "{name} Server certificate was not communicated correctly"
        );
    }
    Ok(())
}

#[test]
fn test_extended_master_secret() -> Result<()> {
    use ExtendedMasterSecretType::{Disable, Request, Require};
    let tests = vec![
        (
            "Request_Request_ExtendedMasterSecret",
            Request,
            Request,
            None,
            None,
        ),
        (
            "Request_Require_ExtendedMasterSecret",
            Request,
            Require,
            None,
            None,
        ),
        (
            "Request_Disable_ExtendedMasterSecret",
            Request,
            Disable,
            None,
            None,
        ),
        (
            "Require_Request_ExtendedMasterSecret",
            Require,
            Request,
            None,
            None,
        ),
        (
            "Require_Require_ExtendedMasterSecret",
            Require,
            Require,
            None,
            None,
        ),
        (
            "Require_Disable_ExtendedMasterSecret",
            Require,
            Disable,
            Some(Error::ErrClientRequiredButNoServerEms),
            Some(Error::ErrAlertFatalOrClose),
        ),
        (
            "Disable_Request_ExtendedMasterSecret",
            Disable,
            Request,
            None,
            None,
        ),
        (
            "Disable_Require_ExtendedMasterSecret",
            Disable,
            Require,
            Some(Error::ErrAlertFatalOrClose),
            Some(Error::ErrServerRequiredButNoClientEms),
        ),
        (
            "Disable_Disable_ExtendedMasterSecret",
            Disable,
            Disable,
            None,
            None,
        ),
    ];

    for (name, client_ems, server_ems, expected_client_err, expected_server_err) in tests {
        let (client, server) = run_handshake(
            test_client(builder().with_extended_master_secret(client_ems), true),
            test_server(builder().with_extended_master_secret(server_ems), true),
        );
        for (side, result, expected) in [
            ("Client", client, expected_client_err),
            ("Server", server, expected_server_err),
        ] {
            match (result, expected) {
                (Err(err), Some(expected)) => {
                    assert_eq!(err, expected, "{name}: {side} error")
                }
                (Ok(_), None) => {}
                (Err(err), None) => panic!("{name}: {side} expected ok, but got {err}"),
                (Ok(_), Some(expected)) => panic!("{name}: {side} expected {expected}, got ok"),
            }
        }
    }
    Ok(())
}

fn fn_not_expected_chain(
    _cert: &[Vec<u8>],
    chain: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<()> {
    if !chain.is_empty() {
        return Err(Error::Other(ERR_NOT_EXPECTED_CHAIN.to_owned()));
    }
    Ok(())
}

fn fn_expected_chain(
    _cert: &[Vec<u8>],
    chain: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<()> {
    if chain.is_empty() {
        return Err(Error::Other(ERR_EXPECTED_CHAIN.to_owned()));
    }
    Ok(())
}

fn fn_wrong_cert(
    _cert: &[Vec<u8>],
    _chain: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<()> {
    Err(Error::Other(ERR_WRONG_CERT.to_owned()))
}

#[test]
fn test_server_certificate() -> Result<()> {
    let server_name = "localhost".to_owned();
    let cert = self_signed(&server_name);
    let ca_pool = ca_pool(&cert)?;

    let server_no_client_cert = || {
        builder()
            .with_certificates(vec![cert.clone()])
            .with_client_auth(ClientAuthType::NoClientCert)
    };

    let tests: Vec<(&str, ConfigBuilder, ConfigBuilder, bool)> = vec![
        (
            "no_ca",
            builder().with_server_name(server_name.clone()),
            server_no_client_cert(),
            true,
        ),
        (
            "good_ca",
            builder()
                .with_roots_cas(ca_pool.clone())
                .with_server_name(server_name.clone()),
            server_no_client_cert(),
            false,
        ),
        (
            "no_ca_skip_verify",
            builder()
                .with_insecure_skip_verify(true)
                .with_server_name(server_name.clone()),
            server_no_client_cert(),
            false,
        ),
        (
            "good_ca_skip_verify_custom_verify_peer",
            builder()
                .with_roots_cas(ca_pool.clone())
                .with_server_name(server_name.clone())
                .with_certificates(vec![cert.clone()]),
            builder()
                .with_certificates(vec![cert.clone()])
                .with_client_auth(ClientAuthType::RequireAnyClientCert)
                .with_verify_peer_certificate(Some(Arc::new(fn_not_expected_chain))),
            false,
        ),
        (
            "good_ca_verify_custom_verify_peer",
            builder()
                .with_roots_cas(ca_pool.clone())
                .with_server_name(server_name.clone())
                .with_certificates(vec![cert.clone()]),
            builder()
                .with_certificates(vec![cert.clone()])
                .with_client_auth(ClientAuthType::RequireAndVerifyClientCert)
                .with_client_cas(ca_pool.clone())
                .with_verify_peer_certificate(Some(Arc::new(fn_expected_chain))),
            false,
        ),
        (
            "good_ca_custom_verify_peer",
            builder()
                .with_roots_cas(ca_pool.clone())
                .with_server_name(server_name.clone())
                .with_verify_peer_certificate(Some(Arc::new(fn_wrong_cert))),
            server_no_client_cert(),
            true,
        ),
        (
            "server_name",
            builder()
                .with_roots_cas(ca_pool.clone())
                .with_server_name(server_name.clone()),
            server_no_client_cert(),
            false,
        ),
        (
            "server_name_error",
            builder()
                .with_roots_cas(ca_pool.clone())
                .with_server_name("barfoo".to_owned()),
            server_no_client_cert(),
            true,
        ),
    ];

    for (name, client_cfg, server_cfg, want_err) in tests {
        let (client, _server) = run_handshake(plain(client_cfg, true), plain(server_cfg, false));
        match client {
            Err(err) if !want_err => panic!("{name}: Client failed({err})"),
            Ok(_) if want_err => panic!("{name}: Error expected"),
            _ => {}
        }
    }
    Ok(())
}

#[test]
fn test_cipher_suite_configuration() -> Result<()> {
    use CipherSuiteId::{
        Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm, Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8,
        Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256, Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
    };
    let tests = vec![
        (
            "No CipherSuites specified",
            vec![],
            vec![],
            None,
            None,
            None,
        ),
        (
            "Invalid CipherSuite",
            vec![CipherSuiteId::Unsupported],
            vec![CipherSuiteId::Unsupported],
            Some(Error::ErrInvalidCipherSuite),
            Some(Error::ErrInvalidCipherSuite),
            None,
        ),
        (
            "Valid CipherSuites specified",
            vec![Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256],
            vec![Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256],
            None,
            None,
            Some(Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256),
        ),
        (
            "CipherSuites mismatch",
            vec![Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256],
            vec![Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha],
            Some(Error::ErrAlertFatalOrClose),
            Some(Error::ErrCipherSuiteNoIntersection),
            None,
        ),
        (
            "Valid CipherSuites CCM specified",
            vec![Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm],
            vec![Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm],
            None,
            None,
            Some(Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm),
        ),
        (
            "Valid CipherSuites CCM-8 specified",
            vec![Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8],
            vec![Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8],
            None,
            None,
            Some(Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8),
        ),
        (
            "Server supports subset of client suites",
            vec![
                Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
                Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
            ],
            vec![Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha],
            None,
            None,
            Some(Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha),
        ),
    ];

    for (
        name,
        client_cipher_suites,
        server_cipher_suites,
        want_client_error,
        want_server_error,
        want_selected_cipher_suite,
    ) in tests
    {
        let (client, server) = run_handshake(
            test_client(builder().with_cipher_suites(client_cipher_suites), true),
            test_server(builder().with_cipher_suites(server_cipher_suites), true),
        );
        match (server, want_server_error) {
            (Err(err), Some(expected)) => assert_eq!(err, expected, "{name}: Server error"),
            (Ok(_), None) => {}
            (Err(err), None) => panic!("{name}: Server expected ok, but got {err}"),
            (Ok(_), Some(expected)) => panic!("{name}: Server expected {expected}, got ok"),
        }
        match (client, want_client_error) {
            (Err(err), Some(expected)) => assert_eq!(err, expected, "{name}: Client error"),
            (Ok(client), None) => {
                if let Some(want_cs) = want_selected_cipher_suite {
                    let selected = client.state.cipher_suite.as_ref().map(|cs| cs.id());
                    assert_eq!(
                        selected,
                        Some(want_cs),
                        "test_cipher_suite_configuration: Server Selected Bad Cipher Suite '{name}'"
                    );
                }
            }
            (Err(err), None) => panic!("{name}: Client expected ok, but got {err}"),
            (Ok(_), Some(expected)) => panic!("{name}: Client expected {expected}, got ok"),
        }
    }
    Ok(())
}

fn psk_callback(_b: &[u8]) -> Result<Vec<u8>> {
    Ok(vec![0x00, 0x01, 0x02])
}

#[test]
fn test_psk_configuration() -> Result<()> {
    let tests = vec![
        (
            "PSK specified",
            false,
            false,
            true,
            true,
            Some(vec![0x00]),
            Some(vec![0x00]),
            Some(Error::ErrNoAvailableCipherSuites),
            Some(Error::ErrNoAvailableCipherSuites),
        ),
        (
            // A server may hold a psk and a certificate both and let each handshake pick (see
            // `test_client_rejects_psk_and_certificate_but_server_accepts_both`); a client may not.
            "PSK and certificate specified",
            true,
            true,
            true,
            true,
            Some(vec![0x00]),
            Some(vec![0x00]),
            Some(Error::ErrPskAndCertificate),
            None,
        ),
        (
            "PSK and no identity specified",
            false,
            false,
            true,
            true,
            None,
            None,
            Some(Error::ErrPskAndIdentityMustBeSetForClient),
            Some(Error::ErrNoAvailableCipherSuites),
        ),
        (
            "No PSK and identity specified",
            false,
            false,
            false,
            false,
            Some(vec![0x00]),
            Some(vec![0x00]),
            Some(Error::ErrIdentityNoPsk),
            Some(Error::ErrServerMustHaveCertificate),
        ),
    ];

    for (
        name,
        client_has_certificate,
        server_has_certificate,
        client_psk,
        server_psk,
        client_psk_identity,
        server_psk_identity,
        want_client_error,
        want_server_error,
    ) in tests
    {
        let psk = |enabled: bool| -> Option<crate::config::PskCallback> {
            if enabled {
                Some(Arc::new(psk_callback))
            } else {
                None
            }
        };
        // Both are configuration errors, so each side is built on its own: no handshake runs.
        let client = test_client(
            builder()
                .with_psk(psk(client_psk))
                .with_psk_identity_hint(client_psk_identity),
            client_has_certificate,
        );
        let server = test_server(
            builder()
                .with_psk(psk(server_psk))
                .with_psk_identity_hint(server_psk_identity),
            server_has_certificate,
        );
        for (side, result, want) in [
            ("Server", server, want_server_error),
            ("Client", client, want_client_error),
        ] {
            match (result, want) {
                (Err(err), Some(expected)) => {
                    assert_eq!(err, expected, "{name} test_psk_configuration: {side} error")
                }
                (Ok(_), None) => {}
                (Err(err), None) => panic!("{name}: {side} expected ok, but got {err}"),
                (Ok(_), Some(expected)) => panic!("{name}: {side} expected {expected}, got ok"),
            }
        }
    }
    Ok(())
}

/// A ClientHello the server answers but whose handshake never goes on: the server never
/// completes, and its timer sends nothing more (its HelloVerifyRequest flight is not
/// retransmitted).
#[test]
fn test_server_timeout() -> Result<()> {
    let cookie = vec![0x5au8; 20];
    let cipher_suites = vec![
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
        CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256,
    ];
    let signature_hash_algorithms = [
        (HashAlgorithm::Sha256, SignatureAlgorithm::Ecdsa),
        (HashAlgorithm::Sha384, SignatureAlgorithm::Ecdsa),
        (HashAlgorithm::Sha512, SignatureAlgorithm::Ecdsa),
        (HashAlgorithm::Sha256, SignatureAlgorithm::Rsa),
        (HashAlgorithm::Sha384, SignatureAlgorithm::Rsa),
        (HashAlgorithm::Sha512, SignatureAlgorithm::Rsa),
    ]
    .into_iter()
    .map(|(hash, signature)| SignatureHashAlgorithm { hash, signature })
    .collect();
    let extensions = vec![
        Extension::SupportedSignatureAlgorithms(ExtensionSupportedSignatureAlgorithms {
            signature_hash_algorithms,
        }),
        Extension::SupportedEllipticCurves(ExtensionSupportedEllipticCurves {
            elliptic_curves: vec![NamedCurve::X25519, NamedCurve::P256, NamedCurve::P384],
        }),
        Extension::SupportedPointFormats(ExtensionSupportedPointFormats {
            point_formats: vec![ELLIPTIC_CURVE_POINT_FORMAT_UNCOMPRESSED],
        }),
    ];
    let packet = record_bytes(&RecordLayer::new(
        PROTOCOL_VERSION1_2,
        0,
        Content::Handshake(Handshake::new(HandshakeMessage::ClientHello(
            HandshakeMessageClientHello {
                version: PROTOCOL_VERSION1_2,
                cookie,
                random: random_at(500),
                cipher_suites,
                compression_methods: default_compression_methods(),
                extensions,
            },
        ))),
    ))?;

    let mut server = test_server(
        builder()
            .with_cipher_suites(vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256])
            .with_flight_interval(Duration::from_millis(100)),
        true,
    )?;
    feed(&mut server, Instant::now(), &packet)?;
    assert!(
        !drain(&mut server).is_empty(),
        "the server answers the ClientHello"
    );

    // Ten flight intervals of virtual time.
    for _ in 0..10 {
        let Some((_, result)) = fire_timer(&mut server) else {
            break;
        };
        result?;
        assert!(
            drain(&mut server).is_empty(),
            "Expected no additional messages from server"
        );
    }
    assert!(!server.is_handshake_completed());
    Ok(())
}

#[test]
fn test_protocol_version_validation() -> Result<()> {
    let cookie = vec![0x5au8; 20];
    let random = random_at(500);
    let downgraded = ProtocolVersion {
        major: 0xfe,
        minor: 0xff,
    };
    let client_hello = |version: ProtocolVersion, sequence: u64, cookie: &[u8]| {
        let mut handshake =
            Handshake::new(HandshakeMessage::ClientHello(HandshakeMessageClientHello {
                version,
                cookie: cookie.to_vec(),
                random: random.clone(),
                cipher_suites: vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256],
                compression_methods: default_compression_methods(),
                extensions: vec![],
            }));
        handshake.handshake_header.message_sequence = sequence as u16;
        let mut record = RecordLayer::new(PROTOCOL_VERSION1_2, 0, Content::Handshake(handshake));
        record.record_layer_header.sequence_number = sequence;
        record
    };

    // Server: a ClientHello of an unsupported version, as the first one and as the one that
    // answers HelloVerifyRequest. The second must echo the server's cookie: without it the
    // message is not the client's and is discarded whatever it says (RFC 6347 4.2.1).
    for (name, downgrade_second) in [
        ("ClientHelloVersion", false),
        ("SecondsClientHelloVersion", true),
    ] {
        let mut server = test_server(
            builder()
                .with_cipher_suites(vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256])
                .with_flight_interval(Duration::from_millis(100)),
            true,
        )?;
        let first_version = if downgrade_second {
            PROTOCOL_VERSION1_2
        } else {
            downgraded
        };
        let first = record_bytes(&client_hello(first_version, 0, &cookie))?;
        let mut last_error = feed(&mut server, Instant::now(), &first).err();
        let mut resp = drain(&mut server);
        if downgrade_second {
            assert_eq!(
                last_error, None,
                "{name}: the first ClientHello is accepted"
            );
            let server_cookie =
                match first_record(resp.first().expect("HelloVerifyRequest"))?.content {
                    Content::Handshake(h) => match h.handshake_message {
                        HandshakeMessage::HelloVerifyRequest(h) => h.cookie,
                        other => panic!("{name}: unexpected handshake message {other:?}"),
                    },
                    other => panic!("{name}: unexpected content {other:?}"),
                };
            let second = record_bytes(&client_hello(downgraded, 1, &server_cookie))?;
            last_error = feed(&mut server, Instant::now(), &second).err();
            resp = drain(&mut server);
        }
        assert_eq!(
            last_error,
            Some(Error::ErrUnsupportedProtocolVersion),
            "{name}: Server error"
        );
        let first = resp.first().expect("the server answers");
        assert_eq!(
            first_record(first)?.record_layer_header.content_type,
            ContentType::Alert,
            "{name}: Peer must return alert to unsupported protocol version"
        );
    }

    // Client
    let local_keypair = NamedCurve::X25519.generate_keypair_with_crypto(provider().crypto())?;
    let server_flight = |message: HandshakeMessage, sequence: u64| {
        let mut handshake = Handshake::new(message);
        handshake.handshake_header.message_sequence = sequence as u16;
        let mut record = RecordLayer::new(PROTOCOL_VERSION1_2, 0, Content::Handshake(handshake));
        record.record_layer_header.sequence_number = sequence;
        record
    };
    let records = vec![
        server_flight(
            HandshakeMessage::HelloVerifyRequest(HandshakeMessageHelloVerifyRequest {
                version: PROTOCOL_VERSION1_2,
                cookie: cookie.clone(),
            }),
            0,
        ),
        server_flight(
            HandshakeMessage::ServerHello(HandshakeMessageServerHello {
                version: downgraded,
                random: random.clone(),
                cipher_suite: CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
                compression_method: default_compression_methods().ids[0],
                extensions: vec![],
            }),
            1,
        ),
        server_flight(
            HandshakeMessage::Certificate(HandshakeMessageCertificate {
                certificate: vec![],
            }),
            2,
        ),
        server_flight(
            HandshakeMessage::ServerKeyExchange(HandshakeMessageServerKeyExchange {
                identity_hint: vec![],
                elliptic_curve_type: crate::curve::EllipticCurveType::NamedCurve,
                named_curve: NamedCurve::X25519,
                public_key: local_keypair.public_key.clone(),
                algorithm: SignatureHashAlgorithm {
                    hash: HashAlgorithm::Sha256,
                    signature: SignatureAlgorithm::Ecdsa,
                },
                signature: vec![0; 64],
            }),
            3,
        ),
        server_flight(
            HandshakeMessage::ServerHelloDone(HandshakeMessageServerHelloDone {}),
            4,
        ),
    ];

    let mut client = test_client(
        builder()
            .with_cipher_suites(vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256])
            .with_flight_interval(Duration::from_millis(100)),
        true,
    )?;
    client.handshake(Instant::now())?;
    drain(&mut client);
    let mut client_error = None;
    let mut resp = vec![];
    for record in &records {
        if let Err(err) = feed(&mut client, Instant::now(), &record_bytes(record)?) {
            client_error.get_or_insert(err);
        }
        resp.extend(drain(&mut client));
    }
    assert_eq!(
        client_error,
        Some(Error::ErrUnsupportedProtocolVersion),
        "ServerHelloVersion: Client error"
    );
    let last = resp.last().expect("the client answers");
    assert_eq!(
        first_record(last)?.record_layer_header.content_type,
        ContentType::Alert,
        "ServerHelloVersion: Peer must return alert to unsupported protocol version"
    );
    Ok(())
}

#[test]
fn test_multiple_hello_verify_request() -> Result<()> {
    let mut cookies = vec![
        // first clientHello contains an empty cookie
        vec![],
    ];
    let mut packets = vec![];
    for i in 0..2u8 {
        let cookie = vec![0x10 + i; 20];
        cookies.push(cookie.clone());

        let mut handshake = Handshake::new(HandshakeMessage::HelloVerifyRequest(
            HandshakeMessageHelloVerifyRequest {
                version: PROTOCOL_VERSION1_2,
                cookie,
            },
        ));
        handshake.handshake_header.message_sequence = u16::from(i);
        let mut record = RecordLayer::new(PROTOCOL_VERSION1_2, 0, Content::Handshake(handshake));
        record.record_layer_header.sequence_number = u64::from(i);
        packets.push(record_bytes(&record)?);
    }

    let mut client = test_client(builder(), true)?;
    client.handshake(Instant::now())?;

    for (i, cookie) in cookies.iter().enumerate() {
        // read client hello
        let sent = drain(&mut client);
        let datagram = sent.first().expect("the client sends a ClientHello");
        match first_record(datagram)?.content {
            Content::Handshake(h) => match h.handshake_message {
                HandshakeMessage::ClientHello(client_hello) => {
                    assert_eq!(&client_hello.cookie, cookie, "Wrong cookie {i}");
                }
                _ => panic!("unexpected handshake message"),
            },
            _ => panic!("unexpected content"),
        };

        if packets.len() <= i {
            break;
        }
        // write hello verify request
        feed(&mut client, Instant::now(), &packets[i])?;
    }
    Ok(())
}
