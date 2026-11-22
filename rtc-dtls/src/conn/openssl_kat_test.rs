//! Known-answer tests against another implementation: the handshakes in
//! `openssl_recordings.rs` were made by OpenSSL alone, so nothing here is checked against
//! this crate's own idea of the protocol. What OpenSSL computed (the master secret, both
//! Finished values, the exporter output, the protected records) is recomputed by the
//! production code from what went over the wire.

use super::openssl_recordings::{Message, PSK, RECORDINGS, Recording};
use super::*;
use crate::cipher_suite::{CipherSuiteHash, CipherSuiteId, cipher_suite_for_id};
use crate::config::ConfigBuilder;
use crate::extension::Extension;
use crate::flight::flight0::negotiate_client_hello;
use crate::flight::flight4::verify_client_finished;
use crate::handshake::handshake_message_finished::HandshakeMessageFinished;
use crate::handshake::handshake_random::HandshakeRandom;
use crate::prf::{prf_extended_master_secret, prf_psk_pre_master_secret};

const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const HELLO_VERIFY_REQUEST: u8 = 3;
const FINISHED: u8 = 20;

fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider is enabled for tests")
}

fn message_sequence(message: &Message) -> u16 {
    u16::from_be_bytes([message.bytes[4], message.bytes[5]])
}

/// The handshake cache as a connection fills it: every message under its epoch, sequence
/// number, type and sender, the first ClientHello and the HelloVerifyRequest included.
fn cache_of(messages: &[Message]) -> HandshakeCache {
    let mut cache = HandshakeCache::new();
    for message in messages {
        assert!(cache.push(
            message.bytes.to_vec(),
            message.epoch,
            message_sequence(message),
            message.bytes[0].into(),
            message.from_client,
        ));
    }
    cache
}

fn find(recording: &Recording, handshake_type: u8, from_client: bool) -> &'static Message {
    recording
        .handshake
        .iter()
        .rev()
        .find(|message| message.bytes[0] == handshake_type && message.from_client == from_client)
        .expect("the message is in the recording")
}

/// The random of a hello: after the handshake header and the version.
fn random_of(hello: &Message) -> Vec<u8> {
    hello.bytes[HANDSHAKE_HEADER_LENGTH + 2..HANDSHAKE_HEADER_LENGTH + 34].to_vec()
}

/// The state one end of the recorded session has once the master secret exists.
fn state_of(recording: &Recording, is_client: bool) -> State {
    let client_random = random_of(find(recording, CLIENT_HELLO, true));
    let server_random = random_of(find(recording, SERVER_HELLO, false));
    let (local, remote) = if is_client {
        (client_random, server_random)
    } else {
        (server_random, client_random)
    };
    let mut state = State::new(provider(), is_client);
    state.local_random = HandshakeRandom::unmarshal(&mut local.as_slice()).unwrap();
    state.remote_random = HandshakeRandom::unmarshal(&mut remote.as_slice()).unwrap();
    state.master_secret = recording.master_secret.to_vec();
    state.cipher_suite = Some(cipher_suite_for_id(recording.suite).unwrap());
    state.extended_master_secret = true;
    state.local_epoch = 1;
    state
}

fn finished_of(message: &Message) -> HandshakeMessageFinished {
    HandshakeMessageFinished {
        verify_data: message.bytes[HANDSHAKE_HEADER_LENGTH..].to_vec(),
    }
}

/// RFC 5246 7.4.9, RFC 6347 4.2.6: the Finished verify_data both ends compute from the
/// transcript are the ones OpenSSL sent. The transcript leaves out the first ClientHello and
/// the HelloVerifyRequest, and takes each message as one unfragmented fragment.
#[test]
fn finished_values_match_the_recorded_handshakes() {
    for recording in RECORDINGS {
        let cfg = HandshakeConfig::new(provider());
        let cache = cache_of(recording.handshake);

        // The server's check of the client's Finished.
        let client_finished = find(recording, FINISHED, true);
        let server_state = state_of(recording, false);
        verify_client_finished(&server_state, &cache, &cfg, &finished_of(client_finished))
            .unwrap_or_else(|err| panic!("{}: client Finished: {err:?}", recording.suite));

        // The client's check of the server's Finished.
        let server_finished = find(recording, FINISHED, false);
        let mut client_state = state_of(recording, true);
        client_state.handshake_recv_sequence = message_sequence(server_finished) as isize;
        crate::flight::flight5::Flight5 {}
            .parse(&mut client_state, &cache, &cfg)
            .unwrap_or_else(|err| panic!("{}: server Finished: {err:?}", recording.suite));
    }
}

/// RFC 6347 4.2.6: the initial ClientHello and the HelloVerifyRequest are not part of the
/// transcript. Changing either leaves the Finished check as it was; changing the ClientHello
/// that carries the cookie breaks it.
#[test]
fn the_cookie_exchange_is_left_out_of_the_transcript() {
    for recording in RECORDINGS {
        let cfg = HandshakeConfig::new(provider());
        let state = state_of(recording, false);
        let client_finished = finished_of(find(recording, FINISHED, true));

        let first_client_hello = recording
            .handshake
            .iter()
            .position(|m| m.bytes[0] == CLIENT_HELLO)
            .unwrap();
        let hello_verify_request = recording
            .handshake
            .iter()
            .position(|m| m.bytes[0] == HELLO_VERIFY_REQUEST)
            .unwrap();
        let second_client_hello = recording
            .handshake
            .iter()
            .rposition(|m| m.bytes[0] == CLIENT_HELLO)
            .unwrap();
        assert_ne!(first_client_hello, second_client_hello, "two ClientHellos");

        let check_with_altered = |index: usize| {
            let mut cache = HandshakeCache::new();
            for (i, message) in recording.handshake.iter().enumerate() {
                let mut bytes = message.bytes.to_vec();
                if i == index {
                    // A byte of the random (ClientHello) or of the cookie (HelloVerifyRequest).
                    bytes[HANDSHAKE_HEADER_LENGTH + 10] ^= 0x01;
                }
                assert!(cache.push(
                    bytes,
                    message.epoch,
                    message_sequence(message),
                    message.bytes[0].into(),
                    message.from_client,
                ));
            }
            verify_client_finished(&state, &cache, &cfg, &client_finished).is_ok()
        };
        assert!(
            check_with_altered(first_client_hello),
            "{}",
            recording.suite
        );
        assert!(
            check_with_altered(hello_verify_request),
            "{}",
            recording.suite
        );
        assert!(
            !check_with_altered(second_client_hello),
            "{}",
            recording.suite
        );
    }
}

/// RFC 7627 4: master_secret = PRF(pre_master_secret, "extended master secret",
/// session_hash)[0..47], with the session hash over the messages up to ClientKeyExchange. For
/// a PSK suite the premaster secret follows from the key (RFC 4279 2), so the master secret
/// in OpenSSL's key log is reproduced from the transcript alone.
#[test]
fn extended_master_secret_matches_the_recorded_psk_handshakes() {
    let provider = provider();
    let mut checked = 0;
    for recording in RECORDINGS.iter().filter(|recording| recording.psk) {
        let cache = cache_of(recording.handshake);
        let session_hash = cache
            .session_hash(provider.crypto(), CipherSuiteHash::Sha256, 0, &[])
            .unwrap();
        let master_secret = prf_extended_master_secret(
            provider.crypto(),
            &prf_psk_pre_master_secret(&PSK),
            &session_hash,
            CipherSuiteHash::Sha256,
        )
        .unwrap();
        assert_eq!(
            master_secret, recording.master_secret,
            "{}",
            recording.suite
        );
        checked += 1;
    }
    assert_eq!(checked, 3);
}

/// RFC 5705, RFC 5764 4.2: the exporter output for `EXTRACTOR-dtls_srtp` is what OpenSSL
/// derived, from either end's view of the randoms.
#[test]
fn the_dtls_srtp_exporter_matches_the_recorded_handshakes() {
    for recording in RECORDINGS {
        for is_client in [true, false] {
            let keying_material = state_of(recording, is_client)
                .export_keying_material("EXTRACTOR-dtls_srtp", &[], recording.exporter.len())
                .unwrap();
            assert_eq!(
                keying_material.as_ref(),
                recording.exporter,
                "{} (client: {is_client})",
                recording.suite
            );
        }
    }
}

/// A cipher suite with the recorded session's keys, for one end.
fn keyed_suite(
    recording: &Recording,
    is_client: bool,
) -> Box<dyn crate::cipher_suite::CipherSuite> {
    let mut suite = cipher_suite_for_id(recording.suite).unwrap();
    suite
        .init(
            provider(),
            recording.master_secret,
            &random_of(find(recording, CLIENT_HELLO, true)),
            &random_of(find(recording, SERVER_HELLO, false)),
            is_client,
        )
        .unwrap();
    suite
}

/// RFC 5246 6.2.3.3, 6.3, RFC 5288, RFC 6655, RFC 7905: the keys expanded from the master
/// secret open the records OpenSSL protected (each side's Finished and the client's
/// close_notify) to the messages OpenSSL printed, for every AEAD suite; and a changed record
/// does not open.
#[test]
fn record_protection_opens_the_recorded_records() {
    for recording in RECORDINGS {
        let mut server = keyed_suite(recording, false);
        let mut client = keyed_suite(recording, true);

        let opened = server.decrypt(recording.client_finished_record).unwrap();
        assert_eq!(
            &opened[RECORD_LAYER_HEADER_SIZE..],
            find(recording, FINISHED, true).bytes,
            "{}: the client's Finished",
            recording.suite
        );
        let opened = client.decrypt(recording.server_finished_record).unwrap();
        assert_eq!(
            &opened[RECORD_LAYER_HEADER_SIZE..],
            find(recording, FINISHED, false).bytes,
            "{}: the server's Finished",
            recording.suite
        );
        // close_notify: warning(1), close_notify(0).
        let opened = server
            .decrypt(recording.client_close_notify_record)
            .unwrap();
        assert_eq!(
            &opened[RECORD_LAYER_HEADER_SIZE..],
            &[1, 0],
            "{}",
            recording.suite
        );

        let mut altered = recording.client_finished_record.to_vec();
        let last = altered.len() - 1;
        altered[last] ^= 0x01;
        assert!(server.decrypt(&altered).is_err(), "{}", recording.suite);
        // The sequence number is authenticated (RFC 6347 4.1.2.1).
        let mut altered = recording.client_finished_record.to_vec();
        altered[10] ^= 0x01;
        assert!(server.decrypt(&altered).is_err(), "{}", recording.suite);
    }
}

/// Where the nonce is a function of the record number alone (ChaCha20-Poly1305, RFC 7905; and
/// AES-CCM as OpenSSL and this crate both build its explicit nonce from the epoch and sequence
/// number), protecting the same message gives the very bytes OpenSSL sent.
#[test]
fn record_protection_reproduces_the_recorded_records() {
    let mut reproduced = 0;
    for recording in RECORDINGS {
        let record = recording.client_finished_record;
        // ChaCha20-Poly1305 carries no nonce. For the others the eight bytes after the record
        // header are the explicit nonce: the record's epoch and sequence number in OpenSSL's
        // AES-CCM as here, a counter from a random start in its AES-GCM.
        let deterministic = recording.suite
            == CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256
            || record[RECORD_LAYER_HEADER_SIZE..RECORD_LAYER_HEADER_SIZE + 8] == record[3..11];
        if !deterministic {
            continue;
        }
        let message = find(recording, FINISHED, true).bytes;
        let header = RecordLayerHeader {
            content_type: ContentType::Handshake,
            protocol_version: PROTOCOL_VERSION1_2,
            epoch: 1,
            sequence_number: 0,
            content_len: message.len() as u16,
        };
        let mut raw = vec![];
        header.marshal(&mut raw).unwrap();
        raw.extend_from_slice(message);
        let protected = keyed_suite(recording, true).encrypt(&header, &raw).unwrap();
        assert_eq!(protected, record, "{}", recording.suite);
        reproduced += 1;
    }
    assert!(
        reproduced >= 3,
        "ChaCha20-Poly1305 and both CCM suites: {reproduced}"
    );
}

/// What OpenSSL's ClientHello offers is understood: this server negotiates from the recorded
/// ClientHello (the one with the cookie) what OpenSSL's own server did.
#[test]
fn the_recorded_client_hellos_are_negotiated() {
    for recording in RECORDINGS {
        let client_hello = find(recording, CLIENT_HELLO, true);
        let handshake = Handshake::unmarshal(&mut &client_hello.bytes[..]).unwrap();
        let HandshakeMessage::ClientHello(client_hello) = handshake.handshake_message else {
            panic!("a ClientHello");
        };
        // OpenSSL offers extensions this crate does not implement (session_ticket,
        // encrypt_then_mac): kept, not an error.
        assert!(
            client_hello
                .extensions
                .iter()
                .any(|extension| matches!(extension, Extension::Unknown { .. })),
            "{}",
            recording.suite
        );

        let mut builder = ConfigBuilder::default()
            .with_crypto_provider(provider())
            .with_cipher_suites(vec![recording.suite])
            .with_srtp_protection_profiles(vec![
                SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
            ]);
        builder = if recording.psk {
            builder.with_psk(Some(Arc::new(|_| Ok(PSK.to_vec()))))
        } else {
            builder.with_certificates(vec![super::conn_conformance_test::self_signed()])
        };
        let cfg = builder.build(false, None).unwrap();
        let mut state = State::new(provider(), false);
        negotiate_client_hello(&mut state, &client_hello, &cfg)
            .unwrap_or_else(|err| panic!("{}: {err:?}", recording.suite));
        assert_eq!(
            state.cipher_suite.as_ref().map(|s| s.id()),
            Some(recording.suite)
        );
        assert!(state.extended_master_secret, "{}", recording.suite);
        assert!(state.secure_renegotiation, "{}", recording.suite);
        assert_eq!(
            state.srtp_protection_profile,
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80
        );
    }
}

/// The cookie exchange with OpenSSL's datagrams: this client answers OpenSSL's
/// HelloVerifyRequest (record and server_version 1.0) with the cookie in a DTLS 1.2
/// ClientHello.
#[test]
fn the_recorded_hello_verify_request_is_answered() {
    use super::conn_conformance_test::{builder, client, drain, feed};

    let recording = RECORDINGS[3];
    let now = Instant::now();
    let mut client = client(builder());
    client.handshake(now).unwrap();
    drain(&mut client);
    feed(&mut client, now, recording.hello_verify_request_datagram).unwrap();

    let second = drain(&mut client);
    assert_eq!(second.len(), 1);
    let hello_verify_request = find(recording, HELLO_VERIFY_REQUEST, false).bytes;
    let cookie = &hello_verify_request[HANDSHAKE_HEADER_LENGTH + 3..];
    let body = &second[0][RECORD_LAYER_HEADER_SIZE + HANDSHAKE_HEADER_LENGTH..];
    assert_eq!(&body[..2], &[0xfe, 0xfd]);
    assert_eq!(body[35] as usize, cookie.len());
    assert_eq!(&body[36..36 + cookie.len()], cookie);
}
