//! Known answers: the DTLS 1.3 handshakes OpenSSL 4.1.0 made with itself
//! (`openssl_recordings.rs`), reproduced by this crate's code. The record layer opens every
//! protected record of the recording and writes each one again byte for byte; the key
//! schedule derives the Finished messages and the exporter output from the recorded secrets
//! and transcript; the transcript rules (the DTLS header fields left out, the first
//! ClientHello replaced by its hash after a HelloRetryRequest) are what makes those match.

use super::hello::{parse_cookie, second_client_hello};
use super::key_schedule::*;
use super::messages::*;
use super::openssl_recordings::*;
use super::record::*;
use super::suite::Suite13;
use crate::signature_hash_algorithm::{SignatureAlgorithm, SignatureHashAlgorithm};
use crypto::{PublicKey, PublicKeyEncoding, RTCCryptoProvider};
use shared::error::Result;
use std::collections::BTreeMap;
use std::sync::Arc;

fn provider() -> Arc<dyn RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider is enabled for tests")
}

fn suite_of(recording: &Recording) -> Suite13 {
    Suite13::for_id(recording.suite).expect("a TLS 1.3 suite")
}

/// The body of a recorded message, and its type.
fn body(message: &Message) -> (u8, &[u8]) {
    (message.bytes[0], &message.bytes[HANDSHAKE_HEADER_LEN..])
}

/// The transcript after each message of the recording: `[i]` is the transcript through
/// message `i`. A HelloRetryRequest turns what precedes it into a message_hash.
fn transcripts(recording: &Recording, crypto: &dyn crypto::RTCCrypto) -> Result<Vec<Transcript>> {
    let suite = suite_of(recording);
    let mut transcript = Transcript::default();
    let mut after = vec![];
    for message in recording.handshake {
        let (handshake_type, body) = body(message);
        if handshake_type == SERVER_HELLO && ServerHello::parse(body)?.is_hello_retry_request() {
            transcript.replace_with_message_hash(crypto, suite)?;
        }
        transcript.add(handshake_type, body);
        after.push(transcript.clone());
    }
    Ok(after)
}

fn position(recording: &Recording, handshake_type: u8, from_client: bool) -> usize {
    recording
        .handshake
        .iter()
        .rposition(|message| {
            message.bytes[0] == handshake_type && message.from_client == from_client
        })
        .expect("the recording has the message")
}

#[test]
fn the_recorded_handshakes_have_the_shape_of_rfc_9147() -> Result<()> {
    for recording in RECORDINGS {
        let types: Vec<(bool, u8)> = recording
            .handshake
            .iter()
            .map(|message| (message.from_client, message.bytes[0]))
            .collect();
        assert_eq!(
            types,
            [
                (true, CLIENT_HELLO),
                (false, SERVER_HELLO),
                (true, CLIENT_HELLO),
                (false, SERVER_HELLO),
                (false, ENCRYPTED_EXTENSIONS),
                (false, CERTIFICATE),
                (false, CERTIFICATE_VERIFY),
                (false, FINISHED),
                (true, FINISHED),
            ]
        );
        // The message_seq of each side counts from zero and goes on across the
        // HelloRetryRequest (RFC 9147 section 5.2).
        let seqs = |from_client: bool| -> Vec<u16> {
            recording
                .handshake
                .iter()
                .filter(|message| message.from_client == from_client)
                .map(|message| u16::from_be_bytes([message.bytes[4], message.bytes[5]]))
                .collect()
        };
        assert_eq!(seqs(true), [0, 1, 2]);
        assert_eq!(seqs(false), [0, 1, 2, 3, 4, 5]);

        // The hellos, read by this crate's parsers.
        let first = ClientHello::parse(body(&recording.handshake[0]).1)?;
        assert!(first.offers_dtls13());
        assert_eq!(first.legacy_version, 0xfefd);
        assert!(first.legacy_cookie.is_empty() && first.legacy_session_id.is_empty());
        let retry = ServerHello::parse(body(&recording.handshake[1]).1)?;
        assert!(retry.is_hello_retry_request());
        assert_eq!(retry.selected_version(), Some(0xfefc));
        assert!(retry.legacy_session_id_echo.is_empty());
        let server_hello = ServerHello::parse(body(&recording.handshake[3]).1)?;
        assert!(!server_hello.is_hello_retry_request());
        assert_eq!(server_hello.selected_version(), Some(0xfefc));
        assert_eq!(server_hello.cipher_suite, recording.suite as u16);
        assert_eq!(retry.cipher_suite, recording.suite as u16);

        // The second ClientHello is the first with the cookie added, as this crate's
        // client writes it.
        let cookie = parse_cookie(retry.extension(EXT_COOKIE).expect("a cookie"))?;
        assert!(retry.extension(EXT_KEY_SHARE).is_none());
        assert_eq!(
            second_client_hello(&first, None, Some(cookie)),
            body(&recording.handshake[2]).1,
            "{}",
            recording.suite
        );
    }
    Ok(())
}

/// RFC 8446 section 4.4.4 over the transcript of RFC 9147 section 5.2: the Finished of each
/// side is the HMAC, under the key expanded from its handshake traffic secret with the
/// "dtls13" label prefix, of the transcript hash.
#[test]
fn the_finished_messages_follow_from_the_transcript_and_the_secrets() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    for recording in RECORDINGS {
        let suite = suite_of(recording);
        let schedule = KeySchedule::new(crypto, suite, DTLS13_LABEL_PREFIX)?;
        let transcripts = transcripts(recording, crypto)?;

        let server_finished = position(recording, FINISHED, false);
        let through_certificate_verify = transcripts[server_finished - 1].hash(crypto, suite)?;
        assert_eq!(
            schedule.finished_verify_data(
                crypto,
                recording.server_handshake_traffic_secret,
                &through_certificate_verify
            )?,
            body(&recording.handshake[server_finished]).1,
            "{}: the server's Finished",
            recording.suite
        );

        let client_finished = position(recording, FINISHED, true);
        let through_server_finished = transcripts[server_finished].hash(crypto, suite)?;
        assert_eq!(
            schedule.finished_verify_data(
                crypto,
                recording.client_handshake_traffic_secret,
                &through_server_finished
            )?,
            body(&recording.handshake[client_finished]).1,
            "{}: the client's Finished",
            recording.suite
        );

        // With the TLS 1.3 prefix, or with the DTLS header fields left in the transcript,
        // it is another value: the two rules are what is being checked.
        let tls = KeySchedule::new(crypto, suite, TLS13_LABEL_PREFIX)?;
        assert_ne!(
            tls.finished_verify_data(
                crypto,
                recording.server_handshake_traffic_secret,
                &through_certificate_verify
            )?,
            body(&recording.handshake[server_finished]).1
        );
    }
    Ok(())
}

/// RFC 8446 section 4.4.3: the server's CertificateVerify is a signature, by the key of its
/// certificate, over the transcript through the Certificate.
#[test]
fn the_certificate_verify_signature_verifies_over_the_transcript() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    for recording in RECORDINGS {
        let suite = suite_of(recording);
        let transcripts = transcripts(recording, crypto)?;
        let certificate = position(recording, CERTIFICATE, false);
        let (context, chain) = parse_certificate(body(&recording.handshake[certificate]).1)
            .map_err(|refusal| refusal.error)?;
        assert!(context.is_empty());
        assert_eq!(chain.len(), 1);
        let (code, signature) =
            parse_certificate_verify(body(&recording.handshake[certificate + 1]).1)?;
        let scheme = SignatureHashAlgorithm::from_scheme_code(code);
        assert!(scheme.is_tls13_signature());
        assert_eq!(scheme.signature, SignatureAlgorithm::Ecdsa);

        let (_, parsed) = x509_parser::parse_x509_certificate(&chain[0]).expect("a certificate");
        let public_key = PublicKey {
            encoding: PublicKeyEncoding::EcUncompressedPoint,
            bytes: &parsed.tbs_certificate.subject_pki.subject_public_key.data,
        };
        let hash = transcripts[certificate].hash(crypto, suite)?;
        crypto
            .verify_signature(
                scheme.crypto_scheme()?,
                public_key,
                &certificate_verify_input(true, &hash),
                signature,
            )
            .expect("the recorded signature verifies");
        // Not as a client's, and not over a transcript one message shorter.
        assert!(
            crypto
                .verify_signature(
                    scheme.crypto_scheme()?,
                    public_key,
                    &certificate_verify_input(false, &hash),
                    signature,
                )
                .is_err()
        );
        let shorter = transcripts[certificate - 1].hash(crypto, suite)?;
        assert!(
            crypto
                .verify_signature(
                    scheme.crypto_scheme()?,
                    public_key,
                    &certificate_verify_input(true, &shorter),
                    signature,
                )
                .is_err()
        );
    }
    Ok(())
}

/// RFC 8446 section 7.5 with the DTLS-SRTP label of RFC 5764: the exporter output OpenSSL
/// printed, from the exporter secret of its key log.
#[test]
fn the_exporter_reproduces_the_recorded_keying_material() -> Result<()> {
    let provider = provider();
    for recording in RECORDINGS {
        let exported = export_keying_material(
            provider.crypto(),
            suite_of(recording),
            recording.exporter_secret,
            "EXTRACTOR-dtls_srtp",
            &[],
            60,
        )?;
        assert_eq!(exported.as_ref(), recording.exporter, "{}", recording.suite);
    }
    Ok(())
}

/// One protected record of a recording, opened.
struct Opened {
    from_client: bool,
    number: RecordNumber,
    content_type: u8,
    content: Vec<u8>,
}

/// Opens every protected record of `recording` with keys made from its recorded secrets,
/// and checks that sealing what came out gives the recorded bytes back.
fn open_all(recording: &Recording) -> Result<(Vec<Opened>, Vec<(bool, Vec<u8>)>)> {
    let provider = provider();
    let crypto = provider.crypto();
    let suite = suite_of(recording);
    let schedule = KeySchedule::new(crypto, suite, DTLS13_LABEL_PREFIX)?;
    let secret = |from_client: bool, epoch: u64| -> &'static [u8] {
        match (from_client, epoch) {
            (true, 2) => recording.client_handshake_traffic_secret,
            (false, 2) => recording.server_handshake_traffic_secret,
            (true, 3) => recording.client_traffic_secret_0,
            (false, 3) => recording.server_traffic_secret_0,
            other => panic!("no secret for {other:?}"),
        }
    };
    let mut expected: BTreeMap<(bool, u64), u64> = BTreeMap::new();
    let mut opened = vec![];
    let mut plaintext = vec![];
    for datagram in recording.datagrams {
        let mut rest = datagram.bytes;
        while !rest.is_empty() {
            let (record, taken) = next_record(rest, 0)?;
            match record {
                DatagramRecord::Plaintext {
                    content_type,
                    fragment,
                    ..
                } => {
                    assert_eq!(content_type, CONTENT_TYPE_HANDSHAKE);
                    plaintext.push((datagram.from_client, fragment.to_vec()));
                }
                DatagramRecord::Ciphertext { header, record } => {
                    let epoch = u64::from(header.epoch_bits);
                    let keys =
                        schedule.traffic_keys(crypto, secret(datagram.from_client, epoch))?;
                    let mut record_keys = RecordKeys::new(crypto, suite, &keys)?;
                    let next = expected.entry((datagram.from_client, epoch)).or_insert(0);
                    let (sequence, content_type, content) =
                        record_keys.open(&header, record, *next)?;
                    assert_eq!(sequence, *next, "the records of an epoch count from zero");
                    *next += 1;

                    // Written again by this crate, in the form OpenSSL chose, it is the
                    // same record: header, encrypted sequence number, ciphertext and tag.
                    let form = HeaderForm {
                        sequence_16: header.sequence.len() == 2,
                        length: record[0] & 0x04 != 0,
                    };
                    let number = RecordNumber { epoch, sequence };
                    let padding =
                        record.len() - header.header_len - suite.tag_len() - 1 - content.len();
                    let sealed =
                        record_keys.seal(number, &[], form, content_type, &content, padding)?;
                    assert_eq!(sealed, record, "{}: record {number:?}", recording.suite);

                    opened.push(Opened {
                        from_client: datagram.from_client,
                        number,
                        content_type,
                        content,
                    });
                }
            }
            rest = &rest[taken..];
        }
    }
    Ok((opened, plaintext))
}

/// RFC 9147 sections 4 and 4.2.3 against another implementation's records: the keys, the
/// nonce, the additional data and the sequence number mask are all in whether these open.
#[test]
fn every_recorded_record_opens_and_is_reproduced() -> Result<()> {
    for recording in RECORDINGS {
        let (opened, plaintext) = open_all(recording)?;

        // The unprotected records carry the hellos, unfragmented, as `-msg` printed them.
        let hellos: Vec<&[u8]> = recording.handshake[..4]
            .iter()
            .map(|message| message.bytes)
            .collect();
        let sent: Vec<&[u8]> = plaintext
            .iter()
            .map(|(_, fragment)| &fragment[..])
            .collect();
        assert_eq!(sent, hellos);

        // The handshake messages in the protected records, put together from their
        // fragments, are the rest of what `-msg` printed.
        for from_client in [false, true] {
            let mut messages: BTreeMap<u16, (u8, Vec<u8>)> = BTreeMap::new();
            for record in opened.iter().filter(|record| {
                record.from_client == from_client && record.content_type == CONTENT_TYPE_HANDSHAKE
            }) {
                assert_eq!(record.number.epoch, 2);
                for fragment in HandshakeFragment::parse_all(&record.content)? {
                    let entry = messages
                        .entry(fragment.message_seq)
                        .or_insert((fragment.handshake_type, vec![0; fragment.length]));
                    entry.1[fragment.fragment_offset
                        ..fragment.fragment_offset + fragment.fragment.len()]
                        .copy_from_slice(fragment.fragment);
                }
            }
            let recorded: Vec<(u8, &[u8])> = recording
                .handshake
                .iter()
                .filter(|message| message.from_client == from_client)
                .map(body)
                .filter(|(handshake_type, _)| {
                    !matches!(*handshake_type, CLIENT_HELLO | SERVER_HELLO)
                })
                .collect();
            let reassembled: Vec<(u8, &[u8])> = messages
                .values()
                .map(|(handshake_type, body)| (*handshake_type, &body[..]))
                .collect();
            assert_eq!(reassembled, recorded, "{}", recording.suite);
        }

        // The server acknowledges the record of the client's Finished (epoch 2, sequence
        // number 0), in epoch 3 (RFC 9147 section 7).
        let acks: Vec<&Opened> = opened
            .iter()
            .filter(|record| record.content_type == CONTENT_TYPE_ACK)
            .collect();
        assert_eq!(acks.len(), 1);
        assert!(!acks[0].from_client);
        assert_eq!(acks[0].number.epoch, 3);
        assert_eq!(
            decode_ack(&acks[0].content)?,
            [RecordNumber {
                epoch: 2,
                sequence: 0
            }]
        );

        // Application data and the closing alert, under the application traffic keys.
        let data = |from_client: bool| -> Vec<&[u8]> {
            opened
                .iter()
                .filter(|record| {
                    record.from_client == from_client
                        && record.content_type == CONTENT_TYPE_APPLICATION_DATA
                })
                .map(|record| &record.content[..])
                .collect()
        };
        assert_eq!(data(true), [b"from the client\n"]);
        assert_eq!(data(false), [b"from the server\n"]);
        let alerts: Vec<&Opened> = opened
            .iter()
            .filter(|record| record.content_type == CONTENT_TYPE_ALERT)
            .collect();
        assert!(alerts.iter().all(|record| record.number.epoch == 3));
        assert!(
            alerts
                .iter()
                .any(|record| record.from_client && record.content == [1, 0]),
            "the client's close_notify"
        );
    }
    Ok(())
}

/// The same records under keys made with the TLS 1.3 label prefix do not open: RFC 9147
/// section 5.9.
#[test]
fn the_recorded_records_do_not_open_with_tls_1_3_labels() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    let recording = RECORDINGS[0];
    let suite = suite_of(recording);
    let schedule = KeySchedule::new(crypto, suite, TLS13_LABEL_PREFIX)?;
    let keys = schedule.traffic_keys(crypto, recording.server_handshake_traffic_secret)?;
    let mut record_keys = RecordKeys::new(crypto, suite, &keys)?;
    let datagram = recording
        .datagrams
        .iter()
        .find(|datagram| !datagram.from_client && is_unified_header(datagram.bytes[0]))
        .expect("a datagram that starts with a protected record");
    let header = UnifiedHeader::parse(datagram.bytes, 0)?;
    assert!(
        record_keys
            .open(&header, &datagram.bytes[..header.record_len], 0)
            .is_err()
    );
    Ok(())
}
