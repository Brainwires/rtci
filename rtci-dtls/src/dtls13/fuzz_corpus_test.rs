//! The logic of the three DTLS 1.3 fuzz targets, run over a fixed corpus: what OpenSSL sent
//! in the recorded handshakes, cut and altered, and operation sequences that reach every
//! branch of the stateful harness. A fuzzer looks for inputs that panic; these must not.

use super::fuzz_harness::*;
use super::handshake_test::provider;
use super::openssl_recordings::RECORDINGS;
use crate::crypto::Certificate;
use std::time::Instant;

/// Each input, each prefix of it at a few lengths, and each with one byte altered at a few
/// places.
fn variants(input: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![input.to_vec()];
    for cut in [
        0,
        1,
        2,
        5,
        12,
        13,
        14,
        25,
        26,
        input.len() / 2,
        input.len().saturating_sub(1),
    ] {
        out.push(input[..cut.min(input.len())].to_vec());
    }
    for at in [
        0,
        1,
        3,
        11,
        12,
        13,
        17,
        24,
        40,
        input.len() / 2,
        input.len().saturating_sub(1),
    ] {
        if at < input.len() {
            for flip in [0x01, 0x80, 0xff] {
                let mut altered = input.to_vec();
                altered[at] ^= flip;
                out.push(altered);
            }
        }
    }
    out
}

#[test]
fn the_record_parser_takes_the_corpus() {
    let mut inputs = 0;
    for recording in RECORDINGS {
        for datagram in recording.datagrams {
            for variant in variants(datagram.bytes) {
                // The first byte of an input chooses the connection id length.
                for connection_id_len in 0u8..5 {
                    let mut input = vec![connection_id_len];
                    input.extend_from_slice(&variant);
                    record_parse(&input);
                    inputs += 1;
                }
            }
        }
    }
    for input in [
        &[][..],
        &[0],
        &[0, 0x2f],
        &[3, 0x3f, 1, 2, 3, 0, 0, 0, 16],
        &[0, 26, 0, 0],
    ] {
        record_parse(input);
    }
    assert!(inputs > 1000);
}

#[test]
fn the_handshake_parsers_take_the_corpus() {
    let provider = provider();
    let certificate =
        Certificate::generate_self_signed(vec!["localhost".to_owned()], provider.crypto())
            .expect("a certificate");
    let mut inputs = 0;
    for recording in RECORDINGS {
        for message in recording.handshake {
            // With the DTLS handshake header (as a fragment) and without (as a body).
            for whole in [message.bytes, &message.bytes[12..]] {
                for variant in variants(whole) {
                    handshake_parse(&variant, provider.clone(), certificate.clone());
                    inputs += 1;
                }
            }
        }
        for datagram in recording.datagrams {
            handshake_parse(datagram.bytes, provider.clone(), certificate.clone());
        }
    }
    assert!(inputs > 500);
}

#[test]
fn an_association_takes_the_corpus_of_operations() {
    let provider = provider();
    let certificate = || {
        Certificate::generate_self_signed(vec!["localhost".to_owned()], provider.crypto())
            .expect("a certificate")
    };
    let start = Instant::now();
    // An operation: flags, length, payload. Flags bit 0 is the direction, bits 1 to 3 the
    // kind (raw, raw, sealed x3, time, application, connection ids), bit 7 a modifier.
    let operation = |flags: u8, payload: &[u8]| {
        let mut out = vec![flags, payload.len() as u8];
        out.extend_from_slice(payload);
        out
    };
    let mut sequences: Vec<Vec<u8>> = vec![vec![]];
    // Every kind of operation in both directions, with payloads that mean something to the
    // receiver: sealed handshake (22), alert (21), ACK (26), application data (23) and an
    // unknown content type; a KeyUpdate, a NewConnectionId, a truncated fragment.
    let key_update = [22u8, 24, 0, 0, 1, 0, 9, 0, 0, 0, 0, 0, 1, 1];
    let new_connection_id = [
        22u8, 10, 0, 0, 7, 0, 9, 0, 0, 0, 0, 0, 7, 0, 4, 3, 1, 2, 3, 1,
    ];
    let payloads: [&[u8]; 9] = [
        &[],
        &[23, b'd', b'a', b't', b'a'],
        &[21, 1, 0],
        &[21, 2, 40],
        &[26, 0, 0],
        &[26, 0, 16, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0],
        &key_update,
        &new_connection_id,
        &[99, 1, 2, 3],
    ];
    for kind in 0u8..8 {
        for direction in 0u8..2 {
            for modifier in [0u8, 0x80] {
                let mut sequence = vec![];
                for payload in payloads {
                    sequence.extend(operation(modifier | (kind << 1) | direction, payload));
                }
                sequences.push(sequence);
            }
        }
    }
    // What OpenSSL sent, as raw datagrams from either side.
    for recording in RECORDINGS.iter().take(2) {
        let mut sequence = vec![];
        for datagram in recording.datagrams {
            let bytes = &datagram.bytes[..datagram.bytes.len().min(255)];
            sequence.extend(operation(u8::from(datagram.from_client), bytes));
        }
        sequences.push(sequence);
    }
    let mut runs = 0;
    for sequence in &sequences {
        // Options: suite, client authentication, cookie exchange, connection ids. Rounds:
        // before, during and after the handshake.
        for options in [0u8, 1, 2, 3, 4, 8, 16, 0x1f] {
            for rounds in [0u8, 1, 2, 3, 7] {
                let mut input = vec![options, rounds];
                input.extend_from_slice(sequence);
                conn_handle_datagrams(
                    &input,
                    start,
                    (provider.clone(), certificate()),
                    (provider.clone(), certificate()),
                );
                runs += 1;
            }
        }
    }
    assert!(runs > 1000);
}
