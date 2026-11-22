//! The DTLS 1.3 record layer: RFC 9147 sections 4 (formats), 4.1 (demultiplexing), 4.2.2
//! (record number reconstruction), 4.2.3 (record number encryption) and 7 (ACK).

use super::key_schedule::{DTLS13_LABEL_PREFIX, KeySchedule};
use super::key_schedule_test::hex;
use super::record::*;
use super::suite::Suite13;
use crate::cipher_suite::CipherSuiteId;
use crypto::HEADER_MASK_SAMPLE_LEN;
use shared::error::{Error, Result};
use std::sync::Arc;

fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider is enabled for tests")
}

const ALL_SUITES: [CipherSuiteId; 5] = [
    CipherSuiteId::Tls_Aes_128_Gcm_Sha256,
    CipherSuiteId::Tls_Aes_256_Gcm_Sha384,
    CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256,
    CipherSuiteId::Tls_Aes_128_Ccm_Sha256,
    CipherSuiteId::Tls_Aes_128_Ccm_8_Sha256,
];

/// Keys for one direction of `suite`, and the same keys again for the other end.
fn key_pair(id: CipherSuiteId) -> Result<(Suite13, RecordKeys, RecordKeys)> {
    let provider = provider();
    let crypto = provider.crypto();
    let suite = Suite13::for_id(id).expect("a TLS 1.3 suite");
    let mut schedule = KeySchedule::new(crypto, suite, DTLS13_LABEL_PREFIX)?;
    schedule.enter_handshake(crypto, &[7; 32], &vec![9; suite.hash_len()])?;
    let secret = schedule.client_handshake_traffic.clone().unwrap();
    let keys = schedule.traffic_keys(crypto, secret.as_ref())?;
    Ok((
        suite,
        RecordKeys::new(crypto, suite, &keys)?,
        RecordKeys::new(crypto, suite, &keys)?,
    ))
}

fn number(epoch: u64, sequence: u64) -> RecordNumber {
    RecordNumber { epoch, sequence }
}

const FORMS: [HeaderForm; 4] = [
    HeaderForm {
        sequence_16: false,
        length: false,
    },
    HeaderForm {
        sequence_16: false,
        length: true,
    },
    HeaderForm {
        sequence_16: true,
        length: false,
    },
    HeaderForm {
        sequence_16: true,
        length: true,
    },
];

#[test]
fn every_header_form_round_trips_under_every_suite() -> Result<()> {
    for id in ALL_SUITES {
        let (_, mut sender, mut receiver) = key_pair(id)?;
        for form in FORMS {
            for connection_id in [&b""[..], &b"\x01\x02\x03\x04\x05"[..]] {
                for epoch in [2u64, 3, 4, 5] {
                    let sequence = 0x0123;
                    let content = b"a record of DTLS 1.3";
                    let record = sender.seal(
                        number(epoch, sequence),
                        connection_id,
                        form,
                        CONTENT_TYPE_APPLICATION_DATA,
                        content,
                        0,
                    )?;

                    // Figure 3: 0 0 1 C S L E E.
                    let first = record[0];
                    assert_eq!(first >> 5, 0b001, "{id} {form:?}");
                    assert_eq!(first & 0x10 != 0, !connection_id.is_empty());
                    assert_eq!(first & 0x08 != 0, form.sequence_16);
                    assert_eq!(first & 0x04 != 0, form.length);
                    assert_eq!(u64::from(first & 0x03), epoch & 3);
                    assert_eq!(&record[1..1 + connection_id.len()], connection_id);

                    let header = UnifiedHeader::parse(&record, connection_id.len())?;
                    assert_eq!(header.epoch_bits, (epoch & 3) as u8);
                    assert_eq!(header.record_len, record.len());
                    assert_eq!(header.header_len, form.header_len(connection_id.len()));
                    assert_eq!(header.sequence.len(), if form.sequence_16 { 2 } else { 1 });
                    if form.length {
                        let at = header.header_len - 2;
                        let length = u16::from_be_bytes([record[at], record[at + 1]]);
                        assert_eq!(usize::from(length), record.len() - header.header_len);
                    }

                    let (opened_sequence, content_type, opened) =
                        receiver.open(&header, &record, sequence)?;
                    assert_eq!(opened_sequence, sequence);
                    assert_eq!(content_type, CONTENT_TYPE_APPLICATION_DATA);
                    assert_eq!(opened, content);
                }
            }
        }
    }
    Ok(())
}

/// RFC 9147 section 4.2.3: the sequence number on the wire is the real one XORed with the
/// leading bytes of the mask of the first 16 bytes of ciphertext, under the sn key.
#[test]
fn the_sequence_number_on_the_wire_is_masked_with_the_ciphertext_sample() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    for id in ALL_SUITES {
        let suite = Suite13::for_id(id).unwrap();
        let mut schedule = KeySchedule::new(crypto, suite, DTLS13_LABEL_PREFIX)?;
        schedule.enter_handshake(crypto, &[7; 32], &vec![9; suite.hash_len()])?;
        let secret = schedule.server_handshake_traffic.clone().unwrap();
        let keys = schedule.traffic_keys(crypto, secret.as_ref())?;
        let mut sender = RecordKeys::new(crypto, suite, &keys)?;
        let mut mask = crypto
            .new_header_mask(suite.header_mask(), keys.sequence_number_key.as_ref())
            .unwrap();

        for form in FORMS {
            let sequence = 0xbeef;
            let record = sender.seal(
                number(2, sequence),
                &[],
                form,
                CONTENT_TYPE_HANDSHAKE,
                &[0x5a; 40],
                0,
            )?;
            let header = UnifiedHeader::parse(&record, 0)?;
            let sample: [u8; HEADER_MASK_SAMPLE_LEN] = record
                [header.header_len..header.header_len + HEADER_MASK_SAMPLE_LEN]
                .try_into()
                .unwrap();
            let expected_mask = mask.mask(&sample).unwrap();
            let wire = &record[header.sequence.clone()];
            let plain: Vec<u8> = if form.sequence_16 {
                (sequence as u16).to_be_bytes().to_vec()
            } else {
                vec![sequence as u8]
            };
            let unmasked: Vec<u8> = wire
                .iter()
                .zip(expected_mask)
                .map(|(byte, mask_byte)| byte ^ mask_byte)
                .collect();
            assert_eq!(unmasked, plain, "{id} {form:?}");
        }
    }
    Ok(())
}

/// RFC 9147 section 4: the additional data is the whole header as it was before the sequence
/// number was encrypted, and the nonce is the IV XORed with the 64-bit sequence number. The
/// record is rebuilt here from the provider's AEAD alone.
#[test]
fn the_record_is_the_aead_of_the_inner_plaintext_under_the_header() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    for id in ALL_SUITES {
        let suite = Suite13::for_id(id).unwrap();
        let mut schedule = KeySchedule::new(crypto, suite, DTLS13_LABEL_PREFIX)?;
        schedule.enter_handshake(crypto, &[7; 32], &vec![9; suite.hash_len()])?;
        let secret = schedule.server_handshake_traffic.clone().unwrap();
        let keys = schedule.traffic_keys(crypto, secret.as_ref())?;
        let mut sender = RecordKeys::new(crypto, suite, &keys)?;

        let sequence: u64 = 0x0001_0203_0405;
        let connection_id = [0xc1, 0xd2];
        let content = [0x11u8; 33];
        let record = sender.seal(
            number(3, sequence),
            &connection_id,
            HeaderForm::FULL,
            CONTENT_TYPE_APPLICATION_DATA,
            &content,
            3,
        )?;

        let tag_len = suite.tag_len();
        let inner_len = content.len() + 1 + 3;
        let mut header = vec![0x20 | 0x10 | 0x08 | 0x04 | 3];
        header.extend_from_slice(&connection_id);
        header.extend_from_slice(&(sequence as u16).to_be_bytes());
        header.extend_from_slice(&((inner_len + tag_len) as u16).to_be_bytes());

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(keys.iv.as_ref());
        for (byte, sequence_byte) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
            *byte ^= sequence_byte;
        }
        let mut inner = content.to_vec();
        inner.push(CONTENT_TYPE_APPLICATION_DATA);
        inner.extend_from_slice(&[0, 0, 0]);
        let mut tag = vec![0u8; tag_len];
        crypto
            .new_aead(suite.aead(), keys.key.as_ref())
            .unwrap()
            .seal_in_place(&nonce, &header, &mut inner, &mut tag)
            .unwrap();

        assert_eq!(record.len(), header.len() + inner.len() + tag_len, "{id}");
        assert_eq!(
            &record[header.len()..header.len() + inner.len()],
            &inner[..],
            "{id}"
        );
        assert_eq!(&record[header.len() + inner.len()..], &tag[..], "{id}");
        // Everything of the header but the sequence number travels as written.
        assert_eq!(&record[..3], &header[..3]);
        assert_eq!(&record[5..7], &header[5..7]);
    }
    Ok(())
}

#[test]
fn a_record_altered_anywhere_does_not_authenticate() -> Result<()> {
    for id in ALL_SUITES {
        let (_, mut sender, mut receiver) = key_pair(id)?;
        let record = sender.seal(
            number(3, 77),
            &[0xaa, 0xbb],
            HeaderForm::FULL,
            CONTENT_TYPE_APPLICATION_DATA,
            b"authenticated",
            0,
        )?;
        let header = UnifiedHeader::parse(&record, 2)?;
        assert!(receiver.open(&header, &record, 77).is_ok());
        for index in 0..record.len() {
            let mut altered = record.clone();
            altered[index] ^= 0x01;
            // The header is parsed again: a changed length or flag may already be refused
            // there, and what still parses must fail authentication.
            let outcome = UnifiedHeader::parse(&altered, 2)
                .and_then(|header| receiver.open(&header, &altered[..header.record_len], 77));
            assert!(outcome.is_err(), "{id}: byte {index} is not protected");
        }
        // The epoch bits are in the additional data too: the same bytes claimed for another
        // epoch do not open, even with the right keys.
        let mut other_epoch = record.clone();
        other_epoch[0] ^= 0x02;
        let header = UnifiedHeader::parse(&other_epoch, 2)?;
        assert!(matches!(
            receiver.open(&header, &other_epoch, 77),
            Err(Error::ErrInvalidMac)
        ));
    }
    Ok(())
}

#[test]
fn a_record_does_not_open_under_another_sequence_number_or_other_keys() -> Result<()> {
    let (_, mut sender, mut receiver) = key_pair(CipherSuiteId::Tls_Aes_128_Gcm_Sha256)?;
    let record = sender.seal(
        number(3, 5),
        &[],
        HeaderForm::FULL,
        CONTENT_TYPE_APPLICATION_DATA,
        b"data",
        0,
    )?;
    let header = UnifiedHeader::parse(&record, 0)?;
    // Reconstructed around an expectation 2^16 further on, the same 16 bits give another
    // full sequence number, another nonce, and no authentication.
    assert!(matches!(
        receiver.open(&header, &record, 5 + (1 << 16)),
        Err(Error::ErrInvalidMac)
    ));
    let (_, _, mut other) = key_pair(CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256)?;
    assert!(other.open(&header, &record, 5).is_err());
    assert!(receiver.open(&header, &record, 5).is_ok());
    Ok(())
}

/// RFC 9147 section 4.2.3: a ciphertext is at least 16 bytes. A sender pads a short plaintext
/// (AES-CCM-8 has an 8-byte tag), and a receiver rejects a shorter record.
#[test]
fn short_plaintexts_are_padded_and_short_records_rejected() -> Result<()> {
    for id in ALL_SUITES {
        let (suite, mut sender, mut receiver) = key_pair(id)?;
        for content in [&b""[..], &b"x"[..], &b"1234567"[..]] {
            let record = sender.seal(
                number(3, 1),
                &[],
                HeaderForm::FULL,
                CONTENT_TYPE_ALERT,
                content,
                0,
            )?;
            let header = UnifiedHeader::parse(&record, 0)?;
            let ciphertext_len = record.len() - header.header_len;
            assert!(
                ciphertext_len >= 16,
                "{id}: {ciphertext_len} bytes of ciphertext"
            );
            assert_eq!(
                ciphertext_len,
                (content.len() + 1 + suite.tag_len()).max(16),
                "{id}: no more padding than is needed"
            );
            let (_, content_type, opened) = receiver.open(&header, &record, 1)?;
            assert_eq!(content_type, CONTENT_TYPE_ALERT);
            assert_eq!(opened, content, "{id}: the padding is removed");
        }
    }

    // 15 bytes of ciphertext, with and without a length.
    let mut short = vec![0x2c, 0, 1, 0, 15];
    short.extend_from_slice(&[0x99; 15]);
    assert!(matches!(
        UnifiedHeader::parse(&short, 0),
        Err(Error::ErrInvalidPacketLength)
    ));
    let mut short = vec![0x28, 0, 1];
    short.extend_from_slice(&[0x99; 15]);
    assert!(UnifiedHeader::parse(&short, 0).is_err());
    Ok(())
}

#[test]
fn padding_is_removed_and_a_record_of_nothing_but_padding_is_refused() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    let suite = Suite13::for_id(CipherSuiteId::Tls_Aes_128_Gcm_Sha256).unwrap();
    let mut schedule = KeySchedule::new(crypto, suite, DTLS13_LABEL_PREFIX)?;
    schedule.enter_handshake(crypto, &[7; 32], &[9; 32])?;
    let secret = schedule.client_handshake_traffic.clone().unwrap();
    let keys = schedule.traffic_keys(crypto, secret.as_ref())?;
    let mut sender = RecordKeys::new(crypto, suite, &keys)?;
    let mut receiver = RecordKeys::new(crypto, suite, &keys)?;

    let record = sender.seal(
        number(3, 9),
        &[],
        HeaderForm::FULL,
        CONTENT_TYPE_APPLICATION_DATA,
        b"padded\0\0",
        100,
    )?;
    let header = UnifiedHeader::parse(&record, 0)?;
    assert_eq!(record.len() - header.header_len, 8 + 1 + 100 + 16);
    // Zeros that belong to the content stay; the padding after the type goes.
    assert_eq!(receiver.open(&header, &record, 9)?.2, b"padded\0\0");

    // RFC 8446 section 5.4: no non-zero byte in the cleartext is an unexpected_message.
    // Made with the AEAD directly: `seal` cannot produce it.
    let header_bytes = [0x2f, 0, 10, 0, 16 + 20];
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(keys.iv.as_ref());
    nonce[11] ^= 10;
    let mut inner = vec![0u8; 20];
    let mut tag = [0u8; 16];
    crypto
        .new_aead(suite.aead(), keys.key.as_ref())
        .unwrap()
        .seal_in_place(&nonce, &header_bytes, &mut inner, &mut tag)
        .unwrap();
    let mut record = header_bytes.to_vec();
    record.extend_from_slice(&inner);
    record.extend_from_slice(&tag);
    let sample: [u8; 16] = record[5..21].try_into().unwrap();
    let mask = crypto
        .new_header_mask(suite.header_mask(), keys.sequence_number_key.as_ref())
        .unwrap()
        .mask(&sample)
        .unwrap();
    record[1] ^= mask[0];
    record[2] ^= mask[1];
    let header = UnifiedHeader::parse(&record, 0)?;
    assert!(matches!(
        receiver.open(&header, &record, 10),
        Err(Error::ErrInvalidContentType)
    ));
    Ok(())
}

#[test]
fn a_record_carries_at_most_two_to_the_fourteen_bytes() -> Result<()> {
    let (_, mut sender, mut receiver) = key_pair(CipherSuiteId::Tls_Aes_128_Gcm_Sha256)?;
    let most = vec![0x42u8; MAX_PLAINTEXT];
    let record = sender.seal(
        number(3, 0),
        &[],
        HeaderForm::FULL,
        CONTENT_TYPE_APPLICATION_DATA,
        &most,
        0,
    )?;
    let header = UnifiedHeader::parse(&record, 0)?;
    assert_eq!(receiver.open(&header, &record, 0)?.2.len(), MAX_PLAINTEXT);

    let too_much = vec![0x42u8; MAX_PLAINTEXT + 1];
    assert!(matches!(
        sender.seal(
            number(3, 1),
            &[],
            HeaderForm::FULL,
            CONTENT_TYPE_APPLICATION_DATA,
            &too_much,
            0
        ),
        Err(Error::ErrRecordOverflow)
    ));
    // Padding never takes a record past 2^14 + 1 bytes of inner plaintext.
    let record = sender.seal(
        number(3, 2),
        &[],
        HeaderForm::FULL,
        CONTENT_TYPE_APPLICATION_DATA,
        &most,
        500,
    )?;
    assert_eq!(record.len(), 5 + MAX_PLAINTEXT + 1 + 16);

    // A header that announces more than 2^14 + 256 bytes is not a record.
    let mut oversize = vec![0x2c, 0, 0];
    oversize.extend_from_slice(&((MAX_CIPHERTEXT + 1) as u16).to_be_bytes());
    oversize.resize(5 + MAX_CIPHERTEXT + 1, 0);
    assert!(matches!(
        UnifiedHeader::parse(&oversize, 0),
        Err(Error::ErrInvalidPacketLength)
    ));
    // The 48-bit sequence number space is not left.
    assert!(matches!(
        sender.seal(
            number(3, MAX_SEQUENCE_NUMBER + 1),
            &[],
            HeaderForm::FULL,
            CONTENT_TYPE_APPLICATION_DATA,
            b"x",
            0
        ),
        Err(Error::ErrSequenceNumberOverflow)
    ));
    Ok(())
}

/// RFC 9147 section 4.2.2: the full sequence number closest to one more than the highest
/// deprotected so far.
#[test]
fn sequence_numbers_are_reconstructed_from_their_low_bits() {
    // (truncated, bits, expected, full)
    let cases: [(u64, u32, u64, u64); 14] = [
        (0, 8, 0, 0),
        (5, 8, 0, 5),
        (0xff, 8, 0, 0xff),
        (0x00, 8, 0x100, 0x100),
        (0xff, 8, 0x100, 0xff),
        (0x05, 8, 0xfe, 0x105),
        (0xfe, 8, 0x105, 0xfe),
        (0x81, 8, 0x100, 0x81),
        (0x7f, 8, 0x100, 0x17f),
        (0x1234, 16, 0x1_1230, 0x1_1234),
        (0xfff0, 16, 0x2_0005, 0x1_fff0),
        (0x0003, 16, 0x1_fffe, 0x2_0003),
        (0xffff, 16, 0, 0xffff),
        (0x0000, 16, 0xffff_ffff_0000, 0xffff_ffff_0000),
    ];
    for (truncated, bits, expected, full) in cases {
        assert_eq!(
            reconstruct_sequence_number(truncated, bits, expected),
            full,
            "truncated {truncated:#x}/{bits} around {expected:#x}"
        );
    }
    // Exactly half a window away either way, the higher candidate is taken.
    assert_eq!(reconstruct_sequence_number(0x80, 8, 0x100), 0x180);
    // Every sequence number within half a window of the expectation comes back as itself.
    for bits in [8u32, 16] {
        let half = 1u64 << (bits - 1);
        let mask = (1u64 << bits) - 1;
        for expected in [0u64, 1, half, half + 3, 1000, 70_000, 1 << 32] {
            for delta in [0, 1, 2, half / 2, half - 1] {
                for full in [
                    expected + delta,
                    expected.saturating_sub(delta.min(half - 1)),
                ] {
                    assert_eq!(
                        reconstruct_sequence_number(full & mask, bits, expected),
                        full,
                        "{full} around {expected} with {bits} bits"
                    );
                }
            }
        }
    }
}

#[test]
fn a_reordered_record_opens_with_its_reconstructed_sequence_number() -> Result<()> {
    let (_, mut sender, mut receiver) = key_pair(CipherSuiteId::Tls_Aes_128_Gcm_Sha256)?;
    let short = HeaderForm {
        sequence_16: false,
        length: true,
    };
    // Sequence numbers beyond eight bits, sent with eight: the receiver has deprotected up
    // to 0x1ff and gets 0x1fe late and 0x203 early.
    for sequence in [0x1feu64, 0x203] {
        let record = sender.seal(
            number(3, sequence),
            &[],
            short,
            CONTENT_TYPE_APPLICATION_DATA,
            b"reordered",
            0,
        )?;
        let header = UnifiedHeader::parse(&record, 0)?;
        let (opened_sequence, _, _) = receiver.open(&header, &record, 0x200)?;
        assert_eq!(opened_sequence, sequence);
    }
    Ok(())
}

/// RFC 9147 section 4: a record without a length takes the rest of the datagram, so it is
/// the last one; records with a length can be followed by more.
#[test]
fn records_share_a_datagram_and_one_without_a_length_ends_it() -> Result<()> {
    let (_, mut sender, mut receiver) = key_pair(CipherSuiteId::Tls_Aes_128_Gcm_Sha256)?;
    let no_length = HeaderForm {
        sequence_16: true,
        length: false,
    };
    let mut datagram = plaintext_record(CONTENT_TYPE_HANDSHAKE, 7, b"plaintext handshake");
    datagram.extend(sender.seal(
        number(2, 0),
        &[],
        HeaderForm::FULL,
        CONTENT_TYPE_HANDSHAKE,
        b"first",
        0,
    )?);
    datagram.extend(sender.seal(
        number(2, 1),
        &[],
        no_length,
        CONTENT_TYPE_HANDSHAKE,
        b"second and last",
        0,
    )?);

    let mut rest = &datagram[..];
    let mut seen = vec![];
    while !rest.is_empty() {
        let (record, taken) = next_record(rest, 0)?;
        match record {
            DatagramRecord::Plaintext {
                content_type,
                sequence,
                fragment,
            } => {
                assert_eq!((content_type, sequence), (CONTENT_TYPE_HANDSHAKE, 7));
                seen.push(fragment.to_vec());
            }
            DatagramRecord::Ciphertext { header, record } => {
                let expected = seen.len() as u64 - 1;
                seen.push(receiver.open(&header, record, expected)?.2);
            }
        }
        rest = &rest[taken..];
    }
    assert_eq!(
        seen,
        vec![
            b"plaintext handshake".to_vec(),
            b"first".to_vec(),
            b"second and last".to_vec()
        ]
    );
    Ok(())
}

/// RFC 9147 section 4.1: alert, handshake and ACK are plaintext records, a first byte with
/// the bits 001 a protected one, and everything else is rejected.
#[test]
fn records_are_demultiplexed_by_their_first_byte() {
    for content_type in [CONTENT_TYPE_ALERT, CONTENT_TYPE_HANDSHAKE, CONTENT_TYPE_ACK] {
        let record = plaintext_record(content_type, 3, &[1, 2]);
        // Figure 2: the type, {254, 253}, a zero epoch, 48 bits of sequence number, a length.
        assert_eq!(
            &record[..13],
            &[content_type, 254, 253, 0, 0, 0, 0, 0, 0, 0, 3, 0, 2]
        );
        assert!(matches!(
            next_record(&record, 0),
            Ok((DatagramRecord::Plaintext { content_type: seen, sequence: 3, fragment }, 15))
                if seen == content_type && fragment == [1, 2]
        ));
        // legacy_record_version is ignored for all purposes.
        let mut other_version = record.clone();
        other_version[1..3].copy_from_slice(&[254, 255]);
        assert!(next_record(&other_version, 0).is_ok());
        // A non-zero epoch under these types is a DTLS 1.2 protected record, not ours.
        let mut epoch_one = record.clone();
        epoch_one[4] = 1;
        assert!(next_record(&epoch_one, 0).is_err());
        // Truncated, in the header and in the fragment.
        assert!(next_record(&record[..12], 0).is_err());
        assert!(next_record(&record[..14], 0).is_err());
    }
    for first in 0u8..=255 {
        // What follows the first byte is laid out as a protected record of 32 bytes would
        // be: a sequence number of the length S says, and the length if L says so.
        let mut record = vec![first, 0];
        if first & 0x08 != 0 {
            record.push(0);
        }
        if first & 0x04 != 0 {
            record.extend_from_slice(&[0, 32]);
        }
        record.extend_from_slice(&[0u8; 32]);
        let plaintext = matches!(first, 21 | 22 | 26);
        if plaintext {
            record = plaintext_record(first, 0, &[0u8; 32]);
        }
        let outcome = next_record(&record, 0);
        // C set without a negotiated connection id is rejected (section 9).
        let ciphertext = (32..64).contains(&first) && first & 0x10 == 0;
        match outcome {
            Ok((DatagramRecord::Plaintext { .. }, _)) => assert!(plaintext, "{first}"),
            Ok((DatagramRecord::Ciphertext { header, .. }, taken)) => {
                assert!(ciphertext, "{first}");
                assert_eq!(taken, record.len());
                assert_eq!(header.record_len - header.header_len, 32);
            }
            Err(_) => assert!(!plaintext && !ciphertext, "{first}"),
        }
    }
    // ChangeCipherSpec (20), application data (23), heartbeat (24) and tls12_cid (25) are
    // not DTLS 1.3 plaintext records.
    for first in [20u8, 23, 24, 25] {
        assert!(next_record(&plaintext_record(first, 0, &[1]), 0).is_err());
    }
    assert!(next_record(&[], 0).is_err());
}

/// RFC 9147 sections 4 and 9: a negotiated connection id is in every record, and a record
/// with one is rejected when none was negotiated.
#[test]
fn the_connection_id_bit_has_to_match_what_was_negotiated() -> Result<()> {
    let (_, mut sender, _) = key_pair(CipherSuiteId::Tls_Aes_128_Gcm_Sha256)?;
    let with = sender.seal(
        number(3, 0),
        &[9, 8, 7],
        HeaderForm::FULL,
        CONTENT_TYPE_APPLICATION_DATA,
        b"cid",
        0,
    )?;
    let without = sender.seal(
        number(3, 1),
        &[],
        HeaderForm::FULL,
        CONTENT_TYPE_APPLICATION_DATA,
        b"no cid",
        0,
    )?;
    let header = UnifiedHeader::parse(&with, 3)?;
    assert_eq!(&with[header.connection_id.clone()], &[9, 8, 7]);
    assert!(UnifiedHeader::parse(&with, 0).is_err());
    assert!(UnifiedHeader::parse(&without, 3).is_err());
    assert!(UnifiedHeader::parse(&without, 0).is_ok());
    Ok(())
}

/// RFC 9147 section 7: an ACK is a 16-bit length and 16-byte record numbers, each a 64-bit
/// epoch and a 64-bit sequence number.
#[test]
fn an_ack_lists_record_numbers() -> Result<()> {
    assert_eq!(encode_ack(&[]), [0, 0]);
    assert_eq!(decode_ack(&[0, 0])?, vec![]);

    let numbers = [number(2, 0), number(2, 1), number(3, 0x0102_0304_0506)];
    let encoded = encode_ack(&numbers);
    assert_eq!(
        encoded,
        hex("0030
             0000000000000002 0000000000000000
             0000000000000002 0000000000000001
             0000000000000003 0000010203040506")
    );
    assert_eq!(decode_ack(&encoded)?, numbers);

    // Not a whole number of record numbers, a length that lies, bytes after the vector.
    assert!(decode_ack(&hex("0008 0000000000000002")).is_err());
    assert!(decode_ack(&hex("0020 0000000000000002 0000000000000000")).is_err());
    assert!(decode_ack(&hex("0010 0000000000000002 0000000000000000 00")).is_err());
    assert!(decode_ack(&[]).is_err());
    assert!(decode_ack(&[0]).is_err());
    Ok(())
}

/// `DtlsVersion::record_overhead` is what a protected record as this stack sends it (the full
/// header form) adds to its content, under every suite, with and without a connection id: a
/// layer above that sizes its datagrams by it (SCTP over DTLS, RFC 8261 section 5) fills the
/// path exactly.
#[test]
fn the_record_overhead_is_what_a_sealed_record_adds() -> Result<()> {
    for id in ALL_SUITES {
        let (_, mut sender, _) = key_pair(id)?;
        for connection_id in [&b""[..], &b"\x01\x02\x03\x04\x05\x06\x07\x08"[..]] {
            let content = vec![0x5a; 1100];
            let record = sender.seal(
                number(3, 7),
                connection_id,
                HeaderForm::FULL,
                CONTENT_TYPE_APPLICATION_DATA,
                &content,
                0,
            )?;
            let overhead = crate::config::DtlsVersion::Dtls1_3
                .record_overhead(id, connection_id.len())
                .expect("a DTLS 1.3 suite");
            assert_eq!(
                record.len() - content.len(),
                overhead,
                "{id}, a connection id of {} bytes",
                connection_id.len()
            );
        }
    }
    Ok(())
}
