//! Record protection properties of the record ciphers that their per-file tests do not cover.

use super::crypto_ccm::{CryptoCcm, CryptoCcmTagLen};
use super::crypto_gcm::CryptoGcm;
use super::*;
use crate::content::ContentType;

fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider is enabled for tests")
}

fn record(epoch: u16, sequence_number: u64, payload: &[u8]) -> (RecordLayerHeader, Vec<u8>) {
    let header = RecordLayerHeader {
        content_type: ContentType::ApplicationData,
        protocol_version: PROTOCOL_VERSION1_2,
        epoch,
        sequence_number,
        content_len: payload.len() as u16,
    };
    let mut raw = Vec::with_capacity(RECORD_LAYER_HEADER_SIZE + payload.len());
    header.marshal(&mut raw).expect("a record header marshals");
    raw.extend_from_slice(payload);
    (header, raw)
}

/// The explicit nonce an AEAD record carries after its header.
fn explicit_nonce(encrypted: &[u8]) -> &[u8] {
    &encrypted[RECORD_LAYER_HEADER_SIZE..RECORD_LAYER_HEADER_SIZE + 8]
}

// ---------------------------------------------------------------------------------------------
// AES-GCM and AES-CCM explicit nonces are the record's epoch and sequence number (RFC 5288
// section 3, RFC 6655 section 3), not random values that could repeat under one key.
// ---------------------------------------------------------------------------------------------

/// Encrypts the same payload as two records under one key with `encrypt`, checks each explicit
/// nonce is that record's epoch || sequence number, and that `decrypt` still opens both.
fn check_explicit_nonces(
    mut encrypt: impl FnMut(&RecordLayerHeader, &[u8]) -> Result<Vec<u8>>,
    mut decrypt: impl FnMut(&[u8]) -> Result<Vec<u8>>,
) -> Result<()> {
    let (first_header, first_raw) = record(1, 7, b"same payload");
    let (second_header, second_raw) = record(1, 0x0000_0102_0304, b"same payload");
    let first = encrypt(&first_header, &first_raw)?;
    let second = encrypt(&second_header, &second_raw)?;

    assert_eq!(explicit_nonce(&first), &[0x00, 0x01, 0, 0, 0, 0, 0, 0x07]);
    assert_eq!(
        explicit_nonce(&second),
        &[0x00, 0x01, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]
    );
    assert_ne!(
        explicit_nonce(&first),
        explicit_nonce(&second),
        "two records under one key never share a nonce"
    );

    assert_eq!(
        &decrypt(&first)?[RECORD_LAYER_HEADER_SIZE..],
        b"same payload"
    );
    assert_eq!(
        &decrypt(&second)?[RECORD_LAYER_HEADER_SIZE..],
        b"same payload"
    );
    Ok(())
}

#[test]
fn gcm_explicit_nonce_is_the_record_epoch_and_sequence_number() -> Result<()> {
    let (local_key, local_iv, remote_key, remote_iv) =
        ([0x11u8; 16], [0x22u8; 4], [0x33u8; 16], [0x44u8; 4]);
    let mut sender = CryptoGcm::new(provider(), &local_key, &local_iv, &remote_key, &remote_iv)?;
    let mut receiver = CryptoGcm::new(provider(), &remote_key, &remote_iv, &local_key, &local_iv)?;
    check_explicit_nonces(
        |header, raw| sender.encrypt(header, raw),
        |encrypted| receiver.decrypt(encrypted),
    )
}

#[test]
fn ccm_explicit_nonce_is_the_record_epoch_and_sequence_number() -> Result<()> {
    for tag_len in [
        CryptoCcmTagLen::CryptoCcmTagLength,
        CryptoCcmTagLen::CryptoCcm8TagLength,
    ] {
        let (local_key, local_iv, remote_key, remote_iv) =
            ([0x11u8; 16], [0x22u8; 4], [0x33u8; 16], [0x44u8; 4]);
        let mut sender = CryptoCcm::new(
            provider(),
            &tag_len,
            &local_key,
            &local_iv,
            &remote_key,
            &remote_iv,
        )?;
        let mut receiver = CryptoCcm::new(
            provider(),
            &tag_len,
            &remote_key,
            &remote_iv,
            &local_key,
            &local_iv,
        )?;
        check_explicit_nonces(
            |header, raw| sender.encrypt(header, raw),
            |encrypted| receiver.decrypt(encrypted),
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// CBC padding (RFC 5246 6.2.3.2). The first six tests are ported from webrtc-rs `dtls`
// v0.17.1 (`crypto/padding.rs`), with a fixed fill in place of a random one.
// ---------------------------------------------------------------------------------------------

use super::crypto_cbc::CryptoCbc;
use super::padding::{check_padding, pad};

/// The padding check as an unpad, the shape the ported tests were written against.
fn unpad(data: &[u8]) -> std::result::Result<&[u8], ()> {
    let (padding_len, valid) = check_padding(data, 0);
    if valid {
        Ok(&data[..data.len() - padding_len])
    } else {
        Err(())
    }
}

#[test]
fn padding_length_is_amount_of_bytes_excluding_the_padding_length_itself() {
    for original_length in 0..128 {
        for padding_length in 0..(256 - original_length) {
            let mut block = vec![0; original_length + padding_length + 1];
            for (index, byte) in block[..original_length].iter_mut().enumerate() {
                *byte = (index * 7 + original_length) as u8;
            }
            let original = block[..original_length].to_vec();
            pad(&mut block, original_length);

            for byte in block[original_length..].iter() {
                assert_eq!(*byte as usize, padding_length);
            }
            assert_eq!(block[..original_length], original);
            assert_eq!(unpad(&block), Ok(&original[..]));
        }
    }
}

#[test]
#[should_panic]
fn full_block_is_padding_error() {
    for original_length in 0..256 {
        let mut block = vec![0; original_length];
        pad(&mut block, original_length);
    }
}

#[test]
#[should_panic]
fn padding_length_bigger_than_255_is_a_pad_error() {
    let padding_length = 256;
    for original_length in 0..128 {
        let mut block = vec![0; original_length + padding_length + 1];
        pad(&mut block, original_length);
    }
}

#[test]
fn empty_block_is_unpadding_error() {
    assert!(unpad(&[]).is_err());
}

#[test]
fn padding_too_big_for_block_is_unpadding_error() {
    assert!(unpad(&[1]).is_err());
}

#[test]
fn one_of_the_padding_bytes_with_value_different_than_padding_length_is_unpadding_error() {
    for padding_length in 0..16 {
        for invalid_byte in 0..padding_length {
            let mut block = vec![0; padding_length + 1];
            pad(&mut block, 0);

            assert_eq!(unpad(&block).ok(), Some(&[][..]));
            block[invalid_byte] = (padding_length - 1) as u8;
            assert!(unpad(&block).is_err());
        }
    }
}

/// Padding that claims more bytes than the record holds in front of the MAC is invalid.
#[test]
fn padding_that_leaves_no_room_for_the_mac_is_invalid() {
    // Sixteen bytes of padding value 15 is valid padding, but not with 20 MAC bytes reserved.
    let block = [15u8; 16];
    assert!(check_padding(&block, 0).1);
    assert!(!check_padding(&block, 20).1);
    let mut record = vec![0u8; 20];
    record.extend_from_slice(&block);
    assert_eq!(check_padding(&record, 20), (16, true));
}

const CBC_KEY: [u8; 32] = [0x11; 32];
const CBC_MAC_KEY: [u8; 20] = [0x33; 20];

/// The receiving side of a CBC pair whose peer writes under `CBC_KEY` / `CBC_MAC_KEY`.
fn cbc_receiver() -> CryptoCbc {
    CryptoCbc::new(provider(), &[0x22; 32], &[0x44; 20], &CBC_KEY, &CBC_MAC_KEY)
        .expect("a CBC cipher builds")
}

fn cbc_header(content_len: u16) -> RecordLayerHeader {
    RecordLayerHeader {
        content_type: ContentType::ApplicationData,
        protocol_version: PROTOCOL_VERSION1_2,
        epoch: 1,
        sequence_number: 9,
        content_len,
    }
}

/// A CBC record built by hand: `payload`, its MAC (one bit flipped when `corrupt_mac`), then
/// `padding` exactly as given, all encrypted under `CBC_KEY`.
fn hand_built_cbc_record(payload: &[u8], corrupt_mac: bool, padding: &[u8]) -> Vec<u8> {
    let provider = provider();
    let header = cbc_header(0);
    let mut hmac = provider
        .crypto()
        .new_hmac(crypto::HmacAlgorithm::Sha1, &CBC_MAC_KEY)
        .expect("an HMAC builds");
    let mut mac = crate::prf::prf_mac(
        hmac.as_mut(),
        header.epoch,
        header.sequence_number,
        header.content_type,
        header.protocol_version,
        None,
        payload,
    )
    .expect("the MAC is computed");
    if corrupt_mac {
        mac[0] ^= 1;
    }

    let mut plaintext = payload.to_vec();
    plaintext.extend_from_slice(&mac);
    plaintext.extend_from_slice(padding);
    assert_eq!(plaintext.len() % 16, 0, "the test pads to whole blocks");

    let iv = [0x5a; 16];
    let mut cipher = provider
        .crypto()
        .new_cbc(crypto::CbcAlgorithm::Aes256Cbc, &CBC_KEY)
        .expect("a CBC cipher builds");
    cipher
        .encrypt_blocks(&iv, &mut plaintext)
        .expect("whole blocks encrypt");

    let mut record = vec![];
    cbc_header((iv.len() + plaintext.len()) as u16)
        .marshal(&mut record)
        .expect("a record header marshals");
    record.extend_from_slice(&iv);
    record.extend_from_slice(&plaintext);
    record
}

/// Twelve payload bytes and the 20-byte MAC fill two blocks, so the padding is a whole block.
const PAYLOAD: &[u8; 12] = b"cbc payload!";

#[test]
fn cbc_accepts_valid_padding_up_to_the_maximum() -> Result<()> {
    for padding in [vec![15u8; 16], vec![255u8; 256]] {
        let record = hand_built_cbc_record(PAYLOAD, false, &padding);
        let decrypted = cbc_receiver().decrypt(&record)?;
        assert_eq!(&decrypted[RECORD_LAYER_HEADER_SIZE..], &PAYLOAD[..]);
    }
    Ok(())
}

/// Bad padding, padding longer than the record, and a bad MAC behind good padding all fail the
/// same way: no error tells them apart.
#[test]
fn cbc_rejects_bad_padding_and_bad_macs_alike() {
    let mut one_byte_wrong = vec![15u8; 16];
    one_byte_wrong[3] = 14;
    let mut claims_too_much = vec![0u8; 15];
    claims_too_much.push(255);

    for (name, record) in [
        (
            "a padding byte differs",
            hand_built_cbc_record(PAYLOAD, false, &one_byte_wrong),
        ),
        (
            "padding longer than the record",
            hand_built_cbc_record(PAYLOAD, false, &claims_too_much),
        ),
        (
            "good padding, bad MAC",
            hand_built_cbc_record(PAYLOAD, true, &[15u8; 16]),
        ),
        (
            "bad padding, bad MAC",
            hand_built_cbc_record(PAYLOAD, true, &one_byte_wrong),
        ),
    ] {
        assert_eq!(
            cbc_receiver().decrypt(&record),
            Err(Error::ErrInvalidMac),
            "{name}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// RFC 9146 section 5: a `tls12_cid` record's MAC or AEAD input covers its connection id.
// ---------------------------------------------------------------------------------------------

/// RFC 9146 has no test vectors; this is section 5.3's `additional_data` (and section 5.1's
/// MAC input in front of the content) built byte by byte from the text.
#[test]
fn tls12_cid_additional_data_is_the_rfc9146_layout() {
    let header = RecordLayerHeader {
        content_type: ContentType::Tls12Cid,
        protocol_version: PROTOCOL_VERSION1_2,
        epoch: 0x0102,
        sequence_number: 0x0000_0304_0506_0708,
        content_len: 0,
    };
    let cid = [0xc1, 0xc2, 0xc3];
    let mut expected = vec![0xff; 8]; // seq_num_placeholder
    expected.extend_from_slice(&[25, 3, 25]); // tls12_cid, cid_length, tls12_cid
    expected.extend_from_slice(&[0xfe, 0xfd]); // DTLSCiphertext.version
    expected.extend_from_slice(&[0x01, 0x02]); // epoch
    expected.extend_from_slice(&[0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // sequence_number
    expected.extend_from_slice(&cid);
    expected.extend_from_slice(&[0x01, 0x23]); // length_of_DTLSInnerPlaintext
    assert_eq!(
        record_additional_data(&header, 0x0123, Some(&cid)),
        expected
    );
    // An empty connection id still has its length byte.
    let empty = record_additional_data(&header, 1, Some(&[]));
    assert_eq!(&empty[8..11], &[25, 0, 25]);
    assert_eq!(empty.len(), 23);
    // Without a connection id it is RFC 5246's 13 bytes.
    assert_eq!(
        record_additional_data(&header, 7, None),
        generate_aead_additional_data(&header, 7).to_vec()
    );
}

/// Each record cipher family seals a `tls12_cid` record that opens only under the same
/// connection id: one byte of it changed, or the record opened as an ordinary one, fails.
#[test]
fn a_tls12_cid_record_opens_only_under_its_connection_id() -> Result<()> {
    use crate::cipher_suite::{CipherSuiteId, cipher_suite_for_id};
    let master_secret = [0x5au8; 48];
    let (client_random, server_random) = ([0x01u8; 32], [0x02u8; 32]);
    for id in [
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm,
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8,
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
    ] {
        let mut sender = cipher_suite_for_id(id)?;
        let mut receiver = cipher_suite_for_id(id)?;
        sender.init(
            provider(),
            &master_secret,
            &client_random,
            &server_random,
            true,
        )?;
        receiver.init(
            provider(),
            &master_secret,
            &client_random,
            &server_random,
            false,
        )?;
        // The DTLSInnerPlaintext: content, then the real type.
        let mut inner = b"under a connection id".to_vec();
        inner.push(ContentType::ApplicationData as u8);
        let (mut header, mut raw) = record(1, 9, &inner);
        header.content_type = ContentType::Tls12Cid;
        raw[0] = ContentType::Tls12Cid as u8;
        let cid = [0xaa, 0xbb, 0xcc, 0xdd];
        let sealed = sender.encrypt_with_connection_id(&header, &raw, &cid)?;

        let opened = receiver.decrypt_with_connection_id(&sealed, &cid)?;
        assert_eq!(&opened[RECORD_LAYER_HEADER_SIZE..], &inner[..], "{id}");
        let mut other = cid;
        other[3] ^= 1;
        assert!(
            receiver
                .decrypt_with_connection_id(&sealed, &other)
                .is_err(),
            "{id}: another connection id"
        );
        assert!(
            receiver.decrypt_with_connection_id(&sealed, &[]).is_err(),
            "{id}: an empty connection id"
        );
        assert!(
            receiver.decrypt(&sealed).is_err(),
            "{id}: opened as an ordinary record"
        );
        // The same content sealed as an ordinary record does not open as a tls12_cid one.
        let (plain_header, plain_raw) = record(1, 10, &inner);
        let plain = sender.encrypt(&plain_header, &plain_raw)?;
        assert!(
            receiver.decrypt_with_connection_id(&plain, &cid).is_err(),
            "{id}"
        );
    }
    Ok(())
}
