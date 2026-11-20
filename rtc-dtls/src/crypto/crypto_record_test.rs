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
