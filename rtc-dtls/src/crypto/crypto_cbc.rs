// AES-CBC (Cipher Block Chaining)
// First historic block cipher for AES.
// CBC mode is insecure and must not be used. It’s been progressively deprecated and
// removed from SSL libraries.
// Introduced with TLS 1.0 year 2002. Superseded by GCM in TLS 1.2 year 2008.
// Removed in TLS 1.3 year 2018.
// RFC 3268 year 2002 https://tools.ietf.org/html/rfc3268

use crypto::{CbcAlgorithm, CbcCipher, HmacAlgorithm, Mac, RTCCryptoProvider, constant_time_eq};
use std::io::Cursor;
use std::sync::Arc;

use crate::content::*;
use crate::crypto::padding;
use crate::crypto::{authentication_error, crypto_error};
use crate::prf::*;
use crate::record_layer::record_layer_header::*;
use shared::error::*;

/// AES-CBC encryption with a separate HMAC for DTLS records, holding the per-direction keys.
pub struct CryptoCbc {
    provider: Arc<dyn RTCCryptoProvider>,
    local_cipher: Box<dyn CbcCipher>,
    remote_cipher: Box<dyn CbcCipher>,
    /// Keyed once per epoch. Re-deriving the HMAC key schedule per record measured ~2x
    /// slower on this path; see `rtc-srtp/benches/README.md` for the equivalent SRTP data.
    write_mac: Box<dyn Mac>,
    read_mac: Box<dyn Mac>,
}

impl CryptoCbc {
    const BLOCK_SIZE: usize = 16;
    const MAC_SIZE: usize = 20;

    /// Builds the cipher from the local and remote keys and salts.
    pub fn new(
        provider: Arc<dyn RTCCryptoProvider>,
        local_key: &[u8],
        local_mac: &[u8],
        remote_key: &[u8],
        remote_mac: &[u8],
    ) -> Result<Self> {
        let local_cipher = provider
            .crypto()
            .new_cbc(CbcAlgorithm::Aes256Cbc, local_key)
            .map_err(crypto_error)?;
        let remote_cipher = provider
            .crypto()
            .new_cbc(CbcAlgorithm::Aes256Cbc, remote_key)
            .map_err(crypto_error)?;
        // Key the record MACs once per epoch, alongside the ciphers.
        let write_mac = provider
            .crypto()
            .new_hmac(HmacAlgorithm::Sha1, local_mac)
            .map_err(crypto_error)?;
        let read_mac = provider
            .crypto()
            .new_hmac(HmacAlgorithm::Sha1, remote_mac)
            .map_err(crypto_error)?;
        Ok(CryptoCbc {
            provider,
            local_cipher,
            write_mac,
            remote_cipher,
            read_mac,
        })
    }

    /// Protects one record, returning header plus ciphertext.
    ///
    /// # Errors
    ///
    /// Fails if the cipher rejects the input.
    pub fn encrypt(&mut self, pkt_rlh: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_with(pkt_rlh, raw, None)
    }

    /// [`Self::encrypt`], for a `tls12_cid` record when `cid` is given (RFC 9146 section
    /// 5.1): the MAC then covers the connection id, which is not in `raw`.
    pub(crate) fn encrypt_with(
        &mut self,
        pkt_rlh: &RecordLayerHeader,
        raw: &[u8],
        cid: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let mut payload = raw[RECORD_LAYER_HEADER_SIZE..].to_vec();
        let raw = &raw[..RECORD_LAYER_HEADER_SIZE];

        // Generate + Append MAC
        let h = pkt_rlh;

        let mac = prf_mac(
            self.write_mac.as_mut(),
            h.epoch,
            h.sequence_number,
            h.content_type,
            h.protocol_version,
            cid,
            &payload,
        )?;
        payload.extend_from_slice(&mac);

        let padding_len = Self::BLOCK_SIZE - (payload.len() % Self::BLOCK_SIZE);
        let padding_start = payload.len();
        payload.resize(padding_start + padding_len, 0);
        padding::pad(&mut payload, padding_start);

        let mut iv = [0; Self::BLOCK_SIZE];
        self.provider.random().fill(&mut iv).map_err(crypto_error)?;
        self.local_cipher
            .encrypt_blocks(&iv, &mut payload)
            .map_err(crypto_error)?;

        // Prepend unencrypte header with encrypted payload
        let mut r = vec![];
        r.extend_from_slice(raw);
        r.extend_from_slice(&iv);
        r.extend_from_slice(&payload);

        let r_len = (r.len() - RECORD_LAYER_HEADER_SIZE) as u16;
        r[RECORD_LAYER_HEADER_SIZE - 2..RECORD_LAYER_HEADER_SIZE]
            .copy_from_slice(&r_len.to_be_bytes());

        Ok(r)
    }

    /// Unprotects one record.
    ///
    /// # Errors
    ///
    /// Fails if authentication fails or the record is too short.
    pub fn decrypt(&mut self, r: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_with(r, None)
    }

    /// [`Self::decrypt`], for a `tls12_cid` record when `cid` is given (RFC 9146); `r` is
    /// the record without its connection id.
    pub(crate) fn decrypt_with(&mut self, r: &[u8], cid: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut reader = Cursor::new(r);
        let h = RecordLayerHeader::unmarshal(&mut reader)?;
        if h.content_type == ContentType::ChangeCipherSpec {
            // Nothing to encrypt with ChangeCipherSpec
            return Ok(r.to_vec());
        }

        if r.len() < RECORD_LAYER_HEADER_SIZE + Self::BLOCK_SIZE {
            return Err(Error::ErrInvalidPacketLength);
        }

        let body = &r[RECORD_LAYER_HEADER_SIZE..];
        let iv = &body[0..Self::BLOCK_SIZE];
        let body = &body[Self::BLOCK_SIZE..];

        if body.is_empty() || !body.len().is_multiple_of(Self::BLOCK_SIZE) {
            return Err(Error::ErrInvalidPacketLength);
        }

        let mut decrypted = body.to_vec();
        self.remote_cipher
            .decrypt_blocks(iv, &mut decrypted)
            .map_err(authentication_error)?;

        // Lucky Thirteen: how long the padding and MAC checks take must not depend on the padding
        // the plaintext claims. The record's length is public; the padding length is not. So the
        // padding is checked without returning early, a record with bad padding is MACed as if it
        // had none (RFC 5246 6.2.3.2), and the bytes the padding took are run through the MAC
        // too, so every record of one length MACs the same number of bytes and fails the same
        // way. (The MAC interface takes whole messages, so the HMAC's own block count is not
        // made constant beyond that.)
        if decrypted.len() <= Self::MAC_SIZE {
            return Err(Error::ErrInvalidMac);
        }
        let (padding_len, padding_valid) = padding::check_padding(&decrypted, Self::MAC_SIZE);
        let strip = padding_len & 0usize.wrapping_sub(usize::from(padding_valid));
        let content_len = decrypted.len() - Self::MAC_SIZE - strip;

        let recv_mac = &decrypted[content_len..content_len + Self::MAC_SIZE];
        let content = &decrypted[..content_len];
        let mac = prf_mac(
            self.read_mac.as_mut(),
            h.epoch,
            h.sequence_number,
            h.content_type,
            h.protocol_version,
            cid,
            content,
        )?;
        let _equalizer = prf_mac(
            self.read_mac.as_mut(),
            h.epoch,
            h.sequence_number,
            h.content_type,
            h.protocol_version,
            cid,
            &decrypted[..strip],
        )?;

        if !(padding_valid & constant_time_eq(recv_mac, &mac)) {
            return Err(Error::ErrInvalidMac);
        }
        let decrypted = content;

        let mut d = Vec::with_capacity(RECORD_LAYER_HEADER_SIZE + decrypted.len());
        d.extend_from_slice(&r[..RECORD_LAYER_HEADER_SIZE]);
        d.extend_from_slice(decrypted);

        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher_pair() -> (CryptoCbc, CryptoCbc) {
        let provider = crypto::default_provider().unwrap();
        let local_key = [0x11; 32];
        let remote_key = [0x22; 32];
        let local_mac = [0x33; 20];
        let remote_mac = [0x44; 20];
        let sender = CryptoCbc::new(
            provider.clone(),
            &local_key,
            &local_mac,
            &remote_key,
            &remote_mac,
        )
        .unwrap();
        let receiver =
            CryptoCbc::new(provider, &remote_key, &remote_mac, &local_key, &local_mac).unwrap();
        (sender, receiver)
    }

    fn record(payload: &[u8]) -> (RecordLayerHeader, Vec<u8>) {
        let header = RecordLayerHeader {
            content_type: ContentType::ApplicationData,
            protocol_version: PROTOCOL_VERSION1_2,
            epoch: 1,
            sequence_number: 7,
            content_len: payload.len() as u16,
        };
        let mut raw = Vec::new();
        header.marshal(&mut raw).unwrap();
        raw.extend_from_slice(payload);
        (header, raw)
    }

    #[test]
    fn roundtrip_and_authentication_failures() {
        let (mut sender, mut receiver) = cipher_pair();
        let (header, raw) = record(b"CBC record payload");
        let encrypted = sender.encrypt(&header, &raw).unwrap();
        assert_eq!(
            receiver.decrypt(&encrypted).unwrap()[RECORD_LAYER_HEADER_SIZE..],
            raw[RECORD_LAYER_HEADER_SIZE..]
        );

        let mut wrong_mac = encrypted.clone();
        wrong_mac[RECORD_LAYER_HEADER_SIZE] ^= 1;
        assert_eq!(receiver.decrypt(&wrong_mac), Err(Error::ErrInvalidMac));

        let mut bad_padding = encrypted.clone();
        *bad_padding.last_mut().unwrap() ^= 1;
        assert_eq!(receiver.decrypt(&bad_padding), Err(Error::ErrInvalidMac));

        let mut truncated = encrypted;
        truncated.pop();
        assert_eq!(
            receiver.decrypt(&truncated),
            Err(Error::ErrInvalidPacketLength)
        );
    }
}
