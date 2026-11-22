use std::sync::Arc;

use bytes::{BufMut, BytesMut};
use crypto::{
    HmacAlgorithm, Mac, RTCCrypto, RTCCryptoProvider, SecretVec, StreamCipher, constant_time_eq,
};
use rtcp::header::{HEADER_LENGTH, SSRC_LENGTH};
use shared::marshal::*;

use super::{Cipher, Epochs, KeySource, PacketOptions, crypto_error, new_aes_cm};
use crate::cryptex::CryptexLayout;
use crate::header_extension::HeaderExtensionKeys;
use crate::key_derivation::*;
use crate::keying::KeyDerivationRate;
use crate::protection_profile::*;
use shared::error::{Error, Result};

pub const CIPHER_AES_CM_HMAC_SHA1AUTH_TAG_LEN: usize = 10;

const HMAC_SHA1_LEN: usize = 20;
const RTCP_ENCRYPTION_FLAG: u32 = 1 << 31;
/// RFC 3711 section 4.1.1: "each packet is encrypted with a distinct IV" and at most 2^16
/// keystream blocks: the block counter is the low 16 bits of the IV, and the packet index sits
/// just above it, so a longer segment would run into the keystream of the next index.
const MAX_KEYSTREAM_LEN: usize = (1 << 16) * 16;

/// Applies the AES-CM keystream of `counter` to `data`, refusing a segment over 2^16 blocks.
fn apply_keystream(
    cipher: &mut dyn StreamCipher,
    counter: &[u8; 16],
    data: &mut [u8],
) -> Result<()> {
    if data.len() > MAX_KEYSTREAM_LEN {
        return Err(Error::Other(format!(
            "{} octets to encrypt with one SRTP IV: AES-CM allows {MAX_KEYSTREAM_LEN}",
            data.len()
        )));
    }
    cipher.apply_keystream(counter, data).map_err(crypto_error)
}

/// The SRTP session keys of one key derivation epoch.
struct SrtpKeys {
    /// AES-CM keyed with k_e, built once here rather than per packet. `None` for the NULL
    /// cipher (RFC 3711 section 4.1.3), which leaves the payload as it is.
    cipher: Option<Box<dyn StreamCipher>>,
    /// k_s.
    salt: SecretVec,
    /// Pre-keyed HMAC-SHA1 (k_a). Deriving the key schedule on every packet measured ~3x slower
    /// on the SRTP path; see `benches/README.md`.
    auth: Box<dyn Mac>,
    /// k_he and k_hs (RFC 6904).
    header: HeaderExtensionKeys,
}

/// The SRTCP session keys of one key derivation epoch.
struct SrtcpKeys {
    cipher: Option<Box<dyn StreamCipher>>,
    salt: SecretVec,
    auth: Box<dyn Mac>,
}

impl SrtpKeys {
    fn derive(
        crypto: &dyn RTCCrypto,
        profile: ProtectionProfile,
        master_key: &[u8],
        master_salt: &[u8],
        index_over_kdr: u64,
    ) -> Result<Self> {
        let prf = profile.prf();
        let kdf = |label: u8, len: usize| {
            derive(
                crypto,
                prf,
                label,
                master_key,
                master_salt,
                index_over_kdr,
                len,
            )
        };
        let cipher = if profile.is_null_cipher() {
            None
        } else {
            let key = kdf(LABEL_SRTP_ENCRYPTION, prf.key_len())?;
            Some(new_aes_cm(crypto, prf.stream_cipher(), key.as_ref())?)
        };
        let salt = kdf(LABEL_SRTP_SALT, master_salt.len())?;
        let auth_key = kdf(LABEL_SRTP_AUTHENTICATION_TAG, profile.auth_key_len())?;
        let auth = crypto
            .new_hmac(HmacAlgorithm::Sha1, auth_key.as_ref())
            .map_err(crypto_error)?;
        let header = HeaderExtensionKeys::derive(
            crypto,
            prf,
            profile.is_null_cipher(),
            master_key,
            master_salt,
            index_over_kdr,
        )?;
        Ok(Self {
            cipher,
            salt,
            auth,
            header,
        })
    }

    /// The SRTP HMAC-SHA1 authentication tag of RFC 3711 section 4.2: over the authenticated
    /// portion and the ROC.
    fn tag(&mut self, buf: &[u8], roc: u32) -> Result<[u8; HMAC_SHA1_LEN]> {
        let mut tag = [0; HMAC_SHA1_LEN];
        self.auth
            .sign(&[buf, &roc.to_be_bytes()], &mut tag)
            .map_err(crypto_error)?;
        Ok(tag)
    }

    fn counter(&self, header: &rtp::Header, roc: u32) -> [u8; 16] {
        generate_counter(header.sequence_number, roc, header.ssrc, self.salt.as_ref())
    }
}

impl SrtcpKeys {
    fn derive(
        crypto: &dyn RTCCrypto,
        profile: ProtectionProfile,
        master_key: &[u8],
        master_salt: &[u8],
        index_over_kdr: u64,
    ) -> Result<Self> {
        let prf = profile.prf();
        let kdf = |label: u8, len: usize| {
            derive(
                crypto,
                prf,
                label,
                master_key,
                master_salt,
                index_over_kdr,
                len,
            )
        };
        let cipher = if profile.is_null_cipher() {
            None
        } else {
            let key = kdf(LABEL_SRTCP_ENCRYPTION, prf.key_len())?;
            Some(new_aes_cm(crypto, prf.stream_cipher(), key.as_ref())?)
        };
        let salt = kdf(LABEL_SRTCP_SALT, master_salt.len())?;
        let auth_key = kdf(LABEL_SRTCP_AUTHENTICATION_TAG, profile.auth_key_len())?;
        let auth = crypto
            .new_hmac(HmacAlgorithm::Sha1, auth_key.as_ref())
            .map_err(crypto_error)?;
        Ok(Self { cipher, salt, auth })
    }

    /// The SRTCP HMAC-SHA1 authentication tag of RFC 3711 section 4.2.
    fn tag(&mut self, buf: &[u8]) -> Result<[u8; HMAC_SHA1_LEN]> {
        let mut tag = [0; HMAC_SHA1_LEN];
        self.auth.sign(&[buf], &mut tag).map_err(crypto_error)?;
        Ok(tag)
    }

    fn counter(&self, srtcp_index: usize, ssrc: u32) -> [u8; 16] {
        generate_counter(
            (srtcp_index & 0xFFFF) as u16,
            (srtcp_index >> 16) as u32,
            ssrc,
            self.salt.as_ref(),
        )
    }
}

/// The AES-CM / HMAC-SHA1 transforms of RFC 3711 (AES-128), RFC 6188 (AES-192, AES-256) and
/// the NULL cipher with HMAC-SHA1 (RFC 3711 section 4.1.3).
pub(crate) struct CipherAesCmHmacSha1 {
    profile: ProtectionProfile,
    source: KeySource,
    srtp: Epochs<SrtpKeys>,
    srtcp: Epochs<SrtcpKeys>,
}

impl CipherAesCmHmacSha1 {
    pub fn new(
        profile: ProtectionProfile,
        master_key: &[u8],
        master_salt: &[u8],
        crypto: &dyn RTCCrypto,
        rate: KeyDerivationRate,
        provider: Option<Arc<dyn RTCCryptoProvider>>,
    ) -> Result<Self> {
        if !profile.is_aes_cm_or_null() {
            return Err(Error::Other(String::from(
                "no AES protection profile passed to CipherAesCmHmacSha1",
            )));
        }
        let source = KeySource::new(profile.prf(), rate, master_key, master_salt, provider)?;
        // Everything here is per-context setup; a packet then costs only the keystream and the
        // message pass of the MAC.
        let srtp = SrtpKeys::derive(crypto, profile, master_key, master_salt, 0)?;
        let srtcp = SrtcpKeys::derive(crypto, profile, master_key, master_salt, 0)?;
        Ok(Self {
            profile,
            source,
            srtp: Epochs::new(0, srtp),
            srtcp: Epochs::new(0, srtcp),
        })
    }

    /// The SRTP keys for packet index `roc || sequence_number`.
    fn srtp_keys(&mut self, header: &rtp::Header, roc: u32) -> Result<&mut SrtpKeys> {
        let index = ((roc as u64) << 16) | header.sequence_number as u64;
        let (profile, source) = (self.profile, &self.source);
        self.srtp.get(source.rate.epoch(index), |epoch| {
            source.derive(|crypto, key, salt| SrtpKeys::derive(crypto, profile, key, salt, epoch))
        })
    }

    /// The SRTCP keys for `srtcp_index` (RFC 3711 section 4.3.2: the SRTCP index takes the
    /// place of the SRTP index in the derivation).
    fn srtcp_keys(&mut self, srtcp_index: usize) -> Result<&mut SrtcpKeys> {
        let (profile, source) = (self.profile, &self.source);
        self.srtcp
            .get(source.rate.epoch(srtcp_index as u64), |epoch| {
                source.derive(|crypto, key, salt| {
                    SrtcpKeys::derive(crypto, profile, key, salt, epoch)
                })
            })
    }
}

impl Cipher for CipherAesCmHmacSha1 {
    /// Get RTP authenticated tag length.
    fn rtp_auth_tag_len(&self) -> usize {
        self.profile.rtp_auth_tag_len()
    }

    /// Get RTCP authenticated tag length.
    fn rtcp_auth_tag_len(&self) -> usize {
        self.profile.rtcp_auth_tag_len()
    }

    /// Get AEAD auth key length of the cipher.
    fn aead_auth_tag_len(&self) -> usize {
        self.profile.aead_auth_tag_len()
    }

    fn get_rtcp_index(&self, input: &[u8], mki_len: usize) -> usize {
        let tail_offset =
            input.len() - (self.profile.rtcp_auth_tag_len() + mki_len + SRTCP_INDEX_SIZE);
        (u32::from_be_bytes([
            input[tail_offset],
            input[tail_offset + 1],
            input[tail_offset + 2],
            input[tail_offset + 3],
        ]) & !RTCP_ENCRYPTION_FLAG) as usize
    }

    fn encrypt_rtp(
        &mut self,
        plaintext: &[u8],
        header: &rtp::Header,
        roc: u32,
        options: PacketOptions<'_>,
    ) -> Result<BytesMut> {
        let tag_len = self.rtp_auth_tag_len();
        let header_len = header.marshal_size();
        if plaintext.len() < header_len {
            return Err(Error::ErrTooShortRtp);
        }
        let keys = self.srtp_keys(header, roc)?;

        let mut writer = BytesMut::with_capacity(plaintext.len() + options.mki.len() + tag_len);
        writer.extend_from_slice(plaintext);

        // RFC 6904 section 3: the header extension elements are encrypted before the tag is
        // computed, which covers them as they go out.
        keys.header.apply(
            &mut writer,
            header.sequence_number,
            roc,
            header.ssrc,
            options.header_extensions,
        )?;

        // Encrypt the payload
        let counter = keys.counter(header, roc);
        if let Some(cipher) = keys.cipher.as_mut() {
            apply_keystream(cipher.as_mut(), &counter, &mut writer[header_len..])?;
        }

        // Generate the auth tag. The MKI is not part of the authenticated portion (RFC 3711
        // section 3.1) and goes between it and the tag.
        let full_auth_tag = keys.tag(&writer, roc)?;
        writer.extend_from_slice(options.mki);
        writer.extend_from_slice(&full_auth_tag[..tag_len]);

        Ok(writer)
    }

    fn decrypt_rtp(
        &mut self,
        encrypted: &[u8],
        header: &rtp::Header,
        roc: u32,
        options: PacketOptions<'_>,
    ) -> Result<BytesMut> {
        let encrypted_len = encrypted.len();
        let tag_len = self.rtp_auth_tag_len();
        let trailer_len = tag_len + options.mki.len();
        let header_len = header.marshal_size();
        if encrypted_len < header_len + trailer_len {
            return Err(Error::SrtpTooSmall(encrypted_len, header_len + trailer_len));
        }
        let keys = self.srtp_keys(header, roc)?;

        // Split the auth tag and the cipher text into two parts.
        let actual_tag = &encrypted[encrypted_len - tag_len..];
        let cipher_text = &encrypted[..encrypted_len - trailer_len];

        // Generate the auth tag we expect to see from the ciphertext.
        let full_expected_tag = keys.tag(cipher_text, roc)?;

        // See if the auth tag actually matches.
        // We use a constant time comparison to prevent timing attacks.
        if !constant_time_eq(actual_tag, &full_expected_tag[..tag_len]) {
            return Err(Error::RtpFailedToVerifyAuthTag);
        }

        // Write cipher_text to the destination buffer.
        let mut writer = BytesMut::with_capacity(cipher_text.len());
        writer.extend_from_slice(cipher_text);

        // Decrypt the ciphertext for the payload.
        let counter = keys.counter(header, roc);
        if let Some(cipher) = keys.cipher.as_mut() {
            apply_keystream(cipher.as_mut(), &counter, &mut writer[header_len..])?;
        }

        // RFC 6904 section 3: header extensions are decrypted only once the tag is validated.
        keys.header.apply(
            &mut writer,
            header.sequence_number,
            roc,
            header.ssrc,
            options.header_extensions,
        )?;

        Ok(writer)
    }

    fn encrypt_rtp_cryptex(
        &mut self,
        packet: &[u8],
        header: &rtp::Header,
        roc: u32,
        layout: CryptexLayout,
        options: PacketOptions<'_>,
    ) -> Result<BytesMut> {
        let tag_len = self.rtp_auth_tag_len();
        if packet.len() < layout.ext_data_start() {
            return Err(Error::ErrTooShortRtp);
        }
        let keys = self.srtp_keys(header, roc)?;

        let mut writer = BytesMut::with_capacity(packet.len() + options.mki.len() + tag_len);
        writer.extend_from_slice(packet);

        // The keystream starts at the first CSRC and runs on over the extension data and
        // the payload, skipping the extension header (RFC 9335 section 6.2).
        let counter = keys.counter(header, roc);
        if let Some(cipher) = keys.cipher.as_mut() {
            let mut region = layout.gather(&writer);
            apply_keystream(cipher.as_mut(), &counter, &mut region)?;
            layout.scatter(&mut writer, &region);
        }

        // The tag covers the packet as it goes out (RFC 3711 section 3.1).
        let full_auth_tag = keys.tag(&writer, roc)?;
        writer.extend_from_slice(options.mki);
        writer.extend_from_slice(&full_auth_tag[..tag_len]);

        Ok(writer)
    }

    fn decrypt_rtp_cryptex(
        &mut self,
        encrypted: &[u8],
        header: &rtp::Header,
        roc: u32,
        layout: CryptexLayout,
        options: PacketOptions<'_>,
    ) -> Result<BytesMut> {
        let encrypted_len = encrypted.len();
        let tag_len = self.rtp_auth_tag_len();
        let trailer_len = tag_len + options.mki.len();
        if encrypted_len < trailer_len + layout.ext_data_start() {
            return Err(Error::SrtpTooSmall(encrypted_len, trailer_len));
        }
        let keys = self.srtp_keys(header, roc)?;

        let actual_tag = &encrypted[encrypted_len - tag_len..];
        let cipher_text = &encrypted[..encrypted_len - trailer_len];

        let full_expected_tag = keys.tag(cipher_text, roc)?;
        if !constant_time_eq(actual_tag, &full_expected_tag[..tag_len]) {
            return Err(Error::RtpFailedToVerifyAuthTag);
        }

        let mut writer = BytesMut::with_capacity(cipher_text.len());
        writer.extend_from_slice(cipher_text);

        let counter = keys.counter(header, roc);
        if let Some(cipher) = keys.cipher.as_mut() {
            let mut region = layout.gather(&writer);
            apply_keystream(cipher.as_mut(), &counter, &mut region)?;
            layout.scatter(&mut writer, &region);
        }

        Ok(writer)
    }

    fn encrypt_rtcp(
        &mut self,
        decrypted: &[u8],
        srtcp_index: usize,
        ssrc: u32,
        encrypt: bool,
        mki: &[u8],
    ) -> Result<BytesMut> {
        let tag_len = self.rtcp_auth_tag_len();
        if decrypted.len() < HEADER_LENGTH + SSRC_LENGTH {
            return Err(Error::ErrTooShortRtcp);
        }
        let keys = self.srtcp_keys(srtcp_index)?;

        let mut writer =
            BytesMut::with_capacity(decrypted.len() + SRTCP_INDEX_SIZE + mki.len() + tag_len);

        // Write the decrypted to the destination buffer.
        writer.extend_from_slice(decrypted);

        // Encrypt everything after header. The E flag says whether the packet was encrypted
        // (RFC 3711 section 3.4): it is clear when the caller asked for an unencrypted packet,
        // and with the NULL cipher.
        let mut esrtcp = srtcp_index as u32 & !RTCP_ENCRYPTION_FLAG;
        if encrypt && let Some(cipher) = keys.cipher.as_mut() {
            let counter = generate_counter(
                (srtcp_index & 0xFFFF) as u16,
                (srtcp_index >> 16) as u32,
                ssrc,
                keys.salt.as_ref(),
            );
            apply_keystream(
                cipher.as_mut(),
                &counter,
                &mut writer[HEADER_LENGTH + SSRC_LENGTH..],
            )?;
            esrtcp |= RTCP_ENCRYPTION_FLAG;
        }

        // Add SRTCP index and the Encryption bit
        writer.put_u32(esrtcp);

        // Generate the auth tag; the MKI goes between the authenticated portion and the tag.
        let full_auth_tag = keys.tag(&writer)?;
        writer.extend_from_slice(mki);
        writer.extend_from_slice(&full_auth_tag[..tag_len]);

        Ok(writer)
    }

    fn decrypt_rtcp(
        &mut self,
        encrypted: &[u8],
        srtcp_index: usize,
        ssrc: u32,
        mki_len: usize,
    ) -> Result<BytesMut> {
        let encrypted_len = encrypted.len();
        let tag_len = self.rtcp_auth_tag_len();
        let trailer_len = tag_len + mki_len + SRTCP_INDEX_SIZE;
        if encrypted_len < trailer_len {
            return Err(Error::SrtcpTooSmall(encrypted_len, trailer_len));
        }

        let tail_offset = encrypted_len - trailer_len;
        if tail_offset < HEADER_LENGTH + SSRC_LENGTH {
            return Err(Error::ErrTooShortRtcp);
        }
        let keys = self.srtcp_keys(srtcp_index)?;

        // Split the auth tag and the authenticated portion (through the E flag and the index).
        let actual_tag = &encrypted[encrypted_len - tag_len..];
        let authenticated = &encrypted[..tail_offset + SRTCP_INDEX_SIZE];

        // Generate the auth tag we expect to see from the ciphertext.
        let full_expected_tag = keys.tag(authenticated)?;

        // See if the auth tag actually matches.
        // We use a constant time comparison to prevent timing attacks.
        if !constant_time_eq(actual_tag, &full_expected_tag[..tag_len]) {
            return Err(Error::RtcpFailedToVerifyAuthTag);
        }

        let mut writer = BytesMut::with_capacity(tail_offset);
        writer.extend_from_slice(&encrypted[0..tail_offset]);

        // RFC 3711 §3.4: SRTCP is authenticated whether or not it is encrypted, so the E flag
        // (which the tag covers) is read only once the tag has verified.
        let is_encrypted = encrypted[tail_offset] >> 7;
        if is_encrypted == 0 {
            return Ok(writer);
        }

        let counter = keys.counter(srtcp_index, ssrc);
        if let Some(cipher) = keys.cipher.as_mut() {
            apply_keystream(
                cipher.as_mut(),
                &counter,
                &mut writer[HEADER_LENGTH + SSRC_LENGTH..],
            )?;
        }

        Ok(writer)
    }
}

#[cfg(test)]
mod srtcp_unencrypted_test {
    use super::*;

    fn cipher() -> CipherAesCmHmacSha1 {
        let provider = crypto::default_provider()
            .expect("a built-in crypto provider must be enabled for tests");
        CipherAesCmHmacSha1::new(
            ProtectionProfile::Aes128CmHmacSha1_80,
            &[0x11; 16],
            &[0x22; 14],
            provider.crypto(),
            KeyDerivationRate::ZERO,
            None,
        )
        .unwrap()
    }

    /// A receiver report with the E flag clear and index 1, before its tag.
    fn unencrypted_rtcp() -> Vec<u8> {
        let mut raw = vec![0x80, 0xc9, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef];
        raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        raw
    }

    /// RFC 3711 §3.4: SRTCP is authenticated even when the E flag says it is not encrypted. A
    /// packet with E clear and a made-up tag was accepted without any check, so anyone could
    /// inject RTCP with no keys.
    #[test]
    fn unencrypted_srtcp_with_a_bad_tag_is_rejected() {
        let mut c = cipher();
        let mut raw = unencrypted_rtcp();
        raw.extend_from_slice(&[0u8; 10]);
        assert!(c.decrypt_rtcp(&raw, 1, 0xdeadbeef, 0).is_err());
    }

    /// A correctly signed unencrypted SRTCP packet is still accepted, unchanged.
    #[test]
    fn unencrypted_srtcp_with_a_valid_tag_is_accepted() {
        let mut c = cipher();
        let mut raw = unencrypted_rtcp();
        let tag = c.srtcp_keys(1).unwrap().tag(&raw).unwrap();
        raw.extend_from_slice(&tag[..c.rtcp_auth_tag_len()]);
        let plain = c.decrypt_rtcp(&raw, 1, 0xdeadbeef, 0).unwrap();
        assert_eq!(&plain[..], &unencrypted_rtcp()[..8]);
    }
}
