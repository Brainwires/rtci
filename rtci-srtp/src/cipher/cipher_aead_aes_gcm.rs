use std::sync::Arc;

use bytes::BytesMut;
use crypto::{AeadAlgorithm, AeadCipher, RTCCrypto, RTCCryptoProvider, SecretVec};

use super::{Cipher, Epochs, KeySource, PacketOptions, crypto_error};
use crate::cryptex::CryptexLayout;
use crate::header_extension::HeaderExtensionKeys;
use crate::key_derivation::*;
use crate::keying::KeyDerivationRate;
use crate::protection_profile::ProtectionProfile;
use shared::{
    error::{Error, Result},
    marshal::*,
};

pub const CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN: usize = 16;

const RTCP_ENCRYPTION_FLAG: u8 = 0x80;
/// The part of an RTCP packet that is associated data even when the rest is encrypted: the
/// first header and the sender's SSRC (RFC 7714 section 9.2).
const RTCP_CLEAR_LEN: usize = 8;
const IV_LEN: usize = 12;

/// The SRTP session keys of one key derivation epoch.
struct SrtpKeys {
    aead: Box<dyn AeadCipher>,
    /// The 12-octet session salt.
    salt: SecretVec,
    /// k_he and k_hs (RFC 6904, RFC 7714 section 8.3).
    header: HeaderExtensionKeys,
}

/// The SRTCP session keys of one key derivation epoch.
struct SrtcpKeys {
    aead: Box<dyn AeadCipher>,
    salt: SecretVec,
}

fn algorithm_of(profile: ProtectionProfile) -> Result<AeadAlgorithm> {
    match profile {
        ProtectionProfile::AeadAes128Gcm => Ok(AeadAlgorithm::Aes128Gcm),
        ProtectionProfile::AeadAes256Gcm => Ok(AeadAlgorithm::Aes256Gcm),
        // Context::new only builds this cipher for the two GCM profiles, so this arm is not
        // reached; it is an error rather than a panic so that no caller can turn a
        // negotiated profile into an abort.
        _ => Err(Error::ErrNoSuchSrtpProfile),
    }
}

fn new_aead(
    crypto: &dyn RTCCrypto,
    profile: ProtectionProfile,
    session_key: &[u8],
) -> Result<Box<dyn AeadCipher>> {
    let cipher = crypto
        .new_aead(algorithm_of(profile)?, session_key)
        .map_err(crypto_error)?;
    if cipher.tag_len() != CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN {
        return Err(Error::Crypto(format!(
            "SRTP AES-GCM requires a {}-byte tag, provider returned {}",
            CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN,
            cipher.tag_len()
        )));
    }
    Ok(cipher)
}

fn session_salt(salt: SecretVec) -> Result<SecretVec> {
    if salt.len() != IV_LEN {
        return Err(Error::SrtpSaltLength(IV_LEN, salt.len()));
    }
    Ok(salt)
}

impl SrtpKeys {
    /// AEAD_AES_128_GCM derives with the AES-CM PRF of RFC 3711, AEAD_AES_256_GCM with
    /// AES_256_CM_PRF of RFC 6188 (RFC 7714 section 11).
    fn derive(
        crypto: &dyn RTCCrypto,
        profile: ProtectionProfile,
        master_key: &[u8],
        master_salt: &[u8],
        index_over_kdr: u64,
    ) -> Result<Self> {
        let prf = profile.prf();
        let key = derive(
            crypto,
            prf,
            LABEL_SRTP_ENCRYPTION,
            master_key,
            master_salt,
            index_over_kdr,
            master_key.len(),
        )?;
        let salt = derive(
            crypto,
            prf,
            LABEL_SRTP_SALT,
            master_key,
            master_salt,
            index_over_kdr,
            master_salt.len(),
        )?;
        Ok(Self {
            aead: new_aead(crypto, profile, key.as_ref())?,
            salt: session_salt(salt)?,
            header: HeaderExtensionKeys::derive(
                crypto,
                prf,
                false,
                master_key,
                master_salt,
                index_over_kdr,
            )?,
        })
    }

    /// The 12-octet IV used by AES-GCM SRTP is formed by first concatenating
    /// 2 octets of zeroes, the 4-octet SSRC, the 4-octet rollover counter
    /// (ROC), and the 2-octet sequence number (SEQ).  The resulting 12-octet
    /// value is then XORed to the 12-octet salt to form the 12-octet IV.
    ///
    /// https://tools.ietf.org/html/rfc7714#section-8.1
    fn iv(&self, header: &rtp::Header, roc: u32) -> [u8; IV_LEN] {
        let mut iv = [0u8; IV_LEN];
        iv[2..6].copy_from_slice(&header.ssrc.to_be_bytes());
        iv[6..10].copy_from_slice(&roc.to_be_bytes());
        iv[10..].copy_from_slice(&header.sequence_number.to_be_bytes());

        for (v, salt) in iv.iter_mut().zip(self.salt.as_ref()) {
            *v ^= salt;
        }

        iv
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
        let key = derive(
            crypto,
            prf,
            LABEL_SRTCP_ENCRYPTION,
            master_key,
            master_salt,
            index_over_kdr,
            master_key.len(),
        )?;
        let salt = derive(
            crypto,
            prf,
            LABEL_SRTCP_SALT,
            master_key,
            master_salt,
            index_over_kdr,
            master_salt.len(),
        )?;
        Ok(Self {
            aead: new_aead(crypto, profile, key.as_ref())?,
            salt: session_salt(salt)?,
        })
    }

    /// The 12-octet IV used by AES-GCM SRTCP is formed by first
    /// concatenating 2 octets of zeroes, the 4-octet SSRC identifier,
    /// 2 octets of zeroes, a single "0" bit, and the 31-bit SRTCP index.
    /// The resulting 12-octet value is then XORed to the 12-octet salt to
    /// form the 12-octet IV.
    ///
    /// https://tools.ietf.org/html/rfc7714#section-9.1
    fn iv(&self, srtcp_index: usize, ssrc: u32) -> [u8; IV_LEN] {
        let mut iv = [0u8; IV_LEN];
        iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
        iv[8..].copy_from_slice(&(srtcp_index as u32 & 0x7FFF_FFFF).to_be_bytes());

        for (v, salt) in iv.iter_mut().zip(self.salt.as_ref()) {
            *v ^= salt;
        }

        iv
    }
}

/// In an SRTCP packet, a 1-bit Encryption flag is prepended to the 31-bit SRTCP index to form
/// a 32-bit value RFC 7714 section 17 calls the "ESRTCP word".
fn esrtcp_word(srtcp_index: usize, encrypted: bool) -> [u8; SRTCP_INDEX_SIZE] {
    let mut word = (srtcp_index as u32 & 0x7FFF_FFFF).to_be_bytes();
    if encrypted {
        word[0] |= RTCP_ENCRYPTION_FLAG;
    }
    word
}

/// Provider-backed AEAD cipher based on AES-GCM.
pub(crate) struct CipherAeadAesGcm {
    profile: ProtectionProfile,
    source: KeySource,
    srtp: Epochs<SrtpKeys>,
    srtcp: Epochs<SrtcpKeys>,
}

impl Cipher for CipherAeadAesGcm {
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

    fn encrypt_rtp(
        &mut self,
        payload: &[u8],
        header: &rtp::Header,
        roc: u32,
        options: PacketOptions<'_>,
    ) -> Result<BytesMut> {
        // Copy the whole packet once, then encrypt the payload region in place
        // with the header region as AAD and a detached tag appended afterwards.
        let header_len = header.marshal_size();
        if payload.len() < header_len {
            return Err(Error::ErrTooShortRtp);
        }
        let keys = self.srtp_keys(header, roc)?;
        let nonce = keys.iv(header, roc);

        let mut writer = BytesMut::with_capacity(
            payload.len() + CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN + options.mki.len(),
        );
        writer.extend_from_slice(payload);

        // RFC 7714 section 8.3: header extension encryption (RFC 6904) comes before the AEAD,
        // which takes the header, encrypted elements included, as associated data.
        keys.header.apply(
            &mut writer,
            header_len,
            header.sequence_number,
            roc,
            header.ssrc,
            options.header_extensions,
        )?;

        let (aad, plaintext) = writer.split_at_mut(header_len);
        let mut tag = [0; CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN];
        keys.aead
            .seal_in_place(&nonce, aad, plaintext, &mut tag)
            .map_err(crypto_error)?;

        writer.extend_from_slice(&tag);
        // The MKI is raw data after the cipher (RFC 7714 section 8.2).
        writer.extend_from_slice(options.mki);
        Ok(writer)
    }

    fn decrypt_rtp(
        &mut self,
        ciphertext: &[u8],
        header: &rtp::Header,
        roc: u32,
        options: PacketOptions<'_>,
    ) -> Result<BytesMut> {
        let trailer_len = CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN + options.mki.len();
        let payload_offset = header.marshal_size();
        if ciphertext.len() < payload_offset + trailer_len {
            // Too short to hold header + tag; the AEAD would reject it and the
            // slice split below would panic.
            return Err(Error::ErrFailedToVerifyAuthTag);
        }
        let keys = self.srtp_keys(header, roc)?;
        let nonce = keys.iv(header, roc);

        let tag_offset = ciphertext.len() - trailer_len;
        let tag = &ciphertext[tag_offset..tag_offset + CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN];
        let mut writer = BytesMut::with_capacity(tag_offset);
        writer.extend_from_slice(&ciphertext[..tag_offset]);

        let (aad, encrypted_payload) = writer.split_at_mut(payload_offset);
        keys.aead
            .open_in_place(&nonce, aad, encrypted_payload, tag)
            .map_err(|_| Error::ErrFailedToVerifyAuthTag)?;

        // RFC 6904 section 3: header extensions are decrypted only once the packet is
        // authenticated.
        keys.header.apply(
            &mut writer,
            payload_offset,
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
        if packet.len() < layout.ext_data_start() {
            return Err(Error::ErrTooShortRtp);
        }
        // RFC 9335 section 6.2: the fixed header and the extension header are the associated
        // data; the CSRCs, the extension data and the payload are one plaintext.
        let keys = self.srtp_keys(header, roc)?;
        let nonce = keys.iv(header, roc);
        let aad = layout.associated_data(packet);
        let mut region = layout.gather(packet);
        let mut tag = [0; CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN];
        keys.aead
            .seal_in_place(&nonce, &aad, &mut region, &mut tag)
            .map_err(crypto_error)?;

        let mut writer = BytesMut::with_capacity(
            packet.len() + CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN + options.mki.len(),
        );
        writer.extend_from_slice(packet);
        layout.scatter(&mut writer, &region);
        writer.extend_from_slice(&tag);
        writer.extend_from_slice(options.mki);
        Ok(writer)
    }

    fn decrypt_rtp_cryptex(
        &mut self,
        ciphertext: &[u8],
        header: &rtp::Header,
        roc: u32,
        layout: CryptexLayout,
        options: PacketOptions<'_>,
    ) -> Result<BytesMut> {
        let trailer_len = CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN + options.mki.len();
        if ciphertext.len() < layout.ext_data_start() + trailer_len {
            return Err(Error::ErrFailedToVerifyAuthTag);
        }

        let keys = self.srtp_keys(header, roc)?;
        let nonce = keys.iv(header, roc);
        let tag_offset = ciphertext.len() - trailer_len;
        let tag = &ciphertext[tag_offset..tag_offset + CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN];
        let body = &ciphertext[..tag_offset];
        let aad = layout.associated_data(body);
        let mut region = layout.gather(body);
        keys.aead
            .open_in_place(&nonce, &aad, &mut region, tag)
            .map_err(|_| Error::ErrFailedToVerifyAuthTag)?;

        let mut writer = BytesMut::with_capacity(tag_offset);
        writer.extend_from_slice(body);
        layout.scatter(&mut writer, &region);
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
        if decrypted.len() < RTCP_CLEAR_LEN {
            return Err(Error::ErrTooShortRtcp);
        }
        let keys = self.srtcp_keys(srtcp_index)?;
        let iv = keys.iv(srtcp_index, ssrc);
        let esrtcp = esrtcp_word(srtcp_index, encrypt);

        let mut writer = BytesMut::with_capacity(
            decrypted.len() + CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN + SRTCP_INDEX_SIZE + mki.len(),
        );
        writer.extend_from_slice(decrypted);

        let mut tag = [0; CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN];
        if encrypt {
            // RFC 7714 section 9.2: the first 8 octets and the ESRTCP word are the associated
            // data, everything else the plaintext.
            let mut aad = [0u8; RTCP_CLEAR_LEN + SRTCP_INDEX_SIZE];
            aad[..RTCP_CLEAR_LEN].copy_from_slice(&decrypted[..RTCP_CLEAR_LEN]);
            aad[RTCP_CLEAR_LEN..].copy_from_slice(&esrtcp);
            keys.aead
                .seal_in_place(&iv, &aad, &mut writer[RTCP_CLEAR_LEN..], &mut tag)
                .map_err(crypto_error)?;
        } else {
            // RFC 7714 section 9.3: the whole packet and the ESRTCP word are the associated
            // data, there is no plaintext, and the cipher is the tag alone.
            let mut aad = Vec::with_capacity(decrypted.len() + SRTCP_INDEX_SIZE);
            aad.extend_from_slice(decrypted);
            aad.extend_from_slice(&esrtcp);
            keys.aead
                .seal_in_place(&iv, &aad, &mut [], &mut tag)
                .map_err(crypto_error)?;
        }

        writer.extend_from_slice(&tag);
        writer.extend_from_slice(&esrtcp);
        writer.extend_from_slice(mki);

        Ok(writer)
    }

    fn decrypt_rtcp(
        &mut self,
        encrypted: &[u8],
        srtcp_index: usize,
        ssrc: u32,
        mki_len: usize,
    ) -> Result<BytesMut> {
        let trailer_len = CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN + SRTCP_INDEX_SIZE + mki_len;
        if encrypted.len() < RTCP_CLEAR_LEN + trailer_len {
            // Too short to hold the SRTCP header + tag; the AEAD would reject it.
            return Err(Error::ErrFailedToVerifyAuthTag);
        }

        let keys = self.srtcp_keys(srtcp_index)?;
        let nonce = keys.iv(srtcp_index, ssrc);

        let tag_start = encrypted.len() - trailer_len;
        let esrtcp_start = tag_start + CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN;
        let tag = &encrypted[tag_start..esrtcp_start];
        // The ESRTCP word as received. It is associated data in both layouts, so the E flag
        // that selects the layout is itself authenticated: a flipped flag fails the tag.
        let esrtcp = &encrypted[esrtcp_start..esrtcp_start + SRTCP_INDEX_SIZE];
        let mut writer = BytesMut::with_capacity(tag_start);
        writer.extend_from_slice(&encrypted[..tag_start]);

        if esrtcp[0] & RTCP_ENCRYPTION_FLAG != 0 {
            let mut aad = [0u8; RTCP_CLEAR_LEN + SRTCP_INDEX_SIZE];
            aad[..RTCP_CLEAR_LEN].copy_from_slice(&encrypted[..RTCP_CLEAR_LEN]);
            aad[RTCP_CLEAR_LEN..].copy_from_slice(esrtcp);
            keys.aead
                .open_in_place(&nonce, &aad, &mut writer[RTCP_CLEAR_LEN..], tag)
                .map_err(|_| Error::ErrFailedToVerifyAuthTag)?;
        } else {
            // RFC 7714 section 9.3: tagged, not encrypted.
            let mut aad = Vec::with_capacity(tag_start + SRTCP_INDEX_SIZE);
            aad.extend_from_slice(&encrypted[..tag_start]);
            aad.extend_from_slice(esrtcp);
            keys.aead
                .open_in_place(&nonce, &aad, &mut [], tag)
                .map_err(|_| Error::ErrFailedToVerifyAuthTag)?;
        }
        Ok(writer)
    }

    fn get_rtcp_index(&self, input: &[u8], mki_len: usize) -> usize {
        let pos = input.len() - mki_len - SRTCP_INDEX_SIZE;
        (u32::from_be_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]])
            & 0x7FFF_FFFF) as usize
    }
}

impl CipherAeadAesGcm {
    /// Create a new AEAD instance.
    pub(crate) fn new(
        profile: ProtectionProfile,
        master_key: &[u8],
        master_salt: &[u8],
        crypto: &dyn RTCCrypto,
        rate: KeyDerivationRate,
        provider: Option<Arc<dyn RTCCryptoProvider>>,
    ) -> Result<CipherAeadAesGcm> {
        algorithm_of(profile)?;
        debug_assert_eq!(
            profile.aead_auth_tag_len(),
            CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN
        );
        if master_salt.len() != profile.salt_len() {
            return Err(Error::SrtpSaltLength(profile.salt_len(), master_salt.len()));
        }

        let source = KeySource::new(profile.prf(), rate, master_key, master_salt, provider)?;
        let srtp = SrtpKeys::derive(crypto, profile, master_key, master_salt, 0)?;
        let srtcp = SrtcpKeys::derive(crypto, profile, master_key, master_salt, 0)?;

        Ok(CipherAeadAesGcm {
            profile,
            source,
            srtp: Epochs::new(0, srtp),
            srtcp: Epochs::new(0, srtcp),
        })
    }

    /// A cipher over given session keys and salts, for the RFC 7714 test vectors, which state
    /// the AEAD key and salt and not a master key. No header extension keys: RFC 6904 does
    /// nothing with this cipher.
    #[cfg(test)]
    pub(crate) fn from_session_keys(
        profile: ProtectionProfile,
        srtp_key: &[u8],
        srtp_salt: &[u8],
        srtcp_key: &[u8],
        srtcp_salt: &[u8],
        crypto: &dyn RTCCrypto,
    ) -> Result<CipherAeadAesGcm> {
        Ok(CipherAeadAesGcm {
            profile,
            source: KeySource::new(profile.prf(), KeyDerivationRate::ZERO, &[], &[], None)?,
            srtp: Epochs::new(
                0,
                SrtpKeys {
                    aead: new_aead(crypto, profile, srtp_key)?,
                    salt: session_salt(SecretVec::new(srtp_salt.to_vec()))?,
                    header: HeaderExtensionKeys::none(),
                },
            ),
            srtcp: Epochs::new(
                0,
                SrtcpKeys {
                    aead: new_aead(crypto, profile, srtcp_key)?,
                    salt: session_salt(SecretVec::new(srtcp_salt.to_vec()))?,
                },
            ),
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

    /// The SRTCP keys for `srtcp_index`.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_aes_gcm_128() {
        let profile = ProtectionProfile::AeadAes128Gcm;
        let master_key = vec![0u8; profile.key_len()];
        let master_salt = vec![0u8; 12];

        let provider = crypto::default_provider().unwrap();
        let mut cipher = CipherAeadAesGcm::new(
            profile,
            &master_key,
            &master_salt,
            provider.crypto(),
            KeyDerivationRate::ZERO,
            None,
        )
        .unwrap();

        let header = rtp::Header {
            ssrc: 0x12345678,
            ..Default::default()
        };

        let payload = vec![0u8; 100];
        let encrypted = cipher
            .encrypt_rtp(&payload, &header, 0, PacketOptions::NONE)
            .unwrap();

        let decrypted = cipher
            .decrypt_rtp(&encrypted, &header, 0, PacketOptions::NONE)
            .unwrap();
        assert_eq!(&decrypted[..], &payload[..]);
    }

    /// Inputs long enough to pass the tag-length check but too short to hold
    /// header + tag must fail cleanly instead of panicking on a slice split.
    #[test]
    fn test_aead_aes_gcm_short_input_errors() {
        let profile = ProtectionProfile::AeadAes128Gcm;
        let master_key = vec![0u8; profile.key_len()];
        let master_salt = vec![0u8; 12];

        let provider = crypto::default_provider().unwrap();
        let mut cipher = CipherAeadAesGcm::new(
            profile,
            &master_key,
            &master_salt,
            provider.crypto(),
            KeyDerivationRate::ZERO,
            None,
        )
        .unwrap();

        let header = rtp::Header {
            ssrc: 0x12345678,
            ..Default::default()
        };

        // 20 bytes: >= the 16-byte tag, but < 12-byte header + 16-byte tag.
        assert!(
            cipher
                .decrypt_rtp(&[0u8; 20], &header, 0, PacketOptions::NONE)
                .is_err()
        );

        // 24 bytes: >= tag + 4-byte SRTCP index, but < 8-byte SRTCP header
        // + tag + index.
        assert!(cipher.decrypt_rtcp(&[0u8; 24], 0, 0x12345678, 0).is_err());
    }

    #[test]
    fn test_aead_aes_gcm_256() {
        let profile = ProtectionProfile::AeadAes256Gcm;
        let master_key = vec![0u8; profile.key_len()];
        let master_salt = vec![0u8; 12];

        let provider = crypto::default_provider().unwrap();
        let mut cipher = CipherAeadAesGcm::new(
            profile,
            &master_key,
            &master_salt,
            provider.crypto(),
            KeyDerivationRate::ZERO,
            None,
        )
        .unwrap();

        let header = rtp::Header {
            ssrc: 0x12345678,
            ..Default::default()
        };

        let payload = vec![0u8; 100];
        let encrypted = cipher
            .encrypt_rtp(&payload, &header, 0, PacketOptions::NONE)
            .unwrap();

        let decrypted = cipher
            .decrypt_rtp(&encrypted, &header, 0, PacketOptions::NONE)
            .unwrap();
        assert_eq!(&decrypted[..], &payload[..]);
    }
}
