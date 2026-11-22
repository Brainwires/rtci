use super::*;
use crate::key_derivation::SRTCP_INDEX_SIZE;
use shared::{error::Result, marshal::Unmarshal};

use bytes::BytesMut;

impl Context {
    /// DecryptRTCP decrypts a RTCP packet with an encrypted payload
    ///
    /// The packet is authenticated whatever its E flag says, and decrypted only when the flag
    /// is set (RFC 3711 section 3.4, RFC 7714 section 9.3).
    ///
    /// # Errors
    ///
    /// Fails if authentication fails, if the packet is a replay or too short, if it names a
    /// master key the context does not have, or with [`Error::ErrExceededMaxPackets`] once the
    /// master key reached its lifetime (RFC 3711 section 9.2).
    pub fn decrypt_rtcp(&mut self, encrypted: &[u8]) -> Result<BytesMut> {
        // A received SRTCP packet must be at least the minimum valid size for the
        // negotiated profile: the RTCP header through the SSRC (read at bytes
        // 4..8), the trailing SRTCP index, the MKI when the context uses one, and the
        // auth tag that `get_rtcp_index` and the cipher read from the end (the HMAC
        // tag for AES-CM, the AEAD tag for GCM). A shorter packet from the network
        // would otherwise index out of bounds and panic (a remotely triggerable DoS).
        // This is self-contained: it does not rely on the individual ciphers' own guards.
        let auth_tag_len = self.profile.rtcp_auth_tag_len();
        let mki_len = self.mki_field_len();
        let min_len =
            8 + SRTCP_INDEX_SIZE + mki_len + auth_tag_len + self.profile.aead_auth_tag_len();
        if encrypted.len() < min_len {
            return Err(Error::ErrTooShortRtcp);
        }

        let mut buf = encrypted;
        rtcp::Header::unmarshal(&mut buf)?;

        let key = self.receiving_key(encrypted, auth_tag_len)?;
        self.check_key_lifetime(key, PacketKind::Rtcp)?;

        let index = self.keys[key].cipher.get_rtcp_index(encrypted, mki_len);
        let ssrc = u32::from_be_bytes([encrypted[4], encrypted[5], encrypted[6], encrypted[7]]);

        // Per-SSRC state is created only once a packet for that SSRC authenticates, so packets
        // under made-up SSRCs cannot grow the state map.
        if let Some(state) = self.srtcp_ssrc_states.get_mut(&ssrc)
            && let Some(replay_detector) = &mut state.replay_detector
            && !replay_detector.check(index as u64)
        {
            return Err(Error::SrtcpSsrcDuplicated(ssrc, index));
        }
        // Refuse a further SSRC before spending a decryption on it.
        self.check_srtcp_ssrc_capacity(ssrc)?;

        let dst = self.keys[key]
            .cipher
            .decrypt_rtcp(encrypted, index, ssrc, mki_len)?;

        let is_new = !self.srtcp_ssrc_states.contains_key(&ssrc);
        if let Some(replay_detector) = &mut self.get_srtcp_ssrc_state(ssrc)?.replay_detector {
            // A new SSRC's detector has not seen this index yet: check, then accept.
            if !is_new || replay_detector.check(index as u64) {
                replay_detector.accept();
            }
        }
        self.count_packet(key, PacketKind::Rtcp);

        Ok(dst)
    }

    /// EncryptRTCP marshals and encrypts an RTCP packet, writing to the dst buffer provided.
    /// If the dst buffer does not have the capacity to hold `len(plaintext) + 14` bytes, a new one will be allocated and returned.
    ///
    /// The first packet of an SSRC carries SRTCP index 0, and each later one the next index
    /// modulo 2^31 (RFC 3711 section 3.4).
    ///
    /// # Errors
    ///
    /// Fails with [`Error::ErrExceededMaxPackets`] once the master key has protected its
    /// lifetime of SRTCP packets, 2^31 at most (RFC 3711 section 9.2, RFC 7714 section 9.4):
    /// one more would reuse a keystream, or a GCM nonce, under the same key. See
    /// [`ContextEvent::KeyExhausted`].
    pub fn encrypt_rtcp(&mut self, decrypted: &[u8]) -> Result<BytesMut> {
        if decrypted.len() < 8 {
            return Err(Error::ErrTooShortRtcp);
        }

        let mut buf = decrypted;
        rtcp::Header::unmarshal(&mut buf)?;

        let ssrc = u32::from_be_bytes([decrypted[4], decrypted[5], decrypted[6], decrypted[7]]);

        // No (master key, SSRC, index) triple is ever used twice: an SSRC's indexes are
        // consecutive modulo 2^31, and a master key protects at most 2^31 SRTCP packets, over
        // all its SSRCs. So an index may wrap only under another master key than the one it
        // was first used with.
        let key = self.sending_key;
        self.check_key_lifetime(key, PacketKind::Rtcp)?;

        let index = self.get_srtcp_ssrc_state(ssrc)?.srtcp_index;
        let encrypt = self.srtcp_encryption;
        let master_key = &mut self.keys[key];
        let dst =
            master_key
                .cipher
                .encrypt_rtcp(decrypted, index, ssrc, encrypt, &master_key.mki)?;

        self.get_srtcp_ssrc_state(ssrc)?.srtcp_index = (index + 1) & MAX_SRTCP_INDEX;
        self.count_packet(key, PacketKind::Rtcp);

        Ok(dst)
    }
}
