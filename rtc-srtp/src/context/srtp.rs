use super::*;
use shared::{
    error::{Error, Result},
    marshal::{MarshalSize, Unmarshal},
};

use bytes::BytesMut;

impl Context {
    /// Decrypts an SRTP packet whose header has already been parsed.
    ///
    /// Saves re-parsing when the caller needed the header to route the packet. The header must
    /// be the one belonging to `encrypted`.
    ///
    /// # Errors
    ///
    /// Fails if authentication fails, if the packet is a replay, or if it is too short to hold
    /// the profile's auth tag.
    pub fn decrypt_rtp_with_header(
        &mut self,
        encrypted: &[u8],
        header: &rtp::Header,
    ) -> Result<BytesMut> {
        let auth_tag_len = self.cipher.rtp_auth_tag_len();
        if encrypted.len() < header.marshal_size() + auth_tag_len {
            return Err(Error::ErrTooShortRtp);
        }

        // Per-SSRC state is created only once a packet for that SSRC authenticates, so packets
        // under made-up SSRCs cannot grow the state map.
        let (roc, diff) = match self.srtp_ssrc_states.get_mut(&header.ssrc) {
            Some(state) => {
                let (roc, diff, _) = state.next_rollover_count(header.sequence_number);
                if let Some(replay_detector) = &mut state.replay_detector
                    && !replay_detector.check(header.sequence_number as u64)
                {
                    return Err(Error::SrtpSsrcDuplicated(
                        header.ssrc,
                        header.sequence_number,
                    ));
                }
                (roc, diff)
            }
            None => {
                // Refuse a further SSRC before spending a decryption on it.
                self.check_srtp_ssrc_capacity(header.ssrc)?;
                let fresh = SrtpSsrcState {
                    ssrc: header.ssrc,
                    ..Default::default()
                };
                let (roc, diff, _) = fresh.next_rollover_count(header.sequence_number);
                (roc, diff)
            }
        };

        let dst = self.cipher.decrypt_rtp(encrypted, header, roc)?;
        {
            let is_new = !self.srtp_ssrc_states.contains_key(&header.ssrc);
            let state = self.get_srtp_ssrc_state(header.ssrc)?;
            if let Some(replay_detector) = &mut state.replay_detector {
                // A new SSRC's detector has not seen this sequence number yet: check, then accept.
                if !is_new || replay_detector.check(header.sequence_number as u64) {
                    replay_detector.accept();
                }
            }
            state.update_rollover_count(header.sequence_number, diff);
        }

        Ok(dst)
    }

    /// DecryptRTP decrypts a RTP packet with an encrypted payload
    pub fn decrypt_rtp(&mut self, encrypted: &[u8]) -> Result<BytesMut> {
        let mut buf = encrypted;
        let header = rtp::Header::unmarshal(&mut buf)?;
        self.decrypt_rtp_with_header(encrypted, &header)
    }

    /// Encrypts an RTP payload, using an already-parsed header.
    ///
    /// Saves re-parsing when the caller has just built the header. Returns the full protected
    /// packet, header included.
    ///
    /// # Errors
    ///
    /// Fails if the SRTP context has no key for this SSRC, if the cipher rejects the input, or
    /// with [`Error::SrtpIndexReused`] if this packet index (ROC and sequence number) already
    /// protected a different packet, or lies more than a window behind the highest index sent.
    /// The same packet under the same index (a retransmission) is protected again, which yields
    /// the same bytes.
    pub fn encrypt_rtp_with_header(
        &mut self,
        plaintext: &[u8],
        header: &rtp::Header,
    ) -> Result<BytesMut> {
        let digest = self.sent_digest_hasher.hash_one(plaintext);
        let (roc, diff, index, is_new) = {
            let state = self.get_srtp_ssrc_state(header.ssrc)?;
            let (roc, diff, ovf) = state.next_rollover_count(header.sequence_number);
            if ovf {
                // ... when 2^48 SRTP packets or 2^31 SRTCP packets have been secured with the same key
                // (whichever occurs before), the key management MUST be called to provide new master key(s)
                // (previously stored and used keys MUST NOT be used again), or the session MUST be terminated.
                // https://www.rfc-editor.org/rfc/rfc3711#section-9.2
                return Err(Error::ErrExceededMaxPackets);
            }

            // Each packet index is protected at most once (RFC 3711 Section 3.3.1, RFC 7714
            // Section 8.1).
            let index = ((roc as u64) << 16) | header.sequence_number as u64;
            let sent = state.sent_indexes.get_or_insert_with(SentIndexes::new);
            let is_new = match sent.check(index, digest) {
                SendIndexUse::New => true,
                SendIndexUse::SamePacket => false,
                SendIndexUse::Refused => {
                    return Err(Error::SrtpIndexReused(header.ssrc, header.sequence_number));
                }
            };
            (roc, diff, index, is_new)
        };

        let dst = self.cipher.encrypt_rtp(plaintext, header, roc)?;

        if is_new {
            let state = self.get_srtp_ssrc_state(header.ssrc)?;
            if let Some(sent) = state.sent_indexes.as_mut() {
                sent.record(index, digest);
            }
            state.update_rollover_count(header.sequence_number, diff);
        }

        Ok(dst)
    }

    /// EncryptRTP marshals and encrypts an RTP packet, writing to the dst buffer provided.
    /// If the dst buffer does not have the capacity to hold `len(plaintext) + 10` bytes, a new one will be allocated and returned.
    pub fn encrypt_rtp(&mut self, plaintext: &[u8]) -> Result<BytesMut> {
        let mut buf = plaintext;
        let header = rtp::Header::unmarshal(&mut buf)?;
        self.encrypt_rtp_with_header(plaintext, &header)
    }
}
