use super::*;
use crate::cryptex;
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
    /// Fails if authentication fails, if the packet is a replay, if it is too short to hold
    /// the profile's auth tag, if it names a master key the context does not have, or with
    /// [`Error::ErrExceededMaxPackets`] once the master key reached its lifetime or the packet
    /// index would pass 2^48 - 1 (RFC 3711 sections 3.3.1 and 9.2).
    pub fn decrypt_rtp_with_header(
        &mut self,
        encrypted: &[u8],
        header: &rtp::Header,
    ) -> Result<BytesMut> {
        let auth_tag_len = self.profile.rtp_auth_tag_len();
        let mki_len = self.mki_field_len();
        if encrypted.len() < header.marshal_size() + auth_tag_len + mki_len {
            return Err(Error::ErrTooShortRtp);
        }

        // The MKI, which nothing authenticates, only selects the key the packet is then
        // authenticated with.
        let key = self.receiving_key(encrypted, auth_tag_len)?;
        self.check_key_lifetime(key, PacketKind::Rtp)?;

        // Per-SSRC state is created only once a packet for that SSRC authenticates, so packets
        // under made-up SSRCs cannot grow the state map.
        let (roc, diff) = match self.srtp_ssrc_states.get_mut(&header.ssrc) {
            Some(state) => {
                let (roc, diff, overflow) = state.next_rollover_count(header.sequence_number);
                if overflow {
                    // The estimate is past ROC 2^32 - 1, i.e. packet index 2^48 or more. The
                    // rollover counter does not wrap under a master key (RFC 3711 section
                    // 3.3.1, RFC 7714 section 13.1): trying the packet with ROC 0 would accept
                    // a keystream (or GCM nonce) used at the start of the stream.
                    return Err(Error::ErrExceededMaxPackets);
                }
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

        let mki_end = encrypted.len() - auth_tag_len;
        let options = PacketOptions {
            mki: &encrypted[mki_end - mki_len..mki_end],
            header_extensions: &self.encrypted_header_extensions,
        };
        let cipher = &mut self.keys[key].cipher;
        let dst = match cryptex::received(encrypted) {
            cryptex::Received::Cryptex(layout) => {
                let mut dst =
                    cipher.decrypt_rtp_cryptex(encrypted, header, roc, layout, options)?;
                cryptex::restore_profile(&mut dst, layout);
                dst
            }
            cryptex::Received::Clear if self.cryptex.require => {
                // Authenticate before blaming the peer: only a packet it really sent is a
                // violation of the policy (RFC 9335 section 5.2). The packet is discarded
                // either way, and leaves no state behind.
                cipher.decrypt_rtp(encrypted, header, roc, options)?;
                if !self.cryptex_violation_reported {
                    self.cryptex_violation_reported = true;
                    self.events
                        .push_back(ContextEvent::CryptexRequiredViolation { ssrc: header.ssrc });
                }
                return Err(Error::Other(format!(
                    "SRTP packet (SSRC {}, sequence number {}) carries CSRCs or header \
                     extensions without Cryptex, which is required",
                    header.ssrc, header.sequence_number
                )));
            }
            _ => cipher.decrypt_rtp(encrypted, header, roc, options)?,
        };
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
        self.count_packet(key, PacketKind::Rtp);

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
    ///
    /// Fails with [`Error::ErrExceededMaxPackets`] once the master key reached its lifetime, or
    /// the stream its 2^48th packet (RFC 3711 sections 3.3.1 and 9.2); see
    /// [`ContextEvent::KeyExhausted`].
    ///
    /// With Cryptex required ([`Cryptex::require`]), fails for a packet that has CSRCs or a
    /// header extension and cannot be protected with Cryptex (an extension that is not RFC
    /// 8285's, or two-byte headers with non-zero "appbits"): nothing leaves with them in the
    /// clear.
    pub fn encrypt_rtp_with_header(
        &mut self,
        plaintext: &[u8],
        header: &rtp::Header,
    ) -> Result<BytesMut> {
        if plaintext.len() < header.marshal_size() {
            return Err(Error::ErrTooShortRtp);
        }
        let key = self.sending_key;
        self.check_key_lifetime(key, PacketKind::Rtp)?;

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

        let cryptex_packet = self
            .cryptex
            .send
            .then(|| cryptex::sender_packet(plaintext))
            .flatten();
        if cryptex_packet.is_none()
            && self.cryptex.require
            && cryptex::carries_csrcs_or_extension(plaintext)
        {
            // RFC 9335 section 5.1 applies Cryptex to RFC 8285 extensions only, and the peer,
            // under the same policy, discards anything else that has CSRCs or an extension.
            return Err(Error::Other(format!(
                "RTP packet (SSRC {}, sequence number {}) has CSRCs or a header extension that \
                 Cryptex, which is required, cannot protect",
                header.ssrc, header.sequence_number
            )));
        }

        let master_key = &mut self.keys[key];
        let options = PacketOptions {
            mki: &master_key.mki,
            header_extensions: &self.encrypted_header_extensions,
        };
        let dst = match cryptex_packet {
            Some((packet, layout)) => master_key
                .cipher
                .encrypt_rtp_cryptex(&packet, header, roc, layout, options)?,
            None => master_key
                .cipher
                .encrypt_rtp(plaintext, header, roc, options)?,
        };

        if is_new {
            let state = self.get_srtp_ssrc_state(header.ssrc)?;
            if let Some(sent) = state.sent_indexes.as_mut() {
                sent.record(index, digest);
            }
            state.update_rollover_count(header.sequence_number, diff);
        }
        // Protecting the same packet again counts too: the count is of packets secured with the
        // key, and it only ever errs on the side of re-keying early.
        self.count_packet(key, PacketKind::Rtp);

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
