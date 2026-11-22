//! Encryption of selected RTP header extension elements ([RFC 6904]).
//!
//! Where Cryptex ([RFC 9335]) encrypts the whole extension block and the CSRCs, RFC 6904
//! encrypts the payload of the extension elements whose ids were negotiated as encrypted
//! (`a=extmap:<id> urn:ietf:params:rtp-hdrext:encrypt <uri>`), and leaves the element headers,
//! the other elements and the padding readable. A [`Context`](crate::context::Context) applies
//! it to the ids given to
//! [`set_encrypted_header_extensions`](crate::context::Context::set_encrypted_header_extensions).
//! A packet protected with Cryptex is never also processed this way (RFC 9335 section 5).
//!
//! [RFC 6904]: https://www.rfc-editor.org/rfc/rfc6904
//! [RFC 9335]: https://www.rfc-editor.org/rfc/rfc9335

use std::ops::Range;

use crypto::{RTCCrypto, SecretVec, StreamCipher};
use shared::error::{Error, Result};

use crate::cipher::{crypto_error, new_aes_cm};
use crate::cryptex::RTP_FIXED_HEADER_LEN;
use crate::key_derivation::{
    LABEL_SRTP_HEADER_ENCRYPTION, LABEL_SRTP_HEADER_SALT, Prf, derive, generate_counter,
};

/// RFC 8285 one-byte header extensions.
const PROFILE_ONE_BYTE: u16 = 0xBEDE;
/// RFC 8285 two-byte header extensions: `0x100` and four "appbits".
const PROFILE_TWO_BYTE: u16 = 0x1000;
const PROFILE_TWO_BYTE_MASK: u16 = 0xFFF0;

/// The header extension element ids whose payload is encrypted (RFC 6904 section 4).
///
/// The ids are the `extmap` ids of the session, 1 to 255 (1 to 14 can appear in one-byte
/// headers). The empty set, the default, encrypts nothing.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct EncryptedHeaderExtensions {
    ids: [u64; 4],
}

impl EncryptedHeaderExtensions {
    /// The empty set: nothing is encrypted.
    pub const NONE: Self = Self { ids: [0; 4] };

    /// The set of `ids`.
    ///
    /// # Errors
    ///
    /// Id 0 is refused: it marks padding in RFC 8285, which is never encrypted (RFC 6904
    /// section 3).
    pub fn new(ids: &[u8]) -> Result<Self> {
        let mut set = Self::default();
        for &id in ids {
            if id == 0 {
                return Err(Error::Other(
                    "header extension id 0 is padding and cannot be encrypted".to_owned(),
                ));
            }
            set.ids[(id >> 6) as usize] |= 1 << (id & 63);
        }
        Ok(set)
    }

    /// Whether the payload of elements with this id is encrypted.
    pub fn contains(&self, id: u8) -> bool {
        self.ids[(id >> 6) as usize] & (1 << (id & 63)) != 0
    }

    /// Whether no id is encrypted.
    pub fn is_empty(&self) -> bool {
        self.ids == [0; 4]
    }

    /// The ids, in ascending order.
    pub fn ids(&self) -> impl Iterator<Item = u8> + '_ {
        (1..=u8::MAX).filter(|id| self.contains(*id))
    }
}

impl std::fmt::Debug for EncryptedHeaderExtensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.ids()).finish()
    }
}

/// The "defined by profile" field and where the extension data (RFC 3550 section 5.3.1's
/// "header extension" proper, after the profile and length) lies in a raw RTP packet, or `None`
/// when the packet has no extension or is too short to hold the one it announces.
pub(crate) fn extension_data(packet: &[u8]) -> Option<(u16, Range<usize>)> {
    let first = *packet.first()?;
    if first & 0x10 == 0 {
        return None;
    }
    let start = RTP_FIXED_HEADER_LEN + 4 * (first & 0x0F) as usize;
    let header = packet.get(start..start + 4)?;
    let profile = u16::from_be_bytes([header[0], header[1]]);
    let len = 4 * u16::from_be_bytes([header[2], header[3]]) as usize;
    let data = start + 4..start + 4 + len;
    (packet.len() >= data.end).then_some((profile, data))
}

/// The encryption mask of RFC 6904 section 3: for each octet of the extension data, whether
/// it is the payload of an element whose id is in `ids`. Element headers, the other elements
/// and padding are never in it. Empty for any profile but RFC 8285's.
///
/// The receiver computes the same mask from the packet as it arrives, since the element
/// headers are not encrypted. Parsing stops at the first thing that is not a well-formed
/// element (as RFC 8285 section 4.2 has a receiver stop), leaving the rest unencrypted.
pub(crate) fn encryption_mask(
    profile: u16,
    data: &[u8],
    ids: &EncryptedHeaderExtensions,
) -> Vec<Range<usize>> {
    let mut mask = Vec::new();
    let mut at = 0;
    if profile == PROFILE_ONE_BYTE {
        while at < data.len() {
            let head = data[at];
            if head == 0 {
                // Padding.
                at += 1;
                continue;
            }
            let id = head >> 4;
            if id == 15 {
                // Reserved: processing stops (RFC 8285 section 4.2).
                break;
            }
            let len = (head & 0x0F) as usize + 1;
            let payload = at + 1..at + 1 + len;
            if payload.end > data.len() {
                break;
            }
            at = payload.end;
            if ids.contains(id) {
                mask.push(payload);
            }
        }
    } else if profile & PROFILE_TWO_BYTE_MASK == PROFILE_TWO_BYTE {
        while at < data.len() {
            let id = data[at];
            if id == 0 {
                // Padding.
                at += 1;
                continue;
            }
            let Some(&len) = data.get(at + 1) else {
                break;
            };
            let payload = at + 2..at + 2 + len as usize;
            if payload.end > data.len() {
                break;
            }
            at = payload.end;
            if ids.contains(id) && !payload.is_empty() {
                mask.push(payload);
            }
        }
    }
    mask
}

/// The header encryption key k_he and salting key k_hs of one master key (RFC 6904 section 3).
pub(crate) struct HeaderExtensionKeys {
    /// AES-CM keyed with k_he; `None` for the NULL cipher, whose header keystream is all zero
    /// (RFC 6904 section 3.2).
    cipher: Option<Box<dyn StreamCipher>>,
    /// k_hs.
    salt: SecretVec,
}

impl HeaderExtensionKeys {
    /// Derives k_he (label 0x06, the length of the payload encryption key) and k_hs (label
    /// 0x07, the length of the session salt) with the session's PRF, master key, master salt
    /// and `index DIV kdr`.
    ///
    /// The keystream transform is the payload's for the AES-CM profiles. The AEAD profiles use
    /// AES-CM of their key size (RFC 7714 section 8.3), with their 96-bit k_hs padded with zeros
    /// on the right as their master salt is in the key derivation.
    pub(crate) fn derive(
        crypto: &dyn RTCCrypto,
        prf: Prf,
        null_cipher: bool,
        master_key: &[u8],
        master_salt: &[u8],
        index_over_kdr: u64,
    ) -> Result<Self> {
        let cipher = if null_cipher {
            None
        } else {
            let key = derive(
                crypto,
                prf,
                LABEL_SRTP_HEADER_ENCRYPTION,
                master_key,
                master_salt,
                index_over_kdr,
                prf.key_len(),
            )?;
            Some(new_aes_cm(crypto, prf.stream_cipher(), key.as_ref())?)
        };
        let salt = derive(
            crypto,
            prf,
            LABEL_SRTP_HEADER_SALT,
            master_key,
            master_salt,
            index_over_kdr,
            master_salt.len(),
        )?;
        Ok(Self { cipher, salt })
    }

    /// No keys: nothing is encrypted. For ciphers built from session keys in tests.
    #[cfg(test)]
    pub(crate) fn none() -> Self {
        Self {
            cipher: None,
            salt: SecretVec::new(Vec::new()),
        }
    }

    /// Encrypts, or decrypts, the payload of the extension elements of `packet` whose ids are
    /// in `ids`, in place. The keystream uses the IV of the packet's payload (RFC 3711 section
    /// 4.1.1) with k_hs in place of k_s, and starts at the first octet of the extension data.
    pub(crate) fn apply(
        &mut self,
        packet: &mut [u8],
        sequence_number: u16,
        roc: u32,
        ssrc: u32,
        ids: &EncryptedHeaderExtensions,
    ) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let Some(cipher) = self.cipher.as_mut() else {
            return Ok(());
        };
        let Some((profile, range)) = extension_data(packet) else {
            return Ok(());
        };
        let data = &mut packet[range];
        let mask = encryption_mask(profile, data, ids);
        let Some(end) = mask.last().map(|range| range.end) else {
            return Ok(());
        };

        // The keystream up to the last encrypted octet; the mask picks the octets it applies to.
        let mut keystream = vec![0u8; end];
        let counter = generate_counter(sequence_number, roc, ssrc, self.salt.as_ref());
        cipher
            .apply_keystream(&counter, &mut keystream)
            .map_err(crypto_error)?;
        for range in mask {
            for at in range {
                data[at] ^= keystream[at];
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::hex;

    fn mask_bytes(profile: u16, data: &[u8], ids: &[u8]) -> Vec<u8> {
        let ids = EncryptedHeaderExtensions::new(ids).unwrap();
        let mut out = vec![0u8; data.len()];
        for range in encryption_mask(profile, data, &ids) {
            out[range].fill(0xFF);
        }
        out
    }

    /// RFC 6904 section 3.1 (figure 2) and Appendix A.2: the mask covers the payloads of
    /// elements 1, 3 and 4 and nothing else.
    #[test]
    fn one_byte_mask_matches_the_rfc_6904_example() {
        let data = hex("17 414273A475262748 22 0000C8 30 8E 46 55996386B395FB 00");
        assert_eq!(
            mask_bytes(0xBEDE, &data, &[1, 3, 4]),
            hex("00 FFFFFFFFFFFFFFFF 00 000000 00 FF 00 FFFFFFFFFFFFFF 00")
        );
        assert_eq!(mask_bytes(0xBEDE, &data, &[]), vec![0; data.len()]);
        assert_eq!(
            mask_bytes(0xBEDE, &data, &[2]),
            hex("00 0000000000000000 00 FFFFFF 00 00 00 00000000000000 00")
        );
    }

    /// RFC 6904 section 3: the mask is built for two-byte headers too; element headers, a
    /// zero-length element and padding are not in it.
    #[test]
    fn two_byte_mask_covers_only_the_selected_payloads() {
        // id 1 len 2 | padding | id 200 len 3 | id 7 len 0 | id 2 len 1 | padding
        let data = hex("01 02 AABB 00 C8 03 CCDDEE 07 00 02 01 FF 00 00 00");
        assert_eq!(
            mask_bytes(0x1000, &data, &[1, 200, 7]),
            hex("00 00 FFFF 00 00 00 FFFFFF 00 00 00 00 00 00 00 00")
        );
        // The appbits do not change the format.
        assert_eq!(
            mask_bytes(0x100F, &data, &[2]),
            hex("00 00 0000 00 00 00 000000 00 00 00 00 FF 00 00 00")
        );
    }

    /// Only RFC 8285 extensions have elements; a profile-specific extension is left alone, and
    /// so is everything from a malformed or reserved element on.
    #[test]
    fn mask_is_empty_for_other_profiles_and_stops_at_malformed_elements() {
        let data = hex("17 414273A475262748 22 0000C8");
        assert_eq!(mask_bytes(0xABCD, &data, &[1, 2]), vec![0; data.len()]);
        // Element 2 announces 16 octets and has 3: nothing from there on.
        let data = hex("10 AA 2F 010203");
        assert_eq!(mask_bytes(0xBEDE, &data, &[1, 2]), hex("00 FF 00 000000"));
        // Id 15 stops the parsing.
        let data = hex("F0 AA 10 BB");
        assert_eq!(mask_bytes(0xBEDE, &data, &[1, 15]), hex("00 00 00 00"));
        // A two-byte element running past the end.
        let data = hex("01 01 AA 02 09 BB");
        assert_eq!(mask_bytes(0x1000, &data, &[1, 2]), hex("00 00 FF 00 00 00"));
    }

    #[test]
    fn id_zero_cannot_be_encrypted() {
        assert!(EncryptedHeaderExtensions::new(&[1, 0]).is_err());
        let set = EncryptedHeaderExtensions::new(&[255, 1, 64, 1]).unwrap();
        assert_eq!(set.ids().collect::<Vec<_>>(), vec![1, 64, 255]);
        assert!(!set.is_empty());
        assert!(EncryptedHeaderExtensions::default().is_empty());
    }

    #[test]
    fn extension_data_is_found_after_the_csrcs() {
        // V=2, X, CC=1.
        let mut packet = vec![0x91, 96, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 9, 9, 9, 9];
        packet.extend_from_slice(&[0xBE, 0xDE, 0x00, 0x01, 0x10, 0xAA, 0x00, 0x00, 0x55]);
        assert_eq!(extension_data(&packet), Some((0xBEDE, 20..24)));
        // No X bit.
        packet[0] = 0x81;
        assert_eq!(extension_data(&packet), None);
        // The announced length runs past the packet.
        packet[0] = 0x91;
        packet[19] = 9;
        assert_eq!(extension_data(&packet), None);
    }
}
