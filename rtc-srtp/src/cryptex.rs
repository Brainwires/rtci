//! Cryptex ([RFC 9335]): encryption of the CSRCs and RTP header extensions.
//!
//! When both ends signalled `a=cryptex`, a sender may protect a packet's CSRC list and its
//! [RFC 8285] header extensions (all but the 4-byte extension header) together with the
//! payload. Such a packet is marked by the extension's "defined by profile" field: `0xC0DE`
//! instead of `0xBEDE` (one-byte extensions) and `0xC2DE` instead of `0x1000` (two-byte
//! extensions). A [`Context`](crate::context::Context) applies it once its [`Cryptex`]
//! settings say so; a receiving context always decrypts a packet so marked.
//!
//! [RFC 9335]: https://www.rfc-editor.org/rfc/rfc9335
//! [RFC 8285]: https://www.rfc-editor.org/rfc/rfc8285

/// The fixed part of an RTP header (RFC 3550 section 5.1).
pub(crate) const RTP_FIXED_HEADER_LEN: usize = 12;
/// RFC 8285 one-byte header extensions.
pub(crate) const PROFILE_ONE_BYTE: u16 = 0xBEDE;
/// RFC 8285 two-byte header extensions (with zero "appbits").
pub(crate) const PROFILE_TWO_BYTE: u16 = 0x1000;
/// RFC 9335 section 5: encrypted one-byte header extensions.
pub(crate) const PROFILE_CRYPTEX_ONE_BYTE: u16 = 0xC0DE;
/// RFC 9335 section 5: encrypted two-byte header extensions.
pub(crate) const PROFILE_CRYPTEX_TWO_BYTE: u16 = 0xC2DE;

/// How a [`Context`](crate::context::Context) uses Cryptex (RFC 9335).
///
/// The default uses none of it: packets are protected as RFC 3711 has it, and a received
/// packet marked as Cryptex is still decrypted as one.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Cryptex {
    /// Protect outgoing packets that carry CSRCs or RFC 8285 header extensions with Cryptex.
    /// Set it only once the peer has signalled that it receives Cryptex (`a=cryptex`).
    pub send: bool,
    /// Cryptex is mandatory (RFC 9335 section 5.2): refuse received packets that carry CSRCs
    /// or header extensions without it, and refuse to protect a packet that has CSRCs or a
    /// header extension and would leave without it (`send` unset, or an extension Cryptex
    /// does not apply to).
    pub require: bool,
}

/// Where the encrypted parts of an RTP packet are: the CSRC list runs from the fixed header
/// to `csrc_end`, the 4-byte extension header starts at `csrc_end`, and the extension data
/// and payload follow it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CryptexLayout {
    pub(crate) csrc_end: usize,
}

impl CryptexLayout {
    /// The length of the CSRC list.
    pub(crate) fn csrc_len(&self) -> usize {
        self.csrc_end - RTP_FIXED_HEADER_LEN
    }

    /// Where the extension data (the part after the 4-byte extension header) starts.
    pub(crate) fn ext_data_start(&self) -> usize {
        self.csrc_end + 4
    }

    /// The cipher's plaintext or ciphertext (RFC 9335 section 6.2): the CSRCs, then the
    /// extension data, the payload and the padding, as one contiguous buffer.
    pub(crate) fn gather(&self, packet: &[u8]) -> Vec<u8> {
        let mut region = Vec::with_capacity(packet.len().saturating_sub(16));
        region.extend_from_slice(&packet[RTP_FIXED_HEADER_LEN..self.csrc_end]);
        region.extend_from_slice(&packet[self.ext_data_start()..]);
        region
    }

    /// Puts a buffer [`gather`](Self::gather) made back into the packet's layout.
    pub(crate) fn scatter(&self, packet: &mut [u8], region: &[u8]) {
        let csrc_len = self.csrc_len();
        packet[RTP_FIXED_HEADER_LEN..self.csrc_end].copy_from_slice(&region[..csrc_len]);
        let start = self.ext_data_start();
        packet[start..].copy_from_slice(&region[csrc_len..]);
    }

    /// The AEAD's associated data (RFC 9335 section 6.2): the fixed header and the
    /// extension header, which aren't contiguous when there are CSRCs.
    pub(crate) fn associated_data(&self, packet: &[u8]) -> [u8; 16] {
        let mut aad = [0u8; 16];
        aad[..RTP_FIXED_HEADER_LEN].copy_from_slice(&packet[..RTP_FIXED_HEADER_LEN]);
        aad[RTP_FIXED_HEADER_LEN..].copy_from_slice(&packet[self.csrc_end..self.csrc_end + 4]);
        aad
    }
}

/// The CSRC count, the X bit and the end of the CSRC list of a raw RTP packet, or `None`
/// when the packet is too short to hold them.
fn csrc_end_of(packet: &[u8]) -> Option<(bool, usize)> {
    let first = *packet.first()?;
    let extension = first & 0x10 != 0;
    let csrc_count = (first & 0x0F) as usize;
    let csrc_end = RTP_FIXED_HEADER_LEN + 4 * csrc_count;
    (packet.len() >= csrc_end).then_some((extension, csrc_end))
}

fn profile_at(packet: &[u8], at: usize) -> Option<u16> {
    let bytes = packet.get(at..at + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// RFC 9335 section 5.1: the packet a sender encrypts with Cryptex, or `None` when Cryptex
/// doesn't apply to it (no CSRCs and no header extension, an extension other than RFC 8285's,
/// two-byte extensions with non-zero "appbits", or a packet too short to parse). The
/// extension's profile is replaced by its Cryptex counterpart, and a packet with CSRCs but
/// no extension gets an empty `0xC0DE` one (the X bit set).
pub(crate) fn sender_packet(packet: &[u8]) -> Option<(Vec<u8>, CryptexLayout)> {
    let (extension, csrc_end) = csrc_end_of(packet)?;
    let layout = CryptexLayout { csrc_end };
    if extension {
        let replacement = match profile_at(packet, csrc_end)? {
            PROFILE_ONE_BYTE => PROFILE_CRYPTEX_ONE_BYTE,
            PROFILE_TWO_BYTE => PROFILE_CRYPTEX_TWO_BYTE,
            _ => return None,
        };
        if packet.len() < layout.ext_data_start() {
            return None;
        }
        let mut out = packet.to_vec();
        out[csrc_end..csrc_end + 2].copy_from_slice(&replacement.to_be_bytes());
        Some((out, layout))
    } else if csrc_end > RTP_FIXED_HEADER_LEN {
        let mut out = Vec::with_capacity(packet.len() + 4);
        out.extend_from_slice(&packet[..csrc_end]);
        out.extend_from_slice(&PROFILE_CRYPTEX_ONE_BYTE.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&packet[csrc_end..]);
        out[0] |= 0x10;
        Some((out, layout))
    } else {
        None
    }
}

/// Whether a raw RTP packet has anything Cryptex is there to protect: a CSRC list or a header
/// extension, of whatever kind.
pub(crate) fn carries_csrcs_or_extension(packet: &[u8]) -> bool {
    packet.first().is_some_and(|first| first & 0x1F != 0)
}

/// What a receiver makes of a protected packet's header (RFC 9335 section 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Received {
    /// Marked as Cryptex: decrypt with this layout.
    Cryptex(CryptexLayout),
    /// Carries CSRCs or a header extension in the clear.
    Clear,
    /// Carries neither: Cryptex has nothing to protect.
    Bare,
}

pub(crate) fn received(packet: &[u8]) -> Received {
    let Some((extension, csrc_end)) = csrc_end_of(packet) else {
        return Received::Bare;
    };
    if extension {
        match profile_at(packet, csrc_end) {
            Some(PROFILE_CRYPTEX_ONE_BYTE | PROFILE_CRYPTEX_TWO_BYTE)
                if packet.len() >= csrc_end + 4 =>
            {
                Received::Cryptex(CryptexLayout { csrc_end })
            }
            _ => Received::Clear,
        }
    } else if csrc_end > RTP_FIXED_HEADER_LEN {
        Received::Clear
    } else {
        Received::Bare
    }
}

/// After decryption: the extension's profile back to its RFC 8285 value, so the header
/// extensions parse as usual (RFC 9335 section 6.3).
pub(crate) fn restore_profile(packet: &mut [u8], layout: CryptexLayout) {
    let at = layout.csrc_end;
    let restored = match profile_at(packet, at) {
        Some(PROFILE_CRYPTEX_ONE_BYTE) => PROFILE_ONE_BYTE,
        Some(PROFILE_CRYPTEX_TWO_BYTE) => PROFILE_TWO_BYTE,
        _ => return,
    };
    packet[at..at + 2].copy_from_slice(&restored.to_be_bytes());
}
