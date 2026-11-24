use crate::error::{Error, Result};

/// The longest SFrame header: the config byte, an 8-byte KID and an 8-byte CTR.
pub const MAX_HEADER_LEN: usize = 17;

const EXTENDED_KID: u8 = 0x80;
const EXTENDED_CTR: u8 = 0x08;

/// An SFrame header (RFC 9605 section 4.3): the key id that selects the key and the counter
/// the nonce is built from.
///
/// ```text
///  0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+------------+------------+
/// |X|  K  |Y|  C  |   KID...   |   CTR...   |
/// +-+-+-+-+-+-+-+-+------------+------------+
/// ```
///
/// A value below 8 is carried in the config byte (`K` or `C`, with `X` or `Y` clear). A larger
/// one follows the config byte as a big-endian integer in the fewest bytes that hold it, and
/// the field holds that length minus one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Header {
    /// The key id (KID).
    pub kid: u64,
    /// The counter (CTR).
    pub ctr: u64,
}

/// The number of bytes a value takes after the config byte: none below 8, else its shortest
/// big-endian form.
const fn extension_len(value: u64) -> usize {
    if value < 8 {
        0
    } else {
        8 - (value.leading_zeros() as usize) / 8
    }
}

/// The config-byte nibble of a value: the value itself below 8, else the extended flag and the
/// length minus one.
const fn nibble(value: u64) -> u8 {
    if value < 8 {
        value as u8
    } else {
        0x08 | (extension_len(value) as u8 - 1)
    }
}

impl Header {
    /// A header with these values.
    #[must_use]
    pub const fn new(kid: u64, ctr: u64) -> Self {
        Self { kid, ctr }
    }

    /// The length in bytes of this header's encoding: 1 to 17.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        1 + extension_len(self.kid) + extension_len(self.ctr)
    }

    /// Writes the header's (minimal) encoding at the start of `out` and returns its length.
    pub fn encode(&self, out: &mut [u8; MAX_HEADER_LEN]) -> usize {
        let kid_len = extension_len(self.kid);
        let ctr_len = extension_len(self.ctr);
        out[0] = (nibble(self.kid) << 4) | nibble(self.ctr);
        out[1..1 + kid_len].copy_from_slice(&self.kid.to_be_bytes()[8 - kid_len..]);
        out[1 + kid_len..1 + kid_len + ctr_len]
            .copy_from_slice(&self.ctr.to_be_bytes()[8 - ctr_len..]);
        1 + kid_len + ctr_len
    }

    /// Appends the header's encoding to `out`.
    pub fn encode_to(&self, out: &mut Vec<u8>) {
        let mut buffer = [0; MAX_HEADER_LEN];
        let len = self.encode(&mut buffer);
        out.extend_from_slice(&buffer[..len]);
    }

    /// Parses the header at the start of `data`. Returns it with the number of bytes it takes;
    /// the rest of `data` is the AEAD output.
    ///
    /// A value that is not in its shortest form is refused with
    /// [`Error::NonMinimalHeader`]: RFC 9605 requires the shortest form of a sender, so a
    /// conforming one never produces anything else. [`decode_lenient`](Self::decode_lenient)
    /// accepts such headers.
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        let (header, len, minimal) = Self::parse(data)?;
        if minimal {
            Ok((header, len))
        } else {
            Err(Error::NonMinimalHeader)
        }
    }

    /// Parses the header at the start of `data`, also when a KID or CTR is longer than it needs
    /// to be (an extended value below 8, or leading zero bytes).
    ///
    /// Decryption authenticates the header bytes as they were received, so a re-encoded header
    /// never validates; accepting the longer forms only admits a sender that does not follow
    /// the encoding rule.
    pub fn decode_lenient(data: &[u8]) -> Result<(Self, usize)> {
        let (header, len, _) = Self::parse(data)?;
        Ok((header, len))
    }

    fn parse(data: &[u8]) -> Result<(Self, usize, bool)> {
        let Some((&config, rest)) = data.split_first() else {
            return Err(Error::TruncatedHeader);
        };
        let (kid, kid_len) = field(config & EXTENDED_KID != 0, (config >> 4) & 0x07, rest)?;
        let (ctr, ctr_len) = field(config & EXTENDED_CTR != 0, config & 0x07, &rest[kid_len..])?;
        let minimal = extension_len(kid) == kid_len && extension_len(ctr) == ctr_len;
        Ok((Self { kid, ctr }, 1 + kid_len + ctr_len, minimal))
    }
}

/// One KID or CTR: inline in `bits` when not `extended`, else `bits + 1` bytes of `rest`.
/// Returns the value and how many bytes of `rest` it took.
fn field(extended: bool, bits: u8, rest: &[u8]) -> Result<(u64, usize)> {
    if !extended {
        return Ok((u64::from(bits), 0));
    }
    let len = usize::from(bits) + 1;
    let Some(bytes) = rest.get(..len) else {
        return Err(Error::TruncatedHeader);
    };
    let mut value = [0; 8];
    value[8 - len..].copy_from_slice(bytes);
    Ok((u64::from_be_bytes(value), len))
}
