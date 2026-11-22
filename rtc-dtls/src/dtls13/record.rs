//! The DTLS 1.3 record layer (RFC 9147 section 4): the unified header of a protected record,
//! record protection with the sequence number encrypted, the reconstruction of a record
//! number from its truncated form, and the ACK content (section 7).

use super::codec::Reader;
use super::key_schedule::TrafficKeys;
use super::suite::Suite13;
use crypto::{AeadCipher, HEADER_MASK_SAMPLE_LEN, HeaderMask, RTCCrypto};
use shared::error::{Error, Result};

pub(crate) const CONTENT_TYPE_ALERT: u8 = 21;
pub(crate) const CONTENT_TYPE_HANDSHAKE: u8 = 22;
pub(crate) const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;
/// The ACK content type (RFC 9147 section 7).
pub(crate) const CONTENT_TYPE_ACK: u8 = 26;

/// The three bits every unified header starts with (RFC 9147 section 4, figure 3).
pub(crate) const UNIFIED_HEADER_FIXED_BITS: u8 = 0b0010_0000;
const UNIFIED_HEADER_FIXED_MASK: u8 = 0b1110_0000;
/// C: a connection id follows the first byte.
const UNIFIED_HEADER_CID: u8 = 0x10;
/// S: the sequence number is 16 bits, not 8.
const UNIFIED_HEADER_SEQ16: u8 = 0x08;
/// L: a 16-bit length follows the sequence number.
const UNIFIED_HEADER_LENGTH: u8 = 0x04;
/// E: the low two bits of the epoch.
const UNIFIED_HEADER_EPOCH: u8 = 0x03;

/// The most a record carries before protection (RFC 8446 section 5.1).
pub(crate) const MAX_PLAINTEXT: usize = 1 << 14;
/// The most a protected record's encrypted_record may hold (RFC 8446 section 5.2).
pub(crate) const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;
/// The fewest bytes of ciphertext a record has: the sample its sequence number is encrypted
/// with (RFC 9147 section 4.2.3).
pub(crate) const MIN_CIPHERTEXT: usize = HEADER_MASK_SAMPLE_LEN;
/// The highest sequence number a plaintext record carries (RFC 9147 section 4), and, to keep
/// one rule, a protected one: an epoch is rekeyed or the association abandoned long before.
pub(crate) const MAX_SEQUENCE_NUMBER: u64 = (1 << 48) - 1;

/// Whether `first_byte` starts a DTLSCiphertext (RFC 9147 section 4.1): leading bits 001.
pub(crate) fn is_unified_header(first_byte: u8) -> bool {
    first_byte & UNIFIED_HEADER_FIXED_MASK == UNIFIED_HEADER_FIXED_BITS
}

/// A record's place in the association: its epoch and its sequence number in that epoch,
/// both in full (RFC 9147 section 4). ACKs name records by it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RecordNumber {
    pub(crate) epoch: u64,
    pub(crate) sequence: u64,
}

/// How a sender writes the unified header: which optional fields it includes. A receiver
/// takes every combination (RFC 9147 section 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderForm {
    /// S: a 16-bit sequence number rather than an 8-bit one.
    pub(crate) sequence_16: bool,
    /// L: the length is present. Without it the record takes the rest of the datagram, so
    /// only the last record of a datagram may leave it out.
    pub(crate) length: bool,
}

impl HeaderForm {
    /// The form this stack sends: a 16-bit sequence number, which a receiver reconstructs
    /// correctly across more reordering and loss than 8 bits allow, and the length, so that
    /// records can share a datagram.
    pub(crate) const FULL: Self = Self {
        sequence_16: true,
        length: true,
    };

    pub(crate) fn header_len(&self, connection_id_len: usize) -> usize {
        1 + connection_id_len
            + if self.sequence_16 { 2 } else { 1 }
            + if self.length { 2 } else { 0 }
    }
}

/// A unified header as read from a datagram, its sequence number still encrypted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnifiedHeader {
    /// The low two bits of the epoch.
    pub(crate) epoch_bits: u8,
    /// Where the connection id sits in the record, if the C bit is set.
    pub(crate) connection_id: std::ops::Range<usize>,
    /// Where the (encrypted) sequence number sits in the record: one or two bytes.
    pub(crate) sequence: std::ops::Range<usize>,
    /// The header's length: where the encrypted record starts.
    pub(crate) header_len: usize,
    /// The whole record's length, header included.
    pub(crate) record_len: usize,
}

impl UnifiedHeader {
    /// Reads the unified header at the start of `datagram_rest`, which runs to the end of the
    /// datagram. `connection_id_len` is the length of the connection ids this side asked its
    /// peer to send, which a header does not state: zero when none was negotiated.
    ///
    /// # Errors
    ///
    /// Fails for anything that is not a well-formed DTLSCiphertext: the fixed bits, a C bit
    /// that does not match whether a connection id was negotiated (RFC 9147 sections 4, 9),
    /// a length that runs past the datagram or past what a record may hold, and a record
    /// too short to carry the sample its sequence number is encrypted with (section 4.2.3).
    pub(crate) fn parse(datagram_rest: &[u8], connection_id_len: usize) -> Result<Self> {
        let first = *datagram_rest.first().ok_or(Error::ErrBufferTooSmall)?;
        if !is_unified_header(first) {
            return Err(Error::ErrInvalidContentType);
        }
        let has_connection_id = first & UNIFIED_HEADER_CID != 0;
        if has_connection_id != (connection_id_len > 0) {
            return Err(Error::ErrInvalidPacketLength);
        }
        let mut at = 1;
        let connection_id = at..at + connection_id_len;
        at += connection_id_len;
        let sequence_len = if first & UNIFIED_HEADER_SEQ16 != 0 {
            2
        } else {
            1
        };
        let sequence = at..at + sequence_len;
        at += sequence_len;
        let record_len = if first & UNIFIED_HEADER_LENGTH != 0 {
            let length = datagram_rest
                .get(at..at + 2)
                .ok_or(Error::ErrBufferTooSmall)?;
            at += 2;
            at + usize::from(u16::from_be_bytes([length[0], length[1]]))
        } else {
            datagram_rest.len()
        };
        if record_len > datagram_rest.len() || at > record_len {
            return Err(Error::ErrBufferTooSmall);
        }
        let ciphertext_len = record_len - at;
        if !(MIN_CIPHERTEXT..=MAX_CIPHERTEXT).contains(&ciphertext_len) {
            return Err(Error::ErrInvalidPacketLength);
        }
        Ok(Self {
            epoch_bits: first & UNIFIED_HEADER_EPOCH,
            connection_id,
            sequence,
            header_len: at,
            record_len,
        })
    }
}

/// The full sequence number closest to `expected` whose low bits are `truncated`
/// (RFC 9147 section 4.2.2): `expected` is one more than the highest sequence number
/// deprotected so far in the epoch.
pub(crate) fn reconstruct_sequence_number(truncated: u64, bits: u32, expected: u64) -> u64 {
    let window = 1u64 << bits;
    let half = window / 2;
    let mask = window - 1;
    let candidate = (expected & !mask) | (truncated & mask);
    if candidate + half <= expected {
        // Closer above: only the wrap of the low bits separates the two.
        candidate.saturating_add(window)
    } else if candidate > expected.saturating_add(half) && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

/// The keys that protect one direction of one epoch.
pub(crate) struct RecordKeys {
    aead: Box<dyn AeadCipher>,
    iv: [u8; 12],
    mask: Box<dyn HeaderMask>,
    tag_len: usize,
}

impl Drop for RecordKeys {
    fn drop(&mut self) {
        // The AEAD and mask keys are the provider's to clear; the IV is ours.
        drop(crypto::SecretVec::new(self.iv.to_vec()));
        self.iv = [0; 12];
    }
}

impl RecordKeys {
    pub(crate) fn new(crypto: &dyn RTCCrypto, suite: Suite13, keys: &TrafficKeys) -> Result<Self> {
        let crypto_error = |error: crypto::CryptoError| Error::Crypto(error.to_string());
        let aead = crypto
            .new_aead(suite.aead(), keys.key.as_ref())
            .map_err(crypto_error)?;
        let mask = crypto
            .new_header_mask(suite.header_mask(), keys.sequence_number_key.as_ref())
            .map_err(crypto_error)?;
        let mut iv = [0u8; 12];
        if keys.iv.len() != iv.len() {
            return Err(Error::ErrInvalidPacketLength);
        }
        iv.copy_from_slice(keys.iv.as_ref());
        Ok(Self {
            aead,
            iv,
            mask,
            tag_len: suite.tag_len(),
        })
    }

    pub(crate) fn tag_len(&self) -> usize {
        self.tag_len
    }

    /// The per-record nonce (RFC 8446 section 5.3): the 64-bit sequence number, padded on the
    /// left to the IV's length, XORed with the IV. The epoch is not part of it (RFC 9147
    /// section 4): each epoch has its own keys.
    fn nonce(&self, sequence: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        for (byte, sequence_byte) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
            *byte ^= sequence_byte;
        }
        nonce
    }

    /// XORs the sequence number in `record`'s header with the mask of the record's first 16
    /// bytes of ciphertext (RFC 9147 section 4.2.3): encrypts it, or decrypts it.
    fn mask_sequence_number(
        &mut self,
        record: &mut [u8],
        sequence: std::ops::Range<usize>,
        header_len: usize,
    ) -> Result<()> {
        let sample: [u8; HEADER_MASK_SAMPLE_LEN] = record
            .get(header_len..header_len + HEADER_MASK_SAMPLE_LEN)
            .and_then(|sample| sample.try_into().ok())
            .ok_or(Error::ErrInvalidPacketLength)?;
        let mask = self
            .mask
            .mask(&sample)
            .map_err(|error| Error::Crypto(error.to_string()))?;
        for (byte, mask_byte) in record[sequence].iter_mut().zip(mask) {
            *byte ^= mask_byte;
        }
        Ok(())
    }

    /// Protects one record: a DTLSCiphertext holding `content` of `content_type`.
    ///
    /// `padding` zero bytes follow the content type inside the protection; more are added
    /// when the ciphertext would otherwise be shorter than the 16 bytes sequence number
    /// encryption samples (RFC 9147 section 4.2.3).
    ///
    /// # Errors
    ///
    /// Fails when `content` is longer than a record may carry.
    pub(crate) fn seal(
        &mut self,
        number: RecordNumber,
        connection_id: &[u8],
        form: HeaderForm,
        content_type: u8,
        content: &[u8],
        padding: usize,
    ) -> Result<Vec<u8>> {
        if content.len() > MAX_PLAINTEXT {
            return Err(Error::ErrRecordOverflow);
        }
        if number.sequence > MAX_SEQUENCE_NUMBER {
            return Err(Error::ErrSequenceNumberOverflow);
        }
        let mut inner_len = content.len() + 1 + padding;
        inner_len = inner_len.max(MIN_CIPHERTEXT.saturating_sub(self.tag_len));
        // RFC 8446 section 5.4: content, type and padding together stay within 2^14 + 1.
        inner_len = inner_len.min(MAX_PLAINTEXT + 1).max(content.len() + 1);
        let ciphertext_len = inner_len + self.tag_len;

        let header_len = form.header_len(connection_id.len());
        let mut record = Vec::with_capacity(header_len + ciphertext_len);
        let mut first = UNIFIED_HEADER_FIXED_BITS | (number.epoch as u8 & UNIFIED_HEADER_EPOCH);
        if !connection_id.is_empty() {
            first |= UNIFIED_HEADER_CID;
        }
        if form.sequence_16 {
            first |= UNIFIED_HEADER_SEQ16;
        }
        if form.length {
            first |= UNIFIED_HEADER_LENGTH;
        }
        record.push(first);
        record.extend_from_slice(connection_id);
        let sequence_at = record.len();
        if form.sequence_16 {
            record.extend_from_slice(&(number.sequence as u16).to_be_bytes());
        } else {
            record.push(number.sequence as u8);
        }
        let sequence = sequence_at..record.len();
        if form.length {
            record.extend_from_slice(&(ciphertext_len as u16).to_be_bytes());
        }
        debug_assert_eq!(record.len(), header_len);

        // The additional data is the header as written so far, before the sequence number is
        // encrypted (RFC 9147 section 4).
        let additional_data = record.clone();
        record.extend_from_slice(content);
        record.push(content_type);
        record.resize(header_len + inner_len, 0);
        let mut tag = vec![0u8; self.tag_len];
        let nonce = self.nonce(number.sequence);
        self.aead
            .seal_in_place(
                &nonce,
                &additional_data,
                &mut record[header_len..],
                &mut tag,
            )
            .map_err(|error| Error::Crypto(error.to_string()))?;
        record.extend_from_slice(&tag);

        self.mask_sequence_number(&mut record, sequence, header_len)?;
        Ok(record)
    }

    /// Removes the protection of the record `record` (exactly one record, whose header is
    /// `header`). `expected_sequence` is one more than the highest sequence number
    /// deprotected in this epoch so far; the record's own is reconstructed from it.
    ///
    /// Returns the record's full sequence number, its content type and its content.
    ///
    /// # Errors
    ///
    /// `ErrInvalidMac` when the record does not authenticate. A record that authenticates
    /// and is nonetheless malformed gives the error that names the alert RFC 8446 section
    /// 5.4 asks for: `ErrRecordOverflow` for more than 2^14 bytes of content, and
    /// `ErrInvalidContentType` for one that is all padding.
    pub(crate) fn open(
        &mut self,
        header: &UnifiedHeader,
        record: &[u8],
        expected_sequence: u64,
    ) -> Result<(u64, u8, Vec<u8>)> {
        let mut record = record.to_vec();
        self.mask_sequence_number(&mut record, header.sequence.clone(), header.header_len)?;
        let (truncated, bits) = match &record[header.sequence.clone()] {
            [low] => (u64::from(*low), 8),
            [high, low] => (u64::from(u16::from_be_bytes([*high, *low])), 16),
            _ => return Err(Error::ErrInvalidPacketLength),
        };
        let sequence = reconstruct_sequence_number(truncated, bits, expected_sequence);

        let (additional_data, protected) = record.split_at_mut(header.header_len);
        if protected.len() < self.tag_len {
            return Err(Error::ErrInvalidPacketLength);
        }
        let (ciphertext, tag) = protected.split_at_mut(protected.len() - self.tag_len);
        let nonce = self.nonce(sequence);
        self.aead
            .open_in_place(&nonce, additional_data, ciphertext, tag)
            .map_err(|_| Error::ErrInvalidMac)?;

        // DTLSInnerPlaintext: content, the type, then zeros (RFC 8446 section 5.4).
        let Some(type_at) = ciphertext.iter().rposition(|byte| *byte != 0) else {
            return Err(Error::ErrInvalidContentType);
        };
        if type_at > MAX_PLAINTEXT {
            return Err(Error::ErrRecordOverflow);
        }
        Ok((
            sequence,
            ciphertext[type_at],
            ciphertext[..type_at].to_vec(),
        ))
    }
}

/// The content of an ACK record (RFC 9147 section 7): the records being acknowledged.
pub(crate) fn encode_ack(record_numbers: &[RecordNumber]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 16 * record_numbers.len());
    out.extend_from_slice(&((16 * record_numbers.len()) as u16).to_be_bytes());
    for number in record_numbers {
        out.extend_from_slice(&number.epoch.to_be_bytes());
        out.extend_from_slice(&number.sequence.to_be_bytes());
    }
    out
}

/// The most record numbers one ACK holds (its vector's length is 16 bits).
pub(crate) const MAX_ACK_RECORD_NUMBERS: usize = (u16::MAX as usize) / 16;

/// Reads the content of an ACK record.
///
/// # Errors
///
/// Fails if the vector is truncated, is not a whole number of record numbers, or is followed
/// by anything.
pub(crate) fn decode_ack(content: &[u8]) -> Result<Vec<RecordNumber>> {
    let mut reader = Reader::new(content);
    let mut numbers = Reader::new(reader.vec16()?);
    reader.finish()?;
    if numbers.remaining() % 16 != 0 {
        return Err(Error::ErrLengthMismatch);
    }
    let mut record_numbers = Vec::with_capacity(numbers.remaining() / 16);
    while !numbers.is_empty() {
        record_numbers.push(RecordNumber {
            epoch: numbers.u64()?,
            sequence: numbers.u64()?,
        });
    }
    Ok(record_numbers)
}

/// The 13-byte header of a DTLSPlaintext record (RFC 9147 section 4): what DTLS 1.2 used,
/// the version always {254, 253}.
pub(crate) const PLAINTEXT_HEADER_LEN: usize = 13;

/// Writes a DTLSPlaintext record.
pub(crate) fn plaintext_record(content_type: u8, sequence: u64, fragment: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(PLAINTEXT_HEADER_LEN + fragment.len());
    record.extend_from_slice(&[content_type, 254, 253, 0, 0]);
    record.extend_from_slice(&sequence.to_be_bytes()[2..]);
    record.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
    record.extend_from_slice(fragment);
    record
}

/// One record cut from a datagram.
pub(crate) enum DatagramRecord<'a> {
    /// A DTLSPlaintext record: content type, 48-bit sequence number and fragment. Its epoch
    /// field is zero and its version is ignored (RFC 9147 section 4).
    Plaintext {
        content_type: u8,
        sequence: u64,
        fragment: &'a [u8],
    },
    /// A DTLSCiphertext record, still protected.
    Ciphertext {
        header: UnifiedHeader,
        record: &'a [u8],
    },
}

/// Cuts the next record off the front of `datagram_rest` (RFC 9147 section 4.1): by its
/// first byte a plaintext alert, handshake or ACK record, or a protected one. Returns it and
/// how many bytes it took.
///
/// # Errors
///
/// Fails for anything else, and for a record that does not fit the datagram; what follows in
/// the datagram cannot be delimited then and goes with it.
pub(crate) fn next_record(
    datagram_rest: &[u8],
    connection_id_len: usize,
) -> Result<(DatagramRecord<'_>, usize)> {
    let first = *datagram_rest.first().ok_or(Error::ErrBufferTooSmall)?;
    match first {
        CONTENT_TYPE_ALERT | CONTENT_TYPE_HANDSHAKE | CONTENT_TYPE_ACK => {
            let header = datagram_rest
                .get(..PLAINTEXT_HEADER_LEN)
                .ok_or(Error::ErrBufferTooSmall)?;
            // A plaintext record is an epoch-0 record; anything else under these content
            // types is a DTLS 1.2 protected record, which this association does not have.
            if header[3..5] != [0, 0] {
                return Err(Error::ErrInvalidPacketLength);
            }
            let mut sequence = [0u8; 8];
            sequence[2..].copy_from_slice(&header[5..11]);
            let length = usize::from(u16::from_be_bytes([header[11], header[12]]));
            if length > MAX_PLAINTEXT {
                return Err(Error::ErrInvalidPacketLength);
            }
            let fragment = datagram_rest
                .get(PLAINTEXT_HEADER_LEN..PLAINTEXT_HEADER_LEN + length)
                .ok_or(Error::ErrBufferTooSmall)?;
            Ok((
                DatagramRecord::Plaintext {
                    content_type: first,
                    sequence: u64::from_be_bytes(sequence),
                    fragment,
                },
                PLAINTEXT_HEADER_LEN + length,
            ))
        }
        _ if is_unified_header(first) => {
            let header = UnifiedHeader::parse(datagram_rest, connection_id_len)?;
            let record_len = header.record_len;
            Ok((
                DatagramRecord::Ciphertext {
                    header,
                    record: &datagram_rest[..record_len],
                },
                record_len,
            ))
        }
        _ => Err(Error::ErrInvalidContentType),
    }
}
