//! Readers and writers for the TLS presentation language (RFC 8446 section 3): big-endian
//! integers and vectors with a one-, two- or three-byte length in front.

use shared::error::{Error, Result};

/// Reads a TLS structure from a byte slice. Every read fails, rather than panics, when the
/// slice is too short.
#[derive(Clone)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len()
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.buf)
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.buf.len() < len {
            return Err(Error::ErrBufferTooSmall);
        }
        let (head, tail) = self.buf.split_at(len);
        self.buf = tail;
        Ok(head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn u24(&mut self) -> Result<usize> {
        let b = self.bytes(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize)
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        let b = self.bytes(8)?;
        let mut value = [0u8; 8];
        value.copy_from_slice(b);
        Ok(u64::from_be_bytes(value))
    }

    /// A vector with a one-byte length.
    pub(crate) fn vec8(&mut self) -> Result<&'a [u8]> {
        let len = self.u8()? as usize;
        self.bytes(len)
    }

    /// A vector with a two-byte length.
    pub(crate) fn vec16(&mut self) -> Result<&'a [u8]> {
        let len = self.u16()? as usize;
        self.bytes(len)
    }

    /// A vector with a three-byte length.
    pub(crate) fn vec24(&mut self) -> Result<&'a [u8]> {
        let len = self.u24()?;
        self.bytes(len)
    }

    /// Fails unless everything has been read: a structure with bytes after its last field is
    /// malformed (RFC 8446 section 6: decode_error).
    pub(crate) fn finish(&self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::ErrLengthMismatch)
        }
    }
}

/// Appends a vector with a one-byte length, written by `body`.
pub(crate) fn put_vec8(out: &mut Vec<u8>, body: impl FnOnce(&mut Vec<u8>)) {
    let at = out.len();
    out.push(0);
    body(out);
    let len = out.len() - at - 1;
    debug_assert!(len <= usize::from(u8::MAX));
    out[at] = len as u8;
}

/// Appends a vector with a two-byte length, written by `body`.
pub(crate) fn put_vec16(out: &mut Vec<u8>, body: impl FnOnce(&mut Vec<u8>)) {
    let at = out.len();
    out.extend_from_slice(&[0, 0]);
    body(out);
    let len = out.len() - at - 2;
    debug_assert!(len <= usize::from(u16::MAX));
    out[at..at + 2].copy_from_slice(&(len as u16).to_be_bytes());
}

/// Appends a vector with a three-byte length, written by `body`.
pub(crate) fn put_vec24(out: &mut Vec<u8>, body: impl FnOnce(&mut Vec<u8>)) {
    let at = out.len();
    out.extend_from_slice(&[0, 0, 0]);
    body(out);
    let len = out.len() - at - 3;
    debug_assert!(len < 1 << 24);
    out[at..at + 3].copy_from_slice(&(len as u32).to_be_bytes()[1..]);
}

pub(crate) fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_u24(out: &mut Vec<u8>, value: usize) {
    debug_assert!(value < 1 << 24);
    out.extend_from_slice(&(value as u32).to_be_bytes()[1..]);
}

/// Appends an extension: its type, and its data with a two-byte length.
pub(crate) fn put_extension(
    out: &mut Vec<u8>,
    extension_type: u16,
    body: impl FnOnce(&mut Vec<u8>),
) {
    put_u16(out, extension_type);
    put_vec16(out, body);
}

/// The extensions of a block (`Extension extensions<..2^16-1>` without its length): each type
/// with its data, in order.
///
/// # Errors
///
/// Fails if the block is truncated or holds two extensions of one type (RFC 8446 section 4.2).
pub(crate) fn read_extensions(block: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut reader = Reader::new(block);
    let mut extensions: Vec<(u16, &[u8])> = vec![];
    while !reader.is_empty() {
        let extension_type = reader.u16()?;
        let data = reader.vec16()?;
        if extensions.iter().any(|(seen, _)| *seen == extension_type) {
            return Err(Error::ErrDuplicateExtension);
        }
        extensions.push((extension_type, data));
    }
    Ok(extensions)
}

/// The data of the extension of `extension_type`, if `extensions` has it.
pub(crate) fn find_extension<'a>(
    extensions: &[(u16, &'a [u8])],
    extension_type: u16,
) -> Option<&'a [u8]> {
    extensions
        .iter()
        .find(|(seen, _)| *seen == extension_type)
        .map(|(_, data)| *data)
}
