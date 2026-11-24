use bytes::{BufMut, BytesMut};

/// The longest leb128 value (AV1 specification 4.10.5).
pub const MAX_LEB128_SIZE: usize = 8;

/// Reads a leb128 value from the start of `bytes` (AV1 specification 4.10.5) and returns it
/// with the number of bytes it took.
///
/// `None` when there is none to read: the bytes end before a byte without the continuation
/// bit, the value takes more than 8 bytes, or it does not fit 32 bits ("it is a requirement of
/// bitstream conformance that the value returned from the leb128 parsing process is less than
/// or equal to (1 << 32) - 1"). An unterminated value used to read as 0 in 0 bytes, a value of
/// 2^32 or more wrapped, and a ninth byte pushed the first one out.
pub fn read_leb128(bytes: &[u8]) -> Option<(u32, usize)> {
    let mut value: u64 = 0;
    for (i, byte) in bytes.iter().take(MAX_LEB128_SIZE).enumerate() {
        value |= u64::from(byte & 0b_0111_1111) << (7 * i);
        if byte & 0b_1000_0000 == 0 {
            return u32::try_from(value).ok().map(|value| (value, i + 1));
        }
    }
    None
}

pub fn leb128_size(value: u32) -> usize {
    let mut size = 0;
    let mut value = value;
    while value >= 0b_1000_0000 {
        size += 1;
        value >>= 7;
    }
    size + 1
}

pub trait BytesMutExt {
    fn put_leb128(&mut self, n: u32);
}

impl BytesMutExt for BytesMut {
    /// Appends `n` to the buffer using unsigned LEB128 variable-length encoding,
    /// as required by the AV1 bitstream/RTP OBU size fields. Each output byte
    /// carries 7 bits of the value in its low bits; bit 7 is a continuation flag
    /// that is set on every byte except the last.
    fn put_leb128(&mut self, mut n: u32) {
        loop {
            let byte = (n & 0b_0111_1111) as u8;
            n >>= 7;
            if n == 0 {
                self.put_u8(byte);
                return;
            }
            self.put_u8(byte | 0b_1000_0000);
        }
    }
}
