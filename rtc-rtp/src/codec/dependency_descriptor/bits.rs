//! The bit-level descriptors of the Dependency Descriptor syntax (AV1 RTP specification A.8.2):
//! `f(n)`, an unsigned number of n bits, most significant first, and `ns(n)`, the
//! non-symmetric encoding of a value in `0..n`.

use shared::error::{Error, Result};

/// Reads `f(n)` and `ns(n)` values from a byte slice.
pub(super) struct BitReader<'a> {
    data: &'a [u8],
    /// Bits consumed so far.
    pos: usize,
}

impl<'a> BitReader<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// `f(n)` for `n` up to 32.
    ///
    /// # Errors
    ///
    /// The data ends before `n` more bits.
    pub(super) fn f(&mut self, n: usize) -> Result<u32> {
        debug_assert!(n <= 32);
        if n > self.data.len() * 8 - self.pos {
            return Err(Error::ErrShortPacket);
        }
        let mut x = 0u32;
        for _ in 0..n {
            let bit = (self.data[self.pos / 8] >> (7 - self.pos % 8)) & 1;
            x = (x << 1) | bit as u32;
            self.pos += 1;
        }
        Ok(x)
    }

    /// One bit as a flag.
    pub(super) fn flag(&mut self) -> Result<bool> {
        Ok(self.f(1)? == 1)
    }

    /// `ns(n)`: a value in `0..n`, for `n` from 1 to 2^31.
    pub(super) fn ns(&mut self, n: u32) -> Result<u32> {
        let w = ns_width(n);
        let m = (1u32 << w) - n;
        let v = self.f(w as usize - 1)?;
        if v < m {
            return Ok(v);
        }
        let extra_bit = self.f(1)?;
        Ok((v << 1) - m + extra_bit)
    }
}

/// The `w` of `ns(n)`: the number of bits of `n`.
fn ns_width(n: u32) -> u32 {
    debug_assert!(n >= 1);
    32 - n.leading_zeros()
}

/// Writes `f(n)` and `ns(n)` values; the unused bits of the last byte are 0.
#[derive(Default)]
pub(super) struct BitWriter {
    data: Vec<u8>,
    /// Bits written so far.
    pos: usize,
}

impl BitWriter {
    /// `write_f(n, v)`: the low `n` bits of `v`, most significant first.
    pub(super) fn f(&mut self, n: usize, v: u32) {
        debug_assert!(n <= 32 && (n == 32 || v >> n == 0));
        for i in (0..n).rev() {
            if self.pos == self.data.len() * 8 {
                self.data.push(0);
            }
            let bit = ((v >> i) & 1) as u8;
            *self.data.last_mut().expect("a byte was pushed") |= bit << (7 - self.pos % 8);
            self.pos += 1;
        }
    }

    pub(super) fn flag(&mut self, v: bool) {
        self.f(1, v as u32);
    }

    /// `write_ns(n, v)` for `v` in `0..n`.
    pub(super) fn ns(&mut self, n: u32, v: u32) {
        debug_assert!(v < n);
        if n == 1 {
            return;
        }
        let w = ns_width(n);
        let m = (1u32 << w) - n;
        if v < m {
            self.f(w as usize - 1, v);
        } else {
            self.f(w as usize, v + m);
        }
    }

    /// The bytes written, the last one padded with zero bits.
    pub(super) fn finish(self) -> Vec<u8> {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AV1 RTP A.8.2, the table for `ns(5)`: 0 is `00`, 1 is `01`, 2 is `10`, 3 is `110`,
    /// 4 is `111`.
    #[test]
    fn ns_5_matches_the_specifications_table() {
        let table: [(u32, &[u32]); 5] = [
            (0, &[0, 0]),
            (1, &[0, 1]),
            (2, &[1, 0]),
            (3, &[1, 1, 0]),
            (4, &[1, 1, 1]),
        ];
        for (value, bits) in table {
            let mut writer = BitWriter::default();
            writer.ns(5, value);
            assert_eq!(writer.pos, bits.len(), "ns(5) of {value}");
            let bytes = writer.finish();
            let mut reader = BitReader::new(&bytes);
            for bit in bits {
                assert_eq!(reader.f(1).unwrap(), *bit, "ns(5) of {value}");
            }
            assert_eq!(BitReader::new(&bytes).ns(5).unwrap(), value);
        }
    }

    /// Every value of every range a descriptor can use (`ns(DtCnt + 1)`, `ns(chain_cnt)`)
    /// reads back, and `ns(1)` takes no bits.
    #[test]
    fn ns_round_trips() {
        for n in 1..=33u32 {
            for v in 0..n {
                let mut writer = BitWriter::default();
                writer.ns(n, v);
                writer.f(3, 0b101);
                let bits = writer.pos;
                let bytes = writer.finish();
                let mut reader = BitReader::new(&bytes);
                assert_eq!(reader.ns(n).unwrap(), v, "ns({n}) of {v}");
                assert_eq!(reader.f(3).unwrap(), 0b101);
                assert_eq!(reader.pos, bits);
            }
        }
        let mut writer = BitWriter::default();
        writer.ns(1, 0);
        assert_eq!(writer.pos, 0);
    }

    #[test]
    fn f_reads_most_significant_bit_first_and_stops_at_the_end() {
        let mut reader = BitReader::new(&[0b1010_0000, 0xFF]);
        assert_eq!(reader.f(3).unwrap(), 0b101);
        assert_eq!(reader.f(13).unwrap(), 0xFF);
        assert!(reader.f(1).is_err());
        assert_eq!(BitReader::new(&[]).f(0).unwrap(), 0);
    }
}
