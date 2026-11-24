//! Wrap-safe extension of RTP sequence numbers, timestamps and picture ids (RFC 3550 A.1).

/// Extends values of a counter `bits` wide that wraps to a monotonic `i64`, by taking each new
/// value as the one nearest to the last one returned.
#[derive(Debug, Clone, Copy)]
pub struct Unwrapper {
    bits: u32,
    last: Option<i64>,
}

impl Unwrapper {
    /// An unwrapper for a counter `bits` wide (1 to 32).
    pub fn new(bits: u32) -> Self {
        assert!((1..=32).contains(&bits), "a counter is 1 to 32 bits wide");
        Self { bits, last: None }
    }

    /// For 16-bit RTP sequence numbers.
    pub fn sequence() -> Self {
        Self::new(16)
    }

    /// For 32-bit RTP timestamps.
    pub fn timestamp() -> Self {
        Self::new(32)
    }

    fn modulus(&self) -> i64 {
        1i64 << self.bits
    }

    /// The extended value of `value` without remembering it.
    pub fn peek(&self, value: u32) -> i64 {
        let m = self.modulus();
        let value = i64::from(value) & (m - 1);
        let Some(last) = self.last else {
            return value;
        };
        let last_low = last.rem_euclid(m);
        let mut diff = value - last_low;
        if diff > m / 2 {
            diff -= m;
        } else if diff < -(m / 2) {
            diff += m;
        }
        last + diff
    }

    /// The extended value of `value`; it becomes the reference for the next one.
    pub fn unwrap(&mut self, value: u32) -> i64 {
        let v = self.peek(value);
        self.last = Some(v);
        v
    }

    /// Whether a value has been seen.
    pub fn is_started(&self) -> bool {
        self.last.is_some()
    }

    /// Forgets the reference.
    pub fn reset(&mut self) {
        self.last = None;
    }
}

/// Whether 16-bit sequence number `a` is after `b` (RFC 1982 serial number arithmetic).
pub fn seq_ahead(a: u16, b: u16) -> bool {
    a != b && a.wrapping_sub(b) < 0x8000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_numbers_extend_across_the_wrap_both_ways() {
        let mut u = Unwrapper::sequence();
        assert_eq!(u.unwrap(65_534), 65_534);
        assert_eq!(u.unwrap(65_535), 65_535);
        assert_eq!(u.unwrap(0), 65_536);
        assert_eq!(u.unwrap(3), 65_539);
        // A reordered packet from before the wrap.
        assert_eq!(u.unwrap(65_533), 65_533);
        assert_eq!(u.peek(10), 65_546);
    }

    #[test]
    fn a_seven_bit_picture_id_wraps_at_128() {
        let mut u = Unwrapper::new(7);
        assert_eq!(u.unwrap(126), 126);
        assert_eq!(u.unwrap(1), 129);
        assert_eq!(u.unwrap(127), 127);
    }

    #[test]
    fn serial_order_of_sequence_numbers() {
        assert!(seq_ahead(1, 65_535));
        assert!(!seq_ahead(65_535, 1));
        assert!(!seq_ahead(5, 5));
    }
}
