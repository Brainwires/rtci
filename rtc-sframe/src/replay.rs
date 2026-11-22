//! Counter-based anti-replay (RFC 9605 section 9.3): the sliding window of RFC 3711 section
//! 3.3.2, on the SFrame CTR. The CTR is 64 bits and never wraps, so there is no rollover to
//! estimate.

/// The window a receiving key gets unless the configuration says otherwise, in counter values.
pub const DEFAULT_REPLAY_WINDOW: usize = 1024;

/// The largest window a key can be given, in counter values (8 KiB of state per key).
pub const MAX_REPLAY_WINDOW: usize = 65_536;

/// Which counters one key has accepted: the highest, and a bitmap of the `size` values up to
/// and including it.
pub(crate) struct ReplayWindow {
    /// One bit per counter value, indexed by `ctr % size`.
    bits: Box<[u64]>,
    /// The highest counter accepted so far, once `started`.
    top: u64,
    started: bool,
}

impl ReplayWindow {
    /// A window of `size` counter values, rounded up to a multiple of 64 and held between 64
    /// and [`MAX_REPLAY_WINDOW`].
    pub(crate) fn new(size: usize) -> Self {
        let words = size.clamp(64, MAX_REPLAY_WINDOW).div_ceil(64);
        Self {
            bits: vec![0u64; words].into_boxed_slice(),
            top: 0,
            started: false,
        }
    }

    fn size(&self) -> u64 {
        self.bits.len() as u64 * 64
    }

    fn slot(&self, ctr: u64) -> (usize, u64) {
        let index = ctr % self.size();
        ((index / 64) as usize, 1u64 << (index % 64))
    }

    /// Whether `ctr` is new: above the highest accepted, or inside the window and not seen.
    pub(crate) fn is_fresh(&self, ctr: u64) -> bool {
        if !self.started || ctr > self.top {
            return true;
        }
        if self.top - ctr >= self.size() {
            return false;
        }
        let (word, bit) = self.slot(ctr);
        self.bits[word] & bit == 0
    }

    /// Records `ctr` as accepted. Call only for an authenticated ciphertext that
    /// [`is_fresh`](Self::is_fresh).
    pub(crate) fn accept(&mut self, ctr: u64) {
        if !self.started {
            self.started = true;
            self.top = ctr;
        } else if ctr > self.top {
            if ctr - self.top >= self.size() {
                self.bits.fill(0);
            } else {
                // The values between the old top and the new one enter the window unseen.
                for skipped in self.top + 1..=ctr {
                    let (word, bit) = self.slot(skipped);
                    self.bits[word] &= !bit;
                }
            }
            self.top = ctr;
        }
        let (word, bit) = self.slot(ctr);
        self.bits[word] |= bit;
    }
}
