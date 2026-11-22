//! The KID layouts of the two key-management schemes RFC 9605 describes: sender keys (section
//! 5.1) and MLS (section 5.2).

use crate::error::{Error, Result};

/// The low `bits` bits set; all 64 when `bits` is 64 or more.
const fn mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// `value << bits`, 0 when that shifts everything out.
const fn shl(value: u64, bits: u32) -> u64 {
    if bits >= 64 { 0 } else { value << bits }
}

/// `value >> bits`, 0 when that shifts everything out.
const fn shr(value: u64, bits: u32) -> u64 {
    if bits >= 64 { 0 } else { value >> bits }
}

/// The KID layout of the sender-keys scheme (RFC 9605 section 5.1, Figure 7).
///
/// ```text
///      64-R bits         R bits
///  <---------------> <------------>
/// +-----------------+--------------+
/// | Key Generation  | Ratchet Step |
/// +-----------------+--------------+
/// ```
///
/// `KID = (key_generation << R) + (ratchet_step % (1 << R))`. `R` is set by the application;
/// every receiver of a sender has to know the sender's `R`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SenderKeyIdLayout {
    ratchet_bits: u32,
}

impl SenderKeyIdLayout {
    /// A layout with `ratchet_bits` (`R`) bits of ratchet step: 0 to 64.
    pub fn new(ratchet_bits: u32) -> Result<Self> {
        if ratchet_bits > 64 {
            return Err(Error::KeyIdLayout);
        }
        Ok(Self { ratchet_bits })
    }

    /// `R`: the number of low-order bits that carry the ratchet step.
    #[must_use]
    pub const fn ratchet_bits(&self) -> u32 {
        self.ratchet_bits
    }

    /// The KID of `key_generation` at `ratchet_step`. Only the low `R` bits of the step are
    /// sent; the generation has to fit the remaining `64 - R`.
    pub fn key_id(&self, key_generation: u64, ratchet_step: u64) -> Result<u64> {
        if key_generation > mask(64 - self.ratchet_bits) {
            return Err(Error::KeyIdLayout);
        }
        Ok(self.compose(key_generation, ratchet_step))
    }

    /// The KID of a generation known to fit its field.
    pub(crate) const fn compose(&self, key_generation: u64, ratchet_step: u64) -> u64 {
        shl(key_generation, self.ratchet_bits) | (ratchet_step & mask(self.ratchet_bits))
    }

    /// The key generation and the low `R` bits of the ratchet step a KID carries.
    #[must_use]
    pub const fn split(&self, kid: u64) -> SenderKeyId {
        SenderKeyId {
            key_generation: shr(kid, self.ratchet_bits),
            ratchet_step: kid & mask(self.ratchet_bits),
        }
    }

    /// How many ratchet steps lie from a key at `from_step` to the one a KID with
    /// `ratchet_step` in its low bits names, counting forward modulo `1 << R`.
    #[must_use]
    pub const fn steps_between(&self, from_step: u64, ratchet_step: u64) -> u64 {
        ratchet_step.wrapping_sub(from_step) & mask(self.ratchet_bits)
    }
}

/// The parts of a sender-keys KID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SenderKeyId {
    /// How many keys the sender had distributed before this one.
    pub key_generation: u64,
    /// The low `R` bits of how often the sender has ratcheted this key forward.
    pub ratchet_step: u64,
}

/// The KID layout of an MLS-keyed session (RFC 9605 section 5.2, Figure 8).
///
/// ```text
///   64-S-E bits   S bits   E bits
///  <-----------> <------> <------>
/// +-------------+--------+-------+
/// | Context ID  | Index  | Epoch |
/// +-------------+--------+-------+
/// ```
///
/// `KID = (context << (S + E)) + (sender_index << E) + (epoch % (1 << E))`. `E` is set by the
/// application and bounds how many epochs can be active at once; `S` is the number of bits a
/// member index of the group needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MlsKeyIdLayout {
    epoch_bits: u32,
    sender_bits: u32,
}

impl MlsKeyIdLayout {
    /// A layout with `epoch_bits` (`E`) and `sender_bits` (`S`); together at most 64.
    pub fn new(epoch_bits: u32, sender_bits: u32) -> Result<Self> {
        if epoch_bits > 64 || sender_bits > 64 - epoch_bits {
            return Err(Error::KeyIdLayout);
        }
        Ok(Self {
            epoch_bits,
            sender_bits,
        })
    }

    /// A layout for a group of `group_size` members: `S` is the smallest value such that
    /// `group_size <= (1 << S)`.
    pub fn for_group_size(epoch_bits: u32, group_size: u64) -> Result<Self> {
        let sender_bits = match group_size {
            0 | 1 => 0,
            size => 64 - (size - 1).leading_zeros(),
        };
        Self::new(epoch_bits, sender_bits)
    }

    /// `E`: the number of low-order bits that carry the epoch.
    #[must_use]
    pub const fn epoch_bits(&self) -> u32 {
        self.epoch_bits
    }

    /// `S`: the number of bits that carry the sender's member index.
    #[must_use]
    pub const fn sender_bits(&self) -> u32 {
        self.sender_bits
    }

    /// The number of bits left for the sender's context value: `64 - S - E`.
    #[must_use]
    pub const fn context_bits(&self) -> u32 {
        64 - self.sender_bits - self.epoch_bits
    }

    /// The low `E` bits of `epoch`: what a KID carries of it, and what two epochs must differ
    /// in to be active together.
    #[must_use]
    pub const fn epoch_slot(&self, epoch: u64) -> u64 {
        epoch & mask(self.epoch_bits)
    }

    /// The KID a member at `sender_index` uses in `epoch` for its `context` (0 gives the
    /// shortest KID). The index and the context have to fit their fields.
    pub fn key_id(&self, epoch: u64, sender_index: u64, context: u64) -> Result<u64> {
        if sender_index > mask(self.sender_bits) || context > mask(self.context_bits()) {
            return Err(Error::KeyIdLayout);
        }
        Ok(shl(context, self.sender_bits + self.epoch_bits)
            | shl(sender_index, self.epoch_bits)
            | self.epoch_slot(epoch))
    }

    /// The context, the sender index and the low `E` epoch bits a KID carries.
    #[must_use]
    pub const fn split(&self, kid: u64) -> MlsKeyId {
        MlsKeyId {
            context: shr(kid, self.sender_bits + self.epoch_bits),
            sender_index: shr(kid, self.epoch_bits) & mask(self.sender_bits),
            epoch: kid & mask(self.epoch_bits),
        }
    }
}

/// The parts of an MLS KID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MlsKeyId {
    /// The value the sender chose, for instance to tell its streams apart.
    pub context: u64,
    /// The sender's member index in the MLS group.
    pub sender_index: u64,
    /// The low `E` bits of the MLS epoch.
    pub epoch: u64,
}
