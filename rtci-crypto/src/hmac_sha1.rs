//! HMAC-SHA1 (RFC 2104, FIPS 180-4) for the ring provider, whose keyed state never leaves the
//! heap object that holds it.
//!
//! ring exposes SHA-1 only as `HMAC_SHA1_FOR_LEGACY_USE_ONLY` and does not use the SHA
//! instructions for it: 4469 ns against 1373 ns with RustCrypto's `sha1` over a 1212-byte SRTP
//! packet, 3.3x and the whole of the SRTP AES-CM/HMAC regression. The built-in providers are
//! already composite (AES-CTR, CCM, CBC and MD5 come from RustCrypto too), so HMAC-SHA1 is
//! composed the same way. `aws-lc-rs` has a fast SHA-1 and keeps its own.
//!
//! The composition is done here, over `sha1`'s compression function, rather than with the
//! `hmac` crate, because of where the keyed state goes. The SHA-1 states after `key XOR ipad`
//! and `key XOR opad` compute any MAC under the key: they are the key in another form. `hmac`
//! 0.12 computes a MAC on a copy of the keyed object (a clone, or the object moved into
//! `finalize`), which puts both states into a stack frame for every packet, where nothing
//! erases them (found there by `rtci-srtp/tests/key_residue.rs`: RFC 7714 section 13.1, "All
//! keys MUST be properly erased when no longer needed"). Here the two keyed states, the
//! working state of the MAC being computed and the block buffer are fields of one boxed
//! object, written in place, zeroized when it is dropped; a call keeps two integers on its
//! stack. What the compression function itself keeps in registers or spills is its own.

use sha1::digest::consts::U64;
use sha1::digest::generic_array::GenericArray;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::common::check_tag_len;
use crate::{CryptoError, Mac};

const BLOCK_LEN: usize = 64;
const OUTPUT_LEN: usize = 20;
/// FIPS 180-4 section 5.3.1.
const INITIAL: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

/// A keyed HMAC-SHA1. Only ever built in a box ([`HmacSha1::boxed`]): the fields are computed
/// where they live.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct HmacSha1 {
    /// The SHA-1 state after the block `key XOR ipad`.
    inner: [u32; 5],
    /// The SHA-1 state after the block `key XOR opad`.
    outer: [u32; 5],
    /// The state of the hash being computed.
    state: [u32; 5],
    /// The block being filled: message octets, then padding; the padded key while keying.
    block: [u8; BLOCK_LEN],
}

fn compress(state: &mut [u32; 5], block: &[u8; BLOCK_LEN]) {
    sha1::compress(
        state,
        std::slice::from_ref(GenericArray::<u8, U64>::from_slice(block)),
    );
}

impl HmacSha1 {
    /// A MAC keyed with `key`, of any length (RFC 2104 section 2: a key longer than a block
    /// is hashed first).
    pub(crate) fn boxed(key: &[u8]) -> Box<Self> {
        let mut mac = Box::new(Self {
            inner: INITIAL,
            outer: INITIAL,
            state: INITIAL,
            block: [0; BLOCK_LEN],
        });
        mac.key(key);
        mac
    }

    fn key(&mut self, key: &[u8]) {
        self.block = [0; BLOCK_LEN];
        if key.len() > BLOCK_LEN {
            self.state = INITIAL;
            let buffered = self.absorb(0, key);
            self.finish(buffered, key.len() as u64);
            self.write_state();
            self.block[OUTPUT_LEN..].fill(0);
        } else {
            self.block[..key.len()].copy_from_slice(key);
        }
        for byte in &mut self.block {
            *byte ^= 0x36;
        }
        self.inner = INITIAL;
        compress(&mut self.inner, &self.block);
        for byte in &mut self.block {
            *byte ^= 0x36 ^ 0x5c;
        }
        self.outer = INITIAL;
        compress(&mut self.outer, &self.block);
        self.block.zeroize();
        self.state.zeroize();
    }

    /// Hashes `data` into `state`, after the `buffered` octets already in `block`; returns
    /// how many octets are in `block` afterwards (fewer than a block).
    fn absorb(&mut self, mut buffered: usize, mut data: &[u8]) -> usize {
        if buffered > 0 {
            let take = (BLOCK_LEN - buffered).min(data.len());
            self.block[buffered..buffered + take].copy_from_slice(&data[..take]);
            buffered += take;
            data = &data[take..];
            if buffered < BLOCK_LEN {
                return buffered;
            }
            compress(&mut self.state, &self.block);
        }
        let (blocks, rest) = data.as_chunks::<BLOCK_LEN>();
        for block in blocks {
            compress(&mut self.state, block);
        }
        self.block[..rest.len()].copy_from_slice(rest);
        rest.len()
    }

    /// The padding of FIPS 180-4 section 5.1.1 after `buffered` octets in `block`, for a
    /// message of `len` octets in all.
    fn finish(&mut self, buffered: usize, len: u64) {
        self.block[buffered] = 0x80;
        self.block[buffered + 1..].fill(0);
        if buffered + 1 > BLOCK_LEN - 8 {
            compress(&mut self.state, &self.block);
            self.block.fill(0);
        }
        self.block[BLOCK_LEN - 8..].copy_from_slice(&(len * 8).to_be_bytes());
        compress(&mut self.state, &self.block);
    }

    /// Writes the hash in `state` to the first [`OUTPUT_LEN`] octets of `block`.
    fn write_state(&mut self) {
        for (i, word) in self.state.iter().enumerate() {
            self.block[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
        }
    }
}

impl Mac for HmacSha1 {
    fn output_len(&self) -> usize {
        OUTPUT_LEN
    }

    fn sign(&mut self, input: &[&[u8]], output: &mut [u8]) -> Result<(), CryptoError> {
        check_tag_len(OUTPUT_LEN, output.len())?;
        // H((key XOR ipad) || message)
        self.state = self.inner;
        let mut buffered = 0;
        let mut len = BLOCK_LEN as u64;
        for part in input {
            buffered = self.absorb(buffered, part);
            len += part.len() as u64;
        }
        self.finish(buffered, len);
        // H((key XOR opad) || that)
        self.write_state();
        self.state = self.outer;
        self.finish(OUTPUT_LEN, (BLOCK_LEN + OUTPUT_LEN) as u64);
        for (chunk, word) in output.as_chunks_mut::<4>().0.iter_mut().zip(&self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        Ok(())
    }

    fn verify(&mut self, input: &[&[u8]], expected: &[u8]) -> Result<(), CryptoError> {
        check_tag_len(OUTPUT_LEN, expected.len())?;
        let mut actual = [0u8; OUTPUT_LEN];
        self.sign(input, &mut actual)?;
        if crate::constant_time_eq(&actual, expected) {
            Ok(())
        } else {
            Err(CryptoError::AuthenticationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::hmac::Mac as _;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn tag(key: &[u8], parts: &[&[u8]]) -> [u8; OUTPUT_LEN] {
        let mut out = [0u8; OUTPUT_LEN];
        HmacSha1::boxed(key).sign(parts, &mut out).expect("a tag");
        out
    }

    /// RFC 2202 section 3, test cases 1, 2 and 6 (a key shorter than the hash, a short text
    /// key, a key longer than a block).
    #[test]
    fn rfc_2202_vectors() {
        assert_eq!(
            hex("b617318655057264e28bc0b6fb378c8ef146be00"),
            tag(&[0x0b; 20], &[b"Hi There"])
        );
        assert_eq!(
            hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
            tag(b"Jefe", &[b"what do ya want for nothing?"])
        );
        assert_eq!(
            hex("aa4ae5e15272d00e95705637ce8a3b55ed402112"),
            tag(
                &[0xaa; 80],
                &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
            )
        );
    }

    /// Every message length around the block and padding boundaries, every key length around
    /// a block, split into parts at every kind of place, and the same object used again:
    /// equal to the `hmac` crate's HMAC-SHA1.
    #[test]
    fn equal_to_the_hmac_crate_for_every_length_and_split() {
        let message: Vec<u8> = (0..300u32).map(|i| (i * 7 + 3) as u8).collect();
        let key_bytes: Vec<u8> = (0..150u32).map(|i| (i * 13 + 5) as u8).collect();
        for key_len in [0, 1, 19, 20, 21, 55, 63, 64, 65, 100, 150] {
            let key = &key_bytes[..key_len];
            let mut ours = HmacSha1::boxed(key);
            for len in 0..=message.len() {
                let message = &message[..len];
                let mut reference =
                    ::hmac::Hmac::<sha1::Sha1>::new_from_slice(key).expect("any key length");
                reference.update(message);
                let expected = reference.finalize().into_bytes();
                for split in [0, 1, len / 3, len / 2, len.saturating_sub(1), len] {
                    let split = split.min(len);
                    let (head, tail) = message.split_at(split);
                    let (middle, tail) = tail.split_at(tail.len() / 2);
                    let mut out = [0u8; OUTPUT_LEN];
                    ours.sign(&[head, middle, &[], tail], &mut out)
                        .expect("a tag");
                    assert_eq!(
                        expected.as_slice(),
                        out,
                        "key of {key_len}, message of {len} split at {split}"
                    );
                    ours.verify(&[message], &out).expect("its own tag verifies");
                }
            }
        }
    }

    #[test]
    fn a_wrong_tag_and_a_wrong_length_are_refused() {
        let mut mac = HmacSha1::boxed(b"key");
        let mut out = [0u8; OUTPUT_LEN];
        mac.sign(&[b"message"], &mut out).expect("a tag");
        out[19] ^= 1;
        assert!(matches!(
            mac.verify(&[b"message"], &out),
            Err(CryptoError::AuthenticationFailed)
        ));
        assert!(mac.sign(&[b"message"], &mut [0u8; 10]).is_err());
        assert!(mac.verify(&[b"message"], &[0u8; 10]).is_err());
    }

    /// The keyed states are where the erasure tests look for them: the two SHA-1 states,
    /// native-endian words, inside the object.
    #[test]
    fn the_object_holds_the_two_keyed_states_and_nothing_of_the_key_itself() {
        let mac = HmacSha1::boxed(&[0x5a; 20]);
        assert_ne!(INITIAL, mac.inner);
        assert_ne!(INITIAL, mac.outer);
        assert_ne!(mac.inner, mac.outer);
        assert_eq!([0u8; BLOCK_LEN], mac.block);
        assert_eq!([0u32; 5], mac.state);
    }
}
