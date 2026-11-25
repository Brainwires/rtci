//! What the key-erasure tests look for: every key an SRTP context derives from a master key,
//! and the forms a cipher object keeps it in (RFC 7714 section 13.1: "All keys MUST be properly
//! erased when no longer needed").
//!
//! Everything here is computed by the test itself, with a small AES (FIPS-197), the SRTP key
//! derivation (RFC 3711 section 4.3) and a SHA-1 compression function (FIPS 180-4), none of them
//! the code under test: each is checked against its standard's vectors
//! (`the_local_primitives_match_their_standards`). A needle is kept only inverted (each byte
//! complemented), so the test's own copy of a key never matches a search; the plain bytes exist
//! only in stack arrays of the function that computes them, which wipes them before it returns.

#![allow(dead_code)]

use rtci_srtp::protection_profile::ProtectionProfile;

/// The longest needle: an AES-256 key.
pub const MAX_NEEDLE: usize = 32;

/// One byte string to look for, kept inverted.
#[derive(Clone, Copy)]
pub struct Needle {
    /// Which key it comes from ("SRTP encryption key", ...).
    pub key: &'static str,
    /// Which form of it ("the key", "round key 3", "GHASH key H", ...).
    pub form: &'static str,
    /// Whether the crate itself holds this form (in a zeroizing buffer), not a provider's
    /// cipher object.
    pub crate_held: bool,
    len: usize,
    inverted: [u8; MAX_NEEDLE],
}

impl Needle {
    fn new(key: &'static str, form: &'static str, crate_held: bool, bytes: &[u8]) -> Self {
        let mut inverted = [0u8; MAX_NEEDLE];
        for (dst, src) in inverted.iter_mut().zip(bytes) {
            *dst = !src;
        }
        Self {
            key,
            form,
            crate_held,
            len: bytes.len(),
            inverted,
        }
    }

    /// The needle's length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether `haystack` holds the needle anywhere.
    pub fn found_in(&self, haystack: &[u8]) -> bool {
        let needle = &self.inverted[..self.len];
        if haystack.len() < self.len {
            return false;
        }
        let first = !needle[0];
        let mut i = 0;
        while i + self.len <= haystack.len() {
            if haystack[i] == first
                && haystack[i..i + self.len]
                    .iter()
                    .zip(needle)
                    .all(|(h, n)| *h == !*n)
            {
                return true;
            }
            i += 1;
        }
        false
    }

    /// The first two bytes, for a prefilter.
    pub fn prefix(&self) -> u16 {
        u16::from_le_bytes([!self.inverted[0], !self.inverted[1]])
    }

    pub fn describe(&self) -> String {
        format!("{} ({}, {} bytes)", self.form, self.key, self.len)
    }
}

/// Overwrites `bytes` so that the compiler cannot drop the stores.
pub fn wipe(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

// ---------------------------------------------------------------------------------------------
// AES (FIPS-197), byte-oriented, for the test's own use.

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// An expanded AES key: `rounds + 1` round keys of 16 bytes, in the byte order FIPS-197
/// section 5.2 defines them (the order AES-NI and ARMv8 implementations store them in).
pub struct Schedule {
    pub bytes: [u8; 240],
    pub rounds: usize,
}

impl Schedule {
    /// KeyExpansion (FIPS-197 section 5.2) of a 16, 24 or 32 byte key.
    pub fn expand(key: &[u8]) -> Self {
        let nk = key.len() / 4;
        assert!(matches!(nk, 4 | 6 | 8), "an AES key of {} bytes", key.len());
        let rounds = nk + 6;
        let words = 4 * (rounds + 1);
        let mut bytes = [0u8; 240];
        bytes[..key.len()].copy_from_slice(key);
        let mut rcon = 1u8;
        for i in nk..words {
            let mut t = [
                bytes[4 * (i - 1)],
                bytes[4 * (i - 1) + 1],
                bytes[4 * (i - 1) + 2],
                bytes[4 * (i - 1) + 3],
            ];
            if i % nk == 0 {
                t = [
                    SBOX[t[1] as usize] ^ rcon,
                    SBOX[t[2] as usize],
                    SBOX[t[3] as usize],
                    SBOX[t[0] as usize],
                ];
                rcon = xtime(rcon);
            } else if nk > 6 && i % nk == 4 {
                t = t.map(|b| SBOX[b as usize]);
            }
            for j in 0..4 {
                bytes[4 * i + j] = bytes[4 * (i - nk) + j] ^ t[j];
            }
            wipe(&mut t);
        }
        Self { bytes, rounds }
    }

    pub fn round_key(&self, i: usize) -> &[u8] {
        &self.bytes[16 * i..16 * (i + 1)]
    }

    /// The cipher (FIPS-197 section 5.1) on one block.
    pub fn encrypt(&self, block: &mut [u8; 16]) {
        add(block, self.round_key(0));
        for round in 1..=self.rounds {
            for b in block.iter_mut() {
                *b = SBOX[*b as usize];
            }
            // ShiftRows: byte (row r, column c) is at 4c + r.
            let s = *block;
            for c in 0..4 {
                for r in 0..4 {
                    block[4 * c + r] = s[4 * ((c + r) % 4) + r];
                }
            }
            if round != self.rounds {
                for c in 0..4 {
                    let col = [
                        block[4 * c],
                        block[4 * c + 1],
                        block[4 * c + 2],
                        block[4 * c + 3],
                    ];
                    let all = col[0] ^ col[1] ^ col[2] ^ col[3];
                    for r in 0..4 {
                        block[4 * c + r] = col[r] ^ all ^ xtime(col[r] ^ col[(r + 1) % 4]);
                    }
                }
            }
            add(block, self.round_key(round));
        }
    }
}

impl Drop for Schedule {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

fn xtime(b: u8) -> u8 {
    (b << 1) ^ if b & 0x80 != 0 { 0x1b } else { 0 }
}

fn add(block: &mut [u8; 16], round_key: &[u8]) {
    for (b, k) in block.iter_mut().zip(round_key) {
        *b ^= k;
    }
}

// ---------------------------------------------------------------------------------------------
// The SRTP key derivation (RFC 3711 section 4.3.1, RFC 6188 section 3; RFC 7714 section 11 pads
// the 96-bit salt to 112 bits), key derivation rate zero.

pub fn derive(master_key: &[u8], master_salt: &[u8], label: u8, out: &mut [u8]) {
    let schedule = Schedule::expand(master_key);
    let mut x = [0u8; 16];
    x[..master_salt.len()].copy_from_slice(master_salt);
    x[7] ^= label;
    for (i, chunk) in out.chunks_mut(16).enumerate() {
        let mut block = x;
        block[14..].copy_from_slice(&(i as u16).to_be_bytes());
        schedule.encrypt(&mut block);
        chunk.copy_from_slice(&block[..chunk.len()]);
        wipe(&mut block);
    }
    wipe(&mut x);
}

// ---------------------------------------------------------------------------------------------
// SHA-1 (FIPS 180-4 section 6.1.2), the compression function only.

pub const SHA1_IV: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

pub fn sha1_compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for t in 0..16 {
        w[t] = u32::from_be_bytes([
            block[4 * t],
            block[4 * t + 1],
            block[4 * t + 2],
            block[4 * t + 3],
        ]);
    }
    for t in 16..80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (t, wt) in w.iter().enumerate() {
        let (f, k) = match t {
            0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6u32),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(*wt);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e]) {
        *s = s.wrapping_add(v);
    }
    w.fill(0);
}

/// The two SHA-1 states an HMAC-SHA1 (RFC 2104) keyed with `key` (at most 64 bytes) starts
/// from: after the block `key XOR ipad` and after `key XOR opad`. Whoever has them can compute
/// the MAC: they are the key in another form.
pub fn hmac_sha1_states(key: &[u8]) -> ([u32; 5], [u32; 5]) {
    let mut inner = SHA1_IV;
    let mut outer = SHA1_IV;
    let mut block = [0u8; 64];
    for (pad, state) in [(0x36u8, &mut inner), (0x5c, &mut outer)] {
        block.fill(pad);
        for (b, k) in block.iter_mut().zip(key) {
            *b ^= k;
        }
        sha1_compress(state, &block);
    }
    wipe(&mut block);
    (inner, outer)
}

fn words(state: &[u32; 5], big_endian: bool) -> [u8; 20] {
    let mut out = [0u8; 20];
    for (chunk, word) in out.chunks_mut(4).zip(state) {
        chunk.copy_from_slice(&if big_endian {
            word.to_be_bytes()
        } else {
            word.to_le_bytes()
        });
    }
    out
}

// ---------------------------------------------------------------------------------------------
// The needles of a context.

const ROUND_KEYS: [&str; 15] = [
    "round key 0",
    "round key 1",
    "round key 2",
    "round key 3",
    "round key 4",
    "round key 5",
    "round key 6",
    "round key 7",
    "round key 8",
    "round key 9",
    "round key 10",
    "round key 11",
    "round key 12",
    "round key 13",
    "round key 14",
];

/// The forms an AES key takes: the key, each round key not inside the key (FIPS-197 section
/// 5.2: words `Nk` on), and for an AEAD key the GHASH key `H = AES_K(0^128)` (NIST SP 800-38D
/// section 6.4).
fn aes_needles(
    out: &mut Vec<Needle>,
    key_name: &'static str,
    key: &[u8],
    crate_held: bool,
    gcm: bool,
) {
    out.push(Needle::new(key_name, "the key", crate_held, key));
    let schedule = Schedule::expand(key);
    let nk = key.len() / 4;
    for (i, name) in ROUND_KEYS.iter().enumerate().take(schedule.rounds + 1) {
        if 4 * i >= nk {
            out.push(Needle::new(key_name, name, false, schedule.round_key(i)));
        }
    }
    if gcm {
        let mut h = [0u8; 16];
        schedule.encrypt(&mut h);
        out.push(Needle::new(key_name, "GHASH key H", false, &h));
        wipe(&mut h);
    }
}

fn hmac_needles(out: &mut Vec<Needle>, key_name: &'static str, key: &[u8]) {
    out.push(Needle::new(key_name, "the key", true, key));
    let (inner, outer) = hmac_sha1_states(key);
    for (state, le, be) in [
        (
            &inner,
            "HMAC inner state (little-endian words)",
            "HMAC inner state (big-endian words)",
        ),
        (
            &outer,
            "HMAC outer state (little-endian words)",
            "HMAC outer state (big-endian words)",
        ),
    ] {
        for (form, big_endian) in [(le, false), (be, true)] {
            let mut bytes = words(state, big_endian);
            out.push(Needle::new(key_name, form, false, &bytes));
            wipe(&mut bytes);
        }
    }
}

/// Every key a context of `profile` derives from the master key and salt (key derivation rate
/// zero), in each form a cipher object may keep it.
pub fn context_needles(
    profile: ProtectionProfile,
    master_key: &[u8],
    master_salt: &[u8],
) -> Vec<Needle> {
    let mut out = Vec::new();
    let aead = matches!(
        profile,
        ProtectionProfile::AeadAes128Gcm | ProtectionProfile::AeadAes256Gcm
    );
    let null = matches!(
        profile,
        ProtectionProfile::NullHmacSha1_80 | ProtectionProfile::NullHmacSha1_32
    );
    let key_len = profile.key_len();
    let salt_len = if aead { 12 } else { 14 };
    let mut buf = [0u8; 32];
    for (encryption, authentication, salt, names) in [
        (
            0x00u8,
            0x01u8,
            0x02u8,
            [
                "SRTP encryption key",
                "SRTP authentication key",
                "SRTP salting key",
            ],
        ),
        (
            0x03,
            0x04,
            0x05,
            [
                "SRTCP encryption key",
                "SRTCP authentication key",
                "SRTCP salting key",
            ],
        ),
    ] {
        if !null {
            derive(master_key, master_salt, encryption, &mut buf[..key_len]);
            // The AES-CM profiles keep the session key in the crate's own zeroizing buffer; an
            // AEAD key goes straight into the provider's object.
            aes_needles(&mut out, names[0], &buf[..key_len], !aead, aead);
        }
        if !aead {
            derive(master_key, master_salt, authentication, &mut buf[..20]);
            hmac_needles(&mut out, names[1], &buf[..20]);
        }
        derive(master_key, master_salt, salt, &mut buf[..salt_len]);
        out.push(Needle::new(names[2], "the key", true, &buf[..salt_len]));
        wipe(&mut buf);
    }
    // The key derivation keys the master key into AES on every derivation.
    aes_needles(&mut out, "master key", master_key, true, false);
    out
}

/// The local primitives against their standards' vectors. Panics on a mismatch.
pub fn check_local_primitives() {
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }
    // FIPS-197 appendix A.1: the last round key of 2b7e1516....
    let schedule = Schedule::expand(&hex("2b7e151628aed2a6abf7158809cf4f3c"));
    assert_eq!(
        hex("d014f9a8c9ee2589e13f0cc8b6630ca6"),
        schedule.round_key(10)
    );
    // FIPS-197 appendix C.1 to C.3.
    for (key, expected) in [
        (
            "000102030405060708090a0b0c0d0e0f",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        ),
        (
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "8ea2b7ca516745bfeafc49904b496089",
        ),
    ] {
        let mut block: [u8; 16] = hex("00112233445566778899aabbccddeeff").try_into().unwrap();
        Schedule::expand(&hex(key)).encrypt(&mut block);
        assert_eq!(hex(expected), block, "FIPS-197 appendix C, key {key}");
    }
    // RFC 3711 appendix B.3.
    let master_key = hex("E1F97A0D3E018BE0D64FA32C06DE4139");
    let master_salt = hex("0EC675AD498AFEEBB6960B3AABE6");
    let mut out = [0u8; 20];
    derive(&master_key, &master_salt, 0x00, &mut out[..16]);
    assert_eq!(hex("C61E7A93744F39EE10734AFE3FF7A087"), out[..16]);
    derive(&master_key, &master_salt, 0x02, &mut out[..14]);
    assert_eq!(hex("30CBBC08863D8C85D49DB34A9AE1"), out[..14]);
    derive(&master_key, &master_salt, 0x01, &mut out);
    assert_eq!(hex("CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4"), out);
    // FIPS 180-4 / FIPS 180-2 appendix A.1: SHA-1("abc").
    let mut block = [0u8; 64];
    block[..3].copy_from_slice(b"abc");
    block[3] = 0x80;
    block[63] = 24;
    let mut state = SHA1_IV;
    sha1_compress(&mut state, &block);
    assert_eq!(
        hex("a9993e364706816aba3e25717850c26c9cd0d89d"),
        words(&state, true)
    );
}

/// An RTP packet (RFC 3550 section 5.1) with a short payload.
pub fn rtp(sequence_number: u16) -> Vec<u8> {
    let mut packet = vec![0x80, 96];
    packet.extend_from_slice(&sequence_number.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 1, 0x11, 0x22, 0x33, 0x44]);
    packet.extend_from_slice(b"payload of a packet");
    packet
}

/// An RTCP receiver report without report blocks (RFC 3550 section 6.4.2).
pub fn rtcp() -> Vec<u8> {
    vec![0x80, 201, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44]
}
