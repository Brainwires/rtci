//! The fuzz entry points on fixed and generated inputs, so that their oracles run with the
//! tests and not only under the fuzzer.

use crate::fuzzing::{context_decrypt, header_decode};
use crate::header_vectors::RFC9605_C1_HEADERS;
use crate::test_util::hex;

/// A small deterministic generator (SplitMix64): the same inputs on every run.
struct Generator(u64);

impl Generator {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

#[test]
fn fuzz_header_decode_holds_on_vectors_and_generated_input() {
    for &(_, _, encoded) in RFC9605_C1_HEADERS {
        let bytes = hex(encoded);
        for len in 0..=bytes.len() {
            header_decode(&bytes[..len]);
        }
    }
    let mut generator = Generator(1);
    for _ in 0..20_000 {
        let len = (generator.next() % 20) as usize;
        header_decode(&generator.bytes(len));
    }
}

#[test]
fn fuzz_context_decrypt_holds_on_every_op_and_generated_input() {
    // Every configuration byte with every op, on a short argument.
    for config in 0..=0x3fu8 {
        let mut input = vec![config];
        for op in 0..=0xffu8 {
            input.push(op);
            input.extend_from_slice(&[0, 3, op, config, 0x5a]);
        }
        context_decrypt(&input);
    }
    // Generated op sequences, ops and lengths included.
    let mut generator = Generator(2);
    for _ in 0..300 {
        let len = (generator.next() % 400) as usize;
        context_decrypt(&generator.bytes(len));
    }
    context_decrypt(&[]);
    context_decrypt(&[0x07]);
    context_decrypt(&[0x07, 0x01]);
}
