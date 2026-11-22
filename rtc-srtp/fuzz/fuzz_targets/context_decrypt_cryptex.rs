#![no_main]
//! Stateful target: SRTP with Cryptex (RFC 9335) on both sides.
//!
//! A sending and a receiving context share fixed keys; the sender protects CSRCs and header
//! extensions, the receiver may require them protected. The input supplies raw packets to decrypt
//! and plaintext RTP the harness shapes into a packet with a CSRC list and an RFC 8285 extension
//! block (one-byte, two-byte, or a profile Cryptex cannot carry), so encryption and decryption of
//! the header regions, the 0xC0DE / 0xC2DE markers and the layout checks all run. Protected
//! packets can be tampered with before decryption. Fixed keys, no clock: every input replays
//! identically.

use libfuzzer_sys::fuzz_target;
use rtc_srtp::context::Context;
use rtc_srtp::cryptex::Cryptex;
use rtc_srtp::option::{srtp_no_replay_protection, srtp_replay_protection};
use rtc_srtp::protection_profile::ProtectionProfile;

const PROFILES: [ProtectionProfile; 4] = [
    ProtectionProfile::Aes128CmHmacSha1_80,
    ProtectionProfile::Aes256CmHmacSha1_80,
    ProtectionProfile::AeadAes128Gcm,
    ProtectionProfile::AeadAes256Gcm,
];

fn byte(arg: &[u8], i: usize) -> u8 {
    arg.get(i).copied().unwrap_or(0)
}

/// Splits the next op argument off `data`: a two-byte length, then that many bytes.
fn take_arg<'a>(data: &mut &'a [u8]) -> &'a [u8] {
    if data.len() < 2 {
        *data = &[];
        return &[];
    }
    let len = usize::from(u16::from_be_bytes([data[0], data[1]])).min(data.len() - 2);
    let (arg, rest) = data[2..].split_at(len);
    *data = rest;
    arg
}

/// An RTP packet built from `arg`: the first byte chooses the CSRC count and the extension
/// profile, the next a sequence number byte; the extension block takes the next bytes (its
/// length in words from the input) and the rest is payload.
fn shaped_packet(arg: &[u8]) -> Vec<u8> {
    let shape = byte(arg, 0);
    let csrc_count = shape & 0x0f;
    let has_extension = shape & 0x10 != 0;
    let mut packet = vec![0x80 | csrc_count | if has_extension { 0x10 } else { 0 }, 96];
    packet.extend_from_slice(&[0, byte(arg, 1)]);
    packet.extend_from_slice(&[0, 0, 0, byte(arg, 1)]);
    packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    for i in 0..csrc_count {
        packet.extend_from_slice(&[0, 0, 0, i]);
    }
    let mut rest = arg.get(2..).unwrap_or(&[]);
    if has_extension {
        let profile: u16 = match (shape >> 5) & 0x03 {
            0 => 0xBEDE,
            1 => 0x1000,
            // Two-byte form with non-zero "appbits": RFC 9335 cannot encrypt it.
            2 => 0x1001,
            _ => u16::from_be_bytes([byte(arg, 2), byte(arg, 3)]),
        };
        let words = usize::from(byte(rest, 0) & 0x07);
        rest = rest.get(1..).unwrap_or(&[]);
        packet.extend_from_slice(&profile.to_be_bytes());
        packet.extend_from_slice(&(words as u16).to_be_bytes());
        for i in 0..words * 4 {
            packet.push(byte(rest, i));
        }
        rest = rest.get(words * 4..).unwrap_or(&[]);
    }
    packet.extend_from_slice(rest);
    packet
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let Some((&config, rest)) = data.split_first() else {
        return;
    };
    data = rest;

    let profile = PROFILES[usize::from(config) % PROFILES.len()];
    let Ok(provider) = rtc_srtp::crypto::default_provider() else {
        return;
    };
    let master_key: Vec<u8> = (0..profile.key_len() as u8).collect();
    let master_salt: Vec<u8> = (0..profile.salt_len() as u8).map(|b| 0xa0 ^ b).collect();
    let new_context = |replay: bool| {
        let srtp = if replay {
            srtp_replay_protection(64)?
        } else {
            srtp_no_replay_protection()
        };
        Context::new(
            &master_key,
            &master_salt,
            profile,
            Some(srtp),
            None,
            provider.crypto(),
        )
    };
    let (Ok(mut sender), Ok(mut receiver)) = (new_context(false), new_context(config & 0x04 != 0))
    else {
        return;
    };
    sender.set_cryptex(Cryptex {
        send: config & 0x08 == 0,
        require: false,
    });
    receiver.set_cryptex(Cryptex {
        send: config & 0x10 != 0,
        require: config & 0x20 != 0,
    });

    // The last protected packet, owned, so it can be replayed and tampered with again.
    let mut last: Option<Vec<u8>> = None;
    let mut ops = 0;
    while let Some((&op, rest)) = data.split_first() {
        data = rest;
        ops += 1;
        if ops > 512 {
            break;
        }
        let arg = take_arg(&mut data);
        let tamper = |packet: &mut [u8]| {
            if op & 0x80 != 0 && !packet.is_empty() {
                let at = usize::from(byte(arg, 0)) % packet.len();
                packet[at] ^= 0x01 | (op & 0x70);
            }
        };
        match op & 0x03 {
            0 => {
                let _ = receiver.decrypt_rtp(arg);
            }
            1 => {
                if let Ok(protected) = sender.encrypt_rtp(&shaped_packet(arg)) {
                    let mut packet = protected.to_vec();
                    last = Some(packet.clone());
                    tamper(&mut packet);
                    let _ = receiver.decrypt_rtp(&packet);
                }
            }
            2 => {
                if let Some(mut packet) = last.clone() {
                    tamper(&mut packet);
                    let _ = receiver.decrypt_rtp(&packet);
                }
            }
            _ => {
                // The receiver protecting its own traffic, Cryptex or not.
                let _ = receiver.encrypt_rtp(&shaped_packet(arg));
            }
        }
    }
});
