//! Entry points for stateful fuzz targets.
//!
//! [`context_decrypt`] keeps a sending and a receiving [`Context`] keyed alike, and feeds the
//! receiver both raw fuzzed packets and fuzzed plaintext the sender has protected first. The
//! protected packets authenticate, so they reach the per-SSRC state: rollover counting, the replay
//! window and the SRTCP index. Fixed keys, no clock: every input replays identically. Gated
//! behind `cfg(fuzzing)`; not part of the supported API.
use crate::context::Context;
use crate::header_extension::EncryptedHeaderExtensions;
use crate::keying::{KeyDerivationRate, KeyLifetime, Keying};
use crate::option::{
    srtcp_no_replay_protection, srtcp_replay_protection, srtp_no_replay_protection,
    srtp_replay_protection,
};
use crate::protection_profile::ProtectionProfile;

const PROFILES: [ProtectionProfile; 10] = ProtectionProfile::ALL;

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

/// `arg` with the version bits of an RTP/RTCP first byte set to 2, so it parses as a header.
fn with_version(arg: &[u8]) -> Vec<u8> {
    let mut packet = arg.to_vec();
    if let Some(first) = packet.first_mut() {
        *first = (*first & 0x3f) | 0x80;
    }
    packet
}

/// Stateful target: SRTP/SRTCP decryption against a context with fixed keys.
///
/// The first byte picks the protection profile and whether the receiver has replay protection
/// (and its window). Its top three bits turn on, for both contexts: an MKI with a key
/// derivation rate of 16 packets and a lifetime of 48 packets per master key; RFC 6904
/// encryption of header extension elements 1 to 3; unencrypted (E = 0) SRTCP. The rest is a
/// sequence of ops, each an op byte followed by a two-byte length and the argument:
///
/// - a raw packet to `decrypt_rtp` or `decrypt_rtcp`;
/// - fuzzed RTP or RTCP plaintext, protected by the sender and then decrypted by the receiver,
///   optionally with one byte of the protected packet flipped first;
/// - a replay of an earlier protected packet.
pub fn context_decrypt(mut data: &[u8]) {
    let Some((&config, rest)) = data.split_first() else {
        return;
    };
    data = rest;

    let profile = PROFILES[usize::from(config) % PROFILES.len()];
    let window = match (config >> 3) & 0x03 {
        0 => None,
        1 => Some(64),
        2 => Some(128),
        _ => Some(1024),
    };
    let keyed = config & 0x20 != 0;
    let header_extensions = config & 0x40 != 0;
    let clear_srtcp = config & 0x80 != 0;

    let Ok(provider) = crypto::default_provider() else {
        return;
    };
    let master_key: Vec<u8> = (0..profile.key_len() as u8).collect();
    let master_salt: Vec<u8> = (0..profile.salt_len() as u8).map(|b| 0xa0 ^ b).collect();
    let new_context = |replay: Option<usize>| {
        let srtp = match replay {
            Some(window) => srtp_replay_protection(window)?,
            None => srtp_no_replay_protection(),
        };
        let srtcp = match replay {
            Some(window) => srtcp_replay_protection(window)?,
            None => srtcp_no_replay_protection(),
        };
        let mut context = if keyed {
            let mut context = Context::with_keying(
                &master_key,
                &master_salt,
                profile,
                Keying {
                    key_derivation_rate: KeyDerivationRate::new(16)?,
                    mki: Some(vec![0x00, 0x01]),
                },
                Some(srtp),
                Some(srtcp),
                provider.clone(),
            )?;
            context.set_key_lifetime(KeyLifetime {
                srtp_packets: 48,
                srtcp_packets: 48,
            })?;
            context
        } else {
            Context::new(
                &master_key,
                &master_salt,
                profile,
                Some(srtp),
                Some(srtcp),
                provider.crypto(),
            )?
        };
        if header_extensions {
            context.set_encrypted_header_extensions(EncryptedHeaderExtensions::new(&[1, 2, 3])?);
        }
        context.set_srtcp_encryption(!clear_srtcp);
        shared::error::Result::Ok(context)
    };
    let (Ok(mut sender), Ok(mut receiver)) = (new_context(None), new_context(window)) else {
        return;
    };

    // The last protected packet of each kind, for the replay op.
    let mut last_rtp = None;
    let mut last_rtcp = None;
    let mut ops = 0;
    while let Some((&op, rest)) = data.split_first() {
        data = rest;
        ops += 1;
        if ops > 512 {
            break;
        }
        let arg = take_arg(&mut data);
        // The top bits of the op byte, when set, flip one byte of a protected packet.
        let flip = |packet: &mut bytes::BytesMut| {
            if op & 0x80 != 0 && !packet.is_empty() {
                let at = usize::from(arg.first().copied().unwrap_or(0)) % packet.len();
                packet[at] ^= 0x01 | (op & 0x70);
            }
        };
        match op & 0x07 {
            0 => {
                let _ = receiver.decrypt_rtp(arg);
            }
            1 => {
                let _ = receiver.decrypt_rtcp(arg);
            }
            2 => {
                if let Ok(mut packet) = sender.encrypt_rtp(&with_version(arg)) {
                    last_rtp = Some(packet.clone());
                    flip(&mut packet);
                    let _ = receiver.decrypt_rtp(&packet);
                }
            }
            3 => {
                if let Ok(mut packet) = sender.encrypt_rtcp(&with_version(arg)) {
                    last_rtcp = Some(packet.clone());
                    flip(&mut packet);
                    let _ = receiver.decrypt_rtcp(&packet);
                }
            }
            4 => {
                if let Some(mut packet) = last_rtp.clone() {
                    flip(&mut packet);
                    let _ = receiver.decrypt_rtp(&packet);
                }
            }
            5 => {
                if let Some(mut packet) = last_rtcp.clone() {
                    flip(&mut packet);
                    let _ = receiver.decrypt_rtcp(&packet);
                }
            }
            6 => {
                // The receiver protecting its own traffic shares the per-SSRC state.
                let _ = receiver.encrypt_rtp(&with_version(arg));
            }
            _ => {
                let _ = receiver.encrypt_rtcp(&with_version(arg));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A protected packet decrypts: the harness reaches the authenticated paths.
    #[test]
    fn protected_packets_reach_the_receiver() {
        for config in 0..PROFILES.len() as u8 {
            let profile = PROFILES[usize::from(config)];
            let provider = crypto::default_provider().unwrap();
            let key: Vec<u8> = (0..profile.key_len() as u8).collect();
            let salt: Vec<u8> = (0..profile.salt_len() as u8).map(|b| 0xa0 ^ b).collect();
            let mut s = Context::new(&key, &salt, profile, None, None, provider.crypto()).unwrap();
            let mut r = Context::new(&key, &salt, profile, None, None, provider.crypto()).unwrap();
            let rtp = with_version(&[0, 96, 0, 1, 0, 0, 0, 1, 0, 0, 0, 7, 0xde, 0xad]);
            let packet = s.encrypt_rtp(&rtp).unwrap();
            assert_eq!(&r.decrypt_rtp(&packet).unwrap()[..], &rtp[..]);
            // Every combination of the option bits, with an op of each kind.
            for options in 0..8u8 {
                let mut input = vec![config | (options << 5)];
                for op in 0..8u8 {
                    input.extend_from_slice(&[op, 0, rtp.len() as u8]);
                    input.extend_from_slice(&rtp);
                }
                context_decrypt(&input);
            }
        }
    }
}
