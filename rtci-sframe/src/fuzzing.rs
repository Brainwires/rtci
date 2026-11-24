//! Entry points for the fuzz targets.
//!
//! [`header_decode`] checks the header parser against the encoder. [`context_decrypt`] keeps a
//! sending and a receiving [`SFrameContext`] keyed alike and feeds the receiver raw fuzzed
//! ciphertexts, ciphertexts the sender has just produced, altered ones and replays, with the
//! key-management helpers alongside. Fixed keys, no clock: every input replays identically.
//! Gated behind `cfg(fuzzing)`; not part of the supported API.

use crate::{
    CipherSuite, Error, Header, MAX_HEADER_LEN, MlsContext, MlsKeyIdLayout, PendingCiphertexts,
    SFrameConfig, SFrameContext, SenderKeyIdLayout, SenderKeyRatchet, SenderKeyReceiver,
};

/// Parser target: any bytes through both header decoders.
///
/// A header the strict decoder accepts re-encodes to the bytes it was read from; one only the
/// lenient decoder accepts carries the same values in more bytes.
pub fn header_decode(data: &[u8]) {
    let lenient = Header::decode_lenient(data);
    match Header::decode(data) {
        Ok((header, len)) => {
            let mut encoded = [0u8; MAX_HEADER_LEN];
            let encoded_len = header.encode(&mut encoded);
            assert_eq!(&encoded[..encoded_len], &data[..len]);
            assert_eq!(encoded_len, header.encoded_len());
            assert_eq!(lenient, Ok((header, len)));
        }
        Err(Error::NonMinimalHeader) => {
            let (header, len) = lenient.expect("a non-minimal header parses leniently");
            assert!(len <= data.len() && len > header.encoded_len());
        }
        Err(error) => {
            assert_eq!(error, Error::TruncatedHeader);
            assert_eq!(lenient, Err(Error::TruncatedHeader));
        }
    }
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

/// The KIDs both contexts hold keys for: one of each header length class.
const KIDS: [u64; 4] = [0, 7, 0x1234, u64::MAX];
const METADATA: &[u8] = b"fuzz metadata";

fn base_key(kid: u64) -> [u8; 16] {
    let mut key = [0x5a; 16];
    key[..8].copy_from_slice(&kid.to_be_bytes());
    key
}

/// Stateful target: decryption against a context with fixed keys.
///
/// The first byte picks the cipher suite, the replay window and whether non-minimal headers
/// are admitted. The rest is a sequence of ops, each an op byte followed by a two-byte length
/// and the argument:
///
/// - a raw ciphertext to `decrypt` (and to the MLS and sender-keys receivers, and the pending
///   store);
/// - fuzzed plaintext, encrypted by the sender and decrypted by the receiver, which must give
///   it back;
/// - the same with one bit of the ciphertext flipped first, which must fail (asserted for the
///   tags of 64 bits and more);
/// - a replay of an earlier ciphertext, which must fail under a replay window and succeed
///   without one;
/// - a key removed and added again on the receiver, and a ratchet step on the sender-keys pair.
pub fn context_decrypt(mut data: &[u8]) {
    let Some((&config_byte, rest)) = data.split_first() else {
        return;
    };
    data = rest;

    let suite = CipherSuite::ALL[usize::from(config_byte & 0x07) % CipherSuite::ALL.len()];
    let config = SFrameConfig {
        replay_window: match (config_byte >> 3) & 0x03 {
            0 => None,
            1 => Some(64),
            2 => Some(128),
            _ => Some(1024),
        },
        allow_non_minimal_headers: config_byte & 0x20 != 0,
    };
    let replay_protected = config.replay_window.is_some();

    let Ok(provider) = crypto::default_provider() else {
        return;
    };
    let mut sender = SFrameContext::with_config(suite, provider.clone(), config.clone());
    let mut receiver = SFrameContext::with_config(suite, provider.clone(), config.clone());
    for kid in KIDS {
        sender.add_send_key(kid, &base_key(kid)).unwrap();
        receiver.add_recv_key(kid, &base_key(kid)).unwrap();
    }

    let layout = MlsKeyIdLayout::new(4, 6).unwrap();
    let mut mls_sender =
        MlsContext::with_config(suite, provider.clone(), layout, 3, config.clone()).unwrap();
    let mut mls_receiver =
        MlsContext::with_config(suite, provider.clone(), layout, 5, config.clone()).unwrap();
    mls_sender.add_epoch(14, b"epoch 14 secret").unwrap();
    mls_receiver.add_epoch(14, b"epoch 14 secret").unwrap();

    let ratchet_layout = SenderKeyIdLayout::new(3).unwrap();
    let mut ratchet =
        SenderKeyRatchet::new(suite, provider.clone(), ratchet_layout, 1, b"sender key").unwrap();
    let mut ratchet_sender = SFrameContext::with_config(suite, provider.clone(), config.clone());
    ratchet_sender
        .add_send_key(ratchet.key_id(), ratchet.base_key())
        .unwrap();
    let mut ratchet_receiver =
        SenderKeyReceiver::with_config(suite, provider, ratchet_layout, config);
    ratchet_receiver
        .set_key(ratchet.key_id(), ratchet.base_key())
        .unwrap();

    let mut pending = PendingCiphertexts::new(4, 4096);
    // Ciphertexts the receiver has accepted, with their plaintext, for the replay op.
    let mut accepted: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut out = Vec::new();

    while let Some((&op, rest)) = data.split_first() {
        data = rest;
        let arg = take_arg(&mut data);
        let kid = KIDS[usize::from(op >> 4) % KIDS.len()];
        out.clear();
        out.extend_from_slice(b"kept");
        match op & 0x0f {
            0 => {
                if receiver.decrypt_into(METADATA, arg, &mut out).is_err() {
                    assert_eq!(out, b"kept", "a failed decryption releases nothing");
                }
                let _ = mls_receiver.decrypt(METADATA, arg);
                let _ = ratchet_receiver.decrypt(METADATA, arg);
                let _ = pending.push(METADATA, arg);
                let _ = pending.take(kid);
            }
            1 => {
                let ciphertext = sender.encrypt(kid, METADATA, arg).unwrap();
                let header = receiver
                    .decrypt_into(METADATA, &ciphertext, &mut out)
                    .expect("a fresh ciphertext decrypts");
                assert_eq!(header.kid, kid);
                assert_eq!(&out[4..], arg);
                if accepted.len() < 16 {
                    accepted.push((ciphertext, arg.to_vec()));
                }
            }
            2 => {
                let Some((&position, plaintext)) = arg.split_first() else {
                    continue;
                };
                let mut ciphertext = sender.encrypt(kid, METADATA, plaintext).unwrap();
                let index = usize::from(position) % ciphertext.len();
                ciphertext[index] ^= 1 << (position >> 5);
                let result = receiver.decrypt_into(METADATA, &ciphertext, &mut out);
                // A 32-bit tag is matched by chance once in 2^32 tries, which a fuzzing
                // campaign reaches; the longer tags are not.
                if suite.tag_len() >= 8 {
                    assert!(result.is_err(), "an altered ciphertext is refused");
                }
                if result.is_err() {
                    assert_eq!(out, b"kept");
                }
            }
            3 => {
                let Some((ciphertext, plaintext)) = arg
                    .first()
                    .filter(|_| !accepted.is_empty())
                    .map(|pick| &accepted[usize::from(*pick) % accepted.len()])
                else {
                    continue;
                };
                let result = receiver.decrypt(METADATA, ciphertext);
                if replay_protected {
                    assert!(
                        matches!(result, Err(Error::Replayed { .. })),
                        "a replay is refused under a replay window"
                    );
                } else {
                    assert_eq!(result.as_ref(), Ok(plaintext));
                }
            }
            4 => {
                // The window of a key that is added again starts over: forget what it accepted.
                receiver.remove_key(kid);
                assert_eq!(
                    receiver.decrypt(METADATA, &sender.encrypt(kid, METADATA, arg).unwrap()),
                    Err(Error::UnknownKeyId(kid))
                );
                receiver.add_recv_key(kid, &base_key(kid)).unwrap();
                accepted.retain(|(ciphertext, _)| {
                    Header::decode(ciphertext).map(|(header, _)| header.kid) != Ok(kid)
                });
            }
            5 => {
                let ciphertext = mls_sender.encrypt(14, u64::from(op >> 4), METADATA, arg);
                let ciphertext = ciphertext.unwrap();
                assert_eq!(
                    mls_receiver.decrypt(METADATA, &ciphertext).as_deref(),
                    Ok(arg)
                );
                assert_eq!(
                    mls_sender.decrypt(METADATA, &ciphertext),
                    Err(Error::KeyRoleConflict(
                        Header::decode(&ciphertext).unwrap().0.kid
                    ))
                );
            }
            _ => {
                // A ratchet step on the sender, at most as far as the receiver follows at once.
                for _ in 0..=(op >> 4) % 3 {
                    let previous = ratchet.key_id();
                    let next = ratchet.advance().unwrap();
                    ratchet_sender.remove_key(previous);
                    ratchet_sender
                        .add_send_key(next, ratchet.base_key())
                        .unwrap();
                }
                let ciphertext = ratchet_sender
                    .encrypt(ratchet.key_id(), METADATA, arg)
                    .unwrap();
                assert_eq!(
                    ratchet_receiver.decrypt(METADATA, &ciphertext).as_deref(),
                    Ok(arg)
                );
                assert_eq!(ratchet_receiver.current_key_id(), Some(ratchet.key_id()));
            }
        }
    }
}
