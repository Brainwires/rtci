use crate::aead::SuiteAead;
use crate::kdf::derive_key_salt;
use crate::test_util::{hex, provider};
use crate::test_vectors::{
    AES_256_CTR, BASE_KEY, CTR, KID, METADATA, PLAINTEXT, RFC9605_C3, SFrameVector,
};
use crate::{
    CipherSuite, Error, ErrorKind, Header, KeyUsage, MAX_HEADER_LEN, PendingCiphertexts,
    SFrameConfig, SFrameContext, SFrameStats,
};

const KEY: &[u8] = b"an SFrame base key";

fn context(suite: CipherSuite) -> SFrameContext {
    SFrameContext::new(suite, provider())
}

fn context_with(suite: CipherSuite, config: SFrameConfig) -> SFrameContext {
    SFrameContext::with_config(suite, provider(), config)
}

fn without_replay_protection() -> SFrameConfig {
    SFrameConfig {
        replay_window: None,
        ..SFrameConfig::default()
    }
}

/// A sender with `KEY` under `kid` and a receiver holding it for decryption.
fn pair(suite: CipherSuite, kid: u64) -> (SFrameContext, SFrameContext) {
    let mut sender = context(suite);
    sender.add_send_key(kid, KEY).unwrap();
    let mut receiver = context(suite);
    receiver.add_recv_key(kid, KEY).unwrap();
    (sender, receiver)
}

fn assert_encrypts_to_the_vector(vector: &SFrameVector) {
    let suite = vector.suite;
    let mut sender = context(suite);
    sender.add_send_key_at(KID, &hex(BASE_KEY), CTR).unwrap();
    // encrypt(ctr, kid, metadata, plaintext) == ct
    let ciphertext = sender
        .encrypt(KID, &hex(METADATA), &hex(PLAINTEXT))
        .unwrap();
    assert_eq!(ciphertext, hex(vector.ct), "{suite}");
    assert_eq!(sender.next_counter(KID), Some(CTR + 1));
}

fn assert_decrypts_the_vector(vector: &SFrameVector) {
    let suite = vector.suite;
    let mut receiver = context(suite);
    receiver.add_recv_key(KID, &hex(BASE_KEY)).unwrap();
    // decrypt(metadata, ct) == pt
    let mut out = Vec::new();
    let header = receiver
        .decrypt_into(&hex(METADATA), &hex(vector.ct), &mut out)
        .unwrap();
    assert_eq!(out, hex(PLAINTEXT), "{suite}");
    assert_eq!(header, Header::new(KID, CTR));
}

#[test]
fn rfc9605_c3_every_suite_encrypts_to_the_given_sframe_ciphertext() {
    assert_eq!(RFC9605_C3.len(), 5);
    for vector in RFC9605_C3 {
        assert_encrypts_to_the_vector(vector);
    }
}

#[test]
fn rfc9605_c3_every_suite_decrypts_the_given_sframe_ciphertext() {
    for vector in RFC9605_C3 {
        assert_decrypts_the_vector(vector);
    }
}

#[test]
fn aes_256_ctr_suites_encrypt_and_decrypt_the_registry_vectors() {
    assert_eq!(AES_256_CTR.len(), 3);
    for vector in AES_256_CTR {
        assert_encrypts_to_the_vector(vector);
        assert_decrypts_the_vector(vector);
    }
}

#[test]
fn cipher_suites_have_their_registry_values_and_names() {
    // RFC 9605 section 8.1 (0x0001 to 0x0005) and RFC 10079 section 4.2 (0x0006 to 0x0008).
    let registry = [
        (0x0001, "AES_128_CTR_HMAC_SHA256_80"),
        (0x0002, "AES_128_CTR_HMAC_SHA256_64"),
        (0x0003, "AES_128_CTR_HMAC_SHA256_32"),
        (0x0004, "AES_128_GCM_SHA256_128"),
        (0x0005, "AES_256_GCM_SHA512_128"),
        (0x0006, "AES_256_CTR_HMAC_SHA512_80"),
        (0x0007, "AES_256_CTR_HMAC_SHA512_64"),
        (0x0008, "AES_256_CTR_HMAC_SHA512_32"),
    ];
    assert_eq!(registry.len(), CipherSuite::ALL.len());
    for (id, name) in registry {
        let suite = CipherSuite::from_id(id).unwrap();
        assert_eq!(suite.id(), id);
        assert_eq!(suite.name(), name);
        assert_eq!(suite.to_string(), name);
        assert_eq!(name.parse::<CipherSuite>(), Ok(suite));
        assert_eq!(CipherSuite::try_from(id), Ok(suite));
        assert_eq!(u16::from(suite), id);
    }
    // Reserved, unassigned and private-use values name no suite.
    for id in [0x0000, 0x0009, 0xf000, 0xffff] {
        assert_eq!(CipherSuite::from_id(id), None);
    }
    assert!("aes_128_gcm_sha256_128".parse::<CipherSuite>().is_err());
}

/// RFC 10079 section 4.1, Tables 1 and 2: the registry's columns `Nh`, `Nka` (none for the GCM
/// suites), `Nk`, `Nn` and `Nt` for every suite.
#[test]
fn cipher_suites_have_the_registry_columns_of_rfc10079() {
    let registry: [(u16, usize, Option<usize>, usize, usize, usize); 8] = [
        (0x0001, 32, Some(16), 48, 12, 10),
        (0x0002, 32, Some(16), 48, 12, 8),
        (0x0003, 32, Some(16), 48, 12, 4),
        (0x0004, 32, None, 16, 12, 16),
        (0x0005, 64, None, 32, 12, 16),
        (0x0006, 64, Some(32), 96, 12, 10),
        (0x0007, 64, Some(32), 96, 12, 8),
        (0x0008, 64, Some(32), 96, 12, 4),
    ];
    assert_eq!(registry.len(), CipherSuite::ALL.len());
    for (id, nh, nka, nk, nn, nt) in registry {
        let suite = CipherSuite::from_id(id).unwrap();
        assert_eq!(
            (
                suite.hash_len(),
                suite.aes_ctr_key_len(),
                suite.key_len(),
                suite.nonce_len(),
                suite.tag_len()
            ),
            (nh, nka, nk, nn, nt),
            "{suite}"
        );
    }
}

#[test]
fn every_suite_round_trips_and_adds_only_header_and_tag() {
    for suite in CipherSuite::ALL {
        for kid in [0u64, 7, 8, 0xffff, u64::MAX] {
            let (mut sender, mut receiver) = pair(suite, kid);
            for (index, len) in [0usize, 1, 15, 16, 17, 1200, 70_000]
                .into_iter()
                .enumerate()
            {
                let plaintext: Vec<u8> = (0..len).map(|i| (i * 7 + index) as u8).collect();
                let metadata = &b"layer 2, key frame"[..index.min(18)];
                let ciphertext = sender.encrypt(kid, metadata, &plaintext).unwrap();

                let header = Header::new(kid, index as u64);
                assert_eq!(
                    ciphertext.len(),
                    header.encoded_len() + len + suite.tag_len(),
                    "{suite}"
                );
                assert!(ciphertext.len() <= len + sender.max_overhead());
                assert_eq!(
                    Header::decode(&ciphertext),
                    Ok((header, header.encoded_len()))
                );
                if len >= 16 {
                    assert!(!ciphertext.windows(16).any(|w| w == &plaintext[..16]));
                }
                assert_eq!(
                    receiver.decrypt(metadata, &ciphertext).as_deref(),
                    Ok(&plaintext[..]),
                    "{suite}, kid {kid:#x}, {len} bytes"
                );
            }
        }
    }
}

#[test]
fn encrypt_into_and_decrypt_into_append_to_the_callers_buffer() {
    let (mut sender, mut receiver) = pair(CipherSuite::Aes128GcmSha256_128, 3);
    let mut wire = b"prefix".to_vec();
    let first = sender.encrypt_into(3, b"m", b"one", &mut wire).unwrap();
    let boundary = wire.len();
    let second = sender.encrypt_into(3, b"m", b"two", &mut wire).unwrap();
    assert_eq!((first, second), (Header::new(3, 0), Header::new(3, 1)));
    assert_eq!(&wire[..6], b"prefix");

    let mut plain = b"out:".to_vec();
    receiver
        .decrypt_into(b"m", &wire[6..boundary], &mut plain)
        .unwrap();
    receiver
        .decrypt_into(b"m", &wire[boundary..], &mut plain)
        .unwrap();
    assert_eq!(plain, b"out:onetwo");
}

#[test]
fn decrypt_refuses_a_wrong_tag_and_releases_nothing() {
    for vector in RFC9605_C3.iter().chain(AES_256_CTR) {
        let suite = vector.suite;
        let ct = hex(vector.ct);
        let mut receiver = context(suite);
        receiver.add_recv_key(KID, &hex(BASE_KEY)).unwrap();

        for index in ct.len() - suite.tag_len()..ct.len() {
            let mut forged = ct.clone();
            forged[index] ^= 0x01;
            let mut out = b"kept".to_vec();
            let error = receiver
                .decrypt_into(&hex(METADATA), &forged, &mut out)
                .unwrap_err();
            assert_eq!(error, Error::AuthenticationFailed, "{suite}");
            assert_eq!(error.kind(), Some(ErrorKind::Authentication));
            assert_eq!(out, b"kept", "{suite}: no plaintext of a forged frame");
        }
        // The failures did not use up the counter: the authentic frame still decrypts.
        assert_eq!(
            receiver.decrypt(&hex(METADATA), &ct),
            Ok(hex(PLAINTEXT)),
            "{suite}"
        );
        assert_eq!(
            receiver.stats().authentication_failures,
            suite.tag_len() as u64
        );
    }
}

#[test]
fn decrypt_refuses_altered_encrypted_data_header_and_metadata() {
    for vector in RFC9605_C3.iter().chain(AES_256_CTR) {
        let suite = vector.suite;
        let ct = hex(vector.ct);
        let metadata = hex(METADATA);
        let mut receiver = context(suite);
        receiver.add_recv_key(KID, &hex(BASE_KEY)).unwrap();
        // The same key under the KID that one flipped header bit leads to.
        receiver.add_recv_key(KID ^ 1, &hex(BASE_KEY)).unwrap();

        // Header: 99 0123 4567. Encrypted data follows.
        for index in 5..ct.len() - suite.tag_len() {
            let mut altered = ct.clone();
            altered[index] ^= 0x80;
            assert_eq!(
                receiver.decrypt(&metadata, &altered),
                Err(Error::AuthenticationFailed),
                "{suite}: data byte {index}"
            );
        }
        // Another CTR (the nonce and the AAD change), another KID (another key).
        for index in [2, 3, 4] {
            let mut altered = ct.clone();
            altered[index] ^= 0x01;
            assert_eq!(
                receiver.decrypt(&metadata, &altered),
                Err(Error::AuthenticationFailed),
                "{suite}: header byte {index}"
            );
        }
        // The metadata is authenticated though it is not in the ciphertext (section 9.4).
        let mut other = metadata.clone();
        other[0] ^= 0x01;
        for wrong in [&other[..], &metadata[1..], &[][..]] {
            let mut out = Vec::new();
            assert_eq!(
                receiver.decrypt_into(wrong, &ct, &mut out),
                Err(Error::AuthenticationFailed),
                "{suite}"
            );
            assert!(out.is_empty());
        }
        assert_eq!(receiver.decrypt(&metadata, &ct), Ok(hex(PLAINTEXT)));
    }
}

#[test]
fn decrypt_reports_an_unknown_kid_with_its_value() {
    for vector in RFC9605_C3 {
        let ct = hex(vector.ct);
        let mut receiver = context(vector.suite);
        receiver.add_recv_key(KID + 1, &hex(BASE_KEY)).unwrap();

        let error = receiver.decrypt(&hex(METADATA), &ct).unwrap_err();
        assert_eq!(error, Error::UnknownKeyId(KID));
        assert_eq!(error.kind(), Some(ErrorKind::KeyId));
        assert_eq!(error.key_id(), Some(KID));
        assert_eq!(receiver.stats().unknown_key_ids, 1);
    }
}

#[test]
fn decrypt_refuses_a_key_other_than_the_senders() {
    for suite in CipherSuite::ALL {
        let mut sender = context(suite);
        sender.add_send_key(9, KEY).unwrap();
        let ciphertext = sender.encrypt(9, b"", b"frame").unwrap();

        let mut receiver = context(suite);
        receiver.add_recv_key(9, b"another base key").unwrap();
        assert_eq!(
            receiver.decrypt(b"", &ciphertext),
            Err(Error::AuthenticationFailed)
        );
    }
    // The cipher suite is part of the key derivation: the same base key under another suite
    // with the same primitives does not decrypt.
    let mut sender = context(CipherSuite::Aes128CtrHmacSha256_80);
    sender.add_send_key(9, KEY).unwrap();
    let mut ciphertext = sender.encrypt(9, b"", b"frame").unwrap();
    ciphertext.truncate(ciphertext.len() - 2);
    let mut receiver = context(CipherSuite::Aes128CtrHmacSha256_64);
    receiver.add_recv_key(9, KEY).unwrap();
    assert_eq!(
        receiver.decrypt(b"", &ciphertext),
        Err(Error::AuthenticationFailed)
    );
}

#[test]
fn decrypt_refuses_every_truncation() {
    for vector in RFC9605_C3.iter().chain(AES_256_CTR) {
        let suite = vector.suite;
        let ct = hex(vector.ct);
        let mut receiver = context(suite);
        receiver.add_recv_key(KID, &hex(BASE_KEY)).unwrap();

        for len in 0..ct.len() {
            let mut out = Vec::new();
            let error = receiver
                .decrypt_into(&hex(METADATA), &ct[..len], &mut out)
                .unwrap_err();
            let expected = if len < 5 {
                // Inside the header (config byte, 2-byte KID, 2-byte CTR).
                Error::TruncatedHeader
            } else if len < 5 + suite.tag_len() {
                Error::TruncatedCiphertext
            } else {
                Error::AuthenticationFailed
            };
            assert_eq!(error, expected, "{suite}: cut to {len} bytes");
            if len < 5 + suite.tag_len() {
                assert_eq!(error.kind(), Some(ErrorKind::Syntax));
            }
            assert!(out.is_empty());
        }
        assert_eq!(receiver.stats().syntax_errors, 5 + suite.tag_len() as u64);
    }
}

#[test]
fn decrypt_refuses_a_non_minimal_header_unless_configured_to_accept_it() {
    // A sender that pads its CTR: the header 19 0000 carries KID 1 inline and CTR 0 in two bytes.
    // Its ciphertext is authentic over the bytes it sent.
    let suite = CipherSuite::Aes128CtrHmacSha256_80;
    let provider = provider();
    let derived = derive_key_salt(provider.crypto(), suite, 1, KEY).unwrap();
    let mut aead = SuiteAead::new(provider.crypto(), suite, &derived.key).unwrap();
    let header = [0x19, 0x00, 0x00];
    let mut data = b"padded".to_vec();
    let mut tag = vec![0u8; suite.tag_len()];
    aead.seal(
        &derived.salt,
        &header,
        b"",
        &mut Vec::new(),
        &mut data,
        &mut tag,
    )
    .unwrap();
    let ciphertext = [&header[..], &data, &tag].concat();

    let mut strict = context(suite);
    strict.add_recv_key(1, KEY).unwrap();
    let error = strict.decrypt(b"", &ciphertext).unwrap_err();
    assert_eq!(error, Error::NonMinimalHeader);
    assert_eq!(error.kind(), Some(ErrorKind::Syntax));

    let mut lenient = context_with(
        suite,
        SFrameConfig {
            allow_non_minimal_headers: true,
            ..SFrameConfig::default()
        },
    );
    lenient.add_recv_key(1, KEY).unwrap();
    assert_eq!(
        lenient.decrypt(b"", &ciphertext).as_deref(),
        Ok(&b"padded"[..])
    );

    // Re-encoding the header to its minimal form does not validate: the tag covers the bytes
    // that were sent.
    let reencoded = [&[0x10][..], &data, &tag].concat();
    assert_eq!(
        lenient.decrypt(b"", &reencoded),
        Err(Error::AuthenticationFailed)
    );
}

#[test]
fn sender_uses_each_counter_once_and_in_order() {
    for suite in CipherSuite::ALL {
        let (mut sender, _) = pair(suite, 2);
        assert_eq!(sender.next_counter(2), Some(0));
        let mut seen = Vec::new();
        for expected_ctr in 0..300u64 {
            // The same plaintext every time: only the counter makes the ciphertexts differ.
            let ciphertext = sender.encrypt(2, b"", b"same frame").unwrap();
            let (header, _) = Header::decode(&ciphertext).unwrap();
            assert_eq!(header, Header::new(2, expected_ctr));
            assert!(
                !seen.contains(&ciphertext),
                "{suite}: a ciphertext repeated"
            );
            seen.push(ciphertext);
            assert_eq!(sender.next_counter(2), Some(expected_ctr + 1));
        }
        assert_eq!(sender.stats().encrypted, 300);
    }
}

#[test]
fn sender_refuses_to_restart_a_keys_counter() {
    let mut sender = context(CipherSuite::Aes128GcmSha256_128);
    sender.add_send_key(4, KEY).unwrap();
    let first = sender.encrypt(4, b"", b"frame").unwrap();

    // Installing the key again would bring the counter back to 0 and repeat the nonce.
    assert_eq!(sender.add_send_key(4, KEY), Err(Error::KeyReuse(4)));
    assert_eq!(sender.add_send_key_at(4, KEY, 0), Err(Error::KeyReuse(4)));
    assert_eq!(Error::KeyReuse(4).key_id(), Some(4));
    let second = sender.encrypt(4, b"", b"frame").unwrap();
    assert_eq!(Header::decode(&second).unwrap().0, Header::new(4, 1));
    assert_ne!(first, second);

    // Another key under the same KID is a new key, with its own counter.
    sender.add_send_key(4, b"the next base key").unwrap();
    assert_eq!(sender.next_counter(4), Some(0));
}

#[test]
fn sender_stops_when_the_counter_is_exhausted() {
    for suite in [
        CipherSuite::Aes128CtrHmacSha256_32,
        CipherSuite::Aes256GcmSha512_128,
    ] {
        let mut sender = context(suite);
        sender.add_send_key_at(6, KEY, u64::MAX - 1).unwrap();
        let mut receiver = context(suite);
        receiver.add_recv_key(6, KEY).unwrap();

        for ctr in [u64::MAX - 1, u64::MAX] {
            let ciphertext = sender.encrypt(6, b"", b"late frame").unwrap();
            assert_eq!(Header::decode(&ciphertext).unwrap().0, Header::new(6, ctr));
            assert_eq!(ciphertext.len(), MAX_HEADER_LEN - 8 + 10 + suite.tag_len());
            assert_eq!(
                receiver.decrypt(b"", &ciphertext).as_deref(),
                Ok(&b"late frame"[..])
            );
        }
        // Every counter value has been used: one more would repeat a nonce.
        assert_eq!(sender.next_counter(6), None);
        let mut out = b"kept".to_vec();
        assert_eq!(
            sender.encrypt_into(6, b"", b"one too many", &mut out),
            Err(Error::CounterExhausted(6))
        );
        assert_eq!(out, b"kept");
        assert_eq!(
            sender.encrypt(6, b"", b"still refused"),
            Err(Error::CounterExhausted(6))
        );
    }
}

#[test]
fn resumed_sender_continues_from_the_stored_counter() {
    let suite = CipherSuite::Aes128CtrHmacSha256_64;
    let (mut sender, mut receiver) = pair(suite, 1);
    for _ in 0..3 {
        let ciphertext = sender.encrypt(1, b"", b"before").unwrap();
        receiver.decrypt(b"", &ciphertext).unwrap();
    }
    let stored = sender.next_counter(1).unwrap();
    drop(sender);

    let mut resumed = context(suite);
    resumed.add_send_key_at(1, KEY, stored).unwrap();
    let ciphertext = resumed.encrypt(1, b"", b"after").unwrap();
    assert_eq!(Header::decode(&ciphertext).unwrap().0, Header::new(1, 3));
    assert_eq!(
        receiver.decrypt(b"", &ciphertext).as_deref(),
        Ok(&b"after"[..])
    );
}

#[test]
fn a_key_is_usable_for_encryption_or_decryption_never_both() {
    for suite in CipherSuite::ALL {
        let mut context = context(suite);
        context.add_send_key(1, KEY).unwrap();
        context.add_recv_key(2, KEY).unwrap();
        assert_eq!(context.key_usage(1), Some(KeyUsage::Encrypt));
        assert_eq!(context.key_usage(2), Some(KeyUsage::Decrypt));
        assert_eq!(context.key_usage(3), None);
        assert_eq!(context.key_count(), 2);

        // A KID's role cannot be changed, with the same key or another.
        assert_eq!(context.add_recv_key(1, KEY), Err(Error::KeyRoleConflict(1)));
        assert_eq!(
            context.add_recv_key(1, b"other"),
            Err(Error::KeyRoleConflict(1))
        );
        assert_eq!(context.add_send_key(2, KEY), Err(Error::KeyRoleConflict(2)));
        assert_eq!(context.key_usage(1), Some(KeyUsage::Encrypt));
        assert_eq!(context.key_usage(2), Some(KeyUsage::Decrypt));

        // A decryption key does not encrypt.
        assert_eq!(
            context.encrypt(2, b"", b"frame"),
            Err(Error::KeyRoleConflict(2))
        );
        assert_eq!(context.next_counter(2), None);
        assert_eq!(
            context.encrypt(3, b"", b"frame"),
            Err(Error::UnknownKeyId(3))
        );

        // An encryption key does not decrypt: a sender's own frame, reflected back, is refused.
        let own = context.encrypt(1, b"", b"frame").unwrap();
        let error = context.decrypt(b"", &own).unwrap_err();
        assert_eq!(error, Error::KeyRoleConflict(1), "{suite}");
        assert_eq!(error.kind(), Some(ErrorKind::KeyId));
    }
}

#[test]
fn removed_key_no_longer_encrypts_or_decrypts() {
    let (mut sender, mut receiver) = pair(CipherSuite::Aes128GcmSha256_128, 5);
    let ciphertext = sender.encrypt(5, b"", b"frame").unwrap();

    assert!(receiver.remove_key(5));
    assert!(!receiver.remove_key(5));
    assert_eq!(
        receiver.decrypt(b"", &ciphertext),
        Err(Error::UnknownKeyId(5))
    );
    assert!(sender.remove_key(5));
    assert_eq!(
        sender.encrypt(5, b"", b"frame"),
        Err(Error::UnknownKeyId(5))
    );

    let mut context = context(CipherSuite::Aes128GcmSha256_128);
    for kid in 0..8 {
        context.add_recv_key(kid, KEY).unwrap();
    }
    context.retain_keys(|kid| kid % 2 == 0);
    assert_eq!(context.key_count(), 4);
    assert_eq!(context.key_usage(3), None);
    assert_eq!(context.key_usage(4), Some(KeyUsage::Decrypt));
}

#[test]
fn receiver_accepts_each_counter_once() {
    for suite in CipherSuite::ALL {
        let (mut sender, mut receiver) = pair(suite, 1);
        let frames: Vec<Vec<u8>> = (0..10u8)
            .map(|n| sender.encrypt(1, b"", &[n; 4]).unwrap())
            .collect();

        // Out of order inside the window is fine, each once.
        for index in [3usize, 0, 2, 9, 1] {
            assert_eq!(
                receiver.decrypt(b"", &frames[index]),
                Ok(vec![index as u8; 4]),
                "{suite}"
            );
        }
        for index in [3usize, 0, 2, 9, 1] {
            let mut out = b"kept".to_vec();
            let error = receiver
                .decrypt_into(b"", &frames[index], &mut out)
                .unwrap_err();
            assert_eq!(
                error,
                Error::Replayed {
                    kid: 1,
                    ctr: index as u64
                },
                "{suite}"
            );
            assert_eq!(error.kind(), None);
            assert_eq!(out, b"kept", "a replayed frame releases nothing");
        }
        // The ones not seen yet are still accepted.
        for index in [4usize, 8, 5, 7, 6] {
            assert_eq!(
                receiver.decrypt(b"", &frames[index]),
                Ok(vec![index as u8; 4])
            );
        }
        assert_eq!(
            receiver.stats(),
            SFrameStats {
                decrypted: 10,
                replays: 5,
                ..SFrameStats::default()
            }
        );
    }
}

#[test]
fn receiver_refuses_counters_older_than_the_replay_window() {
    let suite = CipherSuite::Aes128CtrHmacSha256_80;
    let mut sender = context(suite);
    sender.add_send_key(1, KEY).unwrap();
    let mut receiver = context_with(
        suite,
        SFrameConfig {
            replay_window: Some(64),
            ..SFrameConfig::default()
        },
    );
    receiver.add_recv_key(1, KEY).unwrap();

    let frames: Vec<Vec<u8>> = (0..200u8)
        .map(|n| sender.encrypt(1, b"", &[n]).unwrap())
        .collect();
    // Counter 0 is held back; 1 to 63 arrive, so 0 is still inside a window of 64.
    for frame in &frames[1..64] {
        receiver.decrypt(b"", frame).unwrap();
    }
    assert_eq!(receiver.decrypt(b"", &frames[0]), Ok(vec![0]));

    // 64 is held back; the stream moves on to 128, which puts 64 (128 - 64) just outside.
    for frame in &frames[65..=128] {
        receiver.decrypt(b"", frame).unwrap();
    }
    assert_eq!(
        receiver.decrypt(b"", &frames[64]),
        Err(Error::Replayed { kid: 1, ctr: 64 })
    );
    // A jump far ahead empties the window; what lies behind it is refused, what follows is
    // accepted, once.
    assert_eq!(receiver.decrypt(b"", &frames[199]), Ok(vec![199]));
    assert_eq!(
        receiver.decrypt(b"", &frames[130]),
        Err(Error::Replayed { kid: 1, ctr: 130 })
    );
    assert_eq!(receiver.decrypt(b"", &frames[150]), Ok(vec![150]));
    assert_eq!(
        receiver.decrypt(b"", &frames[150]),
        Err(Error::Replayed { kid: 1, ctr: 150 })
    );
    assert_eq!(
        receiver.decrypt(b"", &frames[199]),
        Err(Error::Replayed { kid: 1, ctr: 199 })
    );
}

#[test]
fn replay_windows_are_per_key() {
    let suite = CipherSuite::Aes128GcmSha256_128;
    let mut sender = context(suite);
    let mut receiver = context(suite);
    for kid in [1, 2] {
        sender.add_send_key(kid, KEY).unwrap();
        receiver.add_recv_key(kid, KEY).unwrap();
    }
    // Both keys use counter 0: they are different (key, nonce) pairs.
    let one = sender.encrypt(1, b"", b"one").unwrap();
    let two = sender.encrypt(2, b"", b"two").unwrap();
    assert_eq!(receiver.decrypt(b"", &one).as_deref(), Ok(&b"one"[..]));
    assert_eq!(receiver.decrypt(b"", &two).as_deref(), Ok(&b"two"[..]));
    assert!(matches!(
        receiver.decrypt(b"", &one),
        Err(Error::Replayed { kid: 1, ctr: 0 })
    ));

    // Adding the key a KID already decrypts with keeps what it has accepted.
    receiver.add_recv_key(1, KEY).unwrap();
    assert!(matches!(
        receiver.decrypt(b"", &one),
        Err(Error::Replayed { kid: 1, ctr: 0 })
    ));
}

#[test]
fn a_forged_frame_does_not_use_up_its_counter() {
    let (mut sender, mut receiver) = pair(CipherSuite::Aes128CtrHmacSha256_32, 1);
    let authentic = sender.encrypt(1, b"", b"frame").unwrap();
    let mut forged = authentic.clone();
    *forged.last_mut().unwrap() ^= 0xff;

    assert_eq!(
        receiver.decrypt(b"", &forged),
        Err(Error::AuthenticationFailed)
    );
    assert_eq!(
        receiver.decrypt(b"", &authentic).as_deref(),
        Ok(&b"frame"[..])
    );
}

#[test]
fn without_a_replay_window_a_frame_decrypts_every_time() {
    let suite = CipherSuite::Aes128GcmSha256_128;
    let mut sender = context(suite);
    sender.add_send_key(1, KEY).unwrap();
    let mut receiver = context_with(suite, without_replay_protection());
    receiver.add_recv_key(1, KEY).unwrap();

    let ciphertext = sender.encrypt(1, b"", b"frame").unwrap();
    for _ in 0..3 {
        assert_eq!(
            receiver.decrypt(b"", &ciphertext).as_deref(),
            Ok(&b"frame"[..])
        );
    }
    assert_eq!(receiver.stats().replays, 0);
}

#[test]
fn a_ciphertext_whose_key_arrives_later_can_be_decrypted_then() {
    for suite in CipherSuite::ALL {
        let mut sender = context(suite);
        sender.add_send_key(8, KEY).unwrap();
        sender.add_send_key(9, KEY).unwrap();
        let mut receiver = context(suite);
        let mut pending = PendingCiphertexts::new(8, 4096);

        let early: Vec<Vec<u8>> = (0..3u8)
            .map(|n| sender.encrypt(8, b"meta", &[n; 3]).unwrap())
            .collect();
        let other = sender.encrypt(9, b"meta", b"other").unwrap();
        for ciphertext in early.iter().chain([&other]) {
            // No key yet: the failure says which, and the ciphertext is untouched.
            let kid = Header::decode(ciphertext).unwrap().0.kid;
            assert_eq!(
                receiver.decrypt(b"meta", ciphertext),
                Err(Error::UnknownKeyId(kid))
            );
            assert_eq!(pending.push(b"meta", ciphertext), Ok(Some(kid)));
        }
        assert_eq!(pending.len(), 4);

        // The key arrives: what waited for it decrypts, in order; the rest keeps waiting.
        receiver.add_recv_key(8, KEY).unwrap();
        let waiting = pending.take(8);
        assert_eq!(waiting.len(), 3);
        for (n, entry) in waiting.iter().enumerate() {
            assert_eq!(entry.kid, 8);
            assert_eq!(
                receiver.decrypt(&entry.metadata, &entry.ciphertext),
                Ok(vec![n as u8; 3]),
                "{suite}"
            );
        }
        assert_eq!(pending.len(), 1);
        assert!(pending.take(8).is_empty());
    }
}

#[test]
fn pending_store_is_bounded_in_frames_and_bytes() {
    // 16 bytes each: a 1-byte header, 11 bytes of body, 4 bytes of metadata.
    let frame = |kid: u8| [&[kid << 4][..], &[0xab; 11]].concat();

    let mut by_count = PendingCiphertexts::new(3, 1 << 20);
    for kid in 0..5 {
        assert_eq!(
            by_count.push(b"meta", &frame(kid)),
            Ok(Some(u64::from(kid)))
        );
    }
    assert_eq!(by_count.len(), 3);
    assert!(by_count.take(0).is_empty() && by_count.take(1).is_empty());
    assert_eq!(by_count.take(2).len(), 1);

    let mut by_bytes = PendingCiphertexts::new(100, 40);
    for kid in 0..5 {
        by_bytes.push(b"meta", &frame(kid)).unwrap();
        assert!(by_bytes.bytes() <= 40);
    }
    assert_eq!((by_bytes.len(), by_bytes.bytes()), (2, 32));
    assert_eq!(by_bytes.take(4).len(), 1);
    assert_eq!((by_bytes.len(), by_bytes.bytes()), (1, 16));

    // A ciphertext larger than the store is not kept, and evicts nothing.
    assert_eq!(by_bytes.push(b"meta", &[0x10; 64]), Ok(None));
    assert_eq!(by_bytes.len(), 1);
    // One that has no header can never be decrypted.
    assert_eq!(by_bytes.push(b"meta", &[]), Err(Error::TruncatedHeader));
    assert_eq!(by_bytes.push(b"meta", &[0x80]), Err(Error::TruncatedHeader));

    by_bytes.discard_oldest(5);
    assert!(by_bytes.is_empty());
    assert_eq!(by_bytes.bytes(), 0);
    by_count.clear();
    assert!(by_count.is_empty());
    assert_eq!(PendingCiphertexts::new(0, 100).push(b"", &[0x00]), Ok(None));
}

#[test]
fn adding_a_key_refuses_an_empty_base_key() {
    let mut context = context(CipherSuite::Aes128GcmSha256_128);
    assert_eq!(context.add_send_key(1, &[]), Err(Error::EmptyBaseKey));
    assert_eq!(context.add_recv_key(1, &[]), Err(Error::EmptyBaseKey));
    assert_eq!(context.key_count(), 0);
}

#[test]
fn base_keys_of_any_length_are_accepted() {
    // HKDF takes input keying material of any length; an MLS exporter gives Nk bytes.
    for suite in CipherSuite::ALL {
        for len in [1, 16, suite.key_len(), 200] {
            let base_key = vec![0x42; len];
            let mut sender = context(suite);
            sender.add_send_key(1, &base_key).unwrap();
            let mut receiver = context(suite);
            receiver.add_recv_key(1, &base_key).unwrap();
            let ciphertext = sender.encrypt(1, b"", b"frame").unwrap();
            assert_eq!(
                receiver.decrypt(b"", &ciphertext).as_deref(),
                Ok(&b"frame"[..])
            );
        }
    }
}

// ---- Invalid ciphertexts cost what valid ones do (RFC 9605 section 4.4.4) ----

mod counting {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crypto::{
        AeadAlgorithm, AeadCipher, CryptoAlgorithm, CryptoError, HmacAlgorithm, Mac, RTCCrypto,
        RTCCryptoProvider, RTCRandom, StreamCipher, StreamCipherAlgorithm,
    };

    /// The symmetric work a provider was asked to do.
    #[derive(Default)]
    pub(super) struct Work {
        mac_bytes: AtomicU64,
        mac_calls: AtomicU64,
        cipher_bytes: AtomicU64,
        cipher_calls: AtomicU64,
    }

    impl Work {
        /// (MAC calls, bytes authenticated, cipher calls, bytes en- or decrypted) since the
        /// last call.
        pub(super) fn take(&self) -> (u64, u64, u64, u64) {
            (
                self.mac_calls.swap(0, Ordering::Relaxed),
                self.mac_bytes.swap(0, Ordering::Relaxed),
                self.cipher_calls.swap(0, Ordering::Relaxed),
                self.cipher_bytes.swap(0, Ordering::Relaxed),
            )
        }
    }

    /// The built-in provider, with every MAC, stream-cipher and AEAD operation counted.
    pub(super) struct CountingProvider {
        pub(super) inner: Arc<dyn RTCCryptoProvider>,
        pub(super) work: Arc<Work>,
    }

    impl RTCCryptoProvider for CountingProvider {
        fn name(&self) -> &'static str {
            "counting"
        }

        fn crypto(&self) -> &dyn RTCCrypto {
            self
        }

        fn random(&self) -> &dyn RTCRandom {
            self.inner.random()
        }
    }

    impl RTCCrypto for CountingProvider {
        fn supports(&self, algorithm: CryptoAlgorithm) -> bool {
            self.inner.crypto().supports(algorithm)
        }

        fn new_hmac(
            &self,
            algorithm: HmacAlgorithm,
            key: &[u8],
        ) -> Result<Box<dyn Mac>, CryptoError> {
            Ok(Box::new(Counted {
                inner: self.inner.crypto().new_hmac(algorithm, key)?,
                work: self.work.clone(),
            }))
        }

        fn new_stream_cipher(
            &self,
            algorithm: StreamCipherAlgorithm,
            key: &[u8],
        ) -> Result<Box<dyn StreamCipher>, CryptoError> {
            Ok(Box::new(Counted {
                inner: self.inner.crypto().new_stream_cipher(algorithm, key)?,
                work: self.work.clone(),
            }))
        }

        fn new_aead(
            &self,
            algorithm: AeadAlgorithm,
            key: &[u8],
        ) -> Result<Box<dyn AeadCipher>, CryptoError> {
            Ok(Box::new(Counted {
                inner: self.inner.crypto().new_aead(algorithm, key)?,
                work: self.work.clone(),
            }))
        }
    }

    struct Counted<T: ?Sized> {
        work: Arc<Work>,
        inner: Box<T>,
    }

    impl Mac for Counted<dyn Mac> {
        fn output_len(&self) -> usize {
            self.inner.output_len()
        }

        fn sign(&mut self, input: &[&[u8]], output: &mut [u8]) -> Result<(), CryptoError> {
            let bytes: usize = input.iter().map(|part| part.len()).sum();
            self.work.mac_calls.fetch_add(1, Ordering::Relaxed);
            self.work
                .mac_bytes
                .fetch_add(bytes as u64, Ordering::Relaxed);
            self.inner.sign(input, output)
        }

        fn verify(&mut self, input: &[&[u8]], expected: &[u8]) -> Result<(), CryptoError> {
            self.inner.verify(input, expected)
        }
    }

    impl StreamCipher for Counted<dyn StreamCipher> {
        fn apply_keystream(&mut self, iv: &[u8], data: &mut [u8]) -> Result<(), CryptoError> {
            self.work.cipher_calls.fetch_add(1, Ordering::Relaxed);
            self.work
                .cipher_bytes
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            self.inner.apply_keystream(iv, data)
        }
    }

    impl AeadCipher for Counted<dyn AeadCipher> {
        fn tag_len(&self) -> usize {
            self.inner.tag_len()
        }

        fn seal_in_place(
            &mut self,
            nonce: &[u8],
            aad: &[u8],
            data: &mut [u8],
            tag_out: &mut [u8],
        ) -> Result<(), CryptoError> {
            self.inner.seal_in_place(nonce, aad, data, tag_out)
        }

        fn open_in_place(
            &mut self,
            nonce: &[u8],
            aad: &[u8],
            data: &mut [u8],
            tag: &[u8],
        ) -> Result<(), CryptoError> {
            self.work.cipher_calls.fetch_add(1, Ordering::Relaxed);
            self.work
                .cipher_bytes
                .fetch_add((aad.len() + data.len()) as u64, Ordering::Relaxed);
            self.inner.open_in_place(nonce, aad, data, tag)
        }
    }
}

#[test]
fn invalid_ciphertexts_cost_the_same_cipher_and_mac_work_as_valid_ones() {
    for suite in CipherSuite::ALL {
        let work = std::sync::Arc::new(counting::Work::default());
        let counted = std::sync::Arc::new(counting::CountingProvider {
            inner: provider(),
            work: work.clone(),
        });
        let mut sender = context(suite);
        sender.add_send_key(1, KEY).unwrap();
        sender.add_send_key(2, KEY).unwrap();
        let mut receiver = SFrameContext::new(suite, counted);
        receiver.add_recv_key(1, KEY).unwrap();
        // The receiver's own sending key: a frame under it is refused for its role.
        receiver.add_send_key(3, KEY).unwrap();

        let plaintext = [0x61; 333];
        let valid = sender.encrypt(1, b"metadata", &plaintext).unwrap();
        let replayed = valid.clone();
        let fresh = sender.encrypt(1, b"metadata", &plaintext).unwrap();
        let mut forged_tag = fresh.clone();
        *forged_tag.last_mut().unwrap() ^= 0x01;
        let mut forged_data = fresh.clone();
        forged_data[10] ^= 0x01;
        // The same length under a KID the receiver has no key for, and under its own.
        let unknown = sender.encrypt(2, b"metadata", &plaintext).unwrap();
        let mut own = unknown.clone();
        own[0] = 0x30 | (own[0] & 0x0f);
        assert_eq!(valid.len(), unknown.len());

        work.take();
        assert_eq!(
            receiver.decrypt(b"metadata", &valid),
            Ok(plaintext.to_vec())
        );
        let expected = work.take();
        assert!(
            expected.2 == 1 && expected.3 >= 333,
            "{suite}: {expected:?}"
        );

        let cases: [(&str, &[u8], Error); 5] = [
            ("forged tag", &forged_tag, Error::AuthenticationFailed),
            ("forged data", &forged_data, Error::AuthenticationFailed),
            ("replay", &replayed, Error::Replayed { kid: 1, ctr: 0 }),
            ("unknown KID", &unknown, Error::UnknownKeyId(2)),
            ("own KID", &own, Error::KeyRoleConflict(3)),
        ];
        for (name, ciphertext, error) in cases {
            let mut out = b"kept".to_vec();
            assert_eq!(
                receiver.decrypt_into(b"metadata", ciphertext, &mut out),
                Err(error),
                "{suite}: {name}"
            );
            assert_eq!(out, b"kept");
            assert_eq!(work.take(), expected, "{suite}: {name}");
        }
    }
}
