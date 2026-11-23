//! Reusable conformance assertions for built-in and application-provided crypto providers.

use crate::{
    AeadAlgorithm, BlockCipherAlgorithm, CbcAlgorithm, CryptoAlgorithm, CryptoError, HashAlgorithm,
    HeaderMaskAlgorithm, HmacAlgorithm, KeyExchangeAlgorithm, PublicKey, PublicKeyEncoding,
    RTCCrypto, RTCCryptoProvider, SignatureScheme, StreamCipherAlgorithm, hkdf_expand,
    hkdf_expand_label, hkdf_extract,
};

/// Exercises the complete initial RTC crypto contract implemented by the built-in providers.
///
/// This helper panics on a contract violation so provider authors can call it directly from a
/// normal `#[test]` function.
pub fn assert_provider(provider: &dyn RTCCryptoProvider) {
    assert_basic_capabilities(provider.crypto());
    assert_hashes_and_hmac(provider.crypto());
    assert_block_and_stream_ciphers(provider.crypto());
    assert_cbc(provider.crypto());
    assert_aead(provider.crypto());
    assert_key_exchange(provider.crypto());
    assert_key_exchange_respond(provider.crypto());
    assert_signatures(provider.crypto());
    assert_tls13_key_schedule(provider.crypto());
    assert_header_masks(provider.crypto());
    assert_rsa_pss(provider.crypto());
    assert_random(provider);
}

fn assert_basic_capabilities(crypto: &dyn RTCCrypto) {
    let capabilities = [
        CryptoAlgorithm::Hash(HashAlgorithm::Md5),
        CryptoAlgorithm::Hash(HashAlgorithm::Sha256),
        CryptoAlgorithm::Hash(HashAlgorithm::Sha384),
        CryptoAlgorithm::Hmac(HmacAlgorithm::Sha1),
        CryptoAlgorithm::Hmac(HmacAlgorithm::Sha256),
        CryptoAlgorithm::Hmac(HmacAlgorithm::Sha512),
        CryptoAlgorithm::Hmac(HmacAlgorithm::Sha384),
        CryptoAlgorithm::HeaderMask(HeaderMaskAlgorithm::Aes128),
        CryptoAlgorithm::HeaderMask(HeaderMaskAlgorithm::Aes256),
        CryptoAlgorithm::HeaderMask(HeaderMaskAlgorithm::ChaCha20),
        CryptoAlgorithm::Signature(SignatureScheme::RsaPssSha256),
        CryptoAlgorithm::Signature(SignatureScheme::RsaPssSha384),
        CryptoAlgorithm::Signature(SignatureScheme::RsaPssSha512),
        CryptoAlgorithm::BlockCipher(BlockCipherAlgorithm::Aes128),
        CryptoAlgorithm::BlockCipher(BlockCipherAlgorithm::Aes256),
        CryptoAlgorithm::BlockCipher(BlockCipherAlgorithm::Aes192),
        CryptoAlgorithm::StreamCipher(StreamCipherAlgorithm::Aes128Ctr),
        CryptoAlgorithm::StreamCipher(StreamCipherAlgorithm::Aes256Ctr),
        CryptoAlgorithm::StreamCipher(StreamCipherAlgorithm::Aes192Ctr),
        CryptoAlgorithm::Cbc(CbcAlgorithm::Aes256Cbc),
        CryptoAlgorithm::Aead(AeadAlgorithm::Aes128Gcm),
        CryptoAlgorithm::Aead(AeadAlgorithm::Aes256Gcm),
        CryptoAlgorithm::Aead(AeadAlgorithm::Aes128Ccm),
        CryptoAlgorithm::Aead(AeadAlgorithm::Aes128Ccm8),
        CryptoAlgorithm::Aead(AeadAlgorithm::ChaCha20Poly1305),
        CryptoAlgorithm::KeyExchange(KeyExchangeAlgorithm::P256),
        CryptoAlgorithm::KeyExchange(KeyExchangeAlgorithm::P384),
        CryptoAlgorithm::KeyExchange(KeyExchangeAlgorithm::X25519),
        CryptoAlgorithm::Signature(SignatureScheme::Ed25519),
        CryptoAlgorithm::Signature(SignatureScheme::EcdsaP256Sha256),
        CryptoAlgorithm::Signature(SignatureScheme::EcdsaP384Sha256),
        CryptoAlgorithm::Signature(SignatureScheme::EcdsaP384Sha384),
        CryptoAlgorithm::Signature(SignatureScheme::RsaPkcs1Sha1),
        CryptoAlgorithm::Signature(SignatureScheme::RsaPkcs1Sha256),
        CryptoAlgorithm::Signature(SignatureScheme::RsaPkcs1Sha384),
        CryptoAlgorithm::Signature(SignatureScheme::RsaPkcs1Sha512),
        CryptoAlgorithm::SigningKeyGeneration(SignatureScheme::Ed25519),
        CryptoAlgorithm::SigningKeyGeneration(SignatureScheme::EcdsaP256Sha256),
        CryptoAlgorithm::SigningKeyImport(SignatureScheme::Ed25519),
        CryptoAlgorithm::SigningKeyImport(SignatureScheme::EcdsaP256Sha256),
        CryptoAlgorithm::SigningKeyImport(SignatureScheme::RsaPkcs1Sha256),
    ];
    for capability in capabilities {
        assert!(
            crypto.supports(capability),
            "missing capability: {capability:?}"
        );
    }
    // RSA key generation: what the provider says it supports, it does; otherwise an explicit
    // unsupported-algorithm error (ring has no RSA key generation).
    if crypto.supports(CryptoAlgorithm::SigningKeyGeneration(
        SignatureScheme::RsaPkcs1Sha256,
    )) {
        assert!(
            crypto
                .generate_signing_key(SignatureScheme::RsaPkcs1Sha256)
                .is_ok()
        );
    } else {
        assert!(matches!(
            crypto.generate_signing_key(SignatureScheme::RsaPkcs1Sha256),
            Err(CryptoError::UnsupportedAlgorithm(_))
        ));
    }
    for scheme in [
        SignatureScheme::Ed25519,
        SignatureScheme::EcdsaP256Sha256,
        SignatureScheme::RsaPkcs1Sha256,
    ] {
        assert!(matches!(
            crypto.import_signing_key(scheme, b"not a PKCS#8 key"),
            Err(CryptoError::InvalidPrivateKey)
        ));
    }
}

/// Checks hash and HMAC known-answer vectors and their error contract.
pub fn assert_hashes_and_hmac(crypto: &dyn RTCCrypto) {
    // RFC 1321, FIPS 180-4, RFC 2202, and RFC 4231 known-answer vectors.
    assert_eq!(
        crypto.hash(HashAlgorithm::Md5, b"abc").unwrap(),
        bytes("900150983cd24fb0d6963f7d28e17f72")
    );
    assert_eq!(
        crypto.hash(HashAlgorithm::Sha256, b"abc").unwrap(),
        bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    // The other certificate fingerprint hashes (RFC 8122 section 5) are optional for a
    // provider; one that reports them must compute them right (FIPS 180-4 "abc" vectors).
    for (algorithm, expected) in [
        (
            HashAlgorithm::Sha1,
            "a9993e364706816aba3e25717850c26c9cd0d89d",
        ),
        (
            HashAlgorithm::Sha224,
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        ),
        (
            HashAlgorithm::Sha384,
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7",
        ),
        (
            HashAlgorithm::Sha512,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
    ] {
        if crypto.supports(CryptoAlgorithm::Hash(algorithm)) {
            assert_eq!(
                crypto.hash(algorithm, b"abc").unwrap(),
                bytes(expected),
                "{algorithm:?}"
            );
        } else {
            assert_eq!(
                crypto.hash(algorithm, b"abc"),
                Err(CryptoError::UnsupportedAlgorithm(CryptoAlgorithm::Hash(
                    algorithm
                ))),
                "{algorithm:?}"
            );
        }
    }

    let key = [0x0b; 20];
    let mut sha1 = [0; 20];
    let mut sha1_mac = crypto.new_hmac(HmacAlgorithm::Sha1, &key).unwrap();
    assert_eq!(sha1_mac.output_len(), 20);
    sha1_mac.sign(&[b"Hi ", b"There"], &mut sha1).unwrap();
    assert_eq!(
        sha1.as_slice(),
        bytes("b617318655057264e28bc0b6fb378c8ef146be00")
    );

    // A keyed MAC is reusable: the second message must not be affected by the first.
    let mut repeat = [0; 20];
    sha1_mac.sign(&[b"Hi ", b"There"], &mut repeat).unwrap();
    assert_eq!(repeat, sha1, "a Mac must produce the same tag when reused");

    let mut sha256 = [0; 32];
    let mut sha256_mac = crypto.new_hmac(HmacAlgorithm::Sha256, &key).unwrap();
    sha256_mac.sign(&[b"Hi ", b"There"], &mut sha256).unwrap();
    assert_eq!(
        sha256.as_slice(),
        bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );

    // Splitting the input across slices must not change the tag.
    let mut joined = [0; 32];
    sha256_mac.sign(&[b"Hi There"], &mut joined).unwrap();
    assert_eq!(joined, sha256, "slice boundaries must not affect the tag");

    sha256_mac.verify(&[b"Hi There"], &sha256).unwrap();
    let mut bad_tag = sha256;
    bad_tag[0] ^= 1;
    assert_eq!(
        sha256_mac.verify(&[b"Hi There"], &bad_tag),
        Err(CryptoError::AuthenticationFailed)
    );
    assert!(matches!(
        sha256_mac.sign(&[b"x"], &mut [0; 31]),
        Err(CryptoError::InvalidTagLength { .. })
    ));

    // RFC 4231 test case 1, HMAC-SHA-512.
    let mut sha512 = [0; 64];
    let mut sha512_mac = crypto.new_hmac(HmacAlgorithm::Sha512, &key).unwrap();
    assert_eq!(sha512_mac.output_len(), 64);
    sha512_mac.sign(&[b"Hi ", b"There"], &mut sha512).unwrap();
    assert_eq!(
        sha512.as_slice(),
        bytes(concat!(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde",
            "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        ))
    );
    sha512_mac.verify(&[b"Hi There"], &sha512).unwrap();
}

/// Checks AES block and stream-cipher known-answer vectors and malformed inputs.
pub fn assert_block_and_stream_ciphers(crypto: &dyn RTCCrypto) {
    // FIPS 197 and NIST SP 800-38A known-answer vectors.
    let mut block = bytes("00112233445566778899aabbccddeeff");
    crypto
        .block_encrypt(
            BlockCipherAlgorithm::Aes128,
            &bytes("000102030405060708090a0b0c0d0e0f"),
            &mut block,
        )
        .unwrap();
    assert_eq!(block, bytes("69c4e0d86a7b0430d8cdb78070b4c55a"));

    let mut block = bytes("00112233445566778899aabbccddeeff");
    crypto
        .block_encrypt(
            BlockCipherAlgorithm::Aes256,
            &bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            &mut block,
        )
        .unwrap();
    assert_eq!(block, bytes("8ea2b7ca516745bfeafc49904b496089"));

    let key = bytes("2b7e151628aed2a6abf7158809cf4f3c");
    let iv = bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let plaintext = bytes("6bc1bee22e409f96e93d7e117393172a");
    let mut encrypted = plaintext.clone();
    crypto
        .new_stream_cipher(StreamCipherAlgorithm::Aes128Ctr, &key)
        .unwrap()
        .apply_keystream(&iv, &mut encrypted)
        .unwrap();
    assert_eq!(encrypted, bytes("874d6191b620e3261bef6864990db6ce"));
    crypto
        .new_stream_cipher(StreamCipherAlgorithm::Aes128Ctr, &key)
        .unwrap()
        .apply_keystream(&iv, &mut encrypted)
        .unwrap();
    assert_eq!(encrypted, plaintext);

    let key = bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    let mut encrypted = plaintext.clone();
    crypto
        .new_stream_cipher(StreamCipherAlgorithm::Aes256Ctr, &key)
        .unwrap()
        .apply_keystream(&iv, &mut encrypted)
        .unwrap();
    assert_eq!(encrypted, bytes("601ec313775789a5b7a7f504bbf3d228"));

    // AES-192 (RFC 6188): FIPS 197 Appendix C.2 and NIST SP 800-38A F.5.3.
    let mut block = bytes("00112233445566778899aabbccddeeff");
    crypto
        .block_encrypt(
            BlockCipherAlgorithm::Aes192,
            &bytes("000102030405060708090a0b0c0d0e0f1011121314151617"),
            &mut block,
        )
        .unwrap();
    assert_eq!(block, bytes("dda97ca4864cdfe06eaf70a0ec0d7191"));
    let key = bytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    let mut encrypted = plaintext.clone();
    crypto
        .new_stream_cipher(StreamCipherAlgorithm::Aes192Ctr, &key)
        .unwrap()
        .apply_keystream(&iv, &mut encrypted)
        .unwrap();
    assert_eq!(encrypted, bytes("1abc932417521ca24f2b0459fe7e6e0b"));
    assert!(matches!(
        crypto.new_stream_cipher(StreamCipherAlgorithm::Aes192Ctr, &[0; 16]),
        Err(CryptoError::InvalidKeyLength { .. })
    ));

    assert!(matches!(
        crypto.block_encrypt(BlockCipherAlgorithm::Aes128, &[0; 15], &mut [0; 16]),
        Err(CryptoError::InvalidKeyLength { .. })
    ));
    assert!(matches!(
        crypto.block_encrypt(BlockCipherAlgorithm::Aes128, &[0; 16], &mut [0; 15]),
        Err(CryptoError::OutputTooSmall { .. })
    ));
    assert!(matches!(
        crypto.new_stream_cipher(StreamCipherAlgorithm::Aes128Ctr, &[0; 15]),
        Err(CryptoError::InvalidKeyLength { .. })
    ));
    let mut stream = crypto
        .new_stream_cipher(StreamCipherAlgorithm::Aes128Ctr, &[0; 16])
        .unwrap();
    assert!(matches!(
        stream.apply_keystream(&[0; 15], &mut [0; 1]),
        Err(CryptoError::InvalidNonceLength { .. })
    ));
}

/// Checks AES-CBC known-answer vectors and malformed inputs.
pub fn assert_cbc(crypto: &dyn RTCCrypto) {
    // NIST SP 800-38A F.2.5.
    let key = bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    let iv = bytes("000102030405060708090a0b0c0d0e0f");
    let plaintext = bytes("6bc1bee22e409f96e93d7e117393172a");
    let mut blocks = plaintext.clone();
    let mut cipher = crypto.new_cbc(CbcAlgorithm::Aes256Cbc, &key).unwrap();
    assert_eq!(cipher.block_len(), 16);
    cipher.encrypt_blocks(&iv, &mut blocks).unwrap();
    assert_eq!(blocks, bytes("f58c4c04d6e5f1ba779eabfb5f7bfbd6"));
    cipher.decrypt_blocks(&iv, &mut blocks).unwrap();
    assert_eq!(blocks, plaintext);

    assert!(matches!(
        crypto.new_cbc(CbcAlgorithm::Aes256Cbc, &[0; 31]),
        Err(CryptoError::InvalidKeyLength { .. })
    ));
    assert!(matches!(
        cipher.encrypt_blocks(&[0; 15], &mut [0; 16]),
        Err(CryptoError::InvalidNonceLength { .. })
    ));
    assert!(matches!(
        cipher.encrypt_blocks(&[0; 16], &mut []),
        Err(CryptoError::OutputTooSmall { .. })
    ));
    assert!(matches!(
        cipher.decrypt_blocks(&[0; 16], &mut [0; 15]),
        Err(CryptoError::OutputTooSmall { .. })
    ));
}

/// Checks AEAD known-answer vectors, round trips, authentication failures, and malformed sizes.
pub fn assert_aead(crypto: &dyn RTCCrypto) {
    // NIST SP 800-38D, NIST SP 800-38C, and RFC 8439 known-answer vectors.
    let mut gcm = crypto.new_aead(AeadAlgorithm::Aes128Gcm, &[0; 16]).unwrap();
    let mut block = vec![0; 16];
    let mut tag = vec![0; gcm.tag_len()];
    gcm.seal_in_place(&[0; 12], &[], &mut block, &mut tag)
        .unwrap();
    assert_eq!(block, bytes("0388dace60b6a392f328c2b971b2fe78"));
    assert_eq!(tag, bytes("ab6e47d42cec13bdf53a67b21257bddf"));
    gcm.open_in_place(&[0; 12], &[], &mut block, &tag).unwrap();
    assert_eq!(block, vec![0; 16]);

    let mut gcm = crypto.new_aead(AeadAlgorithm::Aes256Gcm, &[0; 32]).unwrap();
    let mut block = vec![0; 16];
    let mut tag = vec![0; gcm.tag_len()];
    gcm.seal_in_place(&[0; 12], &[], &mut block, &mut tag)
        .unwrap();
    assert_eq!(block, bytes("cea7403d4d606b6e074ec5d3baf39d18"));
    assert_eq!(tag, bytes("d0d1c8a799996bf0265b98b5d48ab919"));

    let mut ccm8 = crypto
        .new_aead(
            AeadAlgorithm::Aes128Ccm8,
            &bytes("404142434445464748494a4b4c4d4e4f"),
        )
        .unwrap();
    let mut ccm8_buffer = bytes("202122232425262728292a2b2c2d2e2f3031323334353637");
    let mut ccm8_tag = vec![0; ccm8.tag_len()];
    ccm8.seal_in_place(
        &bytes("101112131415161718191a1b"),
        &bytes("000102030405060708090a0b0c0d0e0f10111213"),
        &mut ccm8_buffer,
        &mut ccm8_tag,
    )
    .unwrap();
    assert_eq!(
        ccm8_buffer,
        bytes("e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5")
    );
    assert_eq!(ccm8_tag, bytes("484392fbc1b09951"));

    let mut chacha = crypto
        .new_aead(
            AeadAlgorithm::ChaCha20Poly1305,
            &bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        )
        .unwrap();
    let mut chacha_buffer = bytes(concat!(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393",
        "a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074",
        "6865206675747572652c2073756e73637265656e20776f756c642062652069742e"
    ));
    let mut chacha_tag = vec![0; chacha.tag_len()];
    chacha
        .seal_in_place(
            &bytes("070000004041424344454647"),
            &bytes("50515253c0c1c2c3c4c5c6c7"),
            &mut chacha_buffer,
            &mut chacha_tag,
        )
        .unwrap();
    assert_eq!(
        chacha_buffer,
        bytes(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca967128",
            "2fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fa",
            "b324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
        ))
    );
    assert_eq!(chacha_tag, bytes("1ae10b594f09e26a7e902ecbd0600691"));
    assert!(matches!(
        crypto.new_aead(AeadAlgorithm::Aes128Gcm, &[0; 15]),
        Err(CryptoError::InvalidKeyLength { .. })
    ));
    assert!(matches!(
        gcm.seal_in_place(&[0; 11], &[], &mut [], &mut [0; 16]),
        Err(CryptoError::InvalidNonceLength { .. })
    ));
    assert!(matches!(
        gcm.seal_in_place(&[0; 12], &[], &mut [], &mut [0; 15]),
        Err(CryptoError::InvalidTagLength { .. })
    ));

    let cases = [
        (AeadAlgorithm::Aes256Gcm, 32),
        (AeadAlgorithm::Aes128Ccm, 16),
        (AeadAlgorithm::Aes128Ccm8, 16),
        (AeadAlgorithm::ChaCha20Poly1305, 32),
    ];
    for (algorithm, key_len) in cases {
        let mut cipher = crypto.new_aead(algorithm, &vec![7; key_len]).unwrap();
        let plaintext = b"provider conformance".to_vec();
        let mut encrypted = plaintext.clone();
        let mut tag = vec![0; cipher.tag_len()];
        cipher
            .seal_in_place(&[3; 12], b"aad", &mut encrypted, &mut tag)
            .unwrap();
        assert_ne!(encrypted, plaintext);
        cipher
            .open_in_place(&[3; 12], b"aad", &mut encrypted, &tag)
            .unwrap();
        assert_eq!(encrypted, plaintext);

        let mut ciphertext = plaintext.clone();
        let mut valid_tag = vec![0; cipher.tag_len()];
        cipher
            .seal_in_place(&[3; 12], b"aad", &mut ciphertext, &mut valid_tag)
            .unwrap();

        let mut tampered = ciphertext.clone();
        tag[0] ^= 1;
        assert_eq!(
            cipher.open_in_place(&[3; 12], b"aad", &mut tampered, &tag),
            Err(CryptoError::AuthenticationFailed)
        );

        let mut wrong_aad = ciphertext.clone();
        assert_eq!(
            cipher.open_in_place(&[3; 12], b"bad", &mut wrong_aad, &valid_tag),
            Err(CryptoError::AuthenticationFailed)
        );

        let mut changed_ciphertext = ciphertext.clone();
        changed_ciphertext[0] ^= 1;
        assert_eq!(
            cipher.open_in_place(&[3; 12], b"aad", &mut changed_ciphertext, &valid_tag),
            Err(CryptoError::AuthenticationFailed)
        );

        let mut wrong_key_cipher = crypto.new_aead(algorithm, &vec![8; key_len]).unwrap();
        assert_eq!(
            wrong_key_cipher.open_in_place(&[3; 12], b"aad", &mut ciphertext, &valid_tag),
            Err(CryptoError::AuthenticationFailed)
        );
    }
}

/// Checks every supported one-shot key exchange and malformed peer keys.
pub fn assert_key_exchange(crypto: &dyn RTCCrypto) {
    for algorithm in [
        KeyExchangeAlgorithm::P256,
        KeyExchangeAlgorithm::P384,
        KeyExchangeAlgorithm::X25519,
    ] {
        let left = crypto.start_key_exchange(algorithm).unwrap();
        let right = crypto.start_key_exchange(algorithm).unwrap();
        assert_eq!(left.algorithm(), algorithm);
        let left_public = left.public_key().to_vec();
        let right_public = right.public_key().to_vec();
        let left_secret = left.complete(&right_public).unwrap();
        let right_secret = right.complete(&left_public).unwrap();
        assert_eq!(left_secret.as_ref(), right_secret.as_ref());
        assert!(!left_secret.is_empty());

        let invalid = crypto.start_key_exchange(algorithm).unwrap();
        assert!(matches!(
            invalid.complete(&[0; 1]),
            Err(CryptoError::InvalidPublicKey)
        ));
    }
}

/// Checks the responder's side of a key exchange, and X25519MLKEM768
/// (draft-ietf-tls-ecdhe-mlkem) where the provider has it: the lengths of its shares and
/// secret, agreement, and that malformed shares are refused. A provider without it says so.
pub fn assert_key_exchange_respond(crypto: &dyn RTCCrypto) {
    for algorithm in [
        KeyExchangeAlgorithm::P256,
        KeyExchangeAlgorithm::P384,
        KeyExchangeAlgorithm::X25519,
    ] {
        let initiator = crypto.start_key_exchange(algorithm).unwrap();
        let (share, responder_secret) = crypto
            .key_exchange_respond(algorithm, initiator.public_key())
            .unwrap();
        let initiator_secret = initiator.complete(&share).unwrap();
        assert_eq!(initiator_secret.as_ref(), responder_secret.as_ref());
        assert!(crypto.key_exchange_respond(algorithm, &[0; 1]).is_err());
    }

    let hybrid = KeyExchangeAlgorithm::X25519MlKem768;
    if !crypto.supports(CryptoAlgorithm::KeyExchange(hybrid)) {
        assert!(matches!(
            crypto.start_key_exchange(hybrid).map(|_| ()),
            Err(CryptoError::UnsupportedAlgorithm(_))
        ));
        assert!(crypto.key_exchange_respond(hybrid, &[0; 1216]).is_err());
        return;
    }
    let initiator = crypto.start_key_exchange(hybrid).unwrap();
    assert_eq!(initiator.algorithm(), hybrid);
    // An ML-KEM-768 encapsulation key (1184 bytes) and an X25519 key (32).
    assert_eq!(initiator.public_key().len(), 1216);
    let initiator_share = initiator.public_key().to_vec();
    let (share, responder_secret) = crypto
        .key_exchange_respond(hybrid, &initiator_share)
        .unwrap();
    // An ML-KEM-768 ciphertext (1088 bytes) and an X25519 key (32).
    assert_eq!(share.len(), 1120);
    let initiator_secret = initiator.complete(&share).unwrap();
    // The ML-KEM shared secret (32 bytes) followed by the X25519 one (32).
    assert_eq!(initiator_secret.len(), 64);
    assert_eq!(initiator_secret.as_ref(), responder_secret.as_ref());
    assert_ne!(
        initiator_secret.as_ref()[..32],
        initiator_secret.as_ref()[32..]
    );

    // Encapsulation is randomised: a second answer to the same share is another secret.
    let (_, other_secret) = crypto
        .key_exchange_respond(hybrid, &initiator_share)
        .unwrap();
    assert_ne!(other_secret.as_ref(), responder_secret.as_ref());

    // Shares of the wrong length, either way.
    for length in [0, 32, 1120, 1215, 1217] {
        assert!(matches!(
            crypto.key_exchange_respond(hybrid, &vec![1; length]),
            Err(CryptoError::InvalidPublicKey)
        ));
    }
    for length in [0, 32, 1119, 1121, 1216] {
        let initiator = crypto.start_key_exchange(hybrid).unwrap();
        assert!(matches!(
            initiator.complete(&vec![1; length]),
            Err(CryptoError::InvalidPublicKey)
        ));
    }
    // A ciphertext that was altered decapsulates to another secret (ML-KEM rejects
    // implicitly), so the two ends do not agree.
    let initiator = crypto.start_key_exchange(hybrid).unwrap();
    let (mut share, responder_secret) = crypto
        .key_exchange_respond(hybrid, initiator.public_key())
        .unwrap();
    share[0] ^= 1;
    let initiator_secret = initiator.complete(&share).unwrap();
    assert_ne!(initiator_secret.as_ref(), responder_secret.as_ref());
}

/// Checks signing, verification, key import/export, and invalid signatures and encodings.
pub fn assert_signatures(crypto: &dyn RTCCrypto) {
    for scheme in [SignatureScheme::Ed25519, SignatureScheme::EcdsaP256Sha256] {
        let key = crypto.generate_signing_key(scheme).unwrap();
        let message = b"rtc-crypto provider conformance";
        let signature = key.sign(scheme, message).unwrap();
        crypto
            .verify_signature(scheme, key.public_key(), message, &signature)
            .unwrap();
        assert_eq!(
            crypto.verify_signature(scheme, key.public_key(), b"changed", &signature),
            Err(CryptoError::InvalidSignature)
        );

        let exported = key.to_pkcs8_der().unwrap().unwrap();
        let imported = crypto
            .import_signing_key(scheme, exported.as_ref())
            .unwrap();
        let imported_signature = imported.sign(scheme, message).unwrap();
        crypto
            .verify_signature(scheme, imported.public_key(), message, &imported_signature)
            .unwrap();
        assert!(matches!(
            imported.sign(SignatureScheme::RsaPkcs1Sha256, message),
            Err(CryptoError::UnsupportedAlgorithm(_))
        ));
    }

    assert_eq!(
        crypto.verify_signature(
            SignatureScheme::Ed25519,
            PublicKey {
                encoding: PublicKeyEncoding::SubjectPublicKeyInfoDer,
                bytes: &[0; 32],
            },
            b"message",
            &[0; 64],
        ),
        Err(CryptoError::InvalidPublicKey)
    );

    assert_verification_only_schemes(crypto);
}

fn assert_verification_only_schemes(crypto: &dyn RTCCrypto) {
    let message = b"rtc-crypto verification vector";
    let p384_public_key = bytes(concat!(
        "04c298b589fdd33f544610d13c277e0c703b2e3a72c0dfa2a81725e761614bd8c4",
        "cb80ecf40bba853f37aec2f4e13c7b5d05e7be9231d651bd1dc2848050bcd19858",
        "e448d27bf2418b350626a1f241c4914795c404aa35afab97e15e202296244a"
    ));
    let p384_signature = bytes(concat!(
        "306502302c6f36a6a01282982213b037f73ec8f935e1fcf4dc63035824c2bcb6",
        "aaa378f716d15f63df23e85d60f7d5e46c028ad1023100877055a3a8849e179",
        "ad94da98dc5125f1e78852cf9017795087b90751b99985b989786d2a537f84b08cdf7243820c313"
    ));
    crypto
        .verify_signature(
            SignatureScheme::EcdsaP384Sha384,
            PublicKey {
                encoding: PublicKeyEncoding::EcUncompressedPoint,
                bytes: &p384_public_key,
            },
            message,
            &p384_signature,
        )
        .unwrap();

    let p384_sha256_public_key = bytes(
        "041e88f40d0a7fc21dc01d89951ea8598ce35f9f37bc163f102a633079ceeaa99a9298aad6e5c46100f37e915132e5df9f9cedf3e140f789934113e0f8b280e4bd0904b6f1ec10479f759b5d5f01ae1e4058ece51a073fe089680b9eee7e4d1f9e",
    );
    let p384_sha256_signature = bytes(
        "3065023100b3ede985a4270f3fe8a0177040f17b417c12d132f2f27dc3290ba14a9fcbe08b82189d4c2f82dc5f649f1d49bcbc726002306825847e994ecd3f2924e7468e285af7647825692a83fd995c749e536eff946451b3e253d706a9b848d7170761d06323",
    );
    crypto
        .verify_signature(
            SignatureScheme::EcdsaP384Sha256,
            PublicKey {
                encoding: PublicKeyEncoding::EcUncompressedPoint,
                bytes: &p384_sha256_public_key,
            },
            message,
            &p384_sha256_signature,
        )
        .unwrap();

    let rsa_public_key = bytes(
        "3082010a0282010100b0f8c4868ce9bcd4d11632162c0376bb09dce2facadaa27a6d4ad01b217c0a29e036b1bfd0052254ec3d349383019d8fd2d5c895ac6790bcc6c4dfca7c26bbcf570ee3bdff70826f80e8254776d8e73b431e2bece3d7d515edd23ada88e2c7136ac796685df8a40ed38ce59eaefc2509e1b277a0363938eb8e998a3f9fd6f2ed011b969e48d89d76508904961f8d83756466eff0f1fd5e4621e8ff083fd0d6aa87b31e560c185a1862059ba0fa95f8125ac96bfc7e051c3996587dc1271bb3ebf49303314ee888ccc8441de13a59b0646d9375dfbcbd66c1435398e164bc4672fd63a2eef162a7c1ac7ddb3e9cdb68cfeacff01f036a557477b45172593727f50203010001",
    );
    let rsa_vectors = [
        (
            SignatureScheme::RsaPkcs1Sha1,
            "967636ce08cc1923f2b6fa792d2a7cd6521f4a793adb4a0f94cfc6543e483d5383a6b36dbcef3a5cfd5cc12c333ebc6a22f2d452cac61a352111247e26f5e13595f0b78a9e94be1ff7eb4ab60ef48fff3a0e8c1a70ea041f63413c7dc4a5219d2ddb8349058ce1b7d2c02eb98f285d589f858a18f6473a1d3af47de653d520ceba6825e1a1bd5a0065ef0e4d9ac5929bc1cc3ffab014081224db7e7787c67f1580913fb98a870c1355c86a33770d17f654f24dccd781f3bf8a7de29e00198a99dd2bf1a1298630da433982ae63cbf71c265abebdd003c1c2ee870f7f8ea96c465dedb158a1e2e5048763d308a69eefc91424ad0795e8320fa0e753673f657a45",
        ),
        (
            SignatureScheme::RsaPkcs1Sha256,
            "19b21fd70c4dacec4c3cc6f6aac961e4ea0fb9b5d0ee3862cc35b60849388f2f461ab4697c59c25abb251f88b1de312ced6861ed90152c911356dff768cc4eafdadaa2f8d6b5d70c630d2739f1178fe5cbaff62cee343a20bb38404d35c58d247befa486dd5a3c69affdad5bdecaab876799dd297bd9cc4700e099b92d18d8ad78b64f570e4a398b0b8e9baf9a1b01aaa873b23b7c381917f3383482b7780e0e11e734409fc18daacb0428082789f791af2c4a79d5c75cde45c201e46ae347ab7624e0137940945e174dfab59888892c25b8e10abee1a72f2f31fb3f0e8840db490ba752e1df966979f267756767c88ea0d7909145f379811412f68465e08fd2",
        ),
        (
            SignatureScheme::RsaPkcs1Sha384,
            "0095d1ef58850cbf09dd1219a8678d7fa3f8c490a4a35feb19f50d85991caf659131dc90c52f14466c429a099a53e1d5f321a49065e85f250b85e08158ee46328515acee03bd215d610ec2335e1cbd1525058b950fb8ecb5d073f9fc474613c830c1111868efc3554c2ec62d9efd4694db281a6b3e48ed68d934278f5ba9a6fb19e8d648baa6b5f48d126def83986166ed05d710d5cdccd457092649b08d5e54c5ccfe42786852c98113b78291e3e2ced51ff3ed51ddef8cb81d311a2983cc6c93f0bb583537c067c6afc63e8e4a9d15635882b14d189a217d9588a469ac1899e3adeafdd276150b1023d7b64fea94b50a9ba22cc47c0d8d6ca4faf6b23f76d0",
        ),
        (
            SignatureScheme::RsaPkcs1Sha512,
            "7373b3eaf66ba56bda1ae85a466c2f0321d15c37ce293642f6b69fddbea0e6f4dfa76dd0ba274afaabf71ba9d85198c0e75af95af6c64cb9bb304ea1ea3c04e653649891af78145b823d3ed1179fdbdc4edbedcf1eb3201b44a9a40930bf005da1bbe138dfac2d272364a991fcadcfba9093e889fa03f153771fdd51525ffae16cb2155eac8f6da49b602ae8fb34a5a131693459cacbc5adbc9b6002473732a7e205c2150bd25afe850c29845054e17d56a028d81f293b1dc634ba11a6790aa478f0f36bcc64787e356384ae90ef83c5226183afca64c9ac28c83ca803e01ff801f1ee12c806005d9f5d3562afae08e358722ca606d46d500d43901256625fc4",
        ),
    ];
    for (scheme, signature) in rsa_vectors {
        crypto
            .verify_signature(
                scheme,
                PublicKey {
                    encoding: PublicKeyEncoding::RsaPkcs1Der,
                    bytes: &rsa_public_key,
                },
                message,
                &bytes(signature),
            )
            .unwrap();
    }
}

/// Checks SHA-384, HMAC-SHA-384, HKDF and the TLS 1.3 key schedule against FIPS 180-4,
/// RFC 4231, RFC 5869 and the RFC 8448 section 3 trace.
pub fn assert_tls13_key_schedule(crypto: &dyn RTCCrypto) {
    assert_eq!(
        crypto.hash(HashAlgorithm::Sha384, b"abc").unwrap(),
        bytes(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        )
    );
    assert_eq!(HashAlgorithm::Sha384.output_len(), 48);
    assert_eq!(HmacAlgorithm::Sha384.output_len(), 48);

    // RFC 4231 test case 1.
    let mut tag = [0u8; 48];
    let mut mac = crypto.new_hmac(HmacAlgorithm::Sha384, &[0x0b; 20]).unwrap();
    assert_eq!(mac.output_len(), 48);
    mac.sign(&[b"Hi ", b"There"], &mut tag).unwrap();
    assert_eq!(
        tag.as_slice(),
        bytes(
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
             faea9ea9076ede7f4af152e8b2fa9cb6"
        )
    );
    mac.verify(&[b"Hi There"], &tag).unwrap();

    // RFC 5869 appendix A.1.
    let pseudorandom_key = hkdf_extract(
        crypto,
        HmacAlgorithm::Sha256,
        &bytes("000102030405060708090a0b0c"),
        &[0x0b; 22],
    )
    .unwrap();
    assert_eq!(
        pseudorandom_key.as_ref(),
        bytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    );
    // The info in two pieces: where it is cut must not matter.
    let output = hkdf_expand(
        crypto,
        HmacAlgorithm::Sha256,
        pseudorandom_key.as_ref(),
        &[&bytes("f0f1f2f3"), &bytes("f4f5f6f7f8f9")],
        42,
    )
    .unwrap();
    assert_eq!(
        output.as_ref(),
        bytes(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
        )
    );
    // RFC 5869 appendix A.3: no salt and no info.
    let pseudorandom_key = hkdf_extract(crypto, HmacAlgorithm::Sha256, &[], &[0x0b; 22]).unwrap();
    assert_eq!(
        pseudorandom_key.as_ref(),
        bytes("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
    );
    assert_eq!(
        hkdf_expand(
            crypto,
            HmacAlgorithm::Sha256,
            pseudorandom_key.as_ref(),
            &[],
            42
        )
        .unwrap()
        .as_ref(),
        bytes(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8"
        )
    );
    assert!(matches!(
        hkdf_expand(
            crypto,
            HmacAlgorithm::Sha256,
            pseudorandom_key.as_ref(),
            &[],
            255 * 32 + 1
        ),
        Err(CryptoError::OutputTooSmall { .. })
    ));

    // RFC 8448 section 3, the simple 1-RTT handshake.
    let sha256 = HmacAlgorithm::Sha256;
    let empty_hash = crypto.hash(HashAlgorithm::Sha256, b"").unwrap();
    let early = hkdf_extract(crypto, sha256, &[], &[0; 32]).unwrap();
    assert_eq!(
        early.as_ref(),
        bytes("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
    );
    let derived = hkdf_expand_label(
        crypto,
        sha256,
        early.as_ref(),
        "tls13 ",
        "derived",
        &empty_hash,
        32,
    )
    .unwrap();
    assert_eq!(
        derived.as_ref(),
        bytes("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
    );
    let handshake = hkdf_extract(
        crypto,
        sha256,
        derived.as_ref(),
        &bytes("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"),
    )
    .unwrap();
    assert_eq!(
        handshake.as_ref(),
        bytes("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
    );
    let transcript = bytes("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    let client_handshake = hkdf_expand_label(
        crypto,
        sha256,
        handshake.as_ref(),
        "tls13 ",
        "c hs traffic",
        &transcript,
        32,
    )
    .unwrap();
    assert_eq!(
        client_handshake.as_ref(),
        bytes("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
    );
    let server_handshake = hkdf_expand_label(
        crypto,
        sha256,
        handshake.as_ref(),
        "tls13 ",
        "s hs traffic",
        &transcript,
        32,
    )
    .unwrap();
    assert_eq!(
        server_handshake.as_ref(),
        bytes("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
    );
    let derived = hkdf_expand_label(
        crypto,
        sha256,
        handshake.as_ref(),
        "tls13 ",
        "derived",
        &empty_hash,
        32,
    )
    .unwrap();
    assert_eq!(
        derived.as_ref(),
        bytes("43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4")
    );
    let master = hkdf_extract(crypto, sha256, derived.as_ref(), &[0; 32]).unwrap();
    assert_eq!(
        master.as_ref(),
        bytes("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
    );
    let key = hkdf_expand_label(
        crypto,
        sha256,
        server_handshake.as_ref(),
        "tls13 ",
        "key",
        &[],
        16,
    )
    .unwrap();
    assert_eq!(key.as_ref(), bytes("3fce516009c21727d0f2e4e86ee403bc"));
    let iv = hkdf_expand_label(
        crypto,
        sha256,
        server_handshake.as_ref(),
        "tls13 ",
        "iv",
        &[],
        12,
    )
    .unwrap();
    assert_eq!(iv.as_ref(), bytes("5d313eb2671276ee13000b30"));

    // The DTLS 1.3 prefix (RFC 9147 section 5.9) gives different keys from the same secret.
    let dtls_key = hkdf_expand_label(
        crypto,
        sha256,
        server_handshake.as_ref(),
        "dtls13",
        "key",
        &[],
        16,
    )
    .unwrap();
    assert_ne!(dtls_key.as_ref(), key.as_ref());
    assert!(
        hkdf_expand_label(
            crypto,
            sha256,
            early.as_ref(),
            "dtls13",
            "key",
            &[0; 256],
            16
        )
        .is_err()
    );
}

/// Checks the record-number masks against the header-protection samples of RFC 9001
/// appendix A, which are the computation RFC 9147 section 4.2.3 defines.
pub fn assert_header_masks(crypto: &dyn RTCCrypto) {
    // RFC 9001 A.2: AES-128.
    let mut mask = crypto
        .new_header_mask(
            HeaderMaskAlgorithm::Aes128,
            &bytes("9f50449e04a0e810283a1e9933adedd2"),
        )
        .unwrap();
    let sample: [u8; 16] = bytes("d1b1c98dd7689fb8ec11d242b123dc9b")
        .try_into()
        .unwrap();
    assert_eq!(mask.mask(&sample).unwrap().as_slice(), bytes("437b9aec36"));
    // A keyed mask is reusable.
    assert_eq!(mask.mask(&sample).unwrap().as_slice(), bytes("437b9aec36"));

    // RFC 9001 A.5: ChaCha20, the sample's first four bytes the block counter and the rest
    // the nonce.
    let mut mask = crypto
        .new_header_mask(
            HeaderMaskAlgorithm::ChaCha20,
            &bytes("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"),
        )
        .unwrap();
    let sample: [u8; 16] = bytes("5e5cd55c41f69080575d7999c25a5bfb")
        .try_into()
        .unwrap();
    assert_eq!(mask.mask(&sample).unwrap().as_slice(), bytes("aefefe7d03"));

    // AES-256 is AES-ECB of the sample under a 256-bit key: the block cipher's own answer.
    let key = [0x42u8; 32];
    let mut block = sample;
    crypto
        .block_encrypt(BlockCipherAlgorithm::Aes256, &key, &mut block)
        .unwrap();
    let mut mask = crypto
        .new_header_mask(HeaderMaskAlgorithm::Aes256, &key)
        .unwrap();
    assert_eq!(mask.mask(&sample).unwrap().as_slice(), &block[..5]);

    assert!(matches!(
        crypto.new_header_mask(HeaderMaskAlgorithm::Aes128, &[0; 32]),
        Err(CryptoError::InvalidKeyLength { .. })
    ));
}

/// Checks RSASSA-PSS verification (the TLS 1.3 `rsa_pss_rsae` schemes: MGF1 with the same
/// hash, a salt as long as the digest) against signatures made with OpenSSL.
pub fn assert_rsa_pss(crypto: &dyn RTCCrypto) {
    let message = b"rtc-crypto RSASSA-PSS verification vector";
    let rsa_public_key = bytes(
        "3082010a0282010100b0f8c4868ce9bcd4d11632162c0376bb09dce2facadaa27a6d4ad01b217c0a29\
         e036b1bfd0052254ec3d349383019d8fd2d5c895ac6790bcc6c4dfca7c26bbcf570ee3bdff70826f80\
         e8254776d8e73b431e2bece3d7d515edd23ada88e2c7136ac796685df8a40ed38ce59eaefc2509e1b2\
         77a0363938eb8e998a3f9fd6f2ed011b969e48d89d76508904961f8d83756466eff0f1fd5e4621e8ff\
         083fd0d6aa87b31e560c185a1862059ba0fa95f8125ac96bfc7e051c3996587dc1271bb3ebf4930331\
         4ee888ccc8441de13a59b0646d9375dfbcbd66c1435398e164bc4672fd63a2eef162a7c1ac7ddb3e9c\
         db68cfeacff01f036a557477b45172593727f50203010001",
    );
    let vectors = [
        (
            SignatureScheme::RsaPssSha256,
            "a793bca49825413a688eaac91393ae1f80c08853f95bc2754deda4e816d3d4c2fb26090c3cabcad1\
             e2af65c7948263e5c2bbf1442cc6c42c95c61dce9b10ceb7114f6bc7390e29cea19d0f439d5dcb27\
             56a4669d09da0a27463a65e1ccb25a6c3d320cc337641530352a71ea6db92b9fcabe97e658a645da\
             f6f21aeff8581cba9e5c7e66579ab15c6c277585228b20bc531ec9551af3cc11d64d0e836b69d452\
             7822fc56b8add10cf786b450a94eeef397276f5731ddec78f5ffa5a1d40f6552060520603e48e310\
             38fa9c96952de4dade0723ef7a4947f8cc8916fded1da2215988616433fbb0d2f084173590c23dd9\
             a36fa5283c98a4227226b03fb0b211bd",
        ),
        (
            SignatureScheme::RsaPssSha384,
            "15d74fcf1000dbfaaf843ad0ab3353d4c6c704e12434bd2e323efa9e59dfd913f70ecb5cf487b1e8\
             e1b1980e3d49a01f7f35bacff46c3c361ea22ecf641d1bfee69f63b7bd97d1c7a317a53d9e5eb3ec\
             2ed9ef29bb6004457262f34de89c15db3bbe3f1b3da0dfda8c63f4813cf790a0ed92b942440cf05f\
             fccff518f3af096cda08c417c98351fe7f15cfbf96d73468ac88e390e3e950846d0e70ac665678b2\
             021668e4a3996c498e1f1784c98a9ede2f4b3cbff7fb1fed61266946180248106841acdc3349de98\
             4f956df683773f622efbf79c1863559ba40538c7f3a6e36af5d302e8a0275dc37c0acb34587db107\
             b4db640fb2a78371e768b16fa790ad1c",
        ),
        (
            SignatureScheme::RsaPssSha512,
            "a47446283b0cac22decb44c283fb93d90b50f6a79fe04d83f2484332861d5c9bee21e2b0b16e0d8e\
             7630777b06f821cd4504dc2fcc93c4f39b728d7cb0e81470fbd15b5edf3da1f7194e73ff34d08440\
             240aeda34b7003d393354e00878e61ae9e6d3473e7d3932b8e05d7dc62932af9d65d8be84600654d\
             5be161daac8403e3c2b11a092494e3b9a7ce6a45092b239332443c0baa3e93b01ebb77d0e36f77eb\
             951c9ee95ba859997f5bf7865d0fb5ed7af5e447d8c935721eea0b3941dadbc119a6c2b1d2db198e\
             11735206b2263c8ce87d22065938b7fdc0e73c7857571a5fd8b289f5133c388427b6042b26f62ba9\
             8f70ffb70294b193e079494c1f5674cc",
        ),
    ];
    for (scheme, signature) in vectors {
        let public_key = PublicKey {
            encoding: PublicKeyEncoding::RsaPkcs1Der,
            bytes: &rsa_public_key,
        };
        let signature = bytes(signature);
        crypto
            .verify_signature(scheme, public_key, message, &signature)
            .unwrap();
        assert_eq!(
            crypto.verify_signature(scheme, public_key, b"another message", &signature),
            Err(CryptoError::InvalidSignature)
        );
        // A PSS signature is not a PKCS#1 v1.5 one, and the hash is part of the scheme.
        assert_eq!(
            crypto.verify_signature(
                SignatureScheme::RsaPkcs1Sha256,
                public_key,
                message,
                &signature
            ),
            Err(CryptoError::InvalidSignature)
        );
        let other = if scheme == SignatureScheme::RsaPssSha256 {
            SignatureScheme::RsaPssSha384
        } else {
            SignatureScheme::RsaPssSha256
        };
        assert_eq!(
            crypto.verify_signature(other, public_key, message, &signature),
            Err(CryptoError::InvalidSignature)
        );
    }
}

/// Checks that a provider's secure random source returns fresh output.
pub fn assert_random(provider: &dyn RTCCryptoProvider) {
    let mut first = [0; 32];
    let mut second = [0; 32];
    provider.random().fill(&mut first).unwrap();
    provider.random().fill(&mut second).unwrap();
    assert_ne!(first, second);
}

/// Checks the default unsupported-operation behavior required for partial providers.
pub fn assert_unsupported_hash(crypto: &dyn RTCCrypto) {
    assert!(!crypto.supports(CryptoAlgorithm::Hash(HashAlgorithm::Sha256)));
    assert_eq!(
        crypto.hash(HashAlgorithm::Sha256, b"input"),
        Err(CryptoError::UnsupportedAlgorithm(CryptoAlgorithm::Hash(
            HashAlgorithm::Sha256
        )))
    );
}

/// Checks the provider-neutral failure returned by a deliberately failing random source.
pub fn assert_random_failure(random: &dyn crate::RTCRandom) {
    assert_eq!(random.fill(&mut [0; 1]), Err(CryptoError::RandomnessFailed));
}

fn bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();
    pairs
        .iter()
        .map(|&[hi, lo]| (nibble(hi) << 4) | nibble(lo))
        .collect()
}

fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("invalid hexadecimal test vector"),
    }
}
