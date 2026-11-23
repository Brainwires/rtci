use crypto::HmacAlgorithm;

use crate::kdf::{derive_key_salt, hkdf_expand, hkdf_extract, hkdf_extract_salted};
use crate::test_util::{hex, provider};
use crate::test_vectors::{AES_256_CTR, BASE_KEY, KID, RFC9605_C3, SFrameVector};
use crate::{CipherSuite, Error, derive_ssrc_key, ratchet_base_key};

fn assert_key_derivation(vector: &SFrameVector) {
    let provider = provider();
    let suite = vector.suite;
    let base_key = hex(BASE_KEY);

    let secret = hkdf_extract(provider.crypto(), suite.hmac(), &base_key).unwrap();
    assert_eq!(
        &secret[..suite.hash_len()],
        hex(vector.sframe_secret),
        "{suite}: sframe_secret"
    );

    let derived = derive_key_salt(provider.crypto(), suite, KID, &base_key).unwrap();
    assert_eq!(*derived.key, hex(vector.sframe_key), "{suite}: sframe_key");
    assert_eq!(derived.key.len(), suite.key_len());
    assert_eq!(
        derived.salt[..],
        hex(vector.sframe_salt),
        "{suite}: sframe_salt"
    );
}

#[test]
fn rfc9605_c3_key_derivation_matches_for_every_suite() {
    assert_eq!(RFC9605_C3.len(), 5);
    for vector in RFC9605_C3 {
        assert_key_derivation(vector);
    }
}

#[test]
fn aes_256_ctr_suites_key_derivation_matches_the_registry_vectors() {
    assert_eq!(AES_256_CTR.len(), 3);
    for vector in AES_256_CTR {
        assert_key_derivation(vector);
    }
}

#[test]
fn key_derivation_depends_on_the_kid_and_the_cipher_suite() {
    let provider = provider();
    let base_key = hex(BASE_KEY);
    let derive = |suite, kid| {
        let derived = derive_key_salt(provider.crypto(), suite, kid, &base_key).unwrap();
        (derived.key.to_vec(), *derived.salt)
    };
    let reference = derive(CipherSuite::Aes128CtrHmacSha256_80, KID);
    assert_eq!(reference, derive(CipherSuite::Aes128CtrHmacSha256_80, KID));
    assert_ne!(
        reference,
        derive(CipherSuite::Aes128CtrHmacSha256_80, KID + 1)
    );
    // The same primitives and lengths, another suite value in the label.
    assert_ne!(reference, derive(CipherSuite::Aes128CtrHmacSha256_64, KID));
}

#[test]
fn key_derivation_refuses_an_empty_base_key() {
    let provider = provider();
    assert!(matches!(
        derive_key_salt(provider.crypto(), CipherSuite::Aes128GcmSha256_128, 0, &[]),
        Err(Error::EmptyBaseKey)
    ));
    assert!(matches!(
        ratchet_base_key(provider.crypto(), CipherSuite::Aes128GcmSha256_128, &[]),
        Err(Error::EmptyBaseKey)
    ));
}

#[test]
fn hkdf_matches_rfc5869_test_case_3_with_empty_salt_and_info() {
    // RFC 5869 Appendix A.3: SHA-256, zero-length salt and info, 42 bytes of output (two
    // blocks, the second cut short).
    let provider = provider();
    let ikm = [0x0b; 22];
    let prk = hkdf_extract(provider.crypto(), HmacAlgorithm::Sha256, &ikm).unwrap();
    assert_eq!(
        &prk[..32],
        hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
    );
    let mut okm = [0u8; 42];
    hkdf_expand(
        provider.crypto(),
        HmacAlgorithm::Sha256,
        &prk[..32],
        &[],
        &mut okm,
    )
    .unwrap();
    assert_eq!(
        okm[..],
        hex(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d
             9d201395faa4b61a96c8"
        )
    );
}

#[test]
fn ratchet_derives_the_next_base_keys_of_rfc9605_section_5_1() {
    // base_key[i+1] = HKDF-Expand(HKDF-Extract("", base_key[i]), "SFrame 1.0 Ratchet", Nh),
    // from base_key[0] = 00 01 .. 0f. Expected values computed with an independent HKDF
    // (Python hmac / hashlib); the RFC gives no vector for the ratchet.
    let provider = provider();
    let sha256 = [
        "fb75d8d5782da6c6cbf18ac43eca5da9e47f7e6ac7926a78e486226bd2af0f87",
        "e24577b569963f5222734f2f57c43927c10dd36180e6124cf9f10cd43ab4598e",
        "b791038937f6176e569a04e6ac99e8591d4d969a54ca059dd1405751d7e40059",
    ];
    let sha512 = [
        "895fe5603750295ccbe0d5ed9745617b46e9cf9b428179b8f29f3147492bb08f
         aa190560720ee0e4570760b64e7d5931120c391b7c7becc429ea35a9d07475aa",
        "9e1d8cbe51504d0b940985abd6c33137027a3299388bc4d9f74fddb2c5145f74
         6edac8eb7c6217fe71efe5bfbd9ed0ec77a39539b518d8d6109b529384bb10c4",
        "7381664f166955fb42aca83ba7d7cb0eb8a81d49466ee4d9e70a38d6250a9ed1
         4e99b319df93968d158631825898f147c4226d303070467e03e965c37ac22a77",
    ];
    for (suite, expected) in [
        (CipherSuite::Aes128CtrHmacSha256_80, sha256),
        (CipherSuite::Aes128GcmSha256_128, sha256),
        (CipherSuite::Aes256GcmSha512_128, sha512),
        (CipherSuite::Aes256CtrHmacSha512_32, sha512),
    ] {
        let mut base_key = hex(BASE_KEY);
        for step in expected {
            let next = ratchet_base_key(provider.crypto(), suite, &base_key).unwrap();
            assert_eq!(next.as_ref(), hex(step), "{suite}");
            assert_eq!(next.len(), suite.hash_len());
            base_key = next.as_ref().to_vec();
        }
    }
}

/// RFC 5869 appendix A.1 (SHA-256, test case 1): the salted HKDF-Extract and HKDF-Expand the
/// per-SSRC derivation of draft-ietf-avtcore-rtp-sframe-03 section 7 is built from.
#[test]
fn salted_hkdf_matches_rfc5869_test_case_1() {
    let provider = provider();
    let ikm = [0x0bu8; 22];
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let prk = hkdf_extract_salted(provider.crypto(), HmacAlgorithm::Sha256, &salt, &ikm).unwrap();
    assert_eq!(
        &prk[..32],
        hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    );
    let mut okm = [0u8; 42];
    hkdf_expand(
        provider.crypto(),
        HmacAlgorithm::Sha256,
        &prk[..32],
        &[&info],
        &mut okm,
    )
    .unwrap();
    assert_eq!(
        okm.to_vec(),
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );
}

/// draft-ietf-avtcore-rtp-sframe-03 section 7: the per-SSRC key is
/// HKDF-Expand(HKDF-Extract(SSRC as 4 bytes, base_key), "SFrame 1.0 RTP Stream", Nh): one key
/// per SSRC from one base key, `Nh` bytes, the same for the same inputs.
#[test]
fn the_per_ssrc_key_is_hkdf_of_the_base_key_salted_with_the_ssrc() {
    let provider = provider();
    let base_key = hex(BASE_KEY);
    for suite in [
        CipherSuite::Aes128CtrHmacSha256_80,
        CipherSuite::Aes128GcmSha256_128,
    ] {
        let a = derive_ssrc_key(provider.crypto(), suite, &base_key, 0x0102_0304).unwrap();
        let b = derive_ssrc_key(provider.crypto(), suite, &base_key, 0x0102_0305).unwrap();
        assert_eq!(a.len(), suite.hash_len());
        assert_ne!(a.as_ref(), b.as_ref(), "{suite}: another SSRC, another key");
        let again = derive_ssrc_key(provider.crypto(), suite, &base_key, 0x0102_0304).unwrap();
        assert_eq!(a.as_ref(), again.as_ref());

        let prk =
            hkdf_extract_salted(provider.crypto(), suite.hmac(), &[1, 2, 3, 4], &base_key).unwrap();
        let mut expected = vec![0u8; suite.hash_len()];
        hkdf_expand(
            provider.crypto(),
            suite.hmac(),
            &prk[..suite.hash_len()],
            &[b"SFrame 1.0 RTP Stream"],
            &mut expected,
        )
        .unwrap();
        assert_eq!(a.as_ref(), expected.as_slice(), "{suite}");
    }
    assert!(matches!(
        derive_ssrc_key(provider.crypto(), CipherSuite::Aes128GcmSha256_128, &[], 1),
        Err(Error::EmptyBaseKey)
    ));
}

/// draft-ietf-avtcore-rtp-sframe-03 Appendix A: (cipher suite, base_key, SSRC a, SSRC b, the
/// keys of a after the derivation and after one and two ratchet steps, the same for b).
type PerSsrcVector = (
    u16,
    &'static str,
    u32,
    u32,
    [&'static str; 3],
    [&'static str; 3],
);

const PER_SSRC_VECTORS: &[PerSsrcVector] = &[
    (
        0x0001,
        "000102030405060708090a0b0c0d0e0f",
        0x12345678,
        0x98765432,
        [
            "f309f118aecdacfbc165cc080022b297100bbb55e483b002d762000a0faa684d",
            "a8c48a47a6536eda200b4e94e8eaa6602f4f2266bd66284490229540f93127ab",
            "1141095c432877af08c314e0e2936ce4389d697c74769fb2db911ea467f984dc",
        ],
        [
            "06e5d1b8c6e01f10b592bd2e13ff4b37182b895ec8330d5cc6ec690704043b5f",
            "7aa3bf333dde545fe56daaf2449fbff1774f6df78ce0b593b59f05f3d1f505dd",
            "4aa1c3f077b45d4d76cb470690529534721b21eda62bceaa8ec73e59926d25c4",
        ],
    ),
    (
        0x0002,
        "000102030405060708090a0b0c0d0e0f",
        0x12345678,
        0x98765432,
        [
            "f309f118aecdacfbc165cc080022b297100bbb55e483b002d762000a0faa684d",
            "a8c48a47a6536eda200b4e94e8eaa6602f4f2266bd66284490229540f93127ab",
            "1141095c432877af08c314e0e2936ce4389d697c74769fb2db911ea467f984dc",
        ],
        [
            "06e5d1b8c6e01f10b592bd2e13ff4b37182b895ec8330d5cc6ec690704043b5f",
            "7aa3bf333dde545fe56daaf2449fbff1774f6df78ce0b593b59f05f3d1f505dd",
            "4aa1c3f077b45d4d76cb470690529534721b21eda62bceaa8ec73e59926d25c4",
        ],
    ),
    (
        0x0003,
        "000102030405060708090a0b0c0d0e0f",
        0x12345678,
        0x98765432,
        [
            "f309f118aecdacfbc165cc080022b297100bbb55e483b002d762000a0faa684d",
            "a8c48a47a6536eda200b4e94e8eaa6602f4f2266bd66284490229540f93127ab",
            "1141095c432877af08c314e0e2936ce4389d697c74769fb2db911ea467f984dc",
        ],
        [
            "06e5d1b8c6e01f10b592bd2e13ff4b37182b895ec8330d5cc6ec690704043b5f",
            "7aa3bf333dde545fe56daaf2449fbff1774f6df78ce0b593b59f05f3d1f505dd",
            "4aa1c3f077b45d4d76cb470690529534721b21eda62bceaa8ec73e59926d25c4",
        ],
    ),
    (
        0x0004,
        "000102030405060708090a0b0c0d0e0f",
        0x12345678,
        0x98765432,
        [
            "f309f118aecdacfbc165cc080022b297100bbb55e483b002d762000a0faa684d",
            "a8c48a47a6536eda200b4e94e8eaa6602f4f2266bd66284490229540f93127ab",
            "1141095c432877af08c314e0e2936ce4389d697c74769fb2db911ea467f984dc",
        ],
        [
            "06e5d1b8c6e01f10b592bd2e13ff4b37182b895ec8330d5cc6ec690704043b5f",
            "7aa3bf333dde545fe56daaf2449fbff1774f6df78ce0b593b59f05f3d1f505dd",
            "4aa1c3f077b45d4d76cb470690529534721b21eda62bceaa8ec73e59926d25c4",
        ],
    ),
    (
        0x0005,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        0x12345678,
        0x98765432,
        [
            "4715e2a3e3ecb408c83135a30b8e660c75a3488dbd4d9dd3553a01b39df76bc43a5a0b130159edd90353b09c810e849db7398182ac7c1dea072a2c1b6bac7dda",
            "9f0f48590c721b61733d1021212d6b92953e8aa73e9fac510e33113be7abb3a1230daf15bc5c5247ffeab88f745ca59eba608e832e8e9b5a50cd05c5b866e604",
            "b10d573c2a0447596d8a162093d7c0aa0fe0eb84a598d06174b24e8ab2ca73a81dedb3158a6ea9a734e5544769524766325a4248e585c8231a323f2093afc118",
        ],
        [
            "f7891c6b18d88a93ba7638875b87146df4cb9693ca3837b480e9221539e86c1c98391cb1273423b33f94abe7f67c1070997a588084a54391ebda18b3d6ff92f1",
            "686debc361271a29bb6e908ca4cbae6a8d2512ba73b89bbb883a81d6aceab6bf69e24064ae2758803ac4f2ff0aab2bd8cf1b4eab1e608892e816e4b4d6374b71",
            "ab9a74c7040713e8d1c3aa4ab5c6b22e214c81d571c182b7d83b480364e86c9cd99bff7af9e1abc9e6ef772460835aa420b30d9329b9f686558e6e601eb4615c",
        ],
    ),
    (
        0x0006,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        0x12345678,
        0x98765432,
        [
            "4715e2a3e3ecb408c83135a30b8e660c75a3488dbd4d9dd3553a01b39df76bc43a5a0b130159edd90353b09c810e849db7398182ac7c1dea072a2c1b6bac7dda",
            "9f0f48590c721b61733d1021212d6b92953e8aa73e9fac510e33113be7abb3a1230daf15bc5c5247ffeab88f745ca59eba608e832e8e9b5a50cd05c5b866e604",
            "b10d573c2a0447596d8a162093d7c0aa0fe0eb84a598d06174b24e8ab2ca73a81dedb3158a6ea9a734e5544769524766325a4248e585c8231a323f2093afc118",
        ],
        [
            "f7891c6b18d88a93ba7638875b87146df4cb9693ca3837b480e9221539e86c1c98391cb1273423b33f94abe7f67c1070997a588084a54391ebda18b3d6ff92f1",
            "686debc361271a29bb6e908ca4cbae6a8d2512ba73b89bbb883a81d6aceab6bf69e24064ae2758803ac4f2ff0aab2bd8cf1b4eab1e608892e816e4b4d6374b71",
            "ab9a74c7040713e8d1c3aa4ab5c6b22e214c81d571c182b7d83b480364e86c9cd99bff7af9e1abc9e6ef772460835aa420b30d9329b9f686558e6e601eb4615c",
        ],
    ),
    (
        0x0007,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        0x12345678,
        0x98765432,
        [
            "4715e2a3e3ecb408c83135a30b8e660c75a3488dbd4d9dd3553a01b39df76bc43a5a0b130159edd90353b09c810e849db7398182ac7c1dea072a2c1b6bac7dda",
            "9f0f48590c721b61733d1021212d6b92953e8aa73e9fac510e33113be7abb3a1230daf15bc5c5247ffeab88f745ca59eba608e832e8e9b5a50cd05c5b866e604",
            "b10d573c2a0447596d8a162093d7c0aa0fe0eb84a598d06174b24e8ab2ca73a81dedb3158a6ea9a734e5544769524766325a4248e585c8231a323f2093afc118",
        ],
        [
            "f7891c6b18d88a93ba7638875b87146df4cb9693ca3837b480e9221539e86c1c98391cb1273423b33f94abe7f67c1070997a588084a54391ebda18b3d6ff92f1",
            "686debc361271a29bb6e908ca4cbae6a8d2512ba73b89bbb883a81d6aceab6bf69e24064ae2758803ac4f2ff0aab2bd8cf1b4eab1e608892e816e4b4d6374b71",
            "ab9a74c7040713e8d1c3aa4ab5c6b22e214c81d571c182b7d83b480364e86c9cd99bff7af9e1abc9e6ef772460835aa420b30d9329b9f686558e6e601eb4615c",
        ],
    ),
    (
        0x0008,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        0x12345678,
        0x98765432,
        [
            "4715e2a3e3ecb408c83135a30b8e660c75a3488dbd4d9dd3553a01b39df76bc43a5a0b130159edd90353b09c810e849db7398182ac7c1dea072a2c1b6bac7dda",
            "9f0f48590c721b61733d1021212d6b92953e8aa73e9fac510e33113be7abb3a1230daf15bc5c5247ffeab88f745ca59eba608e832e8e9b5a50cd05c5b866e604",
            "b10d573c2a0447596d8a162093d7c0aa0fe0eb84a598d06174b24e8ab2ca73a81dedb3158a6ea9a734e5544769524766325a4248e585c8231a323f2093afc118",
        ],
        [
            "f7891c6b18d88a93ba7638875b87146df4cb9693ca3837b480e9221539e86c1c98391cb1273423b33f94abe7f67c1070997a588084a54391ebda18b3d6ff92f1",
            "686debc361271a29bb6e908ca4cbae6a8d2512ba73b89bbb883a81d6aceab6bf69e24064ae2758803ac4f2ff0aab2bd8cf1b4eab1e608892e816e4b4d6374b71",
            "ab9a74c7040713e8d1c3aa4ab5c6b22e214c81d571c182b7d83b480364e86c9cd99bff7af9e1abc9e6ef772460835aa420b30d9329b9f686558e6e601eb4615c",
        ],
    ),
];

/// draft-ietf-avtcore-rtp-sframe-03 sections 7 and 8 with the Appendix A vectors: the per-SSRC
/// key is derived once from the base key, and each ratchet step (RFC 9605 5.1) runs on the
/// per-SSRC key (`ratchet_base_key(derive_ssrc_key(..))`), never the other way round; the KID
/// is RFC 9605's, from the key generation and the ratchet steps alone, so both streams share it.
#[test]
fn per_ssrc_keys_and_their_ratchets_match_the_draft_vectors() {
    let provider = provider();
    let mut checked = 0;
    for &(suite, base_key, ssrc_a, ssrc_b, keys_a, keys_b) in PER_SSRC_VECTORS {
        let Ok(suite) = CipherSuite::try_from(suite) else {
            continue;
        };
        if !provider
            .crypto()
            .supports(crypto::CryptoAlgorithm::Hmac(suite.hmac()))
        {
            continue;
        }
        let base_key = hex(base_key);
        for (ssrc, keys) in [(ssrc_a, keys_a), (ssrc_b, keys_b)] {
            let mut key = derive_ssrc_key(provider.crypto(), suite, &base_key, ssrc).unwrap();
            assert_eq!(
                key.as_ref(),
                hex(keys[0]).as_slice(),
                "{suite} {ssrc:#x}: ssrc_key"
            );
            for (step, expected) in keys.iter().enumerate().skip(1) {
                key = ratchet_base_key(provider.crypto(), suite, key.as_ref()).unwrap();
                assert_eq!(
                    key.as_ref(),
                    hex(expected).as_slice(),
                    "{suite} {ssrc:#x}: ratchet {step}"
                );
            }
            // The other order (ratchet the base key, then derive) is not what the draft does.
            let ratcheted_base = ratchet_base_key(provider.crypto(), suite, &base_key).unwrap();
            let wrong =
                derive_ssrc_key(provider.crypto(), suite, ratcheted_base.as_ref(), ssrc).unwrap();
            assert_ne!(wrong.as_ref(), hex(keys[1]).as_slice());
        }
        // RFC 9605 5.1 KIDs: the same for every stream at a given generation and step.
        let layout = crate::SenderKeyIdLayout::new(8).unwrap();
        assert_eq!(layout.key_id(3, 2).unwrap(), (3 << 8) | 2);
        let split = layout.split(layout.key_id(3, 2).unwrap());
        assert_eq!((split.key_generation, split.ratchet_step), (3, 2));
        checked += 1;
    }
    assert!(
        checked >= 2,
        "the vectors of at least two suites were checked"
    );
}
