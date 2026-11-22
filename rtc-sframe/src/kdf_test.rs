use crypto::HmacAlgorithm;

use crate::kdf::{derive_key_salt, hkdf_expand, hkdf_extract};
use crate::test_util::{hex, provider};
use crate::test_vectors::{AES_256_CTR, BASE_KEY, KID, RFC9605_C3, SFrameVector};
use crate::{CipherSuite, Error, ratchet_base_key};

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
