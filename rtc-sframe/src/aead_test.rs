use crate::Error;
use crate::aead::SuiteAead;
use crate::cipher_suite::NONCE_LEN;
use crate::test_util::{hex, provider};
use crate::test_vectors::RFC9605_C2;

fn nonce(text: &str) -> [u8; NONCE_LEN] {
    hex(text).try_into().unwrap()
}

#[test]
fn rfc9605_c2_aes_ctr_hmac_encrypts_to_the_given_ciphertext() {
    assert_eq!(RFC9605_C2.len(), 3);
    let provider = provider();
    for vector in RFC9605_C2 {
        let suite = vector.suite;
        let aad = hex(vector.aad);
        let expected = hex(vector.ct);
        let mut aead = SuiteAead::new(provider.crypto(), suite, &hex(vector.key)).unwrap();

        // AEAD.Encrypt(key, nonce, aad, pt) == ct, with the tag appended. The AAD is the same
        // bytes however it is divided between header and metadata.
        for split in 0..=aad.len() {
            let mut data = hex(vector.pt);
            let mut tag = vec![0u8; suite.tag_len()];
            aead.seal(
                &nonce(vector.nonce),
                &aad[..split],
                &aad[split..],
                &mut Vec::new(),
                &mut data,
                &mut tag,
            )
            .unwrap();
            data.extend_from_slice(&tag);
            assert_eq!(data, expected, "{suite}, aad split at {split}");
        }
    }
}

#[test]
fn rfc9605_c2_aes_ctr_hmac_decrypts_to_the_given_plaintext() {
    let provider = provider();
    for vector in RFC9605_C2 {
        let suite = vector.suite;
        let aad = hex(vector.aad);
        let ct = hex(vector.ct);
        let (data, tag) = ct.split_at(ct.len() - suite.tag_len());
        let mut aead = SuiteAead::new(provider.crypto(), suite, &hex(vector.key)).unwrap();

        let mut buffer = data.to_vec();
        aead.open(
            &nonce(vector.nonce),
            &aad,
            &[],
            &mut Vec::new(),
            &mut buffer,
            tag,
        )
        .unwrap();
        assert_eq!(buffer, hex(vector.pt), "{suite}");
    }
}

#[test]
fn aes_ctr_hmac_refuses_any_change_to_tag_ciphertext_aad_or_nonce() {
    let provider = provider();
    for vector in RFC9605_C2 {
        let suite = vector.suite;
        let aad = hex(vector.aad);
        let ct = hex(vector.ct);
        let (data, tag) = ct.split_at(ct.len() - suite.tag_len());
        let mut aead = SuiteAead::new(provider.crypto(), suite, &hex(vector.key)).unwrap();
        let mut open = |nonce: &[u8; NONCE_LEN], aad: &[u8], data: &[u8], tag: &[u8]| {
            let mut buffer = data.to_vec();
            aead.open(nonce, aad, &[], &mut Vec::new(), &mut buffer, tag)
        };

        for index in 0..tag.len() {
            for bit in 0..8 {
                let mut tag = tag.to_vec();
                tag[index] ^= 1 << bit;
                assert_eq!(
                    open(&nonce(vector.nonce), &aad, data, &tag),
                    Err(Error::AuthenticationFailed),
                    "{suite}: tag byte {index} bit {bit}"
                );
            }
        }
        for index in 0..data.len() {
            let mut data = data.to_vec();
            data[index] ^= 0x01;
            assert_eq!(
                open(&nonce(vector.nonce), &aad, &data, tag),
                Err(Error::AuthenticationFailed)
            );
        }
        let mut other_aad = aad.clone();
        other_aad[0] ^= 0x80;
        assert_eq!(
            open(&nonce(vector.nonce), &other_aad, data, tag),
            Err(Error::AuthenticationFailed)
        );
        // The lengths are authenticated: moving a byte from the AAD to the ciphertext fails.
        assert_eq!(
            open(&nonce(vector.nonce), &aad[..aad.len() - 1], data, tag),
            Err(Error::AuthenticationFailed)
        );
        let mut other_nonce = nonce(vector.nonce);
        other_nonce[NONCE_LEN - 1] ^= 0x01;
        assert_eq!(
            open(&other_nonce, &aad, data, tag),
            Err(Error::AuthenticationFailed)
        );
        // A tag of another suite's length is not this suite's tag.
        assert!(open(&nonce(vector.nonce), &aad, data, &tag[..tag.len() - 1]).is_err());
    }
}

#[test]
fn aead_refuses_a_key_of_the_wrong_length() {
    let provider = provider();
    for suite in crate::CipherSuite::ALL {
        for len in [0, suite.key_len() - 1, suite.key_len() + 1] {
            assert!(
                SuiteAead::new(provider.crypto(), suite, &vec![0x11; len]).is_err(),
                "{suite} with a {len}-byte key"
            );
        }
    }
}
