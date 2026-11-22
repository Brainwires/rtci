//! RFC 7714 sections 16 and 17: the SRTP and SRTCP test vectors of AEAD_AES_128_GCM and
//! AEAD_AES_256_GCM, and unencrypted (E = 0) SRTCP.
//!
//! The vectors state the AEAD key and salt (the session key and salt), not a master key, so
//! the contexts here are built around a cipher made from those; everything else is the code a
//! peer connection runs.

use super::test_support::*;
use super::*;
use crate::test_util::{hex, provider};
use crypto::{AeadAlgorithm, BlockCipherAlgorithm};

const KEY_128: &str = "000102030405060708090a0b0c0d0e0f";
const KEY_256: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
/// "Quid pro quo".
const SALT: &str = "517569642070726f2071756f";

/// "Gallia est omnis divisa in partes tres", sequence number 0xf17b, SSRC 0x5501a0b2.
const RTP_PLAIN: &str = "8040f17b 8041f8d3 5501a0b2 47616c6c 69612065 7374206f 6d6e6973
                         20646976 69736120 696e2070 61727465 73207472 6573";
const RTCP_PLAIN: &str = "81c8000d 4d617273 4e545031 4e545032 52545020 0000042a 0000e930
                          4c756e61 deadbeef deadbeef deadbeef deadbeef deadbeef";
const RTCP_SSRC_MARS: u32 = 0x4d61_7273;
const RTCP_INDEX: usize = 0x5d4;

fn vector_context(profile: ProtectionProfile) -> Context {
    let key = hex(if profile == ProtectionProfile::AeadAes128Gcm {
        KEY_128
    } else {
        KEY_256
    });
    let salt = hex(SALT);
    let cipher =
        CipherAeadAesGcm::from_session_keys(profile, &key, &salt, &key, &salt, provider().crypto())
            .unwrap();
    Context::from_cipher(profile, Box::new(cipher))
}

/// Sections 16.1.1 / 16.1.2 and 16.2.1 / 16.2.2: SRTP encryption and decryption.
#[test]
fn srtp_aead_aes_gcm_matches_rfc_7714_section_16() {
    for (profile, encrypted) in [
        (
            ProtectionProfile::AeadAes128Gcm,
            "8040f17b 8041f8d3 5501a0b2 f24de3a3 fb34de6c acba861c 9d7e4bca be633bd5
             0d294e6f 42a5f47a 51c7d19b 36de3adf 8833899d 7f27beb1 6a9152cf 765ee439 0cce",
        ),
        (
            ProtectionProfile::AeadAes256Gcm,
            "8040f17b 8041f8d3 5501a0b2 32b1de78 a822fe12 ef9f78fa 332e33aa b1801238
             9a58e2f3 b50b2a02 76ffae0f 1ba63799 b87b7aa3 db36dfff d6b0f9bb 7878d7a7 6c13",
        ),
    ] {
        let (plain, encrypted) = (hex(RTP_PLAIN), hex(encrypted));
        let out = vector_context(profile).encrypt_rtp(&plain).unwrap();
        assert_eq!(&out[..], &encrypted[..], "{profile:?} encryption");
        let out = vector_context(profile).decrypt_rtp(&encrypted).unwrap();
        assert_eq!(&out[..], &plain[..], "{profile:?} decryption");
    }
}

/// Sections 17.1 (AES-128) and 17.2 (AES-256): SRTCP encryption and tagging, verification and
/// decryption, with SRTCP index 0x5d4.
#[test]
fn srtcp_aead_aes_gcm_matches_rfc_7714_sections_17_1_and_17_2() {
    for (profile, encrypted) in [
        (
            ProtectionProfile::AeadAes128Gcm,
            "81c8000d 4d617273 63e94885 dcdab67c a727d766 2f6b7e99 7ff5c0f7 6c06f32d
             c676a5f1 730d6fda 4ce09b46 86303ded 0bb9275b c84aa458 96cf4d2f c5abf872
             45d9eade 800005d4",
        ),
        (
            ProtectionProfile::AeadAes256Gcm,
            "81c8000d 4d617273 d50ae4d1 f5ce5d30 4ba297e4 7d470c28 2c3ece5d bffe0a50
             a2eaa5c1 110555be 8415f658 c61de047 6f1b6fad 1d1eb30c 4446839f 57ff6f6c
             b26ac3be 800005d4",
        ),
    ] {
        let (plain, encrypted) = (hex(RTCP_PLAIN), hex(encrypted));
        let mut sender = vector_context(profile);
        sender.set_index(RTCP_SSRC_MARS, RTCP_INDEX);
        let out = sender.encrypt_rtcp(&plain).unwrap();
        assert_eq!(&out[..], &encrypted[..], "{profile:?} encryption");
        let out = vector_context(profile).decrypt_rtcp(&encrypted).unwrap();
        assert_eq!(&out[..], &plain[..], "{profile:?} decryption");
    }
}

/// Sections 17.3 (AES-128) and 17.4 (AES-256), and section 9.3: an SRTCP packet with the E flag
/// clear is authenticated as a whole (the packet and the ESRTCP word are the associated data),
/// carries its tag before the ESRTCP word, and is not decrypted.
#[test]
fn unencrypted_srtcp_aead_aes_gcm_matches_rfc_7714_sections_17_3_and_17_4() {
    for (profile, tag) in [
        (
            ProtectionProfile::AeadAes128Gcm,
            "841dd968 3dd78ec9 2ae58790 125f62b3",
        ),
        (
            ProtectionProfile::AeadAes256Gcm,
            "91db4afb feee5a97 8fab4393 ed2615fe",
        ),
    ] {
        let plain = hex(RTCP_PLAIN);
        let mut tagged = plain.clone();
        tagged.extend_from_slice(&hex(tag));
        tagged.extend_from_slice(&hex("000005d4"));

        let mut sender = vector_context(profile);
        sender.set_srtcp_encryption(false);
        sender.set_index(RTCP_SSRC_MARS, RTCP_INDEX);
        let out = sender.encrypt_rtcp(&plain).unwrap();
        assert_eq!(&out[..], &tagged[..], "{profile:?} tagging");

        let out = vector_context(profile).decrypt_rtcp(&tagged).unwrap();
        assert_eq!(&out[..], &plain[..], "{profile:?} tag verification");
    }
}

/// RFC 3711 section 3.4, RFC 7714 section 9: SRTCP is authenticated whatever its E flag. A
/// packet with E clear and a wrong tag, a changed octet or a changed index is refused, and so
/// is a packet whose E flag was flipped in transit, in either direction.
#[test]
fn unencrypted_srtcp_aead_aes_gcm_is_still_authenticated() {
    for profile in [
        ProtectionProfile::AeadAes128Gcm,
        ProtectionProfile::AeadAes256Gcm,
    ] {
        let mut sender = context(profile);
        sender.set_srtcp_encryption(false);
        let clear = sender.encrypt_rtcp(&rtcp()).unwrap();
        assert_eq!(esrtcp(profile, &clear, 0) >> 31, 0, "E flag is clear");
        assert_eq!(
            &clear[..rtcp().len()],
            &rtcp()[..],
            "the packet is not encrypted"
        );
        assert_eq!(
            &context(profile).decrypt_rtcp(&clear).unwrap()[..],
            &rtcp()[..]
        );

        let e_flag_at = clear.len() - 4;
        for at in [9, rtcp().len() + 3, e_flag_at, clear.len() - 1] {
            let mut forged = clear.to_vec();
            forged[at] ^= if at == e_flag_at { 0x80 } else { 0x01 };
            assert_eq!(
                context(profile).decrypt_rtcp(&forged).unwrap_err(),
                Error::ErrFailedToVerifyAuthTag,
                "{profile:?}: octet {at} changed"
            );
        }

        // An encrypted packet with its E flag cleared is not passed up as if it were plain.
        let mut encrypted = context(profile).encrypt_rtcp(&rtcp()).unwrap().to_vec();
        assert_eq!(esrtcp(profile, &encrypted, 0) >> 31, 1);
        let at = encrypted.len() - 4;
        encrypted[at] &= 0x7F;
        assert_eq!(
            context(profile).decrypt_rtcp(&encrypted).unwrap_err(),
            Error::ErrFailedToVerifyAuthTag
        );
    }
}

/// RFC 3711 section 3.4: the sender may leave SRTCP unencrypted with the HMAC profiles too; the
/// E flag says so and the receiver does not decrypt.
#[test]
fn unencrypted_srtcp_is_sent_and_received_with_the_hmac_profiles() {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::Aes192CmHmacSha1_32,
        ProtectionProfile::Aes256CmHmacSha1_80,
    ] {
        let mut sender = context(profile);
        assert!(sender.srtcp_encryption());
        sender.set_srtcp_encryption(false);
        let clear = sender.encrypt_rtcp(&rtcp()).unwrap();
        assert_eq!(esrtcp(profile, &clear, 0), 0, "E clear, index 0");
        assert_eq!(&clear[..rtcp().len()], &rtcp()[..]);
        assert_eq!(
            &context(profile).decrypt_rtcp(&clear).unwrap()[..],
            &rtcp()[..]
        );

        let mut forged = clear.to_vec();
        forged[10] ^= 1;
        assert_eq!(
            context(profile).decrypt_rtcp(&forged).unwrap_err(),
            Error::RtcpFailedToVerifyAuthTag
        );
    }
}

/// RFC 7714 section 11: AEAD_AES_256_GCM derives its session keys with AES_256_CM_PRF, and
/// AEAD_AES_128_GCM with the AES-CM PRF of RFC 3711, from a 96-bit master salt. The session
/// keys are computed here straight from RFC 3711 section 4.3.1 with the block cipher, and the
/// packets of a context given the master key compared with those of a cipher given these
/// session keys.
#[test]
fn aead_aes_gcm_session_keys_come_from_the_prf_of_the_key_size() {
    let provider = provider();
    for (profile, block) in [
        (
            ProtectionProfile::AeadAes128Gcm,
            BlockCipherAlgorithm::Aes128,
        ),
        (
            ProtectionProfile::AeadAes256Gcm,
            BlockCipherAlgorithm::Aes256,
        ),
    ] {
        let (master_key, master_salt) = key_material(profile);
        // PRF_n(k_master, x) with x = (label || 0^48) XOR master_salt, the salt padded to 112
        // bits; AES blocks of x * 2^16 + i.
        let prf = |label: u8, len: usize| -> Vec<u8> {
            let mut out = Vec::new();
            for i in 0..len.div_ceil(16) {
                let mut x = [0u8; 16];
                x[..12].copy_from_slice(&master_salt);
                x[7] ^= label;
                x[15] = i as u8;
                provider
                    .crypto()
                    .block_encrypt(block, &master_key, &mut x)
                    .unwrap();
                out.extend_from_slice(&x);
            }
            out.truncate(len);
            out
        };
        let key_len = profile.key_len();
        let cipher = CipherAeadAesGcm::from_session_keys(
            profile,
            &prf(0x00, key_len),
            &prf(0x02, 12),
            &prf(0x03, key_len),
            &prf(0x05, 12),
            provider.crypto(),
        )
        .unwrap();
        let mut from_session_keys = Context::from_cipher(profile, Box::new(cipher));
        let mut from_master_key = context(profile);

        let packet = rtp(7, 9, b"payload");
        assert_eq!(
            from_master_key.encrypt_rtp(&packet).unwrap(),
            from_session_keys.encrypt_rtp(&packet).unwrap(),
            "{profile:?} SRTP"
        );
        assert_eq!(
            from_master_key.encrypt_rtcp(&rtcp()).unwrap(),
            from_session_keys.encrypt_rtcp(&rtcp()).unwrap(),
            "{profile:?} SRTCP"
        );
    }
}

/// RFC 7714 sections 10 and 12: the AEAD is used with a 12-octet nonce and a 16-octet tag,
/// which is not truncated, for both key sizes.
#[test]
fn aead_aes_gcm_uses_a_full_tag_and_a_12_octet_nonce() {
    let provider = provider();
    for (profile, algorithm) in [
        (ProtectionProfile::AeadAes128Gcm, AeadAlgorithm::Aes128Gcm),
        (ProtectionProfile::AeadAes256Gcm, AeadAlgorithm::Aes256Gcm),
    ] {
        let packet = rtp(7, 9, b"payload");
        let out = context(profile).encrypt_rtp(&packet).unwrap();
        assert_eq!(out.len(), packet.len() + 16);
        let out = context(profile).encrypt_rtcp(&rtcp()).unwrap();
        assert_eq!(out.len(), rtcp().len() + 16 + 4);

        let mut aead = provider
            .crypto()
            .new_aead(algorithm, &vec![0; profile.key_len()])
            .unwrap();
        assert_eq!(aead.tag_len(), 16);
        for nonce_len in [8, 11, 13, 16] {
            let mut tag = [0u8; 16];
            assert!(
                aead.seal_in_place(&vec![0; nonce_len], &[], &mut [], &mut tag)
                    .is_err(),
                "{algorithm:?} took a {nonce_len}-octet nonce"
            );
        }
    }
}
