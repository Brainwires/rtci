//! Known answers from the RFCs for the primitives the transforms are built from: the AES
//! counter-mode keystream (RFC 3711 Appendix B.2, RFC 6188 sections 7.1 and 7.3), the key
//! derivation functions (RFC 3711 Appendix B.3, RFC 6188 sections 7.2 and 7.4, RFC 6904
//! Appendix A.1) and AES-GCM used to authenticate only (RFC 7714 sections 16.1.3, 16.1.4,
//! 16.2.3 and 16.2.4). Packet-level vectors are with the contexts, in `context/`.

use crate::cipher::new_aes_cm;
use crate::key_derivation::*;
use crate::test_util::{hex, provider};
use crypto::AeadAlgorithm;

/// The keystream segment of the three cases: 65282 AES blocks from an IV whose block counter
/// starts at 0.
const KEYSTREAM_BLOCKS: usize = 65282;

/// The first three and the last three keystream blocks for a session key, with the session
/// salt, SSRC, ROC and sequence number of the RFC's cases, through the IV formation and the
/// counter-mode cipher the transforms use.
fn keystream_ends(prf: Prf, session_key: &str) -> (Vec<u8>, Vec<u8>) {
    let provider = provider();
    // "F0F1...FD0000 (already shifted)": a 14-octet salt of F0..FD, SSRC 0, index 0.
    let salt = hex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD");
    let iv = generate_counter(0, 0, 0, &salt);
    assert_eq!(iv.to_vec(), hex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000"));

    let mut keystream = vec![0u8; KEYSTREAM_BLOCKS * 16];
    new_aes_cm(provider.crypto(), prf.stream_cipher(), &hex(session_key))
        .unwrap()
        .apply_keystream(&iv, &mut keystream)
        .unwrap();
    (
        keystream[..48].to_vec(),
        keystream[keystream.len() - 48..].to_vec(),
    )
}

/// RFC 3711 Appendix B.2.
#[test]
fn aes_128_cm_keystream_matches_rfc_3711_appendix_b2() {
    let (first, last) = keystream_ends(Prf::Aes128, "2B7E151628AED2A6ABF7158809CF4F3C");
    assert_eq!(
        first,
        hex("E03EAD0935C95E80E166B16DD92B4EB4
             D23513162B02D0F72A43A2FE4A5F97AB
             41E95B3BB0A2E8DD477901E4FCA894C0")
    );
    assert_eq!(
        last,
        hex("EC8CDF7398607CB0F2D21675EA9EA1E4
             362B7C3C6773516318A077D7FC5073AE
             6A2CC3787889374FBEB4C81B17BA6C44")
    );
}

/// RFC 6188 section 7.1.
#[test]
fn aes_256_cm_keystream_matches_rfc_6188_section_7_1() {
    let (first, last) = keystream_ends(
        Prf::Aes256,
        "57f82fe3613fd170a85ec93c40b1f0922ec4cb0dc025b58272147cc438944a98",
    );
    assert_eq!(
        first,
        hex("92bdd28a93c3f52511c677d08b5515a4
             9da71b2378a854f67050756ded165bac
             63c4868b7096d88421b563b8c94c9a31")
    );
    assert_eq!(
        last,
        hex("cea518c90fd91ced9cbb18c078a54711
             3dbc4814f4da5f00a08772b63c6a046d
             6eb246913062a16891433e97dd01a57f")
    );
}

/// RFC 6188 section 7.3.
#[test]
fn aes_192_cm_keystream_matches_rfc_6188_section_7_3() {
    let (first, last) = keystream_ends(
        Prf::Aes192,
        "eab234764e517b2d3d160d587d8c86219740f65f99b6bcf7",
    );
    assert_eq!(
        first,
        hex("35096cba4610028dc1b57503804ce37c
             5de986291dcce161d5165ec4568f5c9a
             474a40c77894bc17180202272a4c264d")
    );
    assert_eq!(
        last,
        hex("d108d1a31a00bad6367ec23eb044b415
             c8f57129fdeb970b59f917b257662d4c
             a5dab625811034e8cebdfeb6dc158dd3")
    );
}

fn derived(prf: Prf, label: u8, key: &str, salt: &str, len: usize) -> Vec<u8> {
    derive(
        provider().crypto(),
        prf,
        label,
        &hex(key),
        &hex(salt),
        0,
        len,
    )
    .unwrap()
    .as_ref()
    .to_vec()
}

/// RFC 3711 Appendix B.3, with the whole 94-octet authentication key (six AES blocks), and RFC
/// 6904 Appendix A.1, which derives the header keys from the same master key and salt.
#[test]
fn aes_cm_prf_matches_rfc_3711_appendix_b3_and_rfc_6904_appendix_a1() {
    let key = "E1F97A0D3E018BE0D64FA32C06DE4139";
    let salt = "0EC675AD498AFEEBB6960B3AABE6";
    let prf = Prf::Aes128;
    assert_eq!(
        derived(prf, LABEL_SRTP_ENCRYPTION, key, salt, 16),
        hex("C61E7A93744F39EE10734AFE3FF7A087")
    );
    assert_eq!(
        derived(prf, LABEL_SRTP_SALT, key, salt, 14),
        hex("30CBBC08863D8C85D49DB34A9AE1")
    );
    assert_eq!(
        derived(prf, LABEL_SRTP_AUTHENTICATION_TAG, key, salt, 94),
        hex("CEBE321F6FF7716B6FD4AB49AF256A15
             6D38BAA48F0A0ACF3C34E2359E6CDBCE
             E049646C43D9327AD175578EF7227098
             6371C10C9A369AC2F94A8C5FBCDDDC25
             6D6E919A48B610EF17C2041E47403576
             6B68642C59BBFC2F34DB60DBDFB2")
    );
    // RFC 6904 Appendix A.1: k_he (label 0x06) and k_hs (label 0x07).
    assert_eq!(
        derived(prf, LABEL_SRTP_HEADER_ENCRYPTION, key, salt, 16),
        hex("549752054D6FB708622C4A2E596A1B93")
    );
    assert_eq!(
        derived(prf, LABEL_SRTP_HEADER_SALT, key, salt, 14),
        hex("AB01818174C40D39A3781F7C2D27")
    );
}

/// RFC 6188 section 7.2.
#[test]
fn aes_256_cm_prf_matches_rfc_6188_section_7_2() {
    let key = "f0f04914b513f2763a1b1fa130f10e2998f6f6e43e4309d1e622a0e332b9f1b6";
    let salt = "3b04803de51ee7c96423ab5b78d2";
    let prf = Prf::Aes256;
    assert_eq!(
        derived(prf, LABEL_SRTP_ENCRYPTION, key, salt, 32),
        hex("5ba1064e30ec51613cad926c5a28ef731ec7fb397f70a960653caf06554cd8c4")
    );
    assert_eq!(
        derived(prf, LABEL_SRTP_SALT, key, salt, 14),
        hex("fa31791685ca444a9e07c6c64e93")
    );
    assert_eq!(
        derived(prf, LABEL_SRTP_AUTHENTICATION_TAG, key, salt, 20),
        hex("fd9c32d39ed5fbb5a9dc96b30818454d1313dc05")
    );
}

/// RFC 6188 section 7.4.
#[test]
fn aes_192_cm_prf_matches_rfc_6188_section_7_4() {
    let key = "73edc66c4fa15776fb57f9505c17136550ffda71f3e8e5f1";
    let salt = "c8522f3acd4ce86d5add78edbb11";
    let prf = Prf::Aes192;
    assert_eq!(
        derived(prf, LABEL_SRTP_ENCRYPTION, key, salt, 24),
        hex("31874736a8f1143870c26e4857d8a5b2c4a354407faadabb")
    );
    assert_eq!(
        derived(prf, LABEL_SRTP_SALT, key, salt, 14),
        hex("2372b82d639b6d8503a47adc0a6c")
    );
    assert_eq!(
        derived(prf, LABEL_SRTP_AUTHENTICATION_TAG, key, salt, 20),
        hex("355b10973cd95b9eacf4061c7e1a7151e7cfbfcb")
    );
}

/// RFC 7714 sections 16.1.3 / 16.1.4 (AES-128) and 16.2.3 / 16.2.4 (AES-256): the whole RTP
/// packet is associated data, there is no plaintext, and the cipher is the tag. SRTP has no
/// such mode (section 8.2 has every packet encrypted), so these are run against the AEAD
/// the transform uses; they pin the provider's GMAC for both key sizes, which unencrypted
/// SRTCP (section 9.3) relies on.
#[test]
fn aes_gcm_authentication_only_matches_rfc_7714_section_16() {
    let provider = provider();
    let packet = hex(
        "8040f17b 8041f8d3 5501a0b2 47616c6c 69612065 7374206f 6d6e6973 20646976
         69736120 696e2070 61727465 73207472 6573",
    );
    let iv = hex("51753c6580c2726f20718414");
    for (algorithm, key, expected) in [
        (
            AeadAlgorithm::Aes128Gcm,
            "000102030405060708090a0b0c0d0e0f",
            "22493f82d2bce397e9d79e3b19aa4216",
        ),
        (
            AeadAlgorithm::Aes256Gcm,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "a866d5910f887463067ceefec45215d4",
        ),
    ] {
        let mut aead = provider.crypto().new_aead(algorithm, &hex(key)).unwrap();
        let mut tag = [0u8; 16];
        aead.seal_in_place(&iv, &packet, &mut [], &mut tag).unwrap();
        assert_eq!(tag.to_vec(), hex(expected), "{algorithm:?} tagging");

        // Tag verification, and its refusal of a packet changed in one bit.
        aead.open_in_place(&iv, &packet, &mut [], &tag).unwrap();
        let mut altered = packet.clone();
        altered[20] ^= 0x01;
        assert!(aead.open_in_place(&iv, &altered, &mut [], &tag).is_err());
    }
}
