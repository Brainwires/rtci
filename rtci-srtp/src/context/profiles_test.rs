//! The transforms as whole packets: known answers built from the RFCs' key derivation vectors
//! for AES-128, AES-192 and AES-256 counter mode (RFC 3711 Appendix B.3, RFC 6188 sections 7.2
//! and 7.4), the NULL cipher (RFC 3711 sections 4.1.3 and 5.1), the tag lengths of the `_32`
//! suites (RFC 3711 section 5.2), replay protection defaults (section 3.3.2) and the DTLS-SRTP
//! code points.

use super::test_support::*;
use super::*;
use crate::test_util::{hex, provider};
use crypto::{HmacAlgorithm, StreamCipherAlgorithm};

const SSRC: u32 = 0xCAFE_BABE;

/// The master key and salt and the session keys the RFC derives from them (cipher key, cipher
/// salt, authentication key) for one key size.
struct KeyVector {
    master_key: &'static str,
    master_salt: &'static str,
    cipher_key: &'static str,
    cipher_salt: &'static str,
    auth_key: &'static str,
    algorithm: StreamCipherAlgorithm,
}

/// RFC 3711 Appendix B.3.
const AES_128: KeyVector = KeyVector {
    master_key: "E1F97A0D3E018BE0D64FA32C06DE4139",
    master_salt: "0EC675AD498AFEEBB6960B3AABE6",
    cipher_key: "C61E7A93744F39EE10734AFE3FF7A087",
    cipher_salt: "30CBBC08863D8C85D49DB34A9AE1",
    auth_key: "CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4",
    algorithm: StreamCipherAlgorithm::Aes128Ctr,
};
/// RFC 6188 section 7.4.
const AES_192: KeyVector = KeyVector {
    master_key: "73edc66c4fa15776fb57f9505c17136550ffda71f3e8e5f1",
    master_salt: "c8522f3acd4ce86d5add78edbb11",
    cipher_key: "31874736a8f1143870c26e4857d8a5b2c4a354407faadabb",
    cipher_salt: "2372b82d639b6d8503a47adc0a6c",
    auth_key: "355b10973cd95b9eacf4061c7e1a7151e7cfbfcb",
    algorithm: StreamCipherAlgorithm::Aes192Ctr,
};
/// RFC 6188 section 7.2.
const AES_256: KeyVector = KeyVector {
    master_key: "f0f04914b513f2763a1b1fa130f10e2998f6f6e43e4309d1e622a0e332b9f1b6",
    master_salt: "3b04803de51ee7c96423ab5b78d2",
    cipher_key: "5ba1064e30ec51613cad926c5a28ef731ec7fb397f70a960653caf06554cd8c4",
    cipher_salt: "fa31791685ca444a9e07c6c64e93",
    auth_key: "fd9c32d39ed5fbb5a9dc96b30818454d1313dc05",
    algorithm: StreamCipherAlgorithm::Aes256Ctr,
};

/// The SRTP packet RFC 3711 sections 3.1, 4.1.1 and 4.2 define for `packet` (a 12-octet header
/// and a payload, ROC 0), from the session keys of an RFC vector: the payload XORed with the
/// AES-CM keystream of IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16), then the leftmost
/// `tag_len` octets of HMAC-SHA1(k_a, packet || ROC). `encrypt` false is the NULL cipher.
fn expected_srtp(vector: &KeyVector, packet: &[u8], encrypt: bool, tag_len: usize) -> Vec<u8> {
    let provider = provider();
    let mut iv = [0u8; 16];
    iv[..14].copy_from_slice(&hex(vector.cipher_salt));
    for (dst, src) in iv[4..8].iter_mut().zip(&packet[8..12]) {
        *dst ^= src;
    }
    // i = ROC || SEQ with ROC 0, shifted left by 16 bits: SEQ lands in octets 12 and 13.
    iv[12] ^= packet[2];
    iv[13] ^= packet[3];

    let mut out = packet.to_vec();
    if encrypt {
        provider
            .crypto()
            .new_stream_cipher(vector.algorithm, &hex(vector.cipher_key))
            .unwrap()
            .apply_keystream(&iv, &mut out[12..])
            .unwrap();
    }
    let mut tag = [0u8; 20];
    provider
        .crypto()
        .new_hmac(HmacAlgorithm::Sha1, &hex(vector.auth_key))
        .unwrap()
        .sign(&[&out, &[0, 0, 0, 0]], &mut tag)
        .unwrap();
    out.extend_from_slice(&tag[..tag_len]);
    out
}

fn vector_context(vector: &KeyVector, profile: ProtectionProfile) -> Context {
    Context::new(
        &hex(vector.master_key),
        &hex(vector.master_salt),
        profile,
        None,
        None,
        provider().crypto(),
    )
    .unwrap()
}

/// RFC 3711 sections 3.1, 4.1.1, 4.2 and 5; RFC 6188 sections 2 and 4: the six AES counter-mode
/// suites, each with the PRF of its own key size and an 80- or 32-bit tag.
#[test]
fn aes_cm_packets_match_the_rfc_key_derivation_vectors() {
    let packet = rtp(SSRC, 0x1234, b"Gallia est omnis divisa in partes tres");
    for (vector, profile, tag_len) in [
        (&AES_128, ProtectionProfile::Aes128CmHmacSha1_80, 10),
        (&AES_128, ProtectionProfile::Aes128CmHmacSha1_32, 4),
        (&AES_192, ProtectionProfile::Aes192CmHmacSha1_80, 10),
        (&AES_192, ProtectionProfile::Aes192CmHmacSha1_32, 4),
        (&AES_256, ProtectionProfile::Aes256CmHmacSha1_80, 10),
        (&AES_256, ProtectionProfile::Aes256CmHmacSha1_32, 4),
    ] {
        let expected = expected_srtp(vector, &packet, true, tag_len);
        let protected = vector_context(vector, profile)
            .encrypt_rtp(&packet)
            .unwrap();
        assert_eq!(&protected[..], &expected[..], "{profile:?}");
        assert_ne!(&protected[12..packet.len()], &packet[12..], "{profile:?}");
        assert_eq!(
            &vector_context(vector, profile)
                .decrypt_rtp(&expected)
                .unwrap()[..],
            &packet[..],
            "{profile:?}"
        );
    }
}

/// RFC 3711 sections 4.1.3 and 5.1: the NULL cipher, mandatory to implement, copies the
/// plaintext to the ciphertext; the packet is still authenticated with HMAC-SHA1 under the
/// session authentication key (RFC 5764 section 4.1.2: derived with the AES-CM PRF).
#[test]
fn null_cipher_leaves_the_payload_and_authenticates_the_packet() {
    let packet = rtp(SSRC, 0x1234, b"in the clear, by negotiation");
    for (profile, tag_len) in [
        (ProtectionProfile::NullHmacSha1_80, 10),
        (ProtectionProfile::NullHmacSha1_32, 4),
    ] {
        assert!(profile.is_null_cipher());
        let expected = expected_srtp(&AES_128, &packet, false, tag_len);
        let protected = vector_context(&AES_128, profile)
            .encrypt_rtp(&packet)
            .unwrap();
        assert_eq!(&protected[..], &expected[..], "{profile:?}");
        assert_eq!(&protected[..packet.len()], &packet[..], "payload as it was");

        let mut receiver = vector_context(&AES_128, profile);
        assert_eq!(&receiver.decrypt_rtp(&protected).unwrap()[..], &packet[..]);
        // Authentication and replay protection are as with any other profile.
        assert_eq!(
            receiver.decrypt_rtp(&protected).unwrap_err(),
            Error::SrtpSsrcDuplicated(SSRC, 0x1234)
        );
        let mut forged = protected.to_vec();
        forged[14] ^= 1;
        assert_eq!(
            vector_context(&AES_128, profile)
                .decrypt_rtp(&forged)
                .unwrap_err(),
            Error::RtpFailedToVerifyAuthTag
        );

        // SRTCP: not encrypted, E flag clear, an 80-bit tag whatever the SRTP tag length.
        let report = vector_context(&AES_128, profile)
            .encrypt_rtcp(&rtcp())
            .unwrap();
        assert_eq!(report.len(), rtcp().len() + 4 + 10);
        assert_eq!(&report[..rtcp().len()], &rtcp()[..]);
        assert_eq!(esrtcp(profile, &report, 0), 0);
        assert_eq!(
            &vector_context(&AES_128, profile)
                .decrypt_rtcp(&report)
                .unwrap()[..],
            &rtcp()[..]
        );
        let mut forged = report.to_vec();
        forged[9] ^= 1;
        assert_eq!(
            vector_context(&AES_128, profile)
                .decrypt_rtcp(&forged)
                .unwrap_err(),
            Error::RtcpFailedToVerifyAuthTag
        );
    }
}

/// RFC 3711 section 5.2, RFC 6188 section 4: the `_32` suites shorten the SRTP tag to 32 bits
/// and nothing else. Their SRTCP tag stays at 80 bits ("for SRTCP, HMAC-SHA1 MUST NOT be
/// applied with a value of n_tag smaller than" 80 bits), and their keys are those of the `_80`
/// suite, so the SRTP packet is the `_80` one with the tag cut and the SRTCP packet is the same.
#[test]
fn the_32_bit_tag_suites_keep_an_80_bit_srtcp_tag() {
    for (short, full) in [
        (
            ProtectionProfile::Aes128CmHmacSha1_32,
            ProtectionProfile::Aes128CmHmacSha1_80,
        ),
        (
            ProtectionProfile::Aes192CmHmacSha1_32,
            ProtectionProfile::Aes192CmHmacSha1_80,
        ),
        (
            ProtectionProfile::Aes256CmHmacSha1_32,
            ProtectionProfile::Aes256CmHmacSha1_80,
        ),
        (
            ProtectionProfile::NullHmacSha1_32,
            ProtectionProfile::NullHmacSha1_80,
        ),
    ] {
        assert_eq!(
            (short.rtp_auth_tag_len(), short.rtcp_auth_tag_len()),
            (4, 10)
        );
        assert_eq!(
            (full.rtp_auth_tag_len(), full.rtcp_auth_tag_len()),
            (10, 10)
        );

        let packet = rtp(SSRC, 77, b"tag lengths");
        let with_full = context(full).encrypt_rtp(&packet).unwrap();
        let with_short = context(short).encrypt_rtp(&packet).unwrap();
        assert_eq!(with_short.len(), packet.len() + 4);
        assert_eq!(
            &with_short[..],
            &with_full[..with_full.len() - 6],
            "{short:?}"
        );

        let report = context(short).encrypt_rtcp(&rtcp()).unwrap();
        assert_eq!(
            report,
            context(full).encrypt_rtcp(&rtcp()).unwrap(),
            "{short:?}"
        );
        assert_eq!(report.len(), rtcp().len() + 4 + 10);
        // The receiver wants all 80 bits: a packet cut to a 32-bit tag is refused.
        assert!(
            context(short)
                .decrypt_rtcp(&report[..report.len() - 6])
                .is_err()
        );
    }
}

/// RFC 3711 section 3.3.2: replay protection is on unless it is turned off. A context created
/// with no replay options refuses a packet it has already accepted, SRTP and SRTCP; it used to
/// accept every replay.
#[test]
fn a_context_without_options_has_replay_protection() {
    for profile in ProtectionProfile::ALL {
        let mut sender = context(profile);
        let mut receiver = context(profile);
        let packet = sender.encrypt_rtp(&rtp(SSRC, 1, b"once")).unwrap();
        receiver.decrypt_rtp(&packet).unwrap();
        assert_eq!(
            receiver.decrypt_rtp(&packet).unwrap_err(),
            Error::SrtpSsrcDuplicated(SSRC, 1),
            "{profile:?}"
        );
        let report = sender.encrypt_rtcp(&rtcp()).unwrap();
        receiver.decrypt_rtcp(&report).unwrap();
        assert_eq!(
            receiver.decrypt_rtcp(&report).unwrap_err(),
            Error::SrtcpSsrcDuplicated(RTCP_SSRC, 0),
            "{profile:?}"
        );
    }
}

/// The default window is 64 packets (RFC 3711 section 3.3.2's minimum): a packet 63 behind the
/// newest is accepted once, one 64 behind is too old.
#[test]
fn the_default_replay_window_is_64_packets() {
    let profile = ProtectionProfile::Aes128CmHmacSha1_80;
    let mut sender = context(profile);
    let packets: Vec<_> = (0..=100u16)
        .map(|seq| sender.encrypt_rtp(&rtp(SSRC, seq, b"x")).unwrap())
        .collect();
    let mut receiver = context(profile);
    receiver.decrypt_rtp(&packets[100]).unwrap();
    receiver.decrypt_rtp(&packets[37]).unwrap();
    assert!(receiver.decrypt_rtp(&packets[37]).is_err());
    assert!(receiver.decrypt_rtp(&packets[36]).is_err());
}

/// Replay protection can still be turned off, explicitly.
#[test]
fn replay_protection_is_off_only_when_asked() {
    let profile = ProtectionProfile::Aes128CmHmacSha1_80;
    let (key, salt) = key_material(profile);
    let mut receiver = Context::new(
        &key,
        &salt,
        profile,
        Some(srtp_no_replay_protection()),
        Some(srtcp_no_replay_protection()),
        provider().crypto(),
    )
    .unwrap();
    let mut sender = context(profile);
    let packet = sender.encrypt_rtp(&rtp(SSRC, 1, b"x")).unwrap();
    let report = sender.encrypt_rtcp(&rtcp()).unwrap();
    for _ in 0..2 {
        receiver.decrypt_rtp(&packet).unwrap();
        receiver.decrypt_rtcp(&report).unwrap();
    }
}

/// RFC 3711 section 3.3.2: "SRTP-WINDOW-SIZE ... MUST be at least 64". A smaller window was
/// accepted, and dropped packets that arrived one position late.
#[test]
fn a_replay_window_below_64_is_refused() {
    for window in [0, 1, 32, 63] {
        assert!(srtp_replay_protection(window).is_err(), "{window}");
        assert!(srtcp_replay_protection(window).is_err(), "{window}");
    }
    for window in [64, 65, 1024, 4096] {
        assert!(srtp_replay_protection(window).is_ok(), "{window}");
        assert!(srtcp_replay_protection(window).is_ok(), "{window}");
    }

    // With the minimum window a packet reordered by one position is accepted.
    let profile = ProtectionProfile::Aes128CmHmacSha1_80;
    let (key, salt) = key_material(profile);
    let mut sender = context(profile);
    let first = sender.encrypt_rtp(&rtp(SSRC, 1, b"x")).unwrap();
    let second = sender.encrypt_rtp(&rtp(SSRC, 2, b"x")).unwrap();
    let mut receiver = Context::new(
        &key,
        &salt,
        profile,
        Some(srtp_replay_protection(MIN_REPLAY_PROTECTION_WINDOW).unwrap()),
        None,
        provider().crypto(),
    )
    .unwrap();
    receiver.decrypt_rtp(&second).unwrap();
    receiver.decrypt_rtp(&first).unwrap();
}

/// RFC 3711 section 3.2.1: s_l and the ROC move only for authenticated packets. A forged packet
/// for a stream the receiver already follows, far ahead and across a sequence number wrap,
/// leaves its index and its replay list as they were.
#[test]
fn a_forged_packet_leaves_an_existing_stream_untouched() {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ] {
        let mut sender = context(profile);
        let mut receiver = context(profile);
        let packet = sender.encrypt_rtp(&rtp(SSRC, 0xFFF0, b"x")).unwrap();
        receiver.decrypt_rtp(&packet).unwrap();
        let before = receiver.srtp_ssrc_states[&SSRC].index;

        // Sequence number 5 after 0xFFF0 would be ROC 1, if it were authentic.
        let mut forged = context(profile)
            .encrypt_rtp(&rtp(SSRC, 5, b"x"))
            .unwrap()
            .to_vec();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(receiver.decrypt_rtp(&forged).is_err());
        assert_eq!(
            receiver.srtp_ssrc_states[&SSRC].index, before,
            "{profile:?}"
        );
        assert_eq!(receiver.get_roc(SSRC), Some(0));

        // The stream goes on where it was: the next packets are accepted, and a replay is not.
        let next = sender.encrypt_rtp(&rtp(SSRC, 0xFFF1, b"x")).unwrap();
        receiver.decrypt_rtp(&next).unwrap();
        assert!(receiver.decrypt_rtp(&packet).is_err());
        assert_eq!(receiver.key_usage().srtp_packets, 2);
    }
}

/// RFC 3711 section 4.1.1: a keystream segment is at most 2^16 blocks, since the block counter
/// is the low 16 bits of the IV: one more block would run into the keystream of the next
/// packet index. A packet whose encrypted portion is longer is refused in both directions.
#[test]
fn aes_cm_refuses_more_than_2_pow_16_keystream_blocks() {
    let profile = ProtectionProfile::Aes128CmHmacSha1_80;
    let limit = (1 << 16) * 16;
    let largest = rtp(SSRC, 1, &vec![0x5A; limit]);
    let protected = context(profile).encrypt_rtp(&largest).unwrap();
    assert_eq!(
        &context(profile).decrypt_rtp(&protected).unwrap()[..],
        &largest[..]
    );

    let too_large = rtp(SSRC, 2, &vec![0x5A; limit + 1]);
    assert!(context(profile).encrypt_rtp(&too_large).is_err());
    let mut padded = too_large.clone();
    padded.extend_from_slice(&[0; 10]);
    assert!(context(profile).decrypt_rtp(&padded).is_err());

    let mut report = rtcp();
    report.resize(8 + limit + 4, 0);
    assert!(context(profile).encrypt_rtcp(&report).is_err());
    report.truncate(8 + limit);
    context(profile).encrypt_rtcp(&report).unwrap();
}

/// RFC 5764 section 4.1.2 and RFC 7714 section 14.2 (the IANA "DTLS-SRTP Protection Profiles"
/// registry): the code points `use_srtp` carries. The RFC 6188 counter-mode suites have none.
#[test]
fn dtls_srtp_code_points_are_the_registered_ones() {
    let registered = [
        (0x0001, ProtectionProfile::Aes128CmHmacSha1_80),
        (0x0002, ProtectionProfile::Aes128CmHmacSha1_32),
        (0x0005, ProtectionProfile::NullHmacSha1_80),
        (0x0006, ProtectionProfile::NullHmacSha1_32),
        (0x0007, ProtectionProfile::AeadAes128Gcm),
        (0x0008, ProtectionProfile::AeadAes256Gcm),
    ];
    for (id, profile) in registered {
        assert_eq!(profile.dtls_srtp_id(), Some(id));
        assert_eq!(ProtectionProfile::from_dtls_srtp_id(id), Some(profile));
    }
    for profile in ProtectionProfile::ALL {
        if !registered.iter().any(|(_, known)| *known == profile) {
            assert_eq!(profile.dtls_srtp_id(), None, "{profile:?}");
        }
    }
    // 0x0003 and 0x0004 are unassigned (other stacks use them for AES-f8).
    for id in [0x0000, 0x0003, 0x0004, 0x0009, 0x000B, 0xFFFF] {
        assert_eq!(ProtectionProfile::from_dtls_srtp_id(id), None, "{id:#06x}");
    }
}

/// The key, salt and tag lengths of each suite (RFC 3711 section 5, RFC 5764 section 4.1.2,
/// RFC 6188 section 4, RFC 7714 section 12), and the refusal of anything else.
#[test]
fn key_and_salt_lengths_are_those_of_the_suite() {
    use ProtectionProfile::*;
    for (profile, key_len, salt_len, rtp_tag, rtcp_tag, aead_tag) in [
        (Aes128CmHmacSha1_80, 16, 14, 10, 10, 0),
        (Aes128CmHmacSha1_32, 16, 14, 4, 10, 0),
        (Aes192CmHmacSha1_80, 24, 14, 10, 10, 0),
        (Aes192CmHmacSha1_32, 24, 14, 4, 10, 0),
        (Aes256CmHmacSha1_80, 32, 14, 10, 10, 0),
        (Aes256CmHmacSha1_32, 32, 14, 4, 10, 0),
        (NullHmacSha1_80, 16, 14, 10, 10, 0),
        (NullHmacSha1_32, 16, 14, 4, 10, 0),
        (AeadAes128Gcm, 16, 12, 0, 0, 16),
        (AeadAes256Gcm, 32, 12, 0, 0, 16),
    ] {
        assert_eq!(
            (
                profile.key_len(),
                profile.salt_len(),
                profile.rtp_auth_tag_len(),
                profile.rtcp_auth_tag_len(),
                profile.aead_auth_tag_len(),
                profile.auth_key_len(),
            ),
            (
                key_len,
                salt_len,
                rtp_tag,
                rtcp_tag,
                aead_tag,
                if aead_tag == 0 { 20 } else { 0 }
            ),
            "{profile:?}"
        );
        let crypto_provider = provider();
        let new = |key_len: usize, salt_len: usize| {
            Context::new(
                &vec![1; key_len],
                &vec![2; salt_len],
                profile,
                None,
                None,
                crypto_provider.crypto(),
            )
        };
        assert_eq!(new(key_len, salt_len).unwrap().profile(), profile);
        assert!(new(key_len + 8, salt_len).is_err(), "{profile:?}");
        assert!(new(key_len, salt_len + 2).is_err(), "{profile:?}");
        assert!(new(key_len, salt_len - 2).is_err(), "{profile:?}");
    }
}
