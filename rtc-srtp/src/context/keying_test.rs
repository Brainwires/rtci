//! The Master Key Identifier and the master-key table (RFC 3711 sections 3.1, 3.2.1, 3.4 and
//! 8.1; RFC 7714 sections 8.2 and 9.2), and the key derivation rate (RFC 3711 sections 4.3.1
//! and 4.3.2).

use super::test_support::*;
use super::*;
use crate::test_util::provider;

const SSRC: u32 = 0x0BAD_CAFE;
const MKI_A: [u8; 4] = [0xE1, 0xF9, 0x7A, 0x0D];
const MKI_B: [u8; 4] = [0xE1, 0xF9, 0x7A, 0x0E];

fn mki_context(profile: ProtectionProfile) -> Context {
    keyed_context(
        profile,
        Keying {
            mki: Some(MKI_A.to_vec()),
            ..Default::default()
        },
    )
}

/// A second master key and salt for the profile.
fn second_key(profile: ProtectionProfile) -> (Vec<u8>, Vec<u8>) {
    let (key, salt) = key_material(profile);
    (
        key.iter().map(|b| b ^ 0xFF).collect(),
        salt.iter().map(|b| b ^ 0xFF).collect(),
    )
}

/// RFC 3711 sections 3.1 and 3.4: the MKI follows the authenticated portion and precedes the
/// authentication tag, and is not covered by it. RFC 7714 sections 8.2 and 9.2: with an AEAD
/// it is raw data at the end of the packet. Apart from the MKI the packet is the one a context
/// without MKI produces.
#[test]
fn mki_is_placed_where_the_transform_puts_it() {
    for profile in ProtectionProfile::ALL {
        let packet = rtp(SSRC, 7, b"some payload");
        let plain = context(profile).encrypt_rtp(&packet).unwrap();
        let with_mki = mki_context(profile).encrypt_rtp(&packet).unwrap();
        // The HMAC tag trails the MKI; the AEAD tag is part of the cipher, before it.
        let at = plain.len() - profile.rtp_auth_tag_len();
        let mut expected = plain[..at].to_vec();
        expected.extend_from_slice(&MKI_A);
        expected.extend_from_slice(&plain[at..]);
        assert_eq!(&with_mki[..], &expected[..], "{profile:?} SRTP");

        let plain = context(profile).encrypt_rtcp(&rtcp()).unwrap();
        let with_mki = mki_context(profile).encrypt_rtcp(&rtcp()).unwrap();
        let at = plain.len() - profile.rtcp_auth_tag_len();
        let mut expected = plain[..at].to_vec();
        expected.extend_from_slice(&MKI_A);
        expected.extend_from_slice(&plain[at..]);
        assert_eq!(&with_mki[..], &expected[..], "{profile:?} SRTCP");
        assert_eq!(srtcp_index(profile, &with_mki, MKI_A.len()), 0);
    }
}

/// RFC 3711 section 3.3 (receiver step 7): the MKI and the tag are removed before the packet is
/// handed up, and the packet is processed with the master key its MKI names.
#[test]
fn receiver_selects_the_master_key_by_mki_and_strips_it() {
    for profile in ProtectionProfile::ALL {
        let (key_b, salt_b) = second_key(profile);
        let mut sender = mki_context(profile);
        let mut receiver = mki_context(profile);
        sender.add_master_key(&MKI_B, &key_b, &salt_b).unwrap();
        receiver.add_master_key(&MKI_B, &key_b, &salt_b).unwrap();
        assert_eq!(sender.sending_mki(), Some(&MKI_A[..]));
        assert_eq!(
            sender.mkis().collect::<Vec<_>>(),
            vec![&MKI_A[..], &MKI_B[..]]
        );

        let first = rtp(SSRC, 1, b"under key A");
        let under_a = sender.encrypt_rtp(&first).unwrap();
        let rtcp_a = sender.encrypt_rtcp(&rtcp()).unwrap();

        sender.set_sending_mki(&MKI_B).unwrap();
        let second = rtp(SSRC, 2, b"under key B");
        let under_b = sender.encrypt_rtp(&second).unwrap();
        let rtcp_b = sender.encrypt_rtcp(&rtcp()).unwrap();
        // RFC 3711 section 3.4: the SRTCP index is not reset when the key changes.
        assert_eq!(srtcp_index(profile, &rtcp_b, MKI_B.len()), 1, "{profile:?}");

        // Out of order across the key change: each packet finds its own key.
        assert_eq!(&receiver.decrypt_rtp(&under_b).unwrap()[..], &second[..]);
        assert_eq!(&receiver.decrypt_rtp(&under_a).unwrap()[..], &first[..]);
        assert_eq!(&receiver.decrypt_rtcp(&rtcp_b).unwrap()[..], &rtcp()[..]);
        assert_eq!(&receiver.decrypt_rtcp(&rtcp_a).unwrap()[..], &rtcp()[..]);
        // The replay lists carry over the key change.
        assert!(receiver.decrypt_rtp(&under_a).is_err());
        assert!(receiver.decrypt_rtcp(&rtcp_a).is_err());

        // The counts are per master key (RFC 3711 section 3.2.1).
        for mki in [MKI_A, MKI_B] {
            let usage = receiver.key_usage_of(&mki).unwrap();
            assert_eq!((usage.srtp_packets, usage.srtcp_packets), (1, 1));
        }

        // A packet of key B relabelled as key A does not authenticate: the MKI only selects
        // the key.
        let mut relabelled = sender.encrypt_rtp(&rtp(SSRC, 3, b"x")).unwrap().to_vec();
        let tag_len = profile.rtp_auth_tag_len();
        let at = relabelled.len() - tag_len - MKI_A.len();
        relabelled[at..at + 4].copy_from_slice(&MKI_A);
        assert!(receiver.decrypt_rtp(&relabelled).is_err(), "{profile:?}");
    }
}

/// A packet whose MKI names no master key is discarded (RFC 3711 section 3.2.3: no context, no
/// processing), and so is every packet of a master key that was removed.
#[test]
fn unknown_mki_is_refused() {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ] {
        let (key_b, salt_b) = second_key(profile);
        let mut sender = mki_context(profile);
        sender.add_master_key(&MKI_B, &key_b, &salt_b).unwrap();
        sender.set_sending_mki(&MKI_B).unwrap();
        let packet = sender.encrypt_rtp(&rtp(SSRC, 1, b"x")).unwrap();
        let report = sender.encrypt_rtcp(&rtcp()).unwrap();

        let mut receiver = mki_context(profile);
        assert!(receiver.decrypt_rtp(&packet).is_err());
        assert!(receiver.decrypt_rtcp(&report).is_err());
        receiver.add_master_key(&MKI_B, &key_b, &salt_b).unwrap();
        receiver.decrypt_rtp(&packet).unwrap();
        receiver.decrypt_rtcp(&report).unwrap();

        receiver.remove_master_key(&MKI_B).unwrap();
        let packet = sender.encrypt_rtp(&rtp(SSRC, 2, b"x")).unwrap();
        assert!(receiver.decrypt_rtp(&packet).is_err());
        assert_eq!(receiver.key_usage_of(&MKI_B), None);

        // A packet too short to hold the MKI is refused without reading past its start.
        assert!(receiver.decrypt_rtp(&rtp(SSRC, 9, b"")[..12]).is_err());
        assert!(
            receiver
                .decrypt_rtcp(&[0x80, 0xc9, 0, 1, 0, 0, 0, 1, 0, 0])
                .is_err()
        );
    }
}

/// RFC 3711 section 8.1: re-keying with the MKI. A master key that reached its lifetime is
/// replaced, and the session goes on; the rollover counter is kept (section 3.3.1).
#[test]
fn rekeying_with_an_mki_continues_after_key_exhaustion() {
    for profile in [
        ProtectionProfile::Aes256CmHmacSha1_80,
        ProtectionProfile::AeadAes256Gcm,
    ] {
        let (key_b, salt_b) = second_key(profile);
        let mut sender = mki_context(profile);
        let mut receiver = mki_context(profile);
        let lifetime = KeyLifetime {
            srtp_packets: 2,
            srtcp_packets: 2,
        };
        sender.set_key_lifetime(lifetime).unwrap();
        sender.set_roc(SSRC, 5);

        let send = |sender: &mut Context, seq: u16| sender.encrypt_rtp(&rtp(SSRC, seq, b"x"));
        send(&mut sender, 0xFFFE).unwrap();
        send(&mut sender, 0xFFFF).unwrap();
        assert_eq!(
            send(&mut sender, 0).unwrap_err(),
            Error::ErrExceededMaxPackets
        );
        let told = events(&mut sender);
        assert!(told.contains(&ContextEvent::KeyLifetimeExpiring {
            mki: MKI_A.to_vec(),
            kind: PacketKind::Rtp,
            remaining: 1
        }));
        assert!(told.contains(&ContextEvent::KeyExhausted {
            mki: MKI_A.to_vec(),
            kind: PacketKind::Rtp
        }));

        sender.add_master_key(&MKI_B, &key_b, &salt_b).unwrap();
        receiver.add_master_key(&MKI_B, &key_b, &salt_b).unwrap();
        sender.set_sending_mki(&MKI_B).unwrap();
        // The refused packet (sequence number 0, ROC 6) goes out under the new key.
        let packet = send(&mut sender, 0).unwrap();
        assert_eq!(sender.get_roc(SSRC), Some(6), "the ROC is not reset");
        receiver.set_roc(SSRC, 6);
        assert_eq!(
            &receiver.decrypt_rtp(&packet).unwrap()[..],
            &rtp(SSRC, 0, b"x")[..]
        );
        assert_eq!(sender.key_usage().srtp_packets, 1);
        assert_eq!(sender.key_usage_of(&MKI_A).unwrap().srtp_packets, 2);

        // The exhausted key can be dropped; the one in use cannot.
        assert!(sender.remove_master_key(&MKI_B).is_err());
        sender.remove_master_key(&MKI_A).unwrap();
        assert_eq!(sender.sending_mki(), Some(&MKI_B[..]));
        send(&mut sender, 1).unwrap();
    }
}

/// RFC 3711 section 3.2.1: whether an MKI is used, and its length, are fixed for the lifetime
/// of the context.
#[test]
fn mki_use_and_length_are_fixed_for_the_context() {
    let profile = ProtectionProfile::Aes128CmHmacSha1_80;
    let (key, salt) = key_material(profile);
    let (key_b, salt_b) = second_key(profile);

    // A context without MKI has one master key.
    let mut plain = context(profile);
    assert_eq!(plain.sending_mki(), None);
    assert_eq!(plain.mkis().count(), 0);
    assert!(plain.add_master_key(&MKI_B, &key_b, &salt_b).is_err());
    assert!(plain.set_sending_mki(&MKI_A).is_err());
    assert!(plain.remove_master_key(&[]).is_err());
    let mut keyed_without_mki = keyed_context(profile, Keying::default());
    assert!(
        keyed_without_mki
            .add_master_key(&MKI_B, &key_b, &salt_b)
            .is_err()
    );

    let mut context = mki_context(profile);
    for wrong_length in [&[] as &[u8], &MKI_B[..3], &[1u8, 2, 3, 4, 5][..]] {
        assert!(
            context
                .add_master_key(wrong_length, &key_b, &salt_b)
                .is_err()
        );
    }
    assert!(
        context.add_master_key(&MKI_A, &key_b, &salt_b).is_err(),
        "duplicate MKI"
    );
    assert!(
        context
            .add_master_key(&MKI_B, &key_b[1..], &salt_b)
            .is_err()
    );
    assert!(
        context
            .add_master_key(&MKI_B, &key_b, &salt_b[1..])
            .is_err()
    );
    assert!(context.set_sending_mki(&MKI_B).is_err(), "no such key yet");
    context.add_master_key(&MKI_B, &key_b, &salt_b).unwrap();

    for bad in [vec![], vec![0; MAX_MKI_LEN + 1]] {
        let keying = Keying {
            mki: Some(bad),
            ..Default::default()
        };
        assert!(
            Context::with_keying(&key, &salt, profile, keying, None, None, provider()).is_err()
        );
    }

    // The table is bounded.
    let mut context = mki_context(profile);
    for i in 1..MAX_MASTER_KEYS as u8 {
        context
            .add_master_key(&[0, 0, 1, i], &key_b, &salt_b)
            .unwrap();
    }
    assert!(
        context
            .add_master_key(&[0, 0, 2, 0], &key_b, &salt_b)
            .is_err()
    );
}

/// The master salt with `index DIV kdr` XORed into its last six octets: by RFC 3711 section
/// 4.3.1 (`x = key_id XOR master_salt`), a context with a zero rate and this salt derives the
/// session keys of that epoch of the context under test.
fn salt_of_epoch(profile: ProtectionProfile, epoch: u64) -> Vec<u8> {
    let (_, mut salt) = key_material(profile);
    salt.resize(14, 0);
    for (dst, src) in salt[8..].iter_mut().zip(&epoch.to_be_bytes()[2..]) {
        *dst ^= src;
    }
    salt
}

/// RFC 3711 section 4.3.1: with a non-zero key derivation rate the session keys of a packet
/// come from `index DIV kdr`, the index being ROC || SEQ. Checked against a zero-rate context
/// whose master salt carries that value, for the HMAC profiles (their salt is 112 bits, so the
/// equivalent salt is a valid one).
#[test]
fn srtp_session_keys_follow_the_key_derivation_rate() {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::Aes192CmHmacSha1_80,
        ProtectionProfile::Aes256CmHmacSha1_32,
        ProtectionProfile::NullHmacSha1_80,
    ] {
        let (key, _) = key_material(profile);
        let rate = KeyDerivationRate::new(16).unwrap();
        let mut sender = keyed_context(
            profile,
            Keying {
                key_derivation_rate: rate,
                ..Default::default()
            },
        );
        assert_eq!(sender.key_derivation_rate(), rate);
        sender.set_roc(SSRC, 3);
        // Index 0x3_0000 + seq: epochs 0x3000 (seq 0..15), 0x3001 (16..31), 0x3002 (32..).
        for (seq, epoch) in [(0u16, 0x3000u64), (15, 0x3000), (16, 0x3001), (40, 0x3002)] {
            let packet = rtp(SSRC, seq, b"key derivation rate");
            let mut reference = Context::new(
                &key,
                &salt_of_epoch(profile, epoch),
                profile,
                None,
                None,
                provider().crypto(),
            )
            .unwrap();
            reference.set_roc(SSRC, 3);
            assert_eq!(
                sender.encrypt_rtp(&packet).unwrap(),
                reference.encrypt_rtp(&packet).unwrap(),
                "{profile:?} sequence number {seq}"
            );
        }
    }
}

/// RFC 3711 section 4.3.2: for SRTCP the SRTCP index takes the place of the packet index in
/// the key derivation.
#[test]
fn srtcp_session_keys_follow_the_srtcp_index() {
    let profile = ProtectionProfile::Aes128CmHmacSha1_80;
    let (key, _) = key_material(profile);
    let mut sender = keyed_context(
        profile,
        Keying {
            key_derivation_rate: KeyDerivationRate::new(4).unwrap(),
            ..Default::default()
        },
    );
    for index in 0..10usize {
        let mut reference = Context::new(
            &key,
            &salt_of_epoch(profile, index as u64 / 4),
            profile,
            None,
            None,
            provider().crypto(),
        )
        .unwrap();
        reference.set_index(RTCP_SSRC, index);
        assert_eq!(
            sender.encrypt_rtcp(&rtcp()).unwrap(),
            reference.encrypt_rtcp(&rtcp()).unwrap(),
            "SRTCP index {index}"
        );
    }
}

/// Both ends derive the same keys at the same indexes, for every profile, across rate
/// boundaries and a sequence number wrap, with packets reordered over a boundary.
#[test]
fn key_derivation_rate_round_trips_across_boundaries() {
    for profile in ProtectionProfile::ALL {
        for rate in [1, 8, 1 << 16, 1 << 24] {
            let keying = Keying {
                key_derivation_rate: KeyDerivationRate::new(rate).unwrap(),
                mki: None,
            };
            let mut sender = keyed_context(profile, keying.clone());
            let mut receiver = keyed_context(profile, keying);
            let mut protected = Vec::new();
            for step in 0..24u16 {
                let seq = 0xFFF4u16.wrapping_add(step);
                let packet = rtp(SSRC, seq, &[step as u8; 9]);
                protected.push((packet.clone(), sender.encrypt_rtp(&packet).unwrap()));
            }
            // Deliver in pairs swapped, so some packets cross a boundary backwards.
            for pair in protected.chunks(2) {
                for (plain, packet) in pair.iter().rev() {
                    assert_eq!(
                        &receiver.decrypt_rtp(packet).unwrap()[..],
                        &plain[..],
                        "{profile:?} rate {rate}"
                    );
                }
            }
            for _ in 0..20 {
                let packet = sender.encrypt_rtcp(&rtcp()).unwrap();
                assert_eq!(&receiver.decrypt_rtcp(&packet).unwrap()[..], &rtcp()[..]);
            }
        }
    }
}

/// RFC 3711 section 4.3.1: the rate is fixed when the context is created, zero unless stated,
/// and with a zero rate the keys are derived once (the AEAD_AES_128_GCM packets of a
/// `with_keying` context are those of a plain one).
#[test]
fn key_derivation_rate_defaults_to_zero() {
    for profile in ProtectionProfile::ALL {
        assert!(context(profile).key_derivation_rate().is_zero());
        let packet = rtp(SSRC, 0x8000, b"zero rate");
        assert_eq!(
            keyed_context(profile, Keying::default())
                .encrypt_rtp(&packet)
                .unwrap(),
            context(profile).encrypt_rtp(&packet).unwrap(),
            "{profile:?}"
        );
    }
}
