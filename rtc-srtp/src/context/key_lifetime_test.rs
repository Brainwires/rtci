//! Key exhaustion (RFC 3711 sections 3.3.1, 3.4 and 9.2; RFC 7714 sections 8.4, 9.4, 10 and
//! 13.1; RFC 6188 section 4): a master key protects at most 2^48 SRTP and 2^31 SRTCP packets,
//! the context refuses to go past that in either direction, and it tells the application
//! beforehand so it can re-key.

use super::test_support::*;
use super::*;
use std::collections::HashSet;

const SSRC: u32 = 0x1234_5678;

/// RFC 3711 section 3.4: the SRTCP index is zero before the first packet is sent and goes up
/// by one per packet, per SSRC.
#[test]
fn first_srtcp_packet_carries_index_zero() {
    for profile in ProtectionProfile::ALL {
        let mut sender = context(profile);
        for expected in 0..3 {
            let packet = sender.encrypt_rtcp(&rtcp()).unwrap();
            assert_eq!(srtcp_index(profile, &packet, 0), expected, "{profile:?}");
        }
        // A receiver accepts index 0 as the first packet of a stream.
        let first = context(profile).encrypt_rtcp(&rtcp()).unwrap();
        assert_eq!(
            &context(profile).decrypt_rtcp(&first).unwrap()[..],
            &rtcp()[..]
        );
    }
}

/// RFC 3711 section 9.2, RFC 7714 section 9.4: the 2^31st SRTCP packet is the last one a
/// master key protects. The next one is refused; before the fix the index wrapped to zero and
/// the keystream (the GCM nonce) of the first packets was used again.
#[test]
fn srtcp_is_refused_after_2_pow_31_packets_under_one_key() {
    for profile in ProtectionProfile::ALL {
        let mut sender = context(profile);
        sender
            .set_key_lifetime(KeyLifetime::MAX)
            .expect("the RFC 3711 maximum");
        sender.set_packets_processed(PacketKind::Rtcp, MAX_SRTCP_PACKETS_PER_KEY - 1);
        sender.set_index(RTCP_SSRC, 0x7FFF_FFFF);

        let last = sender.encrypt_rtcp(&rtcp()).unwrap();
        assert_eq!(srtcp_index(profile, &last, 0), 0x7FFF_FFFF, "{profile:?}");
        for _ in 0..3 {
            assert_eq!(
                sender.encrypt_rtcp(&rtcp()).unwrap_err(),
                Error::ErrExceededMaxPackets,
                "{profile:?}"
            );
        }
        // Another SSRC shares the master key, so it is refused too.
        let mut other = rtcp();
        other[4..8].copy_from_slice(&0x0102_0304u32.to_be_bytes());
        assert_eq!(
            sender.encrypt_rtcp(&other).unwrap_err(),
            Error::ErrExceededMaxPackets
        );
        assert_eq!(
            sender.key_usage().srtcp_packets,
            MAX_SRTCP_PACKETS_PER_KEY,
            "refused packets are not counted"
        );
        assert!(events(&mut sender).contains(&ContextEvent::KeyExhausted {
            mki: vec![],
            kind: PacketKind::Rtcp
        }));
    }
}

/// No SRTCP index is used twice with a master key: with a lifetime of N packets, exactly N
/// distinct indexes go out and then the context stops, however the SSRCs share them.
#[test]
fn srtcp_never_repeats_an_index_within_a_key_lifetime() {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes256Gcm,
    ] {
        let mut sender = context(profile);
        sender
            .set_key_lifetime(KeyLifetime {
                srtcp_packets: 40,
                ..KeyLifetime::MAX
            })
            .unwrap();
        let mut seen = HashSet::new();
        let mut sent = 0;
        for round in 0..100u32 {
            let ssrc = round % 3;
            let mut packet = rtcp();
            packet[4..8].copy_from_slice(&ssrc.to_be_bytes());
            match sender.encrypt_rtcp(&packet) {
                Ok(protected) => {
                    sent += 1;
                    assert!(
                        seen.insert((ssrc, srtcp_index(profile, &protected, 0))),
                        "an index was used twice"
                    );
                }
                Err(error) => assert_eq!(error, Error::ErrExceededMaxPackets),
            }
        }
        assert_eq!(sent, 40);
    }
}

/// RFC 3711 section 3.3.1: no SRTP packet is sent once the master key has protected its
/// lifetime of them, and re-keying is triggered before that.
#[test]
fn srtp_is_refused_after_the_key_lifetime_and_the_application_is_told_before() {
    for profile in ProtectionProfile::ALL {
        let mut sender = context(profile);
        sender
            .set_key_lifetime(KeyLifetime {
                srtp_packets: 64,
                ..KeyLifetime::MAX
            })
            .unwrap();
        for seq in 0..59 {
            sender.encrypt_rtp(&rtp(SSRC, seq, b"x")).unwrap();
        }
        assert_eq!(events(&mut sender), vec![], "{profile:?}: 5 of 64 left");
        sender.encrypt_rtp(&rtp(SSRC, 59, b"x")).unwrap();
        assert_eq!(
            events(&mut sender),
            vec![ContextEvent::KeyLifetimeExpiring {
                mki: vec![],
                kind: PacketKind::Rtp,
                remaining: 4
            }],
            "{profile:?}: the last sixteenth of the lifetime"
        );
        for seq in 60..64 {
            sender.encrypt_rtp(&rtp(SSRC, seq, b"x")).unwrap();
        }
        assert_eq!(events(&mut sender), vec![], "told once");
        assert_eq!(sender.key_usage().srtp_packets, 64);

        for seq in 64..67 {
            assert_eq!(
                sender.encrypt_rtp(&rtp(SSRC, seq, b"x")).unwrap_err(),
                Error::ErrExceededMaxPackets,
                "{profile:?}"
            );
        }
        // Another SSRC shares the master key.
        assert_eq!(
            sender.encrypt_rtp(&rtp(SSRC + 1, 1, b"x")).unwrap_err(),
            Error::ErrExceededMaxPackets
        );
        assert_eq!(
            events(&mut sender),
            vec![ContextEvent::KeyExhausted {
                mki: vec![],
                kind: PacketKind::Rtp
            }],
            "told once"
        );
        // The SRTCP count is separate.
        sender.encrypt_rtcp(&rtcp()).unwrap();
    }
}

/// RFC 7714 section 13.1: processing ceases on the receiving side as well once a master key
/// has been used for its lifetime of packets.
#[test]
fn receiver_stops_at_the_key_lifetime() {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ] {
        let mut sender = context(profile);
        let mut receiver = context(profile);
        receiver
            .set_key_lifetime(KeyLifetime {
                srtp_packets: 3,
                srtcp_packets: 2,
            })
            .unwrap();

        for seq in 0..3 {
            let packet = sender.encrypt_rtp(&rtp(SSRC, seq, b"x")).unwrap();
            // A forged packet is not counted against the key.
            let mut forged = packet.to_vec();
            forged[13] ^= 1;
            assert!(receiver.decrypt_rtp(&forged).is_err());
            receiver.decrypt_rtp(&packet).unwrap();
        }
        assert_eq!(receiver.key_usage().srtp_packets, 3);
        let packet = sender.encrypt_rtp(&rtp(SSRC, 3, b"x")).unwrap();
        assert_eq!(
            receiver.decrypt_rtp(&packet).unwrap_err(),
            Error::ErrExceededMaxPackets
        );

        for _ in 0..2 {
            let packet = sender.encrypt_rtcp(&rtcp()).unwrap();
            receiver.decrypt_rtcp(&packet).unwrap();
        }
        let packet = sender.encrypt_rtcp(&rtcp()).unwrap();
        assert_eq!(
            receiver.decrypt_rtcp(&packet).unwrap_err(),
            Error::ErrExceededMaxPackets
        );
        let events = events(&mut receiver);
        for kind in [PacketKind::Rtp, PacketKind::Rtcp] {
            assert!(events.contains(&ContextEvent::KeyExhausted { mki: vec![], kind }));
        }
    }
}

/// RFC 3711 section 3.3.1, RFC 7714 section 13.1: the receiver does not follow the rollover
/// counter past 2^32 - 1. A packet with a low sequence number after ROC 2^32 - 1 would be
/// processed with ROC 0, that is with the keystream of the stream's first packets; it was
/// accepted when protected that way.
#[test]
fn receiver_does_not_follow_a_roc_wrap() {
    for profile in ProtectionProfile::ALL {
        let mut sender = context(profile);
        sender.set_roc(SSRC, u32::MAX);
        let last = sender.encrypt_rtp(&rtp(SSRC, 0xFFFF, b"last")).unwrap();
        // What a sender that wrapped would produce: sequence number 0 under ROC 0.
        let wrapped = context(profile)
            .encrypt_rtp(&rtp(SSRC, 0, b"wrap"))
            .unwrap();

        let mut receiver = context(profile);
        receiver.set_roc(SSRC, u32::MAX);
        receiver.decrypt_rtp(&last).unwrap();
        assert_eq!(receiver.get_roc(SSRC), Some(u32::MAX));
        assert_eq!(
            receiver.decrypt_rtp(&wrapped).unwrap_err(),
            Error::ErrExceededMaxPackets,
            "{profile:?}"
        );
        assert_eq!(receiver.get_roc(SSRC), Some(u32::MAX), "state is unchanged");

        // The sender refuses to produce it in the first place.
        assert_eq!(
            sender.encrypt_rtp(&rtp(SSRC, 0, b"wrap")).unwrap_err(),
            Error::ErrExceededMaxPackets
        );
    }
}

/// RFC 3711 section 9.2 and RFC 7714 section 12 give 2^48 SRTP and 2^31 SRTCP packets; RFC 6188
/// section 4 gives its suites a default lifetime of 2^31 packets. Key management may shorten a
/// lifetime, never extend it past the RFC 3711 maximum.
#[test]
fn key_lifetime_defaults_follow_the_profile_and_cannot_exceed_the_maximum() {
    for profile in ProtectionProfile::ALL {
        let expected_srtp = match profile {
            ProtectionProfile::Aes192CmHmacSha1_80
            | ProtectionProfile::Aes192CmHmacSha1_32
            | ProtectionProfile::Aes256CmHmacSha1_80
            | ProtectionProfile::Aes256CmHmacSha1_32 => 1 << 31,
            _ => 1 << 48,
        };
        let mut context = context(profile);
        assert_eq!(
            context.key_lifetime(),
            KeyLifetime {
                srtp_packets: expected_srtp,
                srtcp_packets: 1 << 31
            },
            "{profile:?}"
        );
        assert_eq!(context.key_usage().lifetime, context.key_lifetime());

        for refused in [
            KeyLifetime {
                srtp_packets: (1 << 48) + 1,
                srtcp_packets: 1 << 31,
            },
            KeyLifetime {
                srtp_packets: 1 << 48,
                srtcp_packets: (1 << 31) + 1,
            },
            KeyLifetime {
                srtp_packets: 0,
                srtcp_packets: 1,
            },
        ] {
            assert!(context.set_key_lifetime(refused).is_err(), "{refused:?}");
        }
        // RFC 5764 section 4.1.2: DTLS-SRTP profiles have a maximum lifetime of 2^31 packets.
        let dtls_srtp = KeyLifetime {
            srtp_packets: 1 << 31,
            srtcp_packets: 1 << 31,
        };
        context.set_key_lifetime(dtls_srtp).unwrap();
        assert_eq!(context.key_lifetime(), dtls_srtp);
    }
}

/// RFC 3711 section 3.2.1: the context counts the packets processed with a master key, SRTP
/// and SRTCP apart, over all the SSRCs that share it.
#[test]
fn packets_are_counted_per_master_key_across_ssrcs() {
    let profile = ProtectionProfile::Aes128CmHmacSha1_80;
    let mut sender = context(profile);
    let mut receiver = context(profile);
    for ssrc in 1..=3u32 {
        for seq in 0..4 {
            let packet = sender.encrypt_rtp(&rtp(ssrc, seq, b"x")).unwrap();
            receiver.decrypt_rtp(&packet).unwrap();
            // A replay is refused and not counted.
            assert!(receiver.decrypt_rtp(&packet).is_err());
        }
    }
    for _ in 0..5 {
        let packet = sender.encrypt_rtcp(&rtcp()).unwrap();
        receiver.decrypt_rtcp(&packet).unwrap();
    }
    for context in [&sender, &receiver] {
        let usage = context.key_usage();
        assert_eq!((usage.srtp_packets, usage.srtcp_packets), (12, 5));
    }
    assert_eq!(sender.key_usage_of(&[]), None, "no MKI in use");
}
