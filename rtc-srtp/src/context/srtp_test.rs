use super::*;
use shared::marshal::*;

/// The built-in provider, for tests only. Library code never resolves a default: every public
/// constructor takes the provider from its caller.
fn test_crypto_provider() -> std::sync::Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

use bytes::Bytes;
use lazy_static::lazy_static;

struct RTPTestCase {
    sequence_number: u16,
    encrypted: Bytes,
}

lazy_static! {
    static ref RTP_TEST_CASE_DECRYPTED: Bytes = Bytes::from_static(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    static ref RTP_TEST_CASES: Vec<RTPTestCase> = vec![
        RTPTestCase {
            sequence_number: 5000,
            encrypted: Bytes::from_static(&[
                0x6d, 0xd3, 0x7e, 0xd5, 0x99, 0xb7, 0x2d, 0x28, 0xb1, 0xf3, 0xa1, 0xf0, 0xc, 0xfb,
                0xfd, 0x8
            ]),
        },
        RTPTestCase {
            sequence_number: 5001,
            encrypted: Bytes::from_static(&[
                0xda, 0x47, 0xb, 0x2a, 0x74, 0x53, 0x65, 0xbd, 0x2f, 0xeb, 0xdc, 0x4b, 0x6d, 0x23,
                0xf3, 0xde
            ]),
        },
        RTPTestCase {
            sequence_number: 5002,
            encrypted: Bytes::from_static(&[
                0x6e, 0xa7, 0x69, 0x8d, 0x24, 0x6d, 0xdc, 0xbf, 0xec, 0x2, 0x1c, 0xd1, 0x60, 0x76,
                0xc1, 0x0e
            ]),
        },
        RTPTestCase {
            sequence_number: 5003,
            encrypted: Bytes::from_static(&[
                0x24, 0x7e, 0x96, 0xc8, 0x7d, 0x33, 0xa2, 0x92, 0x8d, 0x13, 0x8d, 0xe0, 0x76, 0x9f,
                0x08, 0xdc
            ]),
        },
        RTPTestCase {
            sequence_number: 5004,
            encrypted: Bytes::from_static(&[
                0x75, 0x43, 0x28, 0xe4, 0x3a, 0x77, 0x59, 0x9b, 0x2e, 0xdf, 0x7b, 0x12, 0x68, 0x0b,
                0x57, 0x49
            ]),
        },
        RTPTestCase{
            sequence_number: 65535, // upper boundary
            encrypted: Bytes::from_static(&[
                0xaf, 0xf7, 0xc2, 0x70, 0x37, 0x20, 0x83, 0x9c, 0x2c, 0x63, 0x85, 0x15, 0x0e, 0x44,
                0xca, 0x36
            ]),
        },
    ];
}

fn build_test_context() -> Result<Context> {
    let master_key = Bytes::from_static(&[
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ]);
    let master_salt = Bytes::from_static(&[
        0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c,
    ]);

    Context::new(
        &master_key,
        &master_salt,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        test_crypto_provider().crypto(),
    )
}

#[test]
fn test_rtp_invalid_auth() -> Result<()> {
    let master_key = Bytes::from_static(&[
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ]);
    let invalid_salt = Bytes::from_static(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    let mut encrypt_context = build_test_context()?;
    let mut invalid_context = Context::new(
        &master_key,
        &invalid_salt,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        test_crypto_provider().crypto(),
    )?;

    for test_case in &*RTP_TEST_CASES {
        let pkt = rtp::Packet {
            header: rtp::Header {
                sequence_number: test_case.sequence_number,
                ..Default::default()
            },
            payload: RTP_TEST_CASE_DECRYPTED.clone(),
        };

        let pkt_raw = pkt.marshal()?;
        let out = encrypt_context.encrypt_rtp(&pkt_raw)?;

        let result = invalid_context.decrypt_rtp(&out);
        assert!(
            result.is_err(),
            "Managed to decrypt with incorrect salt for packet with SeqNum: {}",
            test_case.sequence_number
        );
    }

    Ok(())
}

#[test]
fn test_rtp_lifecyle() -> Result<()> {
    let mut encrypt_context = build_test_context()?;
    let mut decrypt_context = build_test_context()?;
    let auth_tag_len = ProtectionProfile::Aes128CmHmacSha1_80.rtp_auth_tag_len();

    for test_case in RTP_TEST_CASES.iter() {
        let decrypted_pkt = rtp::Packet {
            header: rtp::Header {
                sequence_number: test_case.sequence_number,
                ..Default::default()
            },
            payload: RTP_TEST_CASE_DECRYPTED.clone(),
        };

        let decrypted_raw = decrypted_pkt.marshal()?;

        let encrypted_pkt = rtp::Packet {
            header: rtp::Header {
                sequence_number: test_case.sequence_number,
                ..Default::default()
            },
            payload: test_case.encrypted.clone(),
        };

        let encrypted_raw = encrypted_pkt.marshal()?;
        let actual_encrypted = encrypt_context.encrypt_rtp(&decrypted_raw)?;
        assert_eq!(
            actual_encrypted, encrypted_raw,
            "RTP packet with SeqNum invalid encryption: {}",
            test_case.sequence_number
        );

        let actual_decrypted = decrypt_context.decrypt_rtp(&encrypted_raw)?;
        assert_ne!(
            encrypted_raw[..encrypted_raw.len() - auth_tag_len].to_vec(),
            actual_decrypted,
            "DecryptRTP improperly encrypted in place"
        );

        assert_eq!(
            actual_decrypted, decrypted_raw,
            "RTP packet with SeqNum invalid decryption: {}",
            test_case.sequence_number,
        )
    }

    Ok(())
}

//TODO: BenchmarkEncryptRTP
//TODO: BenchmarkEncryptRTPInPlace
//TODO: BenchmarkDecryptRTP

/// Packets that fail authentication must not create per-SSRC state: otherwise a peer (or
/// anyone who can reach the socket) can grow the state map with made-up SSRCs.
#[test]
fn test_unauthenticated_packets_do_not_create_ssrc_state() -> Result<()> {
    let mut ctx = build_test_context()?;
    for ssrc in 0..1000u32 {
        let header = rtp::header::Header {
            version: 2,
            sequence_number: 1,
            ssrc,
            ..Default::default()
        };
        let mut raw = header.marshal()?.to_vec();
        raw.extend_from_slice(&[0u8; 30]); // payload + a bogus auth tag
        assert!(ctx.decrypt_rtp_with_header(&raw, &header).is_err());
    }
    assert!(
        ctx.srtp_ssrc_states.is_empty(),
        "{} SSRC states were created by unauthenticated packets",
        ctx.srtp_ssrc_states.len()
    );
    Ok(())
}

/// Fuzz regression (`context_decrypt`): a header extension element that runs past the declared
/// extension length made `Header::marshal_size` exceed the packet, and the AEAD cipher's
/// `split_at_mut(header_len)` panicked. The packet is the minimised fuzz input.
#[test]
fn test_encrypt_rtp_extension_overrunning_header_is_an_error() -> Result<()> {
    const PACKET: [&str; 6] = [
        "92009000000000f89292b60201000000000000961000003b005a5a5a16009292920000920000f892b6ffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffff00000000000026ab00080000042800005a5a5a5a5a5a5a5a",
        "5a003b00000000000a00040000000a00005a5a0000929200ffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffff00000000000026ab0008000b00042800005a5a5a5a5a5a5a5a5a003b0000",
        "0000000a00040000000a00005a5affffffffffffffffffffffffffffff00000000000026ab0008000b00042800005a5a",
        "5a5a5a5a5a5a5a003b00000000000a00040000000a00005a5a",
    ];
    let packet: Vec<u8> = PACKET
        .concat()
        .as_bytes()
        .chunks(2)
        .map(|h| u8::from_str_radix(std::str::from_utf8(h).unwrap(), 16).unwrap())
        .collect();
    // A small packet with the same flaw: a two-byte extension block of one word holding an
    // element whose 11-byte payload runs into the RTP payload.
    let mut small = vec![
        0x90, 96, 0, 1, 0, 0, 0, 1, 0, 0, 0, 7, 0x10, 0x00, 0x00, 0x01, 0x01, 0x0b,
    ];
    small.extend_from_slice(&[0xab; 11]);

    let provider = test_crypto_provider();
    for profile in [
        ProtectionProfile::AeadAes256Gcm,
        ProtectionProfile::AeadAes128Gcm,
        ProtectionProfile::Aes128CmHmacSha1_80,
    ] {
        let key = vec![1u8; profile.key_len()];
        let salt = vec![2u8; profile.salt_len()];
        let mut ctx = Context::new(&key, &salt, profile, None, None, provider.crypto())?;
        assert!(ctx.encrypt_rtp(&packet).is_err(), "{profile:?}");
        assert!(ctx.encrypt_rtp(&small).is_err(), "{profile:?}");
        assert!(ctx.decrypt_rtp(&small).is_err(), "{profile:?}");
    }
    Ok(())
}

const HALF_RANGE_SSRC: u32 = 0x5eed_0001;

fn half_range_rtp(sequence_number: u16) -> Result<Vec<u8>> {
    let pkt = rtp::Packet {
        header: rtp::Header {
            version: 2,
            sequence_number,
            ssrc: HALF_RANGE_SSRC,
            ..Default::default()
        },
        payload: RTP_TEST_CASE_DECRYPTED.clone(),
    };
    Ok(pkt.marshal()?.to_vec())
}

fn build_replay_protected_test_context() -> Result<Context> {
    let master_key = Bytes::from_static(&[
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ]);
    let master_salt = Bytes::from_static(&[
        0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c,
    ]);

    Context::new(
        &master_key,
        &master_salt,
        ProtectionProfile::Aes128CmHmacSha1_80,
        Some(srtp_replay_protection(64)),
        None,
        test_crypto_provider().crypto(),
    )
}

/// A packet exactly 2^15 behind the highest index is old (RFC 3711 Appendix A): it leaves the
/// index where it is, replay protection refuses it, and later packets keep decrypting.
#[test]
fn test_packet_half_range_behind_does_not_rewind_the_index() -> Result<()> {
    const REPLAYED: u16 = 40000 - 32768;

    for replay_protection in [false, true] {
        let mut sender = build_test_context()?;
        let mut receiver = if replay_protection {
            build_replay_protected_test_context()?
        } else {
            build_test_context()?
        };

        let mut kept = None;
        for seq in (0..=40000u16).step_by(16) {
            let protected = sender.encrypt_rtp(&half_range_rtp(seq)?)?;
            receiver.decrypt_rtp(&protected)?;
            if seq == REPLAYED {
                kept = Some(protected);
            }
        }
        let kept = kept.expect("the replayed sequence number is on the stride");

        let replayed = receiver.decrypt_rtp(&kept);
        if replay_protection {
            assert!(
                replayed.is_err(),
                "a replay half the range behind was accepted"
            );
        }
        assert_eq!(
            receiver.srtp_ssrc_states[&HALF_RANGE_SSRC].index, 40000,
            "the index moved (replay protection: {replay_protection})"
        );

        // Genuine traffic continues, across the sequence number wrap.
        let after = std::iter::once(40001u16)
            .chain((41000..=65000u16).step_by(1000))
            .chain(0..4u16);
        for seq in after {
            let protected = sender.encrypt_rtp(&half_range_rtp(seq)?)?;
            assert_eq!(
                receiver.decrypt_rtp(&protected)?.to_vec(),
                half_range_rtp(seq)?,
                "seq {seq} (replay protection: {replay_protection})"
            );
        }
        assert_eq!(
            receiver.srtp_ssrc_states[&HALF_RANGE_SSRC].index >> 16,
            1,
            "the ROC follows the sender across the wrap"
        );
    }
    Ok(())
}

/// An SRTP packet index is protected at most once (RFC 3711 Section 3.3.1, RFC 7714 Section
/// 8.1). Indexes not yet sent, in any order within the window, are still accepted, and so is
/// the sequence number wrap.
#[test]
fn test_encrypt_refuses_a_used_packet_index() -> Result<()> {
    let provider = test_crypto_provider();
    for profile in [
        ProtectionProfile::AeadAes128Gcm,
        ProtectionProfile::AeadAes256Gcm,
        ProtectionProfile::Aes128CmHmacSha1_80,
    ] {
        let key = vec![3u8; profile.key_len()];
        let salt = vec![4u8; profile.salt_len()];
        let mut ctx = Context::new(&key, &salt, profile, None, None, provider.crypto())?;

        let packet = |seq: u16, stamp: u8| -> Result<Vec<u8>> {
            let mut header = rtp::Header {
                version: 2,
                payload_type: 96,
                sequence_number: seq,
                ssrc: 0xfeed_0002,
                ..Default::default()
            };
            header.set_extension(3, bytes::Bytes::from(vec![stamp, 0]))?;
            let pkt = rtp::Packet {
                header,
                payload: RTP_TEST_CASE_DECRYPTED.clone(),
            };
            Ok(pkt.marshal()?.to_vec())
        };

        ctx.encrypt_rtp(&packet(100, 1)?)?;
        ctx.encrypt_rtp(&packet(101, 2)?)?;

        // The same index again, with a different extension (and with the same bytes).
        for stamp in [9, 1] {
            let err = ctx
                .encrypt_rtp(&packet(100, stamp)?)
                .expect_err("a used index was encrypted again");
            assert!(
                matches!(err, Error::SrtpIndexReused(0xfeed_0002, 100)),
                "{profile:?}: {err:?}"
            );
        }

        // A refused packet changes nothing: the stream continues.
        ctx.encrypt_rtp(&packet(103, 3)?)?;
        // An index skipped earlier is new and still in the window.
        ctx.encrypt_rtp(&packet(102, 4)?)?;
        assert!(ctx.encrypt_rtp(&packet(102, 5)?).is_err(), "{profile:?}");

        // Further back than the window: refused, it may have been sent before.
        let far = 103 + SRTP_SEND_INDEX_WINDOW as u16 + 10;
        ctx.encrypt_rtp(&packet(far, 6)?)?;
        assert!(ctx.encrypt_rtp(&packet(104, 7)?).is_err(), "{profile:?}");

        // Across the wrap the ROC makes the index new again.
        let mut seq = far;
        while seq < 65000 {
            seq += 20000.min(65000 - seq).max(1);
            ctx.encrypt_rtp(&packet(seq, 8)?)?;
        }
        ctx.encrypt_rtp(&packet(100, 10)?)?;
        assert_eq!(ctx.srtp_ssrc_states[&0xfeed_0002].index >> 16, 1);
        assert!(ctx.encrypt_rtp(&packet(100, 11)?).is_err(), "{profile:?}");
    }
    Ok(())
}

/// One context keeps SRTP state for at most `MAX_SSRC_STATES` SSRCs: a further SSRC is
/// refused (before decryption on the receiving side) and existing streams keep working.
#[test]
fn test_srtp_ssrc_states_are_capped() -> Result<()> {
    let packet = |ssrc: u32, seq: u16| -> Result<Vec<u8>> {
        let pkt = rtp::Packet {
            header: rtp::Header {
                version: 2,
                sequence_number: seq,
                ssrc,
                ..Default::default()
            },
            payload: RTP_TEST_CASE_DECRYPTED.clone(),
        };
        Ok(pkt.marshal()?.to_vec())
    };

    let mut sender = build_test_context()?;
    let mut receiver = build_replay_protected_test_context()?;
    for ssrc in 0..MAX_SSRC_STATES as u32 {
        let protected = sender.encrypt_rtp(&packet(ssrc, 1)?)?;
        receiver.decrypt_rtp(&protected)?;
    }
    assert_eq!(sender.srtp_ssrc_states.len(), MAX_SSRC_STATES);
    assert_eq!(receiver.srtp_ssrc_states.len(), MAX_SSRC_STATES);

    let extra = MAX_SSRC_STATES as u32;
    let err = sender
        .encrypt_rtp(&packet(extra, 1)?)
        .expect_err("the sender took one SSRC too many");
    assert!(
        matches!(err, Error::SrtpTooManySsrcs(s, _) if s == extra),
        "{err:?}"
    );

    // A packet for a further SSRC, protected by another sender, is refused by the receiver.
    let protected = build_test_context()?.encrypt_rtp(&packet(extra, 1)?)?;
    let err = receiver
        .decrypt_rtp(&protected)
        .expect_err("the receiver took one SSRC too many");
    assert!(
        matches!(err, Error::SrtpTooManySsrcs(s, _) if s == extra),
        "{err:?}"
    );
    assert_eq!(sender.srtp_ssrc_states.len(), MAX_SSRC_STATES);
    assert_eq!(receiver.srtp_ssrc_states.len(), MAX_SSRC_STATES);

    // Known SSRCs are unaffected.
    let protected = sender.encrypt_rtp(&packet(7, 2)?)?;
    assert_eq!(receiver.decrypt_rtp(&protected)?.to_vec(), packet(7, 2)?);
    Ok(())
}
