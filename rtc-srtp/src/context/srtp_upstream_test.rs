//! Tests ported from webrtc-rs `srtp` v0.17 (`context/srtp_test.rs`, `context/srtcp_test.rs`)
//! that the sans-I/O crate had not carried over.

use bytes::{Bytes, BytesMut};
use shared::marshal::*;

use super::*;

fn provider() -> std::sync::Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

fn build_test_context() -> Result<Context> {
    let master_key = [
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ];
    let master_salt = [
        0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c,
    ];
    Context::new(
        &master_key,
        &master_salt,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        provider().crypto(),
    )
}

const RTCP_TEST_MASTER_KEY: [u8; 16] = [
    0xfd, 0xa6, 0x25, 0x95, 0xd7, 0xf6, 0x92, 0x6f, 0x7d, 0x9c, 0x02, 0x4c, 0xc9, 0x20, 0x9f, 0x34,
];
const RTCP_TEST_MASTER_SALT: [u8; 14] = [
    0xa9, 0x65, 0x19, 0x85, 0x54, 0x0b, 0x47, 0xbe, 0x2f, 0x27, 0xa8, 0xb8, 0x81, 0x23,
];

fn build_rtcp_context() -> Result<Context> {
    Context::new(
        &RTCP_TEST_MASTER_KEY,
        &RTCP_TEST_MASTER_SALT,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        Some(srtcp_replay_protection(10)),
        provider().crypto(),
    )
}

fn rtp_packet(ssrc: u32, sequence_number: u16, payload: Bytes) -> Result<BytesMut> {
    rtp::Packet {
        header: rtp::Header {
            version: 2,
            ssrc,
            marker: true,
            sequence_number,
            ..Default::default()
        },
        payload,
    }
    .marshal()
}

#[test]
fn test_rtp_max_packets() -> Result<()> {
    let mut context = build_test_context()?;
    context.set_roc(1, u32::MAX);

    context.encrypt_rtp(&rtp_packet(1, 0xffff, Bytes::new())?)?;

    let err = context
        .encrypt_rtp(&rtp_packet(1, 0x0, Bytes::new())?)
        .expect_err("the 2^48th packet must not be encrypted");
    assert_eq!(err, Error::ErrExceededMaxPackets);
    Ok(())
}

#[test]
fn test_rtp_burst_loss_with_set_roc() -> Result<()> {
    let mut encrypt_context = build_test_context()?;
    encrypt_context.set_roc(1, 3);

    struct PacketWithRoc {
        raw: BytesMut,
        enc: BytesMut,
        roc: u32,
    }

    let mut pkts = vec![];
    for i in (0x8c00u32..0x20400u32).step_by(0x100) {
        let raw = rtp_packet(
            1,
            i as u16,
            Bytes::from(vec![(i >> 16) as u8, (i >> 8) as u8, i as u8]),
        )?;
        let enc = encrypt_context.encrypt_rtp(&raw)?;

        // Keep only the first and last packets, as a bursty loss would.
        if i <= 0x9000 || i >= 0x20100 {
            let roc = encrypt_context.get_roc(1).unwrap();
            pkts.push(PacketWithRoc { raw, enc, roc });
        }
    }

    let mut decrypt_context = build_test_context()?;
    for p in pkts {
        decrypt_context.set_roc(1, p.roc);
        let dec = decrypt_context.decrypt_rtp(&p.enc)?;
        assert_eq!(&p.raw[..], &dec[..]);
    }
    Ok(())
}

#[test]
fn test_decrypt_invalid_srtp() -> Result<()> {
    let mut decrypt_context = build_test_context()?;
    let encrypted = [
        0x41, 0x02, 0x07, 0xf9, 0xf9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb5, 0x73,
        0x19, 0xf6, 0x91, 0xbb, 0x3e, 0xa5, 0x21, 0x07,
    ];
    decrypt_context
        .decrypt_rtp(&encrypted)
        .expect_err("Should fail");
    Ok(())
}

#[test]
fn test_decrypt_invalid_srtcp() -> Result<()> {
    let mut decrypt_context = build_rtcp_context()?;
    let encrypted = [
        0x8f, 0x48, 0xff, 0xff, 0xec, 0x77, 0xb0, 0x43, 0xf9, 0x04, 0x51, 0xff, 0xfb, 0xdf,
    ];
    decrypt_context
        .decrypt_rtcp(&encrypted)
        .expect_err("Should fail");
    Ok(())
}

#[test]
fn test_encrypt_invalid_srtcp() -> Result<()> {
    let mut encrypt_context = build_rtcp_context()?;
    let decrypted = [0xbb, 0xbb, 0x0a, 0x2f];
    let err = encrypt_context
        .encrypt_rtcp(&decrypted)
        .expect_err("Should fail with ErrTooShortRtcp");
    assert_eq!(err, Error::ErrTooShortRtcp);
    Ok(())
}
