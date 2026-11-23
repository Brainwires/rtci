//! RFC 3711 section 3.2.3 and RFC 7714 section 13.1: a cryptographic context per SSRC within
//! one master key, and AES-GCM keyed afresh for every packet.

use super::*;
use crate::test_util::provider;
use shared::marshal::Marshal;

fn context(profile: ProtectionProfile) -> Result<Context> {
    Context::new(
        &vec![0x2b; profile.key_len()],
        &vec![0x7e; profile.salt_len()],
        profile,
        Some(srtp_replay_protection(64)?),
        None,
        provider().crypto(),
    )
}

fn rtp(ssrc: u32, sequence_number: u16, payload: &[u8]) -> Result<Vec<u8>> {
    Ok(rtp::Packet {
        header: rtp::Header {
            version: 2,
            payload_type: 96,
            sequence_number,
            ssrc,
            ..Default::default()
        },
        payload: bytes::Bytes::copy_from_slice(payload),
    }
    .marshal()?
    .to_vec())
}

/// RFC 3711 section 3.2.3: what a packet is checked against is the state of its own SSRC.
/// Two SSRCs with the same sequence numbers under one master key both decrypt, each has its
/// own index, and a replay of one does not touch the other.
#[test]
fn each_ssrc_has_its_own_cryptographic_state() -> Result<()> {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ] {
        let mut sender = context(profile)?;
        let mut receiver = context(profile)?;
        // The same payload and sequence number: another SSRC, another keystream.
        let a = sender.encrypt_rtp(&rtp(0xa, 100, b"same payload")?)?;
        let b = sender.encrypt_rtp(&rtp(0xb, 100, b"same payload")?)?;
        assert_ne!(a[12..], b[12..], "{profile:?}: another keystream per SSRC");
        assert_eq!(
            receiver.decrypt_rtp(&a)?.to_vec(),
            rtp(0xa, 100, b"same payload")?
        );
        assert_eq!(
            receiver.decrypt_rtp(&b)?.to_vec(),
            rtp(0xb, 100, b"same payload")?
        );
        assert!(
            receiver.decrypt_rtp(&a).is_err(),
            "{profile:?}: a replay of a"
        );
        let later_b = sender.encrypt_rtp(&rtp(0xb, 101, b"b again")?)?;
        assert_eq!(
            receiver.decrypt_rtp(&later_b)?.to_vec(),
            rtp(0xb, 101, b"b again")?
        );
        assert_eq!(receiver.srtp_ssrc_states.len(), 2, "{profile:?}");
        assert_eq!(receiver.srtp_ssrc_states[&0xa].index, 100);
        assert_eq!(receiver.srtp_ssrc_states[&0xb].index, 101);
    }
    Ok(())
}

/// RFC 7714 section 13.1: the GCM block counter starts again for each packet. A packet's
/// protection does not depend on the packets protected before it: the same packet protected
/// by a context that has protected others, and by a fresh one, is the same bytes.
#[test]
fn gcm_protection_of_a_packet_does_not_depend_on_the_ones_before() -> Result<()> {
    for profile in [
        ProtectionProfile::AeadAes128Gcm,
        ProtectionProfile::AeadAes256Gcm,
    ] {
        let mut busy = context(profile)?;
        for sequence_number in 1..40u16 {
            busy.encrypt_rtp(&rtp(0xc, sequence_number, &[sequence_number as u8; 1200])?)?;
        }
        let packet = rtp(0xc, 40, &[0x55; 1200])?;
        let after_others = busy.encrypt_rtp(&packet)?;
        let mut fresh = context(profile)?;
        // The fresh context reaches index 40 directly: the ROC is 0 either way.
        let alone = fresh.encrypt_rtp(&packet)?;
        assert_eq!(after_others, alone, "{profile:?}");
    }
    Ok(())
}
