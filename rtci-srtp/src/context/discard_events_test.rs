//! RFC 3711 section 3.3, steps 2 and 5: a replayed packet and a packet whose authentication
//! fails are discarded, and "the event SHOULD be logged". The context reports each as a
//! [`ContextEvent::PacketDiscarded`] and counts them; a flood is counted but not queued
//! without bound.

use super::test_support::*;
use super::*;

const SSRC: u32 = 0x0102_0304;

fn discards(context: &mut Context) -> Vec<(PacketKind, u32, u64, DiscardReason)> {
    events(context)
        .into_iter()
        .filter_map(|event| match event {
            ContextEvent::PacketDiscarded {
                kind,
                ssrc,
                index,
                reason,
            } => Some((kind, ssrc, index, reason)),
            _ => None,
        })
        .collect()
}

#[test]
fn a_replay_and_a_forgery_are_reported_for_srtp_and_srtcp() {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ] {
        let mut sender = context(profile);
        let mut receiver = context(profile);

        let protected = sender.encrypt_rtp(&rtp(SSRC, 7, b"media")).unwrap();
        receiver.decrypt_rtp(&protected).unwrap();
        assert!(
            discards(&mut receiver).is_empty(),
            "{profile:?}: an authentic packet"
        );
        assert!(receiver.decrypt_rtp(&protected).is_err());
        let mut forged = sender
            .encrypt_rtp(&rtp(SSRC, 8, b"media"))
            .unwrap()
            .to_vec();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(receiver.decrypt_rtp(&forged).is_err());
        assert_eq!(
            discards(&mut receiver),
            vec![
                (PacketKind::Rtp, SSRC, 7, DiscardReason::Replay),
                (
                    PacketKind::Rtp,
                    SSRC,
                    8,
                    DiscardReason::AuthenticationFailed
                ),
            ],
            "{profile:?}"
        );

        let protected = sender.encrypt_rtcp(&rtcp()).unwrap();
        receiver.decrypt_rtcp(&protected).unwrap();
        assert!(receiver.decrypt_rtcp(&protected).is_err());
        let mut forged = sender.encrypt_rtcp(&rtcp()).unwrap().to_vec();
        forged[10] ^= 1;
        let forged_index = u64::from(srtcp_index(profile, &forged, 0));
        assert!(receiver.decrypt_rtcp(&forged).is_err());
        assert_eq!(
            discards(&mut receiver),
            vec![
                (PacketKind::Rtcp, RTCP_SSRC, 0, DiscardReason::Replay),
                (
                    PacketKind::Rtcp,
                    RTCP_SSRC,
                    forged_index,
                    DiscardReason::AuthenticationFailed
                ),
            ],
            "{profile:?}"
        );
        assert_eq!(receiver.discarded_packets(), (2, 2), "{profile:?}");
    }
}

#[test]
fn a_flood_of_forgeries_is_counted_but_not_queued_without_bound() {
    let profile = ProtectionProfile::Aes128CmHmacSha1_80;
    let mut sender = context(profile);
    let mut receiver = context(profile);
    for sequence_number in 0..(MAX_PENDING_DISCARD_EVENTS as u16 + 100) {
        let mut forged = sender
            .encrypt_rtp(&rtp(SSRC, sequence_number, b"x"))
            .unwrap()
            .to_vec();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(receiver.decrypt_rtp(&forged).is_err());
    }
    assert_eq!(
        receiver.discarded_packets(),
        (0, MAX_PENDING_DISCARD_EVENTS as u64 + 100)
    );
    assert_eq!(discards(&mut receiver).len(), MAX_PENDING_DISCARD_EVENTS);
}
