//! `configure_congestion_control` composes a working chain (P7-08).
//!
//! The helper declares three named slots and never has to know what else the caller registered, or
//! in what order — so what is worth checking is that it composes at all, with either feedback
//! format and with an estimator the application brought itself.

use rtc::interceptor::{ConstantBitrate, Gcc, Registry, Slot};
use rtc::peer_connection::configuration::interceptor_registry::{
    CongestionFeedback, configure_congestion_control,
};
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::remote_bitrate_limit::REMOTE_BITRATE_LIMIT_SLOT;

/// The estimator seam is what #840's second requirement asks for: an application supplies its own,
/// and it drives the same machinery `Gcc` does.
#[test]
fn an_application_can_supply_its_own_estimator() {
    let mut media_engine = MediaEngine::default();
    let registry = configure_congestion_control(
        Registry::new(),
        ConstantBitrate::new(900_000.0),
        CongestionFeedback::Twcc,
        &mut media_engine,
    )
    .expect("congestion control");

    assert_eq!(
        vec![
            (
                Slot::CongestionControl,
                "CongestionControlInterceptor<ConstantBitrate>".to_owned()
            ),
            (Slot::TwccSender, "TwccSenderInterceptor".to_owned()),
            // The remote description's send limit (`b=TIAS` / `b=AS`), applied to whatever
            // the estimator says.
            (
                Slot::Custom(REMOTE_BITRATE_LIMIT_SLOT),
                "RemoteBitrateLimitInterceptor".to_owned()
            ),
            (Slot::Pacer, "PacerInterceptor".to_owned()),
            (Slot::TwccReceiver, "TwccReceiverInterceptor".to_owned()),
        ],
        registry.slots(),
        "the estimator the application brought is the one in the chain"
    );

    let _chain = registry.build();
}

/// RFC 8888 instead of TWCC, end to end through the helper. D7 makes "both" unrepresentable: the
/// two produce indistinguishable `PacketReport`s, so registering both would double-count every
/// packet — an enum rather than two booleans is what rules that out at compile time.
#[test]
fn rfc8888_is_selectable() {
    let mut media_engine = MediaEngine::default();
    let registry = configure_congestion_control(
        Registry::new(),
        Gcc::default(),
        CongestionFeedback::Rfc8888,
        &mut media_engine,
    )
    .expect("congestion control");

    assert_eq!(
        vec![
            (
                Slot::CongestionControl,
                "CongestionControlInterceptor<Gcc>".to_owned()
            ),
            (
                Slot::Custom(REMOTE_BITRATE_LIMIT_SLOT),
                "RemoteBitrateLimitInterceptor".to_owned()
            ),
            (Slot::Pacer, "PacerInterceptor".to_owned()),
            (Slot::Rfc8888, "Rfc8888Interceptor".to_owned()),
        ],
        registry.slots(),
        "no TWCC sender: RFC 8888 reports against the RTP sequence number and needs none. The \
         recorder is the RFC 8888 one, so both halves of the loop speak the same format"
    );

    let _chain = registry.build();
}

/// The pacer the helper installs releases at the estimator's starting rate before any feedback
/// has arrived (draft-ietf-rmcat-gcc-02 section 4: the pacer sends at the target bitrate), not at
/// the pacer's own 1 Mbit/s default.
#[test]
fn the_helper_paces_at_the_estimators_starting_rate() {
    use rtc::interceptor::{
        AttributedPacket, BandwidthEstimator, Interceptor, Packet, StreamInfo, TaggedPacket,
    };
    use rtc::sansio::Protocol;
    use rtc::shared::TransportContext;
    use rtc::shared::marshal::MarshalSize;
    use std::time::{Duration, Instant};

    let gcc = Gcc::default();
    let target = gcc.target_bitrate();
    let mut media_engine = MediaEngine::default();
    let mut chain = configure_congestion_control(
        Registry::new(),
        gcc,
        CongestionFeedback::Rfc8888,
        &mut media_engine,
    )
    .expect("congestion control")
    .build();
    chain.bind_local_stream(&StreamInfo {
        ssrc: 7,
        clock_rate: 90_000,
        payload_type: 96,
        ..Default::default()
    });

    // Two seconds of media at 1 Mbit/s offered at once; count what leaves in two seconds.
    let epoch = Instant::now();
    for sequence_number in 0..250u16 {
        chain
            .handle_write(TaggedPacket {
                now: epoch,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtc::rtp::packet::Packet {
                    header: rtc::rtp::header::Header {
                        version: 2,
                        payload_type: 96,
                        sequence_number,
                        ssrc: 7,
                        ..Default::default()
                    },
                    payload: vec![0xAB; 1000].into(),
                })),
            })
            .expect("write");
    }
    let mut released_bits = 0usize;
    for step in 0..=2_000u64 {
        chain
            .handle_timeout(epoch + Duration::from_millis(step))
            .expect("timeout");
        while let Some(packet) = chain.poll_write() {
            if let Packet::Rtp(rtp) = &packet.message.packet {
                released_bits += rtp.marshal_size() * 8;
            }
        }
    }

    let rate = released_bits as f64 / 2.0;
    assert!(
        rate <= target * 1.15,
        "released at {rate} bit/s against a target of {target}"
    );
    assert!(rate >= target * 0.8, "and not starved either: {rate} bit/s");
}
