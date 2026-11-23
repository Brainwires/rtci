//! RFC 6051 section 3.3: the in-band NTP-format timestamp on a local stream's packets.

use bytes::Bytes;
use rtc_interceptor::{
    Attribute, AttributedPacket, Interceptor, NtpTimestampBuilder, Packet, RTPHeaderExtension,
    Registry, Slot, StreamInfo, TaggedPacket,
};
use rtp::extension::ntp_timestamp_extension::{
    NTP_56_URI, NTP_64_URI, Ntp56Extension, Ntp64Extension,
};
use shared::TransportContext;
use shared::marshal::Unmarshal;
use shared::time::SystemInstant;
use std::time::{Duration, Instant};

const SSRC: u32 = 0x1234;
const ID: u8 = 9;

fn stream(uri: &str) -> StreamInfo {
    StreamInfo {
        ssrc: SSRC,
        ssrc_rtx: Some(0x5678),
        payload_type: 96,
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: uri.to_owned(),
            id: u16::from(ID),
        }],
        ..Default::default()
    }
}

fn packet(now: Instant, ssrc: u32, sequence_number: u16, timestamp: u32) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                timestamp,
                ssrc,
                ..Default::default()
            },
            payload: Bytes::from_static(&[1, 2, 3]),
        })),
    }
}

/// Writes `msg` and returns the extension's bytes on the packet that left, if any.
fn stamp(chain: &mut impl Interceptor, msg: TaggedPacket) -> Option<Bytes> {
    chain.handle_write(msg).unwrap();
    match chain.poll_write().map(|m| m.message.packet) {
        Some(Packet::Rtp(packet)) => packet.header.get_extension(ID),
        _ => None,
    }
}

fn stamping_chain(info: StreamInfo) -> impl Interceptor {
    let mut chain = Registry::new()
        .with(Slot::Custom(1_850), NtpTimestampBuilder::new().build())
        .build();
    chain.bind_local_stream(&info);
    chain
}

/// RFC 6051 section 3.3: with `ntp-64` negotiated, every packet of the stream's first five
/// seconds carries the 64-bit NTP timestamp of the instant it leaves, on the clock SRs use;
/// then the packets of one frame a second (each packet of that frame); not a retransmission,
/// not a stream that did not negotiate it.
#[test]
fn a_negotiated_stream_carries_the_ntp_timestamp_at_first_and_then_once_a_second() {
    let mut chain = stamping_chain(stream(NTP_64_URI));
    let base = Instant::now();
    let mut stamped = vec![];
    // 30 frames a second, one packet each, for eight seconds; one frame of two packets at 6 s.
    for frame in 0..240u32 {
        let now = base + Duration::from_millis(u64::from(frame) * 1000 / 30);
        let value = stamp(&mut chain, packet(now, SSRC, frame as u16, frame * 3000));
        if let Some(value) = value {
            let ntp = Ntp64Extension::unmarshal(&mut value.clone())
                .unwrap()
                .ntp_time;
            assert_eq!(SystemInstant::shared(now).ntp(now), ntp, "frame {frame}");
            stamped.push(frame);
        }
    }
    let initial: Vec<u32> = stamped.iter().copied().filter(|f| *f < 150).collect();
    assert_eq!(
        initial,
        (0..150).collect::<Vec<_>>(),
        "every packet of the first 5 s"
    );
    let later: Vec<u32> = stamped.iter().copied().filter(|f| *f >= 150).collect();
    assert_eq!(
        later,
        vec![150, 180, 210],
        "a frame a second after: {later:?}"
    );

    // The second packet of a stamped frame is stamped too; a retransmission is not.
    let at = base + Duration::from_secs(9);
    assert!(stamp(&mut chain, packet(at, SSRC, 300, 900_000)).is_some());
    assert!(stamp(&mut chain, packet(at, SSRC, 301, 900_000)).is_some());
    let mut again = packet(at, SSRC, 300, 900_000);
    again.message = again.message.with(Attribute::Retransmission);
    assert!(stamp(&mut chain, again).is_none());

    // Without the extension negotiated nothing is added.
    let mut plain = stamping_chain(StreamInfo {
        rtp_header_extensions: vec![],
        ..stream(NTP_64_URI)
    });
    assert!(stamp(&mut plain, packet(base, SSRC, 1, 0)).is_none());
}

/// RFC 6051 Figure 6: with only `ntp-56` negotiated the packets carry the 56-bit variant.
#[test]
fn a_stream_that_negotiated_the_56_bit_variant_carries_it() {
    let mut chain = stamping_chain(stream(NTP_56_URI));
    let now = Instant::now();
    let value = stamp(&mut chain, packet(now, SSRC, 1, 0)).expect("stamped");
    assert_eq!(7, value.len());
    let ntp = SystemInstant::shared(now).ntp(now);
    let read = Ntp56Extension::unmarshal(&mut value.clone()).unwrap();
    assert_eq!(ntp, read.ntp_time(ntp - (2 << 32)));
}
