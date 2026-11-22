//! FEC and transport-wide congestion control in one chain.
//!
//! Each is tested alone elsewhere. Together they have to agree on three things the FlexFEC
//! audit found broken: the encoder protects the packet as it is sent (after the TWCC sender
//! wrote into it), a repair packet is a packet on the path (numbered when sent, reported when
//! received), and a packet rebuilt from FEC was not delivered by the path (not reported as
//! arrived).

use bytes::Bytes;
use rtc_interceptor::{
    Attribute, AttributedPacket, FlexFec03Decoder, FlexFec03Encoder, FlexFec03ReceiveBuilder,
    FlexFec03SendBuilder, Interceptor, Packet, RTCPFeedback, RTPHeaderExtension,
    ReceiverReportBuilder, Registry, Slot, StreamInfo, TaggedPacket, TwccReceiverBuilder,
    TwccSenderBuilder, convert_twcc,
};
use rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::{Marshal, Unmarshal};
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const TWCC_ID: u8 = 5;

const MEDIA_SSRC: u32 = 1000;
const REPAIR_SSRC: u32 = 2000;
const MEDIA_PT: u8 = 96;
const REPAIR_PT: u8 = 118;

fn stream() -> StreamInfo {
    StreamInfo {
        ssrc: MEDIA_SSRC,
        ssrc_fec: Some(REPAIR_SSRC),
        payload_type: MEDIA_PT,
        payload_type_fec: Some(REPAIR_PT),
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        rtcp_feedback: vec![RTCPFeedback {
            typ: "transport-cc".to_owned(),
            parameter: String::new(),
        }],
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: u16::from(TWCC_ID),
        }],
        ..Default::default()
    }
}

/// A media packet as the application writes it: no header extension.
fn media(sequence_number: u16) -> rtp::Packet {
    rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            marker: sequence_number % 5 == 4,
            payload_type: MEDIA_PT,
            sequence_number,
            timestamp: 90_000 + u32::from(sequence_number) * 3_000,
            ssrc: MEDIA_SSRC,
            ..Default::default()
        },
        payload: Bytes::from(
            (0..(40 + usize::from(sequence_number) * 7))
                .map(|index| (index as u8).wrapping_mul(sequence_number as u8 + 3))
                .collect::<Vec<u8>>(),
        ),
    }
}

/// The same packet as it is on the wire once the TWCC sender numbered it.
fn numbered(mut packet: rtp::Packet, transport_sequence: u16) -> rtp::Packet {
    let extension =
        rtp::extension::transport_cc_extension::TransportCcExtension { transport_sequence };
    packet
        .header
        .set_extension(TWCC_ID, extension.marshal().expect("marshal").freeze())
        .expect("set extension");
    packet
}

fn tagged(now: Instant, packet: rtp::Packet) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(packet)),
    }
}

fn transport_sequence(packet: &rtp::Packet) -> Option<u16> {
    let data = packet.header.get_extension(TWCC_ID)?;
    rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(&mut data.as_ref())
        .ok()
        .map(|extension| extension.transport_sequence)
}

fn wire_bytes(packet: &rtp::Packet) -> Vec<u8> {
    packet.marshal().expect("marshal").to_vec()
}

/// The FEC encoder protects the source packets as they are sent (draft-03 section 4.1). The
/// TWCC sender, below the encoder, writes the transport-wide sequence number into every packet
/// and adds the header extension when the application's packet has none; an encoder that read
/// the packet before that protects an image the receiver never sees, and what is recovered from
/// it is not the packet that was lost (FlexFEC audit bug 1).
#[test]
fn a_lost_packet_is_recovered_as_it_was_sent_when_the_twcc_sender_rewrites_it() {
    let epoch = Instant::now();
    let mut fec = FlexFec03SendBuilder::new()
        .with_num_media_packets(5)
        .with_num_fec_packets(1)
        .build();
    let tap = fec.wire_tap();
    let mut chain = Registry::new()
        .with(Slot::FecEncoder, fec)
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .with(Slot::FecWireImage, tap)
        .build();
    chain.bind_local_stream(&stream());

    let mut wire = Vec::new();
    for sequence_number in 0..5u16 {
        chain
            .handle_write(tagged(epoch, media(sequence_number)))
            .expect("write");
        while let Some(packet) = chain.poll_write() {
            let Packet::Rtp(rtp) = packet.message.packet else {
                continue;
            };
            wire.push(rtp);
        }
    }

    let (media_sent, repair_sent): (Vec<_>, Vec<_>) = wire
        .into_iter()
        .partition(|packet| packet.header.ssrc == MEDIA_SSRC);
    assert_eq!(5, media_sent.len());
    assert_eq!(1, repair_sent.len(), "one repair packet for the block");
    assert_eq!(
        vec![Some(0), Some(1), Some(2), Some(3), Some(4)],
        media_sent
            .iter()
            .map(transport_sequence)
            .collect::<Vec<_>>(),
        "the TWCC sender added the extension to every media packet"
    );
    assert_eq!(
        Some(5),
        transport_sequence(&repair_sent[0]),
        "and numbered the repair packet after them"
    );

    // The path drops media packet 2. The receiver has the other four and the repair packet.
    let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);
    let mut recovered = Vec::new();
    for (index, packet) in media_sent.iter().enumerate() {
        if index != 2 {
            recovered.extend(decoder.decode(packet.clone()));
        }
    }
    recovered.extend(decoder.decode(repair_sent[0].clone()));

    assert_eq!(1, recovered.len(), "the lost packet is rebuilt");
    assert_eq!(
        wire_bytes(&media_sent[2]),
        wire_bytes(&recovered[0]),
        "byte for byte the packet that was sent"
    );
}

/// The receiver chain of the two tests below: FEC decoder, TWCC receiver, receiver reports.
fn receiver() -> impl Interceptor {
    let mut chain = Registry::new()
        .with(Slot::FecDecoder, FlexFec03ReceiveBuilder::new().build())
        .with(
            Slot::TwccReceiver,
            TwccReceiverBuilder::new()
                .with_interval(Duration::from_millis(100))
                .build(),
        )
        .with(
            Slot::ReceiverReport,
            ReceiverReportBuilder::new()
                .with_interval(Duration::from_millis(100))
                .build(),
        )
        .build();
    chain.bind_remote_stream(&stream());
    chain
}

/// Five numbered media packets and the repair packet that protects them, as on the wire.
fn protected_block() -> (Vec<rtp::Packet>, rtp::Packet) {
    let media: Vec<rtp::Packet> = (0..5u16)
        .map(|sequence_number| numbered(media(sequence_number), sequence_number))
        .collect();
    let mut repair = FlexFec03Encoder::new(REPAIR_PT, REPAIR_SSRC).encode(&media, 1);
    assert_eq!(1, repair.len());
    (media, numbered(repair.remove(0), 5))
}

struct Received {
    /// What reached the application side of the chain.
    delivered: Vec<TaggedPacket>,
    /// The TWCC feedback the chain sent, as (transport sequence number, arrived).
    feedback: Vec<(u16, bool)>,
    /// Cumulative packets lost, from the receiver report for the media SSRC.
    total_lost: Option<u32>,
}

/// Deliver the block without media packet 2, then let the reports go out.
fn receive_block_without_packet_two() -> Received {
    let epoch = Instant::now();
    let mut chain = receiver();
    let (media, repair) = protected_block();

    let mut delivered = Vec::new();
    for (index, packet) in media.into_iter().enumerate() {
        if index == 2 {
            continue;
        }
        chain
            .handle_read(tagged(epoch + Duration::from_millis(index as u64), packet))
            .expect("read");
    }
    chain
        .handle_read(tagged(epoch + Duration::from_millis(6), repair))
        .expect("read");
    while let Some(packet) = chain.poll_read() {
        delivered.push(packet);
    }

    let mut feedback = Vec::new();
    let mut total_lost = None;
    for step in [100u64, 200, 300] {
        chain
            .handle_timeout(epoch + Duration::from_millis(step))
            .expect("timeout");
        while let Some(packet) = chain.poll_write() {
            let Packet::Rtcp(rtcp_packets) = &packet.message.packet else {
                continue;
            };
            for rtcp_packet in rtcp_packets {
                if let Some(twcc) = rtcp_packet.as_any().downcast_ref::<TransportLayerCc>() {
                    feedback.extend(
                        convert_twcc(twcc)
                            .into_iter()
                            .map(|ack| (ack.sequence_number, ack.arrived)),
                    );
                }
                if let Some(rr) = rtcp_packet
                    .as_any()
                    .downcast_ref::<rtcp::receiver_report::ReceiverReport>()
                {
                    for report in &rr.reports {
                        if report.ssrc == MEDIA_SSRC {
                            total_lost = Some(report.total_lost);
                        }
                    }
                }
            }
        }
    }

    Received {
        delivered,
        feedback,
        total_lost,
    }
}

/// A repair packet is a packet the path delivered: the sender numbered it and recorded it, so
/// the receiver has to report it. Swallowed by the FEC decoder before the arrival recorders, it
/// is reported lost for ever (FlexFEC audit bug 4).
#[test]
fn a_repair_packet_is_reported_as_received_by_the_twcc_receiver() {
    let received = receive_block_without_packet_two();

    assert!(
        received.feedback.contains(&(5, true)),
        "the repair packet carried transport sequence number 5: {:?}",
        received.feedback
    );
    assert!(
        received
            .delivered
            .iter()
            .all(|packet| match &packet.message.packet {
                Packet::Rtp(rtp) => rtp.header.ssrc == MEDIA_SSRC,
                _ => true,
            }),
        "and it still does not reach the application"
    );
}

/// A packet rebuilt from FEC was not delivered by the path: the sender's congestion controller
/// and `fraction lost` must still see the loss (FlexFEC audit bug 5).
#[test]
fn a_packet_recovered_by_fec_is_not_reported_as_arrived() {
    let received = receive_block_without_packet_two();

    let recovered: Vec<&TaggedPacket> = received
        .delivered
        .iter()
        .filter(|packet| packet.message.has(&Attribute::RecoveredByFec))
        .collect();
    assert_eq!(1, recovered.len(), "FEC did rebuild the lost packet");
    let Packet::Rtp(rtp) = &recovered[0].message.packet else {
        unreachable!()
    };
    assert_eq!(2, rtp.header.sequence_number);

    assert!(
        received.feedback.contains(&(2, false)),
        "the TWCC feedback reports transport sequence number 2 as not received: {:?}",
        received.feedback
    );
    assert_eq!(
        Some(1),
        received.total_lost,
        "and the receiver report counts one packet lost"
    );
}
