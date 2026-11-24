//! `packet::unmarshal` over every packet type, and what it does with what it does not know.
use crate::application_defined::ApplicationDefined;
use crate::extended_report::{ExtendedReport, ReceiverReferenceTimeReportBlock};
use crate::goodbye::Goodbye;
use crate::header::*;
use crate::packet::{self, Packet};
use crate::payload_feedbacks::application_layer_feedback::ApplicationLayerFeedback;
use crate::payload_feedbacks::full_intra_request::{FirEntry, FullIntraRequest};
use crate::payload_feedbacks::layer_refresh_request::{LayerRefreshRequest, LrrEntry};
use crate::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use crate::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate;
use crate::payload_feedbacks::reference_picture_selection_indication::ReferencePictureSelectionIndication;
use crate::payload_feedbacks::slice_loss_indication::{SliEntry, SliceLossIndication};
use crate::payload_feedbacks::temporal_spatial_tradeoff::{
    TemporalSpatialTradeoffNotification, TemporalSpatialTradeoffRequest, TstEntry,
};
use crate::payload_feedbacks::video_back_channel_message::{VbcmEntry, VideoBackChannelMessage};
use crate::raw_packet::RawPacket;
use crate::receiver_report::ReceiverReport;
use crate::reception_report::ReceptionReport;
use crate::sender_report::SenderReport;
use crate::source_description::{
    SdesType, SourceDescription, SourceDescriptionChunk, SourceDescriptionItem,
};
use crate::transport_feedbacks::cc_feedback_report::{
    CcFeedbackMetricBlock, CcFeedbackReport, CcFeedbackReportBlock, Ecn,
};
use crate::transport_feedbacks::rapid_resynchronization_request::RapidResynchronizationRequest;
use crate::transport_feedbacks::tmmb::{
    TemporaryMaximumBitrateNotification, TemporaryMaximumBitrateRequest, TmmbEntry,
};
use crate::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, SymbolTypeTcc,
    TransportLayerCc,
};
use crate::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use bytes::Bytes;
use shared::error::Error;
use shared::marshal::Marshal;

fn report_block() -> ReceptionReport {
    ReceptionReport {
        ssrc: 0xbc5e9a40,
        fraction_lost: 1,
        total_lost: 2,
        last_sequence_number: 0x46e1,
        jitter: 273,
        last_sender_report: 0x9f36432,
        delay: 150137,
    }
}

/// One packet of every type the codec models, in the order of a datagram a peer could send:
/// reports, the description, then everything else.
fn one_of_each() -> Vec<Box<dyn Packet>> {
    vec![
        Box::new(SenderReport {
            ssrc: 1,
            ntp_time: 0xda8bd1fcdddda05a,
            rtp_time: 0xaaf4edd5,
            packet_count: 10,
            octet_count: 2000,
            reports: vec![report_block()],
            profile_extensions: Bytes::new(),
        }),
        Box::new(ReceiverReport {
            ssrc: 1,
            reports: vec![report_block(), report_block()],
            profile_extensions: Bytes::from_static(&[1, 2, 3, 4]),
        }),
        Box::new(SourceDescription {
            chunks: vec![SourceDescriptionChunk {
                source: 1,
                items: vec![
                    SourceDescriptionItem {
                        sdes_type: SdesType::SdesCname,
                        text: Bytes::from_static(b"cname"),
                    },
                    SourceDescriptionItem {
                        sdes_type: SdesType::SdesMid,
                        text: Bytes::from_static(b"0"),
                    },
                ],
            }],
        }),
        Box::new(ApplicationDefined {
            subtype: 3,
            ssrc: 1,
            name: *b"test",
            data: Bytes::from_static(&[9, 8, 7, 6]),
        }),
        Box::new(TransportLayerNack {
            sender_ssrc: 1,
            media_ssrc: 2,
            nacks: vec![NackPair {
                packet_id: 100,
                lost_packets: 0x8001,
            }],
        }),
        Box::new(TemporaryMaximumBitrateRequest {
            sender_ssrc: 1,
            entries: vec![TmmbEntry::new(2, 500_000, 40)],
        }),
        Box::new(TemporaryMaximumBitrateNotification {
            sender_ssrc: 2,
            entries: vec![TmmbEntry::new(1, 500_000, 40)],
        }),
        Box::new(RapidResynchronizationRequest {
            sender_ssrc: 1,
            media_ssrc: 2,
        }),
        // 23 octets and one of padding, with the P bit, in the middle of the datagram: what
        // libwebrtc sends. The padding belongs to this packet alone.
        Box::new(TransportLayerCc {
            sender_ssrc: 1,
            media_ssrc: 2,
            base_sequence_number: 7,
            packet_status_count: 1,
            reference_time: 5,
            fb_pkt_count: 1,
            packet_chunks: vec![PacketStatusChunk::RunLengthChunk(RunLengthChunk {
                type_tcc: StatusChunkTypeTcc::RunLengthChunk,
                packet_status_symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
                run_length: 1,
            })],
            recv_deltas: vec![RecvDelta {
                type_tcc_packet: SymbolTypeTcc::PacketReceivedSmallDelta,
                delta: 1000,
            }],
        }),
        Box::new(CcFeedbackReport {
            sender_ssrc: 1,
            report_blocks: vec![CcFeedbackReportBlock {
                media_ssrc: 2,
                begin_sequence: 10,
                metric_blocks: vec![
                    CcFeedbackMetricBlock {
                        received: true,
                        ecn: Ecn::Ect0,
                        arrival_time_offset: 20,
                    },
                    CcFeedbackMetricBlock::default(),
                ],
            }],
            report_timestamp: 0x12345678,
        }),
        Box::new(PictureLossIndication {
            sender_ssrc: 1,
            media_ssrc: 2,
        }),
        Box::new(SliceLossIndication {
            sender_ssrc: 1,
            media_ssrc: 2,
            sli_entries: vec![SliEntry {
                first: 1,
                number: 2,
                picture: 3,
            }],
        }),
        Box::new(ReferencePictureSelectionIndication {
            sender_ssrc: 1,
            media_ssrc: 2,
            payload_type: 96,
            native_rpsi: Bytes::from_static(&[0x12, 0x30]),
            unused_bits: 4,
        }),
        Box::new(FullIntraRequest {
            sender_ssrc: 1,
            media_ssrc: 0,
            fir: vec![FirEntry {
                ssrc: 2,
                sequence_number: 9,
            }],
        }),
        Box::new(TemporalSpatialTradeoffRequest {
            sender_ssrc: 1,
            entries: vec![TstEntry {
                ssrc: 2,
                sequence_number: 1,
                index: 20,
            }],
        }),
        Box::new(TemporalSpatialTradeoffNotification {
            sender_ssrc: 2,
            entries: vec![TstEntry {
                ssrc: 1,
                sequence_number: 1,
                index: 20,
            }],
        }),
        Box::new(VideoBackChannelMessage {
            sender_ssrc: 1,
            entries: vec![VbcmEntry {
                ssrc: 2,
                sequence_number: 1,
                payload_type: 96,
                octet_string: Bytes::from_static(&[1, 2, 3]),
            }],
        }),
        Box::new(LayerRefreshRequest {
            sender_ssrc: 1,
            entries: vec![LrrEntry {
                ssrc: 2,
                sequence_number: 1,
                payload_type: 98,
                target_temporal_layer_id: 2,
                target_layer_id: 1,
                current: None,
            }],
        }),
        Box::new(ReceiverEstimatedMaximumBitrate {
            sender_ssrc: 1,
            bitrate: 1_000_000.0,
            ssrcs: vec![2, 3],
        }),
        Box::new(ApplicationLayerFeedback {
            sender_ssrc: 1,
            media_ssrc: 2,
            data: Bytes::from_static(b"MINE\x00\x00\x00\x01"),
        }),
        Box::new(ExtendedReport {
            sender_ssrc: 1,
            reports: vec![Box::new(ReceiverReferenceTimeReportBlock {
                ntp_timestamp: 0x0102030405060708,
            })],
        }),
        Box::new(Goodbye {
            sources: vec![1],
            reason: Bytes::from_static(b"done"),
        }),
    ]
}

#[test]
fn every_packet_type_round_trips_through_one_datagram() {
    let packets = one_of_each();
    let raw = packet::marshal(&packets).unwrap().freeze();

    let parsed = packet::unmarshal(&mut raw.clone()).unwrap();
    assert_eq!(packets.len(), parsed.len());
    for (want, got) in packets.iter().zip(&parsed) {
        assert!(want == got, "want {want:?}, got {got:?}");
    }
    assert_eq!(raw, packet::marshal(&parsed).unwrap().freeze());

    // The lenient reader agrees on a datagram with nothing wrong in it.
    assert!(packets == packet::unmarshal_lenient(&mut raw.clone()).unwrap());
}

// RFC 3550 6.1: every packet ends on a 32-bit boundary and its length field says how long it
// is, so the datagram can be walked.
#[test]
fn every_packet_type_is_a_whole_number_of_words_and_says_its_length() {
    for p in one_of_each() {
        let raw = p.marshal().unwrap();
        assert!(raw.len().is_multiple_of(4), "{p:?}");
        assert_eq!(raw.len(), p.marshal_size(), "{p:?}");
        let length = u16::from_be_bytes([raw[2], raw[3]]) as usize;
        assert_eq!(raw.len(), 4 * (length + 1), "{p:?}");
        assert_eq!(2, raw[0] >> 6, "{p:?}");
        let header = p.header();
        assert_eq!(u8::from(header.packet_type), raw[1], "{p:?}");
        assert_eq!(header.count, raw[0] & 0x1f, "{p:?}");
        assert_eq!(header.length as usize, length, "{p:?}");
        assert_eq!(header.padding, raw[0] & 0x20 != 0, "{p:?}");
    }
}

// RFC 3550 6.1: "an implementation SHOULD ignore incoming RTCP packets with types unknown to
// it". RFC 4585 6.1: unassigned FMT values may appear. They are kept as they are, so whoever
// forwards them forwards what arrived.
#[test]
fn unknown_packet_types_and_feedback_formats_stay_raw_bytes() {
    let unknown: [&[u8]; 4] = [
        &[0x80, 0xd0, 0x00, 0x01, 1, 2, 3, 4], // PT 208
        &[0x9f, 0xc0, 0x00, 0x01, 1, 2, 3, 4], // PT 192 (RFC 2032 FIR)
        // RTPFB FMT 12: unassigned (IANA: 1 NACK, 3 TMMBR, 4 TMMBN, 5 RTCP-SR-REQ, 6 RAMS,
        // 7 TLLEI, 8 RTCP-ECN-FB, 9 PAUSE-RESUME, 10 DBI, 11 CCFB; 15 is the transport-cc
        // convention). FMT 9 was used here until RFC 7728 PAUSE-RESUME was parsed.
        &[0x8c, 0xcd, 0x00, 0x02, 0, 0, 0, 1, 0, 0, 0, 2],
        &[0x89, 0xce, 0x00, 0x02, 0, 0, 0, 1, 0, 0, 0, 2], // PSFB FMT 9 (not parsed here)
    ];
    let rr: &[u8] = &[0x80, 0xc9, 0x00, 0x01, 0, 0, 0, 1];
    let datagram = [rr, unknown[0], unknown[1], unknown[2], unknown[3], rr].concat();

    let packets = packet::unmarshal(&mut Bytes::from(datagram.clone())).unwrap();
    assert_eq!(6, packets.len());
    for (raw, parsed) in unknown.iter().zip(&packets[1..5]) {
        let kept = parsed
            .as_any()
            .downcast_ref::<RawPacket>()
            .unwrap_or_else(|| panic!("{parsed:?} is not raw"));
        assert_eq!(*raw, &kept.0[..]);
    }
    assert!(packets[5].as_any().is::<ReceiverReport>());
    assert_eq!(PacketType::Other(208), packets[1].header().packet_type);
    assert_eq!(&datagram[..], &packet::marshal(&packets).unwrap()[..]);
}

#[test]
fn every_packet_type_octet_survives_a_round_trip() {
    for octet in 0..=u8::MAX {
        assert_eq!(octet, u8::from(PacketType::from(octet)));
    }
    assert_eq!(PacketType::ApplicationDefined, PacketType::from(204));
    assert_eq!(PacketType::Other(208), PacketType::from(208));
    assert_eq!("PT208", PacketType::Other(208).to_string());

    let header = Header {
        padding: false,
        count: 3,
        packet_type: PacketType::Other(213),
        length: 1,
    };
    assert_eq!(&[0x83, 213, 0, 1][..], &header.marshal().unwrap()[..]);
}

// RFC 4585 6.4: REMB is application layer feedback that names itself; any other message
// under FMT 15 is another application's and is not a broken REMB.
#[test]
fn format_15_payload_feedback_is_remb_only_when_it_says_remb() {
    let remb = ReceiverEstimatedMaximumBitrate {
        sender_ssrc: 1,
        bitrate: 64_000.0,
        ssrcs: vec![2],
    };
    let other = ApplicationLayerFeedback {
        sender_ssrc: 1,
        media_ssrc: 0,
        data: Bytes::from_static(b"REMC\x01\x00\xfa\x00\x00\x00\x00\x02"),
    };
    let datagram = [remb.marshal().unwrap(), other.marshal().unwrap()].concat();

    let packets = packet::unmarshal(&mut Bytes::from(datagram)).unwrap();
    assert_eq!(Some(&remb), packets[0].as_any().downcast_ref());
    assert_eq!(Some(&other), packets[1].as_any().downcast_ref());
}

#[test]
fn a_malformed_packet_fails_the_datagram_unless_read_leniently() {
    let rr: &[u8] = &[0x80, 0xc9, 0x00, 0x01, 0, 0, 0, 1];
    // A PLI with a word of FCI it must not have.
    let pli: &[u8] = &[0x81, 0xce, 0x00, 0x03, 0, 0, 0, 1, 0, 0, 0, 2, 9, 9, 9, 9];
    let bye: &[u8] = &[0x81, 0xcb, 0x00, 0x01, 0, 0, 0, 1];
    let datagram = Bytes::from([rr, pli, bye].concat());

    assert_eq!(
        Some(Error::InvalidHeader),
        packet::unmarshal(&mut datagram.clone()).err()
    );

    let packets = packet::unmarshal_lenient(&mut datagram.clone()).unwrap();
    assert_eq!(3, packets.len());
    assert!(packets[0].as_any().is::<ReceiverReport>());
    assert_eq!(
        Some(&RawPacket(Bytes::from_static(pli))),
        packets[1].as_any().downcast_ref()
    );
    assert!(packets[2].as_any().is::<Goodbye>());
    assert_eq!(datagram, packet::marshal(&packets).unwrap().freeze());
}

// A PAUSE-RESUME (RFC 7728 section 8.1, RTPFB FMT 9) without its FCI is malformed like any
// other known packet: it fails the datagram read strictly and arrives as a `RawPacket` read
// leniently (the receive path's rule), without taking the packets around it along.
#[test]
fn a_malformed_pause_resume_degrades_like_any_known_packet() {
    let rr: &[u8] = &[0x80, 0xc9, 0x00, 0x01, 0, 0, 0, 1];
    let pause: &[u8] = &[0x89, 0xcd, 0x00, 0x02, 0, 0, 0, 1, 0, 0, 0, 0];
    let bye: &[u8] = &[0x81, 0xcb, 0x00, 0x01, 0, 0, 0, 1];
    let datagram = Bytes::from([rr, pause, bye].concat());

    assert!(packet::unmarshal(&mut datagram.clone()).is_err());

    let packets = packet::unmarshal_lenient(&mut datagram.clone()).unwrap();
    assert_eq!(3, packets.len());
    assert!(packets[0].as_any().is::<ReceiverReport>());
    assert_eq!(
        Some(&RawPacket(Bytes::from_static(pause))),
        packets[1].as_any().downcast_ref()
    );
    assert!(packets[2].as_any().is::<Goodbye>());
    assert_eq!(datagram, packet::marshal(&packets).unwrap().freeze());
}

// RFC 3550 Appendix A.2: the version and the lengths frame the datagram. Without them there
// is no next packet to find, lenient or not.
#[test]
fn a_datagram_whose_framing_is_broken_fails_either_way() {
    let cases: Vec<(&str, &'static [u8], Error)> = vec![
        ("nothing", &[], Error::InvalidHeader),
        ("half a header", &[0x80, 0xc9], Error::PacketTooShort),
        (
            "version 1",
            &[0x40, 0xc9, 0x00, 0x01, 0, 0, 0, 1],
            Error::BadVersion,
        ),
        (
            "a length that runs past the datagram",
            &[0x80, 0xc9, 0x00, 0x02, 0, 0, 0, 1],
            Error::PacketTooShort,
        ),
        (
            "a good packet, then version 0",
            &[0x80, 0xc9, 0x00, 0x01, 0, 0, 0, 1, 0x00, 0xc9, 0x00, 0x00],
            Error::BadVersion,
        ),
        (
            "a good packet, then three stray octets",
            &[0x80, 0xc9, 0x00, 0x01, 0, 0, 0, 1, 0x80, 0xc9, 0x00],
            Error::PacketTooShort,
        ),
    ];
    for (name, raw, want) in cases {
        let strict = packet::unmarshal(&mut Bytes::from_static(raw)).err();
        let lenient = packet::unmarshal_lenient(&mut Bytes::from_static(raw)).err();
        assert_eq!(Some(&want), strict.as_ref(), "{name}");
        assert_eq!(Some(&want), lenient.as_ref(), "{name}, lenient");
    }
}

// A typed parser reads the one packet its header describes and leaves the next one alone.
#[test]
fn a_typed_parser_stops_at_the_end_of_its_packet() {
    use shared::marshal::Unmarshal;

    let mut datagram = Bytes::from_static(&[
        0x80, 0xc9, 0x00, 0x01, 0, 0, 0, 1, // RR
        0x81, 0xce, 0x00, 0x02, 0, 0, 0, 1, 0, 0, 0, 2, // PLI
    ]);
    let rr = ReceiverReport::unmarshal(&mut datagram).unwrap();
    assert!(rr.profile_extensions.is_empty());
    assert_eq!(12, datagram.len());
    let pli = PictureLossIndication::unmarshal(&mut datagram).unwrap();
    assert_eq!(2, pli.media_ssrc);
    assert!(datagram.is_empty());
}

/// xorshift64: a fixed sequence, so a failure reproduces.
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

// What the fuzz targets check, on a fixed set of damaged datagrams: whatever still parses is
// written back, read again and written as the same bytes, and nothing panics on the way. The
// lenient reader accepts whatever the strict one does.
#[test]
fn damaged_datagrams_never_panic_and_keep_one_wire_form() {
    let packets = one_of_each();
    let whole = packet::marshal(&packets).unwrap();
    let singles: Vec<Vec<u8>> = packets
        .iter()
        .map(|p| p.marshal().unwrap().to_vec())
        .collect();

    let mut state = 0x9e3779b97f4a7c15u64;
    let mut parsed_again = 0usize;
    for round in 0..60_000usize {
        // Damage one packet most of the time, the whole datagram now and then.
        let mut raw = if round % 8 == 0 {
            whole.to_vec()
        } else {
            singles[round % singles.len()].clone()
        };
        for _ in 0..1 + next(&mut state) % 3 {
            let at = (next(&mut state) % raw.len() as u64) as usize;
            match next(&mut state) % 4 {
                0 => raw[at] = next(&mut state) as u8,
                1 => raw[at] ^= 1 << (next(&mut state) % 8),
                2 => raw.truncate(at.max(1)),
                _ => raw[at] = [0x00, 0xff, 0x7f, 0x80][(next(&mut state) % 4) as usize],
            }
        }

        let strict = packet::unmarshal(&mut Bytes::from(raw.clone()));
        let lenient = packet::unmarshal_lenient(&mut Bytes::from(raw.clone()));
        let _ = crate::compound_packet::validate_compound(&raw);
        let _ = crate::compound_packet::validate_reduced_size(&raw);
        if strict.is_ok() {
            assert!(lenient.is_ok(), "{raw:?}");
        }
        if let Ok(packets) = lenient {
            for p in &packets {
                let _ = p.header();
                let _ = p.destination_ssrc();
                let _ = p.to_string();
            }
        }

        if let Ok(packets) = strict
            && let Ok(written) = packet::marshal(&packets)
        {
            let again = packet::unmarshal(&mut written.clone().freeze())
                .unwrap_or_else(|e| panic!("{e}: {raw:?} was written as {written:?}"));
            assert_eq!(packets.len(), again.len(), "{raw:?}");
            assert_eq!(
                written,
                packet::marshal(&again).unwrap(),
                "{raw:?} has two wire forms"
            );
            parsed_again += 1;
        }
    }
    assert!(
        parsed_again > 1_000,
        "only {parsed_again} damaged datagrams parsed"
    );
}
