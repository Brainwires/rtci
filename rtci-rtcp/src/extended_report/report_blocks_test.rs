//! Every RFC 3611 report block on its own: wire layout, round trip, and what the RFC forbids.
use super::*;
use crate::packet;

fn xr(block: impl Packet + 'static) -> ExtendedReport {
    ExtendedReport {
        sender_ssrc: 0x01020304,
        reports: vec![Box::new(block)],
    }
}

/// Marshals an XR holding `block`, checks the bytes of the block and reads it back.
fn round_trip(block: impl Packet + Clone + 'static, want_block: &[u8]) {
    let packet = xr(block);
    let raw = packet.marshal().unwrap();
    assert_eq!(0x80, raw[0], "no padding bit, no reserved bit");
    assert_eq!(207, raw[1]);
    assert_eq!((raw.len() / 4 - 1) as u8, raw[3]);
    assert_eq!(want_block, &raw[8..], "{packet:?}");
    assert_eq!(
        packet,
        ExtendedReport::unmarshal(&mut raw.freeze()).unwrap()
    );
}

fn parse(raw: &'static [u8]) -> Result<ExtendedReport> {
    ExtendedReport::unmarshal(&mut Bytes::from_static(raw))
}

fn unknown(report: &dyn Packet) -> &UnknownReportBlock {
    report
        .as_any()
        .downcast_ref::<UnknownReportBlock>()
        .unwrap_or_else(|| panic!("{report:?} was parsed"))
}

// RFC 3611 4.1.
#[test]
fn loss_rle_block_round_trips() {
    round_trip(
        LossRLEReportBlock {
            is_loss_rle: true,
            t: 3,
            ssrc: 0x0a0b0c0d,
            begin_seq: 100,
            end_seq: 131,
            chunks: vec![Chunk(0x4010), Chunk(0xffff)],
        },
        &[
            0x01, 0x03, 0x00, 0x03, // BT=1, T=3, block length 3
            0x0a, 0x0b, 0x0c, 0x0d, // ssrc of source
            0x00, 0x64, 0x00, 0x83, // begin_seq, end_seq
            0x40, 0x10, 0xff, 0xff, // run of 16 ones, bit vector
        ],
    );
}

// RFC 3611 4.2: the same structure with BT=2.
#[test]
fn duplicate_rle_block_round_trips() {
    round_trip(
        DuplicateRLEReportBlock {
            is_loss_rle: false,
            t: 0,
            ssrc: 0x0a0b0c0d,
            begin_seq: 65530,
            end_seq: 4,
            chunks: vec![Chunk(0x000a)],
        },
        &[
            0x02, 0x00, 0x00, 0x03, // BT=2, T=0, block length 3
            0x0a, 0x0b, 0x0c, 0x0d, // ssrc of source
            0xff, 0xfa, 0x00, 0x04, // the range wraps
            0x00, 0x0a, 0x00, 0x00, // run of 10 zeros, terminating null chunk
        ],
    );
}

// RFC 3611 4.1: "If the chunks do not end on a 32-bit boundary, a terminating null chunk is
// added": it rounds the block up and is not one of the chunks.
#[test]
fn an_odd_number_of_rle_chunks_gets_a_terminating_null_chunk() {
    for chunks in [1usize, 2, 3, 4, 5] {
        let block = LossRLEReportBlock {
            is_loss_rle: true,
            t: 0,
            ssrc: 1,
            begin_seq: 0,
            end_seq: 100,
            chunks: vec![Chunk(0x8001); chunks],
        };
        let raw = xr(block.clone()).marshal().unwrap();
        let block_length = u16::from_be_bytes([raw[10], raw[11]]) as usize;

        assert_eq!(2 + chunks.div_ceil(2), block_length, "{chunks} chunks");
        assert_eq!(8 + 4 * (block_length + 1), raw.len());
        if chunks % 2 == 1 {
            assert_eq!(&[0x80, 0x01, 0x00, 0x00][..], &raw[raw.len() - 4..]);
        }
        let parsed = ExtendedReport::unmarshal(&mut raw.freeze()).unwrap();
        assert_eq!(xr(block), parsed);
    }
}

// RFC 3611 4.1: the null chunk "MUST NOT appear anywhere else"; a run length is "between 1 and
// 16,383"; a block "MUST NOT report on a sequence number range of 65,534 or more".
#[test]
fn rle_blocks_the_rfc_forbids_are_neither_written_nor_read() {
    let good = LossRLEReportBlock {
        is_loss_rle: true,
        t: 0,
        ssrc: 1,
        begin_seq: 10,
        end_seq: 20,
        chunks: vec![Chunk(0x4005)],
    };
    assert!(good.marshal().is_ok());

    let null_inside = RLEReportBlock {
        chunks: vec![Chunk(0x4005), Chunk(0), Chunk(0x4005)],
        ..good.clone()
    };
    assert_eq!(Err(Error::WrongChunkType), null_inside.marshal());
    let empty_run = RLEReportBlock {
        chunks: vec![Chunk(0x4000)],
        ..good.clone()
    };
    assert_eq!(Err(Error::WrongChunkType), empty_run.marshal());
    let widest = RLEReportBlock {
        begin_seq: 3,
        end_seq: 3u16.wrapping_add(65533),
        ..good.clone()
    };
    assert!(widest.marshal().is_ok());
    let too_wide = RLEReportBlock {
        begin_seq: 3,
        end_seq: 3u16.wrapping_add(65534),
        ..good.clone()
    };
    assert_eq!(Err(Error::InvalidBlockSize), too_wide.marshal());

    // On the wire each of those is kept unparsed, and the block after it is read.
    let on_the_wire: [&[u8]; 2] = [
        // A run of ones of length zero.
        &[
            0x01, 0x00, 0x00, 0x03, 0, 0, 0, 1, 0, 10, 0, 20, 0x40, 0x00, 0x00, 0x00,
        ],
        // begin_seq 3, end_seq 1: a range of 65,534.
        &[
            0x01, 0x00, 0x00, 0x03, 0, 0, 0, 1, 0, 3, 0, 1, 0x40, 0x05, 0x00, 0x00,
        ],
    ];
    for bad in on_the_wire {
        let mut raw = vec![0x80, 0xcf, 0x00, 0x08, 0, 0, 0, 9];
        raw.extend_from_slice(bad);
        // A receiver reference time block after it.
        raw.extend_from_slice(&[0x04, 0x00, 0x00, 0x02, 1, 2, 3, 4, 5, 6, 7, 8]);
        let parsed = ExtendedReport::unmarshal(&mut Bytes::from(raw)).unwrap();

        assert_eq!(2, parsed.reports.len());
        assert_eq!(
            BlockType::LossRLE,
            unknown(parsed.reports[0].as_ref()).block_type
        );
        assert!(
            parsed.reports[1]
                .as_any()
                .is::<ReceiverReferenceTimeReportBlock>()
        );
    }

    // A null chunk between two chunks, on the wire.
    let parsed = parse(&[
        0x80, 0xcf, 0x00, 0x06, 0, 0, 0, 9, // XR
        0x01, 0x00, 0x00, 0x04, 0, 0, 0, 1, 0, 10, 0, 20, // BT=1, block length 4
        0x40, 0x05, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00, // chunk, null, chunk, null
    ])
    .unwrap();
    assert_eq!(
        BlockType::LossRLE,
        unknown(parsed.reports[0].as_ref()).block_type
    );
}

// RFC 3611 4.1: the four bits before T are reserved, "MUST be ignored by the receiver".
#[test]
fn reserved_bits_of_an_rle_block_are_ignored() {
    let parsed = parse(&[
        0x80, 0xcf, 0x00, 0x05, 0, 0, 0, 9, // XR
        0x01, 0xf5, 0x00, 0x03, 0, 0, 0, 1, 0, 10, 0, 20, 0x40, 0x05, 0x40, 0x05,
    ])
    .unwrap();
    let block = parsed.reports[0]
        .as_any()
        .downcast_ref::<RLEReportBlock>()
        .unwrap();
    assert_eq!(5, block.t);
    // And they are sent as zero.
    assert_eq!(0x05, parsed.marshal().unwrap()[9]);
}

// RFC 3611 4.3.
#[test]
fn packet_receipt_times_block_round_trips() {
    round_trip(
        PacketReceiptTimesReportBlock {
            t: 1,
            ssrc: 0x0a0b0c0d,
            begin_seq: 7,
            end_seq: 9,
            receipt_time: vec![0x11111111, 0x22222222],
        },
        &[
            0x03, 0x01, 0x00, 0x04, // BT=3, T=1, block length 2 + 2
            0x0a, 0x0b, 0x0c, 0x0d, // ssrc of source
            0x00, 0x07, 0x00, 0x09, // begin_seq, end_seq
            0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22,
        ],
    );
    // No receipt time at all is a block of length 2.
    round_trip(
        PacketReceiptTimesReportBlock {
            t: 0,
            ssrc: 1,
            begin_seq: 7,
            end_seq: 7,
            receipt_time: vec![],
        },
        &[0x03, 0x00, 0x00, 0x02, 0, 0, 0, 1, 0, 7, 0, 7],
    );
}

// RFC 3611 4.4: block length 2, an NTP timestamp; the reserved octet is ignored.
#[test]
fn receiver_reference_time_block_round_trips() {
    round_trip(
        ReceiverReferenceTimeReportBlock {
            ntp_timestamp: 0x0102030405060708,
        },
        &[0x04, 0x00, 0x00, 0x02, 1, 2, 3, 4, 5, 6, 7, 8],
    );

    let parsed = parse(&[
        0x80, 0xcf, 0x00, 0x04, 0, 0, 0, 9, 0x04, 0xff, 0x00, 0x02, 1, 2, 3, 4, 5, 6, 7, 8,
    ])
    .unwrap();
    assert_eq!(
        xr(ReceiverReferenceTimeReportBlock {
            ntp_timestamp: 0x0102030405060708,
        })
        .reports,
        parsed.reports
    );
    assert_eq!(0x00, parsed.marshal().unwrap()[9], "sent as zero");
}

// RFC 3611 4.5: any number of three-word sub-blocks, none included.
#[test]
fn dlrr_block_round_trips() {
    round_trip(
        DLRRReportBlock {
            reports: vec![
                DLRRReport {
                    ssrc: 1,
                    last_rr: 0x11112222,
                    dlrr: 0x00010000,
                },
                DLRRReport {
                    ssrc: 2,
                    last_rr: 0x33334444,
                    dlrr: 5,
                },
            ],
        },
        &[
            0x05, 0x00, 0x00, 0x06, // BT=5, block length 6
            0, 0, 0, 1, 0x11, 0x11, 0x22, 0x22, 0x00, 0x01, 0x00, 0x00, // sub-block 1
            0, 0, 0, 2, 0x33, 0x33, 0x44, 0x44, 0x00, 0x00, 0x00, 0x05, // sub-block 2
        ],
    );
    round_trip(DLRRReportBlock { reports: vec![] }, &[0x05, 0, 0, 0]);

    // The reserved octet is ignored.
    let parsed = parse(&[
        0x80, 0xcf, 0x00, 0x05, 0, 0, 0, 9, 0x05, 0xaa, 0x00, 0x03, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0,
        0, 3,
    ])
    .unwrap();
    assert_eq!(vec![1], parsed.destination_ssrc());
}

// RFC 3611 4.6.
#[test]
fn statistics_summary_block_round_trips() {
    round_trip(
        StatisticsSummaryReportBlock {
            loss_reports: true,
            duplicate_reports: true,
            jitter_reports: true,
            ttl_or_hop_limit: TTLorHopLimitType::IPv6,
            ssrc: 0x0a0b0c0d,
            begin_seq: 1,
            end_seq: 2,
            lost_packets: 3,
            dup_packets: 4,
            min_jitter: 5,
            max_jitter: 6,
            mean_jitter: 7,
            dev_jitter: 8,
            min_ttl_or_hl: 9,
            max_ttl_or_hl: 10,
            mean_ttl_or_hl: 11,
            dev_ttl_or_hl: 12,
        },
        &[
            0x06, 0xf0, 0x00, 0x09, // BT=6, L D J, ToH=2, block length 9
            0x0a, 0x0b, 0x0c, 0x0d, // ssrc of source
            0, 1, 0, 2, // begin_seq, end_seq
            0, 0, 0, 3, 0, 0, 0, 4, // lost, dup
            0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8, // jitter
            9, 10, 11, 12, // hop limit
        ],
    );
}

// RFC 3611 4.6: "The fields corresponding to unreported parameters MUST be present, but are
// set to zero. The receiver MUST ignore any such field."
#[test]
fn unreported_statistics_are_sent_as_zero_and_ignored_when_received() {
    let everything = StatisticsSummaryReportBlock {
        loss_reports: false,
        duplicate_reports: true,
        jitter_reports: false,
        ttl_or_hop_limit: TTLorHopLimitType::Missing,
        ssrc: 1,
        begin_seq: 1,
        end_seq: 2,
        lost_packets: 3,
        dup_packets: 4,
        min_jitter: 5,
        max_jitter: 6,
        mean_jitter: 7,
        dev_jitter: 8,
        min_ttl_or_hl: 9,
        max_ttl_or_hl: 10,
        mean_ttl_or_hl: 11,
        dev_ttl_or_hl: 12,
    };
    let raw = xr(everything.clone()).marshal().unwrap();
    assert_eq!(
        &[
            0x06, 0x40, 0x00, 0x09, 0, 0, 0, 1, 0, 1, 0, 2, // only D is set
            0, 0, 0, 0, 0, 0, 0, 4, // lost zero, dup kept
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // jitter zero
            0, 0, 0, 0, // TTL zero
        ][..],
        &raw[8..]
    );

    // A sender that left values in the unreported fields.
    let parsed = parse(&[
        0x80, 0xcf, 0x00, 0x0b, 0, 0, 0, 9, // XR
        0x06, 0x40, 0x00, 0x09, 0, 0, 0, 1, 0, 1, 0, 2, // only D is set
        0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8, 9, 10, 11, 12,
    ])
    .unwrap();
    assert_eq!(xr(everything.reported()).reports, parsed.reports);
    let block = parsed.reports[0]
        .as_any()
        .downcast_ref::<StatisticsSummaryReportBlock>()
        .unwrap();
    assert_eq!(
        (0, 4, 0, 0),
        (
            block.lost_packets,
            block.dup_packets,
            block.max_jitter,
            block.max_ttl_or_hl
        )
    );
}

// RFC 3611 4.6: "The value 3 is undefined and MUST NOT be used." It cannot be written; read,
// it reports no TTL.
#[test]
fn the_undefined_ttl_type_reads_as_no_ttl_report() {
    let parsed = parse(&[
        0x80, 0xcf, 0x00, 0x0b, 0, 0, 0, 9, // XR
        0x06, 0x18, 0x00, 0x09, 0, 0, 0, 1, 0, 1, 0, 2, // ToH = 3
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 10, 11, 12,
    ])
    .unwrap();
    let block = parsed.reports[0]
        .as_any()
        .downcast_ref::<StatisticsSummaryReportBlock>()
        .unwrap();
    assert_eq!(TTLorHopLimitType::Missing, block.ttl_or_hop_limit);
    assert_eq!(0, block.min_ttl_or_hl);
    assert_eq!(0, block.dev_ttl_or_hl);
}

fn voip_metrics() -> VoIPMetricsReportBlock {
    VoIPMetricsReportBlock {
        ssrc: 0x0a0b0c0d,
        loss_rate: 1,
        discard_rate: 2,
        burst_density: 3,
        gap_density: 4,
        burst_duration: 5,
        gap_duration: 6,
        round_trip_delay: 7,
        end_system_delay: 8,
        signal_level: 0xe2, // -30 dBm0
        noise_level: 0xba,  // -70 dBm0
        rerl: 55,
        gmin: 16,
        rfactor: 93,
        ext_rfactor: 127,
        mos_lq: 44,
        mos_cq: 41,
        rx_config: 0xb0,
        reserved: 0,
        jb_nominal: 40,
        jb_maximum: 80,
        jb_abs_max: 120,
    }
}

// RFC 3611 4.7.
#[test]
fn voip_metrics_block_round_trips() {
    round_trip(
        voip_metrics(),
        &[
            0x07, 0x00, 0x00, 0x08, // BT=7, block length 8
            0x0a, 0x0b, 0x0c, 0x0d, // ssrc of source
            1, 2, 3, 4, // loss rate, discard rate, burst density, gap density
            0, 5, 0, 6, // burst duration, gap duration
            0, 7, 0, 8, // round trip delay, end system delay
            0xe2, 0xba, 55, 16, // signal level, noise level, RERL, Gmin
            93, 127, 44, 41, // R factor, ext. R factor, MOS-LQ, MOS-CQ
            0xb0, 0, 0, 40, // RX config, reserved, JB nominal
            0, 80, 0, 120, // JB maximum, JB abs max
        ],
    );
}

// RFC 3611 4.7.4 - 4.7.6: 127 says "unavailable"; Gmin "MUST not be zero", 16 recommended.
#[test]
fn default_voip_metrics_report_nothing_and_can_be_sent() {
    let block = VoIPMetricsReportBlock::default();
    let raw = block.marshal().unwrap();
    assert_eq!(
        &[
            0x07, 0x00, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
            127, 127, 127, 16, 127, 127, 127, 127, 0, 0, 0, 0, 0, 0, 0, 0,
        ][..],
        &raw[..]
    );
}

// RFC 3611 4.7.5: values other than 127 and the valid range "MUST NOT be sent and MUST be
// ignored by the receiving system".
#[test]
fn voip_quality_values_outside_their_range_are_not_sent_and_are_ignored() {
    for bad in [
        VoIPMetricsReportBlock {
            rfactor: 101,
            ..voip_metrics()
        },
        VoIPMetricsReportBlock {
            ext_rfactor: 126,
            ..voip_metrics()
        },
        VoIPMetricsReportBlock {
            mos_lq: 9,
            ..voip_metrics()
        },
        VoIPMetricsReportBlock {
            mos_cq: 51,
            ..voip_metrics()
        },
        VoIPMetricsReportBlock {
            gmin: 0,
            ..voip_metrics()
        },
    ] {
        assert_eq!(Err(Error::InvalidHeader), bad.marshal(), "{bad:?}");
    }
    for edge in [
        VoIPMetricsReportBlock {
            rfactor: 0,
            ext_rfactor: 100,
            mos_lq: 10,
            mos_cq: 50,
            ..voip_metrics()
        },
        VoIPMetricsReportBlock {
            rfactor: 127,
            ext_rfactor: 127,
            mos_lq: 127,
            mos_cq: 127,
            ..voip_metrics()
        },
    ] {
        assert!(edge.marshal().is_ok(), "{edge:?}");
    }

    let parsed = parse(&[
        0x80, 0xcf, 0x00, 0x0a, 0, 0, 0, 9, // XR
        0x07, 0xff, 0x00, 0x08, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, // reserved set
        127, 127, 127, 16, // levels, Gmin
        101, 200, 9, 51, // R factors and MOS scores, none valid
        0, 0xee, 0, 0, 0, 0, 0, 0, // reserved octet set
    ])
    .unwrap();
    let block = parsed.reports[0]
        .as_any()
        .downcast_ref::<VoIPMetricsReportBlock>()
        .unwrap();
    assert_eq!(
        (127, 127, 127, 127),
        (block.rfactor, block.ext_rfactor, block.mos_lq, block.mos_cq)
    );
    assert_eq!(0, block.reserved, "the reserved octet is ignored");

    // And the reserved octet is sent as zero whatever the field holds.
    let noisy = VoIPMetricsReportBlock {
        reserved: 0xee,
        ..voip_metrics()
    };
    assert_eq!(0, noisy.marshal().unwrap()[29]);
}

// RFC 3611 3 / 4: a block type defined later is skipped by its length and kept as it is.
#[test]
fn a_block_of_a_later_type_is_kept_with_its_type_and_type_specific_octet() {
    let raw: &'static [u8] = &[
        0x80, 0xcf, 0x00, 0x07, 0, 0, 0, 9, // XR
        0x0e, 0x5a, 0x00, 0x01, 1, 2, 3, 4, // BT=14, type-specific 0x5a, one word
        0x2a, 0x00, 0x00, 0x00, // BT=42 with nothing in it
        0x04, 0x00, 0x00, 0x02, 1, 2, 3, 4, 5, 6, 7, 8, // RRTR
    ];
    let parsed = parse(raw).unwrap();

    assert_eq!(3, parsed.reports.len());
    assert_eq!(
        &UnknownReportBlock {
            block_type: BlockType::Other(14),
            type_specific: 0x5a,
            bytes: Bytes::from_static(&[1, 2, 3, 4]),
        },
        unknown(parsed.reports[0].as_ref())
    );
    assert_eq!(
        BlockType::Other(42),
        unknown(parsed.reports[1].as_ref()).block_type
    );
    assert_eq!(raw, &parsed.marshal().unwrap()[..]);

    for octet in 0..=u8::MAX {
        assert_eq!(octet, u8::from(BlockType::from(octet)));
    }
}

// RFC 3611 3: the block length counts 32-bit words.
#[test]
fn an_unparsed_block_that_is_not_a_whole_number_of_words_is_not_marshalled() {
    let odd = UnknownReportBlock {
        block_type: BlockType::Other(14),
        type_specific: 0,
        bytes: Bytes::from_static(&[1, 2, 3]),
    };
    assert_eq!(Err(Error::InvalidBlockSize), odd.marshal());
    assert_eq!(Err(Error::InvalidBlockSize), xr(odd).marshal());
}

// A known block with a length its type does not allow is kept unparsed, with its type; the
// blocks around it, and the packets around the XR, are read (audit rfc3611.md bug 4).
#[test]
fn a_block_with_the_wrong_length_for_its_type_costs_only_itself() {
    let cases: Vec<(&str, BlockType, &'static [u8])> = vec![
        (
            "RRTR of three words",
            BlockType::ReceiverReferenceTime,
            &[
                0x04, 0x00, 0x00, 0x03, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ],
        ),
        (
            "RRTR of one word",
            BlockType::ReceiverReferenceTime,
            &[0x04, 0x00, 0x00, 0x01, 1, 2, 3, 4],
        ),
        (
            "DLRR of two words",
            BlockType::DLRR,
            &[0x05, 0x00, 0x00, 0x02, 1, 2, 3, 4, 5, 6, 7, 8],
        ),
        (
            "statistics summary of two words",
            BlockType::StatisticsSummary,
            &[0x06, 0x00, 0x00, 0x02, 1, 2, 3, 4, 5, 6, 7, 8],
        ),
        (
            "VoIP metrics of two words",
            BlockType::VoIPMetrics,
            &[0x07, 0x00, 0x00, 0x02, 1, 2, 3, 4, 5, 6, 7, 8],
        ),
        (
            "loss RLE without its begin and end",
            BlockType::LossRLE,
            &[0x01, 0x00, 0x00, 0x01, 1, 2, 3, 4],
        ),
        (
            "duplicate RLE with nothing",
            BlockType::DuplicateRLE,
            &[0x02, 0x00, 0x00, 0x00],
        ),
        (
            "receipt times without begin and end",
            BlockType::PacketReceiptTimes,
            &[0x03, 0x00, 0x00, 0x01, 1, 2, 3, 4],
        ),
    ];

    for (name, block_type, bad) in cases {
        let mut xr = vec![0x80, 0xcf, 0x00, 0x00, 0, 0, 0, 9];
        xr.extend_from_slice(bad);
        xr.extend_from_slice(&[0x05, 0x00, 0x00, 0x03, 0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0, 9]);
        xr[3] = (xr.len() / 4 - 1) as u8;
        let mut datagram = vec![0x80, 0xc9, 0x00, 0x01, 0, 0, 0, 1]; // RR
        datagram.extend_from_slice(&xr);
        datagram.extend_from_slice(&[0x81, 0xcb, 0x00, 0x01, 0, 0, 0, 1]); // BYE

        let packets = packet::unmarshal(&mut Bytes::from(datagram.clone())).expect(name);
        assert_eq!(3, packets.len(), "{name}");
        let parsed = packets[1]
            .as_any()
            .downcast_ref::<ExtendedReport>()
            .expect(name);
        assert_eq!(2, parsed.reports.len(), "{name}");
        let kept = unknown(parsed.reports[0].as_ref());
        assert_eq!(block_type, kept.block_type, "{name}");
        assert_eq!(&bad[4..], &kept.bytes[..], "{name}");
        assert_eq!(vec![7], parsed.reports[1].destination_ssrc(), "{name}");
        // Nothing is lost on the way back out.
        assert_eq!(
            &datagram[..],
            &packet::marshal(&packets).unwrap()[..],
            "{name}"
        );
    }
}

// What frames the blocks is not negotiable: a block length that runs past the packet leaves
// nothing to skip to.
#[test]
fn an_extended_report_whose_framing_is_broken_is_refused() {
    let cases: Vec<(&str, &'static [u8], Error)> = vec![
        ("no ssrc", &[0x80, 0xcf, 0x00, 0x00], Error::PacketTooShort),
        (
            "a block length past the end of the packet",
            &[
                0x80, 0xcf, 0x00, 0x03, 0, 0, 0, 9, 0x04, 0x00, 0x00, 0x02, 1, 2, 3, 4,
            ],
            Error::PacketTooShort,
        ),
        (
            "padding with a count of zero",
            &[0xa0, 0xcf, 0x00, 0x02, 0, 0, 0, 9, 0, 0, 0, 0],
            Error::WrongPadding,
        ),
        (
            "padding longer than the packet",
            &[0xa0, 0xcf, 0x00, 0x02, 0, 0, 0, 9, 0, 0, 0, 12],
            Error::WrongPadding,
        ),
        (
            "padding that leaves half a block header",
            &[
                0xa0, 0xcf, 0x00, 0x03, 0, 0, 0, 9, 0x04, 0x00, 0x00, 0x00, 0, 0, 0, 6,
            ],
            Error::PacketTooShort,
        ),
        (
            "another packet type",
            &[0x80, 0xc9, 0x00, 0x01, 0, 0, 0, 9],
            Error::WrongType,
        ),
    ];
    for (name, raw, want) in cases {
        assert_eq!(Some(want), parse(raw).err(), "{name}");
    }
}

// RFC 3611 2: five reserved bits share the first octet with V and P and are ignored. An XR
// with no block is the header and the SSRC.
#[test]
fn the_reserved_bits_of_the_xr_header_are_ignored() {
    let parsed = parse(&[0x9f, 0xcf, 0x00, 0x01, 1, 2, 3, 4]).unwrap();
    assert_eq!(0x01020304, parsed.sender_ssrc);
    assert!(parsed.reports.is_empty());
    assert_eq!(
        &[0x80, 0xcf, 0x00, 0x01, 1, 2, 3, 4][..],
        &parsed.marshal().unwrap()[..]
    );
}

// RFC 3611 2 with RFC 3550 6.4.1: the padding comes after the last block.
#[test]
fn padding_after_the_report_blocks_is_cut_off() {
    let padded = parse(&[
        0xa0, 0xcf, 0x00, 0x06, 0, 0, 0, 9, // XR, P=1
        0x04, 0x00, 0x00, 0x02, 1, 2, 3, 4, 5, 6, 7, 8, // RRTR
        0, 0, 0, 0, 0, 0, 0, 8, // eight padding octets
    ])
    .unwrap();
    assert_eq!(1, padded.reports.len());
    assert_eq!(20, padded.marshal().unwrap().len());
}

// RFC 3611 4.1: "If the bit vector chunk is the last chunk and the sequence number range
// ends partway through it, the remaining bits MUST be set to zero and MUST be ignored by the
// receiver" (the trailing bits of the vector past `end_seq`).
#[test]
fn bits_of_a_last_bit_vector_past_the_range_are_zero_and_ignored() {
    let block = RLEReportBlock::from_flags(true, 7, 100, 105, 0, &[true, false, true, true, true]);
    assert_eq!(vec![Chunk(0b1101_1100_0000_0000)], block.chunks);

    // A sender that left ones past the end: the reader stops at the end of the range.
    let lax = RLEReportBlock {
        chunks: vec![Chunk(0b1101_1111_1111_1111)],
        ..block.clone()
    };
    assert_eq!(vec![true, false, true, true, true], lax.flags());
}

// RFC 3611 4.1, 4.1.1, 4.1.2: runs of 15 or more are run-length chunks, the rest bit vectors;
// a reader expands them back to one flag per sequence number, across the 16-bit wrap.
#[test]
fn flags_survive_run_lengths_bit_vectors_and_the_wire() {
    let mut flags = vec![true; 40];
    flags.extend([false, true, false, false, true, true]);
    flags.extend(vec![false; 20]);
    flags.push(true);
    let begin = 65_500u16;
    let end = begin.wrapping_add(flags.len() as u16);
    let block = RLEReportBlock::from_flags(true, 9, begin, end, 0, &flags);
    assert_eq!(ChunkType::RunLength, block.chunks[0].chunk_type());
    assert_eq!(40, block.chunks[0].value());
    assert_eq!(Ok(1), block.chunks[0].run_type());
    let raw = xr(block.clone()).marshal().unwrap();
    let read = ExtendedReport::unmarshal(&mut raw.freeze()).unwrap();
    let read = read.reports[0]
        .as_any()
        .downcast_ref::<RLEReportBlock>()
        .unwrap();
    assert_eq!(flags, read.flags());
}

// RFC 3611 4.1: with thinning T, only the sequence numbers that are a multiple of 2^T are
// reported on.
#[test]
fn thinning_reports_on_every_second_sequence_number() {
    assert_eq!(vec![10, 12, 14], reported_sequence_numbers(9, 16, 1));
    assert_eq!(vec![65_534, 0], reported_sequence_numbers(65_533, 2, 1));
    let block = RLEReportBlock::from_flags(true, 1, 9, 16, 1, &[true, false, true]);
    assert_eq!(vec![true, false, true], block.flags());
}

/// RFC 6679 section 5.2, Figures 3 and 4, in an XR packet built by hand.
const ECN_SUMMARY_XR: [u8; 32] = [
    0x80, 0xcf, 0x00, 0x07, // XR, length 7
    0x00, 0x00, 0x00, 0x09, // sender SSRC
    0x0d, 0x00, 0x00, 0x05, // BT=13, reserved, block length 5
    0x00, 0x00, 0x00, 0x02, // SSRC of media sender
    0x00, 0x00, 0x00, 0x03, // ECT(0)
    0x00, 0x00, 0x00, 0x04, // ECT(1)
    0x00, 0x05, 0x00, 0x06, // ECN-CE, not-ECT
    0x00, 0x07, 0x00, 0x08, // lost, duplicates
];

fn ecn_summary() -> EcnSummaryReportBlock {
    EcnSummaryReportBlock {
        reports: vec![EcnSummaryReport {
            ssrc: 2,
            counters: crate::transport_feedbacks::ecn_feedback::EcnCounters {
                ect0: 3,
                ect1: 4,
                ce: 5,
                not_ect: 6,
                lost: 7,
                duplicates: 8,
            },
        }],
    }
}

#[test]
fn an_ecn_summary_block_has_the_wire_image_of_rfc_6679_figures_3_and_4() {
    let xr = ExtendedReport {
        sender_ssrc: 9,
        reports: vec![Box::new(ecn_summary())],
    };
    assert_eq!(xr.marshal().unwrap().as_ref(), &ECN_SUMMARY_XR[..]);
    let parsed = ExtendedReport::unmarshal(&mut Bytes::from_static(&ECN_SUMMARY_XR)).unwrap();
    let block = parsed.reports[0]
        .as_any()
        .downcast_ref::<EcnSummaryReportBlock>()
        .expect("an ECN summary block");
    assert_eq!(block, &ecn_summary());
}

/// "the report block SHALL still be sent with no report block entry and a zero report block
/// length": an empty block is four octets with length 0, and parses back.
#[test]
fn an_ecn_summary_block_without_senders_has_length_zero() {
    let empty = EcnSummaryReportBlock::default();
    let wire = empty.marshal().unwrap();
    assert_eq!(wire.as_ref(), &[0x0d, 0x00, 0x00, 0x00]);
    let parsed = EcnSummaryReportBlock::unmarshal(&mut wire.clone()).unwrap();
    assert!(parsed.reports.is_empty());
}

/// "Receivers MUST discard reports where the block length is not a multiple of five"; the
/// reserved octet is ignored on reception.
#[test]
fn an_ecn_summary_block_whose_length_is_not_a_multiple_of_five_is_discarded() {
    let mut wire = ECN_SUMMARY_XR.to_vec();
    wire[9] = 0xff; // reserved: ignored
    let parsed = ExtendedReport::unmarshal(&mut Bytes::from(wire.clone())).unwrap();
    assert!(parsed.reports[0].as_any().is::<EcnSummaryReportBlock>());

    // Block length 4 (16 octets of data): not a multiple of five.
    let mut bad = ECN_SUMMARY_XR[..28].to_vec();
    bad[3] = 0x06;
    bad[11] = 0x04;
    let parsed = ExtendedReport::unmarshal(&mut Bytes::from(bad)).unwrap();
    assert!(!parsed.reports[0].as_any().is::<EcnSummaryReportBlock>());
}
