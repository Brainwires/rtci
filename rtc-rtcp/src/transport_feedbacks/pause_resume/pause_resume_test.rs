use super::*;
use bytes::Bytes;

/// RFC 7728 section 7, Figures 5 and 6, written out: RTPFB (205), FMT 9, media source 0, a
/// PAUSE (type 0) for 0x11223344 with PauseID 7, and a PAUSED (type 2, one parameter word)
/// for 0x55667788 with PauseID 8 and the extended sequence number 0x00010203.
const WIRE: [u8; 32] = [
    0x89, 205, 0x00, 0x07, // V=2, FMT=9, PT=205, length 7 (32 octets)
    0x00, 0x00, 0x00, 0x2a, // SSRC of packet sender
    0x00, 0x00, 0x00, 0x00, // SSRC of media source: 0
    0x11, 0x22, 0x33, 0x44, // Target SSRC
    0x00, 0x00, 0x00, 0x07, // Type 0, Res 0, Parameter Len 0, PauseID 7
    0x55, 0x66, 0x77, 0x88, // Target SSRC
    0x20, 0x01, 0x00, 0x08, // Type 2, Res 0, Parameter Len 1, PauseID 8
    0x00, 0x01, 0x02, 0x03, // extended highest sequence number
];

#[test]
fn a_pause_and_a_paused_entry_round_trip_as_figure_6_lays_them_out() {
    let message = PauseResume {
        sender_ssrc: 0x2a,
        entries: vec![
            PauseResumeEntry::pause(0x1122_3344, 7),
            PauseResumeEntry::paused(0x5566_7788, 8, 0x0001_0203),
        ],
    };
    assert_eq!(message.marshal().unwrap().to_vec(), WIRE.to_vec());
    let parsed = PauseResume::unmarshal(&mut Bytes::from_static(&WIRE)).unwrap();
    assert_eq!(parsed, message);
    assert_eq!(
        parsed.entries[1].paused_extended_sequence_number(),
        Some(0x0001_0203)
    );
    assert_eq!(parsed.entries[0].paused_extended_sequence_number(), None);
    assert_eq!(parsed.destination_ssrc(), vec![0x1122_3344, 0x5566_7788]);
}

#[test]
fn the_packet_parser_dispatches_fmt_9_to_pause_resume() {
    let packets = crate::packet::unmarshal(&mut Bytes::from_static(&WIRE)).unwrap();
    assert!(packets[0].as_any().downcast_ref::<PauseResume>().is_some());
}

/// "The SSRC of media source: Not used; SHALL be set to 0" and "Res ... MUST be set to 0 by
/// senders" on the way out; on the way in both are ignored, and unknown type-specific data
/// (here a RESUME with one word) and reserved types are skipped, not refused.
#[test]
fn unused_fields_are_zero_when_written_and_ignored_when_read() {
    let input: Vec<u8> = vec![
        0x89, 205, 0x00, 0x06, // 28 octets
        0x00, 0x00, 0x00, 0x2a, //
        0xde, 0xad, 0xbe, 0xef, // media source not 0: ignored
        0x11, 0x22, 0x33, 0x44, //
        0x1f, 0x01, 0x00, 0x05, // Type 1 (RESUME), Res 0xf, one word, PauseID 5
        0xaa, 0xbb, 0xcc, 0xdd, // unknown RESUME parameter
        0x00, 0x00, 0x00, 0x00, // four octets more: not a whole entry
    ];
    // The last word cannot be a whole entry: refused.
    assert!(PauseResume::unmarshal(&mut Bytes::from(input.clone())).is_err());

    let mut input = input[..24].to_vec();
    input[3] = 5;
    let parsed = PauseResume::unmarshal(&mut Bytes::from(input)).unwrap();
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].typ, PauseResumeType::Resume);
    assert_eq!(parsed.entries[0].pause_id, 5);
    assert_eq!(parsed.entries[0].type_specific.len(), 4);

    let written = PauseResume {
        sender_ssrc: 1,
        entries: vec![PauseResumeEntry::resume(2, 3)],
    }
    .marshal()
    .unwrap();
    assert_eq!(&written[8..12], &[0, 0, 0, 0], "media source SSRC");
    assert_eq!(written[16] & 0x0f, 0, "reserved bits");

    let reserved: Vec<u8> = vec![
        0x89, 205, 0x00, 0x04, //
        0x00, 0x00, 0x00, 0x2a, //
        0x00, 0x00, 0x00, 0x00, //
        0x11, 0x22, 0x33, 0x44, //
        0x90, 0x00, 0x00, 0x01, // Type 9: reserved
    ];
    let parsed = PauseResume::unmarshal(&mut Bytes::from(reserved)).unwrap();
    assert_eq!(parsed.entries[0].typ, PauseResumeType::Reserved(9));
}

/// A sender never writes a reserved type, nor a type-specific field its Parameter Len cannot
/// describe.
#[test]
fn reserved_types_and_ragged_parameters_are_not_written() {
    let reserved = PauseResume {
        sender_ssrc: 1,
        entries: vec![PauseResumeEntry {
            target_ssrc: 2,
            typ: PauseResumeType::Reserved(4),
            pause_id: 0,
            type_specific: Bytes::new(),
        }],
    };
    assert!(reserved.marshal().is_err());
    let ragged = PauseResume {
        sender_ssrc: 1,
        entries: vec![PauseResumeEntry {
            target_ssrc: 2,
            typ: PauseResumeType::Paused,
            pause_id: 0,
            type_specific: Bytes::from_static(&[1, 2, 3]),
        }],
    };
    assert!(ragged.marshal().is_err());
}
