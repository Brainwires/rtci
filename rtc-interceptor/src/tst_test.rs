//! RFC 5104 sections 4.3.2 to 4.3.4: TSTR and VBCM command numbers, and the TSTN a media
//! sender sends for each request.

use super::*;
use crate::stream_info::RTCPFeedback;

const MEDIA: u32 = 0x0100;
const ALICE: u32 = 0x0A11;
const BOB: u32 = 0x0B0B;

fn local(ssrc: u32, tstr: bool) -> StreamInfo {
    StreamInfo {
        ssrc,
        rtcp_feedback: if tstr {
            vec![RTCPFeedback {
                typ: "ccm".to_owned(),
                parameter: "tstr".to_owned(),
            }]
        } else {
            vec![]
        },
        ..Default::default()
    }
}

fn request(from: u32, entries: &[(u32, u8, u8)]) -> TemporalSpatialTradeoffRequest {
    TemporalSpatialTradeoffRequest {
        sender_ssrc: from,
        entries: entries
            .iter()
            .map(|&(ssrc, sequence_number, index)| TstEntry {
                ssrc,
                sequence_number,
                index,
            })
            .collect(),
    }
}

/// The TSTNs written after reading one compound packet of `requests`.
fn notifications(
    responder: &mut TstnResponderInterceptor,
    requests: Vec<TemporalSpatialTradeoffRequest>,
) -> Vec<TemporalSpatialTradeoffNotification> {
    let packets: Vec<Box<dyn rtcp::Packet>> = requests
        .into_iter()
        .map(|r| Box::new(r) as Box<dyn rtcp::Packet>)
        .collect();
    responder
        .handle_read(TaggedPacket {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(packets)),
        })
        .unwrap();
    assert!(responder.poll_read().is_some(), "the request goes on");
    let mut out = vec![];
    while let Some(written) = responder.poll_write() {
        if let Packet::Rtcp(packets) = written.message.packet {
            for packet in packets {
                out.push(
                    packet
                        .as_any()
                        .downcast_ref::<TemporalSpatialTradeoffNotification>()
                        .expect("a TSTN")
                        .clone(),
                );
            }
        }
    }
    out
}

fn entries(n: &TemporalSpatialTradeoffNotification) -> Vec<(u32, u8, u8)> {
    n.entries
        .iter()
        .map(|e| (e.ssrc, e.sequence_number, e.index))
        .collect()
}

/// RFC 5104 4.3.2.2 and 4.3.3.2: "The selected trade-off SHALL be communicated to the media
/// receivers by means of the TSTN message"; one FCI entry per requester, echoing its sequence
/// number, the same index in every entry, from the media sender.
#[test]
fn each_requester_is_answered_with_one_index_for_all() {
    let mut responder = TstnResponderBuilder::new().build();
    responder.bind_local_stream(&local(MEDIA, true));
    let sent = notifications(
        &mut responder,
        vec![
            request(ALICE, &[(MEDIA, 4, 10)]),
            request(BOB, &[(MEDIA, 9, 20)]),
        ],
    );
    assert_eq!(1, sent.len());
    assert_eq!(MEDIA, sent[0].sender_ssrc);
    let got = entries(&sent[0]);
    assert_eq!(vec![(ALICE, 4, 20), (BOB, 9, 20)], got);
}

/// RFC 5104 4.3.3.2: "The Notification SHALL also be sent in response to TSTR repetitions
/// received. If the request receiver has received TSTR with several different sequence
/// numbers from a single requestor, it SHALL only respond to the request with the highest
/// (modulo 256) sequence number." 255 to 0 is a step forward; an older one is not answered.
#[test]
fn repetitions_are_answered_and_only_the_highest_sequence_number_of_a_requester() {
    let mut responder = TstnResponderBuilder::new().build();
    responder.bind_local_stream(&local(MEDIA, true));
    let sent = notifications(
        &mut responder,
        vec![
            request(ALICE, &[(MEDIA, 254, 3)]),
            request(ALICE, &[(MEDIA, 0, 5)]),
            request(ALICE, &[(MEDIA, 255, 4)]),
        ],
    );
    assert_eq!(vec![(ALICE, 0, 5)], entries(&sent[0]));

    let repeated = notifications(&mut responder, vec![request(ALICE, &[(MEDIA, 0, 5)])]);
    assert_eq!(
        vec![(ALICE, 0, 5)],
        entries(&repeated[0]),
        "a repetition is answered"
    );

    let stale = notifications(&mut responder, vec![request(ALICE, &[(MEDIA, 255, 4)])]);
    assert!(stale.is_empty(), "{stale:?}");
}

/// RFC 5104 4.3.3.2: the TSTN carries "the Temporal-Spatial Trade-off index that will be
/// used", which need not be the one asked; and RFC 5104 7.2: nothing is answered for a stream
/// that did not negotiate `ccm tstr`, or for another media sender.
#[test]
fn the_index_is_the_one_used_and_only_negotiated_streams_answer() {
    let mut responder = TstnResponderBuilder::new().with_fixed_index(7).build();
    responder.bind_local_stream(&local(MEDIA, true));
    responder.bind_local_stream(&local(0x0200, false));
    let sent = notifications(
        &mut responder,
        vec![request(
            ALICE,
            &[(MEDIA, 1, 30), (0x0200, 1, 30), (0x0300, 1, 30)],
        )],
    );
    assert_eq!(1, sent.len());
    assert_eq!(vec![(ALICE, 1, 7)], entries(&sent[0]));
}

/// RFC 5104 4.3.2.1 and 4.3.4.1: the sequence number goes up by one, modulo 256, with each new
/// command and stays for a repetition, per command target.
#[test]
fn tstr_and_vbcm_command_numbers_count_new_commands_modulo_256() {
    let mut tstr = TstrCommands::new();
    assert!(tstr.repeat(ALICE, MEDIA).is_none());
    let mut last = tstr.request(ALICE, MEDIA, 40);
    assert_eq!(31, last.entries[0].index, "the index is five bits");
    for _ in 0..300 {
        let next = tstr.request(ALICE, MEDIA, 1);
        assert_eq!(
            last.entries[0].sequence_number.wrapping_add(1),
            next.entries[0].sequence_number
        );
        last = next;
    }
    let again = tstr.repeat(ALICE, MEDIA).unwrap();
    assert_eq!(last.entries, again.entries);
    assert_eq!(0, tstr.request(ALICE, 0x0999, 0).entries[0].sequence_number);

    let mut vbcm = VbcmCommands::new();
    let first = vbcm.request(ALICE, MEDIA, 96, Bytes::from_static(b"h271"));
    let again = vbcm.repeat(ALICE, MEDIA).unwrap();
    let next = vbcm.request(ALICE, MEDIA, 96, Bytes::from_static(b"next"));
    assert_eq!(first.entries, again.entries);
    assert_eq!(1, next.entries[0].sequence_number);
    assert_eq!(0, first.entries[0].sequence_number);
}
