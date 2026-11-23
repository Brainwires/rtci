use super::*;

fn ev(event: u8, end: bool, volume: u8, duration: u16) -> TelephoneEvent {
    TelephoneEvent {
        event,
        end,
        volume,
        duration,
    }
}

fn bytes_of(event: TelephoneEvent) -> Vec<u8> {
    event.marshal().unwrap().to_vec()
}

// ---- wire format -------------------------------------------------------------------------

#[test]
fn rfc4733_figure3_event_payload_bytes() {
    // Figure 3: event 1, E=1, R=0, volume 20, duration 1760.
    let expected = [0x01, 0x94, 0x06, 0xE0];
    assert_eq!(bytes_of(ev(1, true, 20, 1760)), expected);
    let parsed = TelephoneEvent::unmarshal(&mut &expected[..]).unwrap();
    assert_eq!(parsed, ev(1, true, 20, 1760));
}

#[test]
fn round_trip_preserves_every_field() {
    for event in [
        ev(0, false, 0, 1),
        ev(255, true, 63, 0xFFFF),
        ev(11, false, 10, 400),
    ] {
        let raw = event.marshal().unwrap();
        assert_eq!(TelephoneEvent::unmarshal(&mut &raw[..]).unwrap(), event);
    }
}

#[test]
fn sender_writes_the_r_bit_as_zero() {
    let raw = bytes_of(ev(5, true, 63, 100));
    assert_eq!(raw[1] & 0x40, 0);
    let raw = bytes_of(ev(5, false, 63, 100));
    assert_eq!(raw[1] & 0x40, 0);
}

#[test]
fn parser_ignores_the_r_bit() {
    let with_r = [0x03, 0x80 | 0x40 | 7, 0x00, 0x64];
    let parsed = TelephoneEvent::unmarshal(&mut &with_r[..]).unwrap();
    assert_eq!(parsed, ev(3, true, 7, 100));
    let with_r_no_e = [0x03, 0x40, 0x00, 0x64];
    assert_eq!(
        TelephoneEvent::unmarshal(&mut &with_r_no_e[..]).unwrap(),
        ev(3, false, 0, 100)
    );
}

#[test]
fn marshal_rejects_volume_above_63() {
    assert!(ev(1, false, 64, 10).marshal().is_err());
    assert!(marshal_telephone_events(&[ev(1, false, 64, 10)]).is_err());
}

#[test]
fn volume_zero_is_accepted() {
    let raw = bytes_of(ev(1, false, 0, 10));
    assert_eq!(raw, [0x01, 0x00, 0x00, 0x0A]);
}

#[test]
fn marshal_into_a_short_buffer_fails() {
    let mut buf = [0u8; 3];
    assert_eq!(
        ev(1, false, 0, 1).marshal_to(&mut buf),
        Err(Error::ErrBufferTooSmall)
    );
}

#[test]
fn short_report_is_rejected() {
    for len in 0..4 {
        let raw = vec![0u8; len];
        assert_eq!(
            TelephoneEvent::unmarshal(&mut &raw[..]),
            Err(Error::ErrShortPacket)
        );
    }
}

#[test]
fn payload_length_must_be_a_nonzero_multiple_of_four() {
    assert!(parse_telephone_events(&[]).is_err());
    assert!(parse_telephone_events(&[1, 2, 3]).is_err());
    assert!(parse_telephone_events(&[1, 2, 3, 4, 5]).is_err());
    assert!(parse_telephone_events(&[0; 7]).is_err());
    assert_eq!(parse_telephone_events(&[0, 0, 0, 1]).unwrap().len(), 1);
}

#[test]
fn several_events_in_one_payload_round_trip_in_order() {
    let events = [
        ev(1, true, 10, 800),
        ev(2, false, 10, 400),
        ev(3, false, 0, 1),
    ];
    let raw = marshal_telephone_events(&events).unwrap();
    assert_eq!(raw.len(), 12);
    assert_eq!(parse_telephone_events(&raw).unwrap(), events);
}

#[test]
fn an_empty_event_list_does_not_marshal() {
    assert!(marshal_telephone_events(&[]).is_err());
}

// ---- DTMF table --------------------------------------------------------------------------

#[test]
fn dtmf_characters_map_to_section_3_2_codes() {
    let table = "0123456789*#ABCD";
    for (code, c) in table.chars().enumerate() {
        assert_eq!(dtmf_event_from_char(c), Some(code as u8), "{c}");
        assert_eq!(dtmf_char_from_event(code as u8), Some(c));
    }
    for (code, c) in "abcd".chars().enumerate() {
        assert_eq!(dtmf_event_from_char(c), Some(DTMF_A + code as u8));
    }
}

#[test]
fn non_dtmf_characters_and_codes_have_no_mapping() {
    for c in ['e', 'E', ' ', '+', 'x', ','] {
        assert_eq!(dtmf_event_from_char(c), None);
    }
    for code in [16u8, 32, 255] {
        assert_eq!(dtmf_char_from_event(code), None);
    }
}

// ---- events list -------------------------------------------------------------------------

#[test]
fn events_list_parses_ranges_and_single_codes() {
    let set = EventSet::parse("0-15,32,36").unwrap();
    assert_eq!(set.len(), 18);
    for e in 0..=15 {
        assert!(set.contains(e));
    }
    assert!(set.contains(32));
    assert!(set.contains(36));
    assert!(!set.contains(16));
    assert!(!set.contains(33));
}

#[test]
fn events_list_formats_back_to_compact_ranges() {
    assert_eq!(
        EventSet::parse("0-15,32,36").unwrap().to_string(),
        "0-15,32,36"
    );
    assert_eq!(
        EventSet::parse("5,3,4,255,254").unwrap().to_string(),
        "3-5,254-255"
    );
    assert_eq!(EventSet::parse("0-255").unwrap().to_string(), "0-255");
    assert_eq!(EventSet::empty().to_string(), "");
}

#[test]
fn events_list_accepts_unsorted_and_overlapping_elements() {
    let set = EventSet::parse("66,70,0-15,10-12").unwrap();
    assert_eq!(set.to_string(), "0-15,66,70");
}

#[test]
fn malformed_events_lists_are_rejected() {
    for bad in [
        "", ",", "0-", "-5", "0-15,", "0 -15", " 1", "1 ", "256", "0-256", "a", "15-0", "1--2",
        "+1", "0x10", "1,,2", "0-1-2", "1000",
    ] {
        assert!(EventSet::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn absent_events_parameter_means_dtmf_0_to_15() {
    let set = EventSet::from_peer_fmtp(None).unwrap();
    assert_eq!(set, EventSet::dtmf());
    assert_eq!(set.to_string(), "0-15");
    assert_eq!(EventSet::default(), EventSet::dtmf());
    assert!(!set.contains(16));
    assert_eq!(
        EventSet::from_peer_fmtp(Some("0-11")).unwrap().to_string(),
        "0-11"
    );
    assert!(EventSet::from_peer_fmtp(Some("x")).is_err());
}

#[test]
fn event_set_insert_remove_and_iterate() {
    let mut set = EventSet::empty();
    assert!(set.is_empty());
    set.insert(200);
    set.insert(0);
    set.insert(63);
    set.insert(64);
    assert_eq!(set.iter().collect::<Vec<_>>(), vec![0, 63, 64, 200]);
    set.remove(63);
    assert!(!set.contains(63));
    assert_eq!(set.len(), 3);
}

// ---- sender ------------------------------------------------------------------------------

fn sender() -> TelephoneEventSender {
    TelephoneEventSender::new(EventSet::dtmf())
}

#[test]
fn rfc4733_table5_second_digit_packet_sequence() {
    // Table 5, the second "1": starts at 11200, lasts 1760, 50 ms (400 unit) updates. Packets
    // 14 to 20: M on the first, timestamp 11200 throughout, durations 400..1600, then 1760
    // with E three times.
    let packets = telephone_event_packets(&EventSet::dtmf(), 1, 20, 11200, 1760, 400).unwrap();
    let expected: Vec<(bool, u32, u16, bool)> = vec![
        (true, 11200, 400, false),
        (false, 11200, 800, false),
        (false, 11200, 1200, false),
        (false, 11200, 1600, false),
        (false, 11200, 1760, true),
        (false, 11200, 1760, true),
        (false, 11200, 1760, true),
    ];
    let got: Vec<_> = packets
        .iter()
        .map(|p| (p.marker, p.timestamp, p.event.duration, p.event.end))
        .collect();
    assert_eq!(got, expected);
    // The last of them is Figure 3's payload.
    assert_eq!(
        packets[6].payload().unwrap().as_ref(),
        &[0x01, 0x94, 0x06, 0xE0]
    );
}

#[test]
fn first_packet_has_marker_and_later_ones_do_not() {
    let mut s = sender();
    s.start(DTMF_5, 10, 1000).unwrap();
    let first = s.update(160).unwrap();
    assert_eq!(first.len(), 1);
    assert!(first[0].marker);
    let second = s.update(320).unwrap();
    assert!(!second[0].marker);
    let end = s.end(400).unwrap();
    assert!(end.iter().all(|p| !p.marker));
}

#[test]
fn all_packets_keep_the_event_start_timestamp_and_cumulative_duration() {
    let mut s = sender();
    s.start(DTMF_STAR, 0, 0xFFFF_FF00).unwrap();
    let mut durations = vec![];
    for d in [400, 800, 1200] {
        let p = s.update(d).unwrap();
        assert_eq!(p[0].timestamp, 0xFFFF_FF00);
        assert!(!p[0].event.end);
        durations.push(p[0].event.duration);
    }
    assert_eq!(durations, vec![400, 800, 1200]);
}

#[test]
fn the_end_packet_is_sent_three_times_with_e_set() {
    let mut s = sender();
    s.start(DTMF_9, 10, 0).unwrap();
    s.update(400).unwrap();
    let end = s.end(1600).unwrap();
    assert_eq!(end.len(), 3);
    for p in &end {
        assert!(p.event.end);
        assert_eq!(p.timestamp, 0);
        assert_eq!(p.event, end[0].event);
        assert_eq!(p.payload().unwrap(), end[0].payload().unwrap());
    }
    assert_eq!(end[0].event.duration, 1600);
    assert!(!s.is_active());
}

#[test]
fn an_event_ended_before_any_update_marks_only_the_first_end_copy() {
    let mut s = sender();
    s.start(DTMF_0, 10, 77).unwrap();
    let end = s.end(240).unwrap();
    assert_eq!(
        end.iter().map(|p| p.marker).collect::<Vec<_>>(),
        vec![true, false, false]
    );
    assert!(end.iter().all(|p| p.event.end && p.event.duration == 240));
}

#[test]
fn a_zero_duration_is_never_sent_it_is_clamped_to_one() {
    let mut s = sender();
    s.start(DTMF_1, 0, 0).unwrap();
    let p = s.update(0).unwrap();
    assert_eq!(p[0].event.duration, 1);
    let end = s.end(0).unwrap();
    assert!(end.iter().all(|p| p.event.duration == 1));
    let packets = telephone_event_packets(&EventSet::dtmf(), 1, 0, 0, 0, 400).unwrap();
    assert!(packets.iter().all(|p| p.event.duration != 0));
}

#[test]
fn a_long_event_is_split_into_segments_of_0xffff() {
    let mut s = sender();
    s.start(DTMF_1, 10, 1000).unwrap();
    let p = s.update(60_000).unwrap();
    assert_eq!(p.len(), 1);
    assert!(p[0].marker);
    // Crossing 0xFFFF: the old segment closes at 0xFFFF without E, then the new segment
    // starts at 1000 + 0xFFFF without M, counting from the segment start.
    // The segment's final packet goes three times (section 2.5.1.4).
    let p = s.update(70_000).unwrap();
    assert_eq!(p.len(), 4);
    for boundary in &p[..3] {
        assert_eq!(
            (
                boundary.marker,
                boundary.timestamp,
                boundary.event.duration,
                boundary.event.end
            ),
            (false, 1000, 0xFFFF, false)
        );
    }
    assert_eq!(
        (
            p[3].marker,
            p[3].timestamp,
            p[3].event.duration,
            p[3].event.end
        ),
        (false, 1000 + 0xFFFF, (70_000 - 0xFFFF) as u16, false)
    );
    let end = s.end(70_400).unwrap();
    assert_eq!(end.len(), 3);
    for e in &end {
        assert_eq!(e.timestamp, 1000 + 0xFFFF);
        assert_eq!(e.event.duration, (70_400 - 0xFFFF) as u16);
        assert!(e.event.end && !e.marker);
    }
}

#[test]
fn only_the_very_last_packet_of_a_long_event_has_e_set() {
    // 2.5 segments at 8 kHz with 400-unit updates.
    let total = 0xFFFF * 2 + 5000;
    let packets = telephone_event_packets(&EventSet::dtmf(), 3, 5, 0, total, 400).unwrap();
    let (ends, rest): (Vec<&EventPacket>, Vec<&EventPacket>) =
        packets.iter().partition(|p| p.event.end);
    assert_eq!(ends.len(), 3);
    assert!(rest.iter().all(|p| !p.event.end));
    assert_eq!(packets.iter().filter(|p| p.marker).count(), 1);
    assert!(packets[0].marker);
    let boundaries: Vec<_> = rest
        .iter()
        .filter(|p| p.event.duration == 0xFFFF)
        .map(|p| p.timestamp)
        .collect();
    assert_eq!(boundaries, vec![0, 0, 0, 0xFFFF, 0xFFFF, 0xFFFF]);
    assert!(
        ends.iter()
            .all(|p| p.timestamp == 0xFFFF * 2 && p.event.duration == 5000)
    );
    // Timestamps never go back and each segment's durations grow.
    for pair in packets.windows(2) {
        if pair[0].timestamp == pair[1].timestamp {
            assert!(pair[0].event.duration <= pair[1].event.duration);
        } else {
            assert_eq!(pair[1].timestamp, pair[0].timestamp + 0xFFFF);
            assert_eq!(pair[0].event.duration, 0xFFFF);
        }
    }
}

#[test]
fn a_report_landing_exactly_on_0xffff_is_the_segments_final_packet_sent_three_times() {
    let mut s = sender();
    s.start(DTMF_1, 0, 0).unwrap();
    let p = s.update(0xFFFF).unwrap();
    assert_eq!(p.len(), 3, "the segment's final packet, three times");
    assert!(p.iter().all(|p| p.event.duration == 0xFFFF && !p.event.end));
    assert_eq!(p.iter().filter(|p| p.marker).count(), 1);
    let p = s.update(0xFFFF + 400).unwrap();
    assert_eq!(p.len(), 1);
    assert_eq!((p[0].timestamp, p[0].event.duration), (0xFFFF, 400));
}

#[test]
fn segment_timestamps_wrap_around_u32() {
    let start = u32::MAX - 10;
    let mut s = sender();
    s.start(DTMF_1, 0, start).unwrap();
    s.update(0xFFF0).unwrap();
    let p = s.update(0xFFFF + 1).unwrap();
    assert_eq!(p[3].timestamp, start.wrapping_add(0xFFFF));
}

#[test]
fn sender_refuses_events_outside_the_receivers_set() {
    let mut s = TelephoneEventSender::new(EventSet::parse("0-11").unwrap());
    assert!(s.start(DTMF_A, 0, 0).is_err());
    assert!(!s.is_active());
    s.start(DTMF_POUND, 0, 0).unwrap();
    let mut s = TelephoneEventSender::new(EventSet::default());
    assert!(s.start(16, 0, 0).is_err());
    assert!(telephone_event_packets(&EventSet::dtmf(), 32, 0, 0, 800, 400).is_err());
}

#[test]
fn sender_refuses_a_volume_above_63_and_accepts_zero() {
    let mut s = sender();
    assert!(s.start(DTMF_1, 64, 0).is_err());
    s.start(DTMF_1, 0, 0).unwrap();
    assert_eq!(s.update(10).unwrap()[0].event.volume, 0);
}

#[test]
fn sender_misuse_is_an_error() {
    let mut s = sender();
    assert!(s.update(10).is_err());
    assert!(s.end(10).is_err());
    s.start(DTMF_1, 0, 0).unwrap();
    assert!(s.start(DTMF_2, 0, 0).is_err());
    s.update(800).unwrap();
    // Durations are cumulative and never shrink.
    assert!(s.update(400).is_err());
    // A jump of more than one segment is refused, and the event survives a refused end.
    assert!(s.end(800 + 0x10000).is_err());
    assert!(s.is_active());
    s.reset();
    assert!(!s.is_active());
    s.start(DTMF_2, 0, 0).unwrap();
}

#[test]
fn packet_sequence_helper_rejects_bad_intervals() {
    assert!(telephone_event_packets(&EventSet::dtmf(), 1, 0, 0, 800, 0).is_err());
    assert!(telephone_event_packets(&EventSet::dtmf(), 1, 0, 0, 800, 0x10000).is_err());
}

#[test]
fn packet_sequence_helper_with_an_exact_multiple_ends_on_the_last_interval() {
    // Table 5's first "9": 1600 units, 400-unit interval. Updates 400, 800, 1200; the final
    // report (1600) three times. (Table 5 sends 1600 once without E first, the MAY of
    // 2.5.1.4; this sender sets E on the first transmission.)
    let packets = telephone_event_packets(&EventSet::dtmf(), 9, 0, 0, 1600, 400).unwrap();
    let durations: Vec<_> = packets
        .iter()
        .map(|p| (p.event.duration, p.event.end))
        .collect();
    assert_eq!(
        durations,
        vec![
            (400, false),
            (800, false),
            (1200, false),
            (1600, true),
            (1600, true),
            (1600, true)
        ]
    );
}

// ---- receiver ----------------------------------------------------------------------------

fn feed(r: &mut TelephoneEventReceiver, p: &EventPacket) -> Vec<TelephoneEventReport> {
    r.receive(p.timestamp, p.marker, &p.payload().unwrap())
        .unwrap()
}

fn packet(ts: u32, marker: bool, events: &[TelephoneEvent]) -> (u32, bool, Bytes) {
    (ts, marker, marshal_telephone_events(events).unwrap())
}

fn rx(r: &mut TelephoneEventReceiver, p: (u32, bool, Bytes)) -> Vec<TelephoneEventReport> {
    r.receive(p.0, p.1, &p.2).unwrap()
}

#[test]
fn receiver_follows_rfc4733_table5_and_reports_each_digit_once() {
    use TelephoneEventReport::*;
    // Table 5 as sent: "9" (ts 0), "1" (ts 7040), "1" (ts 11200).
    let rows: Vec<(bool, u32, u8, u16, bool)> = vec![
        (true, 0, 9, 400, false),
        (false, 0, 9, 800, false),
        (false, 0, 9, 1200, false),
        (false, 0, 9, 1600, false),
        (false, 0, 9, 1600, true),
        (false, 0, 9, 1600, true),
        (true, 7040, 1, 400, false),
        (false, 7040, 1, 800, false),
        (false, 7040, 1, 1200, false),
        (false, 7040, 1, 1600, false),
        (false, 7040, 1, 2000, false),
        (false, 7040, 1, 2000, true),
        (false, 7040, 1, 2000, true),
        (true, 11200, 1, 400, false),
        (false, 11200, 1, 800, false),
        (false, 11200, 1, 1200, false),
        (false, 11200, 1, 1600, false),
        (false, 11200, 1, 1760, true),
        (false, 11200, 1, 1760, true),
        (false, 11200, 1, 1760, true),
    ];
    let mut r = TelephoneEventReceiver::new();
    let mut all = vec![];
    for (m, ts, e, d, end) in rows {
        all.extend(rx(&mut r, packet(ts, m, &[ev(e, end, 20, d)])));
    }
    let started: Vec<_> = all
        .iter()
        .filter_map(|x| match x {
            Started {
                event, timestamp, ..
            } => Some((*event, *timestamp)),
            _ => None,
        })
        .collect();
    let ended: Vec<_> = all
        .iter()
        .filter_map(|x| match x {
            Ended {
                event,
                total_duration,
            } => Some((*event, *total_duration)),
            _ => None,
        })
        .collect();
    assert_eq!(started, vec![(9, 0), (1, 7040), (1, 11200)]);
    assert_eq!(ended, vec![(9, 1600), (1, 2000), (1, 1760)]);
}

#[test]
fn the_three_end_packets_produce_a_single_end_report() {
    use TelephoneEventReport::*;
    let packets = telephone_event_packets(&EventSet::dtmf(), 4, 10, 500, 800, 400).unwrap();
    let mut r = TelephoneEventReceiver::new();
    let reports: Vec<_> = packets.iter().flat_map(|p| feed(&mut r, p)).collect();
    assert_eq!(
        reports,
        vec![
            Started {
                event: 4,
                volume: 10,
                timestamp: 500
            },
            Updated {
                event: 4,
                duration: 400
            },
            Updated {
                event: 4,
                duration: 800
            },
            Ended {
                event: 4,
                total_duration: 800
            },
        ]
    );
    assert_eq!(r.current(), None);
}

#[test]
fn late_reports_for_an_ended_event_are_ignored() {
    let mut r = TelephoneEventReceiver::new();
    rx(&mut r, packet(100, true, &[ev(1, false, 0, 400)]));
    rx(&mut r, packet(100, false, &[ev(1, true, 0, 800)]));
    // A reordered interim report arriving after the end.
    assert!(rx(&mut r, packet(100, false, &[ev(1, false, 0, 400)])).is_empty());
    assert!(rx(&mut r, packet(100, true, &[ev(1, false, 0, 400)])).is_empty());
    assert_eq!(r.current(), None);
}

#[test]
fn a_lost_first_packet_still_starts_the_event() {
    use TelephoneEventReport::*;
    let mut r = TelephoneEventReceiver::new();
    let reports = rx(&mut r, packet(3000, false, &[ev(7, false, 15, 800)]));
    assert_eq!(
        reports,
        vec![
            Started {
                event: 7,
                volume: 15,
                timestamp: 3000
            },
            Updated {
                event: 7,
                duration: 800
            }
        ]
    );
    assert_eq!(r.current(), Some((7, 800)));
}

#[test]
fn a_lost_end_is_implied_by_the_next_event() {
    use TelephoneEventReport::*;
    let mut r = TelephoneEventReceiver::new();
    rx(&mut r, packet(0, true, &[ev(9, false, 0, 400)]));
    rx(&mut r, packet(0, false, &[ev(9, false, 0, 1200)]));
    let reports = rx(&mut r, packet(7040, true, &[ev(1, false, 0, 400)]));
    assert_eq!(
        reports[0],
        Ended {
            event: 9,
            total_duration: 1200
        }
    );
    assert!(matches!(
        reports[1],
        Started {
            event: 1,
            timestamp: 7040,
            ..
        }
    ));
    // And the same digit pressed again later, its end lost too.
    let reports = rx(&mut r, packet(20000, true, &[ev(1, false, 0, 400)]));
    assert_eq!(
        reports[0],
        Ended {
            event: 1,
            total_duration: 400
        }
    );
    assert!(matches!(
        reports[1],
        Started {
            event: 1,
            timestamp: 20000,
            ..
        }
    ));
}

#[test]
fn a_long_event_accumulates_duration_across_segments() {
    use TelephoneEventReport::*;
    let total = 0xFFFF * 2 + 5000;
    let packets = telephone_event_packets(&EventSet::dtmf(), 3, 5, 10, total, 400).unwrap();
    let mut r = TelephoneEventReceiver::new();
    let reports: Vec<_> = packets.iter().flat_map(|p| feed(&mut r, p)).collect();
    assert_eq!(
        reports
            .iter()
            .filter(|x| matches!(x, Started { .. }))
            .count(),
        1
    );
    assert_eq!(
        reports.last(),
        Some(&Ended {
            event: 3,
            total_duration: total
        })
    );
    // Updates are monotonic across segments.
    let mut last = 0;
    for x in &reports {
        if let Updated { duration, .. } = x {
            assert!(*duration > last);
            last = *duration;
        }
    }
}

#[test]
fn a_segment_continues_even_when_the_0xffff_report_is_lost() {
    use TelephoneEventReport::*;
    let mut r = TelephoneEventReceiver::new();
    rx(&mut r, packet(0, true, &[ev(1, false, 0, 65000)]));
    // The 0xFFFF report is lost; the next segment starts at 0xFFFF.
    let reports = rx(&mut r, packet(0xFFFF, false, &[ev(1, true, 0, 300)]));
    assert_eq!(
        reports,
        vec![
            Updated {
                event: 1,
                duration: 0xFFFF + 300
            },
            Ended {
                event: 1,
                total_duration: 0xFFFF + 300
            }
        ]
    );
}

#[test]
fn a_continuation_needs_the_same_event_code() {
    use TelephoneEventReport::*;
    let mut r = TelephoneEventReceiver::new();
    rx(&mut r, packet(0, true, &[ev(1, false, 0, 0xFFFF)]));
    let reports = rx(&mut r, packet(0xFFFF, false, &[ev(2, false, 0, 100)]));
    assert_eq!(
        reports[0],
        Ended {
            event: 1,
            total_duration: 0xFFFF
        }
    );
    assert!(matches!(reports[1], Started { event: 2, .. }));
}

#[test]
fn a_marked_report_at_the_continuation_point_is_a_new_event() {
    use TelephoneEventReport::*;
    let mut r = TelephoneEventReceiver::new();
    rx(&mut r, packet(0, true, &[ev(1, false, 0, 800)]));
    let reports = rx(&mut r, packet(800, true, &[ev(1, false, 0, 400)]));
    assert_eq!(
        reports[0],
        Ended {
            event: 1,
            total_duration: 800
        }
    );
    assert!(matches!(
        reports[1],
        Started {
            event: 1,
            timestamp: 800,
            ..
        }
    ));
}

#[test]
fn zero_duration_reports_are_ignored() {
    let mut r = TelephoneEventReceiver::new();
    assert!(rx(&mut r, packet(0, true, &[ev(1, false, 0, 0)])).is_empty());
    assert_eq!(r.current(), None);
    rx(&mut r, packet(0, true, &[ev(1, false, 0, 400)]));
    assert!(rx(&mut r, packet(0, false, &[ev(1, true, 0, 0)])).is_empty());
    assert_eq!(r.current(), Some((1, 400)));
}

#[test]
fn receiver_ignores_the_r_bit_in_packets() {
    let mut r = TelephoneEventReceiver::new();
    let reports = r
        .receive(0, true, &[0x05, 0x40 | 0x0A, 0x01, 0x90])
        .unwrap();
    assert_eq!(
        reports[0],
        TelephoneEventReport::Started {
            event: 5,
            volume: 10,
            timestamp: 0
        }
    );
    assert_eq!(r.current(), Some((5, 400)));
}

#[test]
fn several_events_in_one_packet_are_handled_in_order() {
    use TelephoneEventReport::*;
    let mut r = TelephoneEventReceiver::new();
    // "1" lasting 800 then "2" starting where "1" ended (2.5.2.4).
    let reports = rx(
        &mut r,
        packet(1000, true, &[ev(1, true, 0, 800), ev(2, false, 0, 400)]),
    );
    assert_eq!(
        reports,
        vec![
            Started {
                event: 1,
                volume: 0,
                timestamp: 1000
            },
            Updated {
                event: 1,
                duration: 800
            },
            Ended {
                event: 1,
                total_duration: 800
            },
            Started {
                event: 2,
                volume: 0,
                timestamp: 1800
            },
            Updated {
                event: 2,
                duration: 400
            },
        ]
    );
}

#[test]
fn a_packed_segment_end_and_next_segment_continue_one_event() {
    use TelephoneEventReport::*;
    let mut r = TelephoneEventReceiver::new();
    rx(&mut r, packet(0, true, &[ev(1, false, 0, 65000)]));
    let reports = rx(
        &mut r,
        packet(0, false, &[ev(1, false, 0, 0xFFFF), ev(1, false, 0, 200)]),
    );
    assert_eq!(
        reports,
        vec![
            Updated {
                event: 1,
                duration: 0xFFFF
            },
            Updated {
                event: 1,
                duration: 0xFFFF + 200
            }
        ]
    );
}

#[test]
fn a_reordered_shorter_report_does_not_shrink_the_duration() {
    let mut r = TelephoneEventReceiver::new();
    rx(&mut r, packet(0, true, &[ev(1, false, 0, 800)]));
    assert!(rx(&mut r, packet(0, false, &[ev(1, false, 0, 400)])).is_empty());
    assert_eq!(r.current(), Some((1, 800)));
}

#[test]
fn malformed_packets_are_errors_and_leave_state_alone() {
    let mut r = TelephoneEventReceiver::new();
    rx(&mut r, packet(0, true, &[ev(1, false, 0, 800)]));
    assert!(r.receive(0, false, &[]).is_err());
    assert!(r.receive(0, false, &[1, 2, 3]).is_err());
    assert!(r.receive(0, false, &[1, 0x80, 0, 1, 9]).is_err());
    assert_eq!(r.current(), Some((1, 800)));
}

#[test]
fn receiver_state_stays_bounded_over_many_events() {
    let mut r = TelephoneEventReceiver::new();
    for i in 0..10_000u32 {
        let ts = i.wrapping_mul(977);
        let out = r
            .receive(
                ts,
                i % 3 == 0,
                &[(i % 256) as u8, ((i % 2) << 7) as u8, 0, 1],
            )
            .unwrap();
        assert!(out.len() <= 4);
    }
}

/// RFC 4733 section 2.5.1.5: consecutive events packed into one packet. The RTP timestamp is
/// the beginning of the first event, M is set (the packet records the beginning of events), and
/// each event's E bit and duration are what it would have alone. A receiver recovers each
/// event's start from the first one's and the durations before it.
#[test]
fn consecutive_events_packed_into_one_packet_keep_each_events_own_report() {
    use TelephoneEventReport::*;
    let allowed = EventSet::dtmf();
    let packets =
        packed_telephone_event_packets(&allowed, &[(1, 10, 800), (2, 10, 400), (3, 12, 0)], 5000)
            .unwrap();
    assert_eq!(packets.len(), TELEPHONE_EVENT_END_REPEATS);
    assert!(
        packets.windows(2).all(|w| w[0] == w[1]),
        "sent three times, identical"
    );
    let packet = &packets[0];
    assert!(packet.marker);
    assert_eq!(packet.timestamp, 5000);
    assert_eq!(
        packet.events,
        vec![
            ev(1, true, 10, 800),
            ev(2, true, 10, 400),
            ev(3, true, 12, 1)
        ]
    );

    let mut receiver = TelephoneEventReceiver::new();
    let reports = receiver
        .receive(packet.timestamp, packet.marker, &packet.payload().unwrap())
        .unwrap();
    let started: Vec<(u8, u32)> = reports
        .iter()
        .filter_map(|report| match report {
            Started {
                event, timestamp, ..
            } => Some((*event, *timestamp)),
            _ => None,
        })
        .collect();
    assert_eq!(started, vec![(1, 5000), (2, 5800), (3, 6200)]);
    let ended: Vec<(u8, u32)> = reports
        .iter()
        .filter_map(|report| match report {
            Ended {
                event,
                total_duration,
            } => Some((*event, *total_duration)),
            _ => None,
        })
        .collect();
    assert_eq!(ended, vec![(1, 800), (2, 400), (3, 1)]);
    // The repeats change nothing.
    for repeat in &packets[1..] {
        let again = receiver
            .receive(repeat.timestamp, repeat.marker, &repeat.payload().unwrap())
            .unwrap();
        assert!(
            again.iter().all(|r| !matches!(r, Started { .. })),
            "{again:?}"
        );
    }
}

/// Packing keeps the sender's other rules: only events the receiver allows, nothing long
/// enough to need segments, and at least one event.
#[test]
fn packing_refuses_what_a_packet_cannot_carry() {
    let allowed = EventSet::dtmf();
    assert!(packed_telephone_event_packets(&allowed, &[], 0).is_err());
    assert!(packed_telephone_event_packets(&allowed, &[(16, 0, 100)], 0).is_err());
    assert!(packed_telephone_event_packets(&allowed, &[(1, 64, 100)], 0).is_err());
    assert!(packed_telephone_event_packets(&allowed, &[(1, 0, 0x1_0000)], 0).is_err());
}
