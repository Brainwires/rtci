//! RFC 4733 section 4: the tone payload and its sending procedure.

use super::*;

/// RFC 4733 section 4.3.3: the layout of Figure 2; the reserved bits are sent as zero and
/// ignored on reception.
#[test]
fn a_tone_round_trips_with_zero_reserved_bits_and_ignores_them_on_reading() {
    let tone = Tone {
        modulation: 0x0155,
        modulation_divided_by_three: true,
        volume: 10,
        duration: 160,
        frequencies: vec![350, 440],
    };
    let payload = tone.marshal().unwrap();
    assert_eq!(
        &[0xAA, 0xCA, 0x00, 0xA0, 0x01, 0x5E, 0x01, 0xB8],
        &payload[..]
    );
    assert_eq!(Some(tone.clone()), Tone::unmarshal(&payload));
    // A sender that set the reserved bits: they are ignored.
    let mut lax = payload.to_vec();
    lax[4] |= 0xF0;
    lax[6] |= 0xA0;
    assert_eq!(Some(tone), Tone::unmarshal(&lax));
}

/// RFC 4733 section 4.3.3: "The value of zero is not permitted, and tones with such a
/// duration SHOULD be ignored."
#[test]
fn a_tone_of_duration_zero_is_neither_sent_nor_taken() {
    assert!(Tone::default().marshal().is_err());
    assert_eq!(None, Tone::unmarshal(&[0x00, 0x0A, 0x00, 0x00, 0x01, 0x5E]));
    assert!(
        Tone {
            volume: 64,
            duration: 1,
            ..Default::default()
        }
        .marshal()
        .is_err()
    );
}

/// RFC 4733 section 4.4.1: each further packet of a tone has the timestamp of the one before
/// plus its duration; the marker is on the first (section 4.3.2).
#[test]
fn the_packets_of_a_long_tone_follow_on_from_each_other() {
    let tone = Tone {
        volume: 8,
        duration: 1,
        frequencies: vec![425],
        ..Default::default()
    };
    let packets = ToneSender {
        packet_duration: 160,
    }
    .packets(&tone, 4_294_967_000, 400)
    .unwrap();
    assert_eq!(3, packets.len());
    let mut expected = 4_294_967_000u32;
    for (i, packet) in packets.iter().enumerate() {
        assert_eq!(expected, packet.timestamp, "packet {i}");
        assert_eq!(i == 0, packet.marker);
        let report = Tone::unmarshal(&packet.payload).unwrap();
        assert_eq!(vec![425], report.frequencies);
        expected = expected.wrapping_add(u32::from(report.duration));
    }
    assert_eq!(
        vec![160, 160, 80],
        packets
            .iter()
            .map(|p| Tone::unmarshal(&p.payload).unwrap().duration)
            .collect::<Vec<_>>()
    );
}
