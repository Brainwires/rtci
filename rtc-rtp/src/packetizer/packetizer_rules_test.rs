//! The packetizer's marker bit, timestamps and MTU: RFC 3551 4.1 and 4.3, RFC 7587 4.1,
//! RFC 6184 5.1, RFC 3550 5.1.

use super::*;
use crate::codec::{
    comfort_noise::ComfortNoisePayloader, g7xx::G711Payloader, h264::H264Payloader,
    h265::HevcPayloader, opus::OpusPayloader,
};

const SSRC: u32 = 0x1234_ABCD;

fn packetizer(mtu: usize, payloader: Box<dyn Payloader>, clock_rate: u32) -> impl Packetizer {
    new_packetizer(
        Instant::now(),
        mtu,
        96,
        SSRC,
        payloader,
        Box::new(new_fixed_sequencer(1000)),
        clock_rate,
    )
}

#[test]
fn an_mtu_that_leaves_no_room_for_a_payload_is_an_error_not_a_panic() {
    // The audit's reproduction (B6): `mtu - 12` on a usize.
    let now = Instant::now();
    for mtu in [0usize, 1, 8, 11, 12] {
        let mut packetizer = packetizer(mtu, Box::new(G711Payloader::default()), 8000);
        assert!(
            packetizer
                .packetize(now, &Bytes::from_static(&[0u8; 160]), 160)
                .is_err(),
            "mtu {mtu}"
        );
    }
    // One byte of room is enough to send.
    let mut packetizer = packetizer(13, Box::new(G711Payloader::default()), 8000);
    let packets = packetizer
        .packetize(now, &Bytes::from_static(&[0u8; 3]), 3)
        .unwrap();
    assert_eq!(3, packets.len());
}

#[test]
fn audio_packets_carry_no_marker_without_silence_suppression() -> Result<()> {
    // The audit's reproduction (RFC 3551 B2, RFC 7587 bug 1): three packets, M three times.
    let now = Instant::now();
    let mut pcmu = packetizer(1200, Box::new(G711Payloader::default()), 8000);
    let mut opus = packetizer(1200, Box::new(OpusPayloader), 48000);
    for _ in 0..3 {
        for packet in pcmu.packetize(now, &Bytes::from_static(&[0u8; 160]), 160)? {
            assert!(!packet.header.marker);
        }
        for packet in opus.packetize(now, &Bytes::from_static(&[0x78, 1, 2, 3]), 960)? {
            assert!(!packet.header.marker);
        }
    }
    Ok(())
}

#[test]
fn the_first_audio_packet_after_a_skipped_silence_starts_a_talkspurt() -> Result<()> {
    let now = Instant::now();
    let mut opus = packetizer(1200, Box::new(OpusPayloader), 48000);
    let frame = Bytes::from_static(&[0x78, 1, 2, 3]);

    let before = opus.packetize(now, &frame, 960)?;
    assert!(!before[0].header.marker);
    // DTX: 400 ms without packets (RFC 7587 3.1.3: a multiple of 2.5 ms).
    opus.skip_samples(19_200);
    let first = opus.packetize(now, &frame, 960)?;
    let second = opus.packetize(now, &frame, 960)?;

    assert!(first[0].header.marker, "first packet of the talkspurt");
    assert!(!second[0].header.marker, "and only that one");
    // The gap is in the timestamps, not in the sequence numbers.
    assert_eq!(
        before[0].header.timestamp.wrapping_add(960 + 19_200),
        first[0].header.timestamp
    );
    assert_eq!(
        before[0].header.sequence_number.wrapping_add(1),
        first[0].header.sequence_number
    );
    Ok(())
}

#[test]
fn a_talkspurt_marker_is_on_the_first_fragment_of_a_split_buffer_only() -> Result<()> {
    let now = Instant::now();
    let mut pcmu = packetizer(12 + 100, Box::new(G711Payloader::default()), 8000);
    pcmu.skip_samples(800);
    let packets = pcmu.packetize(now, &Bytes::from(vec![0u8; 250]), 250)?;
    let markers: Vec<bool> = packets.iter().map(|p| p.header.marker).collect();
    assert_eq!(vec![true, false, false], markers);
    Ok(())
}

#[test]
fn fragments_of_a_sample_based_buffer_each_carry_their_first_samples_timestamp() -> Result<()> {
    // The audit's reproduction (RFC 3551 B1): 160 octets of PCMU at an MTU of 100 are two
    // packets of 88 and 72 octets; the second is 88 ticks later.
    let now = Instant::now();
    let mut pcmu = packetizer(100, Box::new(G711Payloader::default()), 8000);
    let packets = pcmu.packetize(now, &Bytes::from(vec![0u8; 160]), 160)?;
    assert_eq!(
        vec![88, 72],
        packets.iter().map(|p| p.payload.len()).collect::<Vec<_>>()
    );
    let start = packets[0].header.timestamp;
    assert_eq!(start.wrapping_add(88), packets[1].header.timestamp);

    // The next buffer starts where the caller's sample count says, as before.
    let next = pcmu.packetize(now, &Bytes::from(vec![0u8; 160]), 160)?;
    assert_eq!(start.wrapping_add(160), next[0].header.timestamp);

    // A 4000-octet buffer at an MTU of 1200: t, t+1188, t+2376, t+3564.
    let mut pcmu = packetizer(1200, Box::new(G711Payloader::default()), 8000);
    let packets = pcmu.packetize(now, &Bytes::from(vec![0u8; 4000]), 4000)?;
    let start = packets[0].header.timestamp;
    assert_eq!(
        vec![0u32, 1188, 2376, 3564],
        packets
            .iter()
            .map(|p| p.header.timestamp.wrapping_sub(start))
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn a_video_frame_has_one_timestamp_and_the_marker_on_its_last_packet() -> Result<()> {
    // RFC 6184 5.1: the marker is on the last packet of the access unit, and every packet of
    // the access unit carries its timestamp.
    let now = Instant::now();
    let mut h264 = packetizer(12 + 50, Box::new(H264Payloader::default()), 90000);
    let mut access_unit = vec![0, 0, 0, 1, 0x65];
    access_unit.extend_from_slice(&[0xAB; 180]);
    let packets = h264.packetize(now, &Bytes::from(access_unit), 3000)?;
    assert!(packets.len() > 2, "fragmented");
    let last = packets.len() - 1;
    for (i, packet) in packets.iter().enumerate() {
        assert_eq!(i == last, packet.header.marker, "packet {i}");
        assert_eq!(packets[0].header.timestamp, packet.header.timestamp);
        assert_eq!(
            packets[0].header.sequence_number.wrapping_add(i as u16),
            packet.header.sequence_number,
            "fragments are consecutive"
        );
    }
    let next = h264.packetize(now, &Bytes::from_static(&[0, 0, 0, 1, 0x41, 1, 2]), 3000)?;
    assert_eq!(
        packets[0].header.timestamp.wrapping_add(3000),
        next[0].header.timestamp
    );
    assert!(next[0].header.marker);
    Ok(())
}

/// RFC 6184 section 5.1: an aggregation packet's marker "MUST be set to the value that the
/// marker bit of the last NAL unit of the aggregation packet would have if it were
/// transported in an individual RTP packet". The SPS and PPS of an access unit go in a
/// STAP-A ahead of its IDR: they are not last, so the STAP-A has no marker and the IDR has it.
#[test]
fn a_stap_a_carries_the_marker_its_last_nal_unit_would_have_alone() -> Result<()> {
    let now = Instant::now();
    let mut h264 = packetizer(1200, Box::new(H264Payloader::default()), 90000);
    let access_unit = Bytes::from_static(&[
        0, 0, 0, 1, 0x67, 0x42, 0xC0, 0x1F, // SPS
        0, 0, 0, 1, 0x68, 0xCE, 0x3C, 0x80, // PPS
        0, 0, 0, 1, 0x65, 0x88, 0x84, 0x00, // IDR
    ]);
    let packets = h264.packetize(now, &access_unit, 3000)?;
    assert_eq!(2, packets.len());
    assert_eq!(24, packets[0].payload[0] & 0x1F, "a STAP-A first");
    assert!(!packets[0].header.marker);
    assert_eq!(5, packets[1].payload[0] & 0x1F);
    assert!(packets[1].header.marker);
    Ok(())
}

/// RFC 7798 sections 4.1 and 4.4.3: the marker is on the last packet of the access unit,
/// every packet of it has the access unit's timestamp, and the fragments of a NAL unit go
/// out consecutively in ascending sequence-number order.
#[test]
fn an_h265_access_unit_has_one_timestamp_consecutive_fragments_and_the_marker_last() -> Result<()> {
    let now = Instant::now();
    let mut h265 = packetizer(12 + 60, Box::new(HevcPayloader::default()), 90000);
    let mut access_unit = vec![0, 0, 0, 1, 0x26, 0x01];
    access_unit.extend_from_slice(&[0xAB; 200]);
    let packets = h265.packetize(now, &Bytes::from(access_unit), 3000)?;
    assert!(packets.len() > 2, "fragmented");
    let last = packets.len() - 1;
    for (i, packet) in packets.iter().enumerate() {
        assert_eq!(49, (packet.payload[0] >> 1) & 0x3F, "a fragmentation unit");
        assert_eq!(i == last, packet.header.marker, "packet {i}");
        assert_eq!(packets[0].header.timestamp, packet.header.timestamp);
        assert_eq!(
            packets[0].header.sequence_number.wrapping_add(i as u16),
            packet.header.sequence_number
        );
    }
    Ok(())
}

#[test]
fn packets_are_version_2_with_the_streams_ssrc_and_payload_type() -> Result<()> {
    let now = Instant::now();
    let mut opus = packetizer(1200, Box::new(OpusPayloader), 48000);
    let packet = opus
        .packetize(now, &Bytes::from_static(&[0x78, 1]), 960)?
        .remove(0);
    assert_eq!(2, packet.header.version);
    assert_eq!(SSRC, packet.header.ssrc);
    assert_eq!(96, packet.header.payload_type);
    assert_eq!(1000, packet.header.sequence_number);
    let raw = packet.marshal()?;
    assert_eq!(0x80, raw[0]);
    Ok(())
}

#[test]
fn a_comfort_noise_packet_never_carries_the_marker() -> Result<()> {
    // RFC 3389 4: also right after a silence was skipped.
    let now = Instant::now();
    let mut cn = packetizer(1200, Box::new(ComfortNoisePayloader), 8000);
    cn.skip_samples(800);
    for _ in 0..2 {
        let packets = cn.packetize(now, &Bytes::from_static(&[40, 127, 127]), 160)?;
        assert_eq!(1, packets.len());
        assert!(!packets[0].header.marker);
    }
    Ok(())
}
