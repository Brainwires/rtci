//! RFC 7741 sections 3, 4.2 and 4.4: each partition of a VP8 frame starts a packet of its own,
//! labelled with its `PID` and with `S` on its first packet. The partitions are found as RFC
//! 6386 section 9 lays a frame out; frames built here with the RFC 6386 section 7.3 boolean
//! encoder, and two frames of a libvpx stream (`examples/test-data/output_vp8.ivf`, frames 0
//! and 1).

use super::partitions::vp8_partitions;
use super::*;

const LIBVPX_KEY_FRAME: &[u8] = include_bytes!("testdata/libvpx_key_frame_qcif.vp8");
const LIBVPX_INTER_FRAME: &[u8] = include_bytes!("testdata/libvpx_inter_frame_qcif.vp8");

/// The boolean encoder of RFC 6386 section 7.3, for literals (probability 128).
struct BoolEncoder {
    output: Vec<u8>,
    range: u32,
    bottom: u32,
    bit_count: i32,
}

impl BoolEncoder {
    fn new() -> Self {
        BoolEncoder {
            output: vec![],
            range: 255,
            bottom: 0,
            bit_count: 24,
        }
    }

    fn add_one_to_output(&mut self) {
        let mut i = self.output.len();
        while i > 0 && self.output[i - 1] == 255 {
            self.output[i - 1] = 0;
            i -= 1;
        }
        self.output[i - 1] += 1;
    }

    fn write_bool(&mut self, value: bool) {
        let split = 1 + (((self.range - 1) * 128) >> 8);
        if value {
            self.bottom = self.bottom.wrapping_add(split);
            self.range -= split;
        } else {
            self.range = split;
        }
        while self.range < 128 {
            self.range <<= 1;
            if self.bottom & (1 << 31) != 0 {
                self.add_one_to_output();
            }
            self.bottom <<= 1;
            self.bit_count -= 1;
            if self.bit_count == 0 {
                self.output.push((self.bottom >> 24) as u8);
                self.bottom &= (1 << 24) - 1;
                self.bit_count = 8;
            }
        }
    }

    fn literal(&mut self, value: u32, bits: u32) {
        for bit in (0..bits).rev() {
            self.write_bool(value >> bit & 1 != 0);
        }
    }

    fn flush(mut self) -> Vec<u8> {
        let mut c = self.bit_count;
        let mut v = self.bottom;
        if v & (1 << (32 - c)) != 0 {
            self.add_one_to_output();
        }
        v <<= c & 7;
        c >>= 3;
        for _ in 0..c {
            v <<= 8;
        }
        for _ in 0..4 {
            self.output.push((v >> 24) as u8);
            v <<= 8;
        }
        self.output
    }
}

/// An interframe (frame tag of 3 octets) with segmentation and loop filter deltas in its header
/// (so every optional field before the partition count is read), `1 << log2_partitions` token
/// partitions of `token_sizes` octets, and the first partition padded to `first_size` octets.
fn inter_frame(log2_partitions: u32, first_size: usize, token_sizes: &[usize]) -> Vec<u8> {
    let mut e = BoolEncoder::new();
    e.write_bool(true); // segmentation_enabled
    e.write_bool(true); // update_mb_segmentation_map
    e.write_bool(true); // update_segment_feature_data
    e.literal(1, 1); // segment_feature_mode
    for i in 0..4 {
        e.write_bool(i % 2 == 0); // quantizer_update
        if i % 2 == 0 {
            e.literal(0x55, 7);
            e.literal(1, 1);
        }
    }
    for i in 0..4 {
        e.write_bool(i % 2 == 1); // loop_filter_update
        if i % 2 == 1 {
            e.literal(0x2A, 6);
            e.literal(0, 1);
        }
    }
    for i in 0..3 {
        e.write_bool(i == 1); // segment_prob_update
        if i == 1 {
            e.literal(0xC3, 8);
        }
    }
    e.literal(1, 1); // filter_type
    e.literal(0x3F, 6); // loop_filter_level
    e.literal(5, 3); // sharpness_level
    e.write_bool(true); // loop_filter_adj_enable
    e.write_bool(true); // mode_ref_lf_delta_update
    for i in 0..8 {
        e.write_bool(i % 3 == 0);
        if i % 3 == 0 {
            e.literal(0x3F, 6);
            e.literal(1, 1);
        }
    }
    e.literal(log2_partitions, 2); // log2_nbr_of_dct_partitions
    e.literal(0x2B, 7); // what the header goes on with (quantizer indices)
    let mut first = e.flush();
    assert!(
        first.len() <= first_size,
        "{} octets of header",
        first.len()
    );
    first.resize(first_size, 0xA5);

    // Frame tag: interframe (bit 0 set), version 0, shown, first partition size.
    let tag = 1 | (1 << 4) | ((first_size as u32) << 5);
    let mut frame = vec![tag as u8, (tag >> 8) as u8, (tag >> 16) as u8];
    frame.extend_from_slice(&first);
    let count = 1usize << log2_partitions;
    assert_eq!(count, token_sizes.len());
    for size in &token_sizes[..count - 1] {
        frame.extend_from_slice(&[*size as u8, (*size >> 8) as u8, (*size >> 16) as u8]);
    }
    for (i, size) in token_sizes.iter().enumerate() {
        frame.extend(std::iter::repeat_n(0x10 + i as u8, *size));
    }
    frame
}

/// `(S, PID, payload length)` of each packet, and the frame put back together.
fn descriptors(packets: &[Bytes], descriptor_len: usize) -> (Vec<(bool, u8, usize)>, Vec<u8>) {
    let mut frame = vec![];
    let fields = packets
        .iter()
        .map(|p| {
            frame.extend_from_slice(&p[descriptor_len..]);
            (p[0] & 0x10 != 0, p[0] & 0x07, p.len() - descriptor_len)
        })
        .collect();
    (fields, frame)
}

#[test]
fn the_partitions_of_libvpx_frames_are_found() {
    // A key frame: 10 octets of frame tag, start code and size, a first partition of 787
    // octets, one token partition (no size table).
    assert_eq!(
        Some(vec![0..797, 797..8748]),
        vp8_partitions(LIBVPX_KEY_FRAME)
    );
    // An interframe: 3 octets of frame tag, a first partition of 152 octets.
    assert_eq!(
        Some(vec![0..155, 155..331]),
        vp8_partitions(LIBVPX_INTER_FRAME)
    );
}

#[test]
fn the_partition_count_and_sizes_are_read_from_the_frame() {
    let frame = inter_frame(2, 40, &[5, 0, 7, 4]);
    // Partition 0 is the frame tag, the first partition and the three sizes.
    let p0 = 3 + 40 + 9;
    assert_eq!(
        Some(vec![
            0..p0,
            p0..p0 + 5,
            p0 + 5..p0 + 5,
            p0 + 5..p0 + 12,
            p0 + 12..p0 + 16
        ]),
        vp8_partitions(&frame)
    );
    assert_eq!(
        Some(2),
        vp8_partitions(&inter_frame(0, 30, &[9])).map(|p| p.len())
    );
    assert_eq!(
        Some(3),
        vp8_partitions(&inter_frame(1, 30, &[9, 3])).map(|p| p.len())
    );
    assert_eq!(
        Some(9),
        vp8_partitions(&inter_frame(3, 30, &[1, 2, 3, 4, 5, 6, 7, 8])).map(|p| p.len())
    );
}

/// RFC 7741 section 3 recommends "each data partition in a separate packet or packets";
/// section 4.2: S "SHOULD be set to 1 when the first payload octet of the RTP packet is the
/// beginning of a new VP8 partition" and PID "SHOULD be incremented by 1 for each subsequent
/// partition"; section 4.4: with partitions respected, S and PID "SHOULD be used".
#[test]
fn each_partition_starts_a_packet_with_its_pid_and_s() -> Result<()> {
    let frame = inter_frame(2, 40, &[5, 0, 7, 30]);
    let mut payloader = Vp8Payloader::default();
    // One descriptor octet, 21 octets of frame per packet.
    let packets = payloader.payload(22, &Bytes::from(frame.clone()))?;
    let (fields, rebuilt) = descriptors(&packets, 1);
    assert_eq!(frame, rebuilt, "the frame is sent whole and in order");
    assert_eq!(
        vec![
            // Partition 0 (52 octets) over three packets: S on the first only.
            (true, 0, 21),
            (false, 0, 21),
            (false, 0, 10),
            // Token partition 1.
            (true, 1, 5),
            // Token partition 2 is empty: no packet. Token partition 3.
            (true, 3, 7),
            // Token partition 4 over two packets.
            (true, 4, 21),
            (false, 4, 9),
        ],
        fields
    );
    // A receiver takes the frame's first packet, and only it, as the start of a frame.
    let depacketizer = Vp8Packet::default();
    let heads: Vec<bool> = packets
        .iter()
        .map(|p| depacketizer.is_partition_head(p))
        .collect();
    assert_eq!(vec![true, false, false, false, false, false, false], heads);
    Ok(())
}

/// RFC 7741 section 4.2: "PID cannot be larger than 7. If more than one packet in an encoded
/// frame contains the same PID, the S bit MUST NOT be set for any packet other than the first
/// packet with that PID": the ninth partition of a frame with eight token partitions goes on
/// in the eighth's packets.
#[test]
fn the_ninth_partition_continues_the_pid_7_packets() -> Result<()> {
    let frame = inter_frame(3, 30, &[2, 2, 2, 2, 2, 2, 3, 4]);
    let packets = Vp8Payloader::default().payload(1200, &Bytes::from(frame.clone()))?;
    let (fields, rebuilt) = descriptors(&packets, 1);
    assert_eq!(frame, rebuilt);
    assert_eq!(
        vec![
            (true, 0, 3 + 30 + 21),
            (true, 1, 2),
            (true, 2, 2),
            (true, 3, 2),
            (true, 4, 2),
            (true, 5, 2),
            (true, 6, 2),
            (true, 7, 3 + 4),
        ],
        fields
    );
    Ok(())
}

/// A libvpx interframe goes out as its two partitions, each with its PID, the descriptor
/// fields the peer connection's payloader writes (PictureID) on both.
#[test]
fn a_libvpx_frame_is_sent_partition_by_partition() -> Result<()> {
    let mut payloader = Vp8Payloader {
        enable_picture_id: true,
        ..Default::default()
    };
    let packets = payloader.payload(1200, &Bytes::from_static(LIBVPX_INTER_FRAME))?;
    let (fields, rebuilt) = descriptors(&packets, 3);
    assert_eq!(LIBVPX_INTER_FRAME, &rebuilt[..]);
    assert_eq!(vec![(true, 0, 155), (true, 1, 176)], fields);
    assert!(packets.iter().all(|p| p[0] & 0x80 != 0 && p[2] == 0));
    Ok(())
}

/// RFC 7741 section 4.4: "It is OPTIONAL for a packetizer ... to pay attention to the
/// partition boundaries": with `ignore_partitions` the frame is cut at MTU boundaries, PID 0
/// and S on the first packet only (libwebrtc's packetizer), and "Two fragments from different
/// partitions MAY be aggregated into the same packet": the second packet ends partition 0 and
/// starts partition 1.
#[test]
fn ignore_partitions_cuts_the_frame_at_mtu_boundaries() -> Result<()> {
    let mut payloader = Vp8Payloader {
        ignore_partitions: true,
        ..Default::default()
    };
    let packets = payloader.payload(101, &Bytes::from_static(LIBVPX_INTER_FRAME))?;
    let (fields, rebuilt) = descriptors(&packets, 1);
    assert_eq!(LIBVPX_INTER_FRAME, &rebuilt[..]);
    assert_eq!(
        vec![
            (true, 0, 100),
            (false, 0, 100),
            (false, 0, 100),
            (false, 0, 31)
        ],
        fields
    );
    // Partition 0 is octets 0 to 154: the second packet holds octets 100 to 199.
    assert_eq!(&LIBVPX_INTER_FRAME[100..200], &packets[1][1..]);
    assert_eq!(
        Some(vec![0..155, 155..331]),
        vp8_partitions(LIBVPX_INTER_FRAME)
    );
    Ok(())
}

/// What the payloader is given need not be a VP8 frame whose sizes add up (a truncated or
/// damaged frame, another codec's bytes): it is then cut without regard to partitions, never
/// read past its end, and sent whole. Every prefix of a key frame, every octet of a frame's
/// header and size table changed, and partition sizes that overrun the frame.
#[test]
fn a_frame_whose_partitions_cannot_be_read_is_sent_whole() -> Result<()> {
    let check = |frame: &[u8]| -> Result<()> {
        let packets = Vp8Payloader::default().payload(100, &Bytes::copy_from_slice(frame))?;
        let (fields, rebuilt) = descriptors(&packets, 1);
        assert_eq!(frame, &rebuilt[..]);
        assert!(fields.first().is_none_or(|f| f.0 && f.1 == 0));
        for pair in fields.windows(2) {
            // S only where the PID changes, PIDs ascending, never above 7.
            assert_eq!(pair[1].0, pair[1].1 != pair[0].1, "{fields:?}");
            assert!(pair[1].1 >= pair[0].1 && pair[1].1 <= 7);
        }
        if let Some(parts) = vp8_partitions(frame) {
            assert_eq!(0, parts[0].start);
            assert_eq!(frame.len(), parts.last().map_or(0, |p| p.end));
            assert!(parts.windows(2).all(|w| w[0].end == w[1].start));
        }
        Ok(())
    };
    for len in 0..=LIBVPX_KEY_FRAME.len().min(1200) {
        check(&LIBVPX_KEY_FRAME[..len])?;
    }
    let frame = inter_frame(3, 30, &[2, 2, 2, 2, 2, 2, 3, 4]);
    for i in 0..3 + 30 + 21 {
        for value in [0x00, 0x7F, 0xFF] {
            let mut damaged = frame.clone();
            damaged[i] = value;
            check(&damaged)?;
        }
    }
    // The size table claims more than the frame holds.
    let mut overrun = inter_frame(1, 30, &[9, 3]);
    overrun[3 + 30] = 0xFF;
    assert_eq!(None, vp8_partitions(&overrun));
    check(&overrun)?;
    Ok(())
}
