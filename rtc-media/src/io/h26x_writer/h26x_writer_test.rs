use super::*;
use bytes::Bytes;
use rtp::Packet;
use rtp::codec::h265::HevcPayloader;
use rtp::packetizer::Payloader;

#[test]
fn test_h26x_writer_h264() {
    // TODO: Add tests for H26xWriter with H264
    // This would require:
    // 1. Sample H264 RTP packets
    // 2. Expected Annex B output
    // 3. Verification of correct depacketization
}

#[test]
fn test_h26x_writer_h265_single_nal_preserves_header() {
    let mut writer = H26xWriter::new(Vec::<u8>::new(), true);

    writer
        .write_rtp(&Packet {
            payload: vec![0x28, 0x01, 0xaa, 0xbb].into(),
            ..Default::default()
        })
        .expect("write single nal");

    assert_eq!(
        writer.writer,
        vec![0x00, 0x00, 0x00, 0x01, 0x28, 0x01, 0xaa, 0xbb],
        "writer should persist the original H265 single-NAL header and payload"
    );
}

#[test]
fn test_h26x_writer_h265_flushes_exact_full_tail_fragment() {
    let mut payloader = HevcPayloader::default();
    let nalu = Bytes::from_static(&[0x00, 0x00, 0x01, 0x02, 0x01, 1, 2, 3, 4, 5, 6]);
    let packets = payloader.payload(6, &nalu).expect("packetize H265 NAL");

    assert_eq!(packets.len(), 2, "expected two H265 FU packets");

    let mut writer = H26xWriter::new(Vec::<u8>::new(), true);

    writer
        .write_rtp(&Packet {
            payload: packets[0].clone(),
            ..Default::default()
        })
        .expect("write first fragment");
    assert!(
        writer.writer.is_empty(),
        "writer must not flush before the final HEVC fragment"
    );

    writer
        .write_rtp(&Packet {
            payload: packets[1].clone(),
            ..Default::default()
        })
        .expect("write last fragment");

    assert_eq!(
        writer.writer,
        vec![0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 1, 2, 3, 4, 5, 6],
        "writer should reconstruct the complete Annex-B HEVC NAL"
    );
}

#[test]
fn test_h26x_writer_h265_fragmentation_preserves_layer_and_tid_bits() {
    // LayerId 5, TID 3 in the payload header; FuType 20 (IDR_N_LP).
    let mut writer = H26xWriter::new(Vec::<u8>::new(), true);
    for payload in [
        &[0x62u8, 0x2B, 0x80 | 20, 0xAA][..],
        &[0x62, 0x2B, 0x40 | 20, 0xBB],
    ] {
        writer
            .write_rtp(&Packet {
                payload: Bytes::copy_from_slice(payload),
                ..Default::default()
            })
            .unwrap();
    }
    // (20 << 9) | (5 << 3) | 3 = 0x282B.
    assert_eq!(vec![0, 0, 0, 1, 0x28, 0x2B, 0xAA, 0xBB], writer.writer);
}

/// An H.265 FU NAL unit is bounded at `MAX_H265_FU_NALU_SIZE`: one whose end fragment never
/// comes used to grow the buffer without limit. A fragment with no start before it is skipped.
#[test]
fn test_h26x_writer_h265_fragment_buffer_is_bounded() {
    let mut writer = H26xWriter::new(Vec::<u8>::new(), true);
    let fragment = |fu_header: u8| {
        let mut payload = vec![0x62, 0x01, fu_header]; // PayloadHdr type 49 (FU), FU header
        payload.extend_from_slice(&[0xab; 1200]);
        Packet {
            payload: Bytes::from(payload),
            ..Default::default()
        }
    };

    // A middle fragment with no start is not buffered.
    writer.write_rtp(&fragment(0x01)).unwrap();

    writer.write_rtp(&fragment(0x81)).unwrap(); // S=1, type 1
    let mut refused = false;
    for _ in 0..(MAX_H265_FU_NALU_SIZE / 1200 + 2) {
        if writer.write_rtp(&fragment(0x01)).is_err() {
            refused = true;
            break;
        }
    }
    assert!(refused, "the NAL unit grew past MAX_H265_FU_NALU_SIZE");
    // The partial NAL unit is dropped: its end fragment completes nothing.
    writer.write_rtp(&fragment(0x41)).unwrap();
    assert!(writer.writer.is_empty());
}
