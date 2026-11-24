use super::*;

#[test]
fn test_opus_unmarshal() -> Result<()> {
    let mut pck = OpusPacket;

    // Empty packet
    let empty_bytes = Bytes::from_static(&[]);
    let result = pck.depacketize(&empty_bytes);
    assert!(result.is_err(), "Result should be err in case of error");

    // Normal packet
    let raw_bytes = Bytes::from_static(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x90]);
    let payload = pck.depacketize(&raw_bytes)?;
    assert_eq!(&raw_bytes, &payload, "Payload must be same");

    Ok(())
}

#[test]
fn test_opus_payload() -> Result<()> {
    let mut pck = OpusPayloader;
    let empty = Bytes::from_static(&[]);
    let payload = Bytes::from_static(&[0x90, 0x90, 0x90]);

    // Positive MTU, empty payload
    let result = pck.payload(1, &empty)?;
    assert!(result.is_empty(), "Generated payload should be empty");

    // Positive MTU, small payload
    let result = pck.payload(1, &payload)?;
    assert_eq!(result.len(), 1, "Generated payload should be the 1");

    // Positive MTU, small payload
    let result = pck.payload(2, &payload)?;
    assert_eq!(result.len(), 1, "Generated payload should be the 1");

    Ok(())
}

#[test]
fn test_opus_is_partition_head() -> Result<()> {
    let opus = OpusPacket;
    //"NormalPacket"
    assert!(
        opus.is_partition_head(&Bytes::from_static(&[0x00, 0x00])),
        "All OPUS RTP packet should be the head of a new partition"
    );

    Ok(())
}

#[test]
fn the_payloader_never_fragments_or_aggregates_whatever_the_mtu() -> Result<()> {
    // RFC 7587 4.2: one Opus packet per RTP payload, also when it is larger than the MTU.
    let mut payloader = OpusPayloader;
    let packet = Bytes::from(vec![0x78u8; 1500]);
    assert_eq!(vec![packet.clone()], payloader.payload(100, &packet)?);
    Ok(())
}

#[test]
fn the_packet_duration_is_read_from_the_toc() {
    // RFC 6716 3.1, Table 2: the configuration gives the frame size, the code the count.
    // config 0 (SILK NB 10 ms), code 0: one frame.
    assert_eq!(Some(480), opus_packet_samples(&[0x00, 1]));
    // config 3 (SILK NB 60 ms).
    assert_eq!(Some(2880), opus_packet_samples(&[3 << 3]));
    // config 13 (hybrid SWB 20 ms).
    assert_eq!(Some(960), opus_packet_samples(&[13 << 3]));
    // config 16 (CELT NB 2.5 ms): the shortest packet, and the DTX step.
    assert_eq!(
        Some(OPUS_DTX_TIMESTAMP_STEP),
        opus_packet_samples(&[16 << 3])
    );
    // config 31 (CELT FB 20 ms), code 1 and code 2: two frames.
    assert_eq!(Some(1920), opus_packet_samples(&[(31 << 3) | 1]));
    assert_eq!(Some(1920), opus_packet_samples(&[(31 << 3) | 2]));
    // code 3: the count is in the second byte's low six bits (VBR and padding flags above).
    assert_eq!(Some(2880), opus_packet_samples(&[(31 << 3) | 3, 0xC3]));
    // 120 ms is the longest packet: 6 x 20 ms is valid, 7 x 20 ms is not.
    assert_eq!(
        Some(OPUS_MAX_PACKET_SAMPLES),
        opus_packet_samples(&[(31 << 3) | 3, 6])
    );
    assert_eq!(None, opus_packet_samples(&[(31 << 3) | 3, 7]));
    // 2 x 60 ms is valid, 3 x 60 ms is not.
    assert_eq!(Some(5760), opus_packet_samples(&[(3 << 3) | 1]));
    assert_eq!(None, opus_packet_samples(&[(3 << 3) | 3, 3]));
}

#[test]
fn a_malformed_opus_packet_has_no_duration() {
    assert_eq!(None, opus_packet_samples(&[]));
    // code 3 without its frame count byte, and with a count of zero (RFC 6716 3.4, R5).
    assert_eq!(None, opus_packet_samples(&[0x03]));
    assert_eq!(None, opus_packet_samples(&[0x03, 0x00]));
}

#[test]
fn every_dtx_gap_the_toc_can_describe_is_a_multiple_of_the_step() {
    // RFC 7587 3.1.3: with whole frames dropped, timestamps differ by multiples of 120.
    for toc in 0..=255u8 {
        for count in 0..64u8 {
            if let Some(samples) = opus_packet_samples(&[toc, count]) {
                assert_eq!(0, samples % OPUS_DTX_TIMESTAMP_STEP);
            }
        }
    }
}
