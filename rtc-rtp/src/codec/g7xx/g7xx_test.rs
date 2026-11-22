use super::*;

#[test]
fn test_g7xx_payload() -> Result<()> {
    let mut pck = G711Payloader::default();

    const TEST_LEN: usize = 10000;
    const TEST_MTU: usize = 1500;

    //generate random 8-bit g722 samples
    let samples: Vec<u8> = (0..TEST_LEN).map(|_| rand::random::<u8>()).collect();

    //make a copy, for payloader input
    let mut samples_in = vec![0u8; TEST_LEN];
    samples_in.clone_from_slice(&samples);
    let samples_in = Bytes::copy_from_slice(&samples_in);

    //split our samples into payloads
    let payloads = pck.payload(TEST_MTU, &samples_in)?;

    let outcnt = ((TEST_LEN as f64) / (TEST_MTU as f64)).ceil() as usize;
    assert_eq!(
        outcnt,
        payloads.len(),
        "Generated {} payloads instead of {}",
        payloads.len(),
        outcnt
    );
    assert_eq!(&samples, &samples_in, "Modified input samples");

    let samples_out = payloads.concat();
    assert_eq!(&samples_out, &samples_in, "Output samples don't match");

    let empty = Bytes::from_static(&[]);
    let payload = Bytes::from_static(&[0x90, 0x90, 0x90]);

    // Positive MTU, empty payload
    let result = pck.payload(1, &empty)?;
    assert!(result.is_empty(), "Generated payload should be empty");

    // 0 MTU, small payload
    let result = pck.payload(0, &payload)?;
    assert_eq!(result.len(), 0, "Generated payload should be empty");

    // Positive MTU, small payload
    let result = pck.payload(10, &payload)?;
    assert_eq!(result.len(), 1, "Generated payload should be the 1");

    Ok(())
}

#[test]
fn a_sample_based_payload_is_cut_at_any_octet_and_each_octet_is_one_tick() -> Result<()> {
    // RFC 3551 4.3: any number of samples per packet; the duration follows from the octets.
    let mut payloader = G7xxPayloader;
    let buffer = Bytes::from((0..=249u8).collect::<Vec<u8>>());
    let payloads = payloader.payload(100, &buffer)?;
    assert_eq!(
        vec![100, 100, 50],
        payloads.iter().map(Bytes::len).collect::<Vec<_>>()
    );
    // Nothing is lost, repeated or reordered.
    assert_eq!(buffer.to_vec(), payloads.concat());
    for payload in &payloads {
        assert_eq!(
            Some(payload.len() as u32),
            payloader.payload_duration(payload)
        );
    }
    Ok(())
}

#[test]
fn the_static_payload_types_and_clock_of_rfc3551_table_4() {
    use crate::header::Header;
    use shared::marshal::Marshal;

    // PCMU 0, PCMA 8, G722 9, all with an 8000 Hz RTP clock (4.5.2 for G722).
    for (payload_type, second_octet) in [
        (PCMU_PAYLOAD_TYPE, 0x00u8),
        (PCMA_PAYLOAD_TYPE, 0x08),
        (G722_PAYLOAD_TYPE, 0x09),
    ] {
        let header = Header {
            payload_type,
            ..Default::default()
        };
        assert_eq!(second_octet, header.marshal().unwrap()[1]);
    }
}
