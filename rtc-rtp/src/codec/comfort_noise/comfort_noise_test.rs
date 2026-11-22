use super::*;

fn cn(level: u8, coefficients: &[u8]) -> ComfortNoise {
    ComfortNoise {
        level,
        coefficients: Bytes::copy_from_slice(coefficients),
    }
}

#[test]
fn a_payload_is_the_level_byte_then_the_coefficients() {
    let raw = cn(40, &[1, 2, 3]).marshal().unwrap();
    assert_eq!(raw.as_ref(), &[40, 1, 2, 3]);
}

#[test]
fn round_trip_for_model_orders_0_10_and_12() {
    for order in [0usize, 10, 12] {
        let coefficients: Vec<u8> = (0..order).map(|i| (i * 21) as u8).collect();
        let noise = cn(70, &coefficients);
        let raw = noise.marshal().unwrap();
        assert_eq!(raw.len(), order + 1);
        let parsed = ComfortNoise::unmarshal(&mut raw.freeze()).unwrap();
        assert_eq!(parsed, noise);
        assert_eq!(parsed.model_order(), order);
    }
}

#[test]
fn an_empty_payload_is_rejected() {
    assert_eq!(
        ComfortNoise::unmarshal(&mut Bytes::new()),
        Err(Error::ErrShortPacket)
    );
}

#[test]
fn marshal_rejects_a_level_above_127() {
    assert!(cn(128, &[]).marshal().is_err());
    assert!(cn(255, &[1]).marshal().is_err());
    assert_eq!(cn(127, &[]).marshal().unwrap().as_ref(), &[127]);
}

#[test]
fn parse_masks_a_set_level_msb() {
    let parsed = ComfortNoise::unmarshal(&mut Bytes::from_static(&[0x80 | 33, 9])).unwrap();
    assert_eq!(parsed, cn(33, &[9]));
    // And the sender never sets it.
    assert_eq!(parsed.marshal().unwrap()[0] & 0x80, 0);
}

#[test]
fn marshal_into_a_short_buffer_fails() {
    let mut buf = [0u8; 2];
    assert_eq!(
        cn(1, &[1, 2]).marshal_to(&mut buf),
        Err(Error::ErrBufferTooSmall)
    );
}

#[test]
fn reflection_coefficient_follows_the_section_3_2_formula() {
    for n in 0..=254u8 {
        let expected = 258.0 * (f64::from(n) - 127.0) / 32768.0;
        assert_eq!(reflection_coefficient(n), Some(expected));
        let k = expected;
        assert!(k > -1.0 && k < 1.0);
    }
    assert_eq!(reflection_coefficient(127), Some(0.0));
    assert_eq!(reflection_coefficient(255), None);
}

#[test]
fn quantization_inverts_the_formula_and_clamps() {
    for n in 0..=254u8 {
        let k = reflection_coefficient(n).unwrap();
        assert_eq!(quantize_reflection_coefficient(k), n);
    }
    assert_eq!(quantize_reflection_coefficient(0.0), 127);
    assert_eq!(quantize_reflection_coefficient(-1.0), 0);
    assert_eq!(quantize_reflection_coefficient(1.0), 254);
    assert_eq!(quantize_reflection_coefficient(5.0), 254);
    assert_eq!(quantize_reflection_coefficient(-5.0), 0);
    assert_eq!(quantize_reflection_coefficient(f64::NAN), 127);
    // 0.5 -> 0.5 * 32768 / 258 = 63.50... -> 64 + 127.
    assert_eq!(quantize_reflection_coefficient(0.5), 191);
}

#[test]
fn extra_coefficients_are_ignored_and_missing_ones_are_zero() {
    let noise = cn(10, &[200, 50, 10]);
    assert_eq!(noise.coefficients_for_order(2), vec![200, 50]);
    assert_eq!(noise.coefficients_for_order(5), vec![200, 50, 10, 127, 127]);
    assert_eq!(noise.coefficients_for_order(0), Vec::<u8>::new());
    let k = noise.reflection_coefficients(4);
    assert_eq!(k.len(), 4);
    assert_eq!(k[0], reflection_coefficient(200).unwrap());
    assert_eq!(k[3], 0.0);
    // A reserved index reads as zero.
    assert_eq!(cn(10, &[255]).reflection_coefficients(1), vec![0.0]);
}

#[test]
fn one_payload_per_channel_round_trips() {
    let channels = vec![cn(20, &[1, 2, 3]), cn(30, &[4, 5, 6])];
    let raw = marshal_channels(&channels).unwrap();
    assert_eq!(raw.as_ref(), &[20, 1, 2, 3, 30, 4, 5, 6]);
    assert_eq!(unmarshal_channels(&raw, 2).unwrap(), channels);
    // Model order 0, three channels.
    let raw = Bytes::from_static(&[1, 2, 3]);
    assert_eq!(
        unmarshal_channels(&raw, 3).unwrap(),
        vec![cn(1, &[]), cn(2, &[]), cn(3, &[])]
    );
}

#[test]
fn channel_payloads_must_divide_evenly_and_share_a_model_order() {
    let raw = Bytes::from_static(&[1, 2, 3, 4, 5]);
    assert!(unmarshal_channels(&raw, 2).is_err());
    assert!(unmarshal_channels(&raw, 0).is_err());
    assert!(unmarshal_channels(&Bytes::new(), 1).is_err());
    assert!(unmarshal_channels(&Bytes::from_static(&[1]), 2).is_err());
    assert!(marshal_channels(&[]).is_err());
    assert!(marshal_channels(&[cn(1, &[1]), cn(1, &[1, 2])]).is_err());
    assert!(marshal_channels(&[cn(1, &[1]), cn(200, &[1])]).is_err());
}

#[test]
fn payloader_passes_one_cn_payload_through_unfragmented() {
    let mut p = ComfortNoisePayloader;
    let payload = Bytes::from_static(&[40, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    assert_eq!(p.payload(1200, &payload).unwrap(), vec![payload.clone()]);
    // Even below the payload size: CN is never fragmented.
    assert_eq!(p.payload(4, &payload).unwrap(), vec![payload.clone()]);
    assert!(p.payload(1200, &Bytes::new()).unwrap().is_empty());
    assert!(p.payload(0, &payload).unwrap().is_empty());
}

#[test]
fn depacketizer_returns_the_payload_and_rejects_empty() {
    let mut d = ComfortNoisePacket;
    let payload = Bytes::from_static(&[40, 1]);
    assert_eq!(d.depacketize(&payload).unwrap(), payload);
    assert!(d.depacketize(&Bytes::new()).is_err());
    assert!(d.is_partition_head(&payload));
    assert!(d.is_partition_tail(false, &payload));
}
