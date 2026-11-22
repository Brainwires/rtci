#![no_main]
//! Parser target: RFC 3389 comfort-noise payloads, whole and split per channel (the channel
//! count is the first input byte, 1 to 8). A parsed payload is marshalled back and parsed
//! again: the result must not change. The CN depacketizer and the coefficient helpers run on
//! the same input.

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rtc_rtp::codec::comfort_noise::{
    ComfortNoise, ComfortNoisePacket, marshal_channels, quantize_reflection_coefficient,
    reflection_coefficient, unmarshal_channels,
};
use rtc_rtp::packetizer::Depacketizer;
use rtc_shared::marshal::{Marshal, Unmarshal};

fuzz_target!(|data: &[u8]| {
    let payload = Bytes::copy_from_slice(data);
    if let Ok(noise) = ComfortNoise::unmarshal(&mut payload.clone()) {
        let raw = noise.marshal().expect("a parsed payload marshals").freeze();
        assert_eq!(
            ComfortNoise::unmarshal(&mut raw.clone()).ok(),
            Some(noise.clone())
        );
        let order = usize::from(data[0] & 0x1F);
        assert_eq!(noise.coefficients_for_order(order).len(), order);
        for k in noise.reflection_coefficients(order) {
            let n = quantize_reflection_coefficient(k);
            assert_eq!(reflection_coefficient(n), Some(k));
        }
    }

    if let Some((&first, rest)) = data.split_first() {
        let channels = usize::from(first % 8) + 1;
        let rest = Bytes::copy_from_slice(rest);
        if let Ok(parsed) = unmarshal_channels(&rest, channels) {
            let raw = marshal_channels(&parsed).expect("parsed channels marshal");
            assert_eq!(unmarshal_channels(&raw, channels).ok(), Some(parsed));
        }
    }

    let mut depacketizer = ComfortNoisePacket;
    let _ = depacketizer.is_partition_head(&payload);
    let _ = depacketizer.depacketize(&payload);
    let _ = depacketizer.is_partition_tail(false, &payload);
});
