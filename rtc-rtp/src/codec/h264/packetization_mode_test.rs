//! RFC 6184 6.2: under `packetization-mode=0` every NAL unit goes in a packet of its own.

use super::*;

const SPS: &[u8] = &[0x67, 0x42, 0xC0, 0x1F];
const PPS: &[u8] = &[0x68, 0xCE, 0x3C, 0x80];
const IDR: &[u8] = &[0x65, 0x88, 0x84, 0x00, 0x33];

fn annex_b(nalus: &[&[u8]]) -> Bytes {
    let mut out = vec![];
    for nalu in nalus {
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(nalu);
    }
    Bytes::from(out)
}

#[test]
fn mode_0_sends_each_nal_unit_alone() -> Result<()> {
    let mut payloader = H264Payloader::with_packetization_mode(0);
    let payloads = payloader.payload(1200, &annex_b(&[SPS, PPS, IDR]))?;

    assert_eq!(
        vec![
            Bytes::from_static(SPS),
            Bytes::from_static(PPS),
            Bytes::from_static(IDR)
        ],
        payloads,
        "no STAP-A: the parameter sets go one per packet"
    );
    Ok(())
}

#[test]
fn mode_0_refuses_a_nal_unit_over_the_mtu() {
    let mut payloader = H264Payloader::with_packetization_mode(0);
    let mut big = vec![0x65];
    big.extend(std::iter::repeat_n(0xAB, 2000));

    assert!(payloader.payload(1200, &annex_b(&[&big])).is_err());
}

#[test]
fn mode_1_still_aggregates_and_fragments() -> Result<()> {
    let mut payloader = H264Payloader::with_packetization_mode(1);
    let payloads = payloader.payload(1200, &annex_b(&[SPS, PPS, IDR]))?;
    assert_eq!(2, payloads.len());
    assert_eq!(STAPA_NALU_TYPE, payloads[0][0] & NALU_TYPE_BITMASK);

    let mut big = vec![0x65];
    big.extend(std::iter::repeat_n(0xAB, 2000));
    let fragments = payloader.payload(1200, &annex_b(&[&big]))?;
    assert!(fragments.len() > 1);
    assert_eq!(FUA_NALU_TYPE, fragments[0][0] & NALU_TYPE_BITMASK);
    Ok(())
}
