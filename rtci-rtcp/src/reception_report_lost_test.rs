//! RFC 3550 6.4.1: the cumulative number of packets lost is a signed 24-bit integer.

use super::*;
use bytes::Bytes;

fn report_with_lost_bytes(lost: [u8; 3]) -> ReceptionReport {
    let mut raw = vec![0, 0, 0, 1, 0];
    raw.extend_from_slice(&lost);
    raw.extend_from_slice(&[0; 16]);
    ReceptionReport::unmarshal(&mut Bytes::from(raw)).expect("a 24-byte block")
}

#[test]
fn a_negative_cumulative_loss_reads_negative() {
    assert_eq!(
        -1,
        report_with_lost_bytes([0xFF, 0xFF, 0xFF]).cumulative_lost()
    );
    assert_eq!(
        -3,
        report_with_lost_bytes([0xFF, 0xFF, 0xFD]).cumulative_lost()
    );
    assert_eq!(
        -0x80_0000,
        report_with_lost_bytes([0x80, 0x00, 0x00]).cumulative_lost()
    );
}

#[test]
fn a_positive_cumulative_loss_reads_positive() {
    assert_eq!(0, report_with_lost_bytes([0, 0, 0]).cumulative_lost());
    assert_eq!(
        0x7F_FFFF,
        report_with_lost_bytes([0x7F, 0xFF, 0xFF]).cumulative_lost()
    );
}

#[test]
fn a_signed_loss_round_trips_through_the_wire() -> Result<()> {
    for lost in [-0x80_0000, -2, 0, 5, 0x7F_FFFF] {
        let mut report = ReceptionReport::default();
        report.set_cumulative_lost(lost);
        let mut raw = report.marshal()?.freeze();
        let parsed = ReceptionReport::unmarshal(&mut raw)?;
        assert_eq!(lost, parsed.cumulative_lost());
    }
    Ok(())
}

#[test]
fn an_out_of_range_loss_is_clamped() {
    let mut report = ReceptionReport::default();
    report.set_cumulative_lost(i32::MAX);
    assert_eq!(0x7F_FFFF, report.cumulative_lost());
    report.set_cumulative_lost(i32::MIN);
    assert_eq!(-0x80_0000, report.cumulative_lost());
}
