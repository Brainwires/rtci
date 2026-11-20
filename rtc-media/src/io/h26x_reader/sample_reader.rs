use bytes::{Bytes, BytesMut};
use shared::error::{Error, Result};
use std::io::Read;

use super::H26xReader;

#[cfg(test)]
#[path = "sample_reader_bound_test.rs"]
mod sample_reader_bound_test;

const ANNEXB_START_CODE: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// The most NAL units one access unit may hold.
///
/// A picture split into one slice per macroblock row is a few hundred slices at 4K; the bound
/// leaves an order of magnitude above that. A stream whose slices never start a new picture
/// (`first_mb_in_slice` never 0), or of non-VCL NAL units only, would otherwise be buffered whole.
pub const MAX_ACCESS_UNIT_NALS: usize = 4096;

/// The most bytes one access unit may hold, start codes excluded.
pub const MAX_ACCESS_UNIT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
/// One access unit read from an Annex B stream — the NAL units making up a single frame.
pub struct H26xSample {
    /// The sample's bytes: the access unit's NAL units, each after a 4-byte start code.
    pub data: Bytes,
    /// Whether this sample advances presentation time, i.e. holds a coded picture.
    pub timed: bool,
}

/// Reads whole access units from an H.264 or H.265 Annex B stream.
///
/// A sample is one access unit (H.264 7.4.1.2.3, H.265 7.4.2.4.4): the parameter sets, SEI and
/// access unit delimiter before a picture and every slice of it, so a packetizer puts the RTP
/// marker on its last packet only (RFC 6184 5.1, RFC 7798 4.1). It used to return each H.264
/// NAL unit on its own, which set the marker on every slice and parameter set. A sample ends
/// where the next access unit starts, so it is returned once the next one's first NAL unit is
/// read (or at the end of the stream).
pub struct H26xSampleReader<R: Read> {
    reader: H26xReader<R>,
    is_hevc: bool,
    /// The NAL units of the access unit being read.
    pending: Vec<BytesMut>,
    /// Whether `pending` holds a coded slice.
    pending_has_vcl: bool,
    /// The bytes of the NAL units in `pending`.
    pending_bytes: usize,
}

impl<R: Read> H26xSampleReader<R> {
    /// Wraps `reader`, buffering up to `capacity` bytes.
    ///
    /// Set `is_hevc` for H.265; the two codecs differ in how NAL headers are parsed.
    pub fn new(reader: R, capacity: usize, is_hevc: bool) -> Self {
        Self {
            reader: H26xReader::new(reader, capacity, is_hevc),
            is_hevc,
            pending: vec![],
            pending_has_vcl: false,
            pending_bytes: 0,
        }
    }

    /// Reads the next sample.
    ///
    /// # Errors
    ///
    /// Fails on an I/O error, or at end of stream. Fails with [`Error::ErrBufferFull`] when an
    /// access unit would exceed [`MAX_ACCESS_UNIT_NALS`] NAL units or [`MAX_ACCESS_UNIT_BYTES`]
    /// bytes; the partial access unit is dropped and the next call reads on from there.
    pub fn next_sample(&mut self) -> Result<H26xSample> {
        loop {
            let nal = match self.reader.next_nal() {
                Ok(nal) => nal,
                Err(Error::ErrIoEOF) if !self.pending.is_empty() => {
                    return Ok(self.take_access_unit());
                }
                Err(err) => return Err(err),
            };
            let data = nal.data();
            if data.is_empty() {
                continue;
            }
            let vcl = is_vcl(self.is_hevc, data);
            if self.pending_has_vcl && starts_access_unit(self.is_hevc, data) {
                let sample = self.take_access_unit();
                self.pending_bytes = data.len();
                self.pending.push(data.clone());
                self.pending_has_vcl = vcl;
                return Ok(sample);
            }
            if self.pending.len() >= MAX_ACCESS_UNIT_NALS
                || self.pending_bytes.saturating_add(data.len()) > MAX_ACCESS_UNIT_BYTES
            {
                self.pending.clear();
                self.pending_has_vcl = false;
                self.pending_bytes = 0;
                return Err(Error::ErrBufferFull);
            }
            self.pending_bytes += data.len();
            self.pending.push(data.clone());
            self.pending_has_vcl |= vcl;
        }
    }

    fn take_access_unit(&mut self) -> H26xSample {
        let timed = self.pending_has_vcl;
        self.pending_has_vcl = false;
        self.pending_bytes = 0;
        H26xSample {
            data: build_access_unit(&mut self.pending),
            timed,
        }
    }
}

/// Whether a NAL unit is a coded slice (VCL).
fn is_vcl(is_hevc: bool, nal: &[u8]) -> bool {
    if is_hevc {
        (nal[0] >> 1) & 0x3f <= 31
    } else {
        (1..=5).contains(&(nal[0] & 0x1f))
    }
}

/// Whether a NAL unit begins a new access unit, given that the current one has a coded
/// picture: the NAL unit types that may only precede a picture, or a slice that is the first
/// of its picture (`first_mb_in_slice == 0`, whose ue(v) code is a single 1 bit;
/// `first_slice_segment_in_pic_flag`).
fn starts_access_unit(is_hevc: bool, nal: &[u8]) -> bool {
    if is_hevc {
        let unit_type = (nal[0] >> 1) & 0x3f;
        match unit_type {
            // VPS, SPS, PPS, AUD, prefix SEI, reserved 41..=44, unspecified 48..=55.
            32..=35 | 39 | 41..=44 | 48..=55 => true,
            0..=31 => nal.get(2).is_some_and(|b| b & 0x80 != 0),
            _ => false,
        }
    } else {
        let unit_type = nal[0] & 0x1f;
        match unit_type {
            // SEI, SPS, PPS, AUD, and 14..=18.
            6..=9 | 14..=18 => true,
            // A slice (or partition A, which carries the slice header).
            1 | 2 | 5 => nal.get(1).is_some_and(|b| b & 0x80 != 0),
            _ => false,
        }
    }
}

fn build_access_unit(nals: &mut Vec<BytesMut>) -> Bytes {
    let total_len = nals
        .iter()
        .map(|nal| ANNEXB_START_CODE.len() + nal.len())
        .sum::<usize>();
    let mut access_unit = BytesMut::with_capacity(total_len);
    for nal in nals.drain(..) {
        access_unit.extend_from_slice(&ANNEXB_START_CODE);
        access_unit.extend_from_slice(&nal);
    }
    access_unit.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const SC: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

    fn annex_b(nals: &[&[u8]]) -> Vec<u8> {
        let mut out = vec![];
        for nal in nals {
            out.extend_from_slice(&SC);
            out.extend_from_slice(nal);
        }
        out
    }

    #[test]
    fn h265_sample_reader_groups_parameter_sets_with_following_vcl() -> Result<()> {
        let nals: [&[u8]; 4] = [
            &[0x40, 0x01, 0x01],
            &[0x42, 0x01, 0x02],
            &[0x44, 0x01, 0x03],
            &[0x28, 0x01, 0xaa],
        ];
        let mut reader = H26xSampleReader::new(Cursor::new(annex_b(&nals)), 1024, true);

        let sample = reader.next_sample()?;

        assert!(sample.timed);
        assert_eq!(sample.data, Bytes::from(annex_b(&nals)));
        assert!(matches!(reader.next_sample(), Err(Error::ErrIoEOF)));

        Ok(())
    }

    /// RFC 6184 5.1: the marker bit is set on an access unit's last packet only. The reader
    /// used to return each NAL unit on its own (SPS, PPS and every slice), so a packetizer
    /// set the marker on each of them.
    #[test]
    fn h264_sample_reader_returns_whole_access_units() -> Result<()> {
        // SPS, PPS, then an IDR picture of two slices (first_mb_in_slice 0, then not 0),
        // then a non-IDR picture of one slice.
        let sps: &[u8] = &[0x67, 0x42, 0x00, 0x1f];
        let pps: &[u8] = &[0x68, 0xce, 0x06, 0xe2];
        let idr1: &[u8] = &[0x65, 0x88, 0x84, 0x21];
        let idr2: &[u8] = &[0x65, 0x40, 0x84, 0x21];
        let p1: &[u8] = &[0x41, 0x9a, 0x02, 0x03];
        let stream = annex_b(&[sps, pps, idr1, idr2, p1]);
        let mut reader = H26xSampleReader::new(Cursor::new(stream), 1024, false);

        let first = reader.next_sample()?;
        assert!(first.timed);
        assert_eq!(first.data, Bytes::from(annex_b(&[sps, pps, idr1, idr2])));

        let second = reader.next_sample()?;
        assert!(second.timed);
        assert_eq!(second.data, Bytes::from(annex_b(&[p1])));

        assert!(matches!(reader.next_sample(), Err(Error::ErrIoEOF)));
        Ok(())
    }

    #[test]
    fn parameter_sets_alone_are_untimed() -> Result<()> {
        let sps: &[u8] = &[0x67, 0x42, 0x00, 0x1f];
        let pps: &[u8] = &[0x68, 0xce, 0x06, 0xe2];
        let mut reader = H26xSampleReader::new(Cursor::new(annex_b(&[sps, pps])), 1024, false);
        let sample = reader.next_sample()?;
        assert!(!sample.timed);
        assert_eq!(sample.data, Bytes::from(annex_b(&[sps, pps])));
        Ok(())
    }

    /// x264 with sliced threads (e.g. `tune=zerolatency`) codes each picture as several slices.
    /// Each was a timed sample, so a sender advanced the timestamp mid-picture and receivers
    /// assembled only key frames (found by the browser interop tests in scripts/test-env). Each
    /// picture is now one access unit: one timed sample holding all of its slices.
    #[test]
    fn h264_slices_of_one_picture_advance_time_once() -> Result<()> {
        let idr1: &[u8] = &[0x65, 0x88, 0x84]; // IDR, first_mb_in_slice 0
        let idr2: &[u8] = &[0x65, 0x40, 0x84]; // IDR, first_mb_in_slice 1: same picture
        let p1: &[u8] = &[0x41, 0x9a, 0x02]; // P, first_mb_in_slice 0: next picture
        let p2: &[u8] = &[0x41, 0x20, 0x02]; // P, first_mb_in_slice 3: same picture
        let stream = annex_b(&[idr1, idr2, p1, p2]);
        let mut reader = H26xSampleReader::new(Cursor::new(stream), 1024, false);

        let first = reader.next_sample()?;
        assert!(first.timed);
        assert_eq!(first.data, Bytes::from(annex_b(&[idr1, idr2])));

        let second = reader.next_sample()?;
        assert!(second.timed);
        assert_eq!(second.data, Bytes::from(annex_b(&[p1, p2])));

        assert!(matches!(reader.next_sample(), Err(Error::ErrIoEOF)));
        Ok(())
    }
}
