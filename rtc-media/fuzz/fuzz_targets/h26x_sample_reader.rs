#![no_main]
//! Reader target: an Annex B H.264 or H.265 byte stream grouped into access units (samples), the
//! layer that decides where one picture ends and buffers the NAL units of the next.

use libfuzzer_sys::fuzz_target;
use rtc_media::io::h26x_reader::sample_reader::H26xSampleReader;
use std::io::Cursor;

/// More than any real stream this small could hold; stops a reader that makes no progress.
const MAX_STEPS: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let Some((&config, stream)) = data.split_first() else {
        return;
    };
    let is_hevc = config & 0x01 != 0;
    let capacity = 1 + usize::from(config >> 1) * 16;
    let mut reader = H26xSampleReader::new(Cursor::new(stream), capacity, is_hevc);
    for _ in 0..MAX_STEPS {
        if reader.next_sample().is_err() {
            break;
        }
    }
});
