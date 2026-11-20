#![no_main]
//! Reader target: an Annex B H.264 or H.265 byte stream split into NAL units, each NAL header
//! parsed. The first byte picks the codec and the reader's buffer capacity, so the start-code
//! search runs across buffer refills of different sizes.

use libfuzzer_sys::fuzz_target;
use rtc_media::io::h26x_reader::{H26xNAL, H26xReader};
use std::io::Cursor;

/// More than any real stream this small could hold; stops a reader that makes no progress.
const MAX_STEPS: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let Some((&config, stream)) = data.split_first() else {
        return;
    };
    let is_hevc = config & 0x01 != 0;
    let capacity = 1 + usize::from(config >> 1) * 16;
    let mut reader = H26xReader::new(Cursor::new(stream), capacity, is_hevc);
    for _ in 0..MAX_STEPS {
        match reader.next_nal() {
            Ok(H26xNAL::H264(mut nal)) => nal.parse_header(),
            Ok(H26xNAL::H265(mut nal)) => nal.parse_header(),
            Ok(_) => {}
            Err(_) => break,
        }
    }
});
