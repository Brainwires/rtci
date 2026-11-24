#![no_main]
//! Reader target: an IVF file (the VP8 / VP9 / AV1 container) read frame by frame.

use libfuzzer_sys::fuzz_target;
use rtci_media::io::ivf_reader::IVFReader;
use std::io::Cursor;

/// More than any real file this small could hold; stops a reader that makes no progress.
const MAX_STEPS: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let Ok((mut reader, _header)) = IVFReader::new(Cursor::new(data)) else {
        return;
    };
    for _ in 0..MAX_STEPS {
        if reader.parse_next_frame().is_err() {
            break;
        }
    }
});
