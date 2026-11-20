#![no_main]
//! Reader target: an Ogg Opus file read page by page and packet by packet, with and without the
//! CRC check, plus the OpusHead and OpusTags parsers on the first packets. The readers take
//! untrusted files (an application plays what it is given); RFC 3533 and RFC 7845.

use libfuzzer_sys::fuzz_target;
use rtc_media::io::ogg_reader::{OggReader, parse_opus_head, parse_opus_tags};
use std::io::Cursor;

/// More than any real file this small could hold; stops a reader that makes no progress.
const MAX_STEPS: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let Some((&config, file)) = data.split_first() else {
        return;
    };
    let do_checksum = config & 0x01 != 0;

    if config & 0x02 == 0 {
        // Header first, then packets, as an application plays a file.
        if let Ok((mut reader, _header)) = OggReader::new(Cursor::new(file), do_checksum) {
            for _ in 0..MAX_STEPS {
                let Ok((packet, page)) = reader.next_packet() else {
                    break;
                };
                let _ = page.opus_header_type(&packet);
                let _ = parse_opus_tags(&packet);
            }
        }
    } else {
        // Page by page, splitting each page into packets.
        let mut reader = OggReader::new_with_options(Cursor::new(file), do_checksum);
        for _ in 0..MAX_STEPS {
            let Ok((payload, page)) = reader.parse_next_page() else {
                break;
            };
            let _ = page.is_beginning_of_stream();
            let _ = page.is_end_of_stream();
            let _ = page.is_continued_packet();
            let _ = page.segment_table();
            for (packet, _complete) in page.packets(&payload) {
                let _ = parse_opus_head(packet);
                let _ = parse_opus_tags(packet);
            }
        }
    }
});
