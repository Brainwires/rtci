#![no_main]
//! Stateful target: the jitter-ordering `SampleBuilder` fed fuzzed RTP packets (sequence numbers,
//! timestamps, markers, padding and payloads all chosen by the input) through one of the codec
//! depacketizers, popping samples as it goes. Sequence jumps, wraps and late packets are what an
//! application receiving media from a peer sees.

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rtc_media::io::sample_builder::SampleBuilder;
use rtc_rtp::codec::av1::Av1Depacketizer;
use rtc_rtp::codec::h264::H264Packet;
use rtc_rtp::codec::h265::H265Packet;
use rtc_rtp::codec::opus::OpusPacket;
use rtc_rtp::codec::vp8::Vp8Packet;
use rtc_rtp::codec::vp9::Vp9Packet;
use rtc_rtp::header::Header;
use rtc_rtp::packet::Packet;
use rtc_rtp::packetizer::Depacketizer;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

// One base instant for the whole process: the harness only ever adds input-chosen offsets to it.
static START: OnceLock<Instant> = OnceLock::new();

fn run<T: Depacketizer>(mut builder: SampleBuilder<T>, mut data: &[u8], start: Instant) {
    let mut now = start;
    let mut packets = 0;
    // Each packet: flags, sequence number (2), timestamp (4), a one-byte payload length, payload.
    while data.len() >= 8 {
        let flags = data[0];
        let sequence_number = u16::from_be_bytes([data[1], data[2]]);
        let timestamp = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);
        let len = usize::from(data[7]).min(data.len() - 8);
        let payload = Bytes::copy_from_slice(&data[8..8 + len]);
        data = &data[8 + len..];
        packets += 1;
        if packets > 2048 {
            break;
        }

        now += Duration::from_millis(u64::from(flags >> 4));
        builder.push(
            now,
            Packet {
                header: Header {
                    version: 2,
                    padding: flags & 0x02 != 0,
                    marker: flags & 0x01 != 0,
                    payload_type: 96,
                    sequence_number,
                    timestamp,
                    ssrc: 1,
                    ..Default::default()
                },
                payload,
            },
        );
        if flags & 0x04 != 0 {
            while builder.pop(now).is_some() {}
        }
        if flags & 0x08 != 0 {
            let _ = builder.pop_with_timestamp(now);
        }
    }
    while builder.pop(now).is_some() {}
}

fuzz_target!(|data: &[u8]| {
    let start = *START.get_or_init(Instant::now);
    let Some((&config, rest)) = data.split_first() else {
        return;
    };
    let Some((&max_late, rest)) = rest.split_first() else {
        return;
    };
    let max_late = u16::from(max_late);
    let delay = Duration::from_millis(u64::from(config >> 4) * 50);
    let timed = config & 0x08 != 0;
    match config & 0x07 {
        0 => {
            let b = SampleBuilder::new(max_late, H264Packet::default(), 90000);
            run(
                if timed {
                    b.with_max_time_delay(delay)
                } else {
                    b
                },
                rest,
                start,
            )
        }
        1 => {
            let b = SampleBuilder::new(max_late, H265Packet::default(), 90000);
            run(
                if timed {
                    b.with_max_time_delay(delay)
                } else {
                    b
                },
                rest,
                start,
            )
        }
        2 => {
            let b = SampleBuilder::new(max_late, Vp8Packet::default(), 90000);
            run(
                if timed {
                    b.with_max_time_delay(delay)
                } else {
                    b
                },
                rest,
                start,
            )
        }
        3 => {
            let b = SampleBuilder::new(max_late, Vp9Packet::default(), 90000);
            run(
                if timed {
                    b.with_max_time_delay(delay)
                } else {
                    b
                },
                rest,
                start,
            )
        }
        4 => {
            let b = SampleBuilder::new(max_late, Av1Depacketizer::new(), 90000);
            run(
                if timed {
                    b.with_max_time_delay(delay)
                } else {
                    b
                },
                rest,
                start,
            )
        }
        _ => {
            let b = SampleBuilder::new(max_late, OpusPacket, 48000);
            run(
                if timed {
                    b.with_max_time_delay(delay)
                } else {
                    b
                },
                rest,
                start,
            )
        }
    }
});
