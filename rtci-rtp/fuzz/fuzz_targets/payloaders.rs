#![no_main]
//! Payloader target: an encoded frame split into RTP payloads by each codec's payloader, then
//! handed to the matching depacketizer. The frames come from files or encoders an application
//! feeds in (untrusted media), and the payloaders parse them: H.264 and H.265 NAL units, AV1
//! OBUs, VP8 and VP9 frame headers. Each payloader runs twice so the state it keeps between
//! frames (H.264 SPS / PPS, picture ids) is used.

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rtci_rtp::codec::av1::{Av1Depacketizer, Av1Payloader};
use rtci_rtp::codec::g7xx::G7xxPayloader;
use rtci_rtp::codec::h264::{H264Packet, H264Payloader};
use rtci_rtp::codec::h265::{H265Packet, HevcPayloader};
use rtci_rtp::codec::opus::{OpusPacket, OpusPayloader};
use rtci_rtp::codec::smpte336m::{Smpte336mDepacketizer, Smpte336mPayloader};
use rtci_rtp::codec::vp8::{Vp8Packet, Vp8Payloader};
use rtci_rtp::codec::vp9::{InitialPictureIDFn, Vp9Packet, Vp9Payloader};
use rtci_rtp::packetizer::{Depacketizer, Payloader};
use std::sync::Arc;

fn run(
    payloader: &mut dyn Payloader,
    depacketizer: Option<&mut dyn Depacketizer>,
    mtu: usize,
    frame: &Bytes,
) {
    let first = payloader.payload(mtu, frame);
    let second = payloader.payload(mtu, frame);
    if let Some(depacketizer) = depacketizer {
        for payloads in [first, second].into_iter().flatten() {
            let last = payloads.len().saturating_sub(1);
            for (i, payload) in payloads.iter().enumerate() {
                let _ = depacketizer.is_partition_head(payload);
                let _ = depacketizer.depacketize(payload);
                let _ = depacketizer.is_partition_tail(i == last, payload);
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let config = data[0];
    // A real MTU, or a tiny one that forces fragmentation at every byte.
    let mtu = if config & 0x80 != 0 {
        1200
    } else {
        usize::from(data[1])
    };
    let frame = Bytes::copy_from_slice(&data[2..]);

    match config % 9 {
        0 => run(
            &mut H264Payloader::default(),
            Some(&mut H264Packet::default()),
            mtu,
            &frame,
        ),
        1 => run(
            &mut HevcPayloader::default(),
            Some(&mut H265Packet::default()),
            mtu,
            &frame,
        ),
        2 => run(
            &mut Av1Payloader::default(),
            Some(&mut Av1Depacketizer::new()),
            mtu,
            &frame,
        ),
        3 => {
            let mut payloader = Vp8Payloader::default();
            payloader.enable_picture_id = config & 0x40 != 0;
            run(&mut payloader, Some(&mut Vp8Packet::default()), mtu, &frame)
        }
        4 => {
            let mut payloader = Vp9Payloader::default();
            // A fixed starting picture id: no randomness, so an input replays identically.
            let initial_picture_id: InitialPictureIDFn = Arc::new(|| 0x1234u16);
            payloader.initial_picture_id_fn = Some(initial_picture_id);
            payloader.flexible_mode = config & 0x40 != 0;
            run(&mut payloader, Some(&mut Vp9Packet::default()), mtu, &frame)
        }
        5 => run(&mut OpusPayloader, Some(&mut OpusPacket), mtu, &frame),
        6 => run(
            &mut Smpte336mPayloader,
            Some(&mut Smpte336mDepacketizer),
            mtu,
            &frame,
        ),
        _ => run(&mut G7xxPayloader, None, mtu, &frame),
    }
});
