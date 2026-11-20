//! Two GStreamer fixtures whose structure broke the media readers before, sent over a real
//! connection and checked after the trip, in the test environment (`scripts/test-env/run.sh`);
//! ignored elsewhere.
//!
//! - `opus-multi.ogg`: Ogg pages that carry several Opus packets each (RFC 3533 6). Each RTP
//!   packet carries one Opus packet (RFC 7587 4.2), so the sender must read packets, not pages
//!   (`OggReader::next_packet`).
//! - `h264-slices.h264`: x264 with four slices per picture. An access unit is every slice of a
//!   picture (H.264 7.4.1.2.3) and only its last RTP packet carries the marker (RFC 6184 5.1);
//!   `H26xSampleReader` returns access units.
//!
//! The receiver writes what it got to `received-opus-multi.ogg` and `received-h264-slices.h264`
//! beside the fixtures, and `entry.sh` decodes both with GStreamer.

mod common;
mod testenv;

use bytes::Bytes;
use rtc::media::io::Writer;
use rtc::media::io::h26x_reader::H26xSampleReader;
use rtc::media::io::h26x_writer::H26xWriter;
use rtc::media::io::ogg_reader::OggReader;
use rtc::media::io::ogg_writer::OggWriter;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_H264, MIME_TYPE_OPUS, MediaEngine,
};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp::packetizer::Packetizer;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use std::time::{Duration, Instant};
use testenv::{Env, EnvPeer, Gather, negotiate, pump};

fn media_dir() -> String {
    std::env::var("RTC_TESTENV_MEDIA").expect("RTC_TESTENV_MEDIA")
}

fn opus_codec() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_OPUS.to_owned(),
        clock_rate: 48000,
        channels: 2,
        sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
        rtcp_feedback: vec![],
    }
}

fn h264_codec() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_H264.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"
            .to_owned(),
        rtcp_feedback: vec![],
    }
}

fn pc_with(codec: &RTCRtpCodec, kind: RtpCodecKind, pt: u8) -> RTCPeerConnection {
    let mut me = MediaEngine::default();
    me.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: codec.clone(),
            payload_type: pt,
        },
        kind,
    )
    .unwrap();
    RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .build(Instant::now())
        .unwrap()
}

/// One encoded unit to send: its bytes, the RTP timestamp step after it, and how long to wait
/// before the next one.
struct Unit {
    data: Bytes,
    samples: u32,
    gap: Duration,
}

/// Connects a (sender) and b (receiver) on the WAN, sends `units` on one track, and returns the
/// RTP packets b received, in arrival order.
fn send_track(
    codec: RTCRtpCodec,
    kind: RtpCodecKind,
    pt: u8,
    units: &[Unit],
) -> Vec<rtc::rtp::Packet> {
    common::install_crypto_provider();
    let env = Env::get();
    let mut a =
        EnvPeer::new("a", "open-a", Gather::HOST, &env, pc_with(&codec, kind, pt)).expect("peer a");
    let mut b =
        EnvPeer::new("b", "open-b", Gather::HOST, &env, pc_with(&codec, kind, pt)).expect("peer b");
    let ssrc = 0x5eed_0001;
    let sender =
        a.pc.add_track(MediaStreamTrack::new(
            "fixture-stream".to_owned(),
            "fixture-track".to_owned(),
            "fixture-track".to_owned(),
            kind,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    ssrc: Some(ssrc),
                    ..Default::default()
                },
                codec: codec.clone(),
                ..Default::default()
            }],
        ))
        .unwrap();
    negotiate(&mut a, &mut b).unwrap();
    let mut packetizer = None;
    let mut next = 0usize;
    let mut due = Instant::now();
    let mut done_at = None;
    let mut received = vec![];
    pump(&mut [&mut a, &mut b], Duration::from_secs(90), |p| {
        if p[0].connected() && p[1].connected() && next < units.len() && Instant::now() >= due {
            let negotiated_pt = p[0]
                .pc
                .rtp_sender(sender)
                .and_then(|mut s| {
                    s.get_parameters()
                        .rtp_parameters
                        .codecs
                        .first()
                        .map(|c| c.payload_type)
                })
                .unwrap_or(pt);
            let pk = packetizer.get_or_insert_with(|| {
                rtc::rtp::packetizer::new_packetizer(
                    Instant::now(),
                    1200,
                    negotiated_pt,
                    ssrc,
                    codec.payloader().unwrap(),
                    Box::new(rtc::rtp::sequence::new_random_sequencer()),
                    codec.clock_rate,
                )
            });
            let u = &units[next];
            let packets = pk.packetize(Instant::now(), &u.data, u.samples).unwrap();
            let mut s = p[0].pc.rtp_sender(sender).unwrap();
            for pkt in packets {
                let _ = s.write_rtp(Instant::now(), pkt);
            }
            next += 1;
            due = Instant::now() + u.gap;
            if next == units.len() {
                done_at = Some(Instant::now());
            }
        }
        for m in p[1].reads.drain(..) {
            if let RTCMessage::RtpPacket(_, pkt) = m.message
                && pkt.header.ssrc == ssrc
            {
                received.push(pkt);
            }
        }
        done_at.is_some_and(|t: Instant| t.elapsed() > Duration::from_secs(2))
    })
    .unwrap();
    assert_eq!(
        next,
        units.len(),
        "the sender never connected: {:?} / {:?}",
        a.connection_state(),
        b.connection_state()
    );
    received
}

/// The NAL units of an access unit as `H26xSampleReader` returns it (each after a 4-byte start
/// code).
fn nal_units(au: &[u8]) -> Vec<&[u8]> {
    let mut out = vec![];
    let mut starts = vec![];
    let mut i = 0;
    while i + 4 <= au.len() {
        if au[i..i + 4] == [0, 0, 0, 1] {
            starts.push(i + 4);
            i += 4;
        } else {
            i += 1;
        }
    }
    for (k, &s) in starts.iter().enumerate() {
        let end = starts.get(k + 1).map_or(au.len(), |&n| n - 4);
        if s < end {
            out.push(&au[s..end]);
        }
    }
    out
}

fn is_slice(nal: &[u8]) -> bool {
    matches!(nal.first().map(|b| b & 0x1f), Some(1 | 5))
}

#[test]
#[ignore = "needs the real-network test environment (GStreamer fixtures): scripts/test-env/run.sh"]
fn multi_packet_ogg_pages_arrive_packet_by_packet() {
    let dir = media_dir();
    let path = format!("{dir}/opus-multi.ogg");
    // The fixture must really put several packets on a page, or the test proves nothing.
    let mut pages = OggReader::new_with_options(BufReader::new(File::open(&path).unwrap()), true);
    let mut multi = 0;
    while let Ok((payload, header)) = pages.parse_next_page() {
        if header.packets(&payload).len() > 1 {
            multi += 1;
        }
    }
    assert!(multi > 0, "{path} has no page with more than one packet");

    let (mut reader, _) = OggReader::new(BufReader::new(File::open(&path).unwrap()), true).unwrap();
    let mut sent = vec![];
    while let Ok((packet, _)) = reader.next_packet() {
        if packet.starts_with(b"OpusHead") || packet.starts_with(b"OpusTags") {
            continue;
        }
        sent.push(packet.freeze());
    }
    assert!(sent.len() >= 100, "{path} has {} Opus packets", sent.len());
    // opusenc frame-size=20: 960 samples at 48 kHz per packet.
    let units: Vec<Unit> = sent
        .iter()
        .map(|d| Unit {
            data: d.clone(),
            samples: 960,
            gap: Duration::from_millis(20),
        })
        .collect();
    let mut received = send_track(opus_codec(), RtpCodecKind::Audio, 111, &units);
    // Sequence order (the sequencer starts at a random number and may wrap).
    let base = received_first_seq(&received);
    received.sort_by_key(|p| p.header.sequence_number.wrapping_sub(base));

    let out = format!("{dir}/received-opus-multi.ogg");
    let mut writer = OggWriter::new(File::create(&out).unwrap(), 48000, 2).unwrap();
    for p in &received {
        writer.write_rtp(p).unwrap();
    }
    writer.close().unwrap();

    let got: Vec<Bytes> = received.iter().map(|p| p.payload.clone()).collect();
    eprintln!(
        "Ogg: {multi} pages with several packets; sent {} Opus packets, received {}",
        sent.len(),
        got.len()
    );
    assert_eq!(got.len(), sent.len(), "one RTP packet per Opus packet");
    assert!(
        got == sent,
        "the RTP payloads are not the Opus packets, in order"
    );
}

/// The first packet's sequence number, as the base of the wrap-around sort.
fn received_first_seq(packets: &[rtc::rtp::Packet]) -> u16 {
    packets.first().map_or(0, |p| p.header.sequence_number)
}

#[test]
#[ignore = "needs the real-network test environment (GStreamer fixtures): scripts/test-env/run.sh"]
fn multi_slice_h264_arrives_as_whole_access_units() {
    let dir = media_dir();
    let path = format!("{dir}/h264-slices.h264");
    let mut reader =
        H26xSampleReader::new(BufReader::new(File::open(&path).unwrap()), 1 << 20, false);
    let mut aus = vec![];
    while let Ok(s) = reader.next_sample() {
        // A trailing sample without a picture carries no time; it is not sent.
        if s.timed {
            aus.push(s.data);
        }
    }
    let max_slices = aus
        .iter()
        .map(|au| nal_units(au).into_iter().filter(|n| is_slice(n)).count())
        .max()
        .unwrap_or(0);
    assert!(aus.len() >= 60, "{path} has {} access units", aus.len());
    assert!(
        max_slices >= 2,
        "{path} has one slice per picture: the fixture is not multi-slice"
    );
    let sent_slices: Vec<Vec<u8>> = aus
        .iter()
        .flat_map(|au| {
            nal_units(au)
                .into_iter()
                .filter(|n| is_slice(n))
                .map(<[u8]>::to_vec)
        })
        .collect();

    let units: Vec<Unit> = aus
        .iter()
        .map(|au| Unit {
            data: au.clone(),
            samples: 3000,
            gap: Duration::from_millis(33),
        })
        .collect();
    let received = send_track(h264_codec(), RtpCodecKind::Video, 102, &units);

    // RFC 6184 5.1: the marker is set on the last packet of an access unit, and only there.
    let mut by_ts: BTreeMap<u32, Vec<&rtc::rtp::Packet>> = BTreeMap::new();
    for p in &received {
        by_ts.entry(p.header.timestamp).or_default().push(p);
    }
    let mut bad = vec![];
    for (ts, pkts) in &by_ts {
        let markers: Vec<u16> = pkts
            .iter()
            .filter(|p| p.header.marker)
            .map(|p| p.header.sequence_number)
            .collect();
        let last = pkts.last().unwrap().header.sequence_number;
        if markers != [last] {
            bad.push((*ts, markers, last));
        }
    }

    let out = format!("{dir}/received-h264-slices.h264");
    let mut writer = H26xWriter::new(File::create(&out).unwrap(), false);
    for p in &received {
        writer.write_rtp(p).unwrap();
    }
    writer.close().unwrap();
    let mut back = H26xSampleReader::new(BufReader::new(File::open(&out).unwrap()), 1 << 20, false);
    let mut got_slices = vec![];
    while let Ok(s) = back.next_sample() {
        got_slices.extend(
            nal_units(&s.data)
                .into_iter()
                .filter(|n| is_slice(n))
                .map(<[u8]>::to_vec),
        );
    }
    eprintln!(
        "H.264: {} access units with up to {max_slices} slices; {} RTP timestamps received, {} with a \
         wrong marker; {} of {} slices back byte for byte",
        aus.len(),
        by_ts.len(),
        bad.len(),
        got_slices.len(),
        sent_slices.len()
    );
    assert_eq!(by_ts.len(), aus.len(), "one RTP timestamp per access unit");
    assert!(
        bad.is_empty(),
        "access units whose marker is not exactly on their last packet (timestamp, markers, last): {:?}",
        &bad[..bad.len().min(5)]
    );
    assert!(
        got_slices == sent_slices,
        "the slices written from RTP differ from the slices sent"
    );
}
