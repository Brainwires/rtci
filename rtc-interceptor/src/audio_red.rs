//! Redundant audio data, RED (RFC 2198), for the audio streams whose m= section negotiated a
//! RED format (`a=rtpmap:<pt> red/48000/2`, `a=fmtp:<pt> 111/111`).
//!
//! RFC 8854 section 4.2 has a WebRTC endpoint support RED for audio; Chromium and WebKit
//! offer it with Opus as both the primary and the redundant encoding (the fmtp lists the Opus
//! payload type twice), the form RFC 2198 section 3 allows ("a copy of the primary MAY be
//! used as the redundancy").
//!
//! - **Send.** A packet of a local stream whose payload type is the primary of the
//!   negotiated RED format leaves as a RED packet: the RED payload type in the header, the
//!   copies of the last [`RedAudioBuilder::with_redundancy`] primaries (one by default, as
//!   Chromium sends) before the new primary, the header otherwise the primary's (RFC 2198
//!   section 3). A primary too large to be wrapped, or of another payload type (comfort noise,
//!   DTMF), leaves as it is: the receiver negotiated it too.
//! - **Receive.** A RED packet of a remote stream is taken apart into the packets of its
//!   blocks (RFC 2198 section 4): the primary with the RED packet's sequence number, marker
//!   and CSRCs, and the earlier primaries a lost packet carried, recovered from the redundant
//!   blocks with the sequence numbers they had (one packet per block, as the encoder above and
//!   Chromium send them), no marker ("the marker bit ... is lost") and the RED packet's CSRCs.
//!   Nothing is delivered twice (`RedDecoder`). What arrives after this interceptor (the NACK
//!   generator, the jitter buffer, the application) sees the primary encoding only.
//!
//! # Where it belongs
//!
//! [`Slot::Redundancy`](crate::Slot::Redundancy) (10_450). On the write leg it is
//! application-ward of the NACK responder (4_000) and the FEC encoder (5_000): what is
//! buffered for retransmission and protected is the RED packet on the wire. On the read leg it
//! is application-ward of the receiver report (10_000) and the FEC decoder (10_300), which
//! count and repair the RED packets that arrived, and wire-ward of the NACK generator
//! (10_600), which then does not ask for a packet RED recovered.

use crate::stream_info::StreamInfo;
use crate::{Interceptor, Packet, TaggedPacket};
use rtp::codec::red::{RedDecoder, RedEncoder, RedPacket, parse_red_fmtp};
use sansio::Protocol;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// How many earlier primaries a RED packet carries by default: one, as Chromium sends Opus
/// RED.
pub const RED_AUDIO_DEFAULT_REDUNDANCY: usize = 1;

/// The largest RED payload the sender builds by default: redundant blocks that would make
/// the payload larger are left out (an Opus packet is far smaller), so that a RED packet
/// stays within the path MTU the application sized the primary for, with the header, its
/// extensions and the SRTP tag.
pub const RED_AUDIO_DEFAULT_MAX_PAYLOAD_SIZE: usize = 1000;

/// Builder for [`RedAudioInterceptor`].
#[derive(Debug, Clone)]
pub struct RedAudioBuilder {
    redundancy: usize,
    max_payload_size: usize,
}

impl Default for RedAudioBuilder {
    fn default() -> Self {
        Self {
            redundancy: RED_AUDIO_DEFAULT_REDUNDANCY,
            max_payload_size: RED_AUDIO_DEFAULT_MAX_PAYLOAD_SIZE,
        }
    }
}

impl RedAudioBuilder {
    /// One earlier primary per packet, payloads of at most
    /// [`RED_AUDIO_DEFAULT_MAX_PAYLOAD_SIZE`] octets.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many earlier primaries each RED packet carries (0 sends RED packets with the
    /// primary alone).
    pub fn with_redundancy(mut self, redundancy: usize) -> Self {
        self.redundancy = redundancy;
        self
    }

    /// The largest RED payload built; redundant blocks that would exceed it are left out.
    pub fn with_max_payload_size(mut self, max_payload_size: usize) -> Self {
        self.max_payload_size = max_payload_size;
        self
    }

    /// The interceptor.
    pub fn build(self) -> RedAudioInterceptor {
        RedAudioInterceptor {
            config: self,
            senders: HashMap::new(),
            receivers: HashMap::new(),
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

struct SendStream {
    red_payload_type: u8,
    primary_payload_type: u8,
    encoder: RedEncoder,
    /// The sequence number of the last primary wrapped.
    last_sequence_number: Option<u16>,
}

struct ReceiveStream {
    red_payload_type: u8,
    decoder: RedDecoder,
}

/// RFC 2198 audio redundancy for the streams that negotiated it; see the module
/// documentation.
pub struct RedAudioInterceptor {
    config: RedAudioBuilder,
    senders: HashMap<u32, SendStream>,
    receivers: HashMap<u32, ReceiveStream>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl Default for RedAudioInterceptor {
    fn default() -> Self {
        RedAudioBuilder::new().build()
    }
}

/// The RED format of an audio stream's m= section and its primary encoding: a format named
/// `red` (RFC 2198 section 5) whose fmtp lists only `primary`, the stream's payload type, as
/// the primary and every redundant encoding (the copy-of-the-primary form this interceptor
/// sends and Chromium and WebKit offer). `None` for a video stream or a section without one.
fn negotiated_red(info: &StreamInfo, primary: u8) -> Option<u8> {
    if !info.mime_type.to_ascii_lowercase().starts_with("audio/") {
        return None;
    }
    info.section_mime_types
        .iter()
        .filter(|(_, mime_type)| mime_type.to_ascii_lowercase().ends_with("/red"))
        .find_map(|(payload_type, _)| {
            let fmtp = info
                .section_fmtp_lines
                .iter()
                .find(|(pt, _)| pt == payload_type)
                .map(|(_, fmtp)| fmtp.trim())?;
            let encodings = parse_red_fmtp(fmtp).ok()?;
            encodings
                .iter()
                .all(|pt| *pt == primary)
                .then_some(*payload_type)
        })
}

impl RedAudioInterceptor {
    /// The RTP packets of the blocks of the RED packet `packet` (RFC 2198 section 4), each
    /// not yet delivered, the recovered ones first.
    fn take_apart(stream: &mut ReceiveStream, packet: &rtp::Packet) -> Vec<rtp::Packet> {
        // The timestamps of the redundant blocks in header order, oldest first: block `i` of
        // `n` was the primary of the packet `n - i` before this one.
        let redundant: Vec<u32> = match RedPacket::parse(&packet.payload) {
            Ok(red) => red
                .redundant()
                .iter()
                .map(|block| block.timestamp(packet.header.timestamp))
                .collect(),
            Err(_) => return vec![],
        };
        let Ok(blocks) = stream.decoder.decode_rtp(packet) else {
            return vec![];
        };
        blocks
            .into_iter()
            .map(|recovered| {
                let mut header = packet.header.clone();
                header.payload_type = recovered.block.payload_type;
                header.timestamp = recovered.block.timestamp;
                header.marker = recovered.marker;
                header.csrc = recovered.csrc;
                if !recovered.block.primary {
                    let back = redundant
                        .iter()
                        .position(|ts| *ts == recovered.block.timestamp)
                        .map_or(1, |i| redundant.len() - i);
                    header.sequence_number = header.sequence_number.wrapping_sub(back as u16);
                    // The extensions and padding were the RED packet's.
                    header.extension = false;
                    header.extensions.clear();
                    header.extension_profile = 0;
                }
                header.padding = false;
                rtp::Packet {
                    header,
                    payload: recovered.block.data,
                }
            })
            .collect()
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for RedAudioInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        let red = match &msg.message.packet {
            Packet::Rtp(packet) => self
                .receivers
                .get(&packet.header.ssrc)
                .is_some_and(|stream| packet.header.payload_type == stream.red_payload_type),
            Packet::Rtcp(_) => false,
        };
        if !red {
            self.read_queue.push_back(msg);
            return Ok(());
        }
        let Packet::Rtp(packet) = &msg.message.packet else {
            return Ok(());
        };
        let Some(stream) = self.receivers.get_mut(&packet.header.ssrc) else {
            return Ok(());
        };
        // A malformed RED payload, or one whose every block was delivered: nothing goes on.
        for media in Self::take_apart(stream, packet) {
            self.read_queue.push_back(TaggedPacket {
                now: msg.now,
                transport: msg.transport,
                message: crate::AttributedPacket {
                    attributes: msg.message.attributes.clone(),
                    packet: Packet::Rtp(media),
                },
            });
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(packet) = &mut msg.message.packet
            && !packet.payload.is_empty()
            && let Some(stream) = self.senders.get_mut(&packet.header.ssrc)
            && packet.header.payload_type == stream.primary_payload_type
        {
            // The receiver numbers a recovered block one packet back per block (RFC 2198
            // section 4 leaves the sequence number of redundant data to it): a copy goes only
            // into the packet right after the one it was the primary of.
            if stream
                .last_sequence_number
                .is_some_and(|last| last.wrapping_add(1) != packet.header.sequence_number)
            {
                stream.encoder.reset();
            }
            stream.last_sequence_number = Some(packet.header.sequence_number);
            // A primary that does not fit a RED payload goes as it is.
            if let Ok(red) = stream.encoder.encode_rtp(stream.red_payload_type, packet) {
                *packet = red;
            }
        }
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, _now: Self::Time) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }
}

impl Interceptor for RedAudioInterceptor {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        match negotiated_red(info, info.payload_type) {
            Some(red_payload_type) => {
                let stream = self.senders.entry(info.ssrc).or_insert(SendStream {
                    red_payload_type,
                    primary_payload_type: info.payload_type,
                    encoder: RedEncoder::new(self.config.redundancy, self.config.max_payload_size),
                    last_sequence_number: None,
                });
                if (stream.red_payload_type, stream.primary_payload_type)
                    != (red_payload_type, info.payload_type)
                {
                    stream.red_payload_type = red_payload_type;
                    stream.primary_payload_type = info.payload_type;
                    stream.encoder.reset();
                }
            }
            None => {
                self.senders.remove(&info.ssrc);
            }
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.senders.remove(&info.ssrc);
    }

    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        match negotiated_red(info, info.payload_type) {
            Some(red_payload_type) => {
                self.receivers
                    .entry(info.ssrc)
                    .or_insert(ReceiveStream {
                        red_payload_type,
                        decoder: RedDecoder::default(),
                    })
                    .red_payload_type = red_payload_type;
            }
            None => {
                self.receivers.remove(&info.ssrc);
            }
        }
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.receivers.remove(&info.ssrc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttributedPacket, TaggedPacket};
    use bytes::Bytes;
    use shared::TransportContext;

    const OPUS: u8 = 111;
    const RED: u8 = 63;

    fn info(ssrc: u32, red_fmtp: &str) -> StreamInfo {
        StreamInfo {
            ssrc,
            payload_type: OPUS,
            mime_type: "audio/opus".to_owned(),
            clock_rate: 48_000,
            channels: 2,
            section_mime_types: vec![
                (OPUS, "audio/opus".to_owned()),
                (RED, "audio/red".to_owned()),
            ],
            section_fmtp_lines: vec![
                (OPUS, "minptime=10;useinbandfec=1".to_owned()),
                (RED, red_fmtp.to_owned()),
            ],
            ..Default::default()
        }
    }

    fn opus(ssrc: u32, sequence_number: u16, payload: &'static [u8]) -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    ssrc,
                    payload_type: OPUS,
                    sequence_number,
                    timestamp: u32::from(sequence_number) * 960,
                    marker: sequence_number == 1,
                    ..Default::default()
                },
                payload: Bytes::from_static(payload),
            })),
        }
    }

    fn rtp(msg: TaggedPacket) -> rtp::Packet {
        match msg.message.packet {
            Packet::Rtp(packet) => packet,
            Packet::Rtcp(_) => panic!("RTP expected"),
        }
    }

    /// RFC 2198 sections 3 and 4 through one sender and one receiver: the sender wraps each
    /// Opus packet with a copy of the one before; the receiver gives back each primary, and,
    /// for the packet lost on the way, the copy the next packet carried, with its sequence
    /// number and timestamp and no marker.
    #[test]
    fn red_packets_carry_the_previous_primary_and_recover_a_loss() {
        let mut sender = RedAudioBuilder::new().build();
        let mut receiver = RedAudioBuilder::new().build();
        sender.bind_local_stream(&info(1, "111/111"));
        receiver.bind_remote_stream(&info(1, "111/111"));

        let payloads: [&'static [u8]; 4] = [b"one", b"two", b"three", b"four"];
        let mut wire = vec![];
        for (i, payload) in payloads.iter().enumerate() {
            sender.handle_write(opus(1, i as u16 + 1, payload)).unwrap();
            let red = rtp(sender.poll_write().unwrap());
            assert_eq!(red.header.payload_type, RED);
            assert_eq!(red.header.sequence_number, i as u16 + 1);
            let blocks = RedPacket::parse(&red.payload).unwrap();
            assert_eq!(blocks.primary().data.as_ref(), *payload);
            assert_eq!(blocks.redundant().len(), usize::from(i > 0));
            wire.push(red);
        }
        // The third packet is lost.
        let mut delivered = vec![];
        for (i, red) in wire.into_iter().enumerate() {
            if i == 2 {
                continue;
            }
            receiver
                .handle_read(TaggedPacket {
                    now: Instant::now(),
                    transport: TransportContext::default(),
                    message: AttributedPacket::new(Packet::Rtp(red)),
                })
                .unwrap();
            while let Some(out) = receiver.poll_read() {
                delivered.push(rtp(out));
            }
        }
        let got: Vec<(u16, u32, u8, bool, &[u8])> = delivered
            .iter()
            .map(|p| {
                (
                    p.header.sequence_number,
                    p.header.timestamp,
                    p.header.payload_type,
                    p.header.marker,
                    p.payload.as_ref(),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                (1, 960, OPUS, true, b"one".as_ref()),
                (2, 1920, OPUS, false, b"two".as_ref()),
                (3, 2880, OPUS, false, b"three".as_ref()),
                (4, 3840, OPUS, false, b"four".as_ref()),
            ]
        );
    }

    /// Only a stream whose section negotiated a RED format of its own encoding is touched: a
    /// stream without one, and a packet of another payload type, pass as they are.
    #[test]
    fn without_a_negotiated_red_format_packets_pass_unchanged() {
        let mut sender = RedAudioBuilder::new().build();
        sender.bind_local_stream(&StreamInfo {
            section_mime_types: vec![(OPUS, "audio/opus".to_owned())],
            section_fmtp_lines: vec![(OPUS, String::new())],
            ..info(1, "")
        });
        sender.bind_local_stream(&info(2, "0/0"));
        sender.bind_local_stream(&info(3, "111/111"));
        for ssrc in [1, 2] {
            sender.handle_write(opus(ssrc, 1, b"x")).unwrap();
            assert_eq!(rtp(sender.poll_write().unwrap()).header.payload_type, OPUS);
        }
        let mut dtmf = opus(3, 1, b"x");
        if let Packet::Rtp(p) = &mut dtmf.message.packet {
            p.header.payload_type = 126;
        }
        sender.handle_write(dtmf).unwrap();
        assert_eq!(rtp(sender.poll_write().unwrap()).header.payload_type, 126);
    }
}
