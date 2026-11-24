//! Redundant audio data, RED (RFC 2198), for the audio streams whose m= section negotiated a
//! RED format (`a=rtpmap:<pt> red/48000/2`, `a=fmtp:<pt> 111/111`).
//!
//! RFC 8854 section 4.2 has a WebRTC endpoint support RED for audio; Chromium and WebKit
//! offer it with Opus as both the primary and the redundant encoding (the fmtp lists the Opus
//! payload type twice), the form RFC 2198 section 3 allows ("a copy of the primary MAY be
//! used as the redundancy").
//!
//! - **Send, when.** Negotiating RED does not by itself make the sender use it
//!   ([`AudioRedundancy`], [`RedAudioBuilder::with_audio_redundancy`]). By default a local
//!   stream is sent in RED only when its remote description lists the RED format ahead of the
//!   stream's primary encoding: RFC 3264 sections 5.1 and 6.1 have the formats of an m= line
//!   "listed in order of preference", and the sender "SHOULD use the format with the highest
//!   preference"; RFC 2198 section 5 reads a section that leads with `red` as "the sender will
//!   send redundancy by default, but also may send" the others. libwebrtc decides the same way
//!   (`WebRtcVoiceSendChannel::SetSendCodecs`: "RED codec needs to be negotiated before the
//!   actual codec they reference"), and Chromium and WebKit list RED after Opus, in their
//!   offers and their answers alike, so neither they nor this engine send it between each
//!   other by default. RFC 8854 section 4.1 recommends Opus's own in-band FEC over RED for
//!   Opus, and section 8 has FEC sent only for the loss observed or when the application asks:
//!   [`AudioRedundancy::Always`] is that request.
//! - **Send, how.** A packet of a local stream sent in RED, whose payload type is the primary
//!   of the negotiated RED format, leaves as a RED packet: the RED payload type in the header,
//!   the copies of the last [`RedAudioBuilder::with_redundancy`] primaries (one by default, as
//!   Chromium sends) before the new primary, the header otherwise the primary's (RFC 2198
//!   section 3). A primary too large to be wrapped, or of another payload type (comfort noise,
//!   DTMF), leaves as it is: the receiver negotiated it too.
//! - **Receive.** A RED packet of a remote stream is taken apart into the packets of its
//!   blocks (RFC 2198 section 4): the primary with the RED packet's sequence number, marker
//!   and CSRCs, and the earlier primaries a lost packet carried, recovered from the redundant
//!   blocks with the sequence numbers they had (one packet per block, as the encoder above and
//!   Chromium send them), no marker ("the marker bit ... is lost") and the RED packet's CSRCs.
//!   Nothing is delivered twice (`RedDecoder`). What arrives after this interceptor (the NACK
//!   generator, the jitter buffer, the application) sees the primary encoding only. Received
//!   RED is taken apart whatever the [`AudioRedundancy`] setting: the setting is about what
//!   this side sends, and RFC 8854 section 7 has an endpoint "receive and make use of" the FEC
//!   formats it indicated.
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

/// When a local audio stream whose section negotiated RED (RFC 2198) is sent in RED. Received
/// RED is taken apart in every case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AudioRedundancy {
    /// In RED when the remote description lists the RED format ahead of the stream's primary
    /// encoding, the remote side's preference (RFC 3264 sections 5.1 and 6.1; libwebrtc's
    /// rule too). Chromium and WebKit list it after Opus, so a call with them carries plain
    /// Opus. The default.
    #[default]
    WhenPreferred,
    /// In RED whenever RED is negotiated, whatever its place on the m= line: the application's
    /// request for redundancy (RFC 8854 section 8). Each packet then carries a copy of the
    /// one before, about doubling the audio bitrate.
    Always,
    /// Never in RED, even when the remote side prefers it (RFC 3264's "SHOULD" set aside).
    Never,
}

/// Builder for [`RedAudioInterceptor`].
#[derive(Debug, Clone)]
pub struct RedAudioBuilder {
    redundancy: usize,
    max_payload_size: usize,
    audio_redundancy: AudioRedundancy,
}

impl Default for RedAudioBuilder {
    fn default() -> Self {
        Self {
            redundancy: RED_AUDIO_DEFAULT_REDUNDANCY,
            max_payload_size: RED_AUDIO_DEFAULT_MAX_PAYLOAD_SIZE,
            audio_redundancy: AudioRedundancy::default(),
        }
    }
}

impl RedAudioBuilder {
    /// One earlier primary per packet, payloads of at most
    /// [`RED_AUDIO_DEFAULT_MAX_PAYLOAD_SIZE`] octets, sent in RED when the remote side prefers
    /// it ([`AudioRedundancy::WhenPreferred`]).
    pub fn new() -> Self {
        Self::default()
    }

    /// When a local stream that negotiated RED is sent in RED; see [`AudioRedundancy`].
    pub fn with_audio_redundancy(mut self, audio_redundancy: AudioRedundancy) -> Self {
        self.audio_redundancy = audio_redundancy;
        self
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
    /// The ids of the stream's audio level extensions (RFC 6464 `ssrc-audio-level`, RFC 6465
    /// `csrc-audio-level`): what a packet rebuilt from a redundant block takes from the RED
    /// packet that carried it, as an approximation (RFC 8854 section 4.1).
    level_extensions: Vec<u8>,
}

/// The ids `info` negotiated the audio level extensions under.
fn level_extension_ids(info: &StreamInfo) -> Vec<u8> {
    info.rtp_header_extensions
        .iter()
        .filter(|extension| {
            extension.uri == rtp::extension::AUDIO_LEVEL_URI
                || extension.uri == rtp::extension::CSRC_AUDIO_LEVEL_URI
        })
        .filter_map(|extension| u8::try_from(extension.id).ok())
        .collect()
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

/// Whether the stream's section lists the RED format `red` ahead of the stream's own payload
/// type: the remote side prefers redundancy (RFC 3264 sections 5.1 and 6.1). The section's
/// formats are in the order of the m= line of the description whose numbering the stream
/// uses, the remote one for a local stream.
fn red_is_preferred(info: &StreamInfo, red: u8) -> bool {
    let position = |payload_type: u8| {
        info.section_mime_types
            .iter()
            .position(|(pt, _)| *pt == payload_type)
    };
    matches!(
        (position(red), position(info.payload_type)),
        (Some(red), Some(primary)) if red < primary
    )
}

impl RedAudioInterceptor {
    /// The RED payload type a local stream is sent with under the builder's
    /// [`AudioRedundancy`], or `None` to send it as it is.
    fn red_to_send(&self, info: &StreamInfo) -> Option<u8> {
        let red = negotiated_red(info, info.payload_type)?;
        match self.config.audio_redundancy {
            AudioRedundancy::Always => Some(red),
            AudioRedundancy::WhenPreferred => red_is_preferred(info, red).then_some(red),
            AudioRedundancy::Never => None,
        }
    }

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
                    // The extensions and padding were the RED packet's. RFC 8854 section 4.1:
                    // the header parts RED cannot recover, "RTP header extensions like those
                    // specified in [RFC6464] and [RFC6465]", are approximated "using an
                    // approach similar to those described in [RFC2198], Section 4": as RFC
                    // 2198 applies the RED packet's CSRCs to the rebuilt data, the rebuilt
                    // packet takes the RED packet's audio levels (one packet later in time,
                    // the nearest measure there is). Every other extension is left out.
                    let levels: Vec<(u8, bytes::Bytes)> = stream
                        .level_extensions
                        .iter()
                        .filter_map(|id| packet.header.get_extension(*id).map(|v| (*id, v)))
                        .collect();
                    header.extension = false;
                    header.extensions.clear();
                    header.extension_profile = 0;
                    header.extensions_padding = 0;
                    for (id, value) in levels {
                        // The RED packet carried it in this form, so it fits.
                        let _ = header.set_extension(id, value);
                    }
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
        match self.red_to_send(info) {
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
                let stream = self.receivers.entry(info.ssrc).or_insert(ReceiveStream {
                    red_payload_type,
                    decoder: RedDecoder::default(),
                    level_extensions: vec![],
                });
                stream.red_payload_type = red_payload_type;
                stream.level_extensions = level_extension_ids(info);
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

    /// A stream whose section lists Opus, then RED (Chromium's and WebKit's order).
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

    /// [`info`] with RED listed ahead of Opus: the remote side prefers redundancy.
    fn info_red_first(ssrc: u32, red_fmtp: &str) -> StreamInfo {
        let mut info = info(ssrc, red_fmtp);
        info.section_mime_types.reverse();
        info.section_fmtp_lines.reverse();
        info
    }

    /// The payload type the first packet of a fresh stream leaves `sender` with.
    fn sent_payload_type(sender: &mut RedAudioInterceptor, ssrc: u32) -> u8 {
        sender.handle_write(opus(ssrc, 1, b"x")).unwrap();
        rtp(sender.poll_write().unwrap()).header.payload_type
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

    /// RFC 2198 sections 3 and 4 through one sender and one receiver: the sender, whose remote
    /// side lists RED first, wraps each Opus packet with a copy of the one before; the receiver
    /// gives back each primary, and, for the packet lost on the way, the copy the next packet
    /// carried, with its sequence number and timestamp and no marker.
    #[test]
    fn red_packets_carry_the_previous_primary_and_recover_a_loss() {
        let mut sender = RedAudioBuilder::new().build();
        let mut receiver = RedAudioBuilder::new().build();
        sender.bind_local_stream(&info_red_first(1, "111/111"));
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

    /// Sends `payloads` through `sender`, each RED packet given header extensions by `extend`,
    /// loses the packets at `lost` (indices) and returns what `receiver` delivered.
    fn through(
        sender: &mut RedAudioInterceptor,
        receiver: &mut RedAudioInterceptor,
        payloads: &[&'static [u8]],
        lost: &[usize],
        extend: impl Fn(usize, &mut rtp::header::Header),
    ) -> Vec<rtp::Packet> {
        let mut delivered = vec![];
        for (i, payload) in payloads.iter().enumerate() {
            sender.handle_write(opus(1, i as u16 + 1, payload)).unwrap();
            let mut red = rtp(sender.poll_write().unwrap());
            extend(i, &mut red.header);
            if lost.contains(&i) {
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
        delivered
    }

    /// RFC 8854 section 4.1: "the recommended mechanisms do not allow recovery of parts of the
    /// RTP header that may be important in certain audio applications, e.g., CSRCs and RTP
    /// header extensions like those specified in [RFC6464] and [RFC6465]. Implementations
    /// SHOULD account for this and attempt to approximate this information, using an approach
    /// similar to those described in [RFC2198], Section 4". A packet rebuilt from a redundant
    /// block takes the audio levels of the RED packet that carried it (as RFC 2198 section 4
    /// applies that packet's CSRCs), and no other extension of it.
    #[test]
    fn a_rebuilt_packet_takes_the_audio_levels_of_the_red_packet_that_carried_it() {
        const LEVEL: u8 = 1;
        const CSRC_LEVELS: u8 = 2;
        const OTHER: u8 = 3;
        let mut sender = RedAudioBuilder::new().build();
        let mut receiver = RedAudioBuilder::new().build();
        sender.bind_local_stream(&info_red_first(1, "111/111"));
        let mut remote = info(1, "111/111");
        for (uri, id) in [
            (rtp::extension::AUDIO_LEVEL_URI, LEVEL),
            (rtp::extension::CSRC_AUDIO_LEVEL_URI, CSRC_LEVELS),
            (
                "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
                OTHER,
            ),
        ] {
            remote
                .rtp_header_extensions
                .push(crate::RTPHeaderExtension {
                    uri: uri.to_owned(),
                    id: u16::from(id),
                });
        }
        receiver.bind_remote_stream(&remote);

        let payloads: [&'static [u8]; 4] = [b"one", b"two", b"three", b"four"];
        let delivered = through(&mut sender, &mut receiver, &payloads, &[2], |i, header| {
            header.csrc = vec![77];
            let level = 0x80 | (10 + i as u8);
            header
                .set_extension(LEVEL, Bytes::from(vec![level]))
                .unwrap();
            header
                .set_extension(CSRC_LEVELS, Bytes::from(vec![20 + i as u8]))
                .unwrap();
            header
                .set_extension(OTHER, Bytes::from(vec![1, 2, 3]))
                .unwrap();
        });
        let rebuilt = delivered
            .iter()
            .find(|p| p.header.sequence_number == 3)
            .expect("the lost packet is rebuilt");
        assert_eq!(rebuilt.payload.as_ref(), b"three");
        assert_eq!(
            rebuilt.header.get_extension(LEVEL).as_deref(),
            Some([0x80 | 13].as_ref()),
            "the audio level of the packet that carried it"
        );
        assert_eq!(
            rebuilt.header.get_extension(CSRC_LEVELS).as_deref(),
            Some([23].as_ref())
        );
        assert_eq!(rebuilt.header.csrc, vec![77]);
        assert_eq!(rebuilt.header.get_extension(OTHER), None, "nothing else");
        // The primaries keep their own extensions.
        let primary = delivered
            .iter()
            .find(|p| p.header.sequence_number == 4)
            .unwrap();
        assert_eq!(
            primary.header.get_extension(LEVEL).as_deref(),
            Some([0x80 | 13].as_ref())
        );
        assert!(primary.header.get_extension(OTHER).is_some());
    }

    /// RFC 8854 section 4.1: "if multi-packet protection is needed, the aforementioned
    /// redundant encoding ... SHOULD be used instead". With two redundant blocks per packet
    /// (`with_redundancy(2)`) two consecutive losses are both rebuilt from the packet after
    /// them; with one, only the second of them.
    #[test]
    fn two_redundant_blocks_rebuild_two_consecutive_losses() {
        let payloads: [&'static [u8]; 5] = [b"one", b"two", b"three", b"four", b"five"];
        for (redundancy, rebuilt) in [(2usize, vec![2u16, 3]), (1, vec![3])] {
            let mut sender = RedAudioBuilder::new().with_redundancy(redundancy).build();
            let mut receiver = RedAudioBuilder::new().build();
            sender.bind_local_stream(&info_red_first(1, "111/111/111"));
            receiver.bind_remote_stream(&info(1, "111/111/111"));
            let delivered = through(&mut sender, &mut receiver, &payloads, &[1, 2], |_, _| {});
            let got: Vec<u16> = delivered
                .iter()
                .map(|p| p.header.sequence_number)
                .filter(|seq| [2, 3].contains(seq))
                .collect();
            assert_eq!(got, rebuilt, "redundancy {redundancy}");
            for packet in &delivered {
                assert_eq!(
                    packet.payload.as_ref(),
                    payloads[usize::from(packet.header.sequence_number) - 1]
                );
            }
        }
    }

    /// RFC 8854 section 4.1: "When using constant-bitrate codecs, e.g., PCMU [RFC5391],
    /// redundant encoding MAY be used". A PCMU stream whose section negotiated `red/8000`
    /// naming PCMU (an application's registration: the default codecs offer RED for Opus
    /// only, the clause warning that it "will result in a potentially significant bitrate
    /// increase") is sent in RED and a lost packet comes back from the next one.
    #[test]
    fn a_constant_bitrate_codec_gets_redundancy_when_its_section_negotiated_red() {
        const PCMU: u8 = 0;
        const RED_8K: u8 = 98;
        let pcmu = |red_first: bool| {
            let mut formats = vec![
                (PCMU, "audio/PCMU".to_owned()),
                (RED_8K, "audio/red".to_owned()),
            ];
            if red_first {
                formats.reverse();
            }
            StreamInfo {
                ssrc: 1,
                payload_type: PCMU,
                mime_type: "audio/PCMU".to_owned(),
                clock_rate: 8_000,
                channels: 1,
                section_mime_types: formats,
                section_fmtp_lines: vec![(RED_8K, "0/0".to_owned())],
                ..Default::default()
            }
        };
        let mut sender = RedAudioBuilder::new().build();
        let mut receiver = RedAudioBuilder::new().build();
        sender.bind_local_stream(&pcmu(true));
        receiver.bind_remote_stream(&pcmu(false));
        let mut delivered = vec![];
        for (i, payload) in [b"aaaa", b"bbbb", b"cccc", b"dddd"].iter().enumerate() {
            let mut packet = opus(1, i as u16 + 1, payload.as_slice());
            if let Packet::Rtp(rtp) = &mut packet.message.packet {
                rtp.header.payload_type = PCMU;
                rtp.header.timestamp = u32::from(rtp.header.sequence_number) * 160;
            }
            sender.handle_write(packet).unwrap();
            let red = rtp(sender.poll_write().unwrap());
            assert_eq!(red.header.payload_type, RED_8K);
            if i == 1 {
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
        let got: Vec<(u16, u8, &[u8])> = delivered
            .iter()
            .map(|p| {
                (
                    p.header.sequence_number,
                    p.header.payload_type,
                    p.payload.as_ref(),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                (1, PCMU, b"aaaa".as_ref()),
                (2, PCMU, b"bbbb".as_ref()),
                (3, PCMU, b"cccc".as_ref()),
                (4, PCMU, b"dddd".as_ref()),
            ]
        );
    }

    /// Only a stream whose section negotiated a RED format of its own encoding is touched: a
    /// stream without one, and a packet of another payload type, pass as they are.
    #[test]
    fn without_a_negotiated_red_format_packets_pass_unchanged() {
        let mut sender = RedAudioBuilder::new()
            .with_audio_redundancy(AudioRedundancy::Always)
            .build();
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

    /// RFC 3264 sections 5.1 and 6.1: the formats of an m= line are in order of preference and
    /// the sender "SHOULD use the format with the highest preference". By default
    /// ([`AudioRedundancy::WhenPreferred`]) a stream goes in RED only when its section lists
    /// RED ahead of Opus; `Always` sends RED in either order, `Never` in neither.
    #[test]
    fn red_is_sent_by_the_remote_order_unless_the_application_decides() {
        let cases = [
            (AudioRedundancy::WhenPreferred, false, OPUS),
            (AudioRedundancy::WhenPreferred, true, RED),
            (AudioRedundancy::Always, false, RED),
            (AudioRedundancy::Always, true, RED),
            (AudioRedundancy::Never, false, OPUS),
            (AudioRedundancy::Never, true, OPUS),
        ];
        for (policy, red_first, expected) in cases {
            let mut sender = RedAudioBuilder::new().with_audio_redundancy(policy).build();
            sender.bind_local_stream(&if red_first {
                info_red_first(1, "111/111")
            } else {
                info(1, "111/111")
            });
            assert_eq!(
                sent_payload_type(&mut sender, 1),
                expected,
                "{policy:?}, RED first: {red_first}"
            );
        }
        assert_eq!(
            RedAudioBuilder::new().audio_redundancy,
            AudioRedundancy::WhenPreferred
        );
    }

    /// The setting is about sending: a receiver takes RED apart and recovers a loss from the
    /// next packet's copy whatever its own [`AudioRedundancy`] (RFC 8854 section 7: an endpoint
    /// "MUST be able to receive and make use of" the FEC formats it indicated).
    #[test]
    fn received_red_is_taken_apart_in_every_mode() {
        for policy in [
            AudioRedundancy::WhenPreferred,
            AudioRedundancy::Always,
            AudioRedundancy::Never,
        ] {
            let mut sender = RedAudioBuilder::new()
                .with_audio_redundancy(AudioRedundancy::Always)
                .build();
            let mut receiver = RedAudioBuilder::new().with_audio_redundancy(policy).build();
            sender.bind_local_stream(&info(1, "111/111"));
            // The receiver's section in its own order: Opus first.
            receiver.bind_remote_stream(&info(1, "111/111"));
            let mut delivered = vec![];
            for (seq, payload) in [(1u16, b"one" as &'static [u8]), (2, b"two"), (3, b"three")] {
                sender.handle_write(opus(1, seq, payload)).unwrap();
                let red = rtp(sender.poll_write().unwrap());
                assert_eq!(red.header.payload_type, RED, "{policy:?}");
                if seq == 2 {
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
                    let p = rtp(out);
                    delivered.push((p.header.sequence_number, p.header.payload_type, p.payload));
                }
            }
            assert_eq!(
                delivered,
                vec![
                    (1, OPUS, Bytes::from_static(b"one")),
                    (2, OPUS, Bytes::from_static(b"two")),
                    (3, OPUS, Bytes::from_static(b"three")),
                ],
                "{policy:?}"
            );
        }
    }
}
