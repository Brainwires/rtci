//! Send-side ULPFEC: protects outgoing media, in RED or as a stream of its own.

use super::encoder::{ProtectionLevel, RTP_FIXED_HEADER, UlpfecEncoder, wire_image};
use super::header::LONG_MASK_BITS;
use super::red;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{AttributedPacket, Packet, TaggedPacket};
use bytes::Bytes;
use sansio::Protocol;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use super::encoder::UlpfecStreamPacketizer;

/// Media packets gathered before FEC is produced for them.
pub const ULPFEC_DEFAULT_NUM_MEDIA_PACKETS: usize = 5;

/// FEC packets produced per block of media.
pub const ULPFEC_DEFAULT_NUM_FEC_PACKETS: usize = 1;

/// Where FEC data goes in a RED stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RedPlacement {
    /// A RED packet of its own, whose only block has the FEC payload type. It takes the next
    /// sequence number of the media stream. What libwebrtc sends and expects.
    #[default]
    OwnPacket,
    /// A redundant block in the next media packet, ahead of its primary block, as in RFC 5109
    /// 10.3: FEC is never sent by itself. The media stream's sequence numbers are untouched. A
    /// redundant block holds at most 1023 octets, so FEC data longer than that (protection of
    /// full-size video packets) still goes in a packet of its own.
    WithNextMedia,
}

/// Which streams an interceptor protects.
pub(crate) type StreamFilter = Arc<dyn Fn(&StreamInfo) -> bool + Send + Sync>;

/// The default choice: video streams, the only kind `ulpfec` is negotiated for in WebRTC.
pub(crate) fn video_streams() -> StreamFilter {
    Arc::new(|info: &StreamInfo| {
        info.mime_type
            .get(..6)
            .is_some_and(|kind| kind.eq_ignore_ascii_case("video/"))
    })
}

/// How the FEC travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Carriage {
    Red {
        red_payload_type: u8,
        fec_payload_type: u8,
    },
    Stream,
}

/// Builder for [`UlpfecSendInterceptor`].
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Registry, Slot, UlpfecSendBuilder};
///
/// // `a=rtpmap:116 red/90000`, `a=rtpmap:117 ulpfec/90000`
/// let chain = Registry::new()
///     .with(Slot::FecEncoder, UlpfecSendBuilder::red(116, 117).build())
///     .build();
/// ```
pub struct UlpfecSendBuilder {
    carriage: Carriage,
    placement: RedPlacement,
    num_media_packets: usize,
    num_fec_packets: usize,
    level_lengths: Vec<u16>,
    one_level_only: bool,
    flush_on_marker: bool,
    initial_fec_sequence_number: Option<u16>,
    filter: StreamFilter,
}

impl UlpfecSendBuilder {
    fn new(carriage: Carriage) -> Self {
        Self {
            carriage,
            placement: RedPlacement::default(),
            num_media_packets: ULPFEC_DEFAULT_NUM_MEDIA_PACKETS,
            num_fec_packets: ULPFEC_DEFAULT_NUM_FEC_PACKETS,
            level_lengths: Vec::new(),
            one_level_only: false,
            flush_on_marker: false,
            initial_fec_sequence_number: None,
            filter: video_streams(),
        }
    }

    /// FEC as a redundant encoding (RFC 5109 14.2): every packet of a protected stream leaves as
    /// a RED packet of `red_payload_type`, and FEC data has `fec_payload_type`. Both come from
    /// the negotiated `a=rtpmap` lines (`red`, `ulpfec`).
    pub fn red(red_payload_type: u8, fec_payload_type: u8) -> Self {
        Self::new(Carriage::Red {
            red_payload_type: red_payload_type & 0x7F,
            fec_payload_type: fec_payload_type & 0x7F,
        })
    }

    /// FEC as a stream of its own (RFC 5109 14.1), on the repair SSRC and payload type of
    /// [`StreamInfo::ssrc_fec`] / [`StreamInfo::payload_type_fec`]. A stream without both is not
    /// protected. See [`UlpfecStreamPacketizer`] for why this is not the media SSRC.
    pub fn stream() -> Self {
        Self::new(Carriage::Stream)
    }

    /// Where FEC data goes in a RED stream. Ignored for a separate stream.
    pub fn with_red_placement(mut self, placement: RedPlacement) -> Self {
        self.placement = placement;
        self
    }

    /// How many media packets one block of FEC protects, 1 to 48 (the long mask's reach).
    pub fn with_num_media_packets(mut self, num_media_packets: usize) -> Self {
        self.num_media_packets = num_media_packets.clamp(1, LONG_MASK_BITS);
        self
    }

    /// How many FEC packets each block produces. The block's packets are dealt to them in turn,
    /// so `n` FEC packets recover a burst of up to `n` losses. Zero sends no FEC.
    pub fn with_num_fec_packets(mut self, num_fec_packets: usize) -> Self {
        self.num_fec_packets = num_fec_packets;
        self
    }

    /// Protection lengths of the levels, level 0 first, for uneven protection: level 0 covers the
    /// first `lengths[0]` octets after the fixed RTP header, level 1 the next `lengths[1]`, and
    /// so on; what lies beyond the last level is not protected.
    ///
    /// Empty, the default, is one level as long as the block's longest packet: full protection.
    pub fn with_level_lengths(mut self, lengths: impl Into<Vec<u16>>) -> Self {
        self.level_lengths = lengths.into();
        self
    }

    /// Use one level only, whatever [`with_level_lengths`](Self::with_level_lengths) says: for a
    /// stream whose `ulpfec` format carries `onelevelonly=1` (RFC 5109 13). See
    /// [`one_level_only_from_fmtp`](super::one_level_only_from_fmtp).
    pub fn with_one_level_only(mut self, one_level_only: bool) -> Self {
        self.one_level_only = one_level_only;
        self
    }

    /// Also close a block at a packet with the marker bit (the last packet of a video frame), so
    /// FEC never waits for the next frame.
    pub fn with_flush_on_marker(mut self, flush_on_marker: bool) -> Self {
        self.flush_on_marker = flush_on_marker;
        self
    }

    /// The first sequence number of a separate FEC stream. Random when not set, as an RTP
    /// stream's is (RFC 3550 5.1); a test pins it.
    pub fn with_initial_fec_sequence_number(mut self, sequence_number: u16) -> Self {
        self.initial_fec_sequence_number = Some(sequence_number);
        self
    }

    /// Which bound local streams are protected. The default is every `video/` stream.
    pub fn with_stream_filter(
        mut self,
        filter: impl Fn(&StreamInfo) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.filter = Arc::new(filter);
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> UlpfecSendInterceptor {
        let mut level_lengths = self.level_lengths;
        if self.one_level_only {
            level_lengths.truncate(1);
        }
        UlpfecSendInterceptor {
            carriage: self.carriage,
            placement: self.placement,
            num_media_packets: self.num_media_packets,
            num_fec_packets: self.num_fec_packets,
            level_lengths,
            flush_on_marker: self.flush_on_marker,
            initial_fec_sequence_number: self.initial_fec_sequence_number,
            filter: self.filter,
            streams: HashMap::new(),
            sequence_offsets: HashMap::new(),
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

/// One protected media stream.
struct ProtectedStream {
    /// The packets of the block being gathered, as protected: sequence number and wire image.
    block: Vec<(u16, Bytes)>,
    /// RED, [`RedPlacement::WithNextMedia`]: FEC payloads waiting for the next media packet.
    pending: VecDeque<Bytes>,
    /// Separate stream: the FEC stream's packetizer.
    packetizer: Option<UlpfecStreamPacketizer>,
    /// The sequence number of the last packet sent on the media SSRC, media or FEC.
    last_wire_sequence: u16,
}

/// Produces ULPFEC (RFC 5109) for outgoing media.
///
/// # RED carriage
///
/// Each media packet of a protected stream is rewritten into a RED packet: the payload gains the
/// one-octet primary block header naming the media payload type, and the RTP payload type becomes
/// RED's. FEC is computed over the packets as they would be without RED (the *virtual* packets
/// of RFC 5109 14.2) and with the sequence numbers they have on the wire.
///
/// With [`RedPlacement::OwnPacket`] a FEC packet takes a sequence number of the media stream, so
/// every later media packet of the stream is sent with its sequence number moved up by the number
/// of FEC packets sent so far. The NACK responder sits wire-ward of this interceptor and buffers
/// what is on the wire, so a NACK, which names wire sequence numbers, is answered correctly. The
/// marker bit of the media packet is kept on the RED packet, as browsers do; RFC 2198 has no
/// field for it otherwise.
///
/// # Where it belongs
///
/// [`Slot::FecEncoder`](crate::Slot::FecEncoder): application-ward of the pacer and the
/// transport-wide numbering, so FEC is paced, numbered and recorded as the bytes on the wire it
/// is.
pub struct UlpfecSendInterceptor {
    carriage: Carriage,
    placement: RedPlacement,
    num_media_packets: usize,
    num_fec_packets: usize,
    level_lengths: Vec<u16>,
    flush_on_marker: bool,
    initial_fec_sequence_number: Option<u16>,
    filter: StreamFilter,
    /// Keyed by the media SSRC.
    streams: HashMap<u32, ProtectedStream>,
    /// FEC packets inserted so far into each media stream's sequence space. Kept apart from
    /// `streams` so a stream that is unbound and bound again continues where it was: going back
    /// would reuse sequence numbers already on the wire.
    sequence_offsets: HashMap<u32, u16>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl UlpfecSendInterceptor {
    /// The media SSRCs currently being protected.
    pub fn protected_streams(&self) -> impl Iterator<Item = u32> + '_ {
        self.streams.keys().copied()
    }

    /// The FEC payloads for a full block, each protecting every `count`-th packet.
    fn encode_block(&self, block: &[(u16, Bytes)]) -> Vec<Bytes> {
        let count = self.num_fec_packets.min(block.len());
        if count == 0 {
            return Vec::new();
        }
        let images: HashMap<u16, Bytes> = block.iter().cloned().collect();
        let encoder = UlpfecEncoder::new();
        let mut out = Vec::with_capacity(count);
        for index in 0..count {
            let sequences: Vec<u16> = block
                .iter()
                .enumerate()
                .filter(|(position, _)| position % count == index)
                .map(|(_, (sequence, _))| *sequence)
                .collect();
            let levels: Vec<ProtectionLevel> = if self.level_lengths.is_empty() {
                let longest = sequences
                    .iter()
                    .map(|sequence| images[sequence].len() - RTP_FIXED_HEADER)
                    .max()
                    .unwrap_or(0);
                vec![ProtectionLevel::new(longest as u16, sequences)]
            } else {
                self.level_lengths
                    .iter()
                    .map(|length| ProtectionLevel::new(*length, sequences.clone()))
                    .collect()
            };
            // A block the encoder refuses (a gap in the sequence numbers wider than a mask)
            // goes unprotected rather than half-described.
            if let Ok(fec) = encoder.encode_images(&images, &levels) {
                out.push(fec.marshal());
            }
        }
        out
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for UlpfecSendInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        let Packet::Rtp(rtp_packet) = &mut msg.message.packet else {
            self.write_queue.push_back(msg);
            return Ok(());
        };
        let ssrc = rtp_packet.header.ssrc;
        if !self.streams.contains_key(&ssrc) {
            self.write_queue.push_back(msg);
            return Ok(());
        }
        let now = msg.now;
        let transport = msg.transport;

        // The sequence number this packet has on the wire.
        if let Some(offset) = self.sequence_offsets.get(&ssrc) {
            rtp_packet.header.sequence_number =
                rtp_packet.header.sequence_number.wrapping_add(*offset);
        }

        // A packet the application already built as RED, or as FEC, is not ours to protect.
        let foreign = match self.carriage {
            Carriage::Red {
                red_payload_type,
                fec_payload_type,
            } => {
                rtp_packet.header.payload_type == red_payload_type
                    || rtp_packet.header.payload_type == fec_payload_type
            }
            Carriage::Stream => false,
        };
        if foreign {
            if let Some(stream) = self.streams.get_mut(&ssrc) {
                stream.last_wire_sequence = rtp_packet.header.sequence_number;
            }
            self.write_queue.push_back(msg);
            return Ok(());
        }
        // A packet that cannot be protected (it does not serialise) still leaves.
        let Ok(image) = wire_image(rtp_packet) else {
            self.write_queue.push_back(msg);
            return Ok(());
        };

        let sequence_number = rtp_packet.header.sequence_number;
        let timestamp = rtp_packet.header.timestamp;
        let marker = rtp_packet.header.marker;

        let Some(stream) = self.streams.get_mut(&ssrc) else {
            self.write_queue.push_back(msg);
            return Ok(());
        };
        stream.block.push((sequence_number, image));
        stream.last_wire_sequence = sequence_number;
        if let Some(packetizer) = stream.packetizer.as_mut() {
            packetizer.on_media(timestamp, now);
        }

        // RED: the media packet becomes the primary block, behind any FEC waiting for a ride.
        if let Carriage::Red {
            red_payload_type,
            fec_payload_type,
        } = self.carriage
        {
            let pending: Vec<Bytes> = stream.pending.drain(..).collect();
            let redundant: Vec<(u8, u16, &[u8])> = pending
                .iter()
                .map(|fec| (fec_payload_type, 0u16, &fec[..]))
                .collect();
            // Pending blocks were checked against the block length limit when they were queued.
            if let Ok(payload) = red::write(
                &redundant,
                rtp_packet.header.payload_type,
                &rtp_packet.payload,
            ) {
                rtp_packet.payload = payload;
                rtp_packet.header.payload_type = red_payload_type;
            }
        }

        let block =
            if stream.block.len() >= self.num_media_packets || (self.flush_on_marker && marker) {
                std::mem::take(&mut stream.block)
            } else {
                Vec::new()
            };

        // The media packet goes first; the FEC protects what has already left.
        self.write_queue.push_back(msg);
        if block.is_empty() {
            return Ok(());
        }

        let fec_payloads = self.encode_block(&block);
        let Some(stream) = self.streams.get_mut(&ssrc) else {
            return Ok(());
        };
        for fec in fec_payloads {
            let packet = match self.carriage {
                Carriage::Stream => {
                    let Some(packetizer) = stream.packetizer.as_mut() else {
                        continue;
                    };
                    // Already serialised; parse errors cannot happen for our own output.
                    let Ok(parsed) = super::header::UlpfecPacket::parse(&fec) else {
                        continue;
                    };
                    packetizer.packetize(&parsed, now)
                }
                Carriage::Red {
                    red_payload_type,
                    fec_payload_type,
                } => {
                    if self.placement == RedPlacement::WithNextMedia
                        && fec.len() <= red::MAX_REDUNDANT_BLOCK
                    {
                        stream.pending.push_back(fec);
                        continue;
                    }
                    let Ok(payload) = red::write(&[], fec_payload_type, &fec) else {
                        continue;
                    };
                    // The next sequence number of the media stream: one past the last packet
                    // sent on it, media or FEC.
                    let offset = self.sequence_offsets.entry(ssrc).or_insert(0);
                    *offset = offset.wrapping_add(1);
                    stream.last_wire_sequence = stream.last_wire_sequence.wrapping_add(1);
                    rtp::Packet {
                        header: rtp::header::Header {
                            version: 2,
                            marker: false,
                            payload_type: red_payload_type,
                            sequence_number: stream.last_wire_sequence,
                            timestamp,
                            ssrc,
                            ..Default::default()
                        },
                        payload,
                    }
                }
            };
            self.write_queue.push_back(TaggedPacket {
                now,
                transport,
                message: AttributedPacket::new(Packet::Rtp(packet)),
            });
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }
}

impl Interceptor for UlpfecSendInterceptor {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        if !(self.filter)(info) {
            return;
        }
        let packetizer = match self.carriage {
            Carriage::Red { .. } => None,
            Carriage::Stream => {
                // Both halves or neither, as for FlexFEC: a repair SSRC with no payload type has
                // nothing to mark its packets with, and the reverse has nowhere to send them.
                let (Some(ssrc_fec), Some(payload_type_fec)) =
                    (info.ssrc_fec, info.payload_type_fec)
                else {
                    return;
                };
                Some(UlpfecStreamPacketizer::new(
                    payload_type_fec,
                    ssrc_fec,
                    info.clock_rate,
                    self.initial_fec_sequence_number
                        .unwrap_or_else(rand::random),
                ))
            }
        };
        self.streams.insert(
            info.ssrc,
            ProtectedStream {
                block: Vec::new(),
                pending: VecDeque::new(),
                packetizer,
                last_wire_sequence: 0,
            },
        );
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        // A partly filled block goes with it: its packets have left, and FEC for a stream that
        // has stopped has nothing left to repair. The sequence offset stays.
        self.streams.remove(&info.ssrc);
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}
