//! Receive-side ULPFEC: takes RED apart, recovers lost media, keeps FEC away from the application.

use super::decoder::{UlpfecDecoder, UlpfecDecoderStats};
use super::red::depacketize_red;
use super::sender::{Carriage, StreamFilter, video_streams};
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use bytes::Bytes;
use sansio::Protocol;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

/// Marks an RTP packet that carried only FEC in a RED stream.
///
/// Such a packet has a sequence number of the media stream. The interceptors application-ward of
/// the FEC decoder (the NACK generator, the receiver report, the arrival recorders) count
/// sequence numbers, so the packet is passed on to them, with its payload removed and this
/// attached as [`Attribute::Custom`], instead of being swallowed: swallowed, it would read as a
/// lost media packet and be asked for again. It is not media. Whatever sits at the end of the
/// chain drops it: `rtc`'s peer connection does, and an application driving a chain itself checks
/// `message.custom::<UlpfecRepair>()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UlpfecRepair;

/// Builder for [`UlpfecReceiveInterceptor`].
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Registry, Slot, UlpfecReceiveBuilder};
///
/// // `a=rtpmap:116 red/90000`, `a=rtpmap:117 ulpfec/90000`
/// let chain = Registry::new()
///     .with(Slot::FecDecoder, UlpfecReceiveBuilder::red(116, 117).build())
///     .build();
/// ```
pub struct UlpfecReceiveBuilder {
    carriage: Carriage,
    one_level_only: bool,
    forward_repair: bool,
    filter: StreamFilter,
}

impl UlpfecReceiveBuilder {
    fn new(carriage: Carriage) -> Self {
        Self {
            carriage,
            one_level_only: false,
            forward_repair: true,
            filter: video_streams(),
        }
    }

    /// FEC as a redundant encoding (RFC 5109 14.2): the protected streams arrive as RED packets
    /// of `red_payload_type`, with FEC blocks of `fec_payload_type`.
    pub fn red(red_payload_type: u8, fec_payload_type: u8) -> Self {
        Self::new(Carriage::Red {
            red_payload_type: red_payload_type & 0x7F,
            fec_payload_type: fec_payload_type & 0x7F,
        })
    }

    /// FEC as a stream of its own (RFC 5109 14.1), on the repair SSRC of
    /// [`StreamInfo::ssrc_fec`]. A stream without a repair SSRC and payload type is not bound.
    pub fn stream() -> Self {
        Self::new(Carriage::Stream)
    }

    /// Refuse FEC with more than one protection level: this endpoint signalled `onelevelonly=1`
    /// (RFC 5109 13, 14.3: for a receiver the parameter says what it accepts).
    pub fn with_one_level_only(mut self, one_level_only: bool) -> Self {
        self.one_level_only = one_level_only;
        self
    }

    /// Whether a RED packet that held only FEC is passed on, emptied and marked
    /// [`UlpfecRepair`], so the interceptors behind this one see its sequence number (the
    /// default), or swallowed here.
    pub fn with_repair_forwarding(mut self, forward_repair: bool) -> Self {
        self.forward_repair = forward_repair;
        self
    }

    /// Which bound remote streams are protected. The default is every `video/` stream.
    pub fn with_stream_filter(
        mut self,
        filter: impl Fn(&StreamInfo) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.filter = Arc::new(filter);
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> UlpfecReceiveInterceptor {
        UlpfecReceiveInterceptor {
            carriage: self.carriage,
            one_level_only: self.one_level_only,
            forward_repair: self.forward_repair,
            filter: self.filter,
            decoders: HashMap::new(),
            repair_to_media: HashMap::new(),
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

/// Recovers media lost from streams protected by ULPFEC (RFC 5109).
///
/// # RED carriage
///
/// A RED packet of a protected stream is taken apart (RFC 2198): its primary block goes on as
/// the RTP packet it stands for, with the primary's payload type, which is the *virtual* packet
/// the FEC protects (RFC 5109 14.2); its FEC blocks go to the decoder. A packet of the stream
/// that is not RED passes as it is and is still given to the decoder, since a receiver that
/// accepts RED accepts its encodings bare as well (RFC 2198 5). A bare packet of the FEC payload
/// type on the media SSRC is dropped: FEC is not sent by itself in a RED stream (RFC 5109 14.2).
/// So is a RED packet whose block headers do not fit its length.
///
/// Recovered packets rejoin the read leg marked [`Attribute::RecoveredByFec`].
///
/// # Where it belongs
///
/// [`Slot::FecDecoder`](crate::Slot::FecDecoder): wire-ward of the NACK generator, so a packet
/// that FEC rebuilds is not also asked for.
pub struct UlpfecReceiveInterceptor {
    carriage: Carriage,
    one_level_only: bool,
    forward_repair: bool,
    filter: StreamFilter,
    /// Decoders keyed by the media SSRC they protect.
    decoders: HashMap<u32, UlpfecDecoder>,
    /// Separate stream: repair SSRC (and its payload type) to the media SSRC.
    repair_to_media: HashMap<u32, (u32, u8)>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl UlpfecReceiveInterceptor {
    /// The media SSRCs currently protected.
    pub fn protected_streams(&self) -> impl Iterator<Item = u32> + '_ {
        self.decoders.keys().copied()
    }

    /// The decoder's counters for the media stream `ssrc`.
    pub fn stats(&self, ssrc: u32) -> Option<UlpfecDecoderStats> {
        self.decoders.get(&ssrc).map(UlpfecDecoder::stats)
    }

    fn queue_recovered(
        &mut self,
        now: Instant,
        transport: shared::TransportContext,
        recovered: Vec<rtp::Packet>,
    ) {
        for packet in recovered {
            // Says how it got here: it was never on the wire in this form, so anything measuring
            // the network can tell it from a packet that was.
            let message =
                AttributedPacket::new(Packet::Rtp(packet)).with(Attribute::RecoveredByFec);
            self.read_queue.push_back(TaggedPacket {
                now,
                transport,
                message,
            });
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for UlpfecReceiveInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        let Packet::Rtp(rtp_packet) = &mut msg.message.packet else {
            self.read_queue.push_back(msg);
            return Ok(());
        };
        let ssrc = rtp_packet.header.ssrc;
        let now = msg.now;
        let transport = msg.transport;

        // A packet of a separate FEC stream: to the decoder, and no further. It has an SSRC of
        // its own, so nothing behind this interceptor is waiting for its sequence number.
        if let Some(&(media_ssrc, payload_type_fec)) = self.repair_to_media.get(&ssrc) {
            let recovered = match self.decoders.get_mut(&media_ssrc) {
                Some(decoder) if rtp_packet.header.payload_type == payload_type_fec => {
                    decoder.push_fec(&rtp_packet.payload).unwrap_or_default()
                }
                _ => Vec::new(),
            };
            self.queue_recovered(now, transport, recovered);
            return Ok(());
        }

        let Some(decoder) = self.decoders.get_mut(&ssrc) else {
            self.read_queue.push_back(msg);
            return Ok(());
        };

        let mut recovered = Vec::new();
        if let Carriage::Red {
            red_payload_type,
            fec_payload_type,
        } = self.carriage
        {
            if rtp_packet.header.payload_type == fec_payload_type {
                // FEC by itself in a RED stream (RFC 5109 14.2 forbids it).
                return Ok(());
            }
            if rtp_packet.header.payload_type == red_payload_type {
                let Ok(red) = depacketize_red(&rtp_packet.payload, fec_payload_type) else {
                    return Ok(());
                };
                for fec in &red.fec {
                    recovered.extend(decoder.push_fec(fec).unwrap_or_default());
                }
                match red.primary {
                    Some((payload_type, data)) => {
                        // The virtual RTP packet: the RED packet without its block headers and
                        // redundant data, under the primary's payload type.
                        rtp_packet.header.payload_type = payload_type;
                        rtp_packet.payload = data;
                    }
                    None => {
                        if self.forward_repair {
                            rtp_packet.header.payload_type = fec_payload_type;
                            rtp_packet.payload = Bytes::new();
                            msg.message.add(Attribute::Custom(Arc::new(UlpfecRepair)));
                            self.read_queue.push_back(msg);
                        }
                        self.queue_recovered(now, transport, recovered);
                        return Ok(());
                    }
                }
            }
        }

        // A media packet: the decoder needs it to rebuild its neighbours, and it carries on.
        recovered.extend(decoder.push_media(rtp_packet));
        self.read_queue.push_back(msg);
        self.queue_recovered(now, transport, recovered);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<TaggedPacket> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }
}

impl Interceptor for UlpfecReceiveInterceptor {
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        if !(self.filter)(info) {
            return;
        }
        if self.carriage == Carriage::Stream {
            let (Some(ssrc_fec), Some(payload_type_fec)) = (info.ssrc_fec, info.payload_type_fec)
            else {
                return;
            };
            self.repair_to_media
                .insert(ssrc_fec, (info.ssrc, payload_type_fec));
        }
        self.decoders.insert(
            info.ssrc,
            UlpfecDecoder::new(info.ssrc).with_one_level_only(self.one_level_only),
        );
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.decoders.remove(&info.ssrc);
        self.repair_to_media
            .retain(|_, (media, _)| *media != info.ssrc);
    }

    fn bind_local_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
}
