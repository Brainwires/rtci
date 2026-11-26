//! Receive-side ULPFEC: takes RED apart, recovers lost media, keeps FEC away from the application.

use super::decoder::{UlpfecDecoder, UlpfecDecoderStats};
use super::red::depacketize_red;
use super::sender::{Carriage, StreamFilter, negotiated_carriage, video_streams};
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
/// Such a packet has a sequence number of the media stream. Whoever counts the stream's
/// sequence numbers must see that number as received: the interceptors application-ward of the
/// FEC decoder (the NACK generator, the receiver report, the arrival recorders), and the
/// receiver that puts frames together, for which a number that never arrives is a missing
/// media packet (a frame with one inside it is never complete; one between two frames is
/// waited for). So the packet is passed on, with its payload removed and this attached as
/// [`Attribute::Custom`], instead of being swallowed. It is not media: it goes on as a packet
/// **without a payload**, under the payload type of the stream's media (the primary block of
/// the last media packet; the FEC payload type before any media arrived), with the FEC
/// packet's sequence number, timestamp and no marker. That is what a padding packet of
/// libwebrtc's looks like, and what libwebrtc's own receiver makes of a FEC packet
/// (`video/rtp_video_stream_receiver2.cc:1603-1612` at a222406d, "Notify video_receiver about
/// received FEC packets to avoid NACKing these packets": `NotifyReceiverOfEmptyPacket`, which
/// is `PacketBuffer::InsertPadding` and the NACK module's `OnReceivedPacket`, `:1622-1637`).
/// `rtci`'s peer connection delivers it to the application so; an application driving a chain
/// itself can tell it by `message.custom::<UlpfecRepair>()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UlpfecRepair;

/// Marks an RTP packet as a FEC packet that arrived in a FEC session of its own (RFC 5109
/// section 14.1), for a binder that learns which stream a FEC session protects only as its
/// packets arrive. Carried as [`Attribute::Custom`].
///
/// Whoever drives the chain attaches it to each RTP packet read on a FEC session's transport,
/// beside mapping the packet's SSRC ([`FecSessionSsrcMap`](crate::FecSessionSsrcMap)). The
/// receive interceptor gives such a packet to the decoder of
/// [`media_ssrc`](Self::media_ssrc), if it keeps one (a bound stream that passed the filter,
/// [`UlpfecReceiveBuilder::sessions`] or the RED carriage), and passes it no further. It does
/// the same for a stream bound with [`StreamInfo::fec_session`], which needs no mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecSessionPacket {
    /// The SSRC of the media stream the FEC session's stream protects: the SSRC the packet
    /// had on the FEC session's transport (RFC 5109 section 7.2).
    pub media_ssrc: u32,
    /// The payload type of `ulpfec` in the FEC session's m= section. A packet of the session
    /// with another payload type is not FEC and is discarded (RFC 3550 section 5.1: a
    /// receiver "MUST ignore packets with payload types that it does not understand").
    pub payload_type: u8,
    /// This endpoint signalled `onelevelonly=1` for the session (RFC 5109 section 13): FEC
    /// with more than one level is refused.
    pub one_level_only: bool,
}

/// What the ULPFEC decoder of one protected stream has received and done so far.
///
/// The receive interceptor passes it application-ward as [`Attribute::Custom`] on an empty
/// RTCP packet (a carrier, which the chain's terminus lets through) whenever it changed, so
/// whoever drives the chain can report it: `rtci`'s peer connection puts it in the stream's
/// webrtc-stats `fecPacketsReceived`, `fecBytesReceived` and `fecPacketsDiscarded`. The counts
/// are totals since the stream was bound, so a carrier that is lost loses nothing.
///
/// FEC on a repair SSRC or in a FEC session of its own arrives as packets of its own, which
/// the one who reads them off the wire can count; FEC blocks in RED packets of the media
/// stream (RFC 5109 section 14.2) are known only here, and are counted in
/// [`fec_packets_in_red`](Self::fec_packets_in_red).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct UlpfecReceiveStats {
    /// The protected media stream.
    pub media_ssrc: u32,
    /// FEC blocks that arrived in RED packets of the stream, whatever became of them.
    pub fec_packets_in_red: u64,
    /// Their octets: the FEC header, the level headers and the protected data (the block,
    /// not the RED packet around it).
    pub fec_bytes_in_red: u64,
    /// The decoder's counters: what it took, rebuilt and discarded, from every carriage.
    pub decoder: UlpfecDecoderStats,
}

/// Builder for [`UlpfecReceiveInterceptor`].
///
/// # Example
///
/// ```
/// use rtci_interceptor::{Registry, Slot, UlpfecReceiveBuilder};
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
    decode_every_stream: bool,
    filter: StreamFilter,
    zero_mutable_extensions: bool,
}

impl UlpfecReceiveBuilder {
    fn new(carriage: Carriage) -> Self {
        Self {
            carriage,
            one_level_only: false,
            forward_repair: true,
            decode_every_stream: false,
            filter: video_streams(),
            zero_mutable_extensions: false,
        }
    }

    /// FEC in RTP sessions of their own (RFC 5109 section 14.1), told packet by packet
    /// ([`FecSessionPacket`]): every bound stream that passes the filter has a decoder from
    /// the start, fed with its media, so that the FEC of a session whose protected stream is
    /// only known once packets arrive finds it. A stream bound with a repair flow of the
    /// media's own session ([`StreamInfo::ssrc_fec`]) is read as [`stream`](Self::stream)
    /// reads it.
    pub fn sessions() -> Self {
        let mut builder = Self::new(Carriage::Stream);
        builder.decode_every_stream = true;
        builder
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
    /// [`UlpfecRepair`], so the interceptors behind this one and the receiver that puts frames
    /// together see its sequence number (the default), or swallowed here: its sequence number
    /// is then a missing packet to them.
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

    /// Recover with the values of the transport-wide sequence number, abs-send-time and toffset
    /// extensions zeroed in this receiver's copy of each media packet, as libwebrtc's receiver
    /// does (`UlpfecReceiver::ProcessReceivedFec`, `RtpPacket::ZeroMutableExtensions` at
    /// a222406d): its sender protects them as zeros, since it writes them after its FEC was
    /// computed (see `UlpfecSendBuilder::with_mutable_extensions_zeroed`). A packet rebuilt
    /// from such FEC then has every octet as sent and those values zero, instead of XOR noise
    /// there. `false` by default (RFC 5109 section 8: the FEC covers the packet as sent).
    pub fn with_mutable_extensions_zeroed(mut self, zero: bool) -> Self {
        self.zero_mutable_extensions = zero;
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> UlpfecReceiveInterceptor {
        UlpfecReceiveInterceptor {
            carriage: self.carriage,
            one_level_only: self.one_level_only,
            forward_repair: self.forward_repair,
            decode_every_stream: self.decode_every_stream,
            filter: self.filter,
            zero_mutable_extensions: self.zero_mutable_extensions,
            zeroed_extensions: HashMap::new(),
            decoders: HashMap::new(),
            carriages: HashMap::new(),
            in_red: HashMap::new(),
            reported: HashMap::new(),
            repair_to_media: HashMap::new(),
            media_transport: HashMap::new(),
            media_payload_type: HashMap::new(),
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
    decode_every_stream: bool,
    filter: StreamFilter,
    /// See [`UlpfecReceiveBuilder::with_mutable_extensions_zeroed`].
    zero_mutable_extensions: bool,
    /// With it: the ids of each protected stream's extensions zeroed in the decoder's copies.
    zeroed_extensions: HashMap<u32, Vec<u8>>,
    /// Decoders keyed by the media SSRC they protect.
    decoders: HashMap<u32, UlpfecDecoder>,
    /// How each protected stream's FEC travels, with the payload types its section
    /// negotiated (the builder's when the section lists none, or lists them under those
    /// numbers).
    carriages: HashMap<u32, Carriage>,
    /// FEC blocks (and their octets) read from each protected stream's RED packets.
    in_red: HashMap<u32, (u64, u64)>,
    /// What was last passed on about each protected stream ([`UlpfecReceiveStats`]).
    reported: HashMap<u32, UlpfecReceiveStats>,
    /// Separate stream: repair SSRC (and its payload type) to the media SSRC.
    repair_to_media: HashMap<u32, (u32, u8)>,
    /// Where each protected stream's media last arrived from. A packet rebuilt from a FEC
    /// packet is media of that stream, and the FEC may have come over another transport (a
    /// FEC session of its own, RFC 5109 section 14.1).
    media_transport: HashMap<u32, shared::TransportContext>,
    /// The payload type of each protected stream's last media packet, which a FEC-only packet
    /// of the stream goes on under, emptied ([`UlpfecRepair`]).
    media_payload_type: HashMap<u32, u8>,
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

    /// What this interceptor has received and done for the media stream `ssrc`.
    pub fn receive_stats(&self, ssrc: u32) -> Option<UlpfecReceiveStats> {
        let decoder = self.decoders.get(&ssrc)?;
        let (fec_packets_in_red, fec_bytes_in_red) =
            self.in_red.get(&ssrc).copied().unwrap_or_default();
        Some(UlpfecReceiveStats {
            media_ssrc: ssrc,
            fec_packets_in_red,
            fec_bytes_in_red,
            decoder: decoder.stats(),
        })
    }

    /// Pass [`UlpfecReceiveStats`] of `media_ssrc` application-ward if it changed.
    fn report(&mut self, now: Instant, transport: shared::TransportContext, media_ssrc: u32) {
        let Some(stats) = self.receive_stats(media_ssrc) else {
            return;
        };
        if self.reported.get(&media_ssrc) == Some(&stats) {
            return;
        }
        self.reported.insert(media_ssrc, stats);
        self.read_queue.push_back(TaggedPacket {
            now,
            transport,
            message: AttributedPacket::new(Packet::Rtcp(Vec::new()))
                .with(Attribute::Custom(Arc::new(stats))),
        });
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
        let of_fec_session = msg.message.custom::<FecSessionPacket>().copied();
        let Packet::Rtp(rtp_packet) = &mut msg.message.packet else {
            self.read_queue.push_back(msg);
            return Ok(());
        };
        let ssrc = rtp_packet.header.ssrc;
        let now = msg.now;
        let transport = msg.transport;

        // A packet that arrived in a FEC session of its own, marked by whoever read it there:
        // to the decoder of the stream it protects, and no further. A session's packet with
        // another payload type, or for a stream this interceptor keeps no decoder for, ends
        // here too: it is not media of any stream.
        if let Some(session) = of_fec_session {
            let recovered = match self.decoders.get_mut(&session.media_ssrc) {
                Some(decoder) if rtp_packet.header.payload_type == session.payload_type => {
                    match super::header::UlpfecPacket::parse(&rtp_packet.payload) {
                        Ok(fec) if session.one_level_only && fec.levels.len() > 1 => Vec::new(),
                        _ => decoder.push_fec(&rtp_packet.payload).unwrap_or_default(),
                    }
                }
                _ => Vec::new(),
            };
            let transport = self
                .media_transport
                .get(&session.media_ssrc)
                .copied()
                .unwrap_or(transport);
            self.queue_recovered(now, transport, recovered);
            self.report(now, transport, session.media_ssrc);
            return Ok(());
        }

        // A packet of a separate FEC stream: to the decoder, and no further. It has an SSRC of
        // its own, so nothing behind this interceptor is waiting for its sequence number.
        if let Some(&(media_ssrc, payload_type_fec)) = self.repair_to_media.get(&ssrc) {
            let recovered = match self.decoders.get_mut(&media_ssrc) {
                Some(decoder) if rtp_packet.header.payload_type == payload_type_fec => {
                    decoder.push_fec(&rtp_packet.payload).unwrap_or_default()
                }
                _ => Vec::new(),
            };
            let transport = self
                .media_transport
                .get(&media_ssrc)
                .copied()
                .unwrap_or(transport);
            self.queue_recovered(now, transport, recovered);
            self.report(now, transport, media_ssrc);
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
        } = self.carriages.get(&ssrc).copied().unwrap_or(self.carriage)
        {
            if rtp_packet.header.payload_type == fec_payload_type {
                // FEC by itself in a RED stream (RFC 5109 14.2 forbids it).
                return Ok(());
            }
            if rtp_packet.header.payload_type == red_payload_type {
                let Ok(red) = depacketize_red(&rtp_packet.payload, fec_payload_type) else {
                    return Ok(());
                };
                let in_red = self.in_red.entry(ssrc).or_default();
                for fec in &red.fec {
                    in_red.0 += 1;
                    in_red.1 += fec.len() as u64;
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
                            // Present, and no media: no payload, under the media's payload
                            // type, as padding in the stream would be.
                            rtp_packet.header.payload_type = self
                                .media_payload_type
                                .get(&ssrc)
                                .copied()
                                .unwrap_or(fec_payload_type);
                            rtp_packet.payload = Bytes::new();
                            msg.message.add(Attribute::Custom(Arc::new(UlpfecRepair)));
                            self.read_queue.push_back(msg);
                        }
                        self.queue_recovered(now, transport, recovered);
                        self.report(now, transport, ssrc);
                        return Ok(());
                    }
                }
            }
        }

        // A media packet: the decoder needs it to rebuild its neighbours, and it carries on.
        match self.zeroed_extensions.get(&ssrc) {
            Some(ids) => {
                recovered
                    .extend(decoder.push_media(&super::with_extensions_zeroed(rtp_packet, ids)));
            }
            None => recovered.extend(decoder.push_media(rtp_packet)),
        }
        self.media_transport.insert(ssrc, transport);
        self.media_payload_type
            .insert(ssrc, rtp_packet.header.payload_type);
        self.read_queue.push_back(msg);
        self.queue_recovered(now, transport, recovered);
        self.report(now, transport, ssrc);
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
        // The repair flow the signalling associated with the stream (RFC 5956 section 4.3,
        // `a=ssrc-group:FEC-FR <media> <repair>` with a `ulpfec` format): FEC as a stream of its
        // own (RFC 5109 section 14.1), whichever carriage the builder names, since the
        // multiplexing is "indicated out of band" per stream (section 14). With the stream
        // carriage a repair flow that names no format is taken as ULPFEC.
        //
        // A FEC session of its own ([`StreamInfo::fec_session`], an m= section grouped with
        // the media's): its stream, under the SSRC it has in this chain.
        let separate = match (info.fec_session, info.ssrc_fec, info.payload_type_fec) {
            (Some(session), _, _) => Some((session.ssrc, session.payload_type)),
            (None, Some(ssrc_fec), Some(payload_type_fec))
                if info.fec_is_ulpfec()
                    || (self.carriage == Carriage::Stream && info.mime_type_fec.is_empty()) =>
            {
                Some((ssrc_fec, payload_type_fec))
            }
            _ => None,
        };
        if self.zero_mutable_extensions {
            self.zeroed_extensions
                .insert(info.ssrc, super::mutable_extension_ids(info));
        }
        if let Some((ssrc_fec, payload_type_fec)) = separate {
            self.repair_to_media
                .insert(ssrc_fec, (info.ssrc, payload_type_fec));
        } else if self.carriage == Carriage::Stream && !self.decode_every_stream {
            return;
        }
        // RFC 5109 section 13: `onelevelonly=1` on this endpoint's `ulpfec` format of the
        // section ("what the receiver accepts to receive", section 14.3): FEC with more than
        // one level is refused.
        // RFC 5109 section 14.2: the RED and FEC payload types are the section's, as the
        // sender reads them (an answer keeps the offerer's numbers).
        let carriage = negotiated_carriage(self.carriage, info).unwrap_or(self.carriage);
        let fec_format = separate
            .map(|(_, payload_type)| payload_type)
            .or(match carriage {
                Carriage::Red {
                    fec_payload_type, ..
                } => Some(fec_payload_type),
                Carriage::Stream => None,
            });
        let one_level_only = self.one_level_only
            || info
                .fec_session
                .is_some_and(|session| session.one_level_only)
            || fec_format.is_some_and(|payload_type| {
                info.section_fmtp_lines
                    .iter()
                    .any(|(pt, fmtp)| *pt == payload_type && super::one_level_only_from_fmtp(fmtp))
            });
        self.decoders.insert(
            info.ssrc,
            UlpfecDecoder::new(info.ssrc).with_one_level_only(one_level_only),
        );
        self.carriages.insert(info.ssrc, carriage);
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.decoders.remove(&info.ssrc);
        self.carriages.remove(&info.ssrc);
        self.in_red.remove(&info.ssrc);
        self.reported.remove(&info.ssrc);
        self.media_transport.remove(&info.ssrc);
        self.media_payload_type.remove(&info.ssrc);
        self.zeroed_extensions.remove(&info.ssrc);
        self.repair_to_media
            .retain(|_, (media, _)| *media != info.ssrc);
    }

    fn bind_local_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
}
