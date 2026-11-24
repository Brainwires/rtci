//! Receive-side RFC 8627 FlexFEC: recovers lost media and keeps repair packets from the
//! application.

use super::decoder::{
    FLEXFEC_DEFAULT_REPAIR_WINDOW, FlexFecDecoder, FlexFecDecoderConfig, FlexFecDecoderStats,
};
use super::params::FlexFecParameters;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use sansio::Protocol;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// The longest repair window a receiver built without
/// [`with_max_repair_window`](FlexFecReceiveBuilder::with_max_repair_window) supports: 10 s.
pub const FLEXFEC_MAX_REPAIR_WINDOW: Duration = FLEXFEC_DEFAULT_REPAIR_WINDOW;

/// Builder for [`FlexFecReceiveInterceptor`].
///
/// # Example
///
/// ```
/// use rtci_interceptor::{FlexFecReceiveBuilder, Registry, Slot};
///
/// let chain = Registry::new()
///     .with(Slot::FecDecoder, FlexFecReceiveBuilder::new().build())
///     .build();
/// ```
pub struct FlexFecReceiveBuilder {
    max_repair_window: Duration,
    in_band_payload_type: Option<u8>,
}

impl Default for FlexFecReceiveBuilder {
    fn default() -> Self {
        Self {
            max_repair_window: FLEXFEC_MAX_REPAIR_WINDOW,
            in_band_payload_type: None,
        }
    }
}

impl FlexFecReceiveBuilder {
    /// A builder supporting repair windows up to [`FLEXFEC_MAX_REPAIR_WINDOW`].
    pub fn new() -> Self {
        Self::default()
    }

    /// The longest repair window this receiver buffers for.
    ///
    /// A stream whose negotiated `repair-window` is longer is not protected: the receiver
    /// "must support any valid FLEX FEC configuration within the repair window" it agreed to
    /// (RFC 8627 section 5.2.1), and it cannot for a window it does not buffer. (Refusing the
    /// payload type in the answer is the application's part: see the media engine.)
    pub fn with_max_repair_window(mut self, max_repair_window: Duration) -> Self {
        self.max_repair_window = max_repair_window;
        self
    }

    /// In-band SSRC mapping (RFC 8627 section 7.1.1): there is no `a=ssrc-group:FEC-FR`, a
    /// packet with `payload_type` on an SSRC that is not a bound media stream is a repair
    /// packet, and its CSRC list says which streams it protects. Every bound remote stream is
    /// then a source stream.
    pub fn with_in_band_ssrc_mapping(mut self, payload_type: u8) -> Self {
        self.in_band_payload_type = Some(payload_type);
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> FlexFecReceiveInterceptor {
        FlexFecReceiveInterceptor {
            max_repair_window: self.max_repair_window,
            in_band_payload_type: self.in_band_payload_type,
            decoder: None,
            repair_streams: HashMap::new(),
            source_streams: HashMap::new(),
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

/// Recovers media lost from streams protected by RFC 8627 FlexFEC (`flexfec`, not
/// `flexfec-03`).
///
/// Binds a remote stream that names a FEC SSRC, a FEC payload type and the `flexfec` format
/// ([`StreamInfo::fec_is_flexfec`]). One decoder serves every stream, so a repair packet may
/// protect several of them (its CSRC list), and one repair stream may serve several sources.
///
/// Repair packets are consumed; recovered packets continue up the chain tagged
/// [`Attribute::RecoveredByFec`], a retransmitted one (R=1) tagged
/// [`Attribute::Retransmission`].
pub struct FlexFecReceiveInterceptor {
    max_repair_window: Duration,
    in_band_payload_type: Option<u8>,
    /// Built at the first binding; buffers for the longest repair window bound so far.
    decoder: Option<FlexFecDecoder>,
    /// Repair SSRC to its payload type and how many source streams named it.
    repair_streams: HashMap<u32, (u8, usize)>,
    /// Source SSRC to the repair SSRC it was bound with, if any.
    source_streams: HashMap<u32, Option<u32>>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl FlexFecReceiveInterceptor {
    /// The source SSRCs currently protected.
    pub fn protected_streams(&self) -> impl Iterator<Item = u32> + '_ {
        self.source_streams.keys().copied()
    }

    /// The decoder's counters; zeros before any stream is bound.
    pub fn stats(&self) -> FlexFecDecoderStats {
        self.decoder
            .as_ref()
            .map(FlexFecDecoder::stats)
            .unwrap_or_default()
    }

    fn decoder_for(&mut self, repair_window: Duration) -> &mut FlexFecDecoder {
        let config = FlexFecDecoderConfig::for_repair_window(repair_window);
        let decoder = self
            .decoder
            .get_or_insert_with(|| FlexFecDecoder::new(config));
        // One decoder serves every stream, so it buffers for the longest window among them.
        decoder.widen(config);
        decoder
    }

    /// Whether a packet on `ssrc` with `payload_type` belongs to a repair stream.
    fn is_repair(&self, ssrc: u32, payload_type: u8) -> bool {
        match self.repair_streams.get(&ssrc) {
            // The association says which SSRC; the payload type says it is FlexFEC and not
            // something else on that SSRC.
            Some((repair_payload_type, _)) => *repair_payload_type == payload_type,
            None => {
                self.in_band_payload_type == Some(payload_type)
                    && !self.source_streams.contains_key(&ssrc)
            }
        }
    }

    fn queue_available(&mut self, msg: &TaggedPacket, available: Vec<rtp::Packet>, how: Attribute) {
        for packet in available {
            let mut message = AttributedPacket::new(Packet::Rtp(packet));
            // Says how it got here: it was never on the wire in this form, so anything
            // measuring the network (arrival times, loss) can tell it from a packet that was.
            message.add(how.clone());
            self.read_queue.push_back(TaggedPacket {
                now: msg.now,
                transport: msg.transport,
                message,
            });
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for FlexFecReceiveInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        let Packet::Rtp(rtp_packet) = &msg.message.packet else {
            self.read_queue.push_back(msg);
            return Ok(());
        };
        let ssrc = rtp_packet.header.ssrc;

        if self.is_repair(ssrc, rtp_packet.header.payload_type) {
            // A repair packet: the decoder takes it and it goes no further. It is not media.
            let Some(decoder) = self.decoder.as_mut() else {
                return Ok(());
            };
            let before = decoder.stats().retransmitted;
            let mut available = decoder.push_repair(msg.now, rtp_packet);
            // A retransmission delivers its packet first; anything after it was rebuilt from
            // parity that packet completed.
            let retransmitted = if decoder.stats().retransmitted > before {
                vec![available.remove(0)]
            } else {
                Vec::new()
            };
            self.queue_available(&msg, retransmitted, Attribute::Retransmission);
            self.queue_available(&msg, available, Attribute::RecoveredByFec);
            return Ok(());
        }

        // A source packet: the decoder needs it to recover its neighbours, and it carries on
        // as it arrived. What it made recoverable follows it.
        let recovered = match self.decoder.as_mut() {
            Some(decoder) if decoder.protects(ssrc) => decoder.push_source(msg.now, rtp_packet),
            _ => Vec::new(),
        };
        let (now, transport) = (msg.now, msg.transport);
        self.read_queue.push_back(msg);
        for packet in recovered {
            let mut message = AttributedPacket::new(Packet::Rtp(packet));
            message.add(Attribute::RecoveredByFec);
            self.read_queue.push_back(TaggedPacket {
                now,
                transport,
                message,
            });
        }
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

impl Interceptor for FlexFecReceiveInterceptor {
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        if self.source_streams.contains_key(&info.ssrc) {
            return;
        }

        if let (Some(repair_ssrc), Some(payload_type_fec)) = (info.ssrc_fec, info.payload_type_fec)
            && info.fec_is_flexfec()
        {
            let repair_window = FlexFecParameters::parse(&info.sdp_fmtp_line_fec)
                .repair_window
                .unwrap_or(FLEXFEC_DEFAULT_REPAIR_WINDOW);
            // A window longer than this receiver buffers for cannot be honoured: the stream
            // goes unprotected instead of being half supported.
            if repair_window > self.max_repair_window {
                return;
            }
            self.decoder_for(repair_window).add_source_stream(info.ssrc);
            self.repair_streams
                .entry(repair_ssrc)
                .or_insert((payload_type_fec, 0))
                .1 += 1;
            self.source_streams.insert(info.ssrc, Some(repair_ssrc));
            return;
        }

        // In-band mapping: every media stream may be named by a repair packet's CSRC list. A
        // repair flow bound in its own right (its own SSRC as the stream) is not a source.
        if self.in_band_payload_type.is_some()
            && self.in_band_payload_type != Some(info.payload_type)
            && !self.repair_streams.contains_key(&info.ssrc)
        {
            let max_repair_window = self.max_repair_window;
            self.decoder_for(max_repair_window)
                .add_source_stream(info.ssrc);
            self.source_streams.insert(info.ssrc, None);
        }
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        let Some(repair_ssrc) = self.source_streams.remove(&info.ssrc) else {
            return;
        };
        if let Some(decoder) = self.decoder.as_mut() {
            decoder.remove_source_stream(info.ssrc);
        }
        if let Some(repair_ssrc) = repair_ssrc
            && let Some((_, users)) = self.repair_streams.get_mut(&repair_ssrc)
        {
            *users -= 1;
            if *users == 0 {
                self.repair_streams.remove(&repair_ssrc);
            }
        }
    }

    fn bind_local_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
}
