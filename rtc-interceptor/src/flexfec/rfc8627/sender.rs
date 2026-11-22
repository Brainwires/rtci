//! Send-side RFC 8627 FlexFEC: protects outgoing media with parity repair packets and, when
//! asked, answers NACKs with FlexFEC retransmissions.

use super::decoder::FLEXFEC_DEFAULT_REPAIR_WINDOW;
use super::encoder::{FlexFecEncoder, FlexFecProtection};
use super::params::FlexFecParameters;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// The protection applied when the builder names none: flexible masks, two interleaved repair
/// packets per five source packets (the draft-03 interceptor's default shape).
pub const FLEXFEC_DEFAULT_PROTECTION: FlexFecProtection = FlexFecProtection::Mask {
    media_packets: 5,
    fec_packets: 2,
};

/// Source packets a stream keeps to answer NACKs from, when retransmissions are on.
const RETRANSMISSION_HISTORY: usize = 512;

/// A packet is not retransmitted again within this long of its last retransmission.
const MIN_RETRANSMIT_INTERVAL: Duration = Duration::from_millis(100);

/// Builder for [`FlexFecSendInterceptor`].
///
/// # Example
///
/// ```
/// use rtc_interceptor::{FlexFecProtection, FlexFecSendBuilder, Registry, Slot};
///
/// let chain = Registry::new()
///     .with(
///         Slot::FecEncoder,
///         FlexFecSendBuilder::new()
///             .with_protection(FlexFecProtection::RowAndColumn { l: 4, d: 3 })
///             .build(),
///     )
///     .build();
/// ```
pub struct FlexFecSendBuilder {
    protection: FlexFecProtection,
    repair_window: Duration,
    retransmissions: bool,
    initial_sequence_number: Option<u16>,
    initial_timestamp: Option<u32>,
}

impl Default for FlexFecSendBuilder {
    fn default() -> Self {
        Self {
            protection: FLEXFEC_DEFAULT_PROTECTION,
            repair_window: FLEXFEC_DEFAULT_REPAIR_WINDOW,
            retransmissions: false,
            initial_sequence_number: None,
            initial_timestamp: None,
        }
    }
}

impl FlexFecSendBuilder {
    /// A builder with [`FLEXFEC_DEFAULT_PROTECTION`] and a 10 s repair window.
    pub fn new() -> Self {
        Self::default()
    }

    /// The shape of the protection: flexible masks, rows, columns, or rows and columns.
    ///
    /// A shape with no usable block (`l` of 0, a column of fewer than two rows, a mask block of
    /// more than 110 packets) protects nothing.
    pub fn with_protection(mut self, protection: FlexFecProtection) -> Self {
        self.protection = protection;
        self
    }

    /// The longest repair window this sender uses. A stream whose negotiated `repair-window`
    /// (its `a=fmtp` line) is shorter is held to that one.
    ///
    /// A block of source packets is protected only when its first packet and its repair
    /// packets are sent within the window: RFC 8627 section 1.1.8 forbids repair packets whose
    /// L and D exceed it.
    pub fn with_repair_window(mut self, repair_window: Duration) -> Self {
        self.repair_window = repair_window;
        self
    }

    /// Answer NACKs for the protected streams with FlexFEC retransmission packets (R=1,
    /// section 4.2.2.3) on the repair stream. Off by default.
    ///
    /// This is FlexFEC's own retransmission, in place of RFC 4588 RTX: a chain that turns it on
    /// must not also run a NACK responder for the same streams, or each NACK is answered twice.
    pub fn with_retransmissions(mut self, retransmissions: bool) -> Self {
        self.retransmissions = retransmissions;
        self
    }

    /// The sequence number each repair stream starts at. Unset, it is random (section 4.2.1).
    pub fn with_initial_sequence_number(mut self, sequence_number: u16) -> Self {
        self.initial_sequence_number = Some(sequence_number);
        self
    }

    /// The RTP timestamp each repair stream carries at the instant of its first packet. Unset,
    /// it is random (RFC 3550 section 5.1). From there it follows the send clock.
    pub fn with_initial_timestamp(mut self, timestamp: u32) -> Self {
        self.initial_timestamp = Some(timestamp);
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> FlexFecSendInterceptor {
        FlexFecSendInterceptor {
            protection: self.protection,
            repair_window: self.repair_window,
            retransmissions: self.retransmissions,
            initial_sequence_number: self.initial_sequence_number,
            initial_timestamp: self.initial_timestamp,
            streams: HashMap::new(),
            repair_streams: HashMap::new(),
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

/// One repair stream: its encoder and its send clock. Several source streams may share one.
struct RepairStream {
    encoder: FlexFecEncoder,
    clock_rate: u32,
    initial_timestamp: u32,
    /// The instant of the first repair packet, which carries `initial_timestamp`.
    epoch: Option<Instant>,
    /// How many source streams send their repair packets here.
    users: usize,
}

impl RepairStream {
    /// The repair stream's RTP timestamp at `now`: its transmission time (section 4.2.1), on
    /// the only clock a sans-I/O engine has, the instant the packet is written with.
    fn timestamp_at(&mut self, now: Instant) -> u32 {
        let epoch = *self.epoch.get_or_insert(now);
        let elapsed = now.saturating_duration_since(epoch);
        let ticks = elapsed.as_nanos() * u128::from(self.clock_rate) / 1_000_000_000;
        self.initial_timestamp.wrapping_add(ticks as u32)
    }
}

/// One protected source stream.
struct ProtectedStream {
    repair_ssrc: u32,
    repair_window: Duration,
    /// Source packets awaiting a full block, consecutive.
    block: Vec<rtp::Packet>,
    /// When the first packet of `block` was sent.
    block_started: Option<Instant>,
    /// Recent source packets and when they were sent, oldest first, for retransmission.
    history: VecDeque<(Instant, rtp::Packet)>,
    /// When each sequence number was last retransmitted.
    last_retransmit: HashMap<u16, Instant>,
}

/// Produces RFC 8627 FlexFEC repair packets (`flexfec`, not `flexfec-03`) for outgoing media.
///
/// Binds a local stream that names a FEC SSRC, a FEC payload type and the `flexfec` format
/// ([`StreamInfo::fec_is_flexfec`]). Its `repair-window` is read from the FEC format's
/// `a=fmtp` line.
///
/// Source packets pass through unaltered (section 4.1); repair packets follow the packet that
/// completed their block, on the repair SSRC, with the protected SSRC in their CSRC list.
pub struct FlexFecSendInterceptor {
    protection: FlexFecProtection,
    repair_window: Duration,
    retransmissions: bool,
    initial_sequence_number: Option<u16>,
    initial_timestamp: Option<u32>,
    /// Keyed by the **source** SSRC being protected.
    streams: HashMap<u32, ProtectedStream>,
    /// Keyed by the repair SSRC.
    repair_streams: HashMap<u32, RepairStream>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl FlexFecSendInterceptor {
    /// The source SSRCs currently being protected.
    pub fn protected_streams(&self) -> impl Iterator<Item = u32> + '_ {
        self.streams.keys().copied()
    }

    /// The repair window in force for the source stream `ssrc`.
    pub fn repair_window(&self, ssrc: u32) -> Option<Duration> {
        self.streams.get(&ssrc).map(|stream| stream.repair_window)
    }

    /// Answer one NACK from the retransmission history.
    fn retransmit(&mut self, now: Instant, media_ssrc: u32, sequence_numbers: Vec<u16>) {
        let Some(stream) = self.streams.get_mut(&media_ssrc) else {
            return;
        };
        let Some(repair) = self.repair_streams.get_mut(&stream.repair_ssrc) else {
            return;
        };
        stream
            .last_retransmit
            .retain(|_, at| now.saturating_duration_since(*at) < MIN_RETRANSMIT_INTERVAL);

        for sequence_number in sequence_numbers {
            if stream.last_retransmit.contains_key(&sequence_number) {
                continue;
            }
            // Only what is still inside the repair window: the receiver has agreed to accept a
            // retransmission of any source packet within it (section 1.1.8), and no further.
            let Some((_, source)) = stream.history.iter().find(|(sent, packet)| {
                packet.header.sequence_number == sequence_number
                    && now.saturating_duration_since(*sent) <= stream.repair_window
            }) else {
                continue;
            };
            let timestamp = repair.timestamp_at(now);
            let Ok(packet) = repair.encoder.retransmit(source, timestamp) else {
                continue;
            };
            stream.last_retransmit.insert(sequence_number, now);
            self.write_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(packet)).with(Attribute::Retransmission),
            });
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for FlexFecSendInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if self.retransmissions
            && let Packet::Rtcp(rtcp_packets) = &msg.message.packet
        {
            let mut requests = Vec::new();
            for rtcp_packet in rtcp_packets {
                if let Some(nack) = rtcp_packet
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>()
                    && self.streams.contains_key(&nack.media_ssrc)
                {
                    let mut sequence_numbers: Vec<u16> = nack
                        .nacks
                        .iter()
                        .flat_map(|pair| pair.packet_list())
                        .collect();
                    sequence_numbers.sort_unstable();
                    sequence_numbers.dedup();
                    requests.push((nack.media_ssrc, sequence_numbers));
                }
            }
            for (media_ssrc, sequence_numbers) in requests {
                self.retransmit(msg.now, media_ssrc, sequence_numbers);
            }
        }
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        let Packet::Rtp(rtp_packet) = &msg.message.packet else {
            self.write_queue.push_back(msg);
            return Ok(());
        };
        let now = msg.now;
        let transport = msg.transport;

        let Some(stream) = self.streams.get_mut(&rtp_packet.header.ssrc) else {
            self.write_queue.push_back(msg);
            return Ok(());
        };

        if self.retransmissions {
            if stream.history.len() == RETRANSMISSION_HISTORY {
                stream.history.pop_front();
            }
            stream.history.push_back((now, rtp_packet.clone()));
        }

        let mut repair_packets = Vec::new();
        let block_len = self.protection.block_len();
        if block_len > 0 {
            // L, D and the masks describe positions from one base sequence number, so a block
            // is a run of consecutive packets: a gap starts a new one.
            if let Some(last) = stream.block.last()
                && rtp_packet.header.sequence_number != last.header.sequence_number.wrapping_add(1)
            {
                stream.block.clear();
            }
            if stream.block.is_empty() {
                stream.block_started = Some(now);
            }
            stream.block.push(rtp_packet.clone());

            if stream.block.len() >= block_len {
                // Section 1.1.8: nothing is sent that reaches beyond the repair window. A block
                // that took longer than the window to fill goes unprotected.
                let within_window = stream.block_started.is_some_and(|started| {
                    now.saturating_duration_since(started) <= stream.repair_window
                });
                if within_window
                    && let Some(repair) = self.repair_streams.get_mut(&stream.repair_ssrc)
                {
                    let timestamp = repair.timestamp_at(now);
                    repair_packets =
                        repair
                            .encoder
                            .encode_block(self.protection, &stream.block, timestamp);
                }
                stream.block.clear();
            }
        }

        // The source packet goes out first, as it was handed over; the repair packets protect
        // what has already left.
        self.write_queue.push_back(msg);
        for packet in repair_packets {
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

impl Interceptor for FlexFecSendInterceptor {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        let (Some(repair_ssrc), Some(payload_type_fec)) = (info.ssrc_fec, info.payload_type_fec)
        else {
            return;
        };
        if !info.fec_is_flexfec() || self.streams.contains_key(&info.ssrc) {
            return;
        }

        // The negotiated repair window bounds what may be sent; the builder's can only narrow
        // it.
        let negotiated = FlexFecParameters::parse(&info.sdp_fmtp_line_fec).repair_window;
        let repair_window = negotiated.map_or(self.repair_window, |negotiated| {
            negotiated.min(self.repair_window)
        });

        let (initial_sequence_number, initial_timestamp) =
            (self.initial_sequence_number, self.initial_timestamp);
        self.repair_streams
            .entry(repair_ssrc)
            .or_insert_with(|| RepairStream {
                encoder: FlexFecEncoder::new(payload_type_fec, repair_ssrc)
                    .with_base_sequence_number(
                        initial_sequence_number.unwrap_or_else(rand::random),
                    ),
                // The rate of `flexfec` is recommended to match the source's (section 5.1); 90
                // kHz is the video clock when a stream names none.
                clock_rate: if info.clock_rate == 0 {
                    90_000
                } else {
                    info.clock_rate
                },
                initial_timestamp: initial_timestamp.unwrap_or_else(rand::random),
                epoch: None,
                users: 0,
            })
            .users += 1;
        self.streams.insert(
            info.ssrc,
            ProtectedStream {
                repair_ssrc,
                repair_window,
                block: Vec::new(),
                block_started: None,
                history: VecDeque::new(),
                last_retransmit: HashMap::new(),
            },
        );
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        let Some(stream) = self.streams.remove(&info.ssrc) else {
            return;
        };
        if let Some(repair) = self.repair_streams.get_mut(&stream.repair_ssrc) {
            repair.users -= 1;
            if repair.users == 0 {
                self.repair_streams.remove(&stream.repair_ssrc);
            }
        }
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}
