//! RFC 8627 source packet reconstruction (section 6.3).

use super::header::{FLEXFEC_RECOVERY_SIZE, FlexFecHeader, RTP_FIXED_HEADER_SIZE};
use super::params::FlexFecParameters;
use bytes::Bytes;
use shared::marshal::{Marshal, MarshalSize, Unmarshal};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

/// The repair window a decoder assumes when none is signalled: 10 s, the value libwebrtc
/// writes for FlexFEC.
pub const FLEXFEC_DEFAULT_REPAIR_WINDOW: Duration = Duration::from_secs(10);

/// Bounds on what a [`FlexFecDecoder`] keeps, all of them derived from the repair window the
/// session agreed to (RFC 8627 sections 1.1.2 and 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlexFecDecoderConfig {
    /// How long a source or repair packet is kept after it arrived: the `repair-window`
    /// parameter. A repair packet and the sources it protects are at most this far apart.
    pub repair_window: Duration,
    /// The most source packets kept per source stream, whatever the window. Also the largest
    /// span of sequence numbers a repair packet may cover: one whose L and D (or mask) reach
    /// further cannot be within the repair window and is ignored (section 4.2.2.2).
    pub max_source_packets: usize,
    /// The most repair packets kept while they wait for sources. The source packets they name
    /// are bounded too, at 16 times `max_source_packets` over all of them: the oldest repair
    /// packets go first.
    pub max_repair_packets: usize,
}

impl FlexFecDecoderConfig {
    /// Packets per second the packet-count bounds assume when turning the repair window into a
    /// buffer size.
    pub const ASSUMED_PACKET_RATE: u32 = 1000;
    /// The floor and the ceiling of [`max_source_packets`](Self::max_source_packets) as derived
    /// from a repair window: a short window still holds one full mask, and no window makes a
    /// peer's parameters allocate without bound (section 9).
    pub const MIN_SOURCE_PACKETS: usize = 128;
    /// See [`MIN_SOURCE_PACKETS`](Self::MIN_SOURCE_PACKETS).
    pub const MAX_SOURCE_PACKETS: usize = 4096;

    /// The bounds for a session whose repair window is `repair_window`.
    pub fn for_repair_window(repair_window: Duration) -> Self {
        let packets = (repair_window.as_millis() * u128::from(Self::ASSUMED_PACKET_RATE) / 1000)
            .clamp(
                Self::MIN_SOURCE_PACKETS as u128,
                Self::MAX_SOURCE_PACKETS as u128,
            ) as usize;
        Self {
            repair_window,
            max_source_packets: packets,
            max_repair_packets: packets,
        }
    }

    /// The bounds for a session described by `parameters` (its `a=fmtp` line).
    pub fn for_parameters(parameters: &FlexFecParameters) -> Self {
        Self::for_repair_window(
            parameters
                .repair_window
                .unwrap_or(FLEXFEC_DEFAULT_REPAIR_WINDOW),
        )
    }
}

impl Default for FlexFecDecoderConfig {
    fn default() -> Self {
        Self::for_repair_window(FLEXFEC_DEFAULT_REPAIR_WINDOW)
    }
}

/// One source packet held: when it arrived and its octets as they were on the wire.
#[derive(Debug, Clone)]
struct Held {
    at: Instant,
    wire: Bytes,
}

/// The packets of one source stream, by extended sequence number.
#[derive(Debug, Default)]
struct SourceBuffer {
    packets: BTreeMap<i64, Held>,
    /// The highest extended sequence number placed so far: the anchor 16-bit numbers are
    /// unwrapped against.
    highest: Option<i64>,
    /// The sequence number of the last source packet refused as too far behind `highest`. A
    /// second one right after it means the stream itself moved (a restart), not a stray.
    stray: Option<u16>,
}

impl SourceBuffer {
    /// Keep at most `max` packets, none further behind the newest than `max` sequence numbers.
    fn trim(&mut self, max: usize) {
        let Some(highest) = self.highest else {
            return;
        };
        let floor = highest - max as i64;
        while let Some((&oldest, _)) = self.packets.first_key_value() {
            if oldest > floor && self.packets.len() <= max {
                break;
            }
            self.packets.remove(&oldest);
        }
    }

    /// The extended sequence number `sequence_number` stands for: the one nearest the highest
    /// seen. The first number of a stream is placed one cycle up, so that packets a little
    /// behind it do not go negative.
    fn extend(&self, sequence_number: u16) -> i64 {
        match self.highest {
            None => 0x1_0000 + i64::from(sequence_number),
            Some(highest) => {
                let delta = sequence_number.wrapping_sub(highest as u16) as i16;
                highest + i64::from(delta)
            }
        }
    }
}

/// A repair packet waiting for the source packets it protects.
#[derive(Debug)]
struct PendingRepair {
    at: Instant,
    recovery: [u8; FLEXFEC_RECOVERY_SIZE],
    /// The repair payload: what follows the FEC header.
    payload: Bytes,
    /// Every source packet protected: stream and extended sequence number.
    protected: Vec<(u32, i64)>,
}

/// Counters a [`FlexFecDecoder`] keeps about itself.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FlexFecDecoderStats {
    /// Source packets rebuilt from parity.
    pub recovered: u64,
    /// Source packets delivered by a retransmission (R=1) that were not already held.
    pub retransmitted: u64,
    /// Repair packets ignored: a reserved or malformed header, L=0, a stream this decoder does
    /// not protect, a span beyond the repair window.
    pub ignored_repair_packets: u64,
    /// Repair packets dropped because what they rebuilt was not an RTP packet, or their length
    /// recovery pointed beyond their own payload.
    pub failed_recoveries: u64,
}

/// Recovers lost source packets from RFC 8627 FlexFEC repair packets (`flexfec`, not
/// `flexfec-03`): flexible masks, fixed L/D rows and columns (1-D and 2-D, decoded
/// iteratively), retransmissions, and repair packets that protect several source streams.
///
/// Every packet of the protected source streams goes to
/// [`push_source`](Self::push_source), every packet of the repair stream to
/// [`push_repair`](Self::push_repair); both return the source packets that became available.
///
/// # Bounds
///
/// Only streams registered with [`add_source_stream`](Self::add_source_stream) are buffered: a
/// repair packet naming any other SSRC is ignored, so a peer cannot make the decoder open
/// buffers by inventing CSRCs. Per stream at most
/// [`max_source_packets`](FlexFecDecoderConfig::max_source_packets) are kept, for at most the
/// repair window; a repair packet whose L and D reach beyond that is ignored. Length recovery
/// can never ask for more than the repair packet itself holds.
#[derive(Debug)]
pub struct FlexFecDecoder {
    config: FlexFecDecoderConfig,
    sources: HashMap<u32, SourceBuffer>,
    repairs: VecDeque<PendingRepair>,
    /// Source packets named by the pending repair packets, summed.
    protected_entries: usize,
    stats: FlexFecDecoderStats,
}

impl FlexFecDecoder {
    /// A decoder with no source stream registered.
    pub fn new(config: FlexFecDecoderConfig) -> Self {
        Self {
            config,
            sources: HashMap::new(),
            repairs: VecDeque::new(),
            protected_entries: 0,
            stats: FlexFecDecoderStats::default(),
        }
    }

    /// The bounds this decoder runs with.
    pub fn config(&self) -> &FlexFecDecoderConfig {
        &self.config
    }

    /// Raise each bound to at least `config`'s: another stream joined with a longer repair
    /// window. Bounds are never lowered while packets are held against them.
    pub fn widen(&mut self, config: FlexFecDecoderConfig) {
        self.config.repair_window = self.config.repair_window.max(config.repair_window);
        self.config.max_source_packets = self
            .config
            .max_source_packets
            .max(config.max_source_packets);
        self.config.max_repair_packets = self
            .config
            .max_repair_packets
            .max(config.max_repair_packets);
    }

    /// Counters.
    pub fn stats(&self) -> FlexFecDecoderStats {
        self.stats
    }

    /// Protect the source stream `ssrc`: buffer its packets and accept repair packets for it.
    pub fn add_source_stream(&mut self, ssrc: u32) {
        self.sources.entry(ssrc).or_default();
    }

    /// Stop protecting `ssrc`, dropping what was held for it.
    pub fn remove_source_stream(&mut self, ssrc: u32) {
        self.sources.remove(&ssrc);
        self.drop_repairs_for(ssrc);
    }

    /// Drop the pending repair packets that protect `ssrc`.
    fn drop_repairs_for(&mut self, ssrc: u32) {
        self.repairs
            .retain(|repair| repair.protected.iter().all(|(stream, _)| *stream != ssrc));
        self.protected_entries = self.repairs.iter().map(|r| r.protected.len()).sum();
    }

    fn pop_oldest_repair(&mut self) {
        if let Some(repair) = self.repairs.pop_front() {
            self.protected_entries -= repair.protected.len();
        }
    }

    fn take_repair(&mut self, index: usize) -> Option<PendingRepair> {
        let repair = self.repairs.remove(index)?;
        self.protected_entries -= repair.protected.len();
        Some(repair)
    }

    /// Whether `ssrc` is a protected source stream.
    pub fn protects(&self, ssrc: u32) -> bool {
        self.sources.contains_key(&ssrc)
    }

    /// The protected source streams.
    pub fn source_streams(&self) -> impl Iterator<Item = u32> + '_ {
        self.sources.keys().copied()
    }

    /// Source packets held, over all streams.
    pub fn held_source_packets(&self) -> usize {
        self.sources
            .values()
            .map(|buffer| buffer.packets.len())
            .sum()
    }

    /// Repair packets held while they wait for sources.
    pub fn pending_repair_packets(&self) -> usize {
        self.repairs.len()
    }

    /// Offer a packet of a protected source stream that arrived at `now`. Returns the source
    /// packets it made recoverable.
    pub fn push_source(&mut self, now: Instant, packet: &rtp::Packet) -> Vec<rtp::Packet> {
        self.expire(now);
        if !self.sources.contains_key(&packet.header.ssrc) {
            return Vec::new();
        }
        let mut wire = vec![0u8; packet.marshal_size()];
        if packet.marshal_to(&mut wire).is_err() || wire.len() < RTP_FIXED_HEADER_SIZE {
            return Vec::new();
        }
        if !self.hold(
            now,
            packet.header.ssrc,
            packet.header.sequence_number,
            wire.into(),
        ) {
            return Vec::new();
        }
        self.recover_all(now)
    }

    /// Offer a packet of the repair stream that arrived at `now`. Returns the source packets
    /// it made available: rebuilt from parity, or carried whole by a retransmission and not
    /// held before.
    pub fn push_repair(&mut self, now: Instant, packet: &rtp::Packet) -> Vec<rtp::Packet> {
        self.expire(now);
        // The marker bit of a repair packet is ignored (section 4.2.1), as are its own padding
        // and header extensions: only the CSRC list and the payload are read.
        match FlexFecHeader::parse(&packet.header.csrc, &packet.payload) {
            Err(_) => {
                self.stats.ignored_repair_packets += 1;
                Vec::new()
            }
            Ok(FlexFecHeader::Retransmission) => self.push_retransmission(now, &packet.payload),
            Ok(FlexFecHeader::Repair {
                recovery,
                blocks,
                payload_offset,
            }) => {
                let mut protected = Vec::new();
                for block in &blocks {
                    let Some(buffer) = self.sources.get_mut(&block.ssrc) else {
                        // A stream this decoder does not protect: its packets are never held,
                        // so nothing this repair packet covers can be rebuilt.
                        self.stats.ignored_repair_packets += 1;
                        return Vec::new();
                    };
                    // L and D (or a mask) reaching beyond what the repair window holds: MUST be
                    // ignored (section 4.2.2.2).
                    if block.span() as usize > self.config.max_source_packets {
                        self.stats.ignored_repair_packets += 1;
                        return Vec::new();
                    }
                    let base = buffer.extend(block.sn_base);
                    // A block that lies wholly outside what this stream's buffer can hold (too
                    // far behind the newest packet, or too far ahead of it) repairs nothing the
                    // decoder still has or is about to get: it is not kept, and nothing is
                    // rebuilt out there.
                    if let Some(highest) = buffer.highest {
                        let window = self.config.max_source_packets as i64;
                        let end = base + i64::from(block.span());
                        if end <= highest - window || base > highest + window {
                            self.stats.ignored_repair_packets += 1;
                            return Vec::new();
                        }
                    }
                    // A repair packet ahead of every source packet of its stream anchors the
                    // numbering, so the sources that follow are placed against it.
                    buffer.highest.get_or_insert(base);
                    protected.extend(
                        block
                            .offsets()
                            .into_iter()
                            .map(|offset| (block.ssrc, base + i64::from(offset))),
                    );
                }

                self.protected_entries += protected.len();
                self.repairs.push_back(PendingRepair {
                    at: now,
                    recovery,
                    payload: packet.payload.slice(payload_offset..),
                    protected,
                });
                while self.repairs.len() > self.config.max_repair_packets
                    || self.protected_entries > 16 * self.config.max_source_packets
                {
                    self.pop_oldest_repair();
                }
                self.recover_all(now)
            }
        }
    }

    /// A retransmission (section 4.2.2.3): the payload is the source packet, its version bits
    /// reading R=1 F=0, which is version 2.
    fn push_retransmission(&mut self, now: Instant, payload: &Bytes) -> Vec<rtp::Packet> {
        let Ok(packet) = rtp::Packet::unmarshal(&mut payload.clone()) else {
            self.stats.ignored_repair_packets += 1;
            return Vec::new();
        };
        let ssrc = packet.header.ssrc;
        let Some(buffer) = self.sources.get(&ssrc) else {
            self.stats.ignored_repair_packets += 1;
            return Vec::new();
        };
        // Within the repair window only: a packet further behind than the buffer reaches is
        // one this decoder no longer knows whether it delivered.
        if let Some(highest) = buffer.highest
            && highest - buffer.extend(packet.header.sequence_number)
                >= self.config.max_source_packets as i64
        {
            self.stats.ignored_repair_packets += 1;
            return Vec::new();
        }
        if !self.hold(now, ssrc, packet.header.sequence_number, payload.clone()) {
            // Already held: the original arrived after all, or this is a second copy.
            return Vec::new();
        }
        self.stats.retransmitted += 1;
        let mut available = vec![packet];
        available.extend(self.recover_all(now));
        available
    }

    /// Keep a source packet. Returns false when it was already held or is too old to keep.
    fn hold(&mut self, now: Instant, ssrc: u32, sequence_number: u16, wire: Bytes) -> bool {
        let max = self.config.max_source_packets;
        let Some(buffer) = self.sources.get_mut(&ssrc) else {
            return false;
        };
        let mut extended = buffer.extend(sequence_number);
        if let Some(highest) = buffer.highest
            && highest - extended >= max as i64
        {
            // Too far behind to keep. One such packet is a stray; a second one that follows it
            // is the stream itself, restarted at another number: start over from there.
            let restarted = buffer.stray == Some(sequence_number.wrapping_sub(1));
            buffer.stray = Some(sequence_number);
            if !restarted {
                return false;
            }
            *buffer = SourceBuffer::default();
            extended = buffer.extend(sequence_number);
            self.drop_repairs_for(ssrc);
            let Some(restarted) = self.sources.get_mut(&ssrc) else {
                return false;
            };
            return {
                restarted.packets.insert(extended, Held { at: now, wire });
                restarted.highest = Some(extended);
                true
            };
        }
        buffer.stray = None;
        if buffer.packets.contains_key(&extended) {
            return false;
        }
        buffer.packets.insert(extended, Held { at: now, wire });
        let highest = buffer
            .highest
            .map_or(extended, |highest| highest.max(extended));
        buffer.highest = Some(highest);
        buffer.trim(max);
        true
    }

    /// Drop what arrived longer ago than the repair window.
    fn expire(&mut self, now: Instant) {
        let Some(cutoff) = now.checked_sub(self.config.repair_window) else {
            return;
        };
        for buffer in self.sources.values_mut() {
            buffer.packets.retain(|_, held| held.at >= cutoff);
        }
        while self
            .repairs
            .front()
            .is_some_and(|repair| repair.at < cutoff)
        {
            self.pop_oldest_repair();
        }
    }

    /// The iterative decoding of section 6.3.4: use every repair packet that misses exactly one
    /// source packet, feed what it rebuilt back, and go round again until a pass rebuilds
    /// nothing. Rows and columns are not told apart: the end result is the same in any order.
    fn recover_all(&mut self, now: Instant) -> Vec<rtp::Packet> {
        let mut recovered = Vec::new();
        loop {
            let mut progress = false;
            let mut index = 0;
            while index < self.repairs.len() {
                let missing: Vec<(u32, i64)> = self.repairs[index]
                    .protected
                    .iter()
                    .filter(|(ssrc, extended)| !self.holds(*ssrc, *extended))
                    .copied()
                    .collect();
                match missing.as_slice() {
                    // Everything it protects is here: it has nothing left to give.
                    [] => {
                        self.take_repair(index);
                    }
                    [(ssrc, extended)] => {
                        // Taken out before it is used, so the loop is bounded by the number of
                        // repair packets whatever the rebuilt packet turns out to be.
                        let Some(repair) = self.take_repair(index) else {
                            break;
                        };
                        match self.rebuild(&repair, *ssrc, *extended) {
                            Some((packet, wire)) => {
                                self.stats.recovered += 1;
                                // Held like a packet that arrived, and within the same
                                // bounds: one rebuilt from below the window is handed out and
                                // not kept.
                                let max = self.config.max_source_packets;
                                if let Some(buffer) = self.sources.get_mut(ssrc) {
                                    buffer.packets.insert(*extended, Held { at: now, wire });
                                    buffer.trim(max);
                                }
                                recovered.push(packet);
                                progress = true;
                            }
                            None => self.stats.failed_recoveries += 1,
                        }
                    }
                    _ => index += 1,
                }
            }
            if !progress {
                return recovered;
            }
        }
    }

    fn holds(&self, ssrc: u32, extended: i64) -> bool {
        self.sources
            .get(&ssrc)
            .is_some_and(|buffer| buffer.packets.contains_key(&extended))
    }

    /// Sections 6.3.2 and 6.3.3: XOR the repair packet with every source packet it protects
    /// but the missing one, and read the missing packet out of what is left.
    fn rebuild(
        &self,
        repair: &PendingRepair,
        missing_ssrc: u32,
        missing: i64,
    ) -> Option<(rtp::Packet, Bytes)> {
        let mut bits = repair.recovery;
        for (ssrc, extended) in &repair.protected {
            if (*ssrc, *extended) == (missing_ssrc, missing) {
                continue;
            }
            let wire = &self.sources.get(ssrc)?.packets.get(extended)?.wire;
            let length = (wire.len() - RTP_FIXED_HEADER_SIZE) as u16;
            bits[0] ^= wire[0];
            bits[1] ^= wire[1];
            bits[2] ^= (length >> 8) as u8;
            bits[3] ^= length as u8;
            for (target, &octet) in bits[4..8].iter_mut().zip(&wire[4..8]) {
                *target ^= octet;
            }
        }

        // Y: the length of the missing packet minus its fixed header. It comes off the wire, so
        // it is trusted no further than the repair payload reaches: a sender pads every source
        // to the longest, so an honest Y never exceeds it.
        let length = usize::from(u16::from_be_bytes([bits[2], bits[3]]));
        if length > repair.payload.len() {
            return None;
        }

        let mut wire = Vec::with_capacity(RTP_FIXED_HEADER_SIZE + length);
        // Version 2; P, X and CC from the recovered bit string, then M and PT.
        wire.push(0x80 | (bits[0] & 0x3F));
        wire.push(bits[1]);
        wire.extend_from_slice(&(missing as u16).to_be_bytes());
        wire.extend_from_slice(&bits[4..8]);
        wire.extend_from_slice(&missing_ssrc.to_be_bytes());
        wire.extend_from_slice(&repair.payload[..length]);
        for (ssrc, extended) in &repair.protected {
            if (*ssrc, *extended) == (missing_ssrc, missing) {
                continue;
            }
            let source = &self.sources.get(ssrc)?.packets.get(extended)?.wire;
            for (target, &octet) in wire[RTP_FIXED_HEADER_SIZE..]
                .iter_mut()
                .zip(&source[RTP_FIXED_HEADER_SIZE..])
            {
                *target ^= octet;
            }
        }

        // What comes out has to be an RTP packet: CC, the extension length and the padding
        // count were all recovered from the peer's bits.
        let wire = Bytes::from(wire);
        let packet = rtp::Packet::unmarshal(&mut wire.clone()).ok()?;
        Some((packet, wire))
    }
}
