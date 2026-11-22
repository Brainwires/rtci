//! Recovery (RFC 5109 section 9).

use super::UlpfecError;
use super::encoder::{RTP_FIXED_HEADER, level_slice, protected_bit_string, wire_image, xor_into};
use super::header::UlpfecPacket;
use bytes::Bytes;
use shared::marshal::Unmarshal;
use std::collections::{HashMap, VecDeque};

/// How far behind (and ahead of) the newest media sequence number packets are kept.
///
/// A FEC packet reaches at most 48 sequence numbers past its base, and follows the media it
/// protects; 256 leaves room for reordering and for FEC sent a few blocks late, and bounds the
/// media store at a little over 500 packets whatever the peer sends.
pub const ULPFEC_MEDIA_WINDOW: u16 = 256;

/// The most FEC packets held while they still have something to recover.
pub const ULPFEC_MAX_HELD_FEC: usize = 64;

/// What a decoder has done so far.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct UlpfecDecoderStats {
    /// FEC packets accepted.
    pub fec_packets: u64,
    /// FEC payloads refused: malformed, outside the window, or more levels than signalled.
    pub fec_rejected: u64,
    /// Media packets rebuilt completely and handed out.
    pub recovered: u64,
    /// Recoveries whose result was not an RTP packet (inconsistent FEC data), discarded.
    pub failed: u64,
    /// FEC packets that broke rule a of RFC 5109 7.4 against one already held: a media packet
    /// protected twice at a level above 0, or twice at level 0 with different lengths. They are
    /// used all the same; see [`UlpfecDecoder::push_fec`].
    pub rule_violations: u64,
}

/// A media packet the decoder knows only in part: rebuilt at some levels and not (yet) at others.
#[derive(Debug, Default)]
struct Partial {
    /// The recovery bit string of the header (9.1), once level 0 has been recovered: the first
    /// eight octets of the RTP header and the length after the fixed header.
    bits: Option<[u8; 10]>,
    /// Octets after the fixed RTP header; only the `known` ranges mean anything.
    data: Vec<u8>,
    /// Recovered ranges of `data`, sorted, merged, half-open.
    known: Vec<(usize, usize)>,
}

impl Partial {
    /// The packet's length after the fixed header, once level 0 is recovered.
    fn length(&self) -> Option<usize> {
        self.bits
            .map(|bits| usize::from(u16::from_be_bytes([bits[8], bits[9]])))
    }

    /// Whether the octets `start..start + length` are known. Past the packet's own length they
    /// are: there the protected bit string is zero padding (9.2 step 4).
    fn knows(&self, start: usize, length: usize) -> bool {
        let mut end = start + length;
        if let Some(packet_length) = self.length() {
            end = end.min(packet_length);
        }
        if start >= end {
            return true;
        }
        self.known
            .iter()
            .any(|(known_start, known_end)| *known_start <= start && end <= *known_end)
    }

    /// XOR this packet's octets from `start` into `target`.
    fn xor_level(&self, target: &mut [u8], start: usize) {
        let limit = self
            .length()
            .map_or(self.data.len(), |length| length.min(self.data.len()));
        if start < limit {
            xor_into(target, &self.data[start..limit]);
        }
    }

    /// Record recovered octets at `start`.
    fn add(&mut self, start: usize, octets: &[u8]) {
        if octets.is_empty() {
            return;
        }
        let end = start + octets.len();
        if self.data.len() < end {
            self.data.resize(end, 0);
        }
        self.data[start..end].copy_from_slice(octets);
        self.known.push((start, end));
        self.known.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.known.len());
        for (range_start, range_end) in self.known.drain(..) {
            match merged.last_mut() {
                Some(last) if range_start <= last.1 => last.1 = last.1.max(range_end),
                _ => merged.push((range_start, range_end)),
            }
        }
        self.known = merged;
    }
}

/// What the decoder holds for one sequence number.
#[derive(Debug)]
enum Entry {
    /// Received, or rebuilt in full: the packet as on the wire.
    Complete(Bytes),
    /// Rebuilt at some levels.
    Partial(Partial),
    /// A recovery that did not produce an RTP packet. Kept so it is not attempted again.
    Failed,
}

impl Entry {
    fn bit_string(&self) -> Option<[u8; 10]> {
        match self {
            Self::Complete(image) => Some(protected_bit_string(image)),
            Self::Partial(partial) => partial.bits,
            Self::Failed => None,
        }
    }

    fn knows(&self, start: usize, length: usize) -> bool {
        match self {
            Self::Complete(_) => true,
            Self::Partial(partial) => partial.knows(start, length),
            Self::Failed => false,
        }
    }

    fn xor_level(&self, target: &mut [u8], start: usize) {
        match self {
            Self::Complete(image) => {
                let length = target.len();
                xor_into(target, level_slice(image, start, length));
            }
            Self::Partial(partial) => partial.xor_level(target, start),
            Self::Failed => {}
        }
    }
}

/// A FEC packet still waiting for packets it could help rebuild.
#[derive(Debug)]
struct HeldFec {
    packet: UlpfecPacket,
    /// The payload as received, to recognise a second copy.
    raw: Bytes,
}

/// Recovers lost media packets of one stream from ULPFEC packets.
///
/// Feed it every media packet of the protected stream ([`push_media`](Self::push_media)) and
/// every FEC payload ([`push_fec`](Self::push_fec)); each call returns the packets it could
/// rebuild. Recovery is level by level (9.2) and iterated, so one rebuilt packet can complete
/// another FEC packet's set.
///
/// # Partial recovery
///
/// With uneven protection a packet may be rebuilt at level 0 and not beyond. Its length is then
/// known and longer than what was rebuilt, which is how 9 tells a partial recovery from a full
/// one. A partial packet is kept, used as input to further recovery, and **not** returned: the
/// octets after the recovered part are unknown, and a packet with a made-up tail is worse than a
/// lost one. [`partial_packets`](Self::partial_packets) counts them.
///
/// # Bounds
///
/// Media is kept for [`ULPFEC_MEDIA_WINDOW`] sequence numbers either side of the newest, FEC
/// packets up to [`ULPFEC_MAX_HELD_FEC`], and a recovered packet is never longer than the FEC
/// data received for it.
#[derive(Debug)]
pub struct UlpfecDecoder {
    ssrc: u32,
    one_level_only: bool,
    media: HashMap<u16, Entry>,
    fec: VecDeque<HeldFec>,
    /// The highest media sequence number seen, wrap taken into account.
    newest: Option<u16>,
    /// The last media sequence number that fell outside the window, to tell a stream that
    /// restarted its numbering from one stray packet.
    stray: Option<u16>,
    stats: UlpfecDecoderStats,
}

impl UlpfecDecoder {
    /// A decoder for the media stream `ssrc`.
    pub fn new(ssrc: u32) -> Self {
        Self {
            ssrc,
            one_level_only: false,
            media: HashMap::new(),
            fec: VecDeque::new(),
            newest: None,
            stray: None,
            stats: UlpfecDecoderStats::default(),
        }
    }

    /// Refuse FEC packets with more than one protection level, for a stream that signalled
    /// `onelevelonly=1` (RFC 5109 13).
    pub fn with_one_level_only(mut self, one_level_only: bool) -> Self {
        self.one_level_only = one_level_only;
        self
    }

    /// The media SSRC this decoder protects.
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Counters.
    pub fn stats(&self) -> UlpfecDecoderStats {
        self.stats
    }

    /// Packets rebuilt at some levels only, and so not handed out.
    pub fn partial_packets(&self) -> usize {
        self.media
            .values()
            .filter(|entry| matches!(entry, Entry::Partial(_)))
            .count()
    }

    /// FEC packets held.
    pub fn held_fec_packets(&self) -> usize {
        self.fec.len()
    }

    /// Media packets held, complete or partial.
    pub fn held_media_packets(&self) -> usize {
        self.media.len()
    }

    /// A media packet of the protected stream arrived. Returns what it made recoverable.
    ///
    /// A packet of another SSRC is ignored.
    pub fn push_media(&mut self, packet: &rtp::Packet) -> Vec<rtp::Packet> {
        if packet.header.ssrc != self.ssrc {
            return Vec::new();
        }
        let Ok(image) = wire_image(packet) else {
            return Vec::new();
        };
        let sequence = packet.header.sequence_number;
        if !self.admit(sequence) {
            return Vec::new();
        }
        self.media.insert(sequence, Entry::Complete(image));
        self.recover()
    }

    /// A FEC payload arrived: the payload of a FEC packet of a separate stream, or the FEC block
    /// of a RED packet. Returns the media packets it made recoverable.
    ///
    /// A second copy of a FEC packet already held is ignored.
    ///
    /// Rule a of 7.4 is checked against the FEC packets held and counted in
    /// [`UlpfecDecoderStats::rule_violations`], and the packet is used regardless: the recovery
    /// arithmetic does not depend on the rule, and libwebrtc's masks protect a packet with
    /// several FEC packets whose level-0 lengths differ.
    pub fn push_fec(&mut self, payload: &[u8]) -> Result<Vec<rtp::Packet>, UlpfecError> {
        let packet = match UlpfecPacket::parse(payload) {
            Ok(packet) => packet,
            Err(error) => {
                self.stats.fec_rejected += 1;
                return Err(error);
            }
        };
        if self.one_level_only && packet.levels.len() > 1 {
            self.stats.fec_rejected += 1;
            return Err(UlpfecError::MoreThanOneLevel);
        }
        if !self.in_window(packet.sn_base) {
            self.stats.fec_rejected += 1;
            return Err(UlpfecError::OutsideWindow);
        }
        if self.fec.iter().any(|held| held.raw[..] == *payload) {
            return Ok(Vec::new());
        }
        if self
            .fec
            .iter()
            .any(|held| breaks_rule_a(&held.packet, &packet))
        {
            self.stats.rule_violations += 1;
        }
        self.stats.fec_packets += 1;
        if self.fec.len() == ULPFEC_MAX_HELD_FEC {
            self.fec.pop_front();
        }
        self.fec.push_back(HeldFec {
            packet,
            raw: Bytes::copy_from_slice(payload),
        });
        Ok(self.recover())
    }

    /// Whether `sequence` is within the window around the newest media packet.
    fn in_window(&self, sequence: u16) -> bool {
        let Some(newest) = self.newest else {
            return true;
        };
        let behind = newest.wrapping_sub(sequence);
        let ahead = sequence.wrapping_sub(newest);
        behind <= ULPFEC_MEDIA_WINDOW || ahead <= ULPFEC_MEDIA_WINDOW
    }

    /// Move the window for a media packet, and say whether the packet is to be stored.
    fn admit(&mut self, sequence: u16) -> bool {
        let Some(newest) = self.newest else {
            self.newest = Some(sequence);
            return true;
        };
        let ahead = sequence.wrapping_sub(newest);
        if ahead == 0 {
            return true;
        }
        if ahead < 0x8000 {
            if ahead > ULPFEC_MEDIA_WINDOW
                && self.stray.map(|s| s.wrapping_add(1)) != Some(sequence)
            {
                // One packet far ahead: the first of a renumbered stream, or noise. Decide on
                // the next one.
                self.stray = Some(sequence);
                return false;
            }
            if ahead > ULPFEC_MEDIA_WINDOW {
                self.media.clear();
                self.fec.clear();
            }
            self.newest = Some(sequence);
            self.stray = None;
            self.evict();
            return true;
        }
        if newest.wrapping_sub(sequence) <= ULPFEC_MEDIA_WINDOW {
            return true;
        }
        // Far behind: a stray old packet, unless the next one follows it, which is a stream
        // that restarted its numbering.
        if self.stray.map(|s| s.wrapping_add(1)) == Some(sequence) {
            self.media.clear();
            self.fec.clear();
            self.newest = Some(sequence);
            self.stray = None;
            return true;
        }
        self.stray = Some(sequence);
        false
    }

    /// Drop what has left the window.
    fn evict(&mut self) {
        let Some(newest) = self.newest else {
            return;
        };
        let inside = |sequence: u16| {
            newest.wrapping_sub(sequence) <= ULPFEC_MEDIA_WINDOW
                || sequence.wrapping_sub(newest) <= ULPFEC_MEDIA_WINDOW
        };
        self.media.retain(|sequence, _| inside(*sequence));
        self.fec.retain(|held| inside(held.packet.sn_base));
    }

    /// Rebuild whatever the held packets allow, until a pass rebuilds nothing more.
    fn recover(&mut self) -> Vec<rtp::Packet> {
        let mut recovered = Vec::new();
        let fec = std::mem::take(&mut self.fec);
        loop {
            let mut progress = false;
            for held in &fec {
                for level in 0..held.packet.levels.len() {
                    let Some(sequence) = self.recover_level(&held.packet, level) else {
                        continue;
                    };
                    progress = true;
                    if let Some(packet) = self.complete(sequence) {
                        recovered.push(packet);
                    }
                }
            }
            if !progress {
                break;
            }
        }
        // A FEC packet all of whose packets are known in full has nothing left to give.
        self.fec = fec
            .into_iter()
            .filter(|held| {
                held.packet.levels.iter().any(|level| {
                    level.offsets().any(|offset| {
                        let sequence = held.packet.sn_base.wrapping_add(offset as u16);
                        !matches!(self.media.get(&sequence), Some(Entry::Complete(_)))
                    })
                })
            })
            .collect();
        recovered
    }

    /// Rebuild one level of the single packet that level is missing, if exactly one is missing.
    /// Returns its sequence number.
    fn recover_level(&mut self, fec: &UlpfecPacket, index: usize) -> Option<u16> {
        let level = &fec.levels[index];
        let start = fec.level_offset(index);
        let length = level.payload.len();

        // Step one (9): which packet to rebuild. The level's set minus one must be known at this
        // level, which for level 0 includes the header fields.
        let mut missing = None;
        for offset in level.offsets() {
            let sequence = fec.sn_base.wrapping_add(offset as u16);
            let known = self.media.get(&sequence).is_some_and(|entry| {
                (index > 0 || entry.bit_string().is_some()) && entry.knows(start, length)
            });
            if !known {
                if missing.is_some() {
                    return None;
                }
                missing = Some(sequence);
            }
        }
        let missing = missing?;
        if matches!(self.media.get(&missing), Some(Entry::Failed)) {
            return None;
        }

        // Step two (9.1, 9.2): the recovery bit string is the XOR of the FEC bit string and the
        // protected bit strings of the other packets.
        let mut bits = fec.header_bit_string();
        let mut octets = level.payload.to_vec();
        for offset in level.offsets() {
            let sequence = fec.sn_base.wrapping_add(offset as u16);
            if sequence == missing {
                continue;
            }
            let entry = self.media.get(&sequence)?;
            if index == 0 {
                xor_into(&mut bits, &entry.bit_string()?);
            }
            entry.xor_level(&mut octets, start);
        }

        let entry = self
            .media
            .entry(missing)
            .or_insert_with(|| Entry::Partial(Partial::default()));
        let Entry::Partial(partial) = entry else {
            return None;
        };
        if index == 0 && partial.bits.is_none() {
            // The version bits and the sequence number are not recovered; they are set when the
            // packet is put together.
            bits[0] &= 0x3F;
            bits[2] = 0;
            bits[3] = 0;
            partial.bits = Some(bits);
        }
        partial.add(start, &octets);
        Some(missing)
    }

    /// Turn a partial packet into a complete one once its header and all its octets are known.
    fn complete(&mut self, sequence: u16) -> Option<rtp::Packet> {
        let Some(Entry::Partial(partial)) = self.media.get(&sequence) else {
            return None;
        };
        let bits = partial.bits?;
        let length = partial.length()?;
        if !partial.knows(0, length) {
            return None;
        }

        let mut image = Vec::with_capacity(RTP_FIXED_HEADER + length);
        image.push(0x80 | bits[0]);
        image.push(bits[1]);
        image.extend_from_slice(&sequence.to_be_bytes());
        image.extend_from_slice(&bits[4..8]);
        image.extend_from_slice(&self.ssrc.to_be_bytes());
        let available = length.min(partial.data.len());
        image.extend_from_slice(&partial.data[..available]);
        image.resize(RTP_FIXED_HEADER + length, 0);
        let image = Bytes::from(image);

        match rtp::Packet::unmarshal(&mut image.clone()) {
            Ok(packet) => {
                self.media.insert(sequence, Entry::Complete(image));
                self.stats.recovered += 1;
                Some(packet)
            }
            Err(_) => {
                // The lengths or flags do not describe an RTP packet: the FEC data and the media
                // it was combined with do not belong together.
                self.media.insert(sequence, Entry::Failed);
                self.stats.failed += 1;
                None
            }
        }
    }
}

/// Whether two FEC packets together break rule a of RFC 5109 7.4.
fn breaks_rule_a(first: &UlpfecPacket, second: &UlpfecPacket) -> bool {
    let overlap = |level: usize| {
        let (Some(a), Some(b)) = (first.levels.get(level), second.levels.get(level)) else {
            return false;
        };
        let forward = second.sn_base.wrapping_sub(first.sn_base);
        let backward = first.sn_base.wrapping_sub(second.sn_base);
        if forward < 48 {
            u128::from(a.mask) & (u128::from(b.mask) << forward) != 0
        } else if backward < 48 {
            u128::from(b.mask) & (u128::from(a.mask) << backward) != 0
        } else {
            false
        }
    };
    if overlap(0) && first.levels[0].payload.len() != second.levels[0].payload.len() {
        return true;
    }
    (1..first.levels.len().min(second.levels.len())).any(overlap)
}

#[cfg(test)]
mod tests {
    use super::super::encoder::tests::{media, rfc_packets};
    use super::super::encoder::{ProtectionLevel, UlpfecEncoder};
    use super::*;
    use shared::marshal::Marshal;

    fn fec(packets: &[rtp::Packet], levels: &[ProtectionLevel]) -> Bytes {
        UlpfecEncoder::new()
            .encode(packets, levels)
            .unwrap()
            .marshal()
    }

    fn full(packets: &[rtp::Packet]) -> Bytes {
        let length = UlpfecEncoder::full_protection_length(packets).unwrap();
        let sequences: Vec<u16> = packets.iter().map(|p| p.header.sequence_number).collect();
        fec(packets, &[ProtectionLevel::new(length, sequences)])
    }

    /// Feed everything but the packets at `lost`, then the FEC payloads; return what came out.
    fn run(
        packets: &[rtp::Packet],
        lost: &[u16],
        fec: &[Bytes],
    ) -> (UlpfecDecoder, Vec<rtp::Packet>) {
        let mut decoder = UlpfecDecoder::new(2);
        let mut recovered = Vec::new();
        for packet in packets {
            if !lost.contains(&packet.header.sequence_number) {
                recovered.extend(decoder.push_media(packet));
            }
        }
        for payload in fec {
            recovered.extend(decoder.push_fec(payload).unwrap());
        }
        (decoder, recovered)
    }

    fn assert_identical(expected: &rtp::Packet, actual: &rtp::Packet) {
        assert_eq!(
            expected.marshal().unwrap(),
            actual.marshal().unwrap(),
            "the recovered packet is the lost one, octet for octet"
        );
    }

    #[test]
    fn a_single_loss_is_recovered_octet_for_octet() {
        let packets = rfc_packets();
        for lost in 8..12u16 {
            let (decoder, recovered) = run(&packets, &[lost], &[full(&packets)]);
            assert_eq!(1, recovered.len(), "packet {lost}");
            assert_identical(&packets[usize::from(lost - 8)], &recovered[0]);
            assert_eq!(1, decoder.stats().recovered);
            assert_eq!(0, decoder.held_fec_packets(), "nothing left for it to do");
        }
    }

    #[test]
    fn the_recovered_header_has_version_2_and_the_stream_ssrc() {
        let packets = rfc_packets();
        let (_, recovered) = run(&packets, &[8], &[full(&packets)]);
        let header = &recovered[0].header;
        assert_eq!(2, header.version);
        assert_eq!(2, header.ssrc);
        assert_eq!(8, header.sequence_number);
        assert_eq!(3, header.timestamp);
        assert_eq!(11, header.payload_type);
        assert!(header.marker);
        assert_eq!(200, recovered[0].payload.len());
    }

    #[test]
    fn nothing_is_recovered_without_a_loss_or_beyond_one_loss_per_fec_packet() {
        let packets = rfc_packets();
        let (_, recovered) = run(&packets, &[], &[full(&packets)]);
        assert!(recovered.is_empty());

        let (decoder, recovered) = run(&packets, &[8, 9], &[full(&packets)]);
        assert!(recovered.is_empty(), "one parity packet cannot rebuild two");
        assert_eq!(1, decoder.held_fec_packets(), "it waits for one of them");
    }

    #[test]
    fn a_late_media_packet_completes_a_waiting_fec_packet() {
        let packets = rfc_packets();
        let (mut decoder, recovered) = run(&packets, &[8, 9], &[full(&packets)]);
        assert!(recovered.is_empty());
        let recovered = decoder.push_media(&packets[1]);
        assert_eq!(1, recovered.len());
        assert_identical(&packets[0], &recovered[0]);
    }

    #[test]
    fn fec_arriving_before_the_media_recovers_when_the_media_arrives() {
        let packets = rfc_packets();
        let mut decoder = UlpfecDecoder::new(2);
        assert!(decoder.push_fec(&full(&packets)).unwrap().is_empty());
        let mut recovered = Vec::new();
        for packet in &packets[..3] {
            recovered.extend(decoder.push_media(packet));
        }
        assert_eq!(1, recovered.len());
        assert_identical(&packets[3], &recovered[0]);
    }

    #[test]
    fn a_burst_is_recovered_by_interleaved_fec_packets() {
        let packets: Vec<_> = (100..106)
            .map(|seq| media(seq, u32::from(seq) * 10, 96, false, 50 + usize::from(seq)))
            .collect();
        // Three FEC packets, each over every third media packet: any burst of three is covered.
        let fec_packets: Vec<Bytes> = (0..3)
            .map(|phase| {
                let group: Vec<_> = packets
                    .iter()
                    .filter(|p| (p.header.sequence_number - 100) % 3 == phase)
                    .cloned()
                    .collect();
                full(&group)
            })
            .collect();
        let (_, mut recovered) = run(&packets, &[101, 102, 103], &fec_packets);
        recovered.sort_by_key(|p| p.header.sequence_number);
        assert_eq!(3, recovered.len());
        for (index, packet) in recovered.iter().enumerate() {
            assert_identical(&packets[index + 1], packet);
        }
    }

    #[test]
    fn one_recovery_enables_another() {
        let packets: Vec<_> = (1..5).map(|seq| media(seq, 0, 96, false, 20)).collect();
        // Rows {1,2} and {3,4}, column {1,3}: losing 1, 2 and 3 needs the column first (it has
        // one unknown only once row {3,4} gave back 3), then row {1,2}.
        let rows = [full(&packets[..2]), full(&packets[2..])];
        let column = full(&[packets[0].clone(), packets[2].clone()]);
        let (_, mut recovered) = run(
            &packets,
            &[1, 2, 3],
            &[rows[0].clone(), column, rows[1].clone()],
        );
        recovered.sort_by_key(|p| p.header.sequence_number);
        assert_eq!(3, recovered.len());
        for (index, packet) in recovered.iter().enumerate() {
            assert_identical(&packets[index], packet);
        }
    }

    #[test]
    fn recovery_works_across_the_sequence_number_wrap() {
        let packets: Vec<_> = [65534u16, 65535, 0, 1]
            .into_iter()
            .map(|seq| media(seq, 77, 96, false, 30))
            .collect();
        for lost in [65535u16, 0] {
            let (_, recovered) = run(&packets, &[lost], &[full(&packets)]);
            assert_eq!(1, recovered.len());
            assert_eq!(lost, recovered[0].header.sequence_number);
            let original = packets
                .iter()
                .find(|p| p.header.sequence_number == lost)
                .unwrap();
            assert_identical(original, &recovered[0]);
        }
    }

    #[test]
    fn csrc_extension_and_padding_of_a_lost_packet_come_back() {
        let mut rich = media(9, 5, 96, true, 33);
        rich.header.csrc = vec![1, 2];
        rich.header.padding = true;
        rich.header.padding_size = 7;
        rich.header
            .set_extension(3, Bytes::from_static(&[0xDE, 0xAD]))
            .unwrap();
        // What a receiver holds is the packet as parsed from the wire.
        let rich = rtp::Packet::unmarshal(&mut rich.marshal().unwrap().freeze()).unwrap();
        let packets = vec![media(8, 3, 96, false, 60), rich.clone()];

        let (_, recovered) = run(&packets, &[9], &[full(&packets)]);

        assert_eq!(1, recovered.len());
        assert_identical(&rich, &recovered[0]);
        assert_eq!(vec![1, 2], recovered[0].header.csrc);
        assert!(recovered[0].header.padding);
        assert_eq!(7, recovered[0].header.padding_size);
        assert_eq!(
            Some(Bytes::from_static(&[0xDE, 0xAD])),
            recovered[0].header.get_extension(3)
        );
        assert_eq!(rich.payload, recovered[0].payload);
    }

    #[test]
    fn packets_of_unequal_length_are_recovered_to_their_own_length() {
        let packets = rfc_packets();
        // C is the shortest (100), D the longest (340).
        let (_, recovered) = run(&packets, &[10], &[full(&packets)]);
        assert_eq!(100, recovered[0].payload.len());
        let (_, recovered) = run(&packets, &[11], &[full(&packets)]);
        assert_eq!(340, recovered[0].payload.len());
    }

    /// RFC 5109 10.2 as a recovery: L0 = 70 over {A, B} and {C, D}, L1 = 90 over all four.
    fn two_level_scheme(packets: &[rtp::Packet]) -> Vec<Bytes> {
        vec![
            fec(packets, &[ProtectionLevel::new(70, [8, 9])]),
            fec(
                packets,
                &[
                    ProtectionLevel::new(70, [10, 11]),
                    ProtectionLevel::new(90, [8, 9, 10, 11]),
                ],
            ),
        ]
    }

    #[test]
    fn two_levels_rebuild_a_packet_that_fits_within_them() {
        let packets = rfc_packets();
        // B is 140 octets: level 0 gives the first 70, level 1 the next 90, which reaches its end.
        let (decoder, recovered) = run(&packets, &[9], &two_level_scheme(&packets));
        assert_eq!(1, recovered.len());
        assert_identical(&packets[1], &recovered[0]);
        assert_eq!(0, decoder.partial_packets());

        // C is 100 octets, protected at level 0 by the second FEC packet.
        let (_, recovered) = run(&packets, &[10], &two_level_scheme(&packets));
        assert_identical(&packets[2], &recovered[0]);
    }

    #[test]
    fn a_packet_longer_than_its_protection_is_recovered_in_part_and_not_delivered() {
        let packets = rfc_packets();
        // A is 200 octets; the two levels cover 160.
        let (decoder, recovered) = run(&packets, &[8], &two_level_scheme(&packets));
        assert!(
            recovered.is_empty(),
            "the recovered length says 200 octets and 160 were rebuilt"
        );
        assert_eq!(1, decoder.partial_packets());
        assert_eq!(0, decoder.stats().recovered);
    }

    #[test]
    fn level_0_alone_rebuilds_a_packet_no_longer_than_it() {
        let packets = vec![media(8, 3, 96, false, 60), media(9, 5, 96, true, 200)];
        let payload = fec(&packets, &[ProtectionLevel::new(70, [8, 9])]);
        let (_, recovered) = run(&packets, &[8], std::slice::from_ref(&payload));
        assert_eq!(1, recovered.len(), "60 octets fit in L0 = 70");
        assert_identical(&packets[0], &recovered[0]);

        let (decoder, recovered) = run(&packets, &[9], &[payload]);
        assert!(recovered.is_empty(), "200 octets do not");
        assert_eq!(1, decoder.partial_packets());
    }

    #[test]
    fn a_level_1_recovery_uses_a_packet_recovered_only_in_part() {
        // Level 0 of the second FEC packet covers C and D; level 1 covers all four. With A and C
        // lost, C comes back at level 0 from FEC 2 (D is known), A at level 0 from FEC 1 (B is
        // known), and level 1 then has two packets unknown in its range: neither is delivered
        // unless short enough. C is 100 octets: 70 from level 0, the rest needs level 1.
        let packets = rfc_packets();
        let (decoder, recovered) = run(&packets, &[8, 10], &two_level_scheme(&packets));
        assert!(recovered.is_empty());
        assert_eq!(2, decoder.partial_packets());

        // With C short enough to be whole after level 0, level 1 has one unknown left (A), and
        // rebuilding A's level 1 needs C's octets 70..160: zeros past its end.
        let mut packets = rfc_packets();
        packets[2] = media(10, 7, 11, true, 64);
        packets[0] = media(8, 3, 11, true, 150);
        let (decoder, mut recovered) = run(&packets, &[8, 10], &two_level_scheme(&packets));
        recovered.sort_by_key(|p| p.header.sequence_number);
        assert_eq!(2, recovered.len());
        assert_identical(&packets[0], &recovered[0]);
        assert_identical(&packets[2], &recovered[1]);
        assert_eq!(0, decoder.partial_packets());
    }

    #[test]
    fn one_level_only_refuses_a_second_level() {
        let packets = rfc_packets();
        let scheme = two_level_scheme(&packets);
        let mut decoder = UlpfecDecoder::new(2).with_one_level_only(true);
        assert_eq!(Ok(Vec::new()), decoder.push_fec(&scheme[0]));
        assert_eq!(
            Err(UlpfecError::MoreThanOneLevel),
            decoder.push_fec(&scheme[1])
        );
        assert_eq!(1, decoder.stats().fec_rejected);
        assert_eq!(1, decoder.held_fec_packets());
    }

    #[test]
    fn a_malformed_fec_payload_is_refused_and_counted() {
        let mut decoder = UlpfecDecoder::new(2);
        assert_eq!(Err(UlpfecError::TooShort), decoder.push_fec(&[0u8; 5]));
        assert_eq!(1, decoder.stats().fec_rejected);
        assert_eq!(0, decoder.held_fec_packets());
    }

    #[test]
    fn a_second_copy_of_a_fec_packet_changes_nothing() {
        let packets = rfc_packets();
        let payload = full(&packets);
        let (mut decoder, _) = run(&packets, &[8, 9], std::slice::from_ref(&payload));
        assert_eq!(Ok(Vec::new()), decoder.push_fec(&payload));
        assert_eq!(1, decoder.held_fec_packets());
        assert_eq!(1, decoder.stats().fec_packets);
    }

    #[test]
    fn a_recovered_packet_is_not_recovered_twice() {
        let packets = rfc_packets();
        let first = full(&packets);
        let second = full(&packets[..2]);
        let (_, recovered) = run(&packets, &[8], &[first, second]);
        assert_eq!(1, recovered.len());
    }

    #[test]
    fn a_broken_rule_a_is_counted_and_the_packet_still_used() {
        let packets = rfc_packets();
        let first = fec(
            &packets,
            &[
                ProtectionLevel::new(70, [8, 9]),
                ProtectionLevel::new(90, [8, 9]),
            ],
        );
        let second = fec(
            &packets,
            &[
                ProtectionLevel::new(70, [10, 11]),
                ProtectionLevel::new(90, [9, 10, 11]),
            ],
        );
        let mut decoder = UlpfecDecoder::new(2);
        decoder.push_fec(&first).unwrap();
        decoder.push_fec(&second).unwrap();
        assert_eq!(1, decoder.stats().rule_violations, "9 is at level 1 twice");

        // Level 0 twice with different lengths is the other half of the rule.
        let mut decoder = UlpfecDecoder::new(2);
        decoder
            .push_fec(&fec(&packets, &[ProtectionLevel::new(70, [9, 10])]))
            .unwrap();
        decoder
            .push_fec(&fec(&packets, &[ProtectionLevel::new(80, [10, 11])]))
            .unwrap();
        assert_eq!(1, decoder.stats().rule_violations);
        let mut decoder = UlpfecDecoder::new(2);
        decoder
            .push_fec(&fec(&packets, &[ProtectionLevel::new(70, [9, 10])]))
            .unwrap();
        decoder
            .push_fec(&fec(&packets, &[ProtectionLevel::new(70, [10, 11])]))
            .unwrap();
        assert_eq!(
            0,
            decoder.stats().rule_violations,
            "equal lengths are allowed"
        );
    }

    #[test]
    fn inconsistent_fec_data_does_not_produce_a_packet() {
        let packets = vec![media(8, 3, 96, false, 20), media(9, 5, 96, false, 20)];
        let mut payload = full(&packets).to_vec();
        // CC recovery claims 15 CSRCs the 20 recovered octets cannot hold.
        payload[0] |= 0x0F;
        let mut decoder = UlpfecDecoder::new(2);
        decoder.push_media(&packets[0]);
        assert_eq!(Ok(Vec::new()), decoder.push_fec(&payload));
        assert_eq!(1, decoder.stats().failed);
        // And it is not tried again on every later packet.
        decoder.push_media(&media(10, 7, 96, false, 20));
        assert_eq!(1, decoder.stats().failed);
    }

    #[test]
    fn media_of_another_ssrc_is_ignored() {
        let mut other = media(8, 3, 96, false, 20);
        other.header.ssrc = 99;
        let mut decoder = UlpfecDecoder::new(2);
        decoder.push_media(&other);
        assert_eq!(0, decoder.held_media_packets());
    }

    #[test]
    fn memory_stays_bounded_over_a_long_stream() {
        let mut decoder = UlpfecDecoder::new(2);
        for index in 0..5000u32 {
            let seq = index as u16;
            if index % 3 != 0 {
                decoder.push_media(&media(seq, index, 96, false, 10));
            }
            if index % 4 == 3 {
                // FEC over packets of which two are missing: never completes, so it is held.
                let group: Vec<_> = (0..4)
                    .map(|back| media(seq - 3 + back, index, 96, false, 10))
                    .collect();
                let _ = decoder.push_fec(&full(&group));
            }
        }
        assert!(decoder.held_media_packets() <= 2 * usize::from(ULPFEC_MEDIA_WINDOW) + 1);
        assert!(decoder.held_fec_packets() <= ULPFEC_MAX_HELD_FEC);
    }

    #[test]
    fn fec_far_from_the_stream_is_refused() {
        let mut decoder = UlpfecDecoder::new(2);
        decoder.push_media(&media(1000, 0, 96, false, 10));
        let far: Vec<_> = (5000..5002).map(|s| media(s, 0, 96, false, 10)).collect();
        assert_eq!(
            Err(UlpfecError::OutsideWindow),
            decoder.push_fec(&full(&far))
        );
    }

    #[test]
    fn a_stale_fec_packet_is_dropped_before_the_sequence_numbers_come_round_again() {
        let mut decoder = UlpfecDecoder::new(2);
        let group: Vec<_> = (10..14).map(|s| media(s, 0, 96, false, 10)).collect();
        decoder.push_media(&group[0]);
        decoder.push_fec(&full(&group)).unwrap();
        assert_eq!(1, decoder.held_fec_packets());
        for seq in 14..14 + 2 * ULPFEC_MEDIA_WINDOW {
            decoder.push_media(&media(seq, 0, 96, false, 10));
        }
        assert_eq!(0, decoder.held_fec_packets());
    }

    #[test]
    fn a_stream_that_restarts_its_numbering_is_followed() {
        let mut decoder = UlpfecDecoder::new(2);
        for seq in 30000..30010 {
            decoder.push_media(&media(seq, 0, 96, false, 10));
        }
        let packets: Vec<_> = (100..104).map(|s| media(s, 0, 96, false, 10)).collect();
        // The first packet of the new numbering could be a stray; the second settles it.
        decoder.push_media(&packets[0]);
        decoder.push_media(&packets[1]);
        decoder.push_media(&packets[2]);
        let group = &packets[1..];
        let recovered = decoder.push_fec(&full(group)).unwrap();
        assert_eq!(1, recovered.len());
        assert_identical(&packets[3], &recovered[0]);
    }

    #[test]
    fn one_stray_old_packet_does_not_reset_the_decoder() {
        let packets = rfc_packets();
        let mut decoder = UlpfecDecoder::new(2);
        decoder.push_media(&packets[0]);
        decoder.push_media(&packets[1]);
        decoder.push_media(&media(40000, 0, 96, false, 10));
        decoder.push_media(&packets[2]);
        let recovered = decoder.push_fec(&full(&packets)).unwrap();
        assert_eq!(1, recovered.len());
        assert_identical(&packets[3], &recovered[0]);
    }
}
