//! The protection operation (RFC 5109 section 8) and the FEC packets of a separate stream (7.2).

use super::UlpfecError;
use super::header::{LONG_MASK_BITS, SHORT_MASK_BITS, UlpfecLevel, UlpfecPacket};
use bytes::Bytes;
use shared::marshal::Marshal;
use std::collections::HashMap;
use std::time::Instant;

/// Octets of the fixed RTP header, which the FEC header protects; level payloads start after it.
pub(crate) const RTP_FIXED_HEADER: usize = 12;

/// One protection level to generate: how many octets it covers and which packets it protects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionLevel {
    /// The level's protection length `Ln`, in octets.
    pub protection_length: u16,
    /// Sequence numbers of the media packets protected at this level.
    pub sequence_numbers: Vec<u16>,
}

impl ProtectionLevel {
    /// A level of `protection_length` octets over `sequence_numbers`.
    pub fn new(protection_length: u16, sequence_numbers: impl Into<Vec<u16>>) -> Self {
        Self {
            protection_length,
            sequence_numbers: sequence_numbers.into(),
        }
    }
}

/// The octets of a media packet as they go on the wire: what the FEC protects.
pub(crate) fn wire_image(packet: &rtp::Packet) -> Result<Bytes, UlpfecError> {
    let image = packet
        .marshal()
        .map_err(|_| UlpfecError::PacketTooLarge)?
        .freeze();
    if image.len() < RTP_FIXED_HEADER || image.len() - RTP_FIXED_HEADER > usize::from(u16::MAX) {
        return Err(UlpfecError::PacketTooLarge);
    }
    Ok(image)
}

/// The 80-bit protected bit string of a media packet (RFC 5109 8.1): the first 64 bits of its RTP
/// header, then its length minus the 12 octets of the fixed header.
pub(crate) fn protected_bit_string(image: &[u8]) -> [u8; 10] {
    let mut bits = [0u8; 10];
    bits[..8].copy_from_slice(&image[..8]);
    let length = (image.len() - RTP_FIXED_HEADER) as u16;
    bits[8..].copy_from_slice(&length.to_be_bytes());
    bits
}

/// XOR `source` into `target`, as far as the shorter of the two goes. A source shorter than the
/// target leaves the rest untouched, which is the zero padding of 8.2.
pub(crate) fn xor_into(target: &mut [u8], source: &[u8]) {
    for (target, source) in target.iter_mut().zip(source) {
        *target ^= source;
    }
}

/// The `length` octets of a packet's level starting `offset` octets after the fixed header, as
/// far as the packet reaches.
pub(crate) fn level_slice(image: &[u8], offset: usize, length: usize) -> &[u8] {
    let start = (RTP_FIXED_HEADER + offset).min(image.len());
    let end = (start + length).min(image.len());
    &image[start..end]
}

/// Generates ULPFEC payloads.
///
/// Stateless: every call is one FEC packet over the media packets and levels it is given.
#[derive(Debug, Clone, Copy, Default)]
pub struct UlpfecEncoder;

impl UlpfecEncoder {
    /// An encoder.
    pub fn new() -> Self {
        Self
    }

    /// The protection length that covers every packet in `media` to its end: the longest
    /// packet's length after the fixed RTP header.
    pub fn full_protection_length(media: &[rtp::Packet]) -> Result<u16, UlpfecError> {
        let mut longest = 0usize;
        for packet in media {
            longest = longest.max(wire_image(packet)?.len() - RTP_FIXED_HEADER);
        }
        Ok(longest as u16)
    }

    /// Generate one FEC packet protecting `media` at `levels` (level 0 first).
    ///
    /// The packets are protected as they marshal: CSRC list, header extension, payload and
    /// padding all count as payload (7.3). Each level names its packets by sequence number; a
    /// number that is not in `media` is an error, as is a level without packets and a set of
    /// packets spanning more than 48 sequence numbers. Rule c of 7.4 (a packet holding level `p`
    /// holds level `p - 1`) holds by construction; rules a and b, which relate several FEC
    /// packets, are checked by [`validate_scheme`].
    pub fn encode(
        &self,
        media: &[rtp::Packet],
        levels: &[ProtectionLevel],
    ) -> Result<UlpfecPacket, UlpfecError> {
        let mut images = HashMap::with_capacity(media.len());
        for packet in media {
            images.insert(packet.header.sequence_number, wire_image(packet)?);
        }
        self.encode_images(&images, levels)
    }

    /// [`encode`](Self::encode) over packets already serialised.
    pub(crate) fn encode_images(
        &self,
        images: &HashMap<u16, Bytes>,
        levels: &[ProtectionLevel],
    ) -> Result<UlpfecPacket, UlpfecError> {
        if levels.is_empty() || levels.iter().any(|level| level.sequence_numbers.is_empty()) {
            return Err(UlpfecError::NothingToProtect);
        }
        let mut protected: Vec<u16> = levels
            .iter()
            .flat_map(|level| level.sequence_numbers.iter().copied())
            .collect();
        protected.sort_unstable();
        protected.dedup();
        if protected
            .iter()
            .any(|sequence| !images.contains_key(sequence))
        {
            return Err(UlpfecError::UnknownSequenceNumber);
        }

        // SN base: the lowest protected sequence number, wrap taken into account (7.3). That is
        // the one from which every other is reached going forward by the least distance.
        let (sn_base, span) = protected
            .iter()
            .map(|base| {
                let span = protected
                    .iter()
                    .map(|sequence| sequence.wrapping_sub(*base))
                    .max()
                    .unwrap_or(0);
                (*base, usize::from(span))
            })
            .min_by_key(|(_, span)| *span)
            .ok_or(UlpfecError::NothingToProtect)?;
        if span >= LONG_MASK_BITS {
            return Err(UlpfecError::SpanTooWide);
        }

        // FEC header: the XOR of the bit strings of the packets protected at level 0 (8.1).
        let mut bits = [0u8; 10];
        let mut level0: Vec<u16> = levels[0].sequence_numbers.clone();
        level0.sort_unstable();
        level0.dedup();
        for sequence in &level0 {
            xor_into(&mut bits, &protected_bit_string(&images[sequence]));
        }

        let mut out_levels = Vec::with_capacity(levels.len());
        let mut offset = 0usize;
        for level in levels {
            let length = usize::from(level.protection_length);
            let mut payload = vec![0u8; length];
            let mut mask = 0u64;
            let mut sequences = level.sequence_numbers.clone();
            sequences.sort_unstable();
            sequences.dedup();
            for sequence in &sequences {
                mask |= 1u64 << sequence.wrapping_sub(sn_base);
                xor_into(&mut payload, level_slice(&images[sequence], offset, length));
            }
            out_levels.push(UlpfecLevel {
                mask,
                payload: Bytes::from(payload),
            });
            offset += length;
        }

        Ok(UlpfecPacket {
            long_mask: span >= SHORT_MASK_BITS,
            padding_recovery: bits[0] & 0x20 != 0,
            extension_recovery: bits[0] & 0x10 != 0,
            csrc_count_recovery: bits[0] & 0x0F,
            marker_recovery: bits[1] & 0x80 != 0,
            payload_type_recovery: bits[1] & 0x7F,
            sn_base,
            timestamp_recovery: u32::from_be_bytes([bits[4], bits[5], bits[6], bits[7]]),
            length_recovery: u16::from_be_bytes([bits[8], bits[9]]),
            levels: out_levels,
        })
    }
}

/// Check the mask rules of RFC 5109 7.4 that relate the FEC packets of one group.
///
/// `packets` holds the levels of each FEC packet, level 0 first.
///
/// - **Rule a.** A media packet is protected at most once at each level above 0. At level 0 it
///   may be protected by several FEC packets when their level-0 protection lengths are equal.
/// - **Rule b.** A media packet protected at level `p` is protected at level `p - 1`, in this or
///   another FEC packet of the group.
///
/// Rule c is not checked here because it cannot be broken: a FEC packet's levels are a list.
pub fn validate_scheme(packets: &[&[ProtectionLevel]]) -> Result<(), UlpfecError> {
    // (level, sequence number) -> the protection length it was first protected with.
    let mut seen: HashMap<(usize, u16), u16> = HashMap::new();
    for levels in packets {
        if levels.is_empty() {
            return Err(UlpfecError::NothingToProtect);
        }
        for (index, level) in levels.iter().enumerate() {
            if level.sequence_numbers.is_empty() {
                return Err(UlpfecError::NothingToProtect);
            }
            let mut sequences = level.sequence_numbers.clone();
            sequences.sort_unstable();
            sequences.dedup();
            for sequence in sequences {
                match seen.insert((index, sequence), level.protection_length) {
                    None => {}
                    Some(_) if index > 0 => return Err(UlpfecError::ProtectedTwice),
                    Some(length) if length != level.protection_length => {
                        return Err(UlpfecError::ProtectedTwice);
                    }
                    Some(_) => {}
                }
            }
        }
    }
    for (level, sequence) in seen.keys() {
        if *level > 0 && !seen.contains_key(&(level - 1, *sequence)) {
            return Err(UlpfecError::LevelBelowMissing);
        }
    }
    Ok(())
}

/// Builds the RTP packets of a FEC stream sent apart from the media (RFC 5109 7.2, 14.1).
///
/// The sequence number is one higher than the previous FEC packet's, the marker bit is 0, and the
/// timestamp is the media RTP clock at the instant the FEC packet is sent: the timestamp of the
/// last media packet, advanced by the time since that packet at the stream's clock rate.
///
/// The RFC sets the SSRC to the protected stream's and puts the FEC stream in its own RTP
/// session. Pass the media SSRC for that. Within one RTP session (a WebRTC transport) the FEC
/// stream needs an SSRC of its own, since two sequence number spaces cannot share one.
#[derive(Debug, Clone)]
pub struct UlpfecStreamPacketizer {
    payload_type: u8,
    ssrc: u32,
    clock_rate: u32,
    next_sequence_number: u16,
    /// The last media packet seen: its RTP timestamp and when it was sent.
    media_clock: Option<(u32, Instant)>,
}

impl UlpfecStreamPacketizer {
    /// A packetizer for FEC packets of `payload_type` on `ssrc`, whose first packet has
    /// `initial_sequence_number`. `clock_rate` is the protected media's.
    pub fn new(payload_type: u8, ssrc: u32, clock_rate: u32, initial_sequence_number: u16) -> Self {
        Self {
            payload_type,
            ssrc,
            clock_rate,
            next_sequence_number: initial_sequence_number,
            media_clock: None,
        }
    }

    /// Note a media packet of the protected stream going out at `now` with `timestamp`.
    pub fn on_media(&mut self, timestamp: u32, now: Instant) {
        self.media_clock = Some((timestamp, now));
    }

    /// The media RTP clock at `now`.
    fn timestamp_at(&self, now: Instant) -> u32 {
        match self.media_clock {
            None => 0,
            Some((timestamp, at)) => {
                let elapsed = now.saturating_duration_since(at);
                let ticks = elapsed.as_micros() * u128::from(self.clock_rate) / 1_000_000;
                timestamp.wrapping_add(ticks as u32)
            }
        }
    }

    /// The RTP packet carrying `fec`, sent at `now`.
    pub fn packetize(&mut self, fec: &UlpfecPacket, now: Instant) -> rtp::Packet {
        let sequence_number = self.next_sequence_number;
        self.next_sequence_number = self.next_sequence_number.wrapping_add(1);
        rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                marker: false,
                payload_type: self.payload_type,
                sequence_number,
                timestamp: self.timestamp_at(now),
                ssrc: self.ssrc,
                ..Default::default()
            },
            payload: fec.marshal(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::time::Duration;

    /// A media packet whose payload is a function of its sequence number, so two packets never
    /// cancel each other by accident.
    pub(crate) fn media(
        sequence_number: u16,
        timestamp: u32,
        payload_type: u8,
        marker: bool,
        payload_length: usize,
    ) -> rtp::Packet {
        let payload: Vec<u8> = (0..payload_length)
            .map(|index| (index as u8).wrapping_mul(31) ^ (sequence_number as u8).wrapping_mul(7))
            .collect();
        rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                marker,
                payload_type,
                sequence_number,
                timestamp,
                ssrc: 2,
                ..Default::default()
            },
            payload: Bytes::from(payload),
        }
    }

    /// The four media packets of RFC 5109 section 10: A, B, C and D from SSRC 2, sequence
    /// numbers 8 to 11, timestamps 3, 5, 7, 9, payload types 11, 18, 11, 18, payloads of 200,
    /// 140, 100 and 340 octets, marker set on A and C.
    pub(crate) fn rfc_packets() -> Vec<rtp::Packet> {
        vec![
            media(8, 3, 11, true, 200),
            media(9, 5, 18, false, 140),
            media(10, 7, 11, true, 100),
            media(11, 9, 18, false, 340),
        ]
    }

    /// RFC 5109 10.1: one level over the four packets, L0 = 340. Figures 7, 8 and 9.
    #[test]
    fn rfc_5109_10_1_one_level_matches_the_printed_headers() {
        let packets = rfc_packets();
        assert_eq!(
            Ok(340),
            UlpfecEncoder::full_protection_length(&packets),
            "L0 is the longest of 200, 140, 100 and 340"
        );
        let fec = UlpfecEncoder::new()
            .encode(&packets, &[ProtectionLevel::new(340, [8, 9, 10, 11])])
            .unwrap();
        let wire = fec.marshal();

        // Figure 8: E 0, L 0, P/X/CC/M/PT recovery 0, SN base 8, TS recovery 8, length 372.
        assert_eq!(
            &[0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x01, 0x74],
            &wire[..10]
        );
        // Figure 9: L0 340, mask 61440.
        assert_eq!(&[0x01, 0x54, 0xF0, 0x00], &wire[10..14]);
        assert_eq!(14 + 340, wire.len(), "the level 0 payload is 340 octets");

        // Figure 7: the RTP header of the FEC packet, sent in its own session on the media SSRC.
        let now = Instant::now();
        let mut packetizer = UlpfecStreamPacketizer::new(127, 2, 8000, 1);
        for packet in &packets {
            packetizer.on_media(packet.header.timestamp, now);
        }
        let rtp_packet = packetizer.packetize(&fec, now);
        let rtp_wire = rtp_packet.marshal().unwrap();
        assert_eq!(
            &[
                0x80, 0x7F, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x02
            ],
            &rtp_wire[..12]
        );
    }

    /// RFC 5109 10.2: two FEC packets, L0 = 70 and L1 = 90. Figures 12, 13, 15, 16 and 17.
    #[test]
    fn rfc_5109_10_2_two_levels_match_the_printed_headers() {
        let packets = rfc_packets();
        let first = [ProtectionLevel::new(70, [8, 9])];
        let second = [
            ProtectionLevel::new(70, [10, 11]),
            ProtectionLevel::new(90, [8, 9, 10, 11]),
        ];
        validate_scheme(&[&first, &second]).expect("the scheme of Figure 10 follows 7.4");

        let encoder = UlpfecEncoder::new();
        let wire1 = encoder.encode(&packets, &first).unwrap().marshal();
        // Figure 12: PT recovery 25, SN base 8, TS recovery 6, length recovery 68. The figure
        // prints M recovery as 0, with the four-packet sum of 10.1 as its reason; over the two
        // packets this FEC packet protects at level 0 (A with the marker, B without) the
        // operation of 8.1 gives 1, which is what a receiver needs to rebuild either.
        assert_eq!(
            &[0x00, 0x99, 0x00, 0x08, 0x00, 0x00, 0x00, 0x06, 0x00, 0x44],
            &wire1[..10]
        );
        // Figure 13: L0 70, mask 49152.
        assert_eq!(&[0x00, 0x46, 0xC0, 0x00], &wire1[10..14]);
        assert_eq!(14 + 70, wire1.len());

        let fec2 = encoder.encode(&packets, &second).unwrap();
        let wire2 = fec2.marshal();
        // Figure 15: PT recovery 25, SN base 8 (the lowest over both levels), TS recovery 14,
        // length recovery 304. M recovery is 1 for the same reason (C with the marker, D without).
        assert_eq!(
            &[0x00, 0x99, 0x00, 0x08, 0x00, 0x00, 0x00, 0x0E, 0x01, 0x30],
            &wire2[..10]
        );
        // Figure 16: L0 70, mask 12288.
        assert_eq!(&[0x00, 0x46, 0x30, 0x00], &wire2[10..14]);
        // Figure 17: L1 90, mask 61440, after the 70 octets of level 0.
        assert_eq!(&[0x00, 0x5A, 0xF0, 0x00], &wire2[84..88]);
        assert_eq!(14 + 70 + 4 + 90, wire2.len());

        // Figures 11 and 14: sequence numbers 1 and 2, timestamps 5 and 9 (the media clock when
        // each is sent: after B, and after D). The figures print the marker bit as 1; 7.2 says
        // it SHALL be 0, and 0 is what is sent.
        let now = Instant::now();
        let mut packetizer = UlpfecStreamPacketizer::new(127, 2, 8000, 1);
        packetizer.on_media(3, now);
        packetizer.on_media(5, now);
        let rtp1 = packetizer.packetize(&encoder.encode(&packets, &first).unwrap(), now);
        packetizer.on_media(7, now);
        packetizer.on_media(9, now);
        let rtp2 = packetizer.packetize(&fec2, now);
        assert_eq!((1, 5, 2, 127), header_fields(&rtp1));
        assert_eq!((2, 9, 2, 127), header_fields(&rtp2));
        assert!(!rtp1.header.marker && !rtp2.header.marker);
    }

    fn header_fields(packet: &rtp::Packet) -> (u16, u32, u32, u8) {
        (
            packet.header.sequence_number,
            packet.header.timestamp,
            packet.header.ssrc,
            packet.header.payload_type,
        )
    }

    #[test]
    fn the_level_payload_is_the_xor_with_short_packets_padded_by_zero() {
        let packets = vec![media(1, 0, 96, false, 4), media(2, 0, 96, false, 2)];
        let fec = UlpfecEncoder::new()
            .encode(&packets, &[ProtectionLevel::new(6, [1, 2])])
            .unwrap();
        let a = &packets[0].payload;
        let b = &packets[1].payload;
        assert_eq!(
            &[a[0] ^ b[0], a[1] ^ b[1], a[2], a[3], 0, 0],
            &fec.levels[0].payload[..],
            "the shorter packet counts as zeros, and so does everything past the longest"
        );
        assert_eq!(4 ^ 2, fec.length_recovery);
    }

    #[test]
    fn a_higher_level_starts_where_the_levels_below_end() {
        let packets = vec![media(1, 0, 96, false, 10), media(2, 0, 96, false, 10)];
        let fec = UlpfecEncoder::new()
            .encode(
                &packets,
                &[
                    ProtectionLevel::new(3, [1, 2]),
                    ProtectionLevel::new(4, [1, 2]),
                ],
            )
            .unwrap();
        let a = &packets[0].payload;
        let b = &packets[1].payload;
        let expected: Vec<u8> = (3..7).map(|index| a[index] ^ b[index]).collect();
        assert_eq!(&expected[..], &fec.levels[1].payload[..]);
    }

    #[test]
    fn csrc_extension_and_padding_count_as_payload() {
        let mut with_everything = media(1, 0, 96, false, 5);
        with_everything.header.csrc = vec![0xAABB_CCDD];
        with_everything.header.padding = true;
        with_everything.header.padding_size = 3;
        with_everything
            .header
            .set_extension(1, Bytes::from_static(&[0x42]))
            .unwrap();
        let plain = media(2, 0, 96, false, 5);
        let wire = with_everything.marshal().unwrap();

        let fec = UlpfecEncoder::new()
            .encode(
                &[with_everything, plain.clone()],
                &[ProtectionLevel::new(40, [1, 2])],
            )
            .unwrap();

        assert!(fec.padding_recovery && fec.extension_recovery);
        assert_eq!(1, fec.csrc_count_recovery);
        assert_eq!(
            (wire.len() - 12) as u16 ^ 5,
            fec.length_recovery,
            "length is everything after the fixed header"
        );
        let mut expected = wire[12..].to_vec();
        expected.resize(40, 0);
        xor_into(&mut expected, &plain.payload);
        assert_eq!(&expected[..], &fec.levels[0].payload[..]);
    }

    #[test]
    fn the_sn_base_is_the_lowest_sequence_number_across_a_wrap() {
        let packets = vec![
            media(65534, 0, 96, false, 3),
            media(65535, 0, 96, false, 3),
            media(0, 0, 96, false, 3),
            media(1, 0, 96, false, 3),
        ];
        let fec = UlpfecEncoder::new()
            .encode(&packets, &[ProtectionLevel::new(3, [0, 1, 65535, 65534])])
            .unwrap();
        assert_eq!(65534, fec.sn_base);
        assert_eq!(0b1111, fec.levels[0].mask);
        assert!(!fec.long_mask);
    }

    #[test]
    fn the_sn_base_covers_packets_protected_only_at_a_higher_level() {
        let packets = rfc_packets();
        let fec = UlpfecEncoder::new()
            .encode(
                &packets,
                &[
                    ProtectionLevel::new(70, [10, 11]),
                    ProtectionLevel::new(90, [8, 9, 10, 11]),
                ],
            )
            .unwrap();
        assert_eq!(8, fec.sn_base);
        assert_eq!(0b1100, fec.levels[0].mask);
        assert_eq!(0b1111, fec.levels[1].mask);
    }

    #[test]
    fn a_span_beyond_sixteen_packets_uses_the_long_mask() {
        let packets: Vec<_> = (100..148).map(|seq| media(seq, 0, 96, false, 2)).collect();
        let encoder = UlpfecEncoder::new();
        let short = encoder
            .encode(&packets, &[ProtectionLevel::new(2, [100, 115])])
            .unwrap();
        assert!(!short.long_mask, "offset 15 fits the 16-bit mask");
        let long = encoder
            .encode(&packets, &[ProtectionLevel::new(2, [100, 116, 147])])
            .unwrap();
        assert!(long.long_mask);
        assert_eq!(
            vec![0, 16, 47],
            long.levels[0].offsets().collect::<Vec<_>>()
        );
        assert_eq!(long, UlpfecPacket::parse(&long.marshal()).unwrap());
    }

    #[test]
    fn more_than_forty_eight_sequence_numbers_cannot_be_protected() {
        let packets: Vec<_> = (100..149).map(|seq| media(seq, 0, 96, false, 2)).collect();
        assert_eq!(
            Err(UlpfecError::SpanTooWide),
            UlpfecEncoder::new().encode(&packets, &[ProtectionLevel::new(2, [100, 148])])
        );
    }

    #[test]
    fn a_level_must_name_packets_that_were_given() {
        let packets = rfc_packets();
        let encoder = UlpfecEncoder::new();
        assert_eq!(
            Err(UlpfecError::UnknownSequenceNumber),
            encoder.encode(&packets, &[ProtectionLevel::new(10, [8, 12])])
        );
        assert_eq!(
            Err(UlpfecError::NothingToProtect),
            encoder.encode(&packets, &[])
        );
        assert_eq!(
            Err(UlpfecError::NothingToProtect),
            encoder.encode(&packets, &[ProtectionLevel::new(10, Vec::new())])
        );
    }

    #[test]
    fn a_packet_protected_twice_above_level_0_is_refused() {
        let first = [
            ProtectionLevel::new(10, [1, 2]),
            ProtectionLevel::new(10, [1, 2]),
        ];
        let second = [
            ProtectionLevel::new(10, [3, 4]),
            ProtectionLevel::new(10, [2, 3, 4]),
        ];
        assert_eq!(
            Err(UlpfecError::ProtectedTwice),
            validate_scheme(&[&first, &second])
        );
    }

    #[test]
    fn level_0_may_protect_a_packet_twice_only_with_equal_lengths() {
        let first = [ProtectionLevel::new(10, [1, 2])];
        let same_length = [ProtectionLevel::new(10, [2, 3])];
        let other_length = [ProtectionLevel::new(12, [2, 3])];
        assert_eq!(Ok(()), validate_scheme(&[&first, &same_length]));
        assert_eq!(
            Err(UlpfecError::ProtectedTwice),
            validate_scheme(&[&first, &other_length])
        );
    }

    #[test]
    fn a_level_needs_the_level_below_for_the_same_packet() {
        let first = [ProtectionLevel::new(10, [1, 2])];
        let second = [
            ProtectionLevel::new(10, [3]),
            ProtectionLevel::new(10, [1, 2, 3, 4]),
        ];
        assert_eq!(
            Err(UlpfecError::LevelBelowMissing),
            validate_scheme(&[&first, &second]),
            "packet 4 is protected at level 1 and nowhere at level 0"
        );
    }

    #[test]
    fn a_fec_stream_counts_its_own_sequence_numbers_and_follows_the_media_clock() {
        let fec = UlpfecEncoder::new()
            .encode(&rfc_packets(), &[ProtectionLevel::new(1, [8])])
            .unwrap();
        let start = Instant::now();
        let mut packetizer = UlpfecStreamPacketizer::new(100, 7, 90_000, 65535);
        packetizer.on_media(1000, start);

        let first = packetizer.packetize(&fec, start + Duration::from_millis(10));
        let second = packetizer.packetize(&fec, start + Duration::from_millis(20));

        assert_eq!(65535, first.header.sequence_number);
        assert_eq!(0, second.header.sequence_number, "one higher, with wrap");
        assert_eq!(1000 + 900, first.header.timestamp, "10 ms at 90 kHz");
        assert_eq!(1000 + 1800, second.header.timestamp);
        assert!(!first.header.marker);
        assert_eq!(7, first.header.ssrc);
    }
}
