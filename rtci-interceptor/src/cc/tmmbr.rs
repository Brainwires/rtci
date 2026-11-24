//! Temporary Maximum Media Stream Bit Rate: what a media sender owes a TMMBR (RFC 5104
//! sections 3.5.4 and 4.2).
//!
//! A receiver that cannot take more than some bit rate says so with a TMMBR; the media sender
//! has to stay inside the limit and acknowledge it with a TMMBN naming the tuples that currently
//! bound it. RFC 8834 section 5.1.6 makes honouring a TMMBR mandatory for an endpoint that sends
//! media.
//!
//! The two packets are RTPFB feedback with FMT 3 and 4. `rtci-rtcp` has no codec for them yet and
//! hands them over as [`rtcp::raw_packet::RawPacket`], so the eight-byte FCI entries are read and
//! written here.

use bytes::{BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// RTPFB feedback message type of a TMMBR.
pub(crate) const FMT_TMMBR: u8 = 3;
/// RTPFB feedback message type of a TMMBN.
pub(crate) const FMT_TMMBN: u8 = 4;
/// RTCP packet type of transport layer feedback.
const PT_RTPFB: u8 = 205;

/// How long the owner of a tuple may stay silent before it has left: five reporting intervals of
/// five seconds, the RTP participant timeout (RFC 3550 section 6.3.5).
pub const TMMBR_OWNER_TIMEOUT: Duration = Duration::from_secs(25);

/// One FCI entry of a TMMBR or a TMMBN (RFC 5104 sections 4.2.1.1 and 4.2.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TmmbEntry {
    /// In a TMMBR, the media sender the limit is for; in a TMMBN, the owner of the tuple.
    pub ssrc: u32,
    /// MxTBR: the maximum total media bit rate, in bits per second, IP and transport overhead
    /// included.
    pub bitrate: u64,
    /// The per-packet overhead the requester measured, in bytes.
    pub overhead: u16,
}

/// A TMMBR or TMMBN as it is on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TmmbPacket {
    pub fmt: u8,
    pub sender_ssrc: u32,
    pub entries: Vec<TmmbEntry>,
}

/// Read a TMMBR or TMMBN from a raw RTCP packet. `None` for anything else, or a packet too
/// short for what its header says.
pub(crate) fn parse(raw: &[u8]) -> Option<TmmbPacket> {
    if raw.len() < 12 || raw[0] >> 6 != 2 || raw[1] != PT_RTPFB {
        return None;
    }
    let fmt = raw[0] & 0x1F;
    if fmt != FMT_TMMBR && fmt != FMT_TMMBN {
        return None;
    }
    let length = (usize::from(u16::from_be_bytes([raw[2], raw[3]])) + 1) * 4;
    if length < 12 || length > raw.len() || (length - 12) % 8 != 0 {
        return None;
    }
    let sender_ssrc = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let entries = raw[12..length]
        .as_chunks::<8>()
        .0
        .iter()
        .map(|fci| {
            let word = u32::from_be_bytes([fci[4], fci[5], fci[6], fci[7]]);
            let exponent = word >> 26;
            let mantissa = u64::from((word >> 9) & 0x1_FFFF);
            TmmbEntry {
                ssrc: u32::from_be_bytes([fci[0], fci[1], fci[2], fci[3]]),
                bitrate: mantissa << exponent,
                overhead: (word & 0x1FF) as u16,
            }
        })
        .collect();
    Some(TmmbPacket {
        fmt,
        sender_ssrc,
        entries,
    })
}

/// Write a TMMBN: "SSRC of media source" is 0, the length is 2 + 2 * N, and a bounding set with
/// no tuple gives a TMMBN without FCI (RFC 5104 sections 4.2.2.1 and 4.2.2.2).
pub(crate) fn build_tmmbn(sender_ssrc: u32, entries: &[TmmbEntry]) -> Bytes {
    let mut out = BytesMut::with_capacity(12 + 8 * entries.len());
    out.put_u8(0x80 | FMT_TMMBN);
    out.put_u8(PT_RTPFB);
    out.put_u16(2 + 2 * entries.len() as u16);
    out.put_u32(sender_ssrc);
    out.put_u32(0);
    for entry in entries {
        // The smallest exponent that lets the mantissa fit its 17 bits.
        let mut exponent = 0u32;
        while entry.bitrate >> exponent > 0x1_FFFF && exponent < 63 {
            exponent += 1;
        }
        let mantissa = ((entry.bitrate >> exponent) & 0x1_FFFF) as u32;
        out.put_u32(entry.ssrc);
        out.put_u32(exponent << 26 | mantissa << 9 | u32::from(entry.overhead.min(0x1FF)));
    }
    out.freeze()
}

/// The tuples that bound a sender: the lower envelope of the lines
/// `net media bit rate = MxTBR - 8 * overhead * packet rate` over the packet rates at which the
/// envelope is still above zero (RFC 5104 section 3.5.4.2).
pub(crate) fn bounding_set(tuples: &[TmmbEntry]) -> Vec<TmmbEntry> {
    if tuples.len() <= 1 {
        return tuples.to_vec();
    }
    let net = |tuple: &TmmbEntry, packet_rate: f64| {
        tuple.bitrate as f64 - 8.0 * f64::from(tuple.overhead) * packet_rate
    };
    // The packet rates at which the limiting tuple can change: where two lines cross.
    let mut switchovers = vec![0.0f64];
    for (index, a) in tuples.iter().enumerate() {
        for b in &tuples[index + 1..] {
            if a.overhead != b.overhead {
                let packet_rate = (a.bitrate as f64 - b.bitrate as f64)
                    / (8.0 * (f64::from(a.overhead) - f64::from(b.overhead)));
                if packet_rate > 0.0 && packet_rate.is_finite() {
                    switchovers.push(packet_rate);
                }
            }
        }
    }
    switchovers.sort_by(f64::total_cmp);

    let lowest_at = |packet_rate: f64| {
        tuples.iter().min_by(|a, b| {
            net(a, packet_rate)
                .total_cmp(&net(b, packet_rate))
                // Equal lines: one of them bounds, and it is the same one every time.
                .then(a.bitrate.cmp(&b.bitrate))
                .then(b.overhead.cmp(&a.overhead))
                .then(a.ssrc.cmp(&b.ssrc))
        })
    };

    let mut bounding: Vec<TmmbEntry> = Vec::new();
    for (index, start) in switchovers.iter().enumerate() {
        // The tuple that limits just after this switchover, while the envelope is feasible.
        let probe = match switchovers.get(index + 1) {
            Some(next) => (start + next) / 2.0,
            None => start + 1.0,
        };
        let Some(lowest_here) = lowest_at(*start) else {
            continue;
        };
        if net(lowest_here, *start) < 0.0 {
            break;
        }
        if let Some(lowest) = lowest_at(probe)
            && !bounding.contains(lowest)
        {
            bounding.push(*lowest);
        }
    }
    if bounding.is_empty()
        && let Some(lowest) = lowest_at(0.0)
    {
        bounding.push(*lowest);
    }
    bounding
}

/// The bit rate left for RTP packets (headers and payload) at `packet_rate` packets per second
/// under `tuples`: the lowest of `MxTBR - 8 * overhead * packet rate` (equations (1) and (2) of
/// section 3.5.4.2).
pub(crate) fn net_media_bitrate(tuples: &[TmmbEntry], packet_rate: f64) -> Option<f64> {
    tuples
        .iter()
        .map(|tuple| {
            (tuple.bitrate as f64 - 8.0 * f64::from(tuple.overhead) * packet_rate).max(0.0)
        })
        .reduce(f64::min)
}

/// What was asked of this media sender, and by whom.
#[derive(Debug, Default)]
pub(crate) struct TmmbrState {
    /// The latest request of each owner (the SSRC that sent the TMMBR), with when it was last
    /// heard from.
    requests: HashMap<u32, (TmmbEntry, Instant)>,
    /// The bounding set last computed.
    bounding: Vec<TmmbEntry>,
    /// The bounding set in force: the limit is its net media bit rate at the packet rate the
    /// sender uses now ([`limit`](Self::limit)), not at the one it used when a request came.
    in_force: Vec<TmmbEntry>,
    /// A looser bounding set that may only be used from this instant on
    /// (`2 * RTT + T_Dither_Max`, section 4.2.1.2).
    pending: Option<(Instant, Vec<TmmbEntry>)>,
}

impl TmmbrState {
    /// The owners' tuples, in a stable order.
    fn tuples(&self) -> Vec<TmmbEntry> {
        let mut tuples: Vec<TmmbEntry> = self.requests.values().map(|(entry, _)| *entry).collect();
        tuples.sort_unstable_by_key(|tuple| tuple.ssrc);
        tuples
    }

    /// The bounding set, as a TMMBN reports it: one tuple per owner.
    pub(crate) fn bounding(&self) -> &[TmmbEntry] {
        &self.bounding
    }

    /// The limit on this sender's RTP bit rate at `packet_rate` packets per second, the rate
    /// it sends at now, if any tuple bounds it. Section 3.5.4.2: "the bit rate available for
    /// RTP payloads is equal to the TMMBR reported bit rate minus the packet rate used,
    /// multiplied by the TMMBR reported overhead converted to bits", and "which limitation
    /// applies depends on the packet rate being considered": the limit follows the packet
    /// rate, so a burst of packets around the request (a probe cluster) does not hold the
    /// sender at what was left at that moment.
    pub(crate) fn limit(&self, packet_rate: f64) -> Option<f64> {
        net_media_bitrate(&self.in_force, packet_rate)
    }

    /// Recompute the bounding set and the limit after the requests changed.
    ///
    /// A tighter limit applies at once. A looser one (or none) applies only after
    /// `2 * RTT + T_Dither_Max`, point-to-point included: other receivers may be about to say
    /// that the old limit still holds for them. `T_Dither_Max` is 0 in a session of two.
    /// Tighter and looser are judged at `packet_rate`, the rate the sender uses now.
    fn recompute(&mut self, now: Instant, packet_rate: f64, round_trip_time: Duration) {
        self.bounding = bounding_set(&self.tuples());
        let limit = net_media_bitrate(&self.bounding, packet_rate);
        let tighter = match (limit, self.limit(packet_rate)) {
            (Some(new), Some(old)) => new <= old,
            (Some(_), None) => true,
            (None, _) => false,
        };
        if tighter {
            self.in_force.clone_from(&self.bounding);
            self.pending = None;
        } else {
            self.pending = Some((now + round_trip_time * 2, self.bounding.clone()));
        }
    }

    /// A TMMBR from `owner` asking `ssrc`-addressed limits of this sender. Returns whether a
    /// TMMBN is owed: it is, for every TMMBR, whether or not it changed anything
    /// (section 4.2.2.2).
    pub(crate) fn on_request(
        &mut self,
        now: Instant,
        owner: u32,
        entry: TmmbEntry,
        packet_rate: f64,
        round_trip_time: Duration,
    ) -> bool {
        self.requests.insert(
            owner,
            (
                TmmbEntry {
                    ssrc: owner,
                    ..entry
                },
                now,
            ),
        );
        self.recompute(now, packet_rate, round_trip_time);
        true
    }

    /// `owner` was heard from: it has not timed out.
    pub(crate) fn on_owner_seen(&mut self, now: Instant, owner: u32) {
        if let Some((_, seen)) = self.requests.get_mut(&owner) {
            *seen = now;
        }
    }

    /// `owner` left the session (BYE). Returns whether a TMMBN is owed: it is when the owner had
    /// a tuple (section 4.2.2.2), and it carries no FCI when the set is now empty.
    pub(crate) fn on_owner_left(
        &mut self,
        now: Instant,
        owner: u32,
        packet_rate: f64,
        round_trip_time: Duration,
    ) -> bool {
        if self.requests.remove(&owner).is_none() {
            return false;
        }
        self.recompute(now, packet_rate, round_trip_time);
        true
    }

    /// Time passing: owners that timed out are removed, and a looser limit whose hold-off has
    /// passed takes effect. Returns whether a TMMBN is owed.
    pub(crate) fn on_timeout(
        &mut self,
        now: Instant,
        packet_rate: f64,
        round_trip_time: Duration,
    ) -> bool {
        let before = self.requests.len();
        self.requests
            .retain(|_, (_, seen)| now.saturating_duration_since(*seen) < TMMBR_OWNER_TIMEOUT);
        let left = self.requests.len() != before;
        if left {
            self.recompute(now, packet_rate, round_trip_time);
        }
        if let Some((at, _)) = &self.pending
            && now >= *at
            && let Some((_, bounding)) = self.pending.take()
        {
            self.in_force = bounding;
        }
        left
    }

    /// When this state next needs [`on_timeout`](Self::on_timeout).
    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        let owner = self
            .requests
            .values()
            .map(|(_, seen)| *seen + TMMBR_OWNER_TIMEOUT)
            .min();
        let pending = self.pending.as_ref().map(|(at, _)| *at);
        match (owner, pending) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(ssrc: u32, bitrate: u64, overhead: u16) -> TmmbEntry {
        TmmbEntry {
            ssrc,
            bitrate,
            overhead,
        }
    }

    /// RFC 5104 section 4.2.1.1: SSRC, MxTBR Exp (6 bits), MxTBR Mantissa (17 bits), Measured
    /// Overhead (9 bits); MxTBR = mantissa * 2^exp.
    #[test]
    fn a_tmmbr_fci_entry_is_read_as_the_rfc_lays_it_out() {
        // FMT 3, PT 205, length 4 (20 bytes); sender 0x11223344; media source 0.
        // Entry: SSRC 0xAABBCCDD, exp 2, mantissa 65536, overhead 40.
        let word: u32 = 2 << 26 | 65_536 << 9 | 40;
        let mut raw = vec![0x83, 205, 0, 4, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0];
        raw.extend_from_slice(&0xAABB_CCDDu32.to_be_bytes());
        raw.extend_from_slice(&word.to_be_bytes());

        let packet = parse(&raw).expect("a TMMBR");
        assert_eq!(FMT_TMMBR, packet.fmt);
        assert_eq!(0x1122_3344, packet.sender_ssrc);
        assert_eq!(vec![tuple(0xAABB_CCDD, 262_144, 40)], packet.entries);
    }

    #[test]
    fn a_truncated_or_foreign_packet_is_not_a_tmmbr() {
        assert_eq!(
            None,
            parse(&[0x83, 205, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0]),
            "length says 20"
        );
        assert_eq!(
            None,
            parse(&[0x81, 205, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0]),
            "a NACK"
        );
        assert_eq!(
            None,
            parse(&[0x83, 205, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(None, parse(&[]));
    }

    /// RFC 5104 section 4.2.2.1: TMMBN is FMT 4 with length 2 + 2 * N and media source 0; an
    /// empty bounding set gives a TMMBN without FCI.
    #[test]
    fn a_tmmbn_is_written_as_the_rfc_lays_it_out() {
        let raw = build_tmmbn(7, &[tuple(9, 35_000, 40), tuple(10, 5_000_001, 60)]);
        assert_eq!(&[0x84, 205, 0, 6, 0, 0, 0, 7, 0, 0, 0, 0], &raw[..12]);
        let packet = parse(&raw).expect("a TMMBN");
        assert_eq!(FMT_TMMBN, packet.fmt);
        // 5 000 001 needs an exponent of 6 for the mantissa to fit 17 bits: 78 125 * 64.
        assert_eq!(
            vec![tuple(9, 35_000, 40), tuple(10, 5_000_000, 60)],
            packet.entries
        );

        let empty = build_tmmbn(7, &[]);
        assert_eq!(&[0x84, 205, 0, 2, 0, 0, 0, 7, 0, 0, 0, 0], &empty[..]);
    }

    /// The example of RFC 5104 section 3.5.4.2: A (35 kbit/s, 40 bytes) limits below 31.25
    /// packets per second, B (40 kbit/s, 60 bytes) above; at 20 packets per second the net media
    /// bit rate is 28 600 bit/s.
    #[test]
    fn the_bounding_set_of_the_rfc_example() {
        let a = tuple(1, 35_000, 40);
        let b = tuple(2, 40_000, 60);
        let c = tuple(3, 50_000, 40);

        assert_eq!(
            vec![a, b],
            bounding_set(&[a, b, c]),
            "C lies outside the polygon"
        );
        assert_eq!(Some(28_600.0), net_media_bitrate(&[a, b], 20.0));
        assert_eq!(Some(30_400.0), net_media_bitrate(&[b], 20.0));
        // Past the switchover B is the limit: at 40 packets per second, 20 800 against 22 200.
        assert_eq!(Some(20_800.0), net_media_bitrate(&[a, b], 40.0));
    }

    #[test]
    fn a_tuple_that_is_tighter_everywhere_is_the_whole_bounding_set() {
        let tight = tuple(1, 20_000, 60);
        let loose = tuple(2, 40_000, 40);
        assert_eq!(vec![tight], bounding_set(&[loose, tight]));
    }

    /// RFC 5104 section 4.2.1.2: a tighter limit applies at once; before raising its rate after
    /// a looser one the sender waits 2 * RTT + T_Dither_Max.
    #[test]
    fn a_looser_limit_waits_two_round_trips() {
        let now = Instant::now();
        let rtt = Duration::from_millis(150);
        let mut state = TmmbrState::default();

        state.on_request(now, 9, tuple(1, 500_000, 0), 0.0, rtt);
        assert_eq!(Some(500_000.0), state.limit(0.0), "at once");

        state.on_request(
            now + Duration::from_secs(1),
            9,
            tuple(1, 900_000, 0),
            0.0,
            rtt,
        );
        assert_eq!(Some(500_000.0), state.limit(0.0), "not yet");
        assert_eq!(
            Some(now + Duration::from_millis(1300)),
            state.poll_timeout()
        );
        state.on_timeout(now + Duration::from_millis(1299), 0.0, rtt);
        assert_eq!(Some(500_000.0), state.limit(0.0));
        state.on_timeout(now + Duration::from_millis(1300), 0.0, rtt);
        assert_eq!(Some(900_000.0), state.limit(0.0), "after 2 * RTT");
    }

    /// RFC 5104 section 3.5.4.2: the limit of a bounding set is its net media bit rate at the
    /// packet rate it is asked for, not at the one of the request.
    #[test]
    fn the_limit_is_taken_at_the_packet_rate_in_use() {
        let now = Instant::now();
        let mut state = TmmbrState::default();
        state.on_request(now, 9, tuple(1, 80_000, 60), 171.0, Duration::ZERO);
        assert_eq!(Some(0.0), state.limit(171.0));
        assert_eq!(Some(80_000.0 - 50.0 * 480.0), state.limit(50.0));
    }

    /// RFC 5104 section 4.2.2.2: when the owner of a tuple leaves or times out the tuple is
    /// removed and a TMMBN is owed.
    #[test]
    fn an_owner_that_leaves_or_times_out_takes_its_tuple_with_it() {
        let now = Instant::now();
        let rtt = Duration::from_millis(100);
        let mut state = TmmbrState::default();
        state.on_request(now, 9, tuple(1, 500_000, 0), 0.0, rtt);
        state.on_request(now, 10, tuple(1, 800_000, 0), 0.0, rtt);
        assert_eq!(vec![tuple(9, 500_000, 0)], state.bounding());

        assert!(state.on_owner_left(now, 9, 0.0, rtt), "a TMMBN is owed");
        assert_eq!(vec![tuple(10, 800_000, 0)], state.bounding());
        assert!(
            !state.on_owner_left(now, 9, 0.0, rtt),
            "it had no tuple any more"
        );

        // The other owner goes silent.
        assert!(!state.on_timeout(now + Duration::from_secs(24), 0.0, rtt));
        assert!(state.on_timeout(now + TMMBR_OWNER_TIMEOUT, 0.0, rtt));
        assert!(state.bounding().is_empty());
        state.on_timeout(now + TMMBR_OWNER_TIMEOUT + rtt * 2, 0.0, rtt);
        assert_eq!(
            None,
            state.limit(0.0),
            "no tuple, no limit, after the hold-off"
        );
    }
}
