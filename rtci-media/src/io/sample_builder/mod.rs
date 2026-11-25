#[cfg(test)]
mod sample_builder_frame_start_test;
#[cfg(test)]
mod sample_builder_gap_wait_test;
#[cfg(test)]
mod sample_builder_h26x_test;
#[cfg(test)]
mod sample_builder_key_frame_test;
#[cfg(test)]
mod sample_builder_test;
#[cfg(test)]
mod sample_sequence_location_test;

/// Tracks where a sample sits within the RTP sequence-number space.
pub mod sample_sequence_location;

use self::sample_sequence_location::{Comparison, SampleSequenceLocation};
use crate::Sample;
use bytes::Bytes;
use rtp::Packet;
use rtp::packetizer::Depacketizer;
use std::time::{Duration, Instant};

/// How long a [`SampleBuilder`] of a format with key frames
/// ([`Depacketizer::has_key_frames`]) waits for a missing packet unless told otherwise
/// ([`SampleBuilder::with_max_gap_wait`]).
///
/// No RFC gives a number. RFC 8834 section 6.1 has a retransmission be useful only when it
/// "arrives in time", and RFC 8836 section 2 puts interactive media "within a very limited
/// time window (no more delay than hundreds of milliseconds end-to-end)". 300 ms is the value
/// the repository's capacity instrument measured best of 300, 600 and 1000 ms (a picture older
/// than 2 s in 8, 10 and 37 per cent of runs without a pacer; no difference with one):
/// `docs/receiver-gap-policy.md`. libwebrtc's receiver has no such bound on a packet: it asks
/// for a key frame after 3 s without a decodable frame, 200 ms while it waits for a key frame
/// (`video/video_receive_stream2.h:74-75` at a222406d); `rtci-video`'s
/// `ReceiveConfig::chrome()` is that receiver.
pub const DEFAULT_MAX_GAP_WAIT: Duration = Duration::from_millis(300);

/// Whether `sequence_number` comes before `reference` (RFC 3550 appendix A.1 wrap-around: up
/// to 32767 behind it).
fn older_than(sequence_number: u16, reference: u16) -> bool {
    (1..0x8000).contains(&reference.wrapping_sub(sequence_number))
}

/// SampleBuilder buffers packets until media frames are complete.
///
/// Samples come out in sequence-number order. A missing packet holds back what follows it
/// until it arrives, or until the builder gives it up:
///
/// - when more than `max_late` packets are buffered behind it ([`Self::new`]), or more than
///   [`Self::with_max_time_delay`] of media time;
/// - when it has been missing for [`Self::with_max_gap_wait`], by default
///   [`DEFAULT_MAX_GAP_WAIT`] for a format with key frames and never for another (audio);
/// - at once when a complete key frame is buffered behind it
///   ([`Self::with_key_frame_release`], on by default; [`Depacketizer::is_key_frame_start`]):
///   nothing before a key frame is needed to decode it or what follows it.
pub struct SampleBuilder<T: Depacketizer> {
    /// how many packets to wait until we get a valid Sample
    max_late: u16,
    /// max timestamp between old and new timestamps before dropping packets
    max_late_timestamp: u32,
    buffer: Vec<Option<Packet>>,
    prepared_samples: Vec<Option<Sample>>,
    last_sample_timestamp: Option<u32>,

    /// Interface that allows us to take RTP packets to samples
    depacketizer: T,

    /// sample_rate allows us to compute duration of media.SamplecA
    sample_rate: u32,

    /// filled contains the head/tail of the packets inserted into the buffer
    filled: SampleSequenceLocation,

    /// active contains the active head/tail of the timestamp being actively processed
    active: SampleSequenceLocation,

    /// prepared contains the samples that have been processed to date
    prepared: SampleSequenceLocation,

    /// number of packets forced to be dropped
    dropped_packets: u16,

    /// number of padding packets detected and dropped. This number will be a subset of
    /// `dropped_packets`
    padding_packets: u16,

    /// Whether any packet has been consumed (built into a sample or dropped). Until then the
    /// segment being built starts at the earliest packet that has arrived, not at the first
    /// one to arrive: packets of the first access unit may come out of order.
    consumed_any: bool,

    /// How long a gap may stay missing before it is given up ([`Self::with_max_gap_wait`]);
    /// `None`: no bound in time.
    max_gap_wait: Option<Duration>,

    /// When each buffered packet arrived, by sequence number: allocated only with a gap bound,
    /// for when a gap became known (the arrival of the packet after it).
    arrivals: Vec<Option<Instant>>,

    /// Whether a gap was given up since the last [`Self::take_key_frame_request`].
    key_frame_requested: bool,

    /// How many gaps the time bound gave up.
    skipped_gaps: u64,

    /// Whether a complete key frame releases what is missing before it
    /// ([`Self::with_key_frame_release`]).
    key_frame_release: bool,

    /// How many times a complete key frame released what was missing before it.
    key_frame_releases: u64,

    /// The sequence number after the newest packet consumed (built into a sample or given
    /// up): a packet before it has nothing left to belong to. `None` until one is consumed.
    next_wanted: Option<u16>,
}

impl<T: Depacketizer> SampleBuilder<T> {
    /// Constructs a new SampleBuilder.
    /// `max_late` is how long to wait until we can construct a completed [`Sample`].
    /// `max_late` is measured in RTP packet sequence numbers.
    /// A large max_late will result in less packet loss but higher latency.
    /// The depacketizer extracts media samples from RTP packets.
    ///
    /// With a depacketizer of a format that has key frames ([`Depacketizer::has_key_frames`]:
    /// VP8, VP9, AV1, H.264, H.265) a missing packet is also given up once it has been
    /// missing for [`DEFAULT_MAX_GAP_WAIT`] ([`Self::with_max_gap_wait`] changes or removes
    /// that bound), and a complete key frame releases what is missing before it
    /// ([`Self::with_key_frame_release`]). Any other builder (audio) waits by `max_late` and
    /// [`Self::with_max_time_delay`] alone.
    pub fn new(max_late: u16, depacketizer: T, sample_rate: u32) -> Self {
        let max_gap_wait = depacketizer
            .has_key_frames()
            .then_some(DEFAULT_MAX_GAP_WAIT);
        Self {
            max_late,
            max_late_timestamp: 0,
            buffer: vec![None; u16::MAX as usize + 1],
            prepared_samples: (0..=u16::MAX as usize).map(|_| None).collect(),
            last_sample_timestamp: None,
            depacketizer,
            sample_rate,
            filled: SampleSequenceLocation::new(),
            active: SampleSequenceLocation::new(),
            prepared: SampleSequenceLocation::new(),
            dropped_packets: 0,
            padding_packets: 0,
            consumed_any: false,
            max_gap_wait,
            arrivals: match max_gap_wait {
                Some(_) => vec![None; u16::MAX as usize + 1],
                None => Vec::new(),
            },
            key_frame_requested: false,
            skipped_gaps: 0,
            key_frame_release: true,
            key_frame_releases: 0,
            next_wanted: None,
        }
    }

    /// Sets how long a missing packet is waited for, in wall-clock time, before the builder
    /// gives up on it; `None` removes the bound, and a gap is then held until `max_late`
    /// packets (or [`Self::with_max_time_delay`] of media time) have arrived behind it, or a
    /// key frame releases it ([`Self::with_key_frame_release`]). The default is
    /// [`DEFAULT_MAX_GAP_WAIT`] for a format with key frames
    /// ([`Depacketizer::has_key_frames`]) and no bound for any other.
    ///
    /// A receiver without a time bound freezes for the length of its packet window on a gap
    /// that never fills: the window is a time only at one bit rate, and 256 packets were 8.6 s
    /// at 100 kbit/s in `tests/capacity_cap_video_rtc2rtc.rs`. The bound should be about the
    /// repair window (a few round-trip times, no more than the playout delay accepted); see
    /// `docs/receiver-gap-policy.md`.
    ///
    /// The wait for the oldest missing packet runs from when the builder first knew of the gap:
    /// the arrival of the first packet after it. Once it has lasted the bound, the gap is given
    /// up as `max_late` gives it up: the samples complete before it are built, the incomplete
    /// one and the missing packets are dropped, and building resumes at the next packet that
    /// starts a sample ([`Depacketizer::is_partition_head`]). That sample may be one that
    /// refers to what was lost, so the builder raises a key-frame request
    /// ([`Self::take_key_frame_request`]) for the application to send (PLI, RFC 4585 section
    /// 6.3.1): the builder is not in the engine and sends nothing itself. The next sample
    /// counts the packets skipped in [`Sample::prev_dropped_packets`]. A gap filled before the
    /// bound changes nothing.
    ///
    /// The bound is checked when [`Self::push`] and [`Self::pop`] are called, with the `now`
    /// they are given: nothing here reads a clock. While a gap waits, [`Self::poll_timeout`]
    /// names the instant to call [`Self::pop`] at if no packet arrives first.
    pub fn with_max_gap_wait(mut self, max_gap_wait: impl Into<Option<Duration>>) -> Self {
        self.max_gap_wait = max_gap_wait.into();
        match self.max_gap_wait {
            Some(_) if self.arrivals.is_empty() => {
                self.arrivals = vec![None; u16::MAX as usize + 1];
            }
            Some(_) => {}
            None => self.arrivals = Vec::new(),
        }
        self
    }

    /// Whether a complete key frame releases what is missing before it. On by default; it
    /// acts only with a depacketizer that can tell a key frame
    /// ([`Depacketizer::is_key_frame_start`]: VP8, VP9, AV1, H.264, H.265).
    ///
    /// A key frame is decoded without reference to any earlier frame (RFC 7741 section 3; a
    /// decoder refresh point "completely resets the decoder to a known state", RFC 5104
    /// section 2.2), so once every packet of one is buffered nothing older can still help the
    /// picture, and a sender that discarded its backlog and sent a key frame will never fill
    /// the gap. When one is complete behind a gap, the samples complete before the gap are
    /// built, everything from the gap up to the key frame is dropped (the missing packets,
    /// and frames between them and the key frame, which a decoder could not use without what
    /// is missing), and the key frame is the next sample, with what was dropped counted in
    /// [`Sample::prev_dropped_packets`]. No key-frame request is raised: the key frame is
    /// there. With `false` a gap is held until a bound gives it up, whatever follows it (a
    /// recorder that wants every frame that can still be repaired).
    pub fn with_key_frame_release(mut self, key_frame_release: bool) -> Self {
        self.key_frame_release = key_frame_release;
        self
    }

    /// Whether a gap was given up for the time bound ([`Self::with_max_gap_wait`]) since the
    /// last call: the application should ask the sender for a key frame. Clears the request.
    pub fn take_key_frame_request(&mut self) -> bool {
        std::mem::take(&mut self.key_frame_requested)
    }

    /// How many gaps the time bound ([`Self::with_max_gap_wait`]) gave up.
    pub fn skipped_gaps(&self) -> u64 {
        self.skipped_gaps
    }

    /// How many times a complete key frame released what was missing before it
    /// ([`Self::with_key_frame_release`]).
    pub fn key_frame_releases(&self) -> u64 {
        self.key_frame_releases
    }

    /// The oldest sequence number the builder can still use: the one after the newest packet
    /// it built into a sample or gave up. `None` until then. A packet before it that arrives
    /// late (a repair of what was given up, a duplicate) is ignored by [`Self::push`], so a
    /// receiver should stop asking for those: give this to
    /// `RTCRtpReceiver::set_nack_horizon` (RFC 4588 section 6.3) after popping.
    pub fn nack_horizon(&self) -> Option<u16> {
        self.next_wanted
    }

    /// Records that every packet before `to` is consumed.
    fn consumed_to(&mut self, to: u16) {
        if self.next_wanted.is_none_or(|next| older_than(next, to)) {
            self.next_wanted = Some(to);
        }
    }

    /// The first missing position among those buffered, and the first packet of the first
    /// complete key frame behind it (with any packets of the same RTP timestamp directly
    /// before that one: parameter sets sent in packets of their own).
    fn key_frame_behind_gap(&self) -> Option<(u16, u16)> {
        if !self.filled.has_data() {
            return None;
        }
        let tail = self.filled.tail;
        let mut i = self.filled.head;
        while i != tail && self.buffer[i as usize].is_some() {
            i = i.wrapping_add(1);
        }
        if i == tail {
            return None;
        }
        let gap = i;
        while i != tail {
            let first = i;
            i = i.wrapping_add(1);
            let Some(packet) = &self.buffer[first as usize] else {
                continue;
            };
            if !self.depacketizer.is_key_frame_start(&packet.payload) {
                continue;
            }
            let timestamp = packet.header.timestamp;
            let mut j = first;
            let complete = loop {
                match &self.buffer[j as usize] {
                    Some(p) if p.header.timestamp == timestamp => {
                        if self
                            .depacketizer
                            .is_partition_tail(p.header.marker, &p.payload)
                        {
                            break true;
                        }
                    }
                    // The next frame began: this one ended without its mark.
                    Some(_) => break true,
                    None => break false,
                }
                j = j.wrapping_add(1);
                if j == tail {
                    break false;
                }
            };
            if !complete {
                continue;
            }
            let mut start = first;
            while start.wrapping_sub(1) != gap {
                match &self.buffer[start.wrapping_sub(1) as usize] {
                    Some(p) if p.header.timestamp == timestamp => start = start.wrapping_sub(1),
                    _ => break,
                }
            }
            return Some((gap, start));
        }
        None
    }

    /// Releases what is missing before a complete key frame
    /// ([`Self::with_key_frame_release`]).
    fn release_at_key_frame(&mut self, now: Instant) {
        if !self.key_frame_release {
            return;
        }
        while let Some((gap, start)) = self.key_frame_behind_gap() {
            // Positions consumed earlier and not yet cleared go first, so that the head of
            // what is buffered is the next packet to build from.
            if let Some(next) = self.next_wanted {
                while self.filled.has_data() && older_than(self.filled.head, next) {
                    self.release_packet(self.filled.head);
                    self.filled.head = self.filled.head.wrapping_add(1);
                }
                if self.active.empty() {
                    self.active = self.filled;
                }
            }
            // What is complete before the gap is built, in order; the incomplete sample next
            // to the gap is dropped.
            let mut steps = 0u32;
            while self.filled.has_data() && self.filled.head != gap && steps <= u32::from(u16::MAX)
            {
                self.drop_head(now);
                steps += 1;
            }
            if self.filled.head != gap {
                return;
            }
            let mut i = gap;
            while i != start {
                self.release_packet(i);
                self.dropped_packets = self.dropped_packets.saturating_add(1);
                i = i.wrapping_add(1);
            }
            self.filled.head = start;
            self.active = SampleSequenceLocation {
                head: start,
                tail: self.filled.tail,
            };
            self.consumed_any = true;
            self.consumed_to(start);
            self.key_frame_releases += 1;
        }
    }

    /// When the oldest missing packet will have been waited for as long as
    /// [`Self::with_max_gap_wait`] allows: the instant to call [`Self::pop`] at if nothing
    /// arrives first. `None` without a bound or with no gap.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let bound = self.max_gap_wait?;
        self.oldest_gap().map(|(_, known)| known + bound)
    }

    /// The oldest missing packet among those buffered, and when the builder learned of it
    /// (the arrival of the first packet after it). Only tracked with a gap bound.
    fn oldest_gap(&self) -> Option<(u16, Instant)> {
        if self.arrivals.is_empty() || !self.filled.has_data() {
            return None;
        }
        let mut i = self.filled.head;
        while i != self.filled.tail && self.buffer[i as usize].is_some() {
            i = i.wrapping_add(1);
        }
        if i == self.filled.tail {
            return None;
        }
        let missing = i;
        while i != self.filled.tail && self.buffer[i as usize].is_none() {
            i = i.wrapping_add(1);
        }
        // `filled.tail - 1` always holds the newest packet, so there is one after the gap.
        let known = self.arrivals.get(i as usize).copied().flatten()?;
        Some((missing, known))
    }

    /// Gives up every gap that has been missing for the bound at `now`, as `max_late` does.
    fn give_up_gaps(&mut self, now: Instant) {
        let Some(bound) = self.max_gap_wait else {
            return;
        };
        while let Some((missing, known)) = self.oldest_gap() {
            if now < known + bound {
                break;
            }
            while self.filled.has_data() && self.filled.compare(missing) == Comparison::Inside {
                self.drop_head(now);
            }
            self.skipped_gaps += 1;
            self.key_frame_requested = true;
        }
    }

    /// Sets how long to wait for a missing packet before giving up on the sample it belongs to.
    ///
    /// Bounds head-of-line blocking: without it a single lost packet would stall reassembly
    /// indefinitely. A bound in packets (`max_late`) is a bound in time only at one bit rate (256
    /// packets are 0.3 s at 2.5 Mbit/s and 8.6 s at 100 kbit/s): a receiver should bound the wait
    /// in time, about the NACK repair window, and ask for a key frame when a sample after a gap
    /// reports [`Sample::prev_dropped_packets`]. See `docs/receiver-gap-policy.md`.
    pub fn with_max_time_delay(mut self, max_late_duration: Duration) -> Self {
        self.max_late_timestamp =
            (self.sample_rate as u128 * max_late_duration.as_millis() / 1000) as u32;
        self
    }

    fn too_old(&self, location: &SampleSequenceLocation) -> bool {
        if self.max_late_timestamp == 0 {
            return false;
        }

        let mut found_head: Option<u32> = None;
        let mut found_tail: Option<u32> = None;

        let mut i = location.head;
        while i != location.tail {
            if let Some(ref packet) = self.buffer[i as usize] {
                found_head = Some(packet.header.timestamp);
                break;
            }
            i = i.wrapping_add(1);
        }

        if found_head.is_none() {
            return false;
        }

        let mut i = location.tail.wrapping_sub(1);
        while i != location.head {
            if let Some(ref packet) = self.buffer[i as usize] {
                found_tail = Some(packet.header.timestamp);
                break;
            }
            i = i.wrapping_sub(1);
        }

        if found_tail.is_none() {
            return false;
        }

        found_tail.unwrap().wrapping_sub(found_head.unwrap()) > self.max_late_timestamp
    }

    /// Returns the timestamp associated with a given sample location
    fn fetch_timestamp(&self, location: &SampleSequenceLocation) -> Option<u32> {
        if location.empty() {
            None
        } else {
            Some(
                (self.buffer[location.head as usize])
                    .as_ref()?
                    .header
                    .timestamp,
            )
        }
    }

    fn release_packet(&mut self, i: u16) {
        self.buffer[i as usize] = None;
        if let Some(arrival) = self.arrivals.get_mut(i as usize) {
            *arrival = None;
        }
    }

    /// Clears all buffers that have already been consumed by
    /// popping.
    fn purge_consumed_buffers(&mut self) {
        let active = self.active;
        self.purge_consumed_location(&active, false);
    }

    /// Clears all buffers that have already been consumed
    /// during a sample building method.
    fn purge_consumed_location(&mut self, consume: &SampleSequenceLocation, force_consume: bool) {
        if !self.filled.has_data() {
            return;
        }
        match consume.compare(self.filled.head) {
            Comparison::Inside if force_consume => {
                self.release_packet(self.filled.head);
                self.filled.head = self.filled.head.wrapping_add(1);
            }
            Comparison::Before => {
                self.release_packet(self.filled.head);
                self.filled.head = self.filled.head.wrapping_add(1);
            }
            _ => {}
        }
    }

    /// Flushes all buffers that are already consumed or those buffers
    /// that are too late to consume.
    fn purge_buffers(&mut self, now: Instant) {
        self.purge_consumed_buffers();

        while (self.too_old(&self.filled) || (self.filled.count() > self.max_late))
            && self.filled.has_data()
        {
            self.drop_head(now);
        }
    }

    /// Consumes the oldest buffered position whatever is pending: builds the sample it starts
    /// if that can be built now, otherwise drops it (counted in `dropped_packets`).
    fn drop_head(&mut self, now: Instant) {
        if self.active.empty() {
            // refill the active based on the filled packets
            self.active = self.filled;
        }

        if self.active.has_data() && (self.active.head == self.filled.head) {
            // attempt to force the active packet to be consumed even though
            // outstanding data may be pending arrival
            let err = match self.build_sample(now, true) {
                Ok(_) => return,
                Err(e) => e,
            };

            if !matches!(err, BuildError::InvalidPartition(_)) {
                // In the InvalidPartition case `build_sample` will have already adjusted `dropped_packets`.
                self.dropped_packets = self.dropped_packets.saturating_add(1);
            }

            // could not build the sample so drop it
            self.consumed_any = true;
            self.active.head = self.active.head.wrapping_add(1);
            self.consumed_to(self.active.head);
        }

        self.release_packet(self.filled.head);
        self.filled.head = self.filled.head.wrapping_add(1);
    }

    /// Adds an RTP Packet to self's buffer.
    ///
    /// Push does not copy the input. If you wish to reuse
    /// this memory make sure to copy before calling push
    ///
    /// A packet older than everything already consumed ([`Self::nack_horizon`]: a late
    /// repair of a gap that was given up, a duplicate of a packet already built into a
    /// sample) is ignored: it has no sample left to belong to, and buffered it would look
    /// like the start of a new gap.
    pub fn push(&mut self, now: Instant, p: Packet) {
        let sequence_number = p.header.sequence_number;
        if self
            .next_wanted
            .is_some_and(|next| older_than(sequence_number, next))
        {
            return;
        }
        self.buffer[sequence_number as usize] = Some(p);
        if let Some(arrival) = self.arrivals.get_mut(sequence_number as usize) {
            *arrival = Some(now);
        }
        match self.filled.compare(sequence_number) {
            Comparison::Void => {
                self.filled.head = sequence_number;
                self.filled.tail = sequence_number.wrapping_add(1);
            }
            Comparison::Before => {
                self.filled.head = sequence_number;
                // RFC 6184 5.6, 5.8 and RFC 7798 6: NAL units are passed on in RTP
                // sequence-number order. Before anything was consumed there is no earlier
                // sample to be late for: a packet that arrives after a later one of the
                // first sample still belongs in it, so the segment being built starts there.
                if !self.consumed_any && self.active.has_data() {
                    self.active.head = sequence_number;
                }
            }
            Comparison::After => {
                self.filled.tail = sequence_number.wrapping_add(1);
            }
            _ => {}
        }
        self.release_at_key_frame(now);
        self.purge_buffers(now);
        self.give_up_gaps(now);
    }

    /// Creates a sample from a valid collection of RTP Packets by
    /// walking forwards building a sample if everything looks good clear and
    /// update buffer+values
    fn build_sample(
        &mut self,
        now: Instant,
        purging_buffers: bool,
    ) -> Result<SampleSequenceLocation, BuildError> {
        if self.active.empty() {
            self.active = self.filled;
        }

        if self.active.empty() {
            return Err(BuildError::NoActiveSegment);
        }

        if self.filled.compare(self.active.tail) == Comparison::Inside {
            self.active.tail = self.filled.tail;
        }

        let mut consume = SampleSequenceLocation::new();

        let mut i = self.active.head;
        // `self.active` isn't modified in the loop, fetch the timestamp once and cache it.
        let head_timestamp = self.fetch_timestamp(&self.active);
        while let Some(ref packet) = self.buffer[i as usize] {
            if self.active.compare(i) == Comparison::After {
                break;
            }
            let is_same_timestamp = head_timestamp.map(|t| packet.header.timestamp == t);
            let is_different_timestamp = is_same_timestamp.map(std::ops::Not::not);
            let is_partition_tail = self
                .depacketizer
                .is_partition_tail(packet.header.marker, &packet.payload);

            // If the timestamp is not the same it might be because the next packet is both a start
            // and end of the next partition in which case a sample should be generated now. This
            // can happen when padding packets are used .e.g:
            //
            // p1(t=1), p2(t=1), p3(t=1), p4(t=2, marker=true, start=true)
            //
            // In thic case the generated sample should be p1 through p3, but excluding p4 which is
            // its own sample.
            if is_partition_tail && is_same_timestamp.unwrap_or(true) {
                consume.head = self.active.head;
                consume.tail = i.wrapping_add(1);
                break;
            }

            if is_different_timestamp.unwrap_or(false) {
                consume.head = self.active.head;
                consume.tail = i;
                break;
            }
            i = i.wrapping_add(1);
        }

        if consume.empty() {
            return Err(BuildError::NothingToConsume);
        }

        if !purging_buffers && self.buffer[consume.tail as usize].is_none() {
            // wait for the next packet after this set of packets to arrive
            // to ensure at least one post sample timestamp is known
            // (unless we have to release right now)
            return Err(BuildError::PendingTimestampPacket);
        }

        let sample_timestamp = self.fetch_timestamp(&self.active).unwrap_or(0);
        let mut after_timestamp = sample_timestamp;

        // scan for any packet after the current and use that time stamp as the diff point
        for i in consume.tail..self.active.tail {
            if let Some(ref packet) = self.buffer[i as usize] {
                after_timestamp = packet.header.timestamp;
                break;
            }
        }

        // prior to decoding all the packets, check if this packet
        // would end being disposed anyway
        let head_payload = self.buffer[consume.head as usize]
            .as_ref()
            .map(|p| &p.payload)
            .ok_or(BuildError::GapInSegment)?;
        if !self.depacketizer.is_partition_head(head_payload) {
            // libWebRTC will sometimes send several empty padding packets to smooth out send
            // rate. These packets don't carry any media payloads.
            let is_padding = consume.range(&self.buffer).all(|p| {
                p.map(|p| {
                    self.last_sample_timestamp == Some(p.header.timestamp) && p.payload.is_empty()
                })
                .unwrap_or(false)
            });

            self.dropped_packets = self.dropped_packets.saturating_add(consume.count());
            if is_padding {
                self.padding_packets = self.padding_packets.saturating_add(consume.count());
            }
            self.purge_consumed_location(&consume, true);
            self.purge_consumed_buffers();

            self.consumed_any = true;
            self.active.head = consume.tail;
            self.consumed_to(consume.tail);
            return Err(BuildError::InvalidPartition(consume));
        }

        // the head set of packets is now fully consumed
        self.consumed_any = true;
        self.active.head = consume.tail;
        self.consumed_to(consume.tail);

        // Assemble the sample payload from the consumed packets. For the common
        // single-packet sample (all audio, and any frame that fits one RTP
        // packet) hand back the depacketized `Bytes` directly — it is
        // refcounted, so no copy is needed. Only multi-packet samples require
        // concatenation, and even then `Bytes::from(data)` reuses the `Vec`'s
        // buffer instead of copying it a second time.
        let sample_data: Bytes = if consume.count() == 1 {
            let payload = self.buffer[consume.head as usize]
                .as_ref()
                .map(|p| &p.payload)
                .ok_or(BuildError::GapInSegment)?;
            self.depacketizer
                .depacketize(payload)
                .map_err(|_| BuildError::DepacketizerFailed)?
        } else {
            let mut data: Vec<u8> = Vec::new();
            let mut i = consume.head;
            while i != consume.tail {
                let payload = self.buffer[i as usize]
                    .as_ref()
                    .map(|p| &p.payload)
                    .ok_or(BuildError::GapInSegment)?;

                let p = self
                    .depacketizer
                    .depacketize(payload)
                    .map_err(|_| BuildError::DepacketizerFailed)?;

                data.extend_from_slice(&p);
                i = i.wrapping_add(1);
            }
            Bytes::from(data)
        };
        let samples = after_timestamp.wrapping_sub(sample_timestamp);

        let sample = Sample {
            data: sample_data,
            timestamp: now,
            duration: Duration::from_secs_f64((samples as f64) / (self.sample_rate as f64)),
            packet_timestamp: sample_timestamp,
            prev_dropped_packets: self.dropped_packets,
            prev_padding_packets: self.padding_packets,
        };

        self.dropped_packets = 0;
        self.padding_packets = 0;
        self.last_sample_timestamp = Some(sample_timestamp);

        self.prepared_samples[self.prepared.tail as usize] = Some(sample);
        self.prepared.tail = self.prepared.tail.wrapping_add(1);

        self.purge_consumed_location(&consume, true);
        self.purge_consumed_buffers();

        Ok(consume)
    }

    /// Compiles pushed RTP packets into media samples and then
    /// returns the next valid sample (or None if no sample is compiled).
    pub fn pop(&mut self, now: Instant) -> Option<Sample> {
        self.give_up_gaps(now);
        let _ = self.build_sample(now, false);

        if self.prepared.empty() {
            return None;
        }
        let result = self.prepared_samples[self.prepared.head as usize].take();
        self.prepared.head = self.prepared.head.wrapping_add(1);
        result
    }

    /// Compiles pushed RTP packets into media samples and then
    /// returns the next valid sample with its associated RTP timestamp (or `None` if
    /// no sample is compiled).
    pub fn pop_with_timestamp(&mut self, now: Instant) -> Option<(Sample, u32)> {
        if let Some(sample) = self.pop(now) {
            let timestamp = sample.packet_timestamp;
            Some((sample, timestamp))
        } else {
            None
        }
    }
}

// Computes the distance between two sequence numbers
/*pub(crate) fn seqnum_distance(head: u16, tail: u16) -> u16 {
    if head > tail {
        head.wrapping_add(tail)
    } else {
        tail - head
    }
}*/

pub(crate) fn seqnum_distance(x: u16, y: u16) -> u16 {
    let diff = x.wrapping_sub(y);
    if diff > 0xFFFF / 2 {
        0xFFFF - diff + 1
    } else {
        diff
    }
}

#[derive(Debug)]
enum BuildError {
    /// There's no active segment of RTP packets to consider yet.
    NoActiveSegment,

    /// No sample partition could be found in the active segment.
    NothingToConsume,

    /// A segment to consume was identified, but a subsequent packet is needed to determine the
    /// duration of the sample.
    PendingTimestampPacket,

    /// The active segment's head was not aligned with a sample partition head. Some packets were
    /// dropped.
    InvalidPartition(SampleSequenceLocation),

    /// There was a gap in the active segment because of one or more missing RTP packets.
    GapInSegment,

    /// We failed to depacketize an RTP packet.
    DepacketizerFailed,
}
