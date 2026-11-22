//! Named telephone events, DTMF included ([RFC 4733]).
//!
//! The payload is a list of 4-byte event reports:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     event     |E|R| volume    |          duration             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Besides the wire type (`TelephoneEvent`) this module has the DTMF code table (section 3.2),
//! the `events` fmtp list (`EventSet`, section 2.4), and two sans-I/O state machines:
//! `TelephoneEventSender`, which turns "event started / still going / ended" into the packets
//! of section 2.5.1, and `TelephoneEventReceiver`, which turns received packets back into
//! started / updated / ended reports following section 2.5.2.
//!
//! Event packets travel in the audio stream and share its sequence number space and timestamp
//! base (section 2.5.1.2): the sender here produces marker, timestamp and payload only, and the
//! caller numbers the packets with the audio stream's sequencer, one number per packet sent,
//! retransmissions included (section 2.5.1.6).
//!
//! Every event is treated as a non-state event (all events registered for WebRTC are tones), so
//! a zero duration is never sent and a received zero-duration report is ignored (section 2.3.5).
//!
//! [RFC 4733]: https://datatracker.ietf.org/doc/html/rfc4733
#[cfg(test)]
mod telephone_event_test;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use shared::error::{Error, Result};
use shared::marshal::{Marshal, MarshalSize, Unmarshal};
use std::fmt;

/// Size of one event report on the wire.
pub const TELEPHONE_EVENT_SIZE: usize = 4;
/// The largest volume value: the field is 6 bits, 0 to -63 dBm0 (section 2.3.4).
pub const TELEPHONE_EVENT_MAX_VOLUME: u8 = 63;
/// The largest duration one report (one segment) can carry (section 2.5.1.3).
pub const TELEPHONE_EVENT_MAX_SEGMENT_DURATION: u16 = 0xFFFF;

/// DTMF digit 0 (section 3.2).
pub const DTMF_0: u8 = 0;
/// DTMF digit 1.
pub const DTMF_1: u8 = 1;
/// DTMF digit 2.
pub const DTMF_2: u8 = 2;
/// DTMF digit 3.
pub const DTMF_3: u8 = 3;
/// DTMF digit 4.
pub const DTMF_4: u8 = 4;
/// DTMF digit 5.
pub const DTMF_5: u8 = 5;
/// DTMF digit 6.
pub const DTMF_6: u8 = 6;
/// DTMF digit 7.
pub const DTMF_7: u8 = 7;
/// DTMF digit 8.
pub const DTMF_8: u8 = 8;
/// DTMF digit 9.
pub const DTMF_9: u8 = 9;
/// DTMF `*`.
pub const DTMF_STAR: u8 = 10;
/// DTMF `#`.
pub const DTMF_POUND: u8 = 11;
/// DTMF A.
pub const DTMF_A: u8 = 12;
/// DTMF B.
pub const DTMF_B: u8 = 13;
/// DTMF C.
pub const DTMF_C: u8 = 14;
/// DTMF D.
pub const DTMF_D: u8 = 15;

/// The event code of a DTMF character (`0-9`, `*`, `#`, `A-D`, case-insensitive), section 3.2.
pub fn dtmf_event_from_char(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        '*' => Some(DTMF_STAR),
        '#' => Some(DTMF_POUND),
        'A'..='D' => Some(c as u8 - b'A' + DTMF_A),
        'a'..='d' => Some(c as u8 - b'a' + DTMF_A),
        _ => None,
    }
}

/// The DTMF character of an event code 0 to 15 (`A-D` upper case); `None` for any other code.
pub fn dtmf_char_from_event(event: u8) -> Option<char> {
    match event {
        0..=9 => Some((b'0' + event) as char),
        DTMF_STAR => Some('*'),
        DTMF_POUND => Some('#'),
        DTMF_A..=DTMF_D => Some((b'A' + event - DTMF_A) as char),
        _ => None,
    }
}

/// One named-event report (section 2.3).
///
/// The R bit is not represented: [`Marshal`] writes it as zero and [`Unmarshal`] ignores it
/// (section 2.3.3).
#[derive(PartialEq, Eq, Debug, Default, Copy, Clone)]
pub struct TelephoneEvent {
    /// Event code, 0 to 255 (section 2.3.1); DTMF uses 0 to 15.
    pub event: u8,
    /// E bit: this report carries the end of the event (section 2.3.2).
    pub end: bool,
    /// Power level in -dBm0, 0 to 63 (section 2.3.4). Zero for events without a volume.
    pub volume: u8,
    /// Duration of the event or segment so far, in timestamp units (section 2.3.5).
    pub duration: u16,
}

impl MarshalSize for TelephoneEvent {
    fn marshal_size(&self) -> usize {
        TELEPHONE_EVENT_SIZE
    }
}

impl Marshal for TelephoneEvent {
    /// Writes the 4-byte report with R = 0. Fails on a volume above 63.
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if buf.remaining_mut() < TELEPHONE_EVENT_SIZE {
            return Err(Error::ErrBufferTooSmall);
        }
        if self.volume > TELEPHONE_EVENT_MAX_VOLUME {
            return Err(Error::Other(format!(
                "telephone-event volume {} exceeds {TELEPHONE_EVENT_MAX_VOLUME}",
                self.volume
            )));
        }
        buf.put_u8(self.event);
        buf.put_u8(if self.end { 0x80 } else { 0 } | self.volume);
        buf.put_u16(self.duration);
        Ok(TELEPHONE_EVENT_SIZE)
    }
}

impl Unmarshal for TelephoneEvent {
    /// Reads one 4-byte report, ignoring the R bit.
    fn unmarshal<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < TELEPHONE_EVENT_SIZE {
            return Err(Error::ErrShortPacket);
        }
        let event = buf.get_u8();
        let flags = buf.get_u8();
        let duration = buf.get_u16();
        Ok(TelephoneEvent {
            event,
            end: flags & 0x80 != 0,
            volume: flags & 0x3F,
            duration,
        })
    }
}

/// Parses a telephone-event payload holding one or more reports (section 2.5.1.5).
///
/// # Errors
///
/// Fails on an empty payload or one whose length is not a multiple of 4.
pub fn parse_telephone_events(payload: &[u8]) -> Result<Vec<TelephoneEvent>> {
    if payload.is_empty() || !payload.len().is_multiple_of(TELEPHONE_EVENT_SIZE) {
        return Err(Error::ErrShortPacket);
    }
    let mut buf = payload;
    let mut events = Vec::with_capacity(payload.len() / TELEPHONE_EVENT_SIZE);
    while buf.has_remaining() {
        events.push(TelephoneEvent::unmarshal(&mut buf)?);
    }
    Ok(events)
}

/// Marshals one or more reports into one payload, in order (section 2.5.1.5).
///
/// # Errors
///
/// Fails on an empty list or a report whose volume exceeds 63.
pub fn marshal_telephone_events(events: &[TelephoneEvent]) -> Result<Bytes> {
    if events.is_empty() {
        return Err(Error::Other(
            "telephone-event payload needs an event".into(),
        ));
    }
    let mut out = BytesMut::zeroed(events.len() * TELEPHONE_EVENT_SIZE);
    for (i, event) in events.iter().enumerate() {
        let start = i * TELEPHONE_EVENT_SIZE;
        event.marshal_to(&mut out[start..start + TELEPHONE_EVENT_SIZE])?;
    }
    Ok(out.freeze())
}

/// A set of event codes, as the `events` fmtp parameter lists them (section 2.4).
///
/// Bounded by construction: one bit per code 0 to 255. [`EventSet::default`] is the set a sender
/// assumes when the receiver sent no `events` parameter: DTMF 0 to 15 (section 2.5.1.1).
#[derive(PartialEq, Eq, Copy, Clone)]
pub struct EventSet {
    bits: [u64; 4],
}

impl Default for EventSet {
    fn default() -> Self {
        EventSet::dtmf()
    }
}

impl fmt::Debug for EventSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventSet({self})")
    }
}

impl fmt::Display for EventSet {
    /// The fmtp form: ascending, consecutive codes as `a-b` ranges, comma-separated, no spaces.
    /// An empty set formats as the empty string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut code: u16 = 0;
        while code <= 255 {
            if !self.contains(code as u8) {
                code += 1;
                continue;
            }
            let start = code;
            while code < 255 && self.contains((code + 1) as u8) {
                code += 1;
            }
            if !first {
                f.write_str(",")?;
            }
            first = false;
            if start == code {
                write!(f, "{start}")?;
            } else {
                write!(f, "{start}-{code}")?;
            }
            code += 1;
        }
        Ok(())
    }
}

impl EventSet {
    /// The empty set.
    pub fn empty() -> Self {
        EventSet { bits: [0; 4] }
    }

    /// DTMF events 0 to 15.
    pub fn dtmf() -> Self {
        let mut set = EventSet::empty();
        set.insert_range(DTMF_0, DTMF_D);
        set
    }

    /// Parses an `events` list such as `0-15,32,36` (section 2.4): comma-separated codes or
    /// `low-high` ranges, unsorted, no white space.
    ///
    /// # Errors
    ///
    /// Fails on an empty list or element, white space, a non-decimal token, a code above 255
    /// or a range whose upper bound is below its lower bound.
    pub fn parse(list: &str) -> Result<Self> {
        let mut set = EventSet::empty();
        if list.is_empty() {
            return Err(Error::Other("empty telephone-event list".into()));
        }
        for element in list.split(',') {
            match element.split_once('-') {
                Some((low, high)) => {
                    let low = parse_event_code(low)?;
                    let high = parse_event_code(high)?;
                    if high < low {
                        return Err(Error::Other(format!(
                            "telephone-event range {element} is reversed"
                        )));
                    }
                    set.insert_range(low, high);
                }
                None => set.insert(parse_event_code(element)?),
            }
        }
        Ok(set)
    }

    /// The set a sender may use towards a receiver: the receiver's `events` list when it sent
    /// one, otherwise DTMF 0 to 15 (section 2.5.1.1).
    ///
    /// # Errors
    ///
    /// Fails when the list is present and malformed (see [`EventSet::parse`]).
    pub fn from_peer_fmtp(list: Option<&str>) -> Result<Self> {
        match list {
            Some(list) => EventSet::parse(list),
            None => Ok(EventSet::dtmf()),
        }
    }

    /// Adds one code.
    pub fn insert(&mut self, event: u8) {
        self.bits[usize::from(event >> 6)] |= 1u64 << (event & 63);
    }

    /// Adds every code from `low` to `high` inclusive.
    pub fn insert_range(&mut self, low: u8, high: u8) {
        for event in low..=high {
            self.insert(event);
        }
    }

    /// Removes one code.
    pub fn remove(&mut self, event: u8) {
        self.bits[usize::from(event >> 6)] &= !(1u64 << (event & 63));
    }

    /// Whether `event` is in the set.
    pub fn contains(&self, event: u8) -> bool {
        self.bits[usize::from(event >> 6)] & (1u64 << (event & 63)) != 0
    }

    /// Whether the set has no code.
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|b| *b == 0)
    }

    /// Number of codes in the set.
    pub fn len(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// The codes in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = u8> + '_ {
        (0..=255u8).filter(|e| self.contains(*e))
    }
}

fn parse_event_code(token: &str) -> Result<u8> {
    if token.is_empty() || token.len() > 3 || !token.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Other(format!(
            "invalid telephone-event code {token:?}"
        )));
    }
    token
        .parse::<u8>()
        .map_err(|_| Error::Other(format!("telephone-event code {token} exceeds 255")))
}

/// One packet the [`TelephoneEventSender`] wants sent: the RTP header fields it decides plus the
/// payload. The caller fills in the sequence number (the audio stream's next one), SSRC and the
/// telephone-event payload type.
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct EventPacket {
    /// RTP marker bit.
    pub marker: bool,
    /// RTP timestamp: the start of the event's current segment.
    pub timestamp: u32,
    /// The single event report this packet carries.
    pub event: TelephoneEvent,
}

impl EventPacket {
    /// The marshalled 4-byte payload.
    ///
    /// # Errors
    ///
    /// Fails only on a report with a volume above 63, which the sender never produces.
    pub fn payload(&self) -> Result<Bytes> {
        Ok(self.event.marshal()?.freeze())
    }
}

#[derive(Debug, Copy, Clone)]
struct ActiveEvent {
    event: u8,
    volume: u8,
    start_timestamp: u32,
    /// Cumulative duration reported so far, in timestamp units.
    reported: u32,
    /// Whether the next packet is the event's first (carries M).
    first_pending: bool,
}

/// The sending procedures of RFC 4733 section 2.5.1 for one event at a time, sans-I/O.
///
/// Drive it with [`start`](Self::start), then [`update`](Self::update) at each update interval
/// (the audio packetization interval, or 50 ms; section 2.5.1.2) and finally
/// [`end`](Self::end). Durations passed in are cumulative since the event started, in
/// timestamp units of the telephone-event clock. The sender
///
/// * sets M on the first packet only and keeps each segment's start timestamp on all its
///   packets (sections 2.2.1, 2.2.2, 2.5.1.2);
/// * never reports a zero duration: a zero passed in is clamped to 1 (section 2.3.5);
/// * splits events longer than 0xFFFF units into segments: a report of exactly 0xFFFF without
///   E, then a new segment whose timestamp is the previous one plus 0xFFFF, without M
///   (section 2.5.1.3);
/// * produces the final report three times, identical, with E set on all three
///   (section 2.5.1.4). Segment boundaries (the 0xFFFF report) are reported once, since the
///   next segment's reports follow immediately;
/// * refuses events outside the receiver's [`EventSet`] (section 2.5.1.1).
#[derive(Debug, Clone)]
pub struct TelephoneEventSender {
    allowed: EventSet,
    active: Option<ActiveEvent>,
}

/// How many times the final report of an event is sent (section 2.5.1.4).
pub const TELEPHONE_EVENT_END_REPEATS: usize = 3;

impl TelephoneEventSender {
    /// A sender restricted to `allowed`, the receiver's `events` list (or
    /// [`EventSet::default`] when the receiver sent none).
    pub fn new(allowed: EventSet) -> Self {
        TelephoneEventSender {
            allowed,
            active: None,
        }
    }

    /// The events this sender may send.
    pub fn allowed(&self) -> &EventSet {
        &self.allowed
    }

    /// Whether an event is in progress.
    pub fn is_active(&self) -> bool {
        self.active.is_some()
    }

    /// Starts an event at `rtp_timestamp` (the audio timestamp of the instant it began).
    /// No packet is produced until the first [`update`](Self::update) or [`end`](Self::end).
    ///
    /// # Errors
    ///
    /// Fails if an event is already in progress, the event is not in the allowed set, or the
    /// volume exceeds 63.
    pub fn start(&mut self, event: u8, volume: u8, rtp_timestamp: u32) -> Result<()> {
        if self.active.is_some() {
            return Err(Error::Other(
                "a telephone event is already in progress".into(),
            ));
        }
        if !self.allowed.contains(event) {
            return Err(Error::Other(format!(
                "telephone event {event} is not in the receiver's events list"
            )));
        }
        if volume > TELEPHONE_EVENT_MAX_VOLUME {
            return Err(Error::Other(format!(
                "telephone-event volume {volume} exceeds {TELEPHONE_EVENT_MAX_VOLUME}"
            )));
        }
        self.active = Some(ActiveEvent {
            event,
            volume,
            start_timestamp: rtp_timestamp,
            reported: 0,
            first_pending: true,
        });
        Ok(())
    }

    /// Reports the event as still going, `total_duration` units after it started.
    ///
    /// Returns one packet, or two when the duration crosses a segment boundary (the 0xFFFF
    /// report closing the old segment, then the first report of the new one).
    ///
    /// # Errors
    ///
    /// Fails with no event in progress, a duration smaller than the last one reported, or one
    /// that grew by more than 0xFFFF since the last report (it would skip a whole segment).
    pub fn update(&mut self, total_duration: u32) -> Result<Vec<EventPacket>> {
        let mut active = self.take_checked(total_duration)?;
        let mut packets = Vec::with_capacity(2);
        Self::advance(&mut active, total_duration.max(1), &mut packets);
        let last = Self::report(&mut active, total_duration.max(1), false);
        packets.push(last);
        active.reported = total_duration.max(1);
        self.active = Some(active);
        Ok(packets)
    }

    /// Ends the event, `total_duration` units after it started.
    ///
    /// Returns a segment-boundary packet if the duration crosses one, then the final report
    /// three times: same timestamp, same payload, E set. Only the first of the three can carry
    /// M (when the event produced no packet before).
    ///
    /// # Errors
    ///
    /// As [`update`](Self::update). The event stays in progress when this fails.
    pub fn end(&mut self, total_duration: u32) -> Result<Vec<EventPacket>> {
        let mut active = self.take_checked(total_duration)?;
        let total = total_duration.max(1);
        let mut packets = Vec::with_capacity(1 + TELEPHONE_EVENT_END_REPEATS);
        Self::advance(&mut active, total, &mut packets);
        let last = Self::report(&mut active, total, true);
        for i in 0..TELEPHONE_EVENT_END_REPEATS {
            packets.push(EventPacket {
                marker: last.marker && i == 0,
                ..last
            });
        }
        self.active = None;
        Ok(packets)
    }

    /// Abandons the event in progress without sending its end.
    pub fn reset(&mut self) {
        self.active = None;
    }

    fn take_checked(&mut self, total_duration: u32) -> Result<ActiveEvent> {
        let active = self
            .active
            .ok_or_else(|| Error::Other("no telephone event in progress".into()))?;
        let total = total_duration.max(1);
        if total < active.reported {
            return Err(Error::Other(format!(
                "telephone-event duration {total} is below the {} already reported",
                active.reported
            )));
        }
        if total - active.reported > u32::from(TELEPHONE_EVENT_MAX_SEGMENT_DURATION) {
            return Err(Error::Other(format!(
                "telephone-event duration grew by more than 0xFFFF (from {} to {total})",
                active.reported
            )));
        }
        Ok(active)
    }

    /// Segment index of a cumulative duration (> 0): durations 1..=0xFFFF are segment 0.
    fn segment_of(total: u32) -> u32 {
        (total - 1) / u32::from(TELEPHONE_EVENT_MAX_SEGMENT_DURATION)
    }

    /// Emits the 0xFFFF report closing the segment the last report was in, if `total` lies in
    /// a later segment. `take_checked` bounds the growth, so at most one boundary is crossed.
    fn advance(active: &mut ActiveEvent, total: u32, packets: &mut Vec<EventPacket>) {
        let from = if active.reported == 0 {
            0
        } else {
            Self::segment_of(active.reported)
        };
        if Self::segment_of(total) > from {
            let boundary = (from + 1) * u32::from(TELEPHONE_EVENT_MAX_SEGMENT_DURATION);
            if active.reported != boundary {
                let packet = Self::report(active, boundary, false);
                packets.push(packet);
                active.reported = boundary;
            }
        }
    }

    fn report(active: &mut ActiveEvent, total: u32, end: bool) -> EventPacket {
        let max = u32::from(TELEPHONE_EVENT_MAX_SEGMENT_DURATION);
        let segment = Self::segment_of(total);
        let duration = (total - segment * max) as u16;
        let marker = active.first_pending;
        active.first_pending = false;
        EventPacket {
            marker,
            timestamp: active
                .start_timestamp
                .wrapping_add(segment.wrapping_mul(max)),
            event: TelephoneEvent {
                event: active.event,
                end,
                volume: active.volume,
                duration,
            },
        }
    }
}

/// Every packet for one event of `total_duration` units starting at `rtp_timestamp`, with an
/// update every `interval` units: updates at `interval`, `2 * interval`, ... below the total,
/// then the final report three times. This is what an `RTCDTMFSender`-like caller sends for one
/// tone (`interval` is typically 50 ms worth of units, section 2.5.1.2).
///
/// # Errors
///
/// Fails if `interval` is 0 or above 0xFFFF, or the event is refused (see
/// [`TelephoneEventSender::start`]).
pub fn telephone_event_packets(
    allowed: &EventSet,
    event: u8,
    volume: u8,
    rtp_timestamp: u32,
    total_duration: u32,
    interval: u32,
) -> Result<Vec<EventPacket>> {
    if interval == 0 || interval > u32::from(TELEPHONE_EVENT_MAX_SEGMENT_DURATION) {
        return Err(Error::Other(format!(
            "telephone-event update interval {interval} is out of range"
        )));
    }
    let mut sender = TelephoneEventSender::new(*allowed);
    sender.start(event, volume, rtp_timestamp)?;
    let total = total_duration.max(1);
    let mut packets = Vec::new();
    let mut elapsed = interval;
    while elapsed < total {
        packets.extend(sender.update(elapsed)?);
        elapsed = elapsed.saturating_add(interval);
    }
    packets.extend(sender.end(total)?);
    Ok(packets)
}

/// What a [`TelephoneEventReceiver`] learned from a packet.
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[non_exhaustive]
pub enum TelephoneEventReport {
    /// A new event began at `timestamp` (also reported when its first packets were lost).
    Started {
        /// Event code.
        event: u8,
        /// Volume of the first report seen.
        volume: u8,
        /// RTP timestamp of the start of the event (of its first segment seen).
        timestamp: u32,
    },
    /// The event in progress has now lasted `duration` units in total, segments included.
    Updated {
        /// Event code.
        event: u8,
        /// Cumulative duration across segments.
        duration: u32,
    },
    /// The event ended, after `total_duration` units in total.
    Ended {
        /// Event code.
        event: u8,
        /// Total duration across segments.
        total_duration: u32,
    },
}

#[derive(Debug, Copy, Clone)]
struct ReceivedEvent {
    event: u8,
    first_timestamp: u32,
    segment_timestamp: u32,
    segment_duration: u16,
    /// Sum of the durations of the segments before the current one.
    completed: u32,
}

impl ReceivedEvent {
    fn total(&self) -> u32 {
        self.completed
            .saturating_add(u32::from(self.segment_duration))
    }

    /// Whether `timestamp` lies in a segment of this event before or at `upto`.
    fn covers(&self, event: u8, timestamp: u32, upto: u32) -> bool {
        event == self.event
            && timestamp.wrapping_sub(self.first_timestamp)
                <= upto.wrapping_sub(self.first_timestamp)
    }
}

/// The receiving procedures of RFC 4733 section 2.5.2, sans-I/O: feed it every
/// telephone-event packet's timestamp, marker and payload, get back started / updated / ended
/// reports.
///
/// * The three copies of a final report, and any later report for an event already ended,
///   produce nothing (sections 2.5.1.4, 2.5.2.2).
/// * A report for the same event code whose timestamp is the previous segment's timestamp plus
///   its duration (or plus 0xFFFF, should the 0xFFFF report itself be lost) continues a long
///   event: durations add up across segments (section 2.5.2.3). A lone report with M set
///   always starts a new event.
/// * A report without M for an unknown event starts it (the first packet was lost); a report
///   for a new event or timestamp ends the event in progress (its end packets were lost).
/// * The R bit is ignored, and zero-duration reports are ignored (no event is treated as a
///   state, section 2.3.5).
/// * Several reports in one packet are handled in order, each starting where the previous one
///   ended (section 2.5.2.4).
///
/// State is one event in progress plus the last ended one; nothing grows with input.
#[derive(Debug, Default, Clone)]
pub struct TelephoneEventReceiver {
    current: Option<ReceivedEvent>,
    last_ended: Option<ReceivedEvent>,
}

impl TelephoneEventReceiver {
    /// A receiver with no event in progress.
    pub fn new() -> Self {
        Self::default()
    }

    /// The event in progress, if any: its code and cumulative duration.
    pub fn current(&self) -> Option<(u8, u32)> {
        self.current.map(|c| (c.event, c.total()))
    }

    /// Handles one telephone-event packet.
    ///
    /// # Errors
    ///
    /// Fails on a malformed payload (see [`parse_telephone_events`]); state is unchanged then.
    pub fn receive(
        &mut self,
        timestamp: u32,
        marker: bool,
        payload: &[u8],
    ) -> Result<Vec<TelephoneEventReport>> {
        let events = parse_telephone_events(payload)?;
        let lone_marker = marker && events.len() == 1;
        let mut reports = Vec::new();
        let mut block_timestamp = timestamp;
        for event in &events {
            self.receive_one(block_timestamp, lone_marker, event, &mut reports);
            block_timestamp = block_timestamp.wrapping_add(u32::from(event.duration));
        }
        Ok(reports)
    }

    fn receive_one(
        &mut self,
        timestamp: u32,
        lone_marker: bool,
        report: &TelephoneEvent,
        out: &mut Vec<TelephoneEventReport>,
    ) {
        if report.duration == 0 {
            return;
        }
        if let Some(ended) = self.last_ended
            && ended.covers(report.event, timestamp, ended.segment_timestamp)
        {
            return;
        }

        if let Some(mut current) = self.current {
            if current.covers(report.event, timestamp, current.segment_timestamp) {
                if timestamp != current.segment_timestamp {
                    // A late report from an earlier segment of this event.
                    return;
                }
                if report.duration > current.segment_duration {
                    current.segment_duration = report.duration;
                    out.push(TelephoneEventReport::Updated {
                        event: current.event,
                        duration: current.total(),
                    });
                }
                self.current = Some(current);
                if report.end {
                    self.finish(out);
                }
                return;
            }

            let step = timestamp.wrapping_sub(current.segment_timestamp);
            let continues = report.event == current.event
                && !lone_marker
                && (step == u32::from(current.segment_duration)
                    || step == u32::from(TELEPHONE_EVENT_MAX_SEGMENT_DURATION));
            if continues {
                current.completed = current.completed.saturating_add(step);
                current.segment_timestamp = timestamp;
                current.segment_duration = report.duration;
                out.push(TelephoneEventReport::Updated {
                    event: current.event,
                    duration: current.total(),
                });
                self.current = Some(current);
                if report.end {
                    self.finish(out);
                }
                return;
            }

            // A different event or timestamp: the current one's end packets were lost.
            self.finish(out);
        }

        self.current = Some(ReceivedEvent {
            event: report.event,
            first_timestamp: timestamp,
            segment_timestamp: timestamp,
            segment_duration: report.duration,
            completed: 0,
        });
        out.push(TelephoneEventReport::Started {
            event: report.event,
            volume: report.volume,
            timestamp,
        });
        out.push(TelephoneEventReport::Updated {
            event: report.event,
            duration: u32::from(report.duration),
        });
        if report.end {
            self.finish(out);
        }
    }

    fn finish(&mut self, out: &mut Vec<TelephoneEventReport>) {
        if let Some(current) = self.current.take() {
            out.push(TelephoneEventReport::Ended {
                event: current.event,
                total_duration: current.total(),
            });
            self.last_ended = Some(current);
        }
    }
}
