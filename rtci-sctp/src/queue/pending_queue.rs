use crate::chunk::chunk_payload_data::{
    ChunkPayloadData, MessageId, MessageReliability, PayloadProtocolIdentifier,
};
use crate::config::StreamScheduler;
use rustc_hash::{FxHashMap, FxHashSet};
use shared::error::{Error, Result};

use std::collections::{BTreeSet, VecDeque};
use std::time::Instant;

/// The weight of a stream no one has weighted: the normal data channel priority (RFC 8832).
pub(crate) const DEFAULT_STREAM_WEIGHT: u16 = 256;

pub(crate) type PendingBaseQueue = VecDeque<ChunkPayloadData>;

/// Ownership and policy remain available after the first fragment is sent or
/// the API stream closes. Later fragments cannot replace this message snapshot.
#[derive(Debug, Copy, Clone)]
struct MessageSnapshot {
    id: Option<MessageId>,
    stream_identifier: u16,
    stream_sequence_number: u16,
    stream_generation: u64,
    unordered: bool,
    payload_type: PayloadProtocolIdentifier,
    payload_protocol_id: u32,
    created_at: Option<Instant>,
    reliability: MessageReliability,
}

impl MessageSnapshot {
    fn from_chunk(c: &ChunkPayloadData) -> Self {
        Self {
            id: c.message_id,
            stream_identifier: c.stream_identifier,
            stream_sequence_number: c.stream_sequence_number,
            stream_generation: c.stream_generation,
            unordered: c.unordered,
            payload_type: c.payload_type,
            payload_protocol_id: c.payload_protocol_id,
            created_at: c.created_at,
            reliability: c.reliability,
        }
    }

    fn matches(&self, c: &ChunkPayloadData) -> bool {
        self.id == c.message_id
            && self.stream_identifier == c.stream_identifier
            && self.stream_sequence_number == c.stream_sequence_number
            && self.stream_generation == c.stream_generation
            && self.unordered == c.unordered
    }

    fn apply(&self, c: &mut ChunkPayloadData) {
        c.payload_type = self.payload_type;
        c.payload_protocol_id = self.payload_protocol_id;
        c.created_at = self.created_at;
        c.reliability = self.reliability;
    }
}

/// One message owns its unsent tail. Whole messages stay inline; fragmented
/// messages reuse the packetization buffer.
#[derive(Debug)]
enum QueuedMessage {
    Whole(ChunkPayloadData),
    Fragmented {
        snapshot: MessageSnapshot,
        fragments: PendingBaseQueue,
        next_fragment: usize,
        bytes: usize,
    },
}

impl QueuedMessage {
    fn new(mut chunks: Vec<ChunkPayloadData>) -> Option<Self> {
        let first = chunks.first()?;
        if chunks.len() == 1 && first.beginning_fragment && first.ending_fragment {
            return chunks.pop().map(Self::Whole);
        }
        let snapshot = MessageSnapshot::from_chunk(first);
        let mut bytes = 0;
        for c in &mut chunks {
            snapshot.apply(c);
            bytes += c.user_data.len();
        }
        Some(Self::Fragmented {
            snapshot,
            bytes,
            fragments: VecDeque::from(chunks),
            next_fragment: 0,
        })
    }

    fn peek(&self) -> Option<&ChunkPayloadData> {
        match self {
            Self::Whole(c) => Some(c),
            Self::Fragmented { fragments, .. } => fragments.front(),
        }
    }

    fn snapshot(&self) -> MessageSnapshot {
        match self {
            Self::Whole(c) => MessageSnapshot::from_chunk(c),
            Self::Fragmented { snapshot, .. } => *snapshot,
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Whole(_) => 1,
            Self::Fragmented { fragments, .. } => fragments.len(),
        }
    }

    fn bytes(&self) -> usize {
        match self {
            Self::Whole(c) => c.user_data.len(),
            Self::Fragmented { bytes, .. } => *bytes,
        }
    }

    /// Check the complete remaining tail before changing ownership or counters.
    fn validate_tail(&self) -> Result<(usize, usize)> {
        let (snapshot, fragments, next_fragment, bytes) = match self {
            Self::Whole(c) => return Ok((1, c.user_data.len())),
            Self::Fragmented {
                snapshot,
                fragments,
                next_fragment,
                bytes,
            } => (snapshot, fragments, next_fragment, bytes),
        };
        if !fragments.back().is_some_and(|c| c.ending_fragment) {
            return Err(Error::OtherSctpErr(
                "pending message has no ending fragment".into(),
            ));
        }
        let mut actual_bytes = 0;
        for (i, c) in fragments.iter().enumerate() {
            if !snapshot.matches(c)
                || c.beginning_fragment != (*next_fragment == 0 && i == 0)
                || c.ending_fragment != (i + 1 == fragments.len())
            {
                return Err(Error::OtherSctpErr(
                    "invalid pending message fragments".into(),
                ));
            }
            actual_bytes += c.user_data.len();
        }
        if actual_bytes != *bytes {
            return Err(Error::OtherSctpErr(
                "invalid pending message accounting".into(),
            ));
        }
        Ok((fragments.len(), *bytes))
    }

    fn into_fragments(self) -> Vec<ChunkPayloadData> {
        match self {
            Self::Whole(c) => vec![c],
            Self::Fragmented { fragments, .. } => Vec::from(fragments),
        }
    }
}

/// Takes the next fragment of the message at the front of `queue` after checking it against the
/// message, and removes the message once its last fragment leaves.
fn pop_front_fragment<T>(
    queue: &mut VecDeque<T>,
    message: fn(&mut T) -> Option<&mut QueuedMessage>,
    whole: fn(T) -> Option<ChunkPayloadData>,
) -> Option<ChunkPayloadData> {
    match message(queue.front_mut()?)? {
        QueuedMessage::Whole(_) => whole(queue.pop_front()?),
        QueuedMessage::Fragmented {
            snapshot,
            fragments,
            next_fragment,
            bytes,
        } => {
            let first = fragments.front()?;
            if !snapshot.matches(first)
                || first.beginning_fragment != (*next_fragment == 0)
                || first.ending_fragment != (fragments.len() == 1)
            {
                return None;
            }
            let remaining_bytes = bytes.checked_sub(first.user_data.len())?;
            let next = next_fragment.checked_add(1)?;
            let c = fragments.pop_front()?;
            *next_fragment = next;
            *bytes = remaining_bytes;
            if c.ending_fragment {
                queue.pop_front();
            }
            Some(c)
        }
    }
}

fn tagged_message(entry: &mut (u64, PendingEntry)) -> Option<&mut QueuedMessage> {
    match &mut entry.1 {
        PendingEntry::Message(message) => Some(message),
        PendingEntry::Reset(_) => None,
    }
}

fn tagged_whole(entry: (u64, PendingEntry)) -> Option<ChunkPayloadData> {
    match entry.1 {
        PendingEntry::Message(QueuedMessage::Whole(c)) => Some(c),
        _ => None,
    }
}

/// A reset is control state, with no DATA payload or reliability policy.
#[derive(Debug, Default)]
pub(crate) struct ResetMarker {
    pub(crate) stream_identifier: u16,
    /// The stream as it was when the reset was asked for; a later stream with the same
    /// identifier is another stream.
    pub(crate) generation: u64,
    /// The Incoming SSN Reset Request of the peer this reset answers (RFC 6525 5.2.3).
    pub(crate) response_to: Option<u32>,
}

impl ResetMarker {
    #[cfg(test)]
    pub(crate) fn new(stream_identifier: u16) -> Self {
        ResetMarker {
            stream_identifier,
            ..Default::default()
        }
    }
}

#[derive(Debug)]
enum PendingEntry {
    Message(QueuedMessage),
    Reset(ResetMarker),
}

/// What a stream with a message at its head is scheduled by: the lowest key goes next.
type Key = (u128, u64);

/// One outgoing stream's queue: its messages and resets in the order they were written,
/// each with its arrival number.
#[derive(Debug, Default)]
struct StreamQueue {
    entries: VecDeque<(u64, PendingEntry)>,
    /// The key of the stream while a message is at its head.
    key: Option<Key>,
    /// The message at the head has had a fragment sent.
    part_sent: bool,
    /// Fair queueing: the finish tag of the unit (message, or chunk when interleaving) last
    /// scheduled.
    last_finish: u128,
    /// Round robin per packet: the turn the stream holds until its packet is full.
    turn: Option<u64>,
}

/// The messages waiting to be sent, one queue per stream, and the stream scheduler (RFC 8260
/// section 3) that picks the stream whose data goes next.
///
/// Without user message interleaving a message that has had a fragment sent is finished
/// before any other stream is served (its fragments need consecutive TSNs), so the scheduler
/// chooses at message boundaries. With interleaving (I-DATA) it chooses for every chunk, and
/// each stream still sends one message at a time.
#[derive(Debug, Default)]
pub(crate) struct PendingQueue {
    scheduler: StreamScheduler,
    interleaving: bool,
    streams: FxHashMap<u16, StreamQueue>,
    /// The priority (or weight) of each stream that was given one.
    priorities: FxHashMap<u16, u16>,
    /// The streams with a message at their head, by key.
    heads: BTreeSet<(Key, u16)>,
    /// The streams with a reset at their head, by arrival.
    resets: BTreeSet<(u64, u16)>,
    /// Without interleaving: the stream whose message is part sent.
    locked: Option<u16>,
    /// The streams whose head message is part sent.
    part_sent: FxHashSet<u16>,
    /// Only messages that are part sent may go on (see `set_only_part_sent`).
    only_part_sent: bool,
    next_arrival: u64,
    next_turn: u64,
    /// Fair queueing: the finish tag of the unit most recently started.
    virtual_time: u128,
    /// Round robin per packet: what a packet holds, what the current one holds so far, and
    /// the stream it belongs to.
    packet_budget: usize,
    packet_used: usize,
    packet_stream: Option<u16>,
    queue_len: usize,
    n_bytes: usize,
}

impl PendingQueue {
    pub(crate) fn new() -> Self {
        PendingQueue::default()
    }

    pub(crate) fn with_scheduler(scheduler: StreamScheduler) -> Self {
        PendingQueue {
            scheduler,
            ..PendingQueue::default()
        }
    }

    /// Whether the scheduler may switch streams between the fragments of a message: user
    /// message interleaving was negotiated (RFC 8260 2.2.2).
    pub(crate) fn set_interleaving(&mut self, interleaving: bool) {
        self.interleaving = interleaving;
    }

    /// Whether a packet carries the DATA of one stream only (RFC 8260 3.3).
    pub(crate) fn one_stream_per_packet(&self) -> bool {
        self.scheduler == StreamScheduler::RoundRobinPerPacket
    }

    /// The room a packet has for DATA chunks, for the round-robin-per-packet scheduler.
    pub(crate) fn set_packet_budget(&mut self, bytes: usize) {
        self.packet_budget = bytes;
    }

    /// Sets a stream's priority: its weight under weighted fair queueing (a stream with n
    /// times the weight gets n times the capacity) and its rank under the priority scheduler
    /// (the higher value goes first). Zero counts as one.
    pub(crate) fn set_weight(&mut self, stream: u16, weight: u16) {
        self.priorities.insert(stream, weight.max(1));
        if self.scheduler == StreamScheduler::Priority
            && let Some(q) = self.streams.get_mut(&stream)
            && let Some(key) = q.key
        {
            self.heads.remove(&(key, stream));
            let key = (u128::from(u16::MAX - weight.max(1)), key.1);
            q.key = Some(key);
            self.heads.insert((key, stream));
        }
    }

    /// A new stream took this identifier: it starts with the default priority.
    pub(crate) fn forget_weight(&mut self, stream: u16) {
        if self.priorities.remove(&stream).is_some() {
            self.set_weight(stream, DEFAULT_STREAM_WEIGHT);
            self.priorities.remove(&stream);
        }
    }

    fn weight(&self, stream: u16) -> u16 {
        self.priorities
            .get(&stream)
            .copied()
            .unwrap_or(DEFAULT_STREAM_WEIGHT)
    }

    /// The bytes of the unit at the head of a message that the fair schedulers account for:
    /// the chunk when interleaving, the whole message otherwise.
    fn unit_bytes(&self, message: &QueuedMessage) -> usize {
        if self.interleaving {
            message.peek().map_or(0, |c| c.user_data.len())
        } else {
            message.bytes()
        }
    }

    /// Takes the stream out of the scheduler's sets.
    fn unschedule(&mut self, stream: u16) {
        let Some(q) = self.streams.get_mut(&stream) else {
            return;
        };
        if let Some(key) = q.key.take() {
            self.heads.remove(&(key, stream));
        }
        if let Some((arrival, PendingEntry::Reset(_))) = q.entries.front() {
            self.resets.remove(&(*arrival, stream));
        }
    }

    /// Puts the stream into the scheduler's sets by what is at its head now: a new unit.
    fn schedule(&mut self, stream: u16) {
        let weight = u128::from(self.weight(stream));
        let Some(q) = self.streams.get(&stream) else {
            return;
        };
        let (arrival, unit) = match q.entries.front() {
            None => {
                self.streams.remove(&stream);
                if self.packet_stream == Some(stream) {
                    self.packet_stream = None;
                    self.packet_used = 0;
                }
                return;
            }
            Some((arrival, PendingEntry::Reset(_))) => {
                self.resets.insert((*arrival, stream));
                return;
            }
            Some((arrival, PendingEntry::Message(message))) => (*arrival, self.unit_bytes(message)),
        };
        let fresh_turn = self.next_turn;
        let virtual_time = self.virtual_time;
        let Some(q) = self.streams.get_mut(&stream) else {
            return;
        };
        let key: Key = match self.scheduler {
            // RFC 8260 3.1: the order the application delivered the messages in.
            StreamScheduler::FirstComeFirstServed => (u128::from(arrival), 0),
            // 3.2: the streams take turns, a message or (interleaving) a chunk each.
            StreamScheduler::RoundRobin => {
                self.next_turn += 1;
                (0, fresh_turn)
            }
            // 3.3: a stream keeps its turn until its packet is full.
            StreamScheduler::RoundRobinPerPacket => {
                if q.turn.is_none() {
                    self.next_turn += 1;
                }
                (0, *q.turn.get_or_insert(fresh_turn))
            }
            // 3.4: the higher priority first; equal priorities take turns.
            StreamScheduler::Priority => {
                self.next_turn += 1;
                (u128::from(u16::MAX - weight as u16), fresh_turn)
            }
            // 3.5, 3.6: self-clocked fair queueing. A unit's finish tag is the later of the
            // virtual time and its stream's last tag, plus its bytes over the stream's
            // weight; the lowest tag goes next. Fair capacity is every weight equal.
            StreamScheduler::FairCapacity | StreamScheduler::WeightedFairQueueing => {
                let weight = if self.scheduler == StreamScheduler::FairCapacity {
                    1
                } else {
                    weight
                };
                let start = q.last_finish.max(virtual_time);
                let finish = start + ((unit as u128) << 16) / weight;
                q.last_finish = finish;
                (finish, 0)
            }
        };
        q.key = Some(key);
        self.heads.insert((key, stream));
    }

    fn push(&mut self, stream: u16, entry: PendingEntry) {
        let arrival = self.next_arrival;
        self.next_arrival += 1;
        let q = self.streams.entry(stream).or_default();
        let was_empty = q.entries.is_empty();
        q.entries.push_back((arrival, entry));
        if was_empty {
            self.schedule(stream);
        }
    }

    /// Enqueue one complete packetized message. An empty packetization is a
    /// no-op, matching an empty application write.
    pub(crate) fn push_message(&mut self, chunks: Vec<ChunkPayloadData>) {
        let Some(message) = QueuedMessage::new(chunks) else {
            return;
        };
        self.n_bytes += message.bytes();
        self.queue_len += message.len();
        let stream = message.snapshot().stream_identifier;
        self.push(stream, PendingEntry::Message(message));
    }

    pub(crate) fn push_reset(&mut self, reset: ResetMarker) {
        self.queue_len += 1;
        self.push(reset.stream_identifier, PendingEntry::Reset(reset));
    }

    /// The stream whose message goes next.
    fn next_stream(&self) -> Option<u16> {
        if let Some(stream) = self.locked {
            return Some(stream);
        }
        if self.only_part_sent {
            return self.part_sent.iter().copied().min();
        }
        if let Some(stream) = self.packet_stream
            && self.streams.get(&stream).is_some_and(|q| q.key.is_some())
        {
            return Some(stream);
        }
        self.heads.first().map(|(_, stream)| *stream)
    }

    fn head_message(&self, stream: u16) -> Option<&QueuedMessage> {
        match self.streams.get(&stream)?.entries.front()? {
            (_, PendingEntry::Message(message)) => Some(message),
            (_, PendingEntry::Reset(_)) => None,
        }
    }

    pub(crate) fn peek(&self) -> Option<&ChunkPayloadData> {
        self.head_message(self.next_stream()?)?.peek()
    }

    /// A reset leaves once the messages written to its stream before it have left. It waits
    /// for no other stream, and not for a message that is part sent without interleaving.
    pub(crate) fn pop_ready_reset(&mut self) -> Option<ResetMarker> {
        if self.locked.is_some() {
            return None;
        }
        let (_, stream) = *self.resets.first()?;
        let queue_len = self.queue_len.checked_sub(1)?;
        self.unschedule(stream);
        let entry = self.streams.get_mut(&stream)?.entries.pop_front();
        self.schedule(stream);
        let Some((_, PendingEntry::Reset(reset))) = entry else {
            return None;
        };
        self.queue_len = queue_len;
        Some(reset)
    }

    /// The stream whose head is the message `id`, among the streams a message can be
    /// abandoned on: the one that goes next and the ones part sent.
    fn stream_of_head(&self, id: MessageId) -> Option<u16> {
        let is_head = |stream: &u16| {
            self.head_message(*stream)
                .is_some_and(|m| m.snapshot().id == Some(id))
        };
        self.locked
            .into_iter()
            .chain(self.next_stream())
            .chain(self.part_sent.iter().copied())
            .find(is_head)
    }

    /// Remove the rest of this message once. A repeated call cannot consume
    /// the next message, even when it has the same stream and policy metadata.
    pub(crate) fn drain_message(&mut self, id: MessageId) -> Result<Vec<ChunkPayloadData>> {
        let Some(stream) = self.stream_of_head(id) else {
            return Ok(vec![]);
        };
        let Some(message) = self.head_message(stream) else {
            return Ok(vec![]);
        };
        let (count, bytes) = message.validate_tail()?;
        if count > self.queue_len || bytes > self.n_bytes {
            return Err(Error::OtherSctpErr(
                "invalid pending message accounting".into(),
            ));
        }
        self.unschedule(stream);
        let entry = self
            .streams
            .get_mut(&stream)
            .and_then(|q| q.entries.pop_front());
        self.finish_message(stream);
        self.schedule(stream);
        let Some((_, PendingEntry::Message(message))) = entry else {
            return Err(Error::OtherSctpErr("missing pending message".into()));
        };
        self.queue_len -= count;
        self.n_bytes -= bytes;
        Ok(message.into_fragments())
    }

    /// The message at the head of `stream` is over: sent to its last fragment, or abandoned.
    fn finish_message(&mut self, stream: u16) {
        if self.locked == Some(stream) {
            self.locked = None;
        }
        self.part_sent.remove(&stream);
        if let Some(q) = self.streams.get_mut(&stream) {
            q.part_sent = false;
        }
    }

    /// Round robin per packet: the packet being filled is closed, and the stream it
    /// belonged to gives up its turn. Called when a new packet is started.
    pub(crate) fn start_packet(&mut self) {
        self.packet_used = 0;
        let Some(stream) = self.packet_stream.take() else {
            return;
        };
        if let Some(q) = self.streams.get_mut(&stream)
            && q.turn.take().is_some()
            && q.key.is_some()
        {
            self.unschedule(stream);
            self.schedule(stream);
        }
    }

    /// Takes the next fragment of the stream the scheduler picks. `beginning_fragment` is
    /// what the caller saw with `peek`: a fragment that does not match it is not taken.
    pub(crate) fn pop(
        &mut self,
        beginning_fragment: bool,
        _unordered: bool,
    ) -> Option<ChunkPayloadData> {
        let stream = self.next_stream()?;
        let head = self.head_message(stream)?.peek()?;
        if head.beginning_fragment != beginning_fragment {
            return None;
        }
        let n_bytes = self.n_bytes.checked_sub(head.user_data.len())?;
        let queue_len = self.queue_len.checked_sub(1)?;
        let fair = matches!(
            self.scheduler,
            StreamScheduler::FairCapacity | StreamScheduler::WeightedFairQueueing
        );
        let q = self.streams.get_mut(&stream)?;
        let key = q.key;
        let c = pop_front_fragment(&mut q.entries, tagged_message, tagged_whole)?;
        q.part_sent = !c.ending_fragment;
        self.n_bytes = n_bytes;
        self.queue_len = queue_len;

        // The virtual time moves to a unit's finish tag as the unit starts.
        if fair
            && (self.interleaving || c.beginning_fragment)
            && let Some((finish, _)) = key
        {
            self.virtual_time = self.virtual_time.max(finish);
        }

        if c.ending_fragment {
            self.finish_message(stream);
        } else {
            self.part_sent.insert(stream);
            if !self.interleaving {
                self.locked = Some(stream);
            }
        }

        if self.scheduler == StreamScheduler::RoundRobinPerPacket {
            self.packet_stream = Some(stream);
            self.packet_used += c.wire_size();
        }
        // The unit is done when its message is, or with every chunk when interleaving.
        if c.ending_fragment || self.interleaving {
            self.unschedule(stream);
            self.schedule(stream);
        }
        if self.scheduler == StreamScheduler::RoundRobinPerPacket && self.locked.is_none() {
            // The stream keeps the packet while its next chunk still fits.
            let fits = self
                .head_message(stream)
                .and_then(QueuedMessage::peek)
                .is_some_and(|next| self.packet_used + next.wire_size() <= self.packet_budget);
            if !fits {
                self.start_packet();
            }
        }
        Some(c)
    }

    pub(crate) fn get_num_bytes(&self) -> usize {
        self.n_bytes
    }

    /// Whether anything written to `stream` waits here: a message, or part of one, or a reset.
    pub(crate) fn holds_stream(&self, stream: u16) -> bool {
        self.streams
            .get(&stream)
            .is_some_and(|q| !q.entries.is_empty())
    }

    /// Whether a message is part sent: its remaining fragments go before a pause in sending.
    pub(crate) fn is_mid_message(&self) -> bool {
        !self.part_sent.is_empty()
    }

    /// While set, only the messages that are part sent go on; nothing new is started.
    pub(crate) fn set_only_part_sent(&mut self, only: bool) {
        self.only_part_sent = only;
    }

    /// Numbers the messages of `stream` (of its incarnation `generation`) that have no numbers
    /// yet, in the order the stream sends them: the one at its head only, or every one.
    /// `number` is called with whether each message is unordered and returns its Stream
    /// Sequence Number and Message Identifier. The fragments of a message all get the same
    /// numbers. Returns how many messages were numbered.
    pub(crate) fn number_messages(
        &mut self,
        stream: u16,
        generation: u64,
        head_only: bool,
        mut number: impl FnMut(bool) -> (u16, u32),
    ) -> usize {
        let Some(q) = self.streams.get_mut(&stream) else {
            return 0;
        };
        let mut numbered = 0;
        for (_, entry) in q.entries.iter_mut() {
            let PendingEntry::Message(message) = entry else {
                if head_only {
                    break;
                }
                continue;
            };
            let (pending, unordered, message_generation) = match message {
                QueuedMessage::Whole(c) => (c.numbers_pending, c.unordered, c.stream_generation),
                QueuedMessage::Fragmented {
                    snapshot,
                    fragments,
                    ..
                } => (
                    fragments.front().is_some_and(|c| c.numbers_pending),
                    snapshot.unordered,
                    snapshot.stream_generation,
                ),
            };
            if pending && message_generation == generation {
                let (ssn, mid) = number(unordered);
                match message {
                    QueuedMessage::Whole(c) => {
                        c.stream_sequence_number = ssn;
                        c.mid = mid;
                        c.numbers_pending = false;
                    }
                    QueuedMessage::Fragmented {
                        snapshot,
                        fragments,
                        ..
                    } => {
                        snapshot.stream_sequence_number = ssn;
                        for c in fragments.iter_mut() {
                            c.stream_sequence_number = ssn;
                            c.mid = mid;
                            c.numbers_pending = false;
                        }
                    }
                }
                numbered += 1;
            }
            if head_only {
                break;
            }
        }
        numbered
    }

    /// Gives every message still queued new numbers, in the order its stream sends them:
    /// `number` is called with the stream of each message and whether it is unordered, and
    /// returns its Stream Sequence Number and Message Identifier (RFC 6525 5.2.4 G5, 5.2.7
    /// H5: after an SSN/TSN reset every stream starts over).
    pub(crate) fn renumber(&mut self, mut number: impl FnMut(u16, bool) -> (u16, u32)) {
        let mut streams: Vec<u16> = self.streams.keys().copied().collect();
        streams.sort_unstable();
        for stream in streams {
            let Some(q) = self.streams.get_mut(&stream) else {
                continue;
            };
            for (_, entry) in q.entries.iter_mut() {
                let PendingEntry::Message(message) = entry else {
                    continue;
                };
                match message {
                    // It is numbered when it leaves, from the stream's counters.
                    QueuedMessage::Whole(c) if c.numbers_pending => {}
                    QueuedMessage::Fragmented { fragments, .. }
                        if fragments.front().is_some_and(|c| c.numbers_pending) => {}
                    QueuedMessage::Whole(c) => {
                        let (ssn, mid) = number(c.stream_identifier, c.unordered);
                        if !c.unordered {
                            c.stream_sequence_number = ssn;
                        }
                        c.mid = mid;
                    }
                    QueuedMessage::Fragmented {
                        snapshot,
                        fragments,
                        ..
                    } => {
                        let (ssn, mid) = number(snapshot.stream_identifier, snapshot.unordered);
                        if !snapshot.unordered {
                            snapshot.stream_sequence_number = ssn;
                        }
                        for c in fragments.iter_mut() {
                            if !snapshot.unordered {
                                c.stream_sequence_number = ssn;
                            }
                            c.mid = mid;
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.queue_len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::time::Duration;

    fn fragment(beginning: bool, ending: bool, unordered: bool) -> ChunkPayloadData {
        ChunkPayloadData {
            message_id: MessageId::new(0),
            beginning_fragment: beginning,
            ending_fragment: ending,
            unordered,
            user_data: Bytes::from_static(b"data"),
            ..Default::default()
        }
    }

    #[test]
    fn invalid_message_drain_preserves_fragments_and_accounting() {
        for unordered in [false, true] {
            for next_message in [false, true] {
                let mut queue = PendingQueue::new();
                queue.push_message(vec![
                    fragment(true, false, unordered),
                    fragment(false, false, unordered),
                ]);
                if next_message {
                    // Even a malformed tail must not consume the next owner.
                    queue.push_message(vec![fragment(true, true, unordered)]);
                }
                let id = queue.peek().unwrap().message_id.unwrap();
                let (len, bytes) = (queue.len(), queue.get_num_bytes());
                assert!(queue.drain_message(id).is_err());
                assert_eq!(Some(id), queue.peek().unwrap().message_id);
                assert_eq!(len, queue.len());
                assert_eq!(bytes, queue.get_num_bytes());
                assert!(!queue.is_mid_message());
            }
        }
    }

    #[test]
    fn missing_beginning_is_an_error_without_mutation() {
        let mut queue = PendingQueue::new();
        queue.push_message(vec![fragment(false, true, false)]);
        let id = queue.peek().unwrap().message_id.unwrap();
        assert!(queue.drain_message(id).is_err());
        assert_eq!(Some(id), queue.peek().unwrap().message_id);
        assert_eq!(1, queue.len());
        assert_eq!(4, queue.get_num_bytes());
    }

    #[test]
    fn invalid_batch_pop_preserves_fragments_and_accounting() {
        for unordered in [false, true] {
            for early_end in [false, true] {
                let mut queue = PendingQueue::new();
                queue.push_message(vec![
                    fragment(true, early_end, unordered),
                    fragment(!early_end, true, unordered),
                ]);
                let mut later = fragment(true, true, unordered);
                later.message_id = MessageId::new(1);
                queue.push_message(vec![later]);
                if !early_end {
                    // The first fragment is valid, but the tail repeats B.
                    assert!(queue.pop(true, unordered).is_some());
                }
                let (len, bytes) = (queue.len(), queue.get_num_bytes());
                let first = queue.peek().unwrap();
                let id = first.message_id.unwrap();
                assert!(queue.pop(first.beginning_fragment, unordered).is_none());
                assert!(queue.drain_message(id).is_err());
                assert_eq!(Some(id), queue.peek().unwrap().message_id);
                assert_eq!(len, queue.len());
                assert_eq!(bytes, queue.get_num_bytes());
                assert_eq!(!early_end, queue.is_mid_message());
            }
        }
    }

    #[test]
    fn draining_selected_tail_preserves_other_queue_and_is_idempotent() -> Result<()> {
        for unordered in [false, true] {
            let mut queue = PendingQueue::new();
            let chunks = vec![
                fragment(true, false, unordered),
                fragment(false, true, unordered),
            ];
            let buffer = chunks.as_ptr();
            queue.push_message(chunks);
            assert!(queue.pop(true, unordered).is_some());
            queue.push_message(vec![]);
            let mut other = fragment(true, true, !unordered);
            other.message_id = MessageId::new(1);
            queue.push_message(vec![other]);
            let id = queue.peek().unwrap().message_id.unwrap();
            let tail = queue.drain_message(id)?;
            assert_eq!(1, tail.len());
            assert_eq!(buffer, tail.as_ptr());
            assert!(queue.drain_message(id)?.is_empty());
            assert!(!queue.is_mid_message());
            assert_eq!(1, queue.len());
            assert_eq!(4, queue.get_num_bytes());
            assert_eq!(!unordered, queue.peek().unwrap().unordered);
        }
        Ok(())
    }

    #[test]
    fn message_reuses_fragment_buffer_and_keeps_policy_after_a_sent_prefix() {
        let mut queue = PendingQueue::new();
        let created = Instant::now();
        let deadline = created + Duration::from_millis(100);
        let mut first = fragment(true, false, false);
        first.stream_generation = 7;
        first.created_at = Some(created);
        first.payload_type = PayloadProtocolIdentifier::Binary;
        first.reliability = MessageReliability::Timed { deadline };
        let mut tail = fragment(false, true, false);
        tail.stream_generation = 7;
        tail.reliability = MessageReliability::Rexmit {
            max_retransmits: 99,
        };
        let chunks = vec![first, tail];
        let buffer = chunks.as_ptr();
        let capacity = chunks.capacity();
        queue.push_message(chunks);
        let Some((_, PendingEntry::Message(QueuedMessage::Fragmented { fragments, .. }))) =
            queue.streams[&0].entries.front()
        else {
            panic!("expected a fragmented message");
        };
        assert_eq!(buffer, fragments.as_slices().0.as_ptr());
        assert_eq!(capacity, fragments.capacity());
        queue.pop(true, false).unwrap();
        // A different unordered message cannot interrupt the remaining tail.
        let mut other = fragment(true, true, true);
        other.message_id = MessageId::new(1);
        queue.push_message(vec![other]);
        assert_eq!(MessageId::new(0), queue.peek().unwrap().message_id);
        assert!(matches!(
            queue.streams[&0].entries.front(),
            Some((
                _,
                PendingEntry::Message(QueuedMessage::Fragmented {
                    next_fragment: 1,
                    ..
                })
            ))
        ));
        let tail = queue.pop(false, false).unwrap();
        assert_eq!(Some(created), tail.created_at);
        assert_eq!(Some(deadline), tail.reliability.deadline());
        assert_eq!(PayloadProtocolIdentifier::Binary, tail.payload_type);
        assert_eq!(7, tail.stream_generation);
        assert_eq!(MessageId::new(1), queue.peek().unwrap().message_id);
        queue.pop(true, true).unwrap();
        assert!(queue.is_empty());
        assert_eq!(0, queue.get_num_bytes());
    }

    #[test]
    fn zero_size_data_is_not_a_reset_marker() {
        for id in [None, MessageId::new(1)] {
            let mut queue = PendingQueue::new();
            let mut data = fragment(true, true, false);
            data.message_id = id;
            data.user_data = Bytes::new();
            queue.push_message(vec![data]);
            assert_eq!(1, queue.len());
            assert_eq!(0, queue.get_num_bytes());
            assert!(queue.pop_ready_reset().is_none());
            assert_eq!(id, queue.peek().unwrap().message_id);
            queue.pop(true, false).unwrap();
            assert!(queue.is_empty());
        }
    }

    #[test]
    fn sending_or_abandoning_a_tail_preserves_the_reset_boundary() -> Result<()> {
        for unordered in [false, true] {
            for abandon in [false, true] {
                let mut queue = PendingQueue::new();
                queue.push_message(vec![
                    fragment(true, false, unordered),
                    fragment(false, true, unordered),
                ]);
                queue.push_reset(ResetMarker::new(0));
                let mut later = fragment(true, true, false);
                later.message_id = MessageId::new(1);
                later.stream_generation += 1;
                queue.push_message(vec![later]);

                let id = queue.pop(true, unordered).unwrap().message_id.unwrap();
                assert!(queue.pop_ready_reset().is_none());
                assert_eq!(3, queue.len());
                assert_eq!(8, queue.get_num_bytes());
                if abandon {
                    assert_eq!(1, queue.drain_message(id)?.len());
                    assert!(queue.drain_message(id)?.is_empty());
                } else {
                    assert!(queue.pop(false, unordered).unwrap().ending_fragment);
                }
                // Neither DATA operation can consume a control marker.
                assert!(queue.peek().is_none());
                assert!(queue.pop(true, false).is_none());
                assert_eq!(0, queue.pop_ready_reset().unwrap().stream_identifier);
                assert!(queue.pop_ready_reset().is_none());
                assert_eq!(1, queue.len());
                assert_eq!(4, queue.get_num_bytes());
                assert!(queue.drain_message(id)?.is_empty());
                let later = queue.pop(true, false).unwrap();
                assert_eq!(MessageId::new(1), later.message_id);
                assert_eq!(1, later.stream_generation);
                assert!(queue.is_empty());
                assert_eq!(0, queue.get_num_bytes());
            }
        }
        Ok(())
    }

    fn wfq() -> PendingQueue {
        PendingQueue::with_scheduler(StreamScheduler::WeightedFairQueueing)
    }

    fn message(stream: u16, id: u64, pieces: &[usize]) -> Vec<ChunkPayloadData> {
        pieces
            .iter()
            .enumerate()
            .map(|(i, len)| ChunkPayloadData {
                message_id: MessageId::new(id),
                beginning_fragment: i == 0,
                ending_fragment: i + 1 == pieces.len(),
                stream_identifier: stream,
                user_data: Bytes::from(vec![0; *len]),
                ..Default::default()
            })
            .collect()
    }

    fn pop_next(queue: &mut PendingQueue) -> Option<ChunkPayloadData> {
        let next = queue.peek()?;
        let (beginning, unordered) = (next.beginning_fragment, next.unordered);
        queue.pop(beginning, unordered)
    }

    #[test]
    fn busy_streams_share_the_bytes_sent_within_one_message() {
        let mut queue = wfq();
        for i in 0..64 {
            queue.push_message(message(1, 2 * i, &[16 * 1024]));
            queue.push_message(message(2, 2 * i + 1, &[4 * 1024]));
        }
        let mut sent = [0usize; 3];
        while sent[2] < 64 * 4 * 1024 {
            let c = pop_next(&mut queue).unwrap();
            sent[c.stream_identifier as usize] += c.user_data.len();
            assert!(sent[1].abs_diff(sent[2]) <= 16 * 1024, "{sent:?}");
        }
    }

    #[test]
    fn first_come_first_served_sends_in_arrival_order() {
        let mut queue = PendingQueue::new();
        for i in 0..4 {
            queue.push_message(message(1, 2 * i, &[16 * 1024]));
            queue.push_message(message(2, 2 * i + 1, &[4 * 1024]));
        }
        let order: Vec<_> = std::iter::from_fn(|| pop_next(&mut queue))
            .map(|c| c.stream_identifier)
            .collect();
        assert_eq!(vec![1, 2, 1, 2, 1, 2, 1, 2], order);
    }

    #[test]
    fn a_keystroke_waits_for_the_message_in_flight_and_at_most_one_more_per_busy_stream() {
        let mut queue = wfq();
        for i in 0..8 {
            queue.push_message(message(1, 2 * i, &[4 * 1024; 4]));
            queue.push_message(message(2, 2 * i + 1, &[4 * 1024]));
        }
        for _ in 0..5 {
            pop_next(&mut queue).unwrap();
        }
        let in_flight = queue.is_mid_message();
        queue.push_message(message(3, 100, &[10]));

        let mut ahead = 0;
        let keystroke = loop {
            let c = pop_next(&mut queue).unwrap();
            if c.stream_identifier == 3 {
                break c;
            }
            ahead += c.user_data.len();
        };
        assert!(
            in_flight,
            "the keystroke arrives while a 16 KiB message is part sent"
        );
        assert_eq!(10, keystroke.user_data.len());
        assert!(
            ahead <= 3 * 4 * 1024 + 16 * 1024 + 4 * 1024,
            "{ahead} bytes went first"
        );
    }

    #[test]
    fn weights_share_the_bytes_in_proportion() {
        let mut queue = wfq();
        queue.set_weight(1, 512);
        queue.set_weight(2, 256);
        for i in 0..300 {
            queue.push_message(message(1, 2 * i, &[1024]));
            queue.push_message(message(2, 2 * i + 1, &[1024]));
        }
        let mut sent = [0usize; 3];
        for _ in 0..300 {
            let c = pop_next(&mut queue).unwrap();
            sent[c.stream_identifier as usize] += c.user_data.len();
        }
        assert!(sent[1].abs_diff(2 * sent[2]) <= 2 * 1024, "{sent:?}");
    }

    #[test]
    fn a_reset_waits_only_for_its_own_streams_messages() {
        let mut queue = wfq();
        queue.push_message(message(1, 0, &[100]));
        queue.push_reset(ResetMarker::new(1));
        for i in 1..10 {
            queue.push_message(message(2, i, &[100]));
        }

        assert!(
            queue.pop_ready_reset().is_none(),
            "the stream's message first"
        );
        assert_eq!(1, pop_next(&mut queue).unwrap().stream_identifier);
        // The reset is ready with nine messages of stream 2 still queued.
        assert_eq!(1, queue.pop_ready_reset().unwrap().stream_identifier);
        assert_eq!(2, pop_next(&mut queue).unwrap().stream_identifier);
        assert_eq!(8, queue.len());
    }

    #[test]
    fn draining_drops_the_message_the_scheduler_would_send_next() -> Result<()> {
        let mut queue = wfq();
        queue.push_message(message(1, 0, &[1024; 4]));
        queue.push_message(message(2, 1, &[8 * 1024]));
        assert_eq!(1, pop_next(&mut queue).unwrap().stream_identifier);

        let next = queue.peek().unwrap().message_id.unwrap();
        assert_eq!(MessageId::new(0), Some(next));
        assert_eq!(3, queue.drain_message(next)?.len());
        assert!(!queue.is_mid_message());
        assert_eq!(2, pop_next(&mut queue).unwrap().stream_identifier);
        assert!(queue.is_empty());
        assert_eq!(0, queue.get_num_bytes());
        Ok(())
    }
    // ---- the stream schedulers of RFC 8260 section 3 ---------------------------------------

    fn scheduled(scheduler: StreamScheduler, interleaving: bool) -> PendingQueue {
        let mut queue = PendingQueue::with_scheduler(scheduler);
        queue.set_interleaving(interleaving);
        queue
    }

    fn streams_in_order(queue: &mut PendingQueue) -> Vec<u16> {
        std::iter::from_fn(|| pop_next(queue))
            .map(|c| c.stream_identifier)
            .collect()
    }

    /// The queues of RFC 8260 Figures 1 and 2: streams 0 and 2 each hold one message of
    /// three chunks, stream 1 three messages of one chunk.
    fn figure_queues(queue: &mut PendingQueue) {
        queue.push_message(message(0, 0, &[100; 3]));
        for id in 1..=3 {
            queue.push_message(message(1, id, &[100]));
        }
        queue.push_message(message(2, 4, &[100; 3]));
    }

    /// RFC 8260 Figure 1: round robin without interleaving cycles the streams a message at
    /// a time.
    #[test]
    fn round_robin_without_interleaving_sends_as_figure_1() {
        let mut queue = scheduled(StreamScheduler::RoundRobin, false);
        figure_queues(&mut queue);
        assert_eq!(
            vec![0, 0, 0, 1, 2, 2, 2, 1, 1],
            streams_in_order(&mut queue)
        );
    }

    /// RFC 8260 Figure 2: round robin with interleaving cycles the streams a chunk at a
    /// time, and each stream still sends one message after the other.
    #[test]
    fn round_robin_with_interleaving_sends_as_figure_2() {
        let mut queue = scheduled(StreamScheduler::RoundRobin, true);
        figure_queues(&mut queue);
        let mut order = vec![];
        while let Some(c) = pop_next(&mut queue) {
            order.push((c.stream_identifier, c.message_id.unwrap()));
        }
        let id = |n| MessageId::new(n).unwrap();
        assert_eq!(
            vec![
                (0, id(0)),
                (1, id(1)),
                (2, id(4)),
                (0, id(0)),
                (1, id(2)),
                (2, id(4)),
                (0, id(0)),
                (1, id(3)),
                (2, id(4)),
            ],
            order
        );
    }

    /// RFC 8260 3.1: first come, first served is the order of writing, and interleaving
    /// changes nothing about it.
    #[test]
    fn first_come_first_served_is_the_same_with_interleaving() {
        for interleaving in [false, true] {
            let mut queue = scheduled(StreamScheduler::FirstComeFirstServed, interleaving);
            figure_queues(&mut queue);
            assert_eq!(
                vec![0, 0, 0, 1, 1, 1, 2, 2, 2],
                streams_in_order(&mut queue),
                "interleaving: {interleaving}"
            );
        }
    }

    /// RFC 8260 3.3: round robin per packet changes stream only when a packet is full, so
    /// a packet holds chunks of one stream.
    #[test]
    fn round_robin_per_packet_fills_a_packet_from_one_stream() {
        // Room for three chunks of 100 bytes (116 on the wire each).
        let budget = 3 * 116 + 50;
        let mut queue = scheduled(StreamScheduler::RoundRobinPerPacket, false);
        queue.set_packet_budget(budget);
        for id in 0..6 {
            queue.push_message(message(1, id, &[100]));
            queue.push_message(message(2, 10 + id, &[100]));
        }
        assert_eq!(
            vec![1, 1, 1, 2, 2, 2, 1, 1, 1, 2, 2, 2],
            streams_in_order(&mut queue)
        );

        // With interleaving a message larger than a packet gives the next packet away.
        let mut queue = scheduled(StreamScheduler::RoundRobinPerPacket, true);
        queue.set_packet_budget(budget);
        queue.push_message(message(1, 0, &[100; 6]));
        for id in 1..=3 {
            queue.push_message(message(2, id, &[100]));
        }
        assert_eq!(
            vec![1, 1, 1, 2, 2, 2, 1, 1, 1],
            streams_in_order(&mut queue)
        );

        // Without it the message is finished first: its fragments need consecutive TSNs.
        let mut queue = scheduled(StreamScheduler::RoundRobinPerPacket, false);
        queue.set_packet_budget(budget);
        queue.push_message(message(1, 0, &[100; 6]));
        for id in 1..=3 {
            queue.push_message(message(2, id, &[100]));
        }
        assert_eq!(
            vec![1, 1, 1, 1, 1, 1, 2, 2, 2],
            streams_in_order(&mut queue)
        );

        // A packet that is closed half full (the window stopped the sender) ends the turn.
        let mut queue = scheduled(StreamScheduler::RoundRobinPerPacket, false);
        queue.set_packet_budget(budget);
        for id in 0..4 {
            queue.push_message(message(1, id, &[100]));
            queue.push_message(message(2, 10 + id, &[100]));
        }
        assert_eq!(1, pop_next(&mut queue).unwrap().stream_identifier);
        queue.start_packet();
        assert_eq!(vec![2, 2, 2, 1, 1, 1, 2], streams_in_order(&mut queue));
    }

    /// RFC 8260 3.4: the stream with the higher priority is scheduled first; streams of the
    /// same priority take turns. With interleaving a large message of lower priority does
    /// not delay a message of higher priority; without, only the message already begun does.
    #[test]
    fn the_priority_scheduler_serves_the_highest_priority_first() {
        let mut queue = scheduled(StreamScheduler::Priority, false);
        queue.set_weight(1, 128);
        queue.set_weight(2, 512);
        queue.set_weight(3, 512);
        for id in 0..3 {
            queue.push_message(message(1, id, &[100]));
            queue.push_message(message(2, 10 + id, &[100]));
            queue.push_message(message(3, 20 + id, &[100]));
        }
        assert_eq!(
            vec![2, 3, 2, 3, 2, 3, 1, 1, 1],
            streams_in_order(&mut queue)
        );

        for (interleaving, expected) in [
            (true, vec![1, 1, 2, 2, 1, 1, 1, 1]),
            (false, vec![1, 1, 1, 1, 1, 1, 2, 2]),
        ] {
            let mut queue = scheduled(StreamScheduler::Priority, interleaving);
            queue.set_weight(1, 128);
            queue.set_weight(2, 1024);
            queue.push_message(message(1, 0, &[100; 6]));
            let mut order = vec![
                pop_next(&mut queue).unwrap().stream_identifier,
                pop_next(&mut queue).unwrap().stream_identifier,
            ];
            queue.push_message(message(2, 1, &[100; 2]));
            order.extend(streams_in_order(&mut queue));
            assert_eq!(expected, order, "interleaving: {interleaving}");
        }

        // A priority set while the stream waits applies to what it has queued.
        let mut queue = scheduled(StreamScheduler::Priority, false);
        queue.push_message(message(1, 0, &[100]));
        queue.push_message(message(2, 1, &[100]));
        queue.set_weight(2, 1024);
        assert_eq!(vec![2, 1], streams_in_order(&mut queue));
    }

    /// RFC 8260 3.5: fair capacity gives the streams equal shares of the bytes, whatever
    /// the sizes of their messages and whatever their priorities.
    #[test]
    fn fair_capacity_gives_every_stream_the_same_bytes() {
        for interleaving in [false, true] {
            let mut queue = scheduled(StreamScheduler::FairCapacity, interleaving);
            queue.set_weight(1, 1024);
            for id in 0..40 {
                queue.push_message(message(1, id, &[500, 500]));
            }
            for id in 0..400 {
                queue.push_message(message(2, 1000 + id, &[100]));
            }
            let mut sent = [0usize; 3];
            while sent[1] < 30_000 {
                let c = pop_next(&mut queue).unwrap();
                sent[c.stream_identifier as usize] += c.user_data.len();
                assert!(
                    sent[1].abs_diff(sent[2]) <= 1000,
                    "interleaving {interleaving}: {sent:?}"
                );
            }
        }
    }

    /// RFC 8260 3.6 with interleaving: the weights share the capacity chunk by chunk, so the
    /// small messages of one stream pass through the middle of a large message of another.
    #[test]
    fn weighted_fair_queueing_interleaves_small_messages_with_a_large_one() {
        let mut queue = scheduled(StreamScheduler::WeightedFairQueueing, true);
        queue.push_message(message(1, 0, &[1000; 64]));
        for _ in 0..4 {
            assert_eq!(1, pop_next(&mut queue).unwrap().stream_identifier);
        }
        for id in 1..=10 {
            queue.push_message(message(2, id, &[100]));
        }
        let order = streams_in_order(&mut queue);
        let last_small = order.iter().rposition(|s| *s == 2).unwrap();
        let large_chunks_before = order[..last_small].iter().filter(|s| **s == 1).count();
        assert!(
            large_chunks_before <= 2,
            "{large_chunks_before} chunks of the large message went before the small ones"
        );
        assert_eq!(60, order.iter().filter(|s| **s == 1).count());

        // And in proportion to the weights: 512 against 256 is two bytes for one.
        let mut queue = scheduled(StreamScheduler::WeightedFairQueueing, true);
        queue.set_weight(1, 512);
        queue.set_weight(2, 256);
        queue.push_message(message(1, 0, &[1000; 300]));
        queue.push_message(message(2, 1, &[1000; 300]));
        let mut sent = [0usize; 3];
        for _ in 0..300 {
            let c = pop_next(&mut queue).unwrap();
            sent[c.stream_identifier as usize] += c.user_data.len();
        }
        assert!(sent[1].abs_diff(2 * sent[2]) <= 2000, "{sent:?}");
    }

    /// A stream sends one message at a time under every scheduler, with interleaving too
    /// (RFC 8260 2.2.2), and a reset waits for its own stream only.
    #[test]
    fn every_scheduler_keeps_a_streams_messages_whole_and_in_order() {
        for scheduler in [
            StreamScheduler::FirstComeFirstServed,
            StreamScheduler::RoundRobin,
            StreamScheduler::RoundRobinPerPacket,
            StreamScheduler::Priority,
            StreamScheduler::FairCapacity,
            StreamScheduler::WeightedFairQueueing,
        ] {
            for interleaving in [false, true] {
                let mut queue = scheduled(scheduler, interleaving);
                queue.set_packet_budget(400);
                let mut id = 0;
                for round in 0..5usize {
                    for stream in 1..=4u16 {
                        let pieces = vec![50 * stream as usize; 1 + (round + stream as usize) % 4];
                        queue.push_message(message(stream, id, &pieces));
                        id += 1;
                    }
                }
                queue.push_reset(ResetMarker::new(3));
                let (bytes, len) = (queue.get_num_bytes(), queue.len());

                let mut last: FxHashMap<u16, (MessageId, bool)> = FxHashMap::default();
                let (mut popped_bytes, mut popped, mut reset_seen) = (0, 0, false);
                loop {
                    if let Some(reset) = queue.pop_ready_reset() {
                        assert_eq!(3, reset.stream_identifier);
                        assert!(
                            !queue.streams.contains_key(&3),
                            "{scheduler:?}: the reset left before its stream's messages"
                        );
                        reset_seen = true;
                        popped += 1;
                        continue;
                    }
                    let Some(c) = pop_next(&mut queue) else {
                        break;
                    };
                    let message_id = c.message_id.unwrap();
                    if let Some((previous, ended)) = last.get(&c.stream_identifier) {
                        if *ended {
                            assert!(c.beginning_fragment && message_id != *previous);
                        } else {
                            assert!(
                                !c.beginning_fragment && message_id == *previous,
                                "{scheduler:?}: two messages of a stream in process"
                            );
                        }
                    } else {
                        assert!(c.beginning_fragment);
                    }
                    if !interleaving && !c.ending_fragment {
                        let next = queue.peek().unwrap();
                        assert_eq!(
                            Some(message_id),
                            next.message_id,
                            "{scheduler:?}: another message between the fragments"
                        );
                    }
                    last.insert(c.stream_identifier, (message_id, c.ending_fragment));
                    popped_bytes += c.user_data.len();
                    popped += 1;
                }
                assert!(reset_seen, "{scheduler:?}");
                assert_eq!((bytes, len), (popped_bytes, popped), "{scheduler:?}");
                assert!(queue.is_empty() && queue.streams.is_empty());
                assert!(queue.heads.is_empty() && queue.resets.is_empty());
                assert!(!queue.is_mid_message());
            }
        }
    }
}
