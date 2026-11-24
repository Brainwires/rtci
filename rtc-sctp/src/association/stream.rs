use crate::association::Association;
use crate::association::state::AssociationState;
use crate::chunk::chunk_payload_data::{
    ChunkPayloadData, MessageReliability, PayloadProtocolIdentifier,
};
use crate::queue::reassembly_queue::{Chunks, MessagePart, ReassemblyQueue};
use crate::{ErrorCauseCode, Event, Side};
use shared::error::{Error, Result};

use crate::util::{ByteSlice, BytesArray, BytesChunk, BytesSource};
use bytes::Bytes;
use log::{debug, error, trace};
use std::fmt;
use std::time::{Duration, Instant};

/// Identifier for a stream within a particular association
pub type StreamId = u16;

/// Application events about streams
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamEvent {
    /// One or more new streams has been opened
    Opened {
        /// Which stream was opened.
        id: StreamId,
    },
    /// A currently open stream has data or errors waiting to be read
    Readable {
        /// Which stream is now readable
        id: StreamId,
    },
    /// A formerly write-blocked stream might be ready for a write or have been stopped
    ///
    /// Only generated for streams that are currently open.
    Writable {
        /// Which stream is now writable
        id: StreamId,
    },
    /// A finished stream has been fully acknowledged or stopped
    Finished {
        /// Which stream has been finished
        id: StreamId,
    },
    /// The peer asked us to stop sending on an outgoing stream
    Stopped {
        /// Which stream has been stopped
        id: StreamId,
        /// Error code supplied by the peer
        error_code: ErrorCauseCode,
    },
    /// At least one new stream of a certain directionality may be opened
    Available,
    /// The number of bytes of outgoing data buffered is lower than the threshold.
    BufferedAmountLow {
        /// Which stream is now readable
        id: StreamId,
    },
    /// The number of bytes of outgoing data buffered is higher than the threshold.
    BufferedAmountHigh {
        /// Which stream is now readable
        id: StreamId,
    },
    /// Outgoing buffered data was released (acknowledged OR abandoned), carrying
    /// the exact number of user payload bytes freed for this stream. Unlike the
    /// edge-triggered [`StreamEvent::BufferedAmountLow`], this fires on every
    /// release with the byte delta, so upper layers can keep their own
    /// send-buffer accounting (e.g. a synchronous back-pressure counter) exact.
    BufferedAmountReleased {
        /// Which stream released buffered bytes
        id: StreamId,
        /// User payload bytes released
        n_bytes: usize,
    },
    /// A message of a partially reliable stream was abandoned (RFC 3758 section 3.5, 4.1):
    /// its lifetime or its number of retransmissions ran out, and the peer will not get it.
    MessageAbandoned {
        /// The stream the message was written to
        id: StreamId,
        /// Whether any of it had been sent. A message that expired before its first
        /// transmission (RFC 3758 4.1 TR3) took no TSN and no stream sequence number.
        transmitted: bool,
    },
    /// The message of this stream that was being read in parts ([`Stream::read_part`]) will
    /// not be completed: the sender abandoned it (a FORWARD TSN or I-FORWARD-TSN skipped the
    /// rest of it, RFC 3758 section 3.6, RFC 8260 section 2.3.1) or the stream's sequence
    /// numbers were reset (RFC 6525). No part with `end_of_record` follows; the parts already
    /// read are all there is of it. RFC 6458 section 6.1.7, `SCTP_PARTIAL_DELIVERY_ABORTED`.
    PartialDeliveryAborted {
        /// The stream the message was on
        id: StreamId,
        /// Whether it was an unordered message
        unordered: bool,
        /// Its Stream Sequence Number (DATA) or Message Identifier (I-DATA, RFC 8260)
        sequence: u32,
    },
}

/// Reliability type for stream
#[derive(Default, Debug, Copy, Clone, PartialEq)]
#[non_exhaustive]
pub enum ReliabilityType {
    /// ReliabilityTypeReliable is used for reliable transmission
    #[default]
    Reliable = 0,
    /// ReliabilityTypeRexmit is used for partial reliability by retransmission count
    Rexmit = 1,
    /// ReliabilityTypeTimed is used for partial reliability by retransmission duration
    Timed = 2,
}

impl fmt::Display for ReliabilityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            ReliabilityType::Reliable => "Reliable",
            ReliabilityType::Rexmit => "Rexmit",
            ReliabilityType::Timed => "Timed",
        };
        write!(f, "{}", s)
    }
}

impl From<u8> for ReliabilityType {
    fn from(v: u8) -> ReliabilityType {
        match v {
            1 => ReliabilityType::Rexmit,
            2 => ReliabilityType::Timed,
            _ => ReliabilityType::Reliable,
        }
    }
}

/// Stream represents an SCTP stream
pub struct Stream<'a> {
    pub(crate) stream_identifier: StreamId,
    pub(crate) association: &'a mut Association,
}

impl Stream<'_> {
    /// read reads a packet of len(p) bytes, dropping the Payload Protocol Identifier.
    /// Returns EOF when the stream is reset or an error if the stream is closed
    /// otherwise.
    pub fn read(&mut self) -> Result<Option<Chunks>> {
        self.read_sctp()
    }

    /// read_sctp reads a packet of len(p) bytes and returns the associated Payload
    /// Protocol Identifier.
    /// Returns EOF when the stream is reset or an error if the stream is closed
    /// otherwise.
    pub fn read_sctp(&mut self) -> Result<Option<Chunks>> {
        if let Some(s) = self.association.streams.get_mut(&self.stream_identifier)
            && (s.state == RecvSendState::ReadWritable || s.state == RecvSendState::Readable)
        {
            let bytes_before = s.get_num_bytes_in_reassembly_queue();
            let chunks = s.reassembly_queue.read();
            let drained = !s.reassembly_queue.is_readable();
            self.association
                .reindex_stream(self.stream_identifier, bytes_before);
            if chunks.is_some() {
                self.association.on_receive_buffer_drained();
                // What is left may be all incomplete, with the window still closed.
                self.association.offer_partial_delivery();
            }
            if drained {
                self.association
                    .retry_deferred_resets(self.stream_identifier);
            }
            Ok(chunks)
        } else {
            Err(Error::ErrStreamClosed)
        }
    }

    /// Reads the next part of a message: the partial delivery API of RFC 9260 section 6.9
    /// (the RECEIVE primitive with its "partial flag", 11.1.7; RFC 6458 `MSG_EOR`).
    ///
    /// A complete message comes whole, as one part with
    /// [`end_of_record`](MessagePart::end_of_record) set, just as [`read_sctp`](Self::read_sctp)
    /// gives it. A message that has not all arrived is given out in parts once the fragments
    /// of it held from the first on come to the partial delivery point
    /// ([`TransportConfig::with_partial_delivery_point`](crate::TransportConfig::with_partial_delivery_point)),
    /// or whatever their size when the receive buffer is out of space (a window that would be
    /// advertised as closed, with nothing readable whole). Its first part has
    /// [`first`](MessagePart::first) set, and its last `end_of_record`; until then nothing else
    /// of this stream is read, by either method. What is read leaves the receive buffer at
    /// once, and a window that was closed is announced open again (RFC 9260 6.2).
    ///
    /// Without this, a message larger than the receive buffer, or interleaved messages
    /// (RFC 8260) that fill it together, cannot arrive under the rule of RFC 9260 section 6.2
    /// ("When the receiver's advertised window is 0, the receiver MUST drop any new incoming
    /// DATA chunk with a TSN larger than the largest TSN received so far").
    ///
    /// Returns `Ok(None)` when the stream has nothing to read in this way, and an error if the
    /// stream is closed.
    pub fn read_part(&mut self) -> Result<Option<MessagePart>> {
        let threshold = self.association.partial_delivery_threshold();
        if let Some(s) = self.association.streams.get_mut(&self.stream_identifier)
            && (s.state == RecvSendState::ReadWritable || s.state == RecvSendState::Readable)
        {
            let bytes_before = s.get_num_bytes_in_reassembly_queue();
            let part = s.reassembly_queue.read_part(threshold);
            let drained = !s.reassembly_queue.holds_whole_message();
            self.association
                .reindex_stream(self.stream_identifier, bytes_before);
            if part.is_some() {
                self.association.on_receive_buffer_drained();
                self.association.offer_partial_delivery();
            }
            if drained {
                self.association
                    .retry_deferred_resets(self.stream_identifier);
            }
            Ok(part)
        } else {
            Err(Error::ErrStreamClosed)
        }
    }

    /// Whether a message of this stream is being read in parts: its first part was read
    /// with [`read_part`](Self::read_part) and its last not yet.
    pub fn in_partial_delivery(&self) -> bool {
        self.association
            .streams
            .get(&self.stream_identifier)
            .is_some_and(|s| s.reassembly_queue.in_partial_delivery())
    }

    /// write_sctp writes len(p) bytes from p to the DTLS connection
    ///
    /// `now` is the instant the message is handed to the stack. See the note on
    /// [`Stream`] for why it is a parameter.
    pub fn write_sctp(
        &mut self,
        now: Instant,
        p: &Bytes,
        ppi: PayloadProtocolIdentifier,
    ) -> Result<usize> {
        self.write_source(now, &mut BytesChunk::new(p), ppi, ppi.number())
    }

    /// Sends a message with any Payload Protocol Identifier (RFC 9260 section 3.3.1: the
    /// value is the application's and SCTP passes it through unchanged). The receiver reads
    /// it from [`Chunks::ppid`].
    ///
    /// [`PayloadProtocolIdentifier`] names only the WebRTC values; this takes the number.
    pub fn write_sctp_with_ppid(&mut self, now: Instant, p: &Bytes, ppid: u32) -> Result<usize> {
        self.write_source(now, &mut BytesChunk::new(p), ppid.into(), ppid)
    }

    /// Send data on the given stream.
    ///
    /// Uses the deafult payload protocol (PPI).
    ///
    /// Returns the number of bytes successfully written.
    pub fn write(&mut self, now: Instant, data: &[u8]) -> Result<usize> {
        self.write_with_ppi(now, data, self.get_default_payload_type()?)
    }

    /// Send data on the given stream, with a specific payload protocol.
    ///
    /// Returns the number of bytes successfully written.
    pub fn write_with_ppi(
        &mut self,
        now: Instant,
        data: &[u8],
        ppi: PayloadProtocolIdentifier,
    ) -> Result<usize> {
        self.write_source(now, &mut ByteSlice::from_slice(data), ppi, ppi.number())
    }

    /// write writes len(p) bytes from p with the default Payload Protocol Identifier
    pub fn write_chunk(&mut self, now: Instant, p: &Bytes) -> Result<usize> {
        let ppi = self.get_default_payload_type()?;
        self.write_source(now, &mut BytesChunk::new(p), ppi, ppi.number())
    }

    /// Send an owned [`Bytes`] on the stream with a specific payload protocol.
    ///
    /// Unlike [`write_with_ppi`](Self::write_with_ppi), which takes a `&[u8]` and
    /// must copy it into a freshly allocated buffer, this enqueues the payload
    /// zero-copy: each fragment is a refcounted slice of `data`. Prefer this on the
    /// hot send path when the caller already owns the payload as `Bytes`.
    ///
    /// Returns the number of bytes successfully written.
    pub fn write_chunk_with_ppi(
        &mut self,
        now: Instant,
        data: &Bytes,
        ppi: PayloadProtocolIdentifier,
    ) -> Result<usize> {
        self.write_source(now, &mut BytesChunk::new(data), ppi, ppi.number())
    }

    /// Send data on the given stream
    ///
    /// Returns the number of bytes and chunks successfully written.
    /// Note that this method might also write a partial chunk. In this case
    /// it will not count this chunk as fully written. However
    /// the chunk will be advanced and contain only non-written data after the call.
    pub fn write_chunks(&mut self, now: Instant, data: &mut [Bytes]) -> Result<usize> {
        let ppi = self.get_default_payload_type()?;
        self.write_source(now, &mut BytesArray::from_chunks(data), ppi, ppi.number())
    }

    /// write_source writes BytesSource to the DTLS connection
    fn write_source<B: BytesSource>(
        &mut self,
        now: Instant,
        source: &mut B,
        ppi: PayloadProtocolIdentifier,
        ppid: u32,
    ) -> Result<usize> {
        if !self.is_writable() {
            return Err(Error::ErrStreamClosed);
        }

        // RFC 9260 3.3.1: a DATA chunk carries at least one byte of user data, so there is no
        // empty user message. Refused before anything is consumed: an empty write used to
        // take a Stream Sequence Number and send nothing, and the receiver waited for that
        // number for ever.
        if source.remaining() == 0 {
            return Err(Error::OtherSctpErr(
                "an empty user message cannot be sent (RFC 9260 3.3.1)".into(),
            ));
        }

        if source.remaining() > self.association.max_message_size() as usize {
            return Err(Error::ErrOutboundPacketTooLarge);
        }

        let state: AssociationState = self.association.state();
        match state {
            AssociationState::ShutdownSent
            | AssociationState::ShutdownAckSent
            | AssociationState::ShutdownPending
            | AssociationState::ShutdownReceived => return Err(Error::ErrStreamClosed),
            _ => {}
        };

        let id = self.association.allocate_message_id()?;
        let fragment_size = self.association.fragment_size() as usize;
        let i_data = self.association.message_interleaving();
        let (p, _) = source.pop_chunk(self.association.max_message_size() as usize);

        if let Some(s) = self.association.streams.get_mut(&self.stream_identifier) {
            let (is_buffered_amount_high, mut chunks) =
                s.packetize(now, &p, ppi, ppid, fragment_size, i_data);
            // RFC 6525 5.1.2 A1: while a reset of this outgoing stream is not answered, new
            // data gets no Stream Sequence Number and is queued. It goes out when the answer
            // is in: numbered from 0 if the peer performed the reset, and on from where the
            // stream was if it did not.
            let held = s.outgoing_reset_pending;
            if held {
                for c in &mut chunks {
                    c.message_id = Some(id);
                }
                s.held_writes.push(chunks);
                chunks = vec![];
            }

            if is_buffered_amount_high {
                trace!("StreamEvent::BufferedAmountHigh");
                self.association
                    .events
                    .push_back(Event::Stream(StreamEvent::BufferedAmountHigh {
                        id: self.stream_identifier,
                    }))
            }

            if held {
                self.association.held_write_count += 1;
            } else {
                self.association.send_payload_data(id, chunks);
            }

            Ok(p.len())
        } else {
            Err(Error::ErrStreamClosed)
        }
    }

    /// Whether this stream has data or an error waiting to be read.
    pub fn is_readable(&self) -> bool {
        if let Some(s) = self.association.streams.get(&self.stream_identifier) {
            s.state == RecvSendState::Readable || s.state == RecvSendState::ReadWritable
        } else {
            false
        }
    }

    /// Whether this stream can currently accept more data.
    pub fn is_writable(&self) -> bool {
        if let Some(s) = self.association.streams.get(&self.stream_identifier) {
            s.state == RecvSendState::Writable || s.state == RecvSendState::ReadWritable
        } else {
            false
        }
    }

    /// stop closes the read-direction of the stream.
    /// Future calls to read are not permitted after calling stop.
    ///
    /// `now` is the instant the caller is acting at: resetting the stream queues an outgoing
    /// chunk, so it is on the same write path as [`write_sctp`](Self::write_sctp).
    pub fn stop(&mut self, now: Instant) -> Result<()> {
        let mut reset = false;
        if let Some(s) = self.association.streams.get_mut(&self.stream_identifier) {
            if s.state == RecvSendState::Readable || s.state == RecvSendState::ReadWritable {
                reset = true;
            }
            s.state = ((s.state as u8) & 0x2).into();
        }

        if reset {
            // Reset the outgoing stream
            // https://tools.ietf.org/html/rfc6525
            self.association
                .send_reset_request(now, self.stream_identifier)?;
        }

        Ok(())
    }

    /// finish closes the write-direction of the stream.
    /// Future calls to write are not permitted after calling Close.
    pub fn finish(&mut self) -> Result<()> {
        if let Some(s) = self.association.streams.get_mut(&self.stream_identifier) {
            s.state = ((s.state as u8) & 0x1).into();
        }
        Ok(())
    }

    /// Shuts down the read, write, or both halves of this stream.
    ///
    /// This function will cause all pending and future I/O on the specified portions to return
    /// immediately with an appropriate value (see the documentation of `Shutdown`).
    ///
    /// Resets the stream when both halves of this stream are shutdown.
    pub fn close(&mut self, now: Instant) -> Result<()> {
        self.finish()?;
        self.stop(now)
    }

    /// stream_identifier returns the Stream identifier associated to the stream.
    pub fn stream_identifier(&self) -> StreamId {
        self.stream_identifier
    }

    /// Sets this stream's priority, in data channel priority units (RFC 8832 section 5.1:
    /// 128 below normal, 256 normal, 512 high, 1024 extra high; any value is taken). The
    /// default is 256.
    ///
    /// It is the input of two [stream schedulers](crate::StreamScheduler): under
    /// `WeightedFairQueueing` it is the stream's weight (a stream with n times the priority
    /// gets n times the capacity, RFC 8260 section 3.6), under `Priority` its rank (the
    /// higher value is served first, section 3.4). The other schedulers do not look at it.
    /// It applies from the next scheduling decision on, to what the stream has queued too,
    /// and lasts until the stream is reset.
    ///
    /// RFC 8831 section 6.4 has a data channel's priority drive the scheduler: the data
    /// channel layer calls this with the priority of the channel (from `RTCDataChannelInit`
    /// or the DATA_CHANNEL_OPEN message) when it opens or accepts the stream.
    pub fn set_priority(&mut self, priority: u16) -> Result<()> {
        if !self
            .association
            .streams
            .contains_key(&self.stream_identifier)
        {
            return Err(Error::ErrStreamClosed);
        }
        self.association
            .pending_queue
            .set_weight(self.stream_identifier, priority);
        Ok(())
    }

    /// set_default_payload_type sets the default payload type used by write.
    pub fn set_default_payload_type(
        &mut self,
        default_payload_type: PayloadProtocolIdentifier,
    ) -> Result<()> {
        if let Some(s) = self.association.streams.get_mut(&self.stream_identifier) {
            s.default_payload_type = default_payload_type;
            Ok(())
        } else {
            Err(Error::ErrStreamClosed)
        }
    }

    /// get_default_payload_type returns the payload type associated to the stream.
    pub fn get_default_payload_type(&self) -> Result<PayloadProtocolIdentifier> {
        if let Some(s) = self.association.streams.get(&self.stream_identifier) {
            Ok(s.default_payload_type)
        } else {
            Err(Error::ErrStreamClosed)
        }
    }

    /// set_reliability_params sets reliability parameters for this stream.
    pub fn set_reliability_params(
        &mut self,
        unordered: bool,
        rel_type: ReliabilityType,
        rel_val: u32,
    ) -> Result<()> {
        if let Some(s) = self.association.streams.get_mut(&self.stream_identifier) {
            debug!(
                "[{}] reliability params: ordered={} type={} value={}",
                s.side, !unordered, rel_type, rel_val
            );
            s.unordered = unordered;
            s.reliability_type = rel_type;
            s.reliability_value = rel_val;
            Ok(())
        } else {
            Err(Error::ErrStreamClosed)
        }
    }

    /// Application bytes of this stream that have left the send queue (transmitted, or
    /// abandoned before their first transmission): W3C `bufferedAmount` decreases by what
    /// "the underlying data transport sends ... from its queue", not by what the peer
    /// acknowledges.
    pub fn bytes_dequeued(&self) -> Result<u64> {
        if let Some(s) = self.association.streams.get(&self.stream_identifier) {
            Ok(s.bytes_dequeued)
        } else {
            Err(Error::ErrStreamClosed)
        }
    }

    /// buffered_amount returns the number of bytes of data currently queued to be sent over this stream.
    pub fn buffered_amount(&self) -> Result<usize> {
        if let Some(s) = self.association.streams.get(&self.stream_identifier) {
            Ok(s.buffered_amount)
        } else {
            Err(Error::ErrStreamClosed)
        }
    }

    /// buffered_amount_low_threshold returns the number of bytes of buffered outgoing data that is
    /// considered "low" Defaults to 0.
    pub fn buffered_amount_low_threshold(&self) -> Result<usize> {
        if let Some(s) = self.association.streams.get(&self.stream_identifier) {
            Ok(s.buffered_amount_low)
        } else {
            Err(Error::ErrStreamClosed)
        }
    }

    /// set_buffered_amount_low_threshold is used to update the threshold.
    /// See buffered_amount_low_threshold().
    pub fn set_buffered_amount_low_threshold(&mut self, th: usize) -> Result<()> {
        if let Some(s) = self.association.streams.get_mut(&self.stream_identifier) {
            s.buffered_amount_low = th;
            Ok(())
        } else {
            Err(Error::ErrStreamClosed)
        }
    }

    /// buffered_amount_high_threshold returns the number of bytes of buffered outgoing data that is
    /// considered "high" Defaults to u32::MAX.
    pub fn buffered_amount_high_threshold(&self) -> Result<usize> {
        if let Some(s) = self.association.streams.get(&self.stream_identifier) {
            Ok(s.buffered_amount_high)
        } else {
            Err(Error::ErrStreamClosed)
        }
    }

    /// set_buffered_amount_high_threshold is used to update the threshold.
    /// See buffered_amount_high_threshold().
    pub fn set_buffered_amount_high_threshold(&mut self, th: usize) -> Result<()> {
        if let Some(s) = self.association.streams.get_mut(&self.stream_identifier) {
            s.buffered_amount_high = th;
            Ok(())
        } else {
            Err(Error::ErrStreamClosed)
        }
    }
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum RecvSendState {
    #[default]
    Closed = 0,
    Readable = 1,
    Writable = 2,
    ReadWritable = 3,
}

impl From<u8> for RecvSendState {
    fn from(v: u8) -> Self {
        match v {
            1 => RecvSendState::Readable,
            2 => RecvSendState::Writable,
            3 => RecvSendState::ReadWritable,
            _ => RecvSendState::Closed,
        }
    }
}

/// StreamState represents the state of an SCTP stream
#[derive(Default, Debug)]
pub struct StreamState {
    pub(crate) side: Side,
    pub(crate) max_payload_size: u32,
    pub(crate) stream_identifier: StreamId,
    pub(crate) generation: u64,
    pub(crate) default_payload_type: PayloadProtocolIdentifier,
    pub(crate) reassembly_queue: ReassemblyQueue,
    pub(crate) sequence_number: u16,
    pub(crate) state: RecvSendState,
    pub(crate) unordered: bool,
    pub(crate) reliability_type: ReliabilityType,
    pub(crate) reliability_value: u32,
    pub(crate) buffered_amount: usize,
    /// Application bytes that have left the send queue: transmitted for the first time, or
    /// abandoned before that. DCEP messages and the placeholder byte of an empty message
    /// are not counted.
    pub(crate) bytes_dequeued: u64,
    pub(crate) buffered_amount_low: usize,
    pub(crate) buffered_amount_high: usize,
    /// A reset of this outgoing stream was asked for and is not answered yet (RFC 6525
    /// 5.1.2 A1).
    pub(crate) outgoing_reset_pending: bool,
    /// The messages written while the reset is pending, each as its fragments, without a
    /// Stream Sequence Number.
    pub(crate) held_writes: Vec<Vec<ChunkPayloadData>>,
    /// The Message Identifiers of the next ordered and the next unordered message (RFC 8260
    /// 2.1: two counters for each outgoing stream, both starting at 0).
    pub(crate) ordered_mid: u32,
    pub(crate) unordered_mid: u32,
}
impl StreamState {
    pub(crate) fn new(
        side: Side,
        stream_identifier: StreamId,
        max_payload_size: u32,
        default_payload_type: PayloadProtocolIdentifier,
    ) -> Self {
        StreamState {
            side,
            stream_identifier,
            generation: 0,
            max_payload_size,
            default_payload_type,
            reassembly_queue: ReassemblyQueue::new(stream_identifier),
            sequence_number: 0,
            state: RecvSendState::ReadWritable,
            unordered: false,
            reliability_type: ReliabilityType::Reliable,
            reliability_value: 0,
            buffered_amount: 0,
            bytes_dequeued: 0,
            buffered_amount_low: 0,
            buffered_amount_high: u32::MAX as usize,
            outgoing_reset_pending: false,
            held_writes: vec![],
            ordered_mid: 0,
            unordered_mid: 0,
        }
    }

    /// The numbers of the next message of this stream: its Stream Sequence Number (the
    /// stream's current one for an unordered message, which does not use it up) and its
    /// Message Identifier.
    pub(crate) fn next_message_numbers(&mut self, unordered: bool) -> (u16, u32) {
        if unordered {
            let mid = self.unordered_mid;
            self.unordered_mid = self.unordered_mid.wrapping_add(1);
            (self.sequence_number, mid)
        } else {
            let (ssn, mid) = (self.sequence_number, self.ordered_mid);
            // RFC 9260 6.6: the Stream Sequence Number is not incremented for a message
            // with the U flag.
            self.sequence_number = self.sequence_number.wrapping_add(1);
            self.ordered_mid = self.ordered_mid.wrapping_add(1);
            (ssn, mid)
        }
    }

    /// The stream's outgoing direction was reset: its numbers start over (RFC 6525 5.2.7
    /// H4; RFC 8260 2.3.2 for the two Message Identifier counters).
    pub(crate) fn reset_outgoing_numbers(&mut self) {
        self.sequence_number = 0;
        self.ordered_mid = 0;
        self.unordered_mid = 0;
    }

    pub(crate) fn handle_data(&mut self, pd: &ChunkPayloadData) -> bool {
        self.reassembly_queue.push(pd.clone())
    }

    /// Queues a received DATA chunk for reassembly. `cumulative_tsn` is the receiver's
    /// cumulative TSN before it, which tells a fragment that can never be part of a complete
    /// message (`ReassemblyQueue::discard_orphans`).
    pub(crate) fn handle_received(&mut self, pd: &ChunkPayloadData, cumulative_tsn: u32) -> bool {
        self.reassembly_queue
            .push_received(pd.clone(), Some(cumulative_tsn))
    }

    /// RFC 3758 3.6: what the peer's FORWARD TSN says is applied whatever this side's own
    /// setting for the stream: `unordered` is how this side sends, not how the peer does.
    pub(crate) fn handle_forward_tsn_for_ordered(&mut self, ssn: u16) {
        // Remove all chunks older than or equal to the new TSN from
        // the reassembly_queue.
        self.reassembly_queue.forward_tsn_for_ordered(ssn);
    }

    pub(crate) fn handle_forward_tsn_for_unordered(&mut self, new_cumulative_tsn: u32) {
        // Remove all chunks older than or equal to the new TSN from
        // the reassembly_queue.
        self.reassembly_queue
            .forward_tsn_for_unordered(new_cumulative_tsn);
    }

    fn packetize(
        &mut self,
        now: Instant,
        raw: &Bytes,
        ppi: PayloadProtocolIdentifier,
        ppid: u32,
        fragment_size: usize,
        i_data: bool,
    ) -> (bool, Vec<ChunkPayloadData>) {
        let mut i = 0;
        let mut remaining = raw.len();
        let fragment_size = fragment_size.clamp(1, self.max_payload_size.max(1) as usize);

        // From draft-ietf-rtcweb-data-protocol-09, section 6:
        //   All Data Channel Establishment Protocol messages MUST be sent using
        //   ordered delivery and reliable transmission.
        let unordered = ppi != PayloadProtocolIdentifier::Dcep && self.unordered;
        let reliability = if ppi == PayloadProtocolIdentifier::Dcep {
            MessageReliability::Reliable
        } else {
            match self.reliability_type {
                ReliabilityType::Reliable => MessageReliability::Reliable,
                ReliabilityType::Rexmit => MessageReliability::Rexmit {
                    max_retransmits: self.reliability_value,
                },
                ReliabilityType::Timed => MessageReliability::Timed {
                    deadline: now + Duration::from_millis(self.reliability_value as u64),
                },
            }
        };

        let mut chunks = vec![];
        // The message takes its Stream Sequence Number and Message Identifier when its first
        // fragment leaves the pending queue (`Association::number_next_message`): one that is
        // abandoned before that uses up neither (RFC 3758 4.1 TR3), and one written while a
        // reset of the stream is pending is numbered after the reset (RFC 6525 5.1.2 A1).
        let (ssn, mid) = (0, 0);
        let mut fsn = 0u32;

        while remaining != 0 {
            let fragment_size = std::cmp::min(fragment_size, remaining);

            // Copy the userdata since we'll have to store it until acked
            // and the caller may re-use the buffer in the mean time
            let user_data = raw.slice(i..i + fragment_size);

            let chunk = ChunkPayloadData {
                // Timed reliability measures a message's age from here, so that
                // a long wait for cwnd or rwnd counts against maxPacketLifeTime.
                created_at: Some(now),
                reliability,
                stream_generation: self.generation,
                stream_identifier: self.stream_identifier,
                user_data,
                unordered,
                beginning_fragment: i == 0,
                ending_fragment: remaining - fragment_size == 0,
                immediate_sack: false,
                payload_type: ppi,
                payload_protocol_id: ppid,
                stream_sequence_number: ssn,
                i_data,
                mid,
                fsn,
                numbers_pending: true,
                ..Default::default()
            };

            chunks.push(chunk);
            fsn = fsn.wrapping_add(1);

            remaining -= fragment_size;
            i += fragment_size;
        }

        let old_amount = self.buffered_amount;
        let n_bytes_added = raw.len();
        self.buffered_amount += raw.len();
        let new_amount = self.buffered_amount;

        trace!(
            "[{}] new_amount = {}, old_amount = {}, buffered_amount_high = {}, n_bytes_added = {}",
            self.side, new_amount, old_amount, self.buffered_amount_high, n_bytes_added,
        );

        let is_buffered_amount_high =
            old_amount < self.buffered_amount_high && new_amount >= self.buffered_amount_high;

        (is_buffered_amount_high, chunks)
    }

    /// This method is called by association to notify this stream
    /// of the specified amount of outgoing data has been delivered to the peer.
    pub(crate) fn on_buffer_released(&mut self, n_bytes_released: i64) -> bool {
        if n_bytes_released <= 0 {
            return false;
        }

        let old_amount = self.buffered_amount;
        let new_amount = if old_amount < n_bytes_released as usize {
            self.buffered_amount = 0;
            error!(
                "[{}] released buffer size {} should be <= {}",
                self.side, n_bytes_released, 0,
            );
            0
        } else {
            self.buffered_amount -= n_bytes_released as usize;

            old_amount - n_bytes_released as usize
        };

        trace!(
            "[{}] new_amount = {}, old_amount = {}, buffered_amount_low = {}, n_bytes_released = {}",
            self.side, new_amount, old_amount, self.buffered_amount_low, n_bytes_released,
        );

        old_amount > self.buffered_amount_low && new_amount <= self.buffered_amount_low
    }

    pub(crate) fn get_num_bytes_in_reassembly_queue(&self) -> usize {
        // No lock is required as it reads the size with atomic load function.
        self.reassembly_queue.get_num_bytes()
    }
}

#[cfg(test)]
#[path = "stream_test.rs"]
mod stream_test;
