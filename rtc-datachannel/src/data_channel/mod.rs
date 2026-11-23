//! One data channel over an SCTP stream.
//!
//! A [`DataChannel`](crate::data_channel::DataChannel) is opened either by the DCEP handshake (`DATA_CHANNEL_OPEN`, then
//! `DATA_CHANNEL_ACK`) or out of band when [`DataChannelConfig::negotiated`](crate::data_channel::DataChannelConfig::negotiated) is set and both
//! sides already agreed the stream id through signalling.
//!
//! The reliability the channel is opened with maps onto SCTP send parameters:
//! [`get_reliability_params`](crate::data_channel::DataChannel::get_reliability_params) turns a
//! [`ChannelType`](crate::message::message_channel_open::ChannelType) into the ordered flag and
//! partial-reliability setting SCTP needs, and
//! [`get_channel_type_and_reliability_parameter`](crate::data_channel::DataChannel::get_channel_type_and_reliability_parameter)
//! goes the other way from the W3C `maxPacketLifeTime`/`maxRetransmits` pair.
#[cfg(test)]
mod data_channel_test;
#[cfg(test)]
mod sctp_link_test;

use crate::message::message_type::{MESSAGE_TYPE_CLOSE, MESSAGE_TYPE_THRESHOLD};
use crate::message::{
    message_channel_ack::*, message_channel_close::*, message_channel_open::*,
    message_channel_threshold::*, *,
};
use bytes::{Buf, BytesMut};
use log::debug;
use sctp::{PayloadProtocolIdentifier, ReliabilityType};
use shared::error::{Error, Result};
use shared::marshal::*;
use std::collections::VecDeque;

const RECEIVE_MTU: usize = 8192;

/// DataChannelConfig is used to configure the data channel.
#[derive(Eq, PartialEq, Default, Clone, Debug)]
pub struct DataChannelConfig {
    /// The reliability and ordering guarantees to request.
    pub channel_type: ChannelType,
    /// Whether the channel was negotiated out of band.
    ///
    /// When `true` no DCEP `DATA_CHANNEL_OPEN` is sent — both sides are assumed to have agreed
    /// the stream id and parameters through signalling instead.
    pub negotiated: bool,
    /// The channel's relative priority; see the `CHANNEL_PRIORITY_*` constants.
    pub priority: u16,
    /// The retransmission count or message lifetime, interpreted according to
    /// [`Self::channel_type`].
    pub reliability_parameter: u32,
    /// The channel label, used to distinguish channels on the same association.
    pub label: String,
    /// The subprotocol name, or empty if none.
    pub protocol: String,
}

/// DataChannelMessage is used for data sent over SCTP.
#[derive(Debug, Default, Clone)]
pub struct DataChannelMessage {
    /// Identifies the SCTP association this message belongs to.
    pub association_handle: usize,
    /// The SCTP stream the message arrived on or should be sent on.
    pub stream_id: u16,
    /// The payload protocol identifier, which distinguishes DCEP control messages from string
    /// and binary user data.
    pub ppi: PayloadProtocolIdentifier,
    /// The message bytes.
    pub payload: BytesMut,

    /// Marks a `DATA_CHANNEL_OPEN` that belongs to an out-of-band *negotiated*
    /// channel (W3C WebRTC `RTCDataChannelInit.negotiated`). Such a message is
    /// only used to open and configure the local SCTP stream and must not be
    /// transmitted to the peer, which already created its own channel with the
    /// pre-agreed stream id. Ignored for every other message.
    pub negotiated: bool,
}

impl DataChannelMessage {
    /// Creates a new `DataChannelMessage` with all fields specified.
    pub fn new(
        association_handle: usize,
        stream_id: u16,
        ppi: PayloadProtocolIdentifier,
        payload: BytesMut,
        negotiated: bool,
    ) -> Self {
        Self {
            association_handle,
            stream_id,
            ppi,
            payload,
            negotiated,
        }
    }
}

/// DataChannel represents a data channel
#[derive(Debug, Default, Clone)]
pub struct DataChannel {
    config: DataChannelConfig,
    association_handle: usize,
    stream_id: u16,

    read_outs: VecDeque<DataChannelMessage>,
    write_outs: VecDeque<DataChannelMessage>,

    /// Whether the DCEP handshake for this channel has completed.
    handshake_complete: bool,

    // stats
    messages_sent: usize,
    messages_received: usize,
    bytes_sent: usize,
    bytes_received: usize,
}

impl DataChannel {
    /// Creates a new `DataChannel` with the given configuration, association
    /// handle, and SCTP stream identifier.  Counters start at zero.
    fn new(config: DataChannelConfig, association_handle: usize, stream_id: u16) -> Self {
        Self {
            config,
            association_handle,
            stream_id,
            read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
            ..Default::default()
        }
    }

    /// Dial opens a data channel over SCTP.
    ///
    /// A DCEP `DataChannelOpen` message is always constructed so that the SCTP
    /// handler registers the underlying stream.  For **in-band** channels the
    /// message is also sent over the wire (RFC 8832 sec. 3); for
    /// **pre-negotiated** channels it stays internal-only (see issue #61).
    pub fn dial(
        config: DataChannelConfig,
        association_handle: usize,
        stream_id: u16,
    ) -> Result<Self> {
        let mut data_channel = DataChannel::new(config.clone(), association_handle, stream_id);

        // Both in-band and out-of-band (negotiated) channels emit a
        // DATA_CHANNEL_OPEN so the underlying SCTP stream gets opened and its
        // reliability parameters configured (the Channel Type / Reliability
        // Parameter mapping in RFC 8832 section 5.1). For a negotiated channel
        // the message is flagged so the transport opens the stream locally
        // without sending the DCEP handshake to the peer; that suppression is
        // required by the W3C WebRTC `negotiated` semantics, not by DCEP.
        let msg = Message::DataChannelOpen(DataChannelOpen {
            channel_type: config.channel_type,
            priority: config.priority,
            reliability_parameter: config.reliability_parameter,
            label: config.label.bytes().collect(),
            protocol: config.protocol.bytes().collect(),
        })
        .marshal()?;

        data_channel.write_outs.push_back(DataChannelMessage {
            association_handle,
            stream_id,
            ppi: PayloadProtocolIdentifier::Dcep,
            payload: msg,
            negotiated: config.negotiated,
        });

        // Out-of-band `negotiated` channels have no handshake, so they are
        // handshake-complete immediately. In-band channels stay incomplete until
        // `handle_dcep` processes the peer's `DATA_CHANNEL_ACK`.
        data_channel.handshake_complete = config.negotiated;

        Ok(data_channel)
    }

    /// Accept is used to accept incoming data channels over SCTP
    pub fn accept(
        mut config: DataChannelConfig,
        association_handle: usize,
        stream_id: u16,
        ppi: PayloadProtocolIdentifier,
        buf: &[u8],
    ) -> Result<Self> {
        if ppi != PayloadProtocolIdentifier::Dcep {
            return Err(Error::InvalidPayloadProtocolIdentifier(ppi as u8));
        }

        let mut read_buf = buf;
        let msg = unmarshal_from_peer(&mut read_buf)?;

        if let Message::DataChannelOpen(dco) = msg {
            config.channel_type = dco.channel_type;
            config.priority = dco.priority;
            config.reliability_parameter = dco.reliability_parameter;
            config.label = String::from_utf8(dco.label)?;
            config.protocol = String::from_utf8(dco.protocol)?;
        } else {
            return Err(Error::InvalidMessageType(msg.message_type() as u8));
        };

        let mut data_channel = DataChannel::new(config, association_handle, stream_id);

        data_channel.write_data_channel_ack()?;

        // The remote side's OPEN has been processed and the ACK is written out,
        // so the handshake is complete.
        data_channel.handshake_complete = true;

        Ok(data_channel)
    }

    /// MessagesSent returns the number of messages sent
    pub fn messages_sent(&self) -> usize {
        self.messages_sent
    }

    /// MessagesReceived returns the number of messages received
    pub fn messages_received(&self) -> usize {
        self.messages_received
    }

    /// BytesSent returns the number of bytes sent
    pub fn bytes_sent(&self) -> usize {
        self.bytes_sent
    }

    /// BytesReceived returns the number of bytes received
    pub fn bytes_received(&self) -> usize {
        self.bytes_received
    }

    /// association_handle returns the association handle
    pub fn association_handle(&self) -> usize {
        self.association_handle
    }

    /// StreamIdentifier returns the Stream identifier associated to the stream.
    pub fn stream_identifier(&self) -> u16 {
        self.stream_id
    }

    /// The configuration this channel was opened with.
    pub fn config(&self) -> &DataChannelConfig {
        &self.config
    }

    /// Whether the DCEP handshake for this channel has completed.
    ///
    /// For a locally-created in-band channel this becomes `true` only when the peer's
    /// `DATA_CHANNEL_ACK` is received; for a remote channel it is `true` from `accept()`;
    /// for an out-of-band `negotiated` channel it is `true` from `dial()`.
    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    fn handle_dcep<B>(&mut self, data: &mut B) -> Result<()>
    where
        B: Buf,
    {
        let msg = unmarshal_from_peer(data)?;

        match msg {
            Message::DataChannelOpen(_) => {
                // RFC 8832 section 6: a DATA_CHANNEL_OPEN "received on an already used stream"
                // gets no DATA_CHANNEL_ACK and closes the channel, which is the caller's to
                // do (it owns the stream). The OPEN that opens a channel goes to `accept`.
                debug!("Received DATA_CHANNEL_OPEN on a stream in use");
                return Err(Error::ErrStreamAlreadyExist);
            }
            Message::DataChannelAck(_) => {
                debug!("Received DATA_CHANNEL_ACK");
                // The initiator's DCEP handshake is complete.
                self.handshake_complete = true;
            }
            _ => {
                return Err(Error::InvalidMessageType(msg.message_type() as u8));
            }
        };

        Ok(())
    }

    fn write_data_channel_ack(&mut self) -> Result<()> {
        let ack = Message::DataChannelAck(DataChannelAck {}).marshal()?;
        self.write_outs.push_back(DataChannelMessage {
            association_handle: self.association_handle,
            stream_id: self.stream_id,
            ppi: PayloadProtocolIdentifier::Dcep,
            payload: ack,
            negotiated: false,
        });
        Ok(())
    }

    fn write_data_channel_close(&mut self) -> Result<()> {
        let close = Message::DataChannelClose(DataChannelClose {}).marshal()?;
        self.write_outs.push_back(DataChannelMessage {
            association_handle: self.association_handle,
            stream_id: self.stream_id,
            ppi: PayloadProtocolIdentifier::Dcep,
            payload: close,
            negotiated: false,
        });
        Ok(())
    }

    fn write_data_channel_high_threshold(&mut self, threshold: u32) -> Result<()> {
        let low_threshold =
            Message::DataChannelThreshold(DataChannelThreshold::High(threshold)).marshal()?;
        self.write_outs.push_back(DataChannelMessage {
            association_handle: self.association_handle,
            stream_id: self.stream_id,
            ppi: PayloadProtocolIdentifier::Dcep,
            payload: low_threshold,
            negotiated: false,
        });
        Ok(())
    }

    fn write_data_channel_low_threshold(&mut self, threshold: u32) -> Result<()> {
        let low_threshold =
            Message::DataChannelThreshold(DataChannelThreshold::Low(threshold)).marshal()?;
        self.write_outs.push_back(DataChannelMessage {
            association_handle: self.association_handle,
            stream_id: self.stream_id,
            ppi: PayloadProtocolIdentifier::Dcep,
            payload: low_threshold,
            negotiated: false,
        });
        Ok(())
    }

    /// SetBufferedAmountHighThreshold is used to update the threshold.
    /// See BufferedAmountHighThreshold().
    pub fn set_buffered_amount_high_threshold(&mut self, threshold: u32) -> Result<()> {
        self.write_data_channel_high_threshold(threshold)
    }

    /// SetBufferedAmountLowThreshold is used to update the threshold.
    /// See BufferedAmountLowThreshold().
    pub fn set_buffered_amount_low_threshold(&mut self, threshold: u32) -> Result<()> {
        self.write_data_channel_low_threshold(threshold)
    }

    /*
    /// OnBufferedAmountLow sets the callback handler which would be called when the
    /// number of bytes of outgoing data buffered is lower than the threshold.
    pub fn on_buffered_amount_low(&self, f: OnBufferedAmountLowFn) {
        self.stream.on_buffered_amount_low(f)
    }*/

    /// Decomposes a [`ChannelType`] into the SCTP send parameters it implies.
    ///
    /// Returns whether delivery is unordered, together with the reliability type and value SCTP
    /// needs for partial reliability.
    pub fn get_reliability_params(channel_type: ChannelType) -> (bool, ReliabilityType) {
        match channel_type {
            ChannelType::Reliable => (false, ReliabilityType::Reliable),
            ChannelType::ReliableUnordered => (true, ReliabilityType::Reliable),
            ChannelType::PartialReliableRexmit => (false, ReliabilityType::Rexmit),
            ChannelType::PartialReliableRexmitUnordered => (true, ReliabilityType::Rexmit),
            ChannelType::PartialReliableTimed => (false, ReliabilityType::Timed),
            ChannelType::PartialReliableTimedUnordered => (true, ReliabilityType::Timed),
        }
    }

    /// Derives the [`ChannelType`] and reliability parameter from the `maxPacketLifeTime` /
    /// `maxRetransmits` pair the W3C API exposes.
    ///
    /// The two are mutually exclusive; supplying neither yields a fully reliable channel.
    pub fn get_channel_type_and_reliability_parameter(
        ordered: bool,
        max_retransmits: Option<u16>,
        max_packet_life_time: Option<u16>,
    ) -> (ChannelType, u32) {
        let channel_type;
        let reliability_parameter;

        match (max_retransmits, max_packet_life_time) {
            (None, None) => {
                reliability_parameter = 0u32;
                if ordered {
                    channel_type = ChannelType::Reliable;
                } else {
                    channel_type = ChannelType::ReliableUnordered;
                }
            }

            (Some(max_retransmits), _) => {
                reliability_parameter = max_retransmits as u32;
                if ordered {
                    channel_type = ChannelType::PartialReliableRexmit;
                } else {
                    channel_type = ChannelType::PartialReliableRexmitUnordered;
                }
            }

            (None, Some(max_packet_lifetime)) => {
                reliability_parameter = max_packet_lifetime as u32;
                if ordered {
                    channel_type = ChannelType::PartialReliableTimed;
                } else {
                    channel_type = ChannelType::PartialReliableTimedUnordered;
                }
            }
        }

        (channel_type, reliability_parameter)
    }

    /// Builds the payload protocol identifier and payload for a user message.
    ///
    /// Empty messages get their own identifiers (`StringEmpty`/`BinaryEmpty`) because SCTP
    /// cannot carry a zero-length payload.
    pub fn get_data_channel_message(is_string: bool, data: BytesMut) -> DataChannelMessage {
        // https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-12#section-6.6
        // SCTP does not support the sending of empty user messages.  Therefore,
        // if an empty message has to be sent, the appropriate PPID (WebRTC
        // String Empty or WebRTC Binary Empty) is used and the SCTP user
        // message of one zero byte is sent.  When receiving an SCTP user
        // message with one of these PPIDs, the receiver MUST ignore the SCTP
        // user message and process it as an empty message.
        let ppi = match (is_string, data.len()) {
            (false, 0) => PayloadProtocolIdentifier::BinaryEmpty,
            (false, _) => PayloadProtocolIdentifier::Binary,
            (true, 0) => PayloadProtocolIdentifier::StringEmpty,
            (true, _) => PayloadProtocolIdentifier::String,
        };

        if data.is_empty() {
            DataChannelMessage {
                ppi,
                payload: BytesMut::from(&[0][..]),
                ..Default::default()
            }
        } else {
            DataChannelMessage {
                ppi,
                payload: data,
                ..Default::default()
            }
        }
    }
}

impl sansio::Protocol<DataChannelMessage, DataChannelMessage, ()> for DataChannel {
    type Rout = DataChannelMessage;
    type Wout = DataChannelMessage;
    type Eout = ();
    type Error = Error;
    type Time = ();

    /// Takes one message the peer sent on this channel's stream: a DCEP message is processed
    /// here, and a user message is queued for `poll_read`.
    ///
    /// An error means the peer broke the protocol on this channel (a `DATA_CHANNEL_OPEN` on a
    /// stream in use, a DCEP message that does not parse, an unsupported PPID): RFC 8832
    /// section 6 and RFC 8831 section 6.6 have the receiver close the channel. Such a message
    /// is neither delivered nor counted.
    fn handle_read(&mut self, msg: DataChannelMessage) -> Result<()> {
        match msg.ppi {
            PayloadProtocolIdentifier::Dcep => {
                let mut data_buf = &msg.payload[..];
                self.handle_dcep(&mut data_buf)?;
            }
            PayloadProtocolIdentifier::String
            | PayloadProtocolIdentifier::Binary
            | PayloadProtocolIdentifier::StringEmpty
            | PayloadProtocolIdentifier::BinaryEmpty => {
                // RFC 8832 section 6: "After the DATA_CHANNEL_ACK or any other message has
                // been received on the data channel", the channel is set up: the peer only
                // sends user data once it took the OPEN, so a message ahead of a delayed (or
                // lost) ACK completes the opener's handshake as the ACK would.
                self.handshake_complete = true;
            }
            // RFC 8831 section 6.6: the PPID is what says how the payload is to be read, so
            // a message under any other one (the deprecated partial PPIDs 52 and 54 among
            // them) has no interpretation. It is an error for the caller to close the
            // channel on, never binary data.
            other => return Err(Error::InvalidPayloadProtocolIdentifier(other as u8)),
        }

        self.messages_received += 1;
        self.bytes_received += user_bytes(&msg);
        if msg.ppi != PayloadProtocolIdentifier::Dcep {
            self.read_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<DataChannelMessage> {
        self.read_outs.pop_front()
    }

    /// handle_write writes len(p) bytes from p
    fn handle_write(&mut self, mut msg: DataChannelMessage) -> Result<()> {
        self.messages_sent += 1;
        self.bytes_sent += user_bytes(&msg);

        msg.association_handle = self.association_handle;
        msg.stream_id = self.stream_id;
        self.write_outs.push_back(msg);

        Ok(())
    }

    /// Returns packets to transmit
    fn poll_write(&mut self) -> Option<DataChannelMessage> {
        self.write_outs.pop_front()
    }

    /// Close closes the DataChannel and the underlying SCTP stream.
    fn close(&mut self) -> Result<()> {
        // https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13#section-6.7
        // Closing of a data channel MUST be signaled by resetting the
        // corresponding outgoing streams [RFC6525].  This means that if one
        // side decides to close the data channel, it resets the corresponding
        // outgoing stream.  When the peer sees that an incoming stream was
        // reset, it also resets its corresponding outgoing stream.  Once this
        // is completed, the data channel is closed.  Resetting a stream sets
        // the Stream Sequence Numbers (SSNs) of the stream back to 'zero' with
        // a corresponding notification to the application layer that the reset
        // has been performed.  Streams are available for reuse after a reset
        // has been performed.
        // Closing resets the handshake-complete flag.
        self.handshake_complete = false;
        self.write_data_channel_close()
    }
}

/// The application bytes a message carries: none for an empty message, whose one byte on the
/// wire is only the placeholder SCTP needs (RFC 8831 6.6).
fn user_bytes(msg: &DataChannelMessage) -> usize {
    match msg.ppi {
        PayloadProtocolIdentifier::StringEmpty | PayloadProtocolIdentifier::BinaryEmpty => 0,
        _ => msg.payload.len(),
    }
}

/// Parses a DCEP message the peer sent.
///
/// Types 0x00 (threshold) and 0x01 (close) are this crate's own: they travel from a data channel
/// to the SCTP layer on the write path and are never put on the wire. One that arrives from the
/// peer is refused by its type byte, before any of its body is read.
fn unmarshal_from_peer<B: Buf>(buf: &mut B) -> Result<Message> {
    if let Some(&message_type) = buf.chunk().first()
        && (message_type == MESSAGE_TYPE_THRESHOLD || message_type == MESSAGE_TYPE_CLOSE)
    {
        return Err(Error::InvalidMessageType(message_type));
    }
    Message::unmarshal(buf)
}
