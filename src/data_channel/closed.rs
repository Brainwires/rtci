//! What stays readable of a data channel once it is closed.

use crate::data_channel::internal::RTCDataChannelInternal;
use crate::data_channel::{RTCDataChannelId, RTCDataChannelState, StreamId};

/// The final attributes of a closed data channel, read with
/// [`RTCPeerConnection::closed_data_channel`].
///
/// A W3C `RTCDataChannel` object keeps answering its attributes after it is closed: webrtc-pc
/// 6.2 `bufferedAmount` "does not reset to zero once the channel closes", and `label`, `id`,
/// `readyState` ("closed") and the rest stay what they were. The engine forgets a channel when it
/// closes ([`RTCPeerConnection::data_channel`] returns `None` from then on), so it keeps this
/// record for the handle instead: the application (or an API layer above the engine) reads it
/// after the channel's `OnClose`. The most recent closed channels are kept, at most
/// [`MAX_KEPT_CLOSED_DATA_CHANNELS`].
///
/// [`RTCPeerConnection::closed_data_channel`]: crate::peer_connection::RTCPeerConnection::closed_data_channel
/// [`RTCPeerConnection::data_channel`]: crate::peer_connection::RTCPeerConnection::data_channel
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RTCClosedDataChannel {
    id: RTCDataChannelId,
    stream_id: Option<StreamId>,
    label: String,
    protocol: String,
    ordered: bool,
    max_packet_life_time: Option<u16>,
    max_retransmits: Option<u16>,
    negotiated: bool,
    priority: u16,
    buffered_amount: u64,
    buffered_amount_low_threshold: u32,
}

/// How many closed data channels a peer connection keeps the final attributes of.
pub const MAX_KEPT_CLOSED_DATA_CHANNELS: usize = 64;

impl RTCClosedDataChannel {
    pub(crate) fn of(channel: &RTCDataChannelInternal) -> Self {
        Self {
            id: channel.id,
            stream_id: channel.stream_id,
            label: channel.label().to_owned(),
            protocol: channel.protocol().to_owned(),
            ordered: channel.ordered,
            max_packet_life_time: channel.max_packet_life_time,
            max_retransmits: channel.max_retransmits,
            negotiated: channel.negotiated,
            priority: channel.priority,
            // What `send()` queued less what SCTP took from the stream's queue before the
            // stream closed: data never sent stays counted.
            buffered_amount: channel
                .bytes_queued
                .saturating_sub(channel.bytes_dequeued_at_close.unwrap_or(0)),
            buffered_amount_low_threshold: channel.buffered_amount_low_threshold,
        }
    }

    /// The channel's handle.
    pub fn id(&self) -> RTCDataChannelId {
        self.id
    }

    /// W3C `id`: the SCTP stream identifier it had, `None` if it never got one.
    pub fn stream_id(&self) -> Option<StreamId> {
        self.stream_id
    }

    /// W3C `label`.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// W3C `protocol`.
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// W3C `ordered`.
    pub fn ordered(&self) -> bool {
        self.ordered
    }

    /// W3C `maxPacketLifeTime`.
    pub fn max_packet_life_time(&self) -> Option<u16> {
        self.max_packet_life_time
    }

    /// W3C `maxRetransmits`.
    pub fn max_retransmits(&self) -> Option<u16> {
        self.max_retransmits
    }

    /// W3C `negotiated`.
    pub fn negotiated(&self) -> bool {
        self.negotiated
    }

    /// The DCEP priority (RFC 8832 section 5.1) the channel had.
    pub fn priority(&self) -> u16 {
        self.priority
    }

    /// W3C `readyState`: always "closed".
    pub fn ready_state(&self) -> RTCDataChannelState {
        RTCDataChannelState::Closed
    }

    /// W3C `bufferedAmount` at the close: the bytes `send()` queued that SCTP never took from
    /// the stream's queue (0 after a closing procedure that sent everything).
    pub fn buffered_amount(&self) -> u64 {
        self.buffered_amount
    }

    /// W3C `bufferedAmountLowThreshold` at the close.
    pub fn buffered_amount_low_threshold(&self) -> u32 {
        self.buffered_amount_low_threshold
    }
}
