//! Statistics module for WebRTC.
//!
//! This module provides:
//! - `stats` - W3C WebRTC Statistics API types
//! - `report` - Statistics report generation
//!
//! # Feeding what the engine cannot measure
//!
//! The engine is a transport: members that need an encoder, a decoder, capture or playout are
//! left out of the report until the application supplies them, through
//! [`RTCPeerConnection::update_decoder_stats`](crate::peer_connection::RTCPeerConnection::update_decoder_stats),
//! [`update_audio_receiver_stats`](crate::peer_connection::RTCPeerConnection::update_audio_receiver_stats),
//! [`update_encoder_stats`](crate::peer_connection::RTCPeerConnection::update_encoder_stats),
//! [`update_audio_source_stats`](crate::peer_connection::RTCPeerConnection::update_audio_source_stats),
//! [`update_video_source_stats`](crate::peer_connection::RTCPeerConnection::update_video_source_stats)
//! and
//! [`update_audio_playout_stats`](crate::peer_connection::RTCPeerConnection::update_audio_playout_stats).
//!
//! # Stats Selection
//!
//! When calling `get_stats()`, you can optionally provide a [`StatsSelector`]
//! to filter the returned statistics to only those relevant to a specific
//! sender or receiver.
//!
//! # Examples
//!
//! ```
//! use rtc::peer_connection::RTCPeerConnection;
//! use rtc::rtp_transceiver::RTCRtpSenderId;
//! use rtc::statistics::StatsSelector;
//! use std::time::Instant;
//!
//! # fn example(pc: &mut RTCPeerConnection, sender_id: RTCRtpSenderId) {
//! // Get all stats
//! let all_stats = pc.get_stats(Instant::now(), StatsSelector::None);
//!
//! // Get stats for a specific sender
//! let sender_stats = pc.get_stats(Instant::now(), StatsSelector::Sender(sender_id));
//! # }
//! ```

use crate::rtp_transceiver::{RTCRtpReceiverId, RTCRtpSenderId};

#[cfg(test)]
mod feed_test;
#[cfg(test)]
mod members_test;
#[cfg(test)]
mod report_integrity_test;
#[cfg(test)]
mod statistics_test;

pub(crate) mod accumulator;
mod feed;
pub mod report;
pub mod stats;

// What the application measures and the engine cannot (encoding, decoding, capture,
// playout), for the `update_*_stats` methods of `RTCPeerConnection` (see `feed`).
pub use accumulator::{
    AudioPlayoutStatsUpdate, AudioReceiverStatsUpdate, AudioSourceStatsUpdate, DecoderStatsUpdate,
    EncoderStatsUpdate, VideoSourceStatsUpdate,
};

/// Selector for filtering statistics in `get_stats()`.
///
/// This enum corresponds to the optional `selector` parameter in the
/// W3C WebRTC `getStats()` method. When provided, it filters the returned
/// statistics to only those relevant to the specified sender or receiver.
///
/// # Specification
///
/// See [The stats selection algorithm](https://www.w3.org/TR/webrtc/#the-stats-selection-algorithm)
///
/// # Variants
///
/// - `None` - Return all statistics for the entire connection
/// - `Sender` - Return statistics for a specific RTP sender and referenced objects
/// - `Receiver` - Return statistics for a specific RTP receiver and referenced objects
#[non_exhaustive]
pub enum StatsSelector {
    /// Gather stats for the whole connection.
    ///
    /// Returns all available statistics objects including peer connection,
    /// transport, ICE candidates, codecs, data channels, and all RTP streams.
    None,

    /// Gather stats for a specific RTP sender.
    ///
    /// Returns:
    /// - All `RTCOutboundRtpStreamStats` for streams being sent by this sender
    /// - All stats objects referenced by those outbound streams (transport,
    ///   codec, remote inbound stats, etc.)
    Sender(RTCRtpSenderId),

    /// Gather stats for a specific RTP receiver.
    ///
    /// Returns:
    /// - All `RTCInboundRtpStreamStats` for streams being received by this receiver
    /// - All stats objects referenced by those inbound streams (transport,
    ///   codec, remote outbound stats, etc.)
    Receiver(RTCRtpReceiverId),
}
