//! RTP Media API
//!
//! This module provides the RTCRtpTransceiver, which represents a permanent pairing
//! of an [`RTCRtpSender`](rtp_sender::RTCRtpSender) and an [`RTCRtpReceiver`](rtp_receiver::RTCRtpReceiver),
//! along with shared state.
//!
//! # Overview
//!
//! A transceiver manages bidirectional media exchange for a single media type (audio or video).
//! It combines:
//! - An RTP sender for outgoing media
//! - An RTP receiver for incoming media  
//! - Shared state including direction, mid, and codec preferences
//!
//! # Examples
//!
//! ## Adding a transceiver from a track
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtc::peer_connection::RTCPeerConnectionBuilder;
//! # use rtc::media_stream::MediaStreamTrack;
//! # use rtc::rtp_transceiver::{RTCRtpTransceiverInit, RTCRtpTransceiverDirection};
//! # fn example(audio_track: MediaStreamTrack) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // Add a transceiver for sending audio
//! let init = RTCRtpTransceiverInit {
//!     direction: RTCRtpTransceiverDirection::Sendrecv,
//!     ..Default::default()
//! };
//!
//! let sender_id = peer_connection
//!     .add_transceiver_from_track(audio_track, Some(init))?;
//!
//! println!("Added sender with ID: {:?}", sender_id);
//! # Ok(())
//! # }
//! ```
//!
//! ## Adding a transceiver by media kind
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtc::peer_connection::RTCPeerConnectionBuilder;
//! # use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
//! # use rtc::rtp_transceiver::{RTCRtpTransceiverInit, RTCRtpTransceiverDirection};
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // Add a video transceiver for receiving only
//! let init = RTCRtpTransceiverInit {
//!     direction: RTCRtpTransceiverDirection::Recvonly,
//!     ..Default::default()
//! };
//!
//! let receiver_id = peer_connection
//!     .add_transceiver_from_kind(RtpCodecKind::Video, Some(init))?;
//!
//! println!("Added receiver with ID: {:?}", receiver_id);
//! # Ok(())
//! # }
//! ```
//!
//! ## Controlling transceiver direction
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtc::peer_connection::RTCPeerConnectionBuilder;
//! # use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // Iterate through transceivers and change direction
//! for transceiver_id in peer_connection.get_transceivers() {
//!     // Access the transceiver through peer_connection's internal methods
//!     // Note: Direct transceiver access may be internal API
//!     // This demonstrates the concept - actual usage depends on your API design
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Setting codec preferences
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtc::peer_connection::RTCPeerConnectionBuilder;
//! # use rtc::rtp_transceiver::rtp_sender::RTCRtpCodecParameters;
//! # fn example(preferred_codecs: Vec<RTCRtpCodecParameters>) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // Codec preferences would be set through peer connection methods
//! // The exact API depends on your implementation
//! # Ok(())
//! # }
//! ```
//!
//! # Specification
//!
//! See [RTCRtpTransceiver](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver) in the W3C WebRTC specification.

use crate::media_stream::MediaStreamId;
use crate::peer_connection::RTCPeerConnection;
use crate::rtp_transceiver::rtp_sender::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
pub use direction::RTCRtpTransceiverDirection;
use log::trace;
use shared::error::{Error, Result};

pub(crate) mod direction;
pub(crate) mod fmtp;
pub(crate) mod internal;
pub mod rtp_receiver;
pub mod rtp_sender;
#[cfg(test)]
mod rtp_transceiver_test;

/// SSRC (Synchronization Source) identifier.
///
/// A synchronization source is a randomly chosen value meant to be globally unique
/// within a particular RTP session. It is used to identify a single stream of media.
///
/// # Specification
///
/// See [RFC 3550 Section 3](https://datatracker.ietf.org/doc/html/rfc3550#section-3).
#[allow(clippy::upper_case_acronyms)]
pub type SSRC = u32;

/// RTP payload type identifier.
///
/// Identifies the format of the RTP payload and determines its interpretation by the
/// application. Each codec in an RTP session will have a different payload type.
///
/// # Specification
///
/// See [RFC 3550 Section 3](https://datatracker.ietf.org/doc/html/rfc3550#section-3).
pub type PayloadType = u8;

/// RTP stream identifier.
///
/// Is used for unique identification of RTP stream
///
/// # Specification
///
/// See [RFC 8852 Section 3.1](https://datatracker.ietf.org/doc/html/rfc8852#section-3.1).
pub type RtpStreamId = String;

/// Repaired RTP stream identifier.
///
/// Is used to identify which stream is to be repaired using a redundancy RTP stream
///
/// # Specification
///
/// See [RFC 8852 Section 3.2](https://datatracker.ietf.org/doc/html/rfc8852#section-3.2).
pub type RepairedStreamId = String;

/// Internal identifier for an RTP transceiver.
pub type RTCRtpTransceiverId = usize;

impl From<RTCRtpSenderId> for RTCRtpTransceiverId {
    fn from(id: RTCRtpSenderId) -> Self {
        id.0
    }
}

impl From<RTCRtpReceiverId> for RTCRtpTransceiverId {
    fn from(id: RTCRtpReceiverId) -> Self {
        id.0
    }
}

/// Identifier for an `RTCRtpSender` within a peer connection.
///
/// Used to reference a specific RTP sender when calling methods like `remove_track`.
#[derive(Default, Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct RTCRtpSenderId(pub(crate) RTCRtpTransceiverId);

impl From<RTCRtpTransceiverId> for RTCRtpSenderId {
    fn from(id: RTCRtpTransceiverId) -> Self {
        Self(id)
    }
}

/// Identifier for an `RTCRtpReceiver` within a peer connection.
///
/// Used to reference a specific RTP receiver when handling incoming media.
#[derive(Default, Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct RTCRtpReceiverId(pub(crate) RTCRtpTransceiverId);

impl From<RTCRtpTransceiverId> for RTCRtpReceiverId {
    fn from(id: RTCRtpTransceiverId) -> Self {
        Self(id)
    }
}

/// Initialization parameters for creating an `RTCRtpTransceiver`.
///
/// Used with `add_transceiver_from_track` or `add_transceiver_from_kind` to configure
/// the transceiver's initial direction and encoding parameters.
///
/// # Specification
///
/// See [RTCRtpTransceiverInit](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiverinit)
#[derive(Clone)]
pub struct RTCRtpTransceiverInit {
    /// The initial direction of the transceiver; sendrecv by default.
    pub direction: RTCRtpTransceiverDirection,
    /// The stream IDs associated with the transceiver's sender.
    pub streams: Vec<MediaStreamId>,
    /// The encoding parameters to use when sending media.
    pub send_encodings: Vec<RTCRtpEncodingParameters>,
}

impl Default for RTCRtpTransceiverInit {
    /// W3C `RTCRtpTransceiverInit`: direction "sendrecv", no streams, no send encodings.
    fn default() -> Self {
        Self::with_direction(RTCRtpTransceiverDirection::Sendrecv)
    }
}

impl RTCRtpTransceiverInit {
    /// An init with `direction`, no streams and no send encodings.
    pub fn with_direction(direction: RTCRtpTransceiverDirection) -> Self {
        Self {
            direction,
            streams: vec![],
            send_encodings: vec![],
        }
    }

    /// The init of a transceiver that offers to receive only.
    pub fn recvonly() -> Self {
        Self::with_direction(RTCRtpTransceiverDirection::Recvonly)
    }
}

/// RTCRtpTransceiver represents a permanent pairing of an RTP sender and RTP receiver that share a common mid.
/// The transceiver manages the direction of media flow and codec preferences.
///
/// # Specification
///
/// See [RTCRtpTransceiver](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver) in the W3C WebRTC specification.
pub struct RTCRtpTransceiver<'a> {
    pub(crate) id: RTCRtpTransceiverId,
    pub(crate) peer_connection: &'a mut RTCPeerConnection,
}

/// What the `b=` lines of a remote media section say (RFC 9429 section 5.10), in bits per
/// second. `None`: the section has no such line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RTCRemoteBandwidth {
    /// The most RTP the remote side accepts from this endpoint in the section: `b=TIAS` (RFC
    /// 3890, the bit rate without transport overhead), else the value RFC 9429 section 5.10
    /// derives from `b=AS` (kilobits per second, RFC 8866 section 5.8): "TIAS = AS * 1000 *
    /// 0.95 - (50 * 40 * 8)", which takes out RTCP's 5% and an estimate of the header
    /// overhead. The bound of the congestion controller's estimate, and what an encoder caps
    /// its target with.
    pub max_bitrate: Option<u64>,
    /// The session bandwidth of the section (RFC 3550 section 6.2), which RTCP's share is
    /// taken from: `b=TIAS`, else `b=AS` times 1000.
    pub session_bitrate: Option<u64>,
    /// `b=RS` (RFC 3556): the RTCP bandwidth allocated to active data senders.
    pub rtcp_senders_bitrate: Option<u64>,
    /// `b=RR` (RFC 3556): the RTCP bandwidth allocated to receivers; 0 turns their RTCP off.
    pub rtcp_receivers_bitrate: Option<u64>,
}

impl RTCRtpTransceiver<'_> {
    /// The bandwidth limits the remote description states for this transceiver's media
    /// section (`b=TIAS` / `b=AS`, `b=RS`, `b=RR`); all `None` before a remote description
    /// with such lines is applied.
    pub fn remote_bandwidth(&self) -> RTCRemoteBandwidth {
        self.peer_connection.rtp_transceivers[self.id].remote_bandwidth()
    }

    /// The `xr-format`s the remote description lists in `a=rtcp-xr` for this transceiver's
    /// media section (RFC 3611 section 5.1; the media-level attribute, else the session's),
    /// such as `rcvr-rtt=all`. `None`: no such attribute. `Some` of an empty list: the remote
    /// side wants no XR blocks (RFC 3611 section 5.2).
    pub fn remote_rtcp_xr(&self) -> Option<&[String]> {
        self.peer_connection.rtp_transceivers[self.id].remote_rtcp_xr()
    }

    /// Whether the last answer negotiated reduced-size RTCP for this transceiver's media
    /// section (`a=rtcp-rsize` in the offer and in the answer, RFC 5506 section 5).
    pub fn rtcp_reduced_size(&self) -> bool {
        self.peer_connection.rtp_transceivers[self.id].rtcp_reduced_size()
    }

    /// Returns the media stream identification tag (mid) for this transceiver.
    ///
    /// The mid uniquely identifies the media description in the SDP. When not already set,
    /// this value will be assigned during `create_offer` or `create_answer`.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.mid](https://www.w3.org/TR/webrtc/#dom-rtptransceiver-mid).
    pub fn mid(&self) -> &Option<String> {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized,
        // so, [self.id] here is safe.
        self.peer_connection.rtp_transceivers[self.id].mid()
    }

    /// Returns the id of this transceiver's [`RTCRtpSender`].
    ///
    /// Every transceiver has a sender from its creation, with or without a track (W3C webrtc
    /// 5.4 `[[Sender]]`); the value is always `Some`.
    ///
    /// [`RTCRtpSender`]: crate::rtp_transceiver::rtp_sender::RTCRtpSender
    pub fn sender(&self) -> Option<RTCRtpSenderId> {
        Some(RTCRtpSenderId::from(self.id))
    }

    /// Returns the id of this transceiver's [`RTCRtpReceiver`].
    ///
    /// Every transceiver has a receiver from its creation, whatever its direction (W3C webrtc
    /// 5.4 `[[Receiver]]`); the value is always `Some`.
    ///
    /// [`RTCRtpReceiver`]: crate::rtp_transceiver::rtp_receiver::RTCRtpReceiver
    pub fn receiver(&self) -> Option<RTCRtpReceiverId> {
        Some(RTCRtpReceiverId::from(self.id))
    }

    /// Returns the preferred direction of the transceiver:
    /// [`Stopped`](RTCRtpTransceiverDirection::Stopped) once [`stop`](Self::stop) was called
    /// or the transceiver is stopped, otherwise the direction the application prefers.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.direction](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction).
    pub fn direction(&self) -> RTCRtpTransceiverDirection {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized,
        // so, [self.id] here is safe.
        let transceiver = &self.peer_connection.rtp_transceivers[self.id];
        if transceiver.stopped() {
            RTCRtpTransceiverDirection::Stopped
        } else {
            transceiver.direction()
        }
    }

    /// Whether the transceiver is stopping or stopped: [`stop`](Self::stop) was called, or a
    /// description rejected its m= section. Such a transceiver sends and receives nothing and
    /// is offered rejected; see [`is_stopped`](Self::is_stopped) for the second state alone.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.stop()](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-stop).
    pub fn stopped(&self) -> bool {
        self.peer_connection.rtp_transceivers[self.id].stopped()
    }

    /// W3C `[[Stopped]]`: a description rejected this transceiver's m= section (or it was
    /// created for a rejected one). [`stop`](Self::stop) alone leaves it stopping, not
    /// stopped, until the exchange that rejects the section completes.
    pub fn is_stopped(&self) -> bool {
        self.peer_connection.rtp_transceivers[self.id].is_stopped()
    }

    /// Whether a remote offer's new media section may be associated with this transceiver.
    ///
    /// See [`RTCRtpTransceiver::set_associable_with_remote_offer`].
    pub fn associable_with_remote_offer(&self) -> bool {
        self.peer_connection.rtp_transceivers[self.id].associable_with_remote_offer()
    }

    /// Sets whether a remote offer's new media section may be associated with this
    /// transceiver while it has no mid.
    ///
    /// RFC 9429, Section 5.10 gives a remote offer's new media section a transceiver that
    /// "was created by `addTrack`" (same kind, never associated, not stopped), and otherwise
    /// a new one; a transceiver the application created with `addTransceiver` is not a
    /// candidate, and is offered in a media section of its own later. This crate has one way
    /// to create a transceiver for both, so the application says which it was: `true` (the
    /// default) for `addTrack`, `false` for `addTransceiver`. Set it back to `true` when
    /// `addTrack` reuses the transceiver.
    pub fn set_associable_with_remote_offer(&mut self, associable: bool) {
        self.peer_connection.rtp_transceivers[self.id].set_associable_with_remote_offer(associable);
    }

    /// Marks this transceiver as touched by W3C `addTrack`: a rollback of the remote offer that
    /// created it keeps it (RFC 9429, Section 5.7). For a caller that attaches the track itself,
    /// to a transceiver that already has a sender.
    pub fn keep_on_rollback(&mut self) {
        self.peer_connection.rtp_transceivers[self.id].set_created_by_remote_description(false);
    }

    /// Sets the RTP header extensions this transceiver's next offers and answers carry
    /// (webrtc-extensions, RTP header extension control).
    ///
    /// `Some(uris)` limits the media section's `a=extmap` lines to these URIs: an answer
    /// carries an offered extension only when it is listed, and an offer carries each listed
    /// extension the media engine has registered for this kind, a re-offer included (one
    /// left out of an earlier answer gets the id it had, or a free one). `None` (the default)
    /// is every extension the media engine negotiates (RFC 9429, sections 5.2 and 5.3).
    pub fn set_header_extensions_to_negotiate(&mut self, uris: Option<Vec<String>>) {
        self.peer_connection.rtp_transceivers[self.id].set_header_extensions_to_negotiate(uris);
    }

    /// Sets the preferred direction of this transceiver.
    ///
    /// Changing the direction updates the negotiation-needed flag; setting the direction it
    /// already has does nothing.
    ///
    /// # Errors
    ///
    /// - [`Error::ErrConnectionClosed`] when the connection is closed and
    ///   [`Error::InvalidStateError`] when the transceiver is stopping or stopped (both W3C
    ///   `InvalidStateError`)
    /// - [`Error::ErrInvalidDirection`] for
    ///   [`Stopped`](RTCRtpTransceiverDirection::Stopped) or
    ///   [`Unspecified`](RTCRtpTransceiverDirection::Unspecified) (W3C `TypeError`)
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.direction](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction).
    pub fn set_direction(&mut self, direction: RTCRtpTransceiverDirection) -> Result<()> {
        if self.peer_connection.is_closed() {
            return Err(Error::ErrConnectionClosed);
        }
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized,
        // so, [self.id] here is safe.
        if self.peer_connection.rtp_transceivers[self.id].stopped() {
            return Err(Error::InvalidStateError);
        }
        if matches!(
            direction,
            RTCRtpTransceiverDirection::Stopped | RTCRtpTransceiverDirection::Unspecified
        ) {
            return Err(Error::ErrInvalidDirection);
        }
        let previous_direction = self.peer_connection.rtp_transceivers[self.id].direction();
        if direction == previous_direction {
            return Ok(());
        }
        // A sender that is to send needs encodings (SSRCs) to describe.
        if direction.has_send() {
            self.peer_connection.ensure_send_encodings(self.id)?;
        }
        self.peer_connection.rtp_transceivers[self.id].set_direction(direction);
        trace!("Changing direction of transceiver from {previous_direction} to {direction}");
        self.peer_connection.on_transceiver_direction_changed();
        Ok(())
    }

    /// Returns the negotiated direction of the transceiver.
    ///
    /// The direction the last completed offer/answer exchange negotiated;
    /// [`RTCRtpTransceiverDirection::Unspecified`] (W3C null) before the first, and
    /// [`RTCRtpTransceiverDirection::Stopped`] once the transceiver is stopped.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.currentDirection](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-currentdirection).
    pub fn current_direction(&self) -> RTCRtpTransceiverDirection {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized,
        // so, [self.id] here is safe.
        let transceiver = &self.peer_connection.rtp_transceivers[self.id];
        if transceiver.is_stopped() {
            RTCRtpTransceiverDirection::Stopped
        } else {
            transceiver.current_direction()
        }
    }

    /// Irreversibly stops the transceiver.
    ///
    /// The sender stops sending (an RTCP BYE goes out for each stream it sent), the receiver
    /// stops receiving and its track ends
    /// ([`RTCTrackEvent::OnClose`](crate::peer_connection::event::RTCTrackEvent::OnClose)),
    /// and the direction reads [`Stopped`](RTCRtpTransceiverDirection::Stopped). The
    /// transceiver is then stopping: the next offer rejects its m= section, an answer made
    /// before that still answers it (inactive), and it is stopped
    /// ([`is_stopped`](Self::is_stopped)) and removed once an exchange rejecting the section
    /// completes. Stopping a stopping transceiver does nothing.
    ///
    /// # Errors
    ///
    /// [`Error::ErrConnectionClosed`] when the connection is closed (W3C
    /// `InvalidStateError`), or an error if the sender's interceptor bindings cannot be torn
    /// down.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.stop()](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-stop).
    pub fn stop(&mut self) -> Result<()> {
        if self.peer_connection.is_closed() {
            return Err(Error::ErrConnectionClosed);
        }
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized,
        // so, [self.id] here is safe.
        if self.peer_connection.rtp_transceivers[self.id].stopped() {
            return Ok(());
        }
        let ended = self.peer_connection.rtp_transceivers[self.id].stop_sending_and_receiving(
            &self.peer_connection.media_engine,
            &mut self.peer_connection.interceptor,
        )?;
        if ended {
            self.peer_connection.announce_receiver_track_ended(self.id);
        }
        // https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-stop, last step: update the
        // negotiation-needed flag.
        self.peer_connection
            .on_transceiver_stopped_or_streams_changed();
        Ok(())
    }

    /// Sets the preferred codec list for this transceiver.
    ///
    /// This overrides the default codec preferences from the media engine. An empty list
    /// resets the transceiver to the engine's codecs; duplicates are removed, keeping the
    /// first.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidModificationError`] (W3C webrtc 5.4 `setCodecPreferences`) when a codec
    /// matches none the engine can send or receive for this kind (the codec dictionary match:
    /// MIME type, clock rate, channels and format parameters), or when the list has only
    /// retransmission, redundancy, forward error correction or comfort noise formats.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.setCodecPreferences()](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-setcodecpreferences).
    pub fn set_codec_preferences(&mut self, codecs: Vec<RTCRtpCodecParameters>) -> Result<()> {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized,
        // so, [self.id] here is safe.
        let codecs = self.peer_connection.rtp_transceivers[self.id]
            .validate_codec_preferences(codecs, &self.peer_connection.media_engine)?;
        self.peer_connection.rtp_transceivers[self.id]
            .set_codec_preferences(codecs, &self.peer_connection.media_engine)
    }
}

#[cfg(test)]
mod tests {
    use sansio::Protocol;
    use std::time::Instant;

    use crate::peer_connection::configuration::media_engine::MediaEngine;
    use crate::peer_connection::event::RTCPeerConnectionEvent;
    use crate::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
    use crate::rtp_transceiver::RTCRtpTransceiverDirection;
    use crate::rtp_transceiver::rtp_sender::RtpCodecKind;

    fn build_pc() -> RTCPeerConnection {
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .expect("register default codecs");
        RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .build(Instant::now())
            .expect("build peer connection")
    }

    /// Drain every queued event and count the `OnNegotiationNeededEvent`s, driving only the
    /// public sans-I/O `Protocol` API (no private negotiation state is touched).
    fn count_negotiation_needed(pc: &mut RTCPeerConnection) -> usize {
        let mut count = 0;
        while let Some(event) = pc.poll_event() {
            if matches!(event, RTCPeerConnectionEvent::OnNegotiationNeededEvent) {
                count += 1;
            }
        }
        count
    }

    /// Complete a full offer/answer exchange so `offerer` settles back into a stable, idle
    /// negotiation state.
    fn negotiate(offerer: &mut RTCPeerConnection, answerer: &mut RTCPeerConnection) {
        let offer = offerer.create_offer(None).expect("create offer");
        offerer
            .set_local_description(Instant::now(), offer.clone())
            .expect("offerer set local");
        answerer
            .set_remote_description(Instant::now(), offer)
            .expect("answerer set remote");
        let answer = answerer.create_answer(None).expect("create answer");
        answerer
            .set_local_description(Instant::now(), answer.clone())
            .expect("answerer set local");
        offerer
            .set_remote_description(Instant::now(), answer)
            .expect("offerer set remote");
    }

    #[test]
    fn test_set_direction_triggers_negotiation_on_change() {
        let mut offerer = build_pc();
        let mut answerer = build_pc();

        let tid = offerer
            .add_transceiver_from_kind(
                RtpCodecKind::Video,
                Some(crate::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
            )
            .expect("add offerer transceiver");
        answerer
            .add_transceiver_from_kind(
                RtpCodecKind::Video,
                Some(crate::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
            )
            .expect("add answerer transceiver");

        negotiate(&mut offerer, &mut answerer);
        // Discard events produced by the initial negotiation.
        let _ = count_negotiation_needed(&mut offerer);

        // A transceiver added with `add_transceiver_from_kind(.., None)` negotiates as recvonly.
        assert_eq!(
            offerer.rtp_transceivers[tid].direction(),
            RTCRtpTransceiverDirection::Recvonly,
        );
        offerer
            .rtp_transceiver(tid)
            .expect("transceiver exists")
            .set_direction(RTCRtpTransceiverDirection::Sendrecv)
            .expect("the change is accepted");

        assert_eq!(
            count_negotiation_needed(&mut offerer),
            1,
            "changing the transceiver direction must trigger negotiation-needed",
        );
    }

    #[test]
    fn test_set_direction_noop_when_unchanged() {
        let mut offerer = build_pc();
        let mut answerer = build_pc();

        let tid = offerer
            .add_transceiver_from_kind(
                RtpCodecKind::Video,
                Some(crate::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
            )
            .expect("add offerer transceiver");
        answerer
            .add_transceiver_from_kind(
                RtpCodecKind::Video,
                Some(crate::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
            )
            .expect("add answerer transceiver");

        negotiate(&mut offerer, &mut answerer);
        let _ = count_negotiation_needed(&mut offerer);

        // Setting the current direction again must be a no-op.
        let current = offerer.rtp_transceivers[tid].direction();
        offerer
            .rtp_transceiver(tid)
            .expect("transceiver exists")
            .set_direction(current)
            .expect("the change is accepted");

        assert_eq!(
            count_negotiation_needed(&mut offerer),
            0,
            "setting the same direction must not trigger negotiation-needed",
        );
    }

    fn audio_track(stream: &str) -> crate::media_stream::MediaStreamTrack {
        crate::media_stream::MediaStreamTrack::new(
            stream.to_string(),
            "track".to_string(),
            "label".to_string(),
            RtpCodecKind::Audio,
            vec![
                crate::rtp_transceiver::rtp_sender::RTCRtpEncodingParameters {
                    active: true,
                    ..Default::default()
                },
            ],
        )
    }

    fn msid_lines(sdp: &str) -> Vec<&str> {
        sdp.lines()
            .filter_map(|line| line.strip_prefix("a=msid:"))
            .collect()
    }

    /// RFC 9429, Section 5.2.1: one `a=msid` line per MediaStream of the sender, and the stream
    /// id the track itself has (which an application sets to `-`) when it is in none.
    #[test]
    fn test_offer_has_one_msid_line_per_stream() {
        let mut pc = build_pc();
        let tid = pc
            .add_transceiver_from_track(audio_track("-"), None)
            .expect("add transceiver");

        let offer = pc.create_offer(None).expect("create offer");
        assert_eq!(msid_lines(&offer.sdp), vec!["- track"]);

        pc.rtp_sender(tid.into())
            .expect("sender")
            .set_streams(vec![
                "one".to_string(),
                "two".to_string(),
                "one".to_string(),
            ])
            .expect("the change is accepted");
        let offer = pc.create_offer(None).expect("create offer");
        assert_eq!(msid_lines(&offer.sdp), vec!["one track", "two track"]);

        pc.rtp_sender(tid.into())
            .expect("sender")
            .set_streams(vec![])
            .expect("the change is accepted");
        let offer = pc.create_offer(None).expect("create offer");
        assert_eq!(msid_lines(&offer.sdp), vec!["- track"]);
    }

    /// RFC 9429, Section 5.10: a remote offer's new media section takes a transceiver the
    /// application marked as created by `addTrack` (the default), not one it marked as created
    /// by `addTransceiver`, which keeps waiting for a media section of its own.
    #[test]
    fn test_remote_offer_skips_a_transceiver_that_is_not_associable() {
        let offer = {
            let mut offerer = build_pc();
            offerer
                .add_transceiver_from_track(audio_track("stream"), None)
                .expect("add offerer transceiver");
            offerer.create_offer(None).expect("create offer")
        };

        // The default: the answerer's own transceiver is taken.
        let mut answerer = build_pc();
        let tid = answerer
            .add_transceiver_from_track(audio_track("stream"), None)
            .expect("add answerer transceiver");
        assert!(
            answerer
                .rtp_transceiver(tid)
                .expect("transceiver")
                .associable_with_remote_offer()
        );
        answerer
            .set_remote_description(Instant::now(), offer.clone())
            .expect("set remote");
        assert_eq!(answerer.rtp_transceivers.len(), 1);
        assert!(answerer.rtp_transceivers[tid].mid().is_some());

        // Not associable: the offer gets a new transceiver, this one stays unassociated.
        let mut answerer = build_pc();
        let tid = answerer
            .add_transceiver_from_track(audio_track("stream"), None)
            .expect("add answerer transceiver");
        answerer
            .rtp_transceiver(tid)
            .expect("transceiver")
            .set_associable_with_remote_offer(false);
        answerer
            .set_remote_description(Instant::now(), offer)
            .expect("set remote");
        assert_eq!(answerer.rtp_transceivers.len(), 2);
        assert!(answerer.rtp_transceivers[tid].mid().is_none());
        assert!(answerer.rtp_transceivers[1].mid().is_some());
    }
}
