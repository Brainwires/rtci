//! RTP sender module providing WebRTC RTPSender functionality.
//!
//! This module implements the RTPSender interface which controls how media tracks
//! are encoded and transmitted to remote peers.
//!
//! # Overview
//!
//! An RTP sender manages the transmission of a single media track, providing control over:
//! - Codec selection and parameters
//! - Encoding parameters (bitrate, resolution, framerate)
//! - Simulcast and layered encoding configurations
//! - Direct RTP/RTCP packet transmission
//!
//! # Examples
//!
//! ## Getting the sender's track
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtc::peer_connection::RTCPeerConnectionBuilder;
//! # use rtc::rtp_transceiver::RTCRtpSenderId;
//! # fn example(sender_id: RTCRtpSenderId) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // Get sender and access its track
//! if let Some(mut sender) = peer_connection.rtp_sender(sender_id) {
//!     let track = sender.track();
//!     println!("Track ID: {}", track.track_id());
//!     println!("Track kind: {:?}", track.kind());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Getting and modifying send parameters
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtc::peer_connection::RTCPeerConnectionBuilder;
//! # use rtc::rtp_transceiver::RTCRtpSenderId;
//! # fn example(sender_id: RTCRtpSenderId) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! if let Some(mut sender) = peer_connection.rtp_sender(sender_id) {
//!     // Get current parameters
//!     let mut params = sender.get_parameters().clone();
//!     
//!     // Modify encoding parameters
//!     for encoding in &mut params.encodings {
//!         encoding.max_bitrate = 1_000_000; // 1 Mbps
//!         encoding.max_framerate = Some(30.0);
//!     }
//!     
//!     // Apply the changes
//!     sender.set_parameters(params, None)?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Replacing a track
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtc::peer_connection::RTCPeerConnectionBuilder;
//! # use rtc::media_stream::MediaStreamTrack;
//! # use rtc::rtp_transceiver::RTCRtpSenderId;
//! # fn example(
//! #     sender_id: RTCRtpSenderId,
//! #     new_track: MediaStreamTrack
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! if let Some(mut sender) = peer_connection.rtp_sender(sender_id) {
//!     // Replace with new track (same kind required)
//!     sender.replace_track(new_track)?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Writing raw RTP packets
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtc::peer_connection::RTCPeerConnectionBuilder;
//! # use rtc::rtp_transceiver::RTCRtpSenderId;
//! # use rtp::packet::Packet;
//! # use shared::error::Error;
//! # fn example(
//! #     sender_id: RTCRtpSenderId,
//! #     mut rtp_packet: Packet
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! if let Some(mut sender) = peer_connection.rtp_sender(sender_id) {
//!     // Write RTP packet directly
//!     // The sender will set the correct payload type and SSRC
//!     rtp_packet.header.ssrc = sender
//!         .track()
//!         .ssrcs()
//!         .last()
//!         .ok_or(Error::ErrSenderWithNoSSRCs)?;
//!     sender.write_rtp(Instant::now(), rtp_packet)?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Configuring simulcast with transceiver init
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtc::peer_connection::RTCPeerConnectionBuilder;
//! # use rtc::media_stream::MediaStreamTrack;
//! # use rtc::rtp_transceiver::{RTCRtpTransceiverInit, RTCRtpTransceiverDirection};
//! # use rtc::rtp_transceiver::rtp_sender::{
//! #     RTCRtpEncodingParameters, RTCRtpCodingParameters
//! # };
//! # fn example(video_track: MediaStreamTrack) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // Configure simulcast with three layers
//! let mut init = RTCRtpTransceiverInit {
//!     direction: RTCRtpTransceiverDirection::Sendrecv,
//!     ..Default::default()
//! };
//!
//! // High quality layer
//! init.send_encodings.push(RTCRtpEncodingParameters {
//!     rtp_coding_parameters: RTCRtpCodingParameters {
//!         rid: "h".to_string(),
//!         ..Default::default()
//!     },
//!     max_bitrate: 2_000_000, // 2 Mbps
//!     scale_resolution_down_by: Some(1.0),
//!     ..Default::default()
//! });
//!
//! // Medium quality layer
//! init.send_encodings.push(RTCRtpEncodingParameters {
//!     rtp_coding_parameters: RTCRtpCodingParameters {
//!         rid: "m".to_string(),
//!         ..Default::default()
//!     },
//!     max_bitrate: 1_000_000, // 1 Mbps
//!     scale_resolution_down_by: Some(2.0),
//!     ..Default::default()
//! });
//!
//! // Low quality layer
//! init.send_encodings.push(RTCRtpEncodingParameters {
//!     rtp_coding_parameters: RTCRtpCodingParameters {
//!         rid: "l".to_string(),
//!         ..Default::default()
//!     },
//!     max_bitrate: 500_000, // 500 kbps
//!     scale_resolution_down_by: Some(4.0),
//!     ..Default::default()
//! });
//!
//! peer_connection.add_transceiver_from_track(video_track, Some(init))?;
//! # Ok(())
//! # }
//! ```
//!
//! # Specification
//!
//! * [W3C RTCRtpSender](https://www.w3.org/TR/webrtc/#rtcrtpsender-interface)
//! * [MDN RTCRtpSender](https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpSender)

#[cfg(test)]
mod rtp_sender_test;

pub(crate) mod internal;
pub(crate) mod rtcp_parameters;
pub(crate) mod rtp_capabilities;
pub(crate) mod rtp_codec;
pub(crate) mod rtp_codec_parameters;
pub(crate) mod rtp_coding_parameters;
pub(crate) mod rtp_encoding_parameters;
pub(crate) mod rtp_header_extension_capability;
pub(crate) mod rtp_header_extension_parameters;
pub(crate) mod rtp_parameters;
pub(crate) mod rtp_receiver_parameters;
pub(crate) mod rtp_send_parameters;
pub(crate) mod set_parameter_options;

use crate::media_stream::MediaStreamId;
use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use crate::peer_connection::transport::RTCDtlsTransport;
use crate::rtp_transceiver::RTCRtpSenderId;
use crate::rtp_transceiver::rtp_sender::rtp_codec::encoding_send_codec;
use log::trace;
use sansio::Protocol;
use shared::error::{Error, Result};
use std::time::Instant;

pub(crate) use rtcp_parameters::negotiates_ccfb;
pub use rtcp_parameters::{
    RTCP_FB_ACK_CCFB, TYPE_RTCP_FB_ACK, TYPE_RTCP_FB_CCM, TYPE_RTCP_FB_GOOG_REMB,
    TYPE_RTCP_FB_NACK, TYPE_RTCP_FB_TRANSPORT_CC,
};
pub use rtcp_parameters::{RTCPFeedback, RTCRtcpParameters};
pub use rtp_capabilities::RTCRtpCapabilities;
pub use rtp_codec::{RTCRtpCodec, RtpCodecKind};
pub use rtp_codec_parameters::RTCRtpCodecParameters;
pub use rtp_coding_parameters::{RTCRtpCodingParameters, RTCRtpFecParameters, RTCRtpRtxParameters};
pub use rtp_encoding_parameters::RTCRtpEncodingParameters;
pub use rtp_header_extension_capability::RTCRtpHeaderExtensionCapability;
pub use rtp_header_extension_parameters::RTCRtpHeaderExtensionParameters;
pub use rtp_parameters::RTCRtpParameters;
pub use rtp_receiver_parameters::RTCRtpReceiveParameters;
pub use rtp_send_parameters::RTCRtpSendParameters;
pub use set_parameter_options::RTCSetParameterOptions;

/// The most encodings a sender has (W3C webrtc 5.1 `addTransceiver`: "the maximum number of
/// total simultaneous encodings the user agent may support"): `sendEncodings` past this many
/// are dropped from the end.
pub const MAX_SEND_ENCODINGS: usize = 16;

/// RTCRtpSender controls the encoding and transmission of media tracks to remote peers.
///
/// This struct provides a handle to the RTP sender within a peer connection,
/// allowing control over parameters, track replacement, and direct RTP/RTCP packet writing.
///
/// ## Specifications
///
/// * [MDN]
/// * [W3C]
///
/// [MDN]: https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpSender
/// [W3C]: https://www.w3.org/TR/webrtc/#rtcrtpsender-interface
pub struct RTCRtpSender<'a> {
    pub(crate) id: RTCRtpSenderId,
    pub(crate) peer_connection: &'a mut RTCPeerConnection,
}

impl RTCRtpSender<'_> {
    /// The DTLS transport over which this sender's RTP packets are sent.
    ///
    /// ## Nullability
    ///
    /// `None` until this sender's transceiver has been associated by negotiation. The spec
    /// sources this from the `[[SenderTransport]]` slot, which is per-sender and is filled while
    /// applying a local or remote description — so the predicate is that transceiver's mid, not
    /// a connection-wide flag.
    ///
    /// Deliberately *not* keyed on whether the DTLS endpoint has been built: an offerer
    /// associates its transceivers at `setLocalDescription`, before the answer starts DTLS, and a
    /// browser reports a transport there too. The handle simply reports
    /// [`RTCDtlsTransportState::New`](crate::peer_connection::transport::RTCDtlsTransportState)
    /// until the handshake begins.
    ///
    /// Under bundling every sender and receiver shares one transport, so all of these compare
    /// equal by [`id()`](crate::peer_connection::transport::RTCDtlsTransport::id).
    ///
    /// ## Specifications
    ///
    /// * [W3C](https://www.w3.org/TR/webrtc/#dom-rtcrtpsender-transport)
    pub fn transport(&self) -> Option<RTCDtlsTransport<'_>> {
        // `[[SenderTransport]]` is assigned when this sender's transceiver is associated by
        // negotiation — the point at which the transceiver acquires a mid. Before that the slot
        // is null, which is what the spec means by "prior to construction of the
        // `RTCDtlsTransport` object".
        self.peer_connection.rtp_transceivers[self.id.0]
            .mid()
            .as_ref()?;

        Some(RTCDtlsTransport {
            peer_connection: self.peer_connection,
        })
    }
    fn sender(&self) -> &internal::RTCRtpSenderInternal {
        // Every transceiver has a sender from its creation, and the handle borrows the peer
        // connection mutably, so the transceivers cannot change under it.
        self.peer_connection.rtp_transceivers[self.id.0]
            .sender()
            .as_ref()
            .expect("every transceiver has a sender")
    }

    fn sender_mut(&mut self) -> &mut internal::RTCRtpSenderInternal {
        self.peer_connection.rtp_transceivers[self.id.0]
            .sender_mut()
            .as_mut()
            .expect("every transceiver has a sender")
    }

    /// The track this sender sends (W3C `[[SenderTrack]]`), with the sender's encodings as
    /// its codings: `None` when the sender has no track, as after
    /// [`add_transceiver_from_kind`], [`remove_track`] or [`replace_track`]`(None)`.
    ///
    /// [`add_transceiver_from_kind`]: crate::peer_connection::RTCPeerConnection::add_transceiver_from_kind
    /// [`remove_track`]: crate::peer_connection::RTCPeerConnection::remove_track
    /// [`replace_track`]: Self::replace_track
    ///
    /// ## Specifications
    ///
    /// * [W3C](https://www.w3.org/TR/webrtc/#dom-rtcrtpsender-track)
    pub fn track(&self) -> Option<&MediaStreamTrack> {
        self.sender().attached_track()
    }

    /// The sender's track, to change the state the application owns (`enabled`, constraints).
    pub fn track_mut(&mut self) -> Option<&mut MediaStreamTrack> {
        self.sender_mut().attached_track_mut()
    }

    /// The SSRCs of the sender's encodings, whether or not it has a track. Empty for a
    /// sender that has not needed encodings yet (see
    /// [`ensure_transceiver_sender`](crate::peer_connection::RTCPeerConnection::ensure_transceiver_sender)).
    pub fn ssrcs(&self) -> impl Iterator<Item = crate::rtp_transceiver::SSRC> + '_ {
        self.sender()
            .send_encodings()
            .iter()
            .filter_map(|encoding| encoding.rtp_coding_parameters.ssrc)
    }

    /// The ids of the MediaStreams this sender's track is signalled in (W3C
    /// `[[AssociatedMediaStreamIds]]`), as [`set_streams`](Self::set_streams) or the track's
    /// own stream id set them; empty for none (the description then says `a=msid:-`).
    pub fn streams(&self) -> &[MediaStreamId] {
        self.sender().associated_streams()
    }

    /// The RTP capabilities of the engine for sending `kind`: every codec the media engine
    /// has registered for it (the retransmission format once, without an `sdpFmtpLine`) and
    /// the header extensions registered for sending. Nothing negotiated is read: the answer
    /// is the same before and after negotiation and for every sender (W3C
    /// `RTCRtpSender.getCapabilities`, a static method). `None` for a kind that is neither
    /// audio nor video.
    ///
    /// # Parameters
    ///
    /// * `kind` - The codec type (audio or video) to query capabilities for
    pub fn get_capabilities(&self, kind: RtpCodecKind) -> Option<RTCRtpCapabilities> {
        internal::RTCRtpSenderInternal::get_capabilities(kind, &self.peer_connection.media_engine)
    }

    /// Updates the RTP send parameters for this sender.
    ///
    /// `parameters` is what [`get_parameters`](Self::get_parameters) last returned, with the
    /// changes wanted in its encodings: `active`, `max_bitrate`, `max_framerate`,
    /// `scale_resolution_down_by` and `codec`.
    ///
    /// # Errors
    ///
    /// The W3C `setParameters` steps:
    /// - [`Error::InvalidStateError`] when the transceiver is stopping or stopped, or
    ///   `get_parameters` has not been called since the last `set_parameters`
    /// - [`Error::InvalidModificationError`] when the transaction id is not the one
    ///   `get_parameters` returned; when the number of encodings, their order, a rid or an
    ///   SSRC differs; when a read-only member (`header_extensions`, `rtcp`, `codecs`) was
    ///   changed; or when an encoding's `codec` was set to one that is not among the
    ///   negotiated send codecs (before negotiation: the codecs the engine can send)
    /// - [`Error::RangeError`] for a `scale_resolution_down_by` below 1.0 or a negative
    ///   `max_framerate`
    pub fn set_parameters(
        &mut self,
        parameters: RTCRtpSendParameters,
        set_parameter_options: Option<RTCSetParameterOptions>,
    ) -> Result<()> {
        // W3C webrtc 5.2 setParameters, step 4: a stopped (or stopping) transceiver's sender
        // takes no parameters.
        if self.peer_connection.rtp_transceivers[self.id.0].stopped() {
            return Err(Error::InvalidStateError);
        }
        self.peer_connection.rtp_transceivers[self.id.0]
            .sender_mut()
            .as_mut()
            .expect("every transceiver has a sender")
            .set_parameters(
                parameters,
                set_parameter_options,
                &self.peer_connection.media_engine,
            )
    }

    /// Returns the sender's current RTP send parameters.
    ///
    /// The returned parameters describe how the track is encoded and transmitted,
    /// including codecs, encodings, and header extensions. Calls until the next
    /// [`set_parameters`](Self::set_parameters) return the same parameters, with the same
    /// transaction id.
    pub fn get_parameters(&mut self) -> &RTCRtpSendParameters {
        self.peer_connection.rtp_transceivers[self.id.0]
            .sender_mut()
            .as_mut()
            .expect("every transceiver has a sender")
            .get_parameters(&self.peer_connection.media_engine)
    }

    /// Replaces the track this sender sends, without negotiation (W3C `replaceTrack`).
    ///
    /// `Some(track)`: the sender sends `track` from now on. Its encodings and their SSRCs,
    /// the `a=msid` it is signalled with and its associated streams are not changed, so no
    /// negotiation is needed; [`track`](Self::track) returns the new track with the sender's
    /// encodings as its codings. A sender that no description carries yet, or that has no
    /// encodings, takes the new track's own codings (the SSRCs the application chose) instead.
    ///
    /// `None`: the sender stops sending (an RTCP BYE goes out for each of its streams) and
    /// its track becomes null; [`write_rtp`](Self::write_rtp) is refused until it has a track
    /// again.
    ///
    /// # Errors
    ///
    /// - [`Error::ErrRTPSenderNewTrackHasIncorrectKind`] when the track is not of the
    ///   sender's kind (W3C `TypeError`)
    /// - [`Error::InvalidStateError`] when the transceiver is stopping or stopped
    ///
    /// ## Specifications
    ///
    /// * [W3C](https://www.w3.org/TR/webrtc/#dom-rtcrtpsender-replacetrack)
    pub fn replace_track(&mut self, track: Option<MediaStreamTrack>) -> Result<()> {
        self.peer_connection.replace_sender_track(self.id.0, track)
    }

    /// Sets the ids of the MediaStreams this sender's track is signalled in, to exactly
    /// `streams` without duplicates; an empty list is no stream (`a=msid:-`). The
    /// negotiation-needed flag is updated: a description has to carry the change.
    ///
    /// # Errors
    ///
    /// [`Error::ErrConnectionClosed`] when the connection is closed (W3C `InvalidStateError`).
    ///
    /// ## Specifications
    ///
    /// * [W3C](https://www.w3.org/TR/webrtc/#dom-rtcrtpsender-setstreams)
    pub fn set_streams(&mut self, streams: Vec<MediaStreamId>) -> Result<()> {
        if self.peer_connection.is_closed() {
            return Err(Error::ErrConnectionClosed);
        }
        self.sender_mut().set_streams(streams);
        // https://www.w3.org/TR/webrtc/#dom-rtcrtpsender-setstreams: update the
        // negotiation-needed flag.
        self.peer_connection
            .on_transceiver_stopped_or_streams_changed();
        Ok(())
    }

    /// Writes an RTP packet to the network.
    ///
    /// This method allows direct writing of RTP packets, automatically setting
    /// the correct payload type and SSRC based on the sender's configuration.
    ///
    /// When the MID header extension (`urn:ietf:params:rtp-hdrext:sdes:mid`) is negotiated,
    /// the packet is given the transceiver's mid, and when RtpStreamId
    /// (`urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id`) is, the rid of its encoding (RFC 9143
    /// section 15, RFC 8852): the application does not stamp them. A packet that already
    /// carries the extension keeps its value.
    ///
    /// # Parameters
    ///
    /// * `packet` - The RTP packet to send
    ///
    /// # Errors
    ///
    /// [`Error::ErrRTPSenderTrackRemoved`] after the sender's track was removed
    /// ([`remove_track`](crate::peer_connection::RTCPeerConnection::remove_track),
    /// [`replace_track`](Self::replace_track)`(None)`), until it has a track again. A sender
    /// made without a track for a sending transceiver is not refused: the engine makes no
    /// media of its own, and forwards what the application writes with the sender's SSRCs
    /// ([`ssrcs`](Self::ssrcs)). Otherwise
    /// returns an error if no matching encoding is found, the codec is unsupported (neither the
    /// packet's payload type nor its encoding's codec is negotiated on this sender leg), or
    /// internal handle_write returns error. A packet whose payload type is not negotiated is
    /// rewritten to its encoding's negotiated payload type.
    pub fn write_rtp(&mut self, now: Instant, mut packet: rtp::Packet) -> Result<()> {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized and
        // the direction won't be changed too, so, unwrap() here is safe.

        let mid = self.peer_connection.rtp_transceivers[self.id.0]
            .mid()
            .clone();
        let (sender, media_engine) = (
            self.peer_connection.rtp_transceivers[self.id.0]
                .sender_mut()
                .as_mut()
                .expect("every transceiver has a sender"),
            &mut self.peer_connection.media_engine,
        );

        if sender.track_removed() {
            return Err(Error::ErrRTPSenderTrackRemoved);
        }

        if !sender
            .track()
            .ssrcs()
            .any(|ssrc| ssrc == packet.header.ssrc)
        {
            return Err(Error::ErrSenderWithNoSSRCs);
        }

        let parameters = sender.get_parameters(media_engine);
        let (codecs, encodings) = (&parameters.rtp_parameters.codecs, &parameters.encodings);

        //From SSRC, find the encoding
        let encoding = encodings
            .iter()
            .find(|encoding| {
                encoding
                    .rtp_coding_parameters
                    .ssrc
                    .is_some_and(|s| s == packet.header.ssrc)
            })
            .ok_or(Error::ErrRTPSenderNoBaseEncoding)?;

        // W3C webrtc 5.2 RTCRtpEncodingParameters.active: an inactive encoding is not sent.
        if !encoding.active {
            trace!(
                "rtp_sender {:?} drops RTP ssrc {}: its encoding is inactive",
                self.id, packet.header.ssrc
            );
            return Ok(());
        }

        // Prefer the packet's negotiated payload type when it identifies a codec. Otherwise
        // fall back to the encoding's codec and rewrite the payload type to the one negotiated
        // for it, as before upstream's 8080cef3 removed the fallback (Brainwires fork keeps it;
        // the fork never narrows what an API accepts, see FORK.md).
        if !codecs
            .iter()
            .any(|codec| codec.payload_type == packet.header.payload_type)
        {
            // An encoding that names no codec is sent with the one negotiation picked, as its
            // stream is bound (`encoding_send_codec`); one that names a codec, with that codec.
            let Some(codec) = encoding_send_codec(&encoding.codec, codecs) else {
                trace!(
                    "rtp_sender {:?} rejecting RTP ssrc {} pt {}: no negotiated codec matches the packet or its encoding; sender codecs [{}]",
                    self.id,
                    packet.header.ssrc,
                    packet.header.payload_type,
                    codecs
                        .iter()
                        .map(|codec| format!(
                            "{}:{}",
                            codec.rtp_codec.mime_type, codec.payload_type
                        ))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                return Err(Error::ErrRTPTransceiverCodecUnsupported);
            };
            trace!(
                "rtp_sender {:?} rewriting RTP ssrc {} pt {} to the encoding's negotiated pt {}",
                self.id, packet.header.ssrc, packet.header.payload_type, codec.payload_type
            );
            packet.header.payload_type = codec.payload_type;
        }

        // Header extensions whose id is not negotiated on this leg are passed through, as before
        // upstream's 1f1b0874 made them an error (kept by the Brainwires fork, see FORK.md).
        if let Some(ext) = packet.header.extensions.iter().find(|ext| {
            !parameters
                .rtp_parameters
                .header_extensions
                .iter()
                .any(|negotiated| negotiated.id as u8 == ext.id)
        }) {
            trace!(
                "rtp_sender {:?} RTP ssrc {} carries header extension id {} that is not negotiated on this sender leg; passing it through",
                self.id, packet.header.ssrc, ext.id,
            );
        }

        // RFC 9143 sections 9.1 and 15: the offerer and answerer identify the m= section an
        // RTP stream belongs to with the MID header extension, and RFC 8852 section 3.3 / RFC
        // 8853 section 5.5 the encoding of a simulcast stream with RtpStreamId. Both go into
        // every packet the sender writes when the extension is negotiated: a receiver that
        // was not told the SSRC (the engine's descriptions name none for simulcast, and RFC
        // 9143 makes `a=ssrc` optional) needs one to associate the stream, at any time it
        // starts to listen or the SSRC changes. A value the application put there itself is
        // left alone. The NACK responder turns the RtpStreamId of a packet it retransmits
        // into RepairedRtpStreamId.
        let stamps = [
            (::sdp::extmap::SDES_MID_URI, mid.as_deref().unwrap_or("")),
            (
                ::sdp::extmap::SDES_RTP_STREAM_ID_URI,
                encoding.rtp_coding_parameters.rid.as_str(),
            ),
        ];
        for (uri, value) in stamps {
            if value.is_empty() {
                continue;
            }
            let Some(id) = parameters
                .rtp_parameters
                .header_extensions
                .iter()
                .find(|negotiated| negotiated.uri == uri)
                .and_then(|negotiated| u8::try_from(negotiated.id).ok())
            else {
                continue;
            };
            if packet.header.get_extension(id).is_none() {
                packet
                    .header
                    .set_extension(id, bytes::Bytes::copy_from_slice(value.as_bytes()))?;
            }
        }

        let track_id = sender.track().track_id().to_string();
        self.peer_connection.handle_write(TaggedRTCMessage {
            now,
            message: RTCMessage::RtpPacket(track_id, packet),
        })
    }

    /// Writes RTCP packets to the network.
    ///
    /// This method allows direct writing of sender-related RTCP reports such as
    /// Sender Reports (SR) or other feedback messages.
    ///
    /// # Parameters
    ///
    /// * `packets` - Vector of RTCP packets to send
    ///
    /// # Errors
    ///
    /// Returns an error if internal handle_write returns error
    pub fn write_rtcp(&mut self, now: Instant, packets: Vec<Box<dyn rtcp::Packet>>) -> Result<()> {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized and
        // the direction won't be changed too, so, unwrap() here is safe.

        let track_id = self.sender().track().track_id().to_string();
        self.peer_connection.handle_write(TaggedRTCMessage {
            now,
            message: RTCMessage::RtcpPacket(track_id, packets),
        })
    }
}
