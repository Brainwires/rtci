//! RTP Receiver implementation following the W3C WebRTC specification.
//!
//! This module provides the [`RTCRtpReceiver`] which represents an RTP receiver
//! as defined in the [W3C WebRTC specification](https://www.w3.org/TR/webrtc/#rtcrtpreceiver-interface).
//!
//! # Overview
//!
//! An RTP receiver manages the reception of media from a remote peer, providing:
//! - Access to the received media track
//! - RTP capabilities and receive parameters
//! - Contributing source (CSRC) and synchronization source (SSRC) information
//! - Statistics about received media
//!
//! # Examples
//!
//! ## Accessing the received track
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtci::peer_connection::RTCPeerConnectionBuilder;
//! # use rtci::media_stream::MediaStreamTrackId;
//! # use rtci::rtp_transceiver::RTCRtpReceiverId;
//! # fn example(
//! #     receiver_id: RTCRtpReceiverId,
//! #     track_id: MediaStreamTrackId
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // Get the receiver and access its track
//! if let Some(receiver) = peer_connection.rtp_receiver(receiver_id) {
//!     let track = receiver.track();
//!     println!("Track ID: {}", track.track_id());
//!     println!("Track kind: {:?}", track.kind());
//!     println!("Track enabled: {}", track.enabled());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Getting receive parameters
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtci::peer_connection::RTCPeerConnectionBuilder;
//! # use rtci::rtp_transceiver::RTCRtpReceiverId;
//! # fn example(receiver_id: RTCRtpReceiverId) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! if let Some(mut receiver) = peer_connection.rtp_receiver(receiver_id) {
//!     // Get current receive parameters
//!     let params = receiver.get_parameters();
//!     
//!     println!("Codecs: {:?}", params.rtp_parameters.codecs);
//!     println!("Header extensions: {:?}", params.rtp_parameters.header_extensions);
//!     println!("RTCP CNAME: {}", params.rtp_parameters.rtcp.cname);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Checking receiver capabilities
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtci::peer_connection::RTCPeerConnectionBuilder;
//! # use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;
//! # use rtci::rtp_transceiver::RTCRtpReceiverId;
//! # fn example(receiver_id: RTCRtpReceiverId) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! if let Some(receiver) = peer_connection.rtp_receiver(receiver_id) {
//!     // Check video capabilities
//!     if let Some(capabilities) = receiver.get_capabilities(RtpCodecKind::Video) {
//!         println!("Supported video codecs:");
//!         for codec in capabilities.codecs {
//!             println!("  - {} @ {} Hz", codec.mime_type, codec.clock_rate);
//!         }
//!     
//!         println!("Supported header extensions:");
//!         for ext in capabilities.header_extensions {
//!             println!("  - {}", ext.uri);
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Getting contributing sources
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtci::peer_connection::RTCPeerConnectionBuilder;
//! # use rtci::rtp_transceiver::RTCRtpReceiverId;
//! # fn example(receiver_id: RTCRtpReceiverId) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! if let Some(mut receiver) = peer_connection.rtp_receiver(receiver_id) {
//!     // Get CSRC information for mixed audio
//!     for csrc in receiver.get_contributing_sources() {
//!         println!("CSRC: {}, timestamp: {:?}", csrc.source, csrc.timestamp);
//!         println!("  Audio level: {:?}", csrc.audio_level);
//!         println!("  RTP timestamp: {}", csrc.rtp_timestamp);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Getting synchronization sources
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtci::peer_connection::RTCPeerConnectionBuilder;
//! # use rtci::rtp_transceiver::RTCRtpReceiverId;
//! # fn example(receiver_id: RTCRtpReceiverId) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! if let Some(mut receiver) = peer_connection.rtp_receiver(receiver_id) {
//!     // Get SSRC information
//!     for ssrc in receiver.get_synchronization_sources() {
//!         println!("SSRC: {}, timestamp: {:?}", ssrc.source, ssrc.timestamp);
//!         println!("  RTP timestamp: {}", ssrc.rtp_timestamp);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Handling incoming receivers
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtci::peer_connection::RTCPeerConnectionBuilder;
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // After remote description is set, collect receiver IDs first
//! let receiver_ids: Vec<_> = peer_connection.get_receivers().collect();
//!
//! // Then iterate and process each receiver
//! for receiver_id in receiver_ids {
//!     if let Some(receiver) = peer_connection.rtp_receiver(receiver_id) {
//!         // Access the remote track (track_id would come from signaling)
//!         // Process the incoming media as needed
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Specification
//!
//! * [W3C RTCRtpReceiver](https://www.w3.org/TR/webrtc/#rtcrtpreceiver-interface)
//! * [MDN RTCRtpReceiver](https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpReceiver)

#[cfg(test)]
mod rtp_receiver_test;

pub mod frame_metadata;
pub(crate) mod internal;
pub(crate) mod rtp_contributing_source;

use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use crate::peer_connection::transport::RTCDtlsTransport;
use crate::rtp_transceiver::RTCRtpReceiverId;
use crate::rtp_transceiver::rtp_sender::rtp_capabilities::RTCRtpCapabilities;
use crate::rtp_transceiver::rtp_sender::rtp_codec::RtpCodecKind;
use crate::rtp_transceiver::rtp_sender::rtp_receiver_parameters::RTCRtpReceiveParameters;
use sansio::Protocol;
use shared::error::Result;
use std::time::Instant;

pub use frame_metadata::{
    RTCEncodedAudioFrameMetadata, RTCEncodedFrameMetadata, RTCEncodedFrameMetadataKind,
    RTCEncodedVideoFrameMetadata, RTCEncodedVideoFrameType,
};
pub use rtp_contributing_source::{RTCRtpContributingSource, RTCRtpSynchronizationSource};

/// Represents an RTP receiver for a media stream track.
///
/// The `RTCRtpReceiver` interface allows an application to inspect the receipt of a
/// [`MediaStreamTrack`] as defined in the [W3C WebRTC specification](https://www.w3.org/TR/webrtc/#rtcrtpreceiver-interface).
///
/// # Lifetime
///
/// This struct borrows the [`RTCPeerConnection`] mutably, ensuring exclusive access
/// during RTP receiver operations.
pub struct RTCRtpReceiver<'a> {
    pub(crate) id: RTCRtpReceiverId,
    pub(crate) peer_connection: &'a mut RTCPeerConnection,
}

impl RTCRtpReceiver<'_> {
    /// The DTLS transport over which this receiver's RTP packets are received.
    ///
    /// ## Nullability
    ///
    /// `None` until this receiver's transceiver has been associated by negotiation. The spec
    /// sources this from the `[[ReceiverTransport]]` slot, which is per-receiver and is filled while
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
    /// * [W3C](https://www.w3.org/TR/webrtc/#dom-rtcrtpreceiver-transport)
    pub fn transport(&self) -> Option<RTCDtlsTransport<'_>> {
        // `[[ReceiverTransport]]` is assigned when this receiver's transceiver is associated by
        // negotiation — the point at which the transceiver acquires a mid. Before that the slot
        // is null, which is what the spec means by "prior to construction of the
        // `RTCDtlsTransport` object".
        let mid = self.peer_connection.rtp_transceivers[self.id.0]
            .mid()
            .as_ref()?;

        Some(RTCDtlsTransport {
            peer_connection: self.peer_connection,
            transport: self
                .peer_connection
                .pipeline_context
                .transports
                .transport_id_for(mid),
        })
    }
    /// The ids of the remote MediaStreams this receiver's track is in: one per `a=msid` line
    /// of the remote media section, in order, without the `-` that stands for no stream
    /// (RFC 8830 sections 2 and 3; W3C `[[AssociatedRemoteMediaStreams]]`, the `streams` of
    /// the track event). Empty until an answer is applied, and for a track in no stream.
    pub fn streams(&self) -> &[crate::media_stream::MediaStreamId] {
        self.peer_connection.rtp_transceivers[self.id.0]
            .receiver()
            .as_ref()
            .map_or(&[], |receiver| receiver.streams())
    }

    /// The receiver's track, mutably: what the application changes on it (`enabled`,
    /// `apply_constraints`, `stop`). Stopping it does not stop the receiver (W3C 5.3).
    pub fn track_mut(&mut self) -> &mut MediaStreamTrack {
        self.peer_connection.rtp_transceivers[self.id.0]
            .receiver_mut()
            .as_mut()
            .expect("every transceiver has a receiver")
            .track_mut()
    }

    /// Reports a video frame the application received on this receiver, `width` x `height`
    /// pixels, at `now`: its decoder, or a depacketizer that reads the frame size from a key
    /// frame, supplies it. The receiver's track then reports the frame's size, its aspect
    /// ratio and a frame-rate estimate from the frames of the last second in its settings
    /// (W3C webrtc-pc 9.3.1). Ignored for an audio receiver.
    pub fn report_received_frame(&mut self, now: Instant, width: u32, height: u32) {
        let receiver = self.peer_connection.rtp_transceivers[self.id.0]
            .receiver_mut()
            .as_mut()
            .expect("every transceiver has a receiver");
        if receiver.kind() == RtpCodecKind::Video {
            receiver.report_received_frame(now, width, height);
        }
    }

    /// Returns the track associated with this receiver.
    ///
    /// The [`track`](RTCRtpReceiver::track) method returns the [`MediaStreamTrack`] that is
    /// associated with this receiver as specified in the [W3C WebRTC specification](https://www.w3.org/TR/webrtc/#dom-rtpreceiver-track).
    ///
    /// # Returns
    ///
    /// Returns a reference to the [`MediaStreamTrack`] associated with this receiver.
    pub fn track(&self) -> &MediaStreamTrack {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized and
        // the direction won't be changed too, so, unwrap() here is safe.
        self.peer_connection.rtp_transceivers[self.id.0]
            .receiver()
            .as_ref()
            .unwrap()
            .track()
    }

    /// The RTP capabilities of the engine for receiving `kind`: every codec the media engine
    /// has registered for it (the retransmission format once, without an `sdpFmtpLine`) and
    /// the header extensions registered for receiving. Nothing negotiated is read (W3C
    /// `RTCRtpReceiver.getCapabilities`, a static method). `None` for a kind that is neither
    /// audio nor video.
    ///
    /// # Parameters
    ///
    /// * `kind` - The codec kind (audio or video)
    pub fn get_capabilities(&self, kind: RtpCodecKind) -> Option<RTCRtpCapabilities> {
        internal::RTCRtpReceiverInternal::get_capabilities(kind, &self.peer_connection.media_engine)
    }

    /// An H.264 depacketizer for `codec` (one of this receiver's negotiated codecs, whose
    /// fmtp line is the sender's) built with the connection's de-interleaving settings
    /// ([`MediaEngine::h264_depacketizer`]): under the `StrictRfc` behaviour profile an
    /// interleaved stream's PDON starts at 0 as RFC 6184 section 7.2.2 has it; by default it
    /// does not, a departure from that section ([`MediaEngine::set_h264_literal_pdon`]).
    ///
    /// [`MediaEngine::h264_depacketizer`]: crate::peer_connection::configuration::media_engine::MediaEngine::h264_depacketizer
    /// [`MediaEngine::set_h264_literal_pdon`]: crate::peer_connection::configuration::media_engine::MediaEngine::set_h264_literal_pdon
    ///
    /// # Errors
    ///
    /// As [`RTCRtpCodec::h264_depacketizer`](crate::rtp_transceiver::rtp_sender::RTCRtpCodec::h264_depacketizer).
    pub fn h264_depacketizer(
        &self,
        codec: &crate::rtp_transceiver::rtp_sender::RTCRtpCodec,
    ) -> Result<rtp::codec::h264::H264Packet> {
        self.peer_connection.media_engine.h264_depacketizer(codec)
    }

    /// The jitter buffer target the application asked for (W3C `jitterBufferTarget`): `None`
    /// (null) leaves the delay to the engine.
    ///
    /// The engine keeps the value for the application's jitter buffer to read; the jitter
    /// buffer interceptors take their delay when they are built.
    pub fn jitter_buffer_target(&self) -> Option<std::time::Duration> {
        self.peer_connection.rtp_transceivers[self.id.0]
            .receiver()
            .as_ref()
            .and_then(|receiver| receiver.jitter_buffer_target())
    }

    /// Sets the jitter buffer target; `None` resets it to the engine's choice.
    ///
    /// # Errors
    ///
    /// [`Error::RangeError`](shared::error::Error::RangeError) for a target above 4000
    /// milliseconds (a `Duration` cannot be negative, the other value W3C refuses); the
    /// stored target is then unchanged.
    pub fn set_jitter_buffer_target(&mut self, target: Option<std::time::Duration>) -> Result<()> {
        self.receiver_mut().set_jitter_buffer_target(target)?;
        // "Update the underlying system about the new target": the jitter buffer of the
        // interceptor chain (`AdaptiveJitterBufferInterceptor`) holds the receiver's streams
        // for it, clamped to its minimum and maximum delay; a stream that appears later is
        // given it with its first packet (`record_sources`).
        let ssrcs: Vec<u32> = self.receiver().track().ssrcs().collect();
        if !ssrcs.is_empty() {
            let now = self.peer_connection.pipeline_context.now;
            self.peer_connection.interceptor.handle_write(
                interceptor::JitterBufferControl { ssrcs, target }.into_packet(now),
            )?;
        }
        Ok(())
    }

    /// Returns the RTP receive parameters for this receiver.
    ///
    /// The [`get_parameters`](RTCRtpReceiver::get_parameters) method returns the current parameters
    /// for how the receiver's track is decoded as defined in the
    /// [W3C WebRTC specification](https://www.w3.org/TR/webrtc/#dom-rtcrtpreceiver-getparameters).
    ///
    /// # Returns
    ///
    /// Returns a reference to the RTP receive parameters.
    pub fn get_parameters(&mut self) -> &RTCRtpReceiveParameters {
        use crate::rtp_transceiver::RTCRtpTransceiverDirection;
        // W3C 4.4.1.4: once a description negotiated a direction without receiving
        // (sendonly, inactive), [[ReceiveCodecs]] is empty.
        let transceiver = &mut self.peer_connection.rtp_transceivers[self.id.0];
        let receiving = !matches!(
            transceiver.current_direction(),
            RTCRtpTransceiverDirection::Sendonly | RTCRtpTransceiverDirection::Inactive
        );
        let negotiated = transceiver.negotiated_header_extensions().to_vec();
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized and
        // the direction won't be changed too, so, unwrap() here is safe.
        transceiver
            .receiver_mut()
            .as_mut()
            .unwrap()
            .get_public_parameters(&self.peer_connection.media_engine, &negotiated, receiving)
    }

    /// Returns an iterator over the contributing sources for this receiver.
    ///
    /// The [`get_contributing_sources`](RTCRtpReceiver::get_contributing_sources) method returns
    /// information about the contributing sources (CSRCs) for the most recent RTP packets
    /// received by this receiver as defined in the
    /// [W3C WebRTC specification](https://www.w3.org/TR/webrtc/#dom-rtcrtpreceiver-getcontributingsources).
    ///
    /// Contributing sources represent mixers or other entities that have contributed to the
    /// RTP stream.
    ///
    /// # Returns
    ///
    /// Returns an iterator over [`RTCRtpContributingSource`] objects.
    pub fn get_contributing_sources(&self) -> impl Iterator<Item = &RTCRtpContributingSource> {
        let now = self.sources_now();
        self.peer_connection.rtp_transceivers[self.id.0]
            .receiver()
            .as_ref()
            .expect("every transceiver has a receiver")
            .live_contributing_sources(now)
    }

    /// The wall-clock time (since the Unix epoch) of the newest instant the connection has
    /// been given, which the sources' timestamps are compared with: a source not heard in the
    /// ten seconds before it is not listed.
    fn sources_now(&self) -> std::time::Duration {
        let context = &self.peer_connection.pipeline_context;
        context
            .interceptor_handler_context
            .wall_clock
            .map(|wall_clock| wall_clock.unix(context.now))
            .unwrap_or_default()
    }

    /// Returns an iterator over the synchronization sources for this receiver.
    ///
    /// The [`get_synchronization_sources`](RTCRtpReceiver::get_synchronization_sources) method
    /// returns information about the synchronization sources (SSRCs) for the most recent RTP
    /// packets received by this receiver as defined in the
    /// [W3C WebRTC specification](https://www.w3.org/TR/webrtc/#dom-rtcrtpreceiver-getsynchronizationsources).
    ///
    /// Synchronization sources represent the original sources of the RTP packets.
    ///
    /// # Returns
    ///
    /// Returns an iterator over [`RTCRtpSynchronizationSource`] objects.
    pub fn get_synchronization_sources(
        &self,
    ) -> impl Iterator<Item = &RTCRtpSynchronizationSource> {
        let now = self.sources_now();
        self.peer_connection.rtp_transceivers[self.id.0]
            .receiver()
            .as_ref()
            .expect("every transceiver has a receiver")
            .live_synchronization_sources(now)
    }

    /// Writes RTCP feedback packets for this receiver.
    ///
    /// This method allows sending receiver-side RTCP feedback such as:
    /// - Receiver Reports (RR)
    /// - Picture Loss Indication (PLI)
    /// - Full Intra Request (FIR)
    /// - Negative Acknowledgements (NACK)
    ///
    /// # Parameters
    ///
    /// * `packets` - A vector of RTCP packets to send
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the packets were queued successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if internal handle_write returns error
    ///
    /// # Examples
    ///
    /// ```
    /// // Send a Picture Loss Indication to request a keyframe
    /// use rtci::peer_connection::RTCPeerConnection;
    /// use rtci::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
    /// use rtci::rtp_transceiver::RTCRtpReceiverId;
    /// use std::time::Instant;
    ///
    /// # fn example(
    /// #     peer_connection: &mut RTCPeerConnection,
    /// #     receiver_id: RTCRtpReceiverId,
    /// #     remote_ssrc: u32,
    /// # ) -> Result<(), Box<dyn std::error::Error>> {
    /// if let Some(mut receiver) = peer_connection.rtp_receiver(receiver_id) {
    ///     let pli = PictureLossIndication {
    ///         sender_ssrc: 0,
    ///         media_ssrc: remote_ssrc,
    ///     };
    ///     receiver.write_rtcp(Instant::now(), vec![Box::new(pli)])?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn write_rtcp(&mut self, now: Instant, packets: Vec<Box<dyn rtcp::Packet>>) -> Result<()> {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized and
        // the direction won't be changed too, so, unwrap() here is safe.

        let receiver = self.peer_connection.rtp_transceivers[self.id.0]
            .receiver_mut()
            .as_mut()
            .unwrap();

        // RFC 4585 section 4.2, RFC 5104 section 7.2: only the feedback the section negotiated.
        let codecs = receiver.get_codec_preferences();
        if !self
            .peer_connection
            .setting_engine
            .unnegotiated_rtcp_feedback
            && !codecs.is_empty()
            && let Some((typ, parameter)) =
                crate::rtp_transceiver::rtp_sender::rtp_codec::unnegotiated_feedback(
                    &packets, codecs,
                )
        {
            return Err(shared::error::Error::ErrRTCPFeedbackNotNegotiated(
                typ.to_owned(),
                parameter.to_owned(),
            ));
        }

        let track_id = receiver.track().track_id().to_string();
        self.peer_connection.handle_write(TaggedRTCMessage {
            now,
            message: RTCMessage::RtcpPacket(track_id, packets),
        })
    }

    /// W3C webrtc-encoded-transform 4, `getMetadata()` of a received encoded frame: the
    /// metadata of the frame the application reassembled from `packets`, the RTP packets
    /// `poll_read` delivered for it (one SSRC and RTP timestamp, in sequence number order).
    ///
    /// From the packets: `synchronizationSource`, `payloadType`, `contributingSources`,
    /// `rtpTimestamp`, `mimeType` (the codec negotiated for the payload type), an audio
    /// frame's `sequenceNumber` and `audioLevel` (RFC 6464, linear), a video frame's type,
    /// size and layer indices from the payload (see [`RTCEncodedVideoFrameMetadata`]). From
    /// what the receiver recorded as the packets passed: `receiveTime`, `captureTime` and
    /// `senderCaptureTimeOffset`, and the Dependency Descriptor's `frameId` and
    /// `dependencies`.
    ///
    /// # Errors
    ///
    /// `TypeError` when `packets` is empty or its packets are not of one frame (different
    /// SSRCs or RTP timestamps).
    pub fn encoded_frame_metadata(
        &mut self,
        packets: &[rtp::Packet],
    ) -> Result<RTCEncodedFrameMetadataKind> {
        let Some(first) = packets.first() else {
            return Err(shared::error::Error::TypeError(
                "a frame has at least one packet".to_owned(),
            ));
        };
        if packets.iter().any(|p| {
            p.header.ssrc != first.header.ssrc || p.header.timestamp != first.header.timestamp
        }) {
            return Err(shared::error::Error::TypeError(
                "the packets of a frame share their SSRC and RTP timestamp".to_owned(),
            ));
        }
        let media_engine = &self.peer_connection.media_engine;
        let (mime_type, kind, clock_rate) =
            match media_engine.get_codec_by_payload(first.header.payload_type) {
                Ok((codec, kind)) => (
                    codec.rtp_codec.mime_type.clone(),
                    kind,
                    codec.rtp_codec.clock_rate,
                ),
                // A format only this endpoint's pending offer lists for the section (RFC
                // 3264 section 5.1: its media may arrive before the answer negotiates it).
                Err(_) => {
                    let receiver = self.receiver();
                    receiver
                        .receivable_codecs()
                        .find(|codec| codec.payload_type == first.header.payload_type)
                        .map(|codec| {
                            (
                                codec.rtp_codec.mime_type.clone(),
                                receiver.kind(),
                                codec.rtp_codec.clock_rate,
                            )
                        })
                        .unwrap_or_else(|| (String::new(), receiver.kind(), 0))
                }
            };
        // webrtc-extensions 15: the remote capture timestamp, by the stream's sender reports.
        let remote_capture =
            |frame: &mut frame_metadata::RTCEncodedFrameMetadata,
             stats: &crate::statistics::accumulator::RTCStatsAccumulator| {
                let capture_ntp = frame
                    .capture_time
                    .map(|ms| (ms + frame.sender_capture_time_offset.unwrap_or(0.0)) / 1000.0);
                frame.remote_capture_time = stats
                    .inbound_rtp_streams
                    .get(&frame.synchronization_source)
                    .and_then(|stream| {
                        stream.remote_capture_instant(frame.rtp_timestamp, clock_rate, capture_ntp)
                    });
            };
        // RFC 8834 section 10: only an extension the section negotiated for receiving is read.
        let reads = |uri: &str| self.receiver().reads_header_extension(uri);
        let extension_payloads = |uri: &str| -> Vec<bytes::Bytes> {
            if !reads(uri) {
                return vec![];
            }
            let (id, audio, video) = media_engine.get_header_extension_id(
                crate::rtp_transceiver::rtp_sender::RTCRtpHeaderExtensionCapability {
                    uri: uri.to_owned(),
                },
            );
            if id == 0 || !(audio || video) {
                return vec![];
            }
            packets
                .iter()
                .filter_map(|p| p.header.get_extension(id as u8))
                .collect()
        };
        if kind == RtpCodecKind::Audio {
            // RFC 6464: the level octet's low seven bits, -dBov; the frame's last level.
            let audio_level = extension_payloads(::sdp::extmap::AUDIO_LEVEL_URI)
                .last()
                .and_then(|payload| payload.first().copied())
                .map(internal::linear_audio_level);
            let mut frame = self
                .receiver()
                .frame_records()
                .common(&first.header, mime_type);
            remote_capture(&mut frame, &self.peer_connection.pipeline_context.stats);
            return Ok(RTCEncodedFrameMetadataKind::Audio(
                RTCEncodedAudioFrameMetadata {
                    frame,
                    sequence_number: Some(first.header.sequence_number),
                    audio_level,
                },
            ));
        }

        let descriptor =
            extension_payloads(rtp::codec::dependency_descriptor::DEPENDENCY_DESCRIPTOR_URI)
                .first()
                .and_then(|payload| {
                    rtp::codec::dependency_descriptor::DependencyDescriptor::unmarshal_mandatory(
                        payload,
                    )
                    .ok()
                });
        // At most one packet of a frame carries the corruption detection message.
        let corruption_detection = extension_payloads(rtp::extension::CORRUPTION_DETECTION_URI)
            .first()
            .and_then(|payload| {
                use shared::marshal::Unmarshal;
                rtp::extension::corruption_detection_extension::CorruptionDetectionExtension::unmarshal(
                    &mut payload.as_ref(),
                )
                .ok()
            });
        let payloads: Vec<&bytes::Bytes> = packets.iter().map(|p| &p.payload).collect();
        let info = frame_metadata::inspect_video_payloads(&mime_type, &payloads);
        let ssrc = first.header.ssrc;
        let receiver = self.receiver_mut();
        let described = descriptor
            .and_then(|(_, _, _, frame_number)| {
                receiver.frame_records().described_frame(ssrc, frame_number)
            })
            .cloned();
        let mut frame = receiver.frame_records().common(&first.header, mime_type);
        let spatial_index = described
            .as_ref()
            .map(|d| d.spatial_id)
            .or(info.spatial_id)
            .map(u32::from);
        let size = receiver.frame_records_mut().size(
            ssrc,
            spatial_index.unwrap_or(0),
            described.as_ref().and_then(|d| d.resolution).or(info.size),
            &info.layer_sizes,
        );
        let frame_type = if packets.iter().all(|p| p.payload.is_empty()) {
            RTCEncodedVideoFrameType::Empty
        } else {
            match info
                .key_frame
                .or(described.as_ref().map(|d| d.structure_attached))
            {
                Some(true) => RTCEncodedVideoFrameType::Key,
                _ => RTCEncodedVideoFrameType::Delta,
            }
        };
        remote_capture(&mut frame, &self.peer_connection.pipeline_context.stats);
        Ok(RTCEncodedFrameMetadataKind::Video(
            RTCEncodedVideoFrameMetadata {
                frame,
                frame_type,
                frame_id: described.as_ref().map(|d| d.frame_id),
                dependencies: described
                    .as_ref()
                    .map(|d| d.dependencies.clone())
                    .unwrap_or_default(),
                width: size.map(|s| s.0),
                height: size.map(|s| s.1),
                spatial_index,
                temporal_index: described
                    .as_ref()
                    .map(|d| d.temporal_id)
                    .or(info.temporal_id)
                    .map(u32::from),
                corruption_detection,
            },
        ))
    }

    /// webrtc-encoded-transform 6.5 "send request key frame" (`sendKeyFrameRequest()` of a
    /// receiver's transform): sends a Full Intra Request (RFC 5104 4.3.1) for the streams
    /// this receiver receives.
    ///
    /// Returns whether one was sent. Nothing is sent, and the request resolves, when a FIR is
    /// not appropriate: the transceiver is stopped or does not receive by the current
    /// description, no stream has arrived yet, or `ccm fir` was not negotiated for the
    /// receiver's codecs (RFC 5104 section 7: a CCM message is sent only when negotiated).
    ///
    /// # Errors
    ///
    /// `InvalidStateError` for a receiver that is not a video receiver.
    pub fn send_key_frame_request(&mut self, now: Instant) -> Result<bool> {
        use rtcp::payload_feedbacks::full_intra_request::{FirEntry, FullIntraRequest};
        if self.receiver().kind() != RtpCodecKind::Video {
            return Err(shared::error::Error::InvalidStateError);
        }
        let transceiver = &self.peer_connection.rtp_transceivers[self.id.0];
        let receiving = !transceiver.stopped() && transceiver.current_direction().has_recv();
        let fir_negotiated = self.receiver().get_codec_preferences().iter().any(|codec| {
            codec
                .rtp_codec
                .rtcp_feedback
                .iter()
                .any(|fb| fb.typ == "ccm" && fb.parameter == "fir")
        });
        let ssrcs: Vec<u32> = self.receiver().track().ssrcs().collect();
        if !receiving || !fir_negotiated || ssrcs.is_empty() {
            return Ok(false);
        }
        let sender_ssrc = transceiver
            .sender()
            .as_ref()
            .and_then(|s| s.send_encodings().first())
            .and_then(|e| e.rtp_coding_parameters.ssrc)
            .unwrap_or(0);
        let sequence_number = self.receiver_mut().next_fir_sequence_number();
        let fir = FullIntraRequest {
            sender_ssrc,
            media_ssrc: 0,
            fir: ssrcs
                .into_iter()
                .map(|ssrc| FirEntry {
                    ssrc,
                    sequence_number,
                })
                .collect(),
        };
        self.write_rtcp(now, vec![Box::new(fir)])?;
        Ok(true)
    }

    fn receiver(&self) -> &internal::RTCRtpReceiverInternal {
        self.peer_connection.rtp_transceivers[self.id.0]
            .receiver()
            .as_ref()
            .expect("every transceiver has a receiver")
    }

    fn receiver_mut(&mut self) -> &mut internal::RTCRtpReceiverInternal {
        self.peer_connection.rtp_transceivers[self.id.0]
            .receiver_mut()
            .as_mut()
            .expect("every transceiver has a receiver")
    }

    /// Asks the remote sender of this receiver's streams to keep its media under `bitrate`
    /// bits per second (total media bit rate at the IP layer), or lifts that limit with
    /// `None`: RFC 5104 TMMBR, sent by the congestion control interceptor
    /// (`interceptor::TmmbrControl::{Limit, Clear}`), repeated until the sender acknowledges
    /// it with a TMMBN.
    ///
    /// Only effective for a stream that negotiated `a=rtcp-fb:<pt> ccm tmmbr` (RFC 5104
    /// section 7.2: no CCM message is sent that was not negotiated) and with the default
    /// interceptors (their congestion control interceptor holds the request state); otherwise
    /// nothing is sent. The limit applies to every SSRC the receiver's track receives.
    pub fn set_remote_bitrate_limit(&mut self, now: Instant, bitrate: Option<u64>) -> Result<()> {
        let ssrcs: Vec<u32> = self.peer_connection.rtp_transceivers[self.id.0]
            .receiver()
            .as_ref()
            .map(|receiver| receiver.track().ssrcs().collect())
            .unwrap_or_default();
        for media_ssrc in ssrcs {
            let control = match bitrate {
                Some(bitrate) => interceptor::TmmbrControl::Limit {
                    media_ssrc,
                    bitrate,
                },
                None => interceptor::TmmbrControl::Clear { media_ssrc },
            };
            self.peer_connection
                .interceptor
                .handle_write(control.into_packet(now))?;
        }
        Ok(())
    }

    /// Tells the NACK generator the oldest sequence number of the received stream `ssrc` that
    /// the application can still use, or removes that horizon with `None`. RFC 4588 6.3: "the
    /// receiver should generally assess whether the retransmitted packet would still be useful
    /// at the time it is received". A video pipeline that has released or given up every frame
    /// before `oldest_useful` gives it here after each frame, and the generator
    /// (`interceptor::NackControl::Horizon`) no longer asks for missing packets older than it;
    /// newer ones are asked for as before. A request for an older packet that still waits in
    /// the RTCP session for its packet (RFC 4585 3.5.2) is dropped there, so no NACK sent
    /// after this call names a packet before `oldest_useful`. Sequence numbers compare with wrap-around (RFC 3550
    /// A.1), so the horizon is to be moved on as playout advances.
    ///
    /// Only effective with the default interceptors (their NACK generator holds the request
    /// state). An SSRC this receiver's track does not receive is ignored.
    pub fn set_nack_horizon(
        &mut self,
        now: Instant,
        ssrc: u32,
        oldest_useful: Option<u16>,
    ) -> Result<()> {
        let received = self.peer_connection.rtp_transceivers[self.id.0]
            .receiver()
            .as_ref()
            .is_some_and(|receiver| receiver.track().ssrcs().any(|s| s == ssrc));
        if !received {
            return Ok(());
        }
        self.peer_connection.interceptor.handle_write(
            interceptor::NackControl::Horizon {
                media_ssrc: ssrc,
                oldest_useful,
            }
            .into_packet(now),
        )
    }
}
