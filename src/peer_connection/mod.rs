//! Peer-to-peer connections
//!
//! This module implements the `RTCPeerConnection` interface as defined in the
//! [W3C WebRTC specification](https://www.w3.org/TR/webrtc/). It provides
//! the core functionality for establishing peer-to-peer connections, negotiating
//! media capabilities, and managing data channels.
//!
//! # Overview
//!
//! `RTCPeerConnection` is the central interface in WebRTC. It handles:
//!
//! - **Signaling**: Creating and exchanging SDP offers/answers
//! - **ICE**: Gathering candidates and establishing connectivity
//! - **Media**: Managing audio/video tracks and transceivers
//! - **Data**: Creating and managing data channels
//! - **Security**: DTLS encryption for all communication
//!
//! # Architecture
//!
//! This is a **sans-I/O** implementation, meaning it separates protocol logic
//! from I/O operations. The application is responsible for:
//!
//! - Transmitting/receiving network packets
//! - Managing the event loop
//! - Handling signaling channel communication
//!
//! ## Sans-I/O Benefits
//!
//! - **Flexibility**: Works with any I/O runtime (tokio, async-std, blocking, etc.)
//! - **Testability**: Protocol logic can be tested without network I/O
//! - **Control**: Application has full control over threading and scheduling
//!
//! # Connection Establishment
//!
//! The typical WebRTC connection flow:
//!
//! ```text
//! Peer A (Offerer)              Signaling Server              Peer B (Answerer)
//! ════════════════              ════════════════              ═══════════════════
//!      │                               │                               │
//!      │ 1. create_offer()             │                               │
//!      │─────────────────┐             │                               │
//!      │                 │             │                               │
//!      │<────────────────┘             │                               │
//!      │                               │                               │
//!      │ 2. set_local_description()    │                               │
//!      │─────────────────┐             │                               │
//!      │                 │             │                               │
//!      │<────────────────┘             │                               │
//!      │                               │                               │
//!      │ 3. send offer (via signaling) │                               │
//!      │──────────────────────────────>│──────────────────────────────>│
//!      │                               │                               │
//!      │                               │  4. set_remote_description()  │
//!      │                               │                  ┌────────────┤
//!      │                               │                  │            │
//!      │                               │                  └───────────>│
//!      │                               │                               │
//!      │                               │       5. create_answer()      │
//!      │                               │                  ┌────────────┤
//!      │                               │                  │            │
//!      │                               │                  └───────────>│
//!      │                               │                               │
//!      │                               │  6. set_local_description()   │
//!      │                               │                  ┌────────────┤
//!      │                               │                  │            │
//!      │                               │                  └───────────>│
//!      │                               │                               │
//!      │ 7. receive answer             │<──────────────────────────────│
//!      │<──────────────────────────────┤                               │
//!      │                               │                               │
//!      │ 8. set_remote_description()   │                               │
//!      │─────────────────┐             │                               │
//!      │                 │             │                               │
//!      │<────────────────┘             │                               │
//!      │                               │                               │
//!      │ 9. ICE candidates exchanged   │                               │
//!      │<─────────────────────────────────────────────────────────────>│
//!      │                               │                               │
//!      │ 10. Media/data flows directly │                               │
//!      │<═════════════════════════════════════════════════════════════>│
//! ```
//!
//! # Examples
//!
//! ## Creating a Peer Connection
//!
//! ```
//! # use std::time::Instant;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create with default configuration
//! let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Creating an Offer (Initiating Peer)
//!
//! ```no_run
//! # use std::time::Instant;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // Add media track or data channel first
//! // pc.add_track(audio_track)?;
//!
//! // Create offer
//! let offer = pc.create_offer(None)?;
//!
//! // Set as local description
//! pc.set_local_description(Instant::now(), offer.clone())?;
//!
//! // Send offer.sdp to remote peer via signaling channel
//! // signaling_channel.send(offer.sdp)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Answering an Offer (Responding Peer)
//!
//! ```no_run
//! # use std::time::Instant;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//! use rtc::peer_connection::sdp::RTCSessionDescription;
//!
//! # fn example(remote_offer_sdp: String) -> Result<(), Box<dyn std::error::Error>> {
//! let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // Receive offer from remote peer
//! let offer = RTCSessionDescription::offer(remote_offer_sdp)?;
//!
//! // Set as remote description
//! pc.set_remote_description(Instant::now(), offer)?;
//!
//! // Create answer
//! let answer = pc.create_answer(None)?;
//!
//! // Set as local description
//! pc.set_local_description(Instant::now(), answer.clone())?;
//!
//! // Send answer.sdp to remote peer via signaling channel
//! // signaling_channel.send(answer.sdp)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Adding Media Tracks
//!
//! ```no_run
//! # use std::time::Instant;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//! use rtc::media_stream::MediaStreamTrack;
//! use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
//!
//! # fn example(audio_track: MediaStreamTrack) -> Result<(), Box<dyn std::error::Error>> {
//! let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // Add an audio track
//! let sender_id = pc.add_track(audio_track)?;
//!
//! // Or add a transceiver for receiving
//! let transceiver_id = pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Creating Data Channels
//!
//! ```no_run
//! # use std::time::Instant;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//! use rtc::data_channel::RTCDataChannelInit;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // Create a reliable, ordered data channel
//! let init = RTCDataChannelInit {
//!     ordered: true,
//!     max_retransmits: None,
//!     ..Default::default()
//! };
//!
//! let channel_id = pc.create_data_channel("my-channel", Some(init))?;
//! # Ok(())
//! # }
//! ```
//!
//! ## ICE Candidate Exchange
//!
//! ```no_run
//! use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
//! use rtc::peer_connection::transport::RTCIceCandidateInit;
//!
//! # fn example(mut pc: RTCPeerConnection) -> Result<(), Box<dyn std::error::Error>> {
//! // When local candidates are gathered, send to remote peer
//! // (In sans-I/O, you'd poll for events to get candidates)
//!
//! // When receiving remote candidate from signaling channel
//! let remote_candidate = RTCIceCandidateInit {
//!     candidate: "candidate:1 1 UDP 2130706431 192.168.1.100 54321 typ host".to_string(),
//!     ..Default::default()
//! };
//!
//! pc.add_remote_candidate(remote_candidate)?;
//! # Ok(())
//! # }
//! ```
//!
//! # State Management
//!
//! The peer connection maintains several state machines:
//!
//! - **Signaling State**: SDP negotiation progress (stable, have-local-offer, etc.)
//! - **ICE Connection State**: Network connectivity status
//! - **ICE Gathering State**: Candidate gathering progress
//! - **Connection State**: Overall connection health
//!
//! Monitor these states through the event system (sans-I/O polling).
//!
//! # Thread Safety
//!
//! `RTCPeerConnection` is **not** thread-safe. The application must ensure
//! exclusive access or use appropriate synchronization primitives.
//!
//! # Specification
//!
//! - [W3C WebRTC 1.0] - Main specification
//! - [RFC 9429] - JSEP: JavaScript Session Establishment Protocol
//! - [RFC 8866] - SDP: Session Description Protocol
//! - [RFC 8445] - ICE: Interactive Connectivity Establishment
//! - [RFC 8831] - WebRTC Data Channels
//!
//! [W3C WebRTC 1.0]: https://www.w3.org/TR/webrtc/
//! [RFC 9429]: https://datatracker.ietf.org/doc/html/rfc9429
//! [RFC 8866]: https://datatracker.ietf.org/doc/html/rfc8866
//! [RFC 8445]: https://datatracker.ietf.org/doc/html/rfc8445
//! [RFC 8831]: https://datatracker.ietf.org/doc/html/rfc8831

pub mod certificate;
pub mod configuration;
pub mod cryptex;
mod dtls_sdp;
pub mod event;
pub(crate) mod handler;
mod internal;
mod object_model;
pub mod priority;
mod remote_tracks;
pub mod rtc_error;
mod states_events;
// wpt100:hdrext
mod always_negotiate;
pub mod message;
pub mod sdp;
#[cfg(test)]
mod set_configuration_test;
#[cfg(test)]
mod set_description_atomic_test;
#[cfg(test)]
mod set_remote_description_test;
pub mod state;
pub mod transport;
#[cfg(test)]
mod upstream_peer_connection_test;
#[cfg(test)]
pub(crate) mod util_test;

use crate::data_channel::init::RTCDataChannelInit;
use crate::data_channel::parameters::DataChannelParameters;
use crate::data_channel::registry::DataChannelRegistry;
use crate::data_channel::state::RTCDataChannelState;
use crate::data_channel::{RTCDataChannel, RTCDataChannelId, internal::RTCDataChannelInternal};
use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::peer_connection::configuration::setting_engine::SettingEngine;
use crate::peer_connection::configuration::{
    RTCConfiguration, RTCIceTransportPolicy,
    offer_answer_options::{RTCAnswerOptions, RTCOfferOptions},
};
use crate::peer_connection::handler::PipelineContext;
use crate::peer_connection::handler::dtls::DtlsHandlerContext;
use crate::peer_connection::handler::ice::IceHandlerContext;
use crate::peer_connection::handler::sctp::SctpHandlerContext;
use crate::peer_connection::sdp::MediaDescriptionExt;
use crate::peer_connection::sdp::section_multiplexes_rtcp;
use crate::peer_connection::sdp::session_description::RTCSessionDescription;
use crate::peer_connection::sdp::{
    ATTR_KEY_RTCP_MUX_ONLY, RemoteIceDetails, SctpNegotiation, candidate_line_ufrag,
    check_answer_against_offer, check_extmap_ids, check_extmap_levels,
    codecs_from_media_description, discard_stray_bundle_only, effective_direction,
    extract_fingerprints, extract_ice_details, extract_tls_id, get_mid_value, get_peer_direction,
    has_ice_trickle_option, has_rtcp_mux, has_rtp_media, inherit_session_extmap,
    inherit_session_rtcp_xr, insert_media_line, is_lite_set, is_live_rtp_section,
    is_rejected_media, is_sdp_token, is_unknown_application_media, media_ice_credentials,
    negotiated_sctp, remap_answerer_assigned_extmaps, remote_candidates, remote_ice_options,
    remote_ice_pacing, sdp_type::RTCSdpType, update_sdp_origin, validate_application_media_section,
    validate_dtls_attributes,
};
use crate::peer_connection::state::RTCIceGatheringState;
use crate::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use crate::peer_connection::state::peer_connection_state::{
    NegotiationNeededState, RTCPeerConnectionState,
};
use crate::peer_connection::state::signaling_state::{RTCSignalingState, StateChangeOp};
use crate::peer_connection::transport::RTCSctpTransport;
use crate::peer_connection::transport::dtls::fingerprint::{
    RTCDtlsFingerprint, preferred_fingerprints,
};
use crate::peer_connection::transport::dtls::parameters::RTCDtlsParameters;
use crate::peer_connection::transport::dtls::role::{
    DEFAULT_DTLS_ROLE_ANSWER, DEFAULT_DTLS_ROLE_OFFER, RTCDtlsRole,
};
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
use crate::peer_connection::transport::dtls::{
    DtlsAssociationUpdate, DtlsRemoteUpdate, DtlsTransport, RTCDtlsTransportConfig,
};
use crate::peer_connection::transport::ice::IceTransport;
use crate::peer_connection::transport::ice::candidate::RTCIceCandidateInit;
use crate::peer_connection::transport::ice::parameters::RTCIceParameters;
use crate::peer_connection::transport::ice::role::RTCIceRole;
use crate::peer_connection::transport::ice::state::RTCIceTransportState;
use crate::peer_connection::transport::sctp::{
    SctpNegotiationOutcome, SctpRenegotiation, SctpTransport,
};
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::rtp_receiver::RTCRtpReceiver;
use crate::rtp_transceiver::rtp_sender::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::RTCRtpSender;
use crate::rtp_transceiver::rtp_sender::internal::validate_send_encodings;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    CodecMatch, RtpCodecKind, codec_parameters_fuzzy_search,
};
use crate::rtp_transceiver::{
    RTCRtpReceiverId, RTCRtpSenderId, RTCRtpTransceiver, RTCRtpTransceiverId,
    RTCRtpTransceiverInit, internal::RTCRtpTransceiverInternal,
};
use crate::statistics::StatsSelector;
use crate::statistics::accumulator::RTCStatsAccumulator;
use crate::statistics::report::RTCStatsReport;
use ::sdp::description::common::Attribute;
use ::sdp::description::session::{ATTR_KEY_CANDIDATE, ATTR_KEY_END_OF_CANDIDATES, Origin};
use ::sdp::util::ConnectionRole;
use ice::AgentConfig;
use ice::candidate::{Candidate, unmarshal_candidate};
use interceptor::{Interceptor, Registry};
use shared::error::{Error, Result};
use shared::util::math_rand_alpha;
use std::time::Instant;

/// The most remote candidates `add_remote_candidate` takes per remote description, the ICE
/// agent's own cap: further ones reach neither the stats nor the stored description.
const MAX_TRICKLED_REMOTE_CANDIDATES: usize = 256;

/// Builder for creating RTCPeerConnection instances.
///
/// This builder provides a fluent API for configuring peer connections with:
/// - ICE servers (STUN/TURN) via [`RTCConfiguration`]
/// - Media codecs and RTP extensions via [`MediaEngine`]
/// - Low-level transport settings via [`SettingEngine`]
/// - RTP/RTCP interceptors for NACK, TWCC, and RTCP reports
///
/// # Examples
///
/// ## Basic peer connection
///
/// ```
/// # use std::time::Instant;
/// use rtc::peer_connection::RTCPeerConnectionBuilder;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
/// # Ok(())
/// # }
/// ```
///
/// ## With ICE servers
///
/// ```
/// # use std::time::Instant;
/// use rtc::peer_connection::RTCPeerConnectionBuilder;
/// use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let pc = RTCPeerConnectionBuilder::new()
///     .with_configuration(
///         RTCConfigurationBuilder::new()
///             .with_ice_servers(vec![RTCIceServer {
///                 urls: vec!["stun:stun.l.google.com:19302".to_string()],
///                 ..Default::default()
///             }])
///             .build()
///     )
///     .build(Instant::now())?;
/// # Ok(())
/// # }
/// ```
///
/// ## With custom media engine
///
/// ```
/// # use std::time::Instant;
/// use rtc::peer_connection::RTCPeerConnectionBuilder;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// media_engine.register_default_codecs()?;
///
/// let pc = RTCPeerConnectionBuilder::new()
///     .with_media_engine(media_engine)
///     .build(Instant::now())?;
/// # Ok(())
/// # }
/// ```
///
/// ## With interceptors
///
/// ```
/// # use std::time::Instant;
/// use rtc::peer_connection::RTCPeerConnectionBuilder;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
/// use rtc::peer_connection::configuration::interceptor_registry::{
///     Registry, register_default_interceptors,
/// };
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = register_default_interceptors(registry, &mut media_engine)?;
///
/// let pc = RTCPeerConnectionBuilder::new()
///     .with_media_engine(media_engine)
///     .with_interceptor_registry(registry)
///     .build(Instant::now())?;
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct RTCPeerConnectionBuilder {
    configuration: RTCConfiguration,
    media_engine: MediaEngine,
    setting_engine: SettingEngine,
    interceptor_registry: Registry,
}

impl RTCPeerConnectionBuilder {
    /// Creates a new RTCPeerConnectionBuilder with default configuration.
    ///
    /// The default builder includes:
    /// - Empty ICE server list
    /// - Default MediaEngine (no codecs registered)
    /// - Default SettingEngine (standard timeouts and limits)
    /// - NoopInterceptor (no RTP/RTCP processing)
    ///
    /// Use `with_*` methods to customize configuration before calling `build()`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Self {
        Self::default()
    }
}

impl RTCPeerConnectionBuilder {
    /// Sets the RTCConfiguration for the peer connection.
    ///
    /// The configuration includes ICE servers, transport policies, bundle policies,
    /// RTCP mux policies, and certificates.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    /// use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = RTCConfigurationBuilder::new()
    ///     .with_ice_servers(vec![RTCIceServer {
    ///         urls: vec!["stun:stun.l.google.com:19302".to_string()],
    ///         ..Default::default()
    ///     }])
    ///     .build();
    ///
    /// let pc = RTCPeerConnectionBuilder::new()
    ///     .with_configuration(config)
    ///     .build(Instant::now())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_configuration(mut self, configuration: RTCConfiguration) -> Self {
        self.configuration = configuration;
        self
    }

    /// Sets the MediaEngine for the peer connection.
    ///
    /// The media engine configures codecs and RTP header extensions.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    /// use rtc::peer_connection::configuration::media_engine::MediaEngine;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut media_engine = MediaEngine::default();
    /// media_engine.register_default_codecs()?;
    ///
    /// let pc = RTCPeerConnectionBuilder::new()
    ///     .with_media_engine(media_engine)
    ///     .build(Instant::now())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_media_engine(mut self, media_engine: MediaEngine) -> Self {
        self.media_engine = media_engine;
        self
    }

    /// Sets the SettingEngine for the peer connection.
    ///
    /// The setting engine configures low-level transport parameters including
    /// timeouts, buffer sizes, ICE settings, and SCTP parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use std::time::Duration;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_ice_timeouts(
    ///         Some(Duration::from_secs(30)),
    ///         Some(Duration::from_secs(60)),
    ///         Some(Duration::from_millis(100)),
    ///     )
    ///     .build();
    ///
    /// let pc = RTCPeerConnectionBuilder::new()
    ///     .with_setting_engine(setting_engine)
    ///     .build(Instant::now())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_setting_engine(mut self, setting_engine: SettingEngine) -> Self {
        self.setting_engine = setting_engine;
        self
    }

    /// Configures the peer connection with an interceptor registry.
    ///
    /// Interceptors process RTP/RTCP packets as they flow through the pipeline,
    /// enabling features like:
    /// - NACK (Negative Acknowledgment) for packet loss recovery
    /// - TWCC (Transport-Wide Congestion Control) for bandwidth estimation
    /// - RTCP Reports for quality statistics
    ///
    /// This method replaces the builder's interceptor type — `NoopInterceptor` by default —
    /// with the registry's, so it returns a `RTCPeerConnectionBuilder<P>` rather than
    /// `Self`. Every other builder setting is carried over, and the remaining setters are
    /// available on the returned builder, so this does not have to be the last call before
    /// `build()`; it is simply the only one that changes the builder's type.
    ///
    /// # Type Parameters
    ///
    /// * `P` - The interceptor type produced by the registry
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    /// use rtc::peer_connection::configuration::media_engine::MediaEngine;
    /// use rtc::peer_connection::configuration::interceptor_registry::{
    ///     Registry, register_default_interceptors,
    /// };
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut media_engine = MediaEngine::default();
    /// let registry = Registry::new();
    /// let registry = register_default_interceptors(registry, &mut media_engine)?;
    ///
    /// let pc = RTCPeerConnectionBuilder::new()
    ///     .with_media_engine(media_engine)
    ///     .with_interceptor_registry(registry)
    ///     .build(Instant::now())?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # One connection type, whatever the chain
    ///
    /// A chain is a flat list of interceptors, so the connection has one concrete type whatever
    /// the list contains. That is what lets a non-generic struct own one, or two connections with
    /// *different* chains share a collection:
    ///
    /// ```
    /// # use std::time::Instant;
    /// use rtc::peer_connection::configuration::interceptor_registry::{
    ///     Registry, register_default_interceptors,
    /// };
    /// use rtc::peer_connection::configuration::media_engine::MediaEngine;
    /// use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
    ///
    /// struct Session {
    ///     peer_connection: RTCPeerConnection, // no type parameter
    /// }
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut media_engine = MediaEngine::default();
    /// let registry =
    ///     register_default_interceptors(Registry::new(), &mut media_engine)?;
    ///
    /// let session = Session {
    ///     peer_connection: RTCPeerConnectionBuilder::new()
    ///         .with_media_engine(media_engine)
    ///         .with_interceptor_registry(registry)
    ///         .build(Instant::now())?,
    /// };
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The registry is assembled into the chain by [`build`](RTCPeerConnectionBuilder::build),
    /// so it stays a list — inspectable, extendable — right up until the connection is made.
    pub fn with_interceptor_registry(mut self, interceptor_registry: Registry) -> Self {
        self.interceptor_registry = interceptor_registry;
        self
    }

    /// Builds the RTCPeerConnection with the configured settings.
    ///
    /// This method validates the configuration and creates a new peer connection.
    /// If validation fails (e.g., expired certificates, invalid ICE servers),
    /// an error is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Certificates have expired
    /// - ICE server URLs are invalid
    /// - Other validation checks fail
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn build(self, now: Instant) -> Result<RTCPeerConnection> {
        // RFC 3711 section 3.3.2: "A replay list ... the window size MUST be at least 64"; 0
        // turns replay protection off, which the setting engine documents.
        let replay = &self.setting_engine.replay_protection;
        for (what, window) in [("SRTP", replay.srtp), ("SRTCP", replay.srtcp)] {
            if (1..64).contains(&window) {
                return Err(Error::ErrSrtpReplayWindowTooSmall(what, window));
            }
        }
        if let Some(lifetime) = self.setting_engine.srtp_key_lifetime {
            ::srtp::keying::validate_key_lifetime(lifetime)?;
        }
        RTCPeerConnection::new(
            now,
            self.configuration,
            self.media_engine,
            self.setting_engine,
            // The registry is a list until here; `build` freezes it into the chain.
            Box::new(self.interceptor_registry.build()),
        )
    }
}

/// The `RTCPeerConnection` interface represents a WebRTC connection between the local computer
/// and a remote peer. It provides methods to connect to a remote peer, maintain and monitor
/// the connection, and close the connection once it's no longer needed.
///
/// This is a sans-I/O implementation following the [W3C WebRTC specification](https://www.w3.org/TR/webrtc/).
///
/// # Driving the connection
///
/// This type performs **no I/O and reads no clock**. It never opens a socket, never sleeps, and
/// never calls `Instant::now()` on your behalf: every method that needs the time takes it as an
/// argument. Progress happens only when you feed it something. That is what makes a whole
/// session reproducible in a test with no socket and no sleep.
///
/// The driving methods come from the [`sansio::Protocol`] trait, so **the trait must be in scope**
/// (`use rtc::sansio::Protocol;`) or none of them will resolve:
///
/// | Method | Direction | What it does |
/// | --- | --- | --- |
/// | [`handle_read`] | in | Feed one received datagram, tagged with its 5-tuple and arrival instant |
/// | [`poll_write`] | out | Take the next packet to put on the wire; drain until `None` |
/// | [`poll_read`] | out | Take the next inbound RTP/RTCP/data-channel message for the application |
/// | [`poll_event`] | out | Take the next state change or notification |
/// | [`poll_timeout`] | out | Next deadline for retransmissions, keepalives and ICE checks |
/// | [`handle_timeout`] | in | Report that a deadline has passed |
/// | [`handle_write`] | in | Queue an outbound RTP/RTCP/data-channel message |
/// | [`close`] | in | Shut the connection down |
///
/// Nothing is sent eagerly: `handle_read`, `handle_timeout`, `handle_write` and the negotiation
/// methods all *queue* packets, so drain `poll_write` after any of them.
///
/// [`handle_event`] also exists on the trait, but [`RTCEvent`] is uninhabited — no value of it can
/// be constructed, so there is nothing to call it with. It reserves the signature for the first
/// inbound event variant.
///
/// # Back-pressure
///
/// [`poll_read`] is the throttle. Undrained data-channel messages leave bytes in SCTP's reassembly
/// queue, which lowers the receiver-window credit advertised in every SACK, which tells the peer to
/// slow down. **Declining to call `poll_read` is how back-pressure is applied**; resume when the
/// application catches up. Media is never throttled this way: RTP arrives over SRTP and is subject
/// to none of SCTP's flow control, and `poll_read` interleaves the two by the instant each packet
/// was observed, so a stalled data channel cannot starve video.
///
/// # ICE candidates
///
/// Because there is no I/O here, there is no candidate gathering either: the application owns the
/// sockets, so it owns gathering. Hand every local candidate to [`Self::add_local_candidate`], and
/// finish with an empty candidate string to signal end-of-gathering — see that method for the
/// details.
///
/// # Examples
///
/// ```
/// # use std::time::Instant;
/// use rtc::peer_connection::RTCPeerConnectionBuilder;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
/// # Ok(())
/// # }
/// ```
///
/// A complete event loop is shown in the [crate-level documentation](crate).
///
/// [`sansio::Protocol`]: sansio::Protocol
/// [`handle_read`]: sansio::Protocol::handle_read
/// [`poll_write`]: sansio::Protocol::poll_write
/// [`poll_read`]: sansio::Protocol::poll_read
/// [`poll_event`]: sansio::Protocol::poll_event
/// [`poll_timeout`]: sansio::Protocol::poll_timeout
/// [`handle_timeout`]: sansio::Protocol::handle_timeout
/// [`handle_write`]: sansio::Protocol::handle_write
/// [`handle_event`]: sansio::Protocol::handle_event
/// [`close`]: sansio::Protocol::close
/// [`RTCEvent`]: crate::peer_connection::event::RTCEvent
pub struct RTCPeerConnection {
    //////////////////////////////////////////////////
    // PeerConnection WebRTC Spec Interface Definition
    //////////////////////////////////////////////////
    pub(crate) configuration: RTCConfiguration,
    pub(crate) media_engine: MediaEngine,
    pub(crate) setting_engine: SettingEngine,
    pub(crate) interceptor: Box<dyn Interceptor>,

    local_description: Option<RTCSessionDescription>,
    current_local_description: Option<RTCSessionDescription>,
    pending_local_description: Option<RTCSessionDescription>,
    remote_description: Option<RTCSessionDescription>,
    current_remote_description: Option<RTCSessionDescription>,
    pending_remote_description: Option<RTCSessionDescription>,

    pub(crate) signaling_state: RTCSignalingState,
    pub(crate) peer_connection_state: RTCPeerConnectionState,
    can_trickle_ice_candidates: Option<bool>,
    /// Remote candidates `add_remote_candidate` has taken since the last remote description,
    /// held at [`MAX_TRICKLED_REMOTE_CANDIDATES`].
    trickled_remote_candidates: usize,

    //////////////////////////////////////////////////
    // PeerConnection Internal State Machine
    //////////////////////////////////////////////////
    pub(crate) pipeline_context: PipelineContext,
    pub(crate) data_channels: DataChannelRegistry,
    pub(super) rtp_transceivers: Vec<RTCRtpTransceiverInternal>,
    /// The transceivers removed since `take_removed_transceivers` was last called, each by the
    /// id it had when it was removed, in removal order.
    pub(super) removed_transceivers: Vec<RTCRtpTransceiverId>,
    /// The id of the "default" remote MediaStream of the session (RFC 9429 section 5.8), once
    /// a media section without `a=msid` needed one.
    pub(super) default_remote_stream_id: Option<crate::media_stream::MediaStreamId>,

    greater_mid: isize,
    sdp_origin: Origin,
    /// The text of the description `create_offer` or `create_answer` made last: the next one
    /// takes the following `o=` session version when it differs (`update_sdp_origin`).
    last_generated_sdp: String,
    last_offer: String,
    last_answer: String,

    /// W3C `[[LocalIceCredentialsToReplace]]`: the username fragments of the local
    /// descriptions `restart_ice` was called with. Offers restart ICE while the current local
    /// description still has one of them (`ice_restart_pending`).
    pub(crate) ice_credentials_to_replace: Vec<String>,
    /// The last completed offer/answer rejected every m-section, which closes the transport
    /// (RFC 8843 §7.1.3, RFC 9429 §5.10): the next description that sets one up with new ICE
    /// credentials starts new ICE and DTLS associations.
    transport_closed: bool,
    /// The value of the `a=identity` attribute offers and answers carry (RFC 8827 section 5);
    /// see `dtls_sdp`.
    identity_assertion: Option<String>,
    /// What a rollback restores: set while an offer applied in the stable state is pending.
    last_stable_state: Option<internal::LastStableState>,
    /// The transport part of the pending remote offer, applied with the local answer.
    pending_remote_transport: Option<internal::PendingRemoteTransport>,
    negotiation_needed_state: NegotiationNeededState,
    is_negotiation_ongoing: bool,
    // wpt100:hdrext — `alwaysNegotiateDataChannels` (see `always_negotiate`).
    always_negotiate_data_channels: bool,
    /// What the application has been told of the transports' states (`states_events`).
    pub(crate) announced: states_events::AnnouncedStates,
}

impl RTCPeerConnection {
    /// Creates an SDP offer to start a new WebRTC connection to a remote peer.
    ///
    /// The offer includes information about the attached media tracks, codecs and options supported
    /// by the browser, and ICE candidates gathered by the ICE agent. This offer can be sent to a
    /// remote peer over a signaling channel to establish a connection.
    ///
    /// # Parameters
    ///
    /// * `options` - Optional configuration for the offer, such as whether to restart ICE.
    ///
    /// # Returns
    ///
    /// Returns an `RTCSessionDescription` containing the SDP offer.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The peer connection is closed
    /// - There's an error generating the SDP
    ///
    /// # Specification
    ///
    /// See [createOffer](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-createoffer)
    pub fn create_offer(
        &mut self,
        mut options: Option<RTCOfferOptions>,
    ) -> Result<RTCSessionDescription> {
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        // W3C webrtc-pc createOffer: "If connection.[[SignalingState]] is neither 'stable' nor
        // 'have-local-offer', return a promise rejected with a newly created
        // InvalidStateError" (RFC 9429 section 5.2: an offer is made from the stable state, or
        // again while the previous one is pending). Checked before anything is touched: an
        // endpoint that has a remote offer to answer keeps its mids and its restart request.
        if !matches!(
            self.signaling_state,
            RTCSignalingState::Stable | RTCSignalingState::HaveLocalOffer
        ) {
            return Err(Error::ErrIncorrectSignalingState);
        }

        // Staging, not restarting: the offer must advertise fresh ICE credentials, but JSEP
        // requires `createOffer` to be free of side effects, and inbound STUN is still being
        // validated against the current ufrag/pwd. `set_local_description` applies the restart.
        // W3C createOffer: "If connection.[[LocalIceCredentialsToReplace]] is not empty, or if
        // options.iceRestart is true": every offer restarts ICE until an answer has replaced
        // the credentials `restart_ice` was called for, even if an earlier restart offer was
        // discarded or rolled back.
        let is_ice_restart_requested =
            self.ice_restart_pending() || options.take().is_some_and(|options| options.ice_restart);

        // A new transport after the last one was closed (every m-section rejected) is a new ICE
        // session: the offer carries new credentials and `set_local_description` restarts the
        // agent, so none of the closed transport's candidates or selected pair carry over.
        if is_ice_restart_requested || self.transport_closed {
            self.stage_ice_restart()?;
        }

        // include unmatched local transceivers
        // update the greater mid if the remote description provides a greater one
        if let Some(d) = self.current_remote_description.as_ref()
            && let Some(parsed) = &d.parsed
        {
            for media in &parsed.media_descriptions {
                if let Some(mid) = get_mid_value(media) {
                    if mid.is_empty() {
                        continue;
                    }
                    let numeric_mid = match mid.parse::<isize>() {
                        Ok(n) => n,
                        Err(_) => continue,
                    };
                    if numeric_mid > self.greater_mid {
                        self.greater_mid = numeric_mid;
                    }
                }
            }
        }
        for transceiver in &mut self.rtp_transceivers {
            if let Some(mid) = transceiver.mid()
                && !mid.is_empty()
            {
                if let Ok(numeric_mid) = mid.parse::<isize>()
                    && numeric_mid > self.greater_mid
                {
                    self.greater_mid = numeric_mid;
                }
            } else if transceiver.stopped() {
                // A stopped transceiver with no mid gets none: it has no m= section (RFC 9429,
                // Section 5.2.2), and a mid would make it look associated.
            } else if let Some(generate) = self.setting_engine.mid_generator.clone() {
                // `SettingEngineBuilder::with_mid_generator`: the generator gets the greatest
                // numeric mid so far; each call moves it on, so two new transceivers in one
                // offer don't get the same argument.
                let mid = generate(self.greater_mid);
                if let Ok(numeric_mid) = mid.parse::<isize>() {
                    self.greater_mid = self.greater_mid.max(numeric_mid);
                } else {
                    self.greater_mid = self.greater_mid.saturating_add(1);
                }
                transceiver.set_mid(mid)?;
            } else {
                // A remote description may carry any numeric mid, `isize::MAX` included.
                self.greater_mid = self.greater_mid.checked_add(1).ok_or_else(|| {
                    Error::Other("no numeric mid is left above the remote description's".into())
                })?;
                transceiver.set_mid(format!("{}", self.greater_mid))?;
            }
        }

        let d = if self.current_remote_description.is_none() {
            self.generate_unmatched_sdp()?
        } else {
            self.generate_matched_sdp(
                true, /*includeUnmatched */
                DEFAULT_DTLS_ROLE_OFFER.to_connection_role(),
                false,
            )?
        };

        // wpt100:hdrext — `a=cryptex` per the RTCRtpHeaderEncryptionPolicy (RFC 9335).
        let d = self.add_cryptex_attribute(d, true);
        // `a=tls-id` (RFC 8842) and `a=identity` (RFC 8827).
        let mut d = self.add_dtls_association_attributes(d, true)?;

        update_sdp_origin(&mut self.sdp_origin, &mut self.last_generated_sdp, &mut d);

        let sdp = d.marshal();

        let offer = RTCSessionDescription {
            sdp_type: RTCSdpType::Offer,
            sdp,
            parsed: Some(d),
        };

        self.last_offer.clone_from(&offer.sdp);

        Ok(offer)
    }

    /// Creates an SDP answer in response to an offer from a remote peer.
    ///
    /// This method must be called after `set_remote_description()` has been called
    /// with an offer. The answer describes which media formats and codecs this peer
    /// will accept and how the connection will be established.
    ///
    /// # Parameters
    ///
    /// - `options`: Optional answer configuration. Currently not used but reserved
    ///   for future extensions.
    ///
    /// # Returns
    ///
    /// Returns an `RTCSessionDescription` containing the SDP answer that should be
    /// set as the local description and sent to the remote peer.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No remote description has been set (`ErrNoRemoteDescription`)
    /// - The peer connection is closed (`ErrConnectionClosed`)
    /// - The signaling state is incorrect (`ErrIncorrectSignalingState`)
    /// - SDP generation fails
    ///
    /// # Signaling State Requirements
    ///
    /// This method can only be called when the signaling state is:
    /// - `HaveRemoteOffer` - After receiving an initial offer
    /// - `HaveLocalPranswer` - After sending a provisional answer
    ///
    /// # Examples
    ///
    /// ## Basic Answer Flow
    ///
    /// ```no_run
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    /// use rtc::peer_connection::sdp::RTCSessionDescription;
    ///
    /// # fn example(remote_offer_sdp: String) -> Result<(), Box<dyn std::error::Error>> {
    /// let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    ///
    /// // 1. Receive and set remote offer
    /// let offer = RTCSessionDescription::offer(remote_offer_sdp)?;
    /// pc.set_remote_description(Instant::now(), offer)?;
    ///
    /// // 2. Create answer
    /// let answer = pc.create_answer(None)?;
    ///
    /// // 3. Set as local description
    /// pc.set_local_description(Instant::now(), answer.clone())?;
    ///
    /// // 4. Send answer to remote peer
    /// // signaling_channel.send(answer.sdp)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## With Media Tracks
    ///
    /// ```no_run
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    /// use rtc::peer_connection::sdp::RTCSessionDescription;
    /// use rtc::media_stream::MediaStreamTrack;
    ///
    /// # fn example(
    /// #     remote_offer_sdp: String,
    /// #     audio_track: MediaStreamTrack,
    /// # ) -> Result<(), Box<dyn std::error::Error>> {
    /// let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    ///
    /// // Set remote offer
    /// let offer = RTCSessionDescription::offer(remote_offer_sdp)?;
    /// pc.set_remote_description(Instant::now(), offer)?;
    ///
    /// // Add local track before creating answer
    /// pc.add_track(audio_track)?;
    ///
    /// // Create answer (will include the track)
    /// let answer = pc.create_answer(None)?;
    /// pc.set_local_description(Instant::now(), answer)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # DTLS Role Selection
    ///
    /// The answer automatically determines the appropriate DTLS role:
    /// - Keeps the role of the DTLS association the connection has (RFC 8842 section 5.3: an
    ///   answer does not change the negotiated roles), whatever the settings say
    /// - For a new association: takes the role an offer with `a=setup:active` or `passive`
    ///   leaves
    /// - Uses `answering_dtls_role` from settings if configured
    /// - Defaults to `Client` (active) for lower latency
    /// - Uses `Server` (passive) if remote is ICE-Lite
    ///
    /// # Specification
    ///
    /// - [W3C RTCPeerConnection.createAnswer]
    /// - [RFC 9429 Section 5.3] - Generating an Answer
    ///
    /// [W3C RTCPeerConnection.createAnswer]: https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-createanswer
    /// [RFC 9429 Section 5.3]: https://datatracker.ietf.org/doc/html/rfc9429#section-5.3
    pub fn create_answer(
        &mut self,
        _options: Option<RTCAnswerOptions>,
    ) -> Result<RTCSessionDescription> {
        if self.remote_description().is_none() {
            return Err(Error::ErrNoRemoteDescription);
        }

        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        if self.signaling_state != RTCSignalingState::HaveRemoteOffer
            && self.signaling_state != RTCSignalingState::HaveLocalPranswer
        {
            return Err(Error::ErrIncorrectSignalingState);
        }

        let mut connection_role = self.setting_engine.answering_dtls_role.to_connection_role();
        // RFC 5763 §5: "The answerer MUST use either a setup attribute value of setup:active or
        // setup:passive." `actpass` is an offer-only value, so an answering role of
        // `RTCDtlsRole::Auto` — which maps to it — means "no preference" and has to be resolved
        // to a concrete role here, exactly like `Unspecified`.
        //
        // Letting `actpass` through leaves the role genuinely unnegotiated: the answerer falls
        // back to its own `answering_dtls_role`, and the offerer, seeing no explicit role in the
        // answer, falls back to *its* configured role. When those agree — e.g. an offerer pinned
        // to `Client` answered by a peer configured `Auto` — both endpoints become the DTLS
        // client, both wait for a ClientHello, and the handshake never completes.
        if matches!(
            connection_role,
            ConnectionRole::Unspecified | ConnectionRole::Actpass
        ) {
            connection_role = DEFAULT_DTLS_ROLE_ANSWER.to_connection_role();

            if let Some(remote_description) = self.remote_description()
                && let Some(parsed) = remote_description.parsed.as_ref()
                && is_lite_set(parsed)
                && !self.setting_engine.candidates.ice_lite
            {
                connection_role = RTCDtlsRole::Server.to_connection_role();
            }
        }

        // An offer that already took a role leaves the other one (RFC 5763 §5: an offerer's
        // setup:active is answered with setup:passive, and setup:passive with setup:active);
        // only an actpass offer lets the answerer choose.
        if let Some(parsed) = self.remote_description().and_then(|r| r.parsed.as_ref()) {
            match RTCDtlsRole::from(parsed) {
                RTCDtlsRole::Client => connection_role = ConnectionRole::Passive,
                RTCDtlsRole::Server => connection_role = ConnectionRole::Active,
                _ => {}
            }
        }

        // The transport that applying the offer started, kept or set up anew has its role:
        // the answer states that one. For an association that is kept this is RFC 8842
        // section 5.3 ("a setup attribute with a value that does not change the previously
        // negotiated DTLS roles"): the endpoint that was the offerer, and so the DTLS server,
        // when the association was set up stays the server when it answers a later offer,
        // whatever its configured answering role and its ICE role say.
        // A new association the offer asks for has the role applying the answer gives it
        // (`defer_remote_transport` worked it out).
        let transport_role = match self
            .pending_remote_transport
            .as_ref()
            .and_then(|pending| pending.new_dtls_role)
        {
            Some(role) => Some(role),
            None => self
                .dtls_transport()
                .is_started()
                .then(|| self.dtls_transport().role()),
        };
        match transport_role {
            Some(RTCDtlsRole::Client) => connection_role = ConnectionRole::Active,
            Some(RTCDtlsRole::Server) => connection_role = ConnectionRole::Passive,
            _ => {}
        }

        let d = self.generate_matched_sdp(
            false, /*includeUnmatched */
            connection_role,
            self.setting_engine.ignore_rid_pause_for_recv,
        )?;

        // wpt100:hdrext — `a=cryptex` when the offer had it (RFC 9335 section 4).
        let d = self.add_cryptex_attribute(d, false);
        // `a=tls-id` when the offer had one (RFC 8842 section 5.3), and `a=identity`.
        let mut d = self.add_dtls_association_attributes(d, false)?;

        update_sdp_origin(&mut self.sdp_origin, &mut self.last_generated_sdp, &mut d);

        let sdp = d.marshal();

        let answer = RTCSessionDescription {
            sdp_type: RTCSdpType::Answer,
            sdp,
            parsed: Some(d),
        };

        self.last_answer.clone_from(&answer.sdp);

        Ok(answer)
    }

    /// Sets the local description for this peer connection.
    ///
    /// This method applies a local SDP description (offer or answer) to the peer
    /// connection, updating the local media and transport configuration. It must be
    /// called after creating an offer or answer.
    ///
    /// # Parameters
    ///
    /// - `local_description`: The session description to set as the local description.
    ///   This should be an offer or answer created by `create_offer()` or `create_answer()`.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The peer connection is closed (`ErrConnectionClosed`)
    /// - The SDP type is invalid for the current signaling state
    /// - SDP parsing fails
    /// - Transport configuration fails
    ///
    /// # Signaling State Transitions
    ///
    /// Setting the local description causes signaling state transitions:
    ///
    /// - **Offer**: `Stable` → `HaveLocalOffer`
    /// - **Answer**: `HaveRemoteOffer` → `Stable`
    /// - **Pranswer**: `HaveRemoteOffer` → `HaveLocalPranswer`
    ///
    /// # Examples
    ///
    /// ## Setting Local Offer
    ///
    /// ```no_run
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    ///
    /// // Create offer
    /// let offer = pc.create_offer(None)?;
    ///
    /// // Set as local description
    /// pc.set_local_description(Instant::now(), offer.clone())?;
    ///
    /// // Now send offer.sdp to remote peer via signaling
    /// // signaling_channel.send(offer.sdp)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Setting Local Answer
    ///
    /// ```no_run
    /// # use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    /// use rtc::peer_connection::sdp::RTCSessionDescription;
    ///
    /// # fn example(remote_offer_sdp: String) -> Result<(), Box<dyn std::error::Error>> {
    /// let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    ///
    /// // Set remote offer first
    /// let offer = RTCSessionDescription::offer(remote_offer_sdp)?;
    /// pc.set_remote_description(Instant::now(), offer)?;
    ///
    /// // Create and set local answer
    /// let answer = pc.create_answer(None)?;
    /// pc.set_local_description(Instant::now(), answer.clone())?;
    ///
    /// // Send answer to remote peer
    /// // signaling_channel.send(answer.sdp)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Empty SDP Handling (JSEP 5.4)
    ///
    /// If the SDP string is empty, the last offer or answer is reused:
    /// - For offers: Uses the last generated offer
    /// - For answers: Uses the last generated answer
    ///
    /// This allows re-applying descriptions without regenerating SDP.
    ///
    /// # Media and Transport Activation
    ///
    /// When setting a local answer:
    /// - RTP transceivers are activated
    /// - SCTP transport is started for data channels
    /// - Media can begin flowing
    ///
    /// # Specification
    ///
    /// - [W3C RTCPeerConnection.setLocalDescription]
    /// - [RFC 9429 Section 5.9] - Applying a Local Description
    ///
    /// [W3C RTCPeerConnection.setLocalDescription]: https://www.w3.org/TR/webrtc/#dom-peerconnection-setlocaldescription
    /// [RFC 9429 Section 5.9]: https://datatracker.ietf.org/doc/html/rfc9429#section-5.9
    pub fn set_local_description(
        &mut self,
        now: Instant,
        mut local_description: RTCSessionDescription,
    ) -> Result<()> {
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        // JSEP 5.4
        if local_description.sdp.is_empty() {
            match local_description.sdp_type {
                RTCSdpType::Answer | RTCSdpType::Pranswer => {
                    local_description.sdp.clone_from(&self.last_answer);
                }
                RTCSdpType::Offer => {
                    local_description.sdp.clone_from(&self.last_offer);
                }
                RTCSdpType::Rollback => {
                    // WebRTC spec: rollback SDP is ignored, empty is allowed
                }
                _ => return Err(Error::ErrPeerConnSDPTypeInvalidValueSetLocalDescription),
            }
        }

        // Parse SDP (skip for rollback as content is ignored per spec)
        if local_description.sdp_type != RTCSdpType::Rollback {
            local_description.parsed = Some(local_description.unmarshal()?);
        }

        // Everything that can refuse the description is checked before anything is changed
        // (RFC 9429 section 5.9: "the session state MUST be restored to its state before"):
        // the signaling state, that it is the description last created, and that each of an
        // answer's media sections has a mid and a transceiver.
        let next_state = self.check_description(&local_description, StateChangeOp::SetLocal)?;
        if local_description.sdp_type == RTCSdpType::Answer
            && let Some(parsed) = &local_description.parsed
        {
            self.check_local_answer(parsed)?;
        }

        // What is left can only fail inside a transport; should it, the description state is
        // put back as it was.
        let snapshot = self.description_snapshot();
        let sdp_type = local_description.sdp_type;
        let applied = self.apply_local_description(now, local_description, next_state);
        if applied.is_err() {
            self.restore_description_snapshot(snapshot);
        } else {
            self.after_local_description(sdp_type);
        }
        applied
    }

    /// The checks `set_local_description` makes on an answer's media sections before applying
    /// it: the ones its loop over them relies on.
    fn check_local_answer(
        &self,
        parsed: &::sdp::description::session::SessionDescription,
    ) -> Result<()> {
        let transceiver_by_mid =
            RTCPeerConnection::transceiver_index_by_mid(&self.rtp_transceivers);
        for media in &parsed.media_descriptions {
            let mid_value = match get_mid_value(media) {
                Some(mid) if !mid.is_empty() => mid,
                _ => return Err(Error::ErrPeerConnLocalDescriptionWithoutMidValue),
            };
            if media.is_webrtc_datachannel()
                || is_rejected_media(media)
                || transceiver_by_mid.contains_key(mid_value.as_str())
            {
                continue;
            }
            return Err(Error::ErrPeerConnTransceiverMidNil);
        }
        Ok(())
    }

    /// Applies a local description `set_local_description` has checked.
    fn apply_local_description(
        &mut self,
        now: Instant,
        local_description: RTCSessionDescription,
        next_state: RTCSignalingState,
    ) -> Result<()> {
        // Apply an ICE restart staged by `create_offer`, now that the description is known to
        // be the one created and valid in this state: a description that is refused, and a
        // rollback, leave the session on its credentials. A no-op if none was staged, so an
        // offer that was created and then discarded leaves the existing session untouched.
        if local_description.sdp_type != RTCSdpType::Rollback
            && self.ice_transport().has_pending_restart()
        {
            self.apply_ice_restart(now)?;
        }

        self.commit_description(&local_description, StateChangeOp::SetLocal, next_state)?;

        // The transports take the remote offer's parameters now that it is answered
        // (`defer_remote_transport`).
        if matches!(
            local_description.sdp_type,
            RTCSdpType::Answer | RTCSdpType::Pranswer
        ) && let Some(pending) = self.pending_remote_transport.take()
            && let Some(parsed) = self.remote_description().and_then(|r| r.parsed.clone())
        {
            self.apply_remote_transport(now, &parsed, false, Some(pending.ice_restart))?;
        }

        let we_answer = local_description.sdp_type == RTCSdpType::Answer;
        if we_answer && let Some(parsed_local_description) = &local_description.parsed {
            // WebRTC Spec 1.0 https://www.w3.org/TR/webrtc/
            // Section 4.4.1.5
            let transceiver_by_mid =
                RTCPeerConnection::transceiver_index_by_mid(&self.rtp_transceivers);
            for media in &parsed_local_description.media_descriptions {
                let mid_value = match get_mid_value(media) {
                    Some(mid) if !mid.is_empty() => mid,
                    _ => return Err(Error::ErrPeerConnLocalDescriptionWithoutMidValue),
                };

                if media.is_webrtc_datachannel() {
                    continue;
                }

                let i = match transceiver_by_mid.get(mid_value.as_str()) {
                    Some(&i) => i,
                    // A rejected section an earlier exchange already rejected has no transceiver
                    // any more (it was removed), nor has one of a media type this endpoint
                    // doesn't know.
                    None if is_rejected_media(media) => continue,
                    None => return Err(Error::ErrPeerConnTransceiverMidNil),
                };

                let kind = RtpCodecKind::from(media.media_name.media.as_str());
                let mut direction = get_peer_direction(media);
                if kind == RtpCodecKind::Unspecified
                    || is_unknown_application_media(media)
                    || direction == RTCRtpTransceiverDirection::Unspecified
                {
                    continue;
                }

                // If a transceiver is created by applying a remote description that has recvonly transceiver,
                // it will have no sender. In this case, the transceiver's current direction is set to inactive so
                // that the transceiver can be reused by next AddTrack.
                if direction == RTCRtpTransceiverDirection::Sendonly
                    && self.rtp_transceivers[i].sender().is_none()
                {
                    direction = RTCRtpTransceiverDirection::Inactive;
                }

                self.rtp_transceivers[i].set_current_direction(direction);
            }

            if let Some(remote_description) = self.remote_description().cloned()
                && let Some(parsed_remote_description) = remote_description.parsed.as_ref()
            {
                self.apply_negotiated_rtcp(parsed_remote_description, parsed_local_description);
                self.apply_negotiated_simulcast(
                    parsed_remote_description,
                    parsed_local_description,
                    true,
                );

                // we_answer: we first call set_remote_description,
                // then, we create_answer() and set_local_description() here
                // Now we should have done SDP negotiation.
                // Therefore, it is ready to start sctp and rtp.
                let negotiated =
                    negotiated_sctp(parsed_local_description, parsed_remote_description);
                self.apply_sctp_negotiation(now, negotiated)?;
                self.start_rtp(remote_description.clone())?;
                self.apply_negotiated_session(
                    now,
                    parsed_local_description,
                    parsed_remote_description,
                )?;
            }

            // An answer applied: the stopped transceivers whose sections it left rejected go.
            // Last, so that nothing that can still fail comes after a removal.
            self.remove_stopped_rejected_transceivers();
        }

        if local_description.sdp_type != RTCSdpType::Rollback
            && let Some(parsed) = local_description.parsed.as_ref()
        {
            self.begin_local_gathering(parsed);
        }

        if matches!(
            local_description.sdp_type,
            RTCSdpType::Answer | RTCSdpType::Pranswer
        ) {
            self.assign_data_channel_ids();
        }

        // wpt100:hdrext — Cryptex once both sides signalled it (RFC 9335).
        self.update_cryptex();
        self.update_encrypted_header_extensions();

        Ok(())
    }

    /// Returns the local session description.
    ///
    /// Returns `pending_local_description` if it is not null, otherwise returns
    /// `current_local_description`. This property is used to determine if
    /// `set_local_description` has already been called.
    ///
    /// # Specification
    ///
    /// See [localDescription](https://www.w3.org/TR/webrtc/#dom-peerconnection-localdescription)
    pub fn local_description(&self) -> Option<RTCSessionDescription> {
        if let Some(pending_local_description) = self.pending_local_description() {
            return Some(pending_local_description);
        }
        self.current_local_description()
    }

    /// Returns the current local description as last successfully negotiated since
    /// the last negotiation completed.
    ///
    /// This represents the local description from the last offer/answer exchange that was
    /// successfully applied, not including any offers currently being negotiated.
    ///
    /// Returns `None` if there is no current local description (e.g., before initial negotiation).
    ///
    /// # Specification
    ///
    /// See [currentLocalDescription](https://www.w3.org/TR/webrtc/#dom-peerconnection-currentlocaldesc)
    pub fn current_local_description(&self) -> Option<RTCSessionDescription> {
        self.populate_local_candidates(self.current_local_description.as_ref())
    }

    /// Returns the pending local description if it exists.
    ///
    /// This represents the local description from a call to `set_local_description()` whose
    /// corresponding remote description has not yet been applied. This is `None` if negotiation
    /// is not in progress or if a rollback has been performed.
    ///
    /// Returns `None` if there is no pending local description.
    ///
    /// # Specification
    ///
    /// See [pendingLocalDescription](https://www.w3.org/TR/webrtc/#dom-peerconnection-pendinglocaldesc)
    pub fn pending_local_description(&self) -> Option<RTCSessionDescription> {
        self.populate_local_candidates(self.pending_local_description.as_ref())
    }

    /// Returns whether the remote peer supports trickle ICE.
    ///
    /// This value is determined from the remote SDP description after `set_remote_description()`
    /// is called. It checks for "trickle" in the "ice-options" attribute per
    /// RFC 8838 and RFC 9429 section 4.1.17.
    ///
    /// Returns:
    /// - `None` if no remote description has been set yet (unknown)
    /// - `Some(true)` if the remote peer indicated trickle ICE support
    /// - `Some(false)` if the remote peer did not indicate support
    ///
    /// # Specification
    ///
    /// See [canTrickleIceCandidates](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-cantrickleicecandidates)
    pub fn can_trickle_ice_candidates(&self) -> Option<bool> {
        self.can_trickle_ice_candidates
    }

    /// The ICE options of the current remote description (`a=ice-options`, RFC 8839 section
    /// 5.6), each once: `trickle` (RFC 8840), `ice2` (RFC 8445 section 10: the peer implements
    /// RFC 8445 rather than RFC 5245), and any other the peer states. Empty without a remote
    /// description.
    pub fn remote_ice_options(&self) -> Vec<String> {
        self.remote_description()
            .and_then(|r| r.parsed.as_ref())
            .map(remote_ice_options)
            .unwrap_or_default()
    }

    /// The lip synchronization groups of the current remote description (`a=group:LS`, RFC
    /// 5888 section 7), each the mids of media sections whose playout the remote side wants
    /// synchronized: the receivers of those transceivers are played out in sync by an
    /// application that renders them. Empty without a remote description or groups.
    pub fn remote_lip_sync_groups(&self) -> Vec<Vec<String>> {
        self.remote_description()
            .and_then(|r| r.parsed.as_ref())
            .map(crate::peer_connection::sdp::ls_groups)
            .unwrap_or_default()
    }

    /// Sets the remote description as part of the offer/answer negotiation.
    ///
    /// This changes the remote description associated with the connection. This description
    /// specifies the properties of the remote end of the connection, including the media format.
    ///
    /// # Parameters
    ///
    /// * `remote_description` - The remote session description to set.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The peer connection is closed
    /// - The SDP cannot be parsed
    /// - The media engine fails to update from the remote description
    ///
    /// # Specification
    ///
    /// See [setRemoteDescription](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-setremotedescription!overload-1)
    pub fn set_remote_description(
        &mut self,
        now: Instant,
        remote_description: RTCSessionDescription,
    ) -> Result<()> {
        // W3C webrtc-pc section 4.4.2 (`setRemoteDescription`), the implicit rollback: a remote
        // offer that arrives while a local offer is pending rolls the local offer back and is then applied, as
        // one operation. RFC 9429's state machine is kept (the rollback of section 5.7, then
        // the offer in `stable`); `SettingEngineBuilder::with_implicit_rollback(false)`
        // leaves the rollback to the application and refuses the offer (section 5.6). An
        // offer that is then refused leaves the local offer pending.
        if !self.setting_engine.explicit_rollback_only
            && remote_description.sdp_type == RTCSdpType::Offer
            && self.signaling_state == RTCSignalingState::HaveLocalOffer
            && self.peer_connection_state != RTCPeerConnectionState::Closed
        {
            let snapshot = self.description_snapshot();
            self.apply_set_remote_description(now, RTCSessionDescription::rollback(None)?)?;
            return match self.apply_set_remote_description(now, remote_description) {
                Ok(()) => Ok(()),
                Err(err) => {
                    self.restore_description_snapshot(snapshot);
                    Err(err)
                }
            };
        }
        self.apply_set_remote_description(now, remote_description)
    }

    fn apply_set_remote_description(
        &mut self,
        now: Instant,
        mut remote_description: RTCSessionDescription,
    ) -> Result<()> {
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        let answers = matches!(
            remote_description.sdp_type,
            RTCSdpType::Answer | RTCSdpType::Pranswer
        );

        // Parse SDP (skip for rollback as content is ignored per spec)
        if remote_description.sdp_type != RTCSdpType::Rollback {
            let mut parsed = remote_description.unmarshal()?;
            self.assign_missing_mids(&mut parsed, answers);
            discard_stray_bundle_only(&mut parsed, answers);
            check_extmap_levels(&parsed)?;
            inherit_session_extmap(&mut parsed);
            inherit_session_rtcp_xr(&mut parsed);
            check_extmap_ids(&parsed)?;
            if !answers {
                let taken: Vec<u16> = self
                    .media_engine
                    .negotiated_header_extensions
                    .keys()
                    .copied()
                    .collect();
                let registered = &self.media_engine.header_extensions;
                remap_answerer_assigned_extmaps(
                    &mut parsed,
                    |kind, uri| {
                        registered.iter().any(|e| {
                            e.uri == uri
                                && (kind == "audio" && e.is_audio || kind == "video" && e.is_video)
                        })
                    },
                    &taken,
                );
            }
            // `RTCRtpHeaderEncryptionPolicy::Require`: refused before any of it is applied.
            self.check_required_cryptex(&parsed)?;
            // RFC 8841 section 5.1: a data section without a valid `a=sctp-port` is invalid.
            validate_application_media_section(&parsed)?;
            // So is a description whose DTLS attributes are malformed (RFC 8122 section 5,
            // RFC 4145 section 4, RFC 8842 sections 4 and 5.1).
            validate_dtls_attributes(&parsed, self.setting_engine.accept_lowercase_fingerprints)?;
            // RFC 8122 section 5: a certificate is verified with the most preferred hash
            // function the peer offers; MD5, MD2 and functions the crypto provider lacks are
            // never used. A description that offers nothing else cannot be verified at all.
            if !self
                .dtls_transport()
                .disable_certificate_fingerprint_verification
                && let Ok(fingerprints) = extract_fingerprints(&parsed)
                && preferred_fingerprints(
                    &fingerprints,
                    self.dtls_transport().crypto_provider.crypto(),
                )
                .is_none()
            {
                return Err(Error::ErrUnsupportedFingerprintAlgorithm);
            }
            remote_description.parsed = Some(parsed);
        }

        // The codecs and header extensions the description negotiates, worked out on a copy
        // and kept only once the description is accepted: a description the media engine
        // can't read (or the signaling state refuses) changes neither the signaling state nor
        // the negotiated codecs.
        let negotiated_media_engine = match &remote_description.parsed {
            Some(parsed) => {
                let mut media_engine = self.media_engine.clone();
                media_engine.update_from_remote_description(parsed)?;
                Some(media_engine)
            }
            None => None,
        };

        // Everything that can refuse the description is checked before anything is changed
        // (RFC 9429 section 5.10: "the session state MUST be restored to its state before";
        // W3C webrtc-pc "set a session description": a description that fails the checks of
        // RFC 9429 section 5.8 leaves the connection as it was): the signaling state, the
        // media sections, an answer against its offer, and the ICE and DTLS parameters.
        let next_state = self.check_description(&remote_description, StateChangeOp::SetRemote)?;
        if let Some(parsed) = &remote_description.parsed {
            self.check_remote_description(parsed, answers)?;
        }

        // What is left can only fail inside a transport; should it, the description state is
        // put back as it was.
        let snapshot = self.description_snapshot();
        let (sdp_type, prior_state) = (remote_description.sdp_type, self.signaling_state);
        let applied = self.apply_remote_description(
            now,
            remote_description,
            next_state,
            negotiated_media_engine,
        );
        if applied.is_err() {
            self.restore_description_snapshot(snapshot);
        } else {
            self.after_remote_description(sdp_type, prior_state);
        }
        applied
    }

    /// Gives the ICE and DTLS transports the parameters of a remote description: an answer's
    /// when it is applied, an offer's when the local answer to it is
    /// ([`Self::defer_remote_transport`]; `deferred_ice_restart` is whether that offer restarts
    /// ICE, as worked out then: the restart's local half was applied with the answer).
    fn apply_remote_transport(
        &mut self,
        now: Instant,
        parsed_remote_description: &::sdp::description::session::SessionDescription,
        we_offer: bool,
        deferred_ice_restart: Option<bool>,
    ) -> Result<()> {
        // The ICE and DTLS transports start with the first description that sets one up,
        // not with the first remote description: a description with nothing to negotiate
        // (no m-section) has no ICE credentials, and a remote offer may be applied again or
        // rolled back before an answer makes it current.
        let transports_started = self.ice_transport().state() != RTCIceTransportState::New;

        if let Some(RemoteIceDetails {
            ufrag: remote_ufrag,
            pwd: remote_pwd,
            candidates,
        }) = extract_ice_details(parsed_remote_description)?
        {
            let remote_end_of_candidates = parsed_remote_description
                .media_descriptions
                .iter()
                .any(|m| !is_rejected_media(m) && m.has_attribute(ATTR_KEY_END_OF_CANDIDATES));
            // A description that sets up a transport consumes the closure of the last one.
            let new_association = std::mem::take(&mut self.transport_closed);
            let remote_is_lite = is_lite_set(parsed_remote_description);
            let local_ice_role = self.local_ice_role(remote_is_lite, we_offer);
            let remote_dtls_parameters = RTCDtlsParameters {
                role: RTCDtlsRole::from(parsed_remote_description),
                fingerprints: extract_fingerprints(parsed_remote_description)?,
            };

            let remote_tls_id = extract_tls_id(parsed_remote_description)?;
            // A session with media sections needs SRTP keys from the association: it is
            // set up with `use_srtp`, and one that was not is replaced (RFC 5764 section
            // 4.1).
            self.dtls_transport_mut().srtp_required = has_rtp_media(parsed_remote_description);

            // After the transport was closed, the description that sets one up again starts
            // a new ICE session even when the peer keeps its ICE credentials: some browsers
            // hold one ufrag/pwd per session, not per transport (Firefox), so a new m-section
            // after every one was rejected arrives with the old credentials but new
            // candidates and a new DTLS association. Keeping the old session left the agent on
            // the closed transport's selected pair, sending the DTLS handshake there.
            let ice_restart = deferred_ice_restart.unwrap_or_else(|| {
                transports_started
                    && (new_association
                        || self
                            .ice_transport()
                            .have_remote_credentials_change(&remote_ufrag, &remote_pwd))
            });
            // The local half of a restart was applied with this side's description (the
            // offerer's offer, the answerer's answer): the transport takes the peer's new
            // credentials. So does one whose credentials a restart of this side's cleared.
            if transports_started
                && (ice_restart
                    || self
                        .ice_transport()
                        .have_remote_credentials_change(&remote_ufrag, &remote_pwd))
            {
                self.ice_transport_mut()
                    .set_remote_credentials(remote_ufrag.clone(), remote_pwd.clone())?;
            }
            if transports_started {
                // RFC 8445 section 6.1.1: "Once the roles are determined for a session,
                // they persist throughout the lifetime of the session", an ICE restart
                // included ("an ICE agent MUST NOT redetermine the role as part of an ICE
                // restart unless" a full agent became lite, or a role conflict is
                // repaired, which the agent does by itself). So whoever offers later, the
                // ICE agent keeps its role, except that with one lite and one full agent
                // the full one is controlling, and that a transport set up again after it
                // was closed is a new session: its roles are determined as the first
                // time, by who offers. (`local_ice_role`, which follows the offerer, is
                // what the DTLS role is derived from when `a=setup` leaves it open.)
                let local_is_lite = self.setting_engine.candidates.ice_lite;
                self.ice_transport_mut()
                    .agent
                    .set_remote_lite(remote_is_lite);
                let role = if remote_is_lite != local_is_lite {
                    Some(if local_is_lite {
                        RTCIceRole::Controlled
                    } else {
                        RTCIceRole::Controlling
                    })
                } else if new_association {
                    Some(local_ice_role)
                } else {
                    None
                };
                if let Some(role) = role
                    && role != self.ice_transport().role()
                {
                    self.ice_transport_mut().set_role(role);
                    self.pipeline_context.stats.transport.ice_role = role;
                }

                // RFC 8842 section 3.1: the DTLS association goes on, across an ICE restart
                // too, unless the description changes the roles, the fingerprints or the
                // `tls-id`, or sets up a transport that was closed; then a new association
                // replaces it, with or without an ICE restart.
                let association = self.dtls_transport_mut().update_remote(
                    local_ice_role,
                    remote_dtls_parameters.clone(),
                    remote_tls_id.clone(),
                    DtlsRemoteUpdate {
                        we_offer,
                        ice_restart,
                        transport_closed: new_association,
                    },
                )?;
                if association == DtlsAssociationUpdate::New {
                    self.pipeline_context
                        .stats
                        .transport
                        .on_dtls_state_changed(RTCDtlsTransportState::Connecting);
                    // An ICE restart starts the client's handshake when it selects its
                    // pair. Without one no pair change is coming: the handshake starts now,
                    // on the pair ICE has (or with the first pair, if it has none yet).
                    if !ice_restart && self.ice_transport().agent.media_path().is_some() {
                        self.pipeline_context.dtls_handler_context.connect_requested = Some(now);
                    }
                    self.update_connection_state(false);
                }
            }

            // Two lite agents, this one controlled: an offer with `a=remote-candidates` is the
            // controlling agent's updated candidate exchange (RFC 8445 section 8.2, RFC 8839
            // section 4.4.2.2): its candidates replace the remote ones, and the agent selects
            // again among them.
            let lite_update = !we_offer
                && remote_is_lite
                && self.setting_engine.candidates.ice_lite
                && transports_started
                && !remote_candidates(parsed_remote_description)?.is_empty();
            if lite_update {
                self.ice_transport_mut()
                    .agent
                    .replace_remote_candidates(now, candidates);
            } else {
                // The description's candidate lines: candidates the application supplied, as
                // much as those it trickles.
                for candidate in candidates {
                    self.add_signalled_remote_candidate(candidate)?;
                }
            }
            // `a=end-of-candidates` (RFC 8838 section 14): the candidates above were the
            // generation's last. The agent ignores later ones and can fail without
            // waiting for its timeout when none of them works.
            if remote_end_of_candidates {
                self.ice_transport_mut()
                    .agent
                    .set_remote_end_of_candidates();
            }

            if !transports_started {
                log::trace!(
                    "start_transports: local_ice_role={local_ice_role}, remote_dtls_role={}",
                    remote_dtls_parameters.role
                );

                self.start_transports(
                    now,
                    local_ice_role,
                    RTCIceParameters {
                        username_fragment: remote_ufrag,
                        password: remote_pwd,
                        ice_lite: remote_is_lite,
                    },
                    remote_dtls_parameters,
                )?;
                self.dtls_transport_mut().remote_tls_id = remote_tls_id;
            }
            // RFC 8445 section 14.2: "Both agents MUST use the higher out of the two
            // proposed values"; the peer's is its `a=ice-pacing` (RFC 8839 section 5.5),
            // the default when it states none. Every description states it again.
            self.ice_transport_mut()
                .agent
                .set_remote_pacing(remote_ice_pacing(parsed_remote_description));
        }
        Ok(())
    }

    /// The ICE role of this side for a description that sets up a transport. If one of the
    /// agents is lite and the other one is not, the full agent is the controlling one. If both
    /// or neither agents are lite the offering agent is controlling (RFC 8445 section 6.1.1).
    fn local_ice_role(&self, remote_is_lite: bool, we_offer: bool) -> RTCIceRole {
        let local_is_lite = self.setting_engine.candidates.ice_lite;
        if (we_offer && remote_is_lite == local_is_lite) || (remote_is_lite && !local_is_lite) {
            RTCIceRole::Controlling
        } else {
            RTCIceRole::Controlled
        }
    }

    /// Keeps the transport part of a remote offer for the local answer
    /// ([`internal::PendingRemoteTransport`]), so that a rollback of the offer leaves the ICE
    /// and DTLS transports as they were (RFC 9429 section 5.7): nothing is started, restarted
    /// or replaced, and no candidate of the offer's ICE generation reaches the agent, until the
    /// answer is applied. What the answer states is staged: the new local ICE credentials of a
    /// restart, the role and `tls-id` of a new DTLS association.
    fn defer_remote_transport(
        &mut self,
        parsed: &::sdp::description::session::SessionDescription,
    ) -> Result<()> {
        // An offer applied over a pending one replaces it.
        self.drop_pending_remote_transport();
        let Some(RemoteIceDetails { ufrag, pwd, .. }) = extract_ice_details(parsed)? else {
            return Ok(());
        };
        let transports_started = self.ice_transport().state() != RTCIceTransportState::New;
        let ice_restart = transports_started
            && (self.transport_closed
                || self
                    .ice_transport()
                    .have_remote_credentials_change(&ufrag, &pwd));
        // The answer carries the new local credentials: staged now, applied with the answer.
        // Credentials an offer of this side staged already are the ones it carries.
        let staged_restart = if ice_restart && !self.ice_transport().has_pending_restart() {
            let gathering = self.ice_transport().gathering_state();
            self.stage_ice_restart()?;
            Some(gathering)
        } else {
            None
        };
        let new_dtls_role = self.dtls_transport().planned_association(
            self.local_ice_role(is_lite_set(parsed), false),
            &RTCDtlsParameters {
                role: RTCDtlsRole::from(parsed),
                fingerprints: extract_fingerprints(parsed)?,
            },
            extract_tls_id(parsed)?.as_deref(),
            DtlsRemoteUpdate {
                we_offer: false,
                ice_restart,
                transport_closed: self.transport_closed,
            },
            has_rtp_media(parsed),
        );
        let staged_tls_id =
            new_dtls_role.is_some() && self.dtls_transport_mut().stage_answer_tls_id()?;
        self.pending_remote_transport = Some(internal::PendingRemoteTransport {
            ufrag,
            ice_restart,
            staged_restart,
            new_dtls_role,
            staged_tls_id,
        });
        Ok(())
    }

    /// Whether the remote candidates of the pending remote offer's ICE generation wait for the
    /// local answer: the offer starts the transport or restarts ICE.
    fn remote_candidates_wait_for_answer(&self) -> bool {
        self.pending_remote_transport
            .as_ref()
            .is_some_and(|pending| {
                pending.ufrag != self.ice_transport().get_remote_user_credentials().0
            })
    }

    /// The checks `set_remote_description` makes on a parsed description before applying it
    /// (RFC 9429 section 5.8.3), none of which changes anything:
    ///
    /// - every media section has a mid (`assign_missing_mids` has run);
    /// - an answer or provisional answer answers the pending local offer
    ///   ([`check_answer_against_offer`]) and names only media sections that have a transceiver;
    /// - the formats of each audio and video section can be read;
    /// - the ICE credentials and candidates and the DTLS fingerprints of the transport the
    ///   description sets up are present, well formed and do not conflict.
    fn check_remote_description(
        &self,
        parsed: &::sdp::description::session::SessionDescription,
        answers: bool,
    ) -> Result<()> {
        let mut mids: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for media in &parsed.media_descriptions {
            let Some(mid) = get_mid_value(media).filter(|mid| !mid.is_empty()) else {
                return Err(Error::ErrPeerConnRemoteDescriptionWithoutMidValue);
            };
            // RFC 5888 section 4: the identification-tag is a token, and "MUST be unique
            // within an SDP session description" (RFC 9429 section 5.8.2: "if a MID is
            // repeated, this is an error").
            if !is_sdp_token(mid) {
                return Err(Error::SdpInvalidValue(format!(
                    "a=mid:{mid} is not a token (RFC 5888 section 4)"
                )));
            }
            if !mids.insert(mid.as_str()) {
                return Err(Error::SdpInvalidValue(format!(
                    "a=mid:{mid} names more than one media section (RFC 5888 section 4)"
                )));
            }
        }

        if answers {
            if let Some(offer) = self
                .pending_local_description
                .as_ref()
                .and_then(|offer| offer.parsed.as_ref())
            {
                check_answer_against_offer(offer, parsed)?;
            }
            let transceiver_by_mid =
                RTCPeerConnection::transceiver_index_by_mid(&self.rtp_transceivers);
            for media in &parsed.media_descriptions {
                if media.is_webrtc_datachannel()
                    || is_rejected_media(media)
                    || RtpCodecKind::from(media.media_name.media.as_str())
                        == RtpCodecKind::Unspecified
                {
                    continue;
                }
                if !get_mid_value(media)
                    .is_some_and(|mid| transceiver_by_mid.contains_key(mid.as_str()))
                {
                    return Err(Error::ErrPeerConnTransceiverMidNil);
                }
            }
        }

        for media in &parsed.media_descriptions {
            if !media.is_webrtc_datachannel()
                && !is_unknown_application_media(media)
                && !is_rejected_media(media)
                && RtpCodecKind::from(media.media_name.media.as_str()) != RtpCodecKind::Unspecified
            {
                codecs_from_media_description(media)?;
                if let Some(err) = sdp::simulcast::malformed_simulcast_line(media) {
                    return Err(Error::SdpInvalidValue(format!(
                        "{err} (RFC 9429 section 5.8, RFC 8853 section 5.2)"
                    )));
                }
                // RFC 9429 section 5.8.3: "All rid-ids referenced in an 'a=simulcast' line
                // MUST exist as 'a=rid' lines."
                if let Some(rid) = sdp::simulcast::simulcast_rid_without_line(media) {
                    return Err(Error::SdpInvalidValue(format!(
                        "a=simulcast names rid {rid} without an a=rid line (RFC 9429 section 5.8.3)"
                    )));
                }
            }
        }

        // RTP/RTCP multiplexing (RFC 9429 section 5.8.3). This endpoint has no RTCP component,
        // so a section that does not multiplex cannot be used at all.
        for (index, media) in parsed.media_descriptions.iter().enumerate() {
            if media.has_attribute(ATTR_KEY_RTCP_MUX_ONLY) && !has_rtcp_mux(media) {
                return Err(Error::SdpInvalidValue(format!(
                    "m= section {index}: a=rtcp-mux-only without a=rtcp-mux (RFC 8858 section 4.2)"
                )));
            }
            // In a subsequent offer or an answer a bundled section leaves the attribute to the
            // tagged section of its group (RFC 9143 section 7.1.3). In an initial offer only a
            // bundle-only section does (section 9.3.1.1).
            if !is_live_rtp_section(media)
                || section_multiplexes_rtcp(parsed, media, !answers && self.is_initial_exchange())
            {
                continue;
            }
            if answers {
                // RFC 8858 section 4.4, RFC 9429 section 5.11: "if no RTCP component exists
                // ... this indicates an error".
                return Err(Error::SdpInvalidValue(format!(
                    "m= section {index}: the answer has no a=rtcp-mux and there is no RTCP \
                     component to fall back to (RFC 8858 section 4.4)"
                )));
            }
            // W3C webrtc-pc "set a session description" and RFC 9429 section 5.8.3: under the
            // mux policy "require" (the default) every m= section has `a=rtcp-mux`. Under
            // "negotiate" the offer is applied and that section is answered rejected.
            if self.configuration.rtcp_mux_policy
                != crate::peer_connection::configuration::RTCRtcpMuxPolicy::Negotiate
            {
                return Err(Error::SdpInvalidValue(format!(
                    "m= section {index}: no a=rtcp-mux under the RTCP mux policy \"require\" \
                     (RFC 9429 section 5.8.3)"
                )));
            }
        }

        if extract_ice_details(parsed)?.is_some() {
            extract_fingerprints(parsed)?;
        }
        // RFC 9429 section 5.8.2: "Any 'a=remote-candidates' attributes MUST be parsed".
        remote_candidates(parsed)?;
        Ok(())
    }

    /// Applies a remote description `set_remote_description` has checked.
    fn apply_remote_description(
        &mut self,
        now: Instant,
        remote_description: RTCSessionDescription,
        next_state: RTCSignalingState,
        negotiated_media_engine: Option<MediaEngine>,
    ) -> Result<()> {
        let answers = matches!(
            remote_description.sdp_type,
            RTCSdpType::Answer | RTCSdpType::Pranswer
        );

        self.commit_description(&remote_description, StateChangeOp::SetRemote, next_state)?;
        if remote_description.sdp_type != RTCSdpType::Rollback {
            self.trickled_remote_candidates = 0;
        }
        if let Some(media_engine) = negotiated_media_engine {
            self.media_engine = media_engine;
        }
        self.pipeline_context
            .interceptor_handler_context
            .ssrc_owners
            .clear();
        self.pipeline_context
            .endpoint_handler_context
            .ssrc_owners
            .clear();

        if let Some(parsed_remote_description) = &remote_description.parsed {
            // Detect trickle ICE support from remote SDP (RFC 8838/RFC 9429 section 4.1.17)
            // Check for "trickle" in space-separated "ice-options" attribute values
            let has_trickle_ice = has_ice_trickle_option(parsed_remote_description);

            match remote_description.sdp_type {
                RTCSdpType::Offer | RTCSdpType::Answer | RTCSdpType::Pranswer => {
                    self.can_trickle_ice_candidates = Some(has_trickle_ice);
                }
                _ => {
                    // Rollback or other types: reset to unknown
                    self.can_trickle_ice_candidates = None;
                }
            }

            // Disable RTX/FEC on RTPSenders if the remote didn't support it
            for transceiver in &mut self.rtp_transceivers {
                if let Some(sender) = transceiver.sender_mut() {
                    let (is_rtx_enabled, is_fec_enabled) = (
                        self.media_engine
                            .is_rtx_enabled(sender.kind(), RTCRtpTransceiverDirection::Sendonly),
                        self.media_engine
                            .is_fec_enabled(sender.kind(), RTCRtpTransceiverDirection::Sendonly),
                    );
                    sender.configure_rtx_and_fec(is_rtx_enabled, is_fec_enabled);
                }
            }

            // A provisional answer is, like the final one, the remote side answering our offer
            // (RFC 8829 §4.1.10.1): it decides the ICE role and doesn't create transceivers.
            let is_final_answer = remote_description.sdp_type == RTCSdpType::Answer;
            let we_offer = is_final_answer || remote_description.sdp_type == RTCSdpType::Pranswer;

            // Extract media descriptions to avoid borrowing conflicts
            let media_descriptions = self
                .remote_description()
                .as_ref()
                .and_then(|r| r.parsed.as_ref())
                .map(|parsed| parsed.media_descriptions.clone());

            if let Some(media_descriptions) = media_descriptions {
                // Each mid's transceiver, kept up to date as m-sections claim transceivers, so
                // matching a description's m-sections is one lookup each.
                let mut transceiver_by_mid =
                    RTCPeerConnection::transceiver_index_by_mid(&self.rtp_transceivers);
                if !we_offer {
                    for media in &media_descriptions {
                        let mid_value = match get_mid_value(media) {
                            Some(mid) if !mid.is_empty() => mid,
                            _ => return Err(Error::ErrPeerConnRemoteDescriptionWithoutMidValue),
                        };

                        if media.is_webrtc_datachannel() {
                            continue;
                        }

                        // A rejected m= section (port 0) is answered rejected. The transceiver
                        // it already has is stopped, unless it is already (W3C 4.4.1.6: "if the
                        // media description is rejected, and transceiver is not already
                        // stopped, stop the RTCRtpTransceiver"), firing no track event. One no
                        // transceiver has yet gets one, as every m= section does (RFC 9429
                        // section 5.10), created stopped: no direction, no media, no track
                        // event. A rollback of the offer removes a transceiver it created; one
                        // it stopped stays stopped (the stop algorithm is not undone).
                        if is_rejected_media(media) {
                            let kind = RtpCodecKind::from(media.media_name.media.as_str());
                            if let Some(&i) = transceiver_by_mid.get(mid_value.as_str()) {
                                self.rtp_transceivers[i]
                                    .stop(&self.media_engine, &mut self.interceptor)?;
                            } else if matches!(kind, RtpCodecKind::Audio | RtpCodecKind::Video)
                                // A section the last exchange already rejected, whose stopped
                                // transceiver was removed then, is not a new section: it gets
                                // no transceiver again.
                                && !self.rejected_in_current_description(mid_value)
                            {
                                let mut transceiver = RTCRtpTransceiverInternal::new(
                                    kind,
                                    None,
                                    RTCRtpTransceiverInit {
                                        direction: RTCRtpTransceiverDirection::Recvonly,
                                        streams: vec![],
                                        send_encodings: vec![],
                                    },
                                );
                                transceiver.set_mid(mid_value.to_string())?;
                                // Gone again if this offer is rolled back (RFC 9429, Section 5.7).
                                transceiver.set_created_by_remote_description(true);
                                transceiver.stop(&self.media_engine, &mut self.interceptor)?;
                                let i = self.add_rtp_transceiver(transceiver);
                                transceiver_by_mid.entry(mid_value.to_string()).or_insert(i);
                            }
                            continue;
                        }

                        let kind = RtpCodecKind::from(media.media_name.media.as_str());
                        // A section with no direction attribute, its own or the session's,
                        // is sendrecv (RFC 8866 section 6.7, RFC 3264 section 6.1).
                        let direction = effective_direction(parsed_remote_description, media);
                        if kind == RtpCodecKind::Unspecified || is_unknown_application_media(media)
                        {
                            continue;
                        }

                        // Applying an offer leaves the transceiver's [[Direction]] alone (W3C
                        // 4.4.1.6): the answer states it intersected with the reverse of the
                        // offered direction (RFC 9429 section 5.3.1), so an `a=inactive` or a
                        // one-way offer pauses it only for that answer, and a later sendrecv
                        // offer is answered sendrecv again. Only a rejected section, port 0,
                        // stops a transceiver (RFC 9429 section 5.10).
                        let transceiver_index =
                            if let Some(&i) = transceiver_by_mid.get(mid_value.as_str()) {
                                Some(i)
                            } else {
                                RTCPeerConnection::satisfy_type_and_direction(
                                    kind,
                                    direction,
                                    &self.rtp_transceivers,
                                )
                            };

                        if let Some(i) = transceiver_index {
                            let transceiver = &mut self.rtp_transceivers[i];
                            transceiver.set_codec_preferences_from_remote_description(
                                media,
                                &self.media_engine,
                            )?;

                            if transceiver.mid().is_none() {
                                transceiver.set_mid(mid_value.to_string())?;
                                transceiver_by_mid.entry(mid_value.to_string()).or_insert(i);
                            }
                        } else {
                            // W3C webrtc-pc "set a session description": "Create an
                            // RTCRtpTransceiver with ... direction 'recvonly'", whatever the
                            // offered direction (RFC 9429 section 5.10). It has no sender
                            // until `addTrack` gives it one, so a section offered recvonly is
                            // answered inactive.
                            let mut transceiver = RTCRtpTransceiverInternal::new(
                                kind,
                                None,
                                RTCRtpTransceiverInit {
                                    direction: RTCRtpTransceiverDirection::Recvonly,
                                    streams: vec![],
                                    send_encodings: vec![],
                                },
                            );

                            transceiver.set_codec_preferences_from_remote_description(
                                media,
                                &self.media_engine,
                            )?;

                            if transceiver.mid().is_none() {
                                transceiver.set_mid(mid_value.to_string())?;
                            }

                            // Mark as implicitly created by a remote offer so that, if this offer
                            // is later rolled back, the transceiver is stopped and removed
                            // (RFC 9429, Section 5.7) — unless a track is attached via add_track.
                            transceiver.set_created_by_remote_description(true);

                            let i = self.add_rtp_transceiver(transceiver);
                            transceiver_by_mid.entry(mid_value.to_string()).or_insert(i);
                        }
                    }
                } else {
                    // we_offer
                    // WebRTC Spec 1.0 https://www.w3.org/TR/webrtc/
                    // 4.5.9.2
                    // This is an answer from the remote.
                    for media in &media_descriptions {
                        let mid_value = match get_mid_value(media) {
                            Some(mid) if !mid.is_empty() => mid,
                            _ => return Err(Error::ErrPeerConnRemoteDescriptionWithoutMidValue),
                        };

                        if media.is_webrtc_datachannel() {
                            continue;
                        }

                        // A rejected m= section in the answer: the transceiver is stopped (W3C
                        // 4.4.1.6), not given a direction; one already stopped stays as it is.
                        if is_rejected_media(media) {
                            if let Some(&i) = transceiver_by_mid.get(mid_value.as_str()) {
                                self.rtp_transceivers[i]
                                    .stop(&self.media_engine, &mut self.interceptor)?;
                            }
                            continue;
                        }

                        let kind = RtpCodecKind::from(media.media_name.media.as_str());
                        let mut direction = effective_direction(parsed_remote_description, media);
                        if kind == RtpCodecKind::Unspecified || is_unknown_application_media(media)
                        {
                            continue;
                        }

                        let transceiver =
                            if let Some(&i) = transceiver_by_mid.get(mid_value.as_str()) {
                                &mut self.rtp_transceivers[i]
                            } else {
                                return Err(Error::ErrPeerConnTransceiverMidNil);
                            };

                        // reverse direction if it was a remote answer
                        if direction == RTCRtpTransceiverDirection::Sendonly {
                            direction = RTCRtpTransceiverDirection::Recvonly;
                        } else if direction == RTCRtpTransceiverDirection::Recvonly {
                            direction = RTCRtpTransceiverDirection::Sendonly;
                        }

                        // [[CurrentDirection]] is set by a final answer only (W3C 4.4.1.6).
                        if is_final_answer {
                            transceiver.set_current_direction(direction);
                        }

                        transceiver.set_codec_preferences_from_remote_description(
                            media,
                            &self.media_engine,
                        )?;
                    }
                }
            }

            // What the remote side says about bandwidth, section by section.
            self.apply_remote_bandwidth(parsed_remote_description);

            // The ICE and DTLS transports take an answer's parameters now, an offer's
            // when the local answer is applied (`defer_remote_transport`).
            if we_offer {
                self.apply_remote_transport(now, parsed_remote_description, true, None)?;
            } else {
                self.defer_remote_transport(parsed_remote_description)?;
            }

            if is_final_answer
                && let Some(parsed_local_description) = self
                    .current_local_description
                    .as_ref()
                    .and_then(|desc| desc.parsed.clone())
                    .as_ref()
            {
                self.apply_negotiated_rtcp(parsed_local_description, parsed_remote_description);
                self.apply_negotiated_simulcast(
                    parsed_local_description,
                    parsed_remote_description,
                    false,
                );
                // The updated candidate exchange of two lite agents is complete (RFC 8445
                // section 8.2) once an offer that carried it is answered.
                if self
                    .pipeline_context
                    .ice_handler_context
                    .lite_candidate_update
                    .is_some()
                    && !remote_candidates(parsed_local_description)
                        .unwrap_or_default()
                        .is_empty()
                {
                    self.pipeline_context
                        .ice_handler_context
                        .lite_candidate_update = None;
                }

                // we_offer: we create_offer() and set_local_description() first
                // then, after call set_remote_description here,
                // Now we should have done SDP negotiation.
                // Therefore, it is ready to start sctp and rtp.
                let negotiated =
                    negotiated_sctp(parsed_local_description, parsed_remote_description);
                self.apply_sctp_negotiation(now, negotiated)?;
                self.start_rtp(remote_description.clone())?;
                self.apply_negotiated_session(
                    now,
                    parsed_local_description,
                    parsed_remote_description,
                )?;
            }

            // An answer applied: the stopped transceivers whose sections it left rejected go.
            // Last, so that nothing that can still fail comes after a removal.
            if is_final_answer {
                self.remove_stopped_rejected_transceivers();
            }
        }

        if answers {
            self.assign_data_channel_ids();
        }

        // wpt100:hdrext — Cryptex once both sides signalled it (RFC 9335).
        self.update_cryptex();
        self.update_encrypted_header_extensions();

        Ok(())
    }

    /// Returns the remote session description.
    ///
    /// Returns `pending_remote_description` if it is not null, otherwise returns
    /// `current_remote_description`. This property is used to determine if
    /// `set_remote_description` has already been called.
    ///
    /// # Specification
    ///
    /// See [remoteDescription](https://www.w3.org/TR/webrtc/#dom-peerconnection-remotedescription)
    pub fn remote_description(&self) -> Option<&RTCSessionDescription> {
        if self.pending_remote_description.is_some() {
            self.pending_remote_description.as_ref()
        } else {
            self.current_remote_description.as_ref()
        }
    }

    /// Returns the current remote description as last successfully negotiated since
    /// the last negotiation completed.
    ///
    /// This represents the remote description from the last offer/answer exchange that was
    /// successfully applied, not including any offers currently being negotiated.
    ///
    /// Returns `None` if there is no current remote description (e.g., before initial negotiation).
    ///
    /// # Specification
    ///
    /// See [currentRemoteDescription](https://www.w3.org/TR/webrtc/#dom-peerconnection-currentremotedesc)
    pub fn current_remote_description(&self) -> Option<&RTCSessionDescription> {
        self.current_remote_description.as_ref()
    }

    /// Returns the pending remote description if it exists.
    ///
    /// This represents the remote description from a call to `set_remote_description()` whose
    /// corresponding local description has not yet been applied. This is `None` if negotiation
    /// is not in progress or if a rollback has been performed.
    ///
    /// Returns `None` if there is no pending remote description.
    ///
    /// # Specification
    ///
    /// See [pendingRemoteDescription](https://www.w3.org/TR/webrtc/#dom-peerconnection-pendingremotedesc)
    pub fn pending_remote_description(&self) -> Option<&RTCSessionDescription> {
        self.pending_remote_description.as_ref()
    }

    /// Adds a remote ICE candidate to the peer connection.
    ///
    /// This method provides a remote candidate to the ICE agent. When the remote peer
    /// gathers ICE candidates and sends them over the signaling channel, this method
    /// should be called to add each candidate.
    ///
    /// # Parameters
    ///
    /// * `remote_candidate` - The ICE candidate initialization data.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No remote description has been set
    /// - The candidate string is invalid
    ///
    /// # Specification
    ///
    /// See [addIceCandidate](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-addicecandidate!overload-1)
    pub fn add_remote_candidate(&mut self, remote_candidate: RTCIceCandidateInit) -> Result<()> {
        let Some(parsed) = self
            .remote_description()
            .and_then(|r| r.parsed.as_ref())
            .cloned()
        else {
            return Err(Error::ErrNoRemoteDescription);
        };
        let parsed = &parsed;

        let candidate_value = match remote_candidate.candidate.strip_prefix("candidate:") {
            Some(s) => s,
            None => remote_candidate.candidate.as_str(),
        };
        // The value is written into the remote description's text as one line.
        if candidate_value
            .bytes()
            .any(|b| matches!(b, b'\r' | b'\n' | b'\0'))
        {
            return Err(Error::SdpInvalidValue(
                "ICE candidate contains CR, LF or NUL".to_owned(),
            ));
        }

        // The media description the candidate is for: sdpMid wins over sdpMLineIndex. With
        // neither, an end-of-candidates indication is for every media description; a candidate
        // without either (which W3C addIceCandidate refuses before it gets here) is given to the
        // ICE transport only.
        let section = if let Some(mid) = &remote_candidate.sdp_mid {
            Some(
                parsed
                    .media_descriptions
                    .iter()
                    .position(|m| get_mid_value(m).is_some_and(|v| v == mid))
                    .ok_or(Error::ErrIceCandidateMediaSectionNotFound)?,
            )
        } else if let Some(index) = remote_candidate.sdp_mline_index {
            let index = usize::from(index);
            if index >= parsed.media_descriptions.len() {
                return Err(Error::ErrIceCandidateMediaSectionNotFound);
            }
            Some(index)
        } else {
            None
        };

        // Without a usernameFragment, the line's own `ufrag` extension names its generation
        // (RFC 8838 section 9: a candidate is tied to an ICE session): one of another
        // generation is stale and is ignored.
        if remote_candidate.username_fragment.is_none()
            && let Some(line_ufrag) = candidate_line_ufrag(candidate_value)
        {
            let known = match section {
                Some(i) => {
                    media_ice_credentials(parsed, &parsed.media_descriptions[i]).0
                        == Some(line_ufrag)
                }
                None => parsed
                    .media_descriptions
                    .iter()
                    .any(|m| media_ice_credentials(parsed, m).0 == Some(line_ufrag)),
            };
            if !known {
                unmarshal_candidate(candidate_value)?;
                log::warn!(
                    "ignoring remote candidate: its ufrag {line_ufrag} names another ICE generation"
                );
                return Ok(());
            }
        }

        // A usernameFragment must be one of the corresponding media description's (any media
        // description's when there is none): a candidate of another ICE generation is refused.
        if let Some(ufrag) = remote_candidate.username_fragment.as_deref() {
            let known = match section {
                Some(i) => {
                    media_ice_credentials(parsed, &parsed.media_descriptions[i]).0 == Some(ufrag)
                }
                None => parsed
                    .media_descriptions
                    .iter()
                    .any(|m| media_ice_credentials(parsed, m).0 == Some(ufrag)),
            };
            if !known {
                return Err(Error::ErrIceCandidateUsernameFragmentMismatch);
            }
        }

        if candidate_value.is_empty() {
            // End-of-candidates (RFC 8838 §8.2) for the media description, or all of them.
            let count = parsed.media_descriptions.len();
            let sections: Vec<usize> = section.map_or_else(|| (0..count).collect(), |i| vec![i]);
            for i in sections {
                self.add_remote_description_attribute(
                    i,
                    remote_candidate.username_fragment.as_deref(),
                    ATTR_KEY_END_OF_CANDIDATES,
                    None,
                );
            }
            // One transport carries every section (BUNDLE): its agent is told, with the
            // answer when the candidates wait for it (it reads the description then).
            if !self.remote_candidates_wait_for_answer() {
                self.ice_transport_mut()
                    .agent
                    .set_remote_end_of_candidates();
            }
            return Ok(());
        }

        // RFC 8838 section 14: "After an agent has received an end-of-candidates indication, it
        // MUST ignore any newly received candidates for that data stream". Such a candidate is
        // checked and then ignored: it reaches neither the agent nor the description's text.
        let after_end_of_candidates = match section {
            Some(i) => parsed.media_descriptions[i].has_attribute(ATTR_KEY_END_OF_CANDIDATES),
            None => parsed
                .media_descriptions
                .iter()
                .any(|m| m.has_attribute(ATTR_KEY_END_OF_CANDIDATES)),
        };
        if after_end_of_candidates {
            unmarshal_candidate(candidate_value)?;
            log::warn!("ignoring remote candidate: it follows end-of-candidates");
            return Ok(());
        }

        // A candidate its media description already holds adds nothing; past the budget, a
        // candidate is checked and then ignored, as the ICE agent ignores one past its own cap.
        // Neither reaches the stats or the description's text.
        let duplicate = section.is_some_and(|i| {
            parsed.media_descriptions[i]
                .attributes
                .iter()
                .any(|a| a.key == ATTR_KEY_CANDIDATE && a.value.as_deref() == Some(candidate_value))
        });
        if duplicate || self.trickled_remote_candidates >= MAX_TRICKLED_REMOTE_CANDIDATES {
            unmarshal_candidate(candidate_value)?;
            if !duplicate {
                log::warn!(
                    "ignoring remote candidate: already took {MAX_TRICKLED_REMOTE_CANDIDATES} (the cap)"
                );
            }
            return Ok(());
        }

        // The candidates of a remote offer that starts the transport or restarts ICE reach
        // the agent with the local answer (`defer_remote_transport`), from the description.
        let waits = self.remote_candidates_wait_for_answer();
        let Some(section) = section else {
            if waits {
                unmarshal_candidate(candidate_value)?;
            } else {
                self.add_ice_remote_candidate(candidate_value)?;
            }
            self.trickled_remote_candidates += 1;
            return Ok(());
        };

        // Only a candidate of the ICE transport in use reaches the agent. One for another
        // m-section's own transport, which BUNDLE replaces (an offer under the `balanced` or
        // `max-compat` policy gives each m-section its own credentials), is recorded in the
        // remote description only.
        let section_ufrag = remote_candidate.username_fragment.clone().or_else(|| {
            media_ice_credentials(parsed, &parsed.media_descriptions[section])
                .0
                .map(str::to_owned)
        });
        let (transport_ufrag, _) = self.ice_transport().get_remote_user_credentials();
        if !waits
            && (transport_ufrag.is_empty()
                || section_ufrag.is_none()
                || section_ufrag.as_deref() == Some(transport_ufrag))
        {
            self.add_ice_remote_candidate(candidate_value)?;
        } else {
            // Still refuse what doesn't parse, as the transport would.
            unmarshal_candidate(candidate_value)?;
        }

        self.add_remote_description_attribute(
            section,
            section_ufrag.as_deref(),
            ATTR_KEY_CANDIDATE,
            Some(candidate_value),
        );
        self.trickled_remote_candidates += 1;
        Ok(())
    }

    /// Adds `a=<key>[:<value>]` to the remote description's media section `index`, in the
    /// pending and the current remote description, each only while that section is of the
    /// candidate's ICE generation (`ufrag`, when given). The SDP text keeps the remote side's
    /// own lines: the attribute is inserted at the end of the section. An end-of-candidates line
    /// a section already has isn't added again.
    fn add_remote_description_attribute(
        &mut self,
        index: usize,
        ufrag: Option<&str>,
        key: &str,
        value: Option<&str>,
    ) {
        for description in [
            self.pending_remote_description.as_mut(),
            self.current_remote_description.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            let Some(parsed) = description.parsed.as_mut() else {
                continue;
            };
            let Some(media) = parsed.media_descriptions.get(index) else {
                continue;
            };
            if ufrag.is_some() && media_ice_credentials(parsed, media).0 != ufrag {
                continue;
            }
            if value.is_none() && media.has_attribute(key) {
                continue;
            }
            parsed.media_descriptions[index]
                .attributes
                .push(Attribute::new(key.to_owned(), value.map(str::to_owned)));
            description.sdp = insert_media_line(&description.sdp, index, key, value);
        }
    }

    /// Reports what the transport learned about the path of a connectivity check: a hard ICMP
    /// error for a datagram sent on it (RFC 8445 section 7.2.5.2.2), a TCP connection that
    /// could not be established, or one whose first answer was not STUN (RFC 6544 section
    /// 7.1). `transport` names the path: the local address a candidate is based on and the
    /// remote candidate's address. Returns whether a candidate pair failed for it; a pair a
    /// check has validated never does (ICMP is not authenticated).
    pub fn handle_ice_transport_error(
        &mut self,
        now: Instant,
        transport: shared::TransportContext,
        error: ::ice::TransportError,
    ) -> bool {
        self.ice_transport_mut()
            .agent
            .handle_transport_error(now, transport, error)
    }

    /// Adds a local ICE candidate to the peer connection.
    ///
    /// This has no W3C counterpart: a browser's ICE agent gathers its own candidates, but this
    /// crate performs no I/O, so the application owns the sockets and therefore owns gathering.
    /// Every local candidate the connection is to advertise must be handed to this method.
    ///
    /// # Signalling the end of gathering
    ///
    /// An **empty candidate string** is the end-of-gathering sentinel. It advertises no
    /// candidate; it ends the current ICE generation's gathering as W3C webrtc-pc section 5.6
    /// has the user agent do: an `OnIceCandidateEvent` with the generation's end-of-candidates
    /// candidate ([`RTCIceCandidate::end_of_candidates`] set, its `candidate` attribute the
    /// empty string), the ICE gathering state [`RTCIceGatheringState::Complete`] with
    /// `OnIceGathererStateChange` and [`RTCPeerConnectionEvent::OnIceGatheringStateChangeEvent`],
    /// and last an `OnIceCandidateEvent` with no candidate. The local descriptions then carry
    /// `a=end-of-candidates`. A second sentinel for the same generation changes nothing; after
    /// an ICE restart the new generation gathers anew. No other call reaches `Complete`, so a
    /// caller that never sends it leaves the connection reporting `Gathering` forever. Send it
    /// once, after the last real candidate:
    ///
    /// ```no_run
    /// # use std::time::Instant;
    /// # use rtc::peer_connection::RTCPeerConnectionBuilder;
    /// use rtc::peer_connection::transport::RTCIceCandidateInit;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    /// // ... add every gathered candidate first ...
    /// pc.add_local_candidate(RTCIceCandidateInit::default())?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Parameters
    ///
    /// - `local_candidate`: The ICE candidate initialization data, or a value whose `candidate`
    ///   field is empty to signal end-of-gathering. For candidates of type `srflx` (server
    ///   reflexive) or `relay`, set `url` to the STUN/TURN server the candidate was gathered
    ///   from, so that `getStats` attributes it correctly.
    ///
    /// # Errors
    ///
    /// Returns an error if a non-empty candidate string cannot be parsed.
    ///
    /// [`RTCIceGatheringState::Complete`]: crate::peer_connection::state::RTCIceGatheringState::Complete
    /// [`RTCPeerConnectionEvent::OnIceGatheringStateChangeEvent`]: crate::peer_connection::event::RTCPeerConnectionEvent::OnIceGatheringStateChangeEvent
    /// [`RTCIceCandidate::end_of_candidates`]: crate::peer_connection::transport::RTCIceCandidate::end_of_candidates
    pub fn add_local_candidate(&mut self, local_candidate: RTCIceCandidateInit) -> Result<()> {
        let candidate_value = match local_candidate.candidate.strip_prefix("candidate:") {
            Some(s) => s,
            None => local_candidate.candidate.as_str(),
        };

        if !candidate_value.is_empty() {
            self.add_ice_local_candidate(candidate_value, local_candidate.url.as_deref())?;
        } else {
            self.finish_local_gathering();
        }

        Ok(())
    }

    /// W3C "set the RTCSessionDescription", for an answer or a provisional answer: once the
    /// description has negotiated the DTLS role of the SCTP transport, every in-band channel
    /// whose id is still null is given one by RFC 8832 section 6 (even as the DTLS client, odd
    /// as the server). Channels created before negotiation get their ids here rather than when
    /// SCTP later connects, as `RTCDataChannel.id` requires.
    ///
    /// Running out of ids does not fail the description: the channels left without one keep a
    /// null id, and the SCTP connected procedure tries them again against the association's
    /// negotiated stream count.
    fn assign_data_channel_ids(&mut self) {
        let dtls_role = self.dtls_transport().role();
        if !matches!(dtls_role, RTCDtlsRole::Client | RTCDtlsRole::Server) {
            return;
        }
        let max_channels = self.sctp_transport().max_channels();
        if let Err(err) = self
            .data_channels
            .assign_stream_ids(dtls_role, max_channels)
        {
            log::debug!("data channel ids not assigned: {err}");
        }
    }

    /// Tells the peer connection that ICE should be restarted.
    ///
    /// This method causes the next call to `create_offer` to generate an offer that
    /// will restart ICE. This is useful when network conditions change or the connection
    /// fails.
    ///
    /// # Specification
    ///
    /// See [restartIce](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-restartice)
    pub fn restart_ice(&mut self) {
        // W3C restartIce: every ICE credential of the current and pending local descriptions
        // is to be replaced, and the negotiation-needed flag is updated.
        self.ice_credentials_to_replace = self.local_ice_ufrags();
        self.trigger_negotiation_needed();
    }

    /// The RTCP canonical name (CNAME) of this connection: the one name every SSRC it sends
    /// from is described with in RTCP (RFC 3550 6.5.1), so that a receiver can tell which
    /// streams come from one endpoint and synchronise them.
    ///
    /// It is generated with the connection as RFC 7022 section 4.2 defines a short-term
    /// persistent CNAME (96 random bits, Base64: 16 characters), is the same for senders,
    /// retransmission and FEC streams and receiver reports, and does not change (RFC 8834
    /// 4.9).
    pub fn rtcp_cname(&self) -> &str {
        &self.pipeline_context.interceptor_handler_context.cname
    }

    /// The RTCP canonical name the remote source `ssrc` named in its SDES, once one has
    /// arrived (RFC 3550 6.5.1). Remote streams with the same CNAME come from one endpoint
    /// and share a clock, which is what makes them synchronisable (audio with video).
    ///
    /// Recorded by the RTCP session interceptor
    /// ([`configure_rtcp_reports`](crate::peer_connection::configuration::interceptor_registry::configure_rtcp_reports),
    /// part of the default interceptors); `None` without it.
    pub fn remote_rtcp_cname(&self, ssrc: crate::rtp_transceiver::SSRC) -> Option<&str> {
        self.pipeline_context
            .interceptor_handler_context
            .remote_cnames
            .get(&ssrc)
            .map(String::as_str)
    }

    /// Returns the current configuration of this peer connection.
    ///
    /// The returned reference is to the current configuration. To modify the configuration,
    /// use `set_configuration`.
    ///
    /// # Specification
    ///
    /// See [getConfiguration](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-getconfiguration)
    pub fn get_configuration(&self) -> &RTCConfiguration {
        &self.configuration
    }

    /// Updates the configuration of this peer connection (W3C "set a configuration").
    ///
    /// Only the fields the W3C algorithm permits changing after construction are applied, and
    /// only once every check has passed: a refused configuration changes nothing. ICE servers
    /// past [`MAX_ICE_SERVERS`](configuration::MAX_ICE_SERVERS) are ignored; an empty list
    /// clears them.
    ///
    /// # Parameters
    ///
    /// - `configuration`: The configuration to apply.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The peer connection is closed (`ErrConnectionClosed`)
    /// - The peer identity differs from the one already set (`ErrModifyingPeerIdentity`)
    /// - The certificates are not those the connection was constructed with, in the same
    ///   order (`ErrModifyingCertificates`); W3C `InvalidModificationError`
    /// - The bundle or RTCP multiplexing policy differs (`ErrModifyingBundlePolicy`,
    ///   `ErrModifyingRTCPMuxPolicy`), or the candidate pool size does once a local
    ///   description was set (`ErrModifyingICECandidatePoolSize`); W3C
    ///   `InvalidModificationError`
    /// - An ICE server fails "validate an ICE server URL" (see `RTCIceServer::urls`): W3C
    ///   `SyntaxError` or, for TURN credentials, `InvalidAccessError`
    ///
    /// # Specification
    ///
    /// See [setConfiguration](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-setconfiguration)
    pub fn set_configuration(&mut self, mut configuration: RTCConfiguration) -> Result<()> {
        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-setconfiguration (step #2)
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        // https://www.w3.org/TR/webrtc/#set-the-configuration: every check runs before
        // anything is changed, so that a refused configuration leaves the connection's as it
        // was (bug B6 of the audit).
        if !configuration.peer_identity.is_empty()
            && configuration.peer_identity != self.configuration.peer_identity
        {
            return Err(Error::ErrModifyingPeerIdentity);
        }
        // The certificates are those of the constructor, one for one: the same list, the same
        // certificates in the same order ("the same ECMAScript object": the same certificate
        // and expiry).
        if configuration.certificates.len() != self.configuration.certificates.len()
            || configuration
                .certificates
                .iter()
                .zip(&self.configuration.certificates)
                .any(|(new, old)| new != old || new.expires != old.expires)
        {
            return Err(Error::ErrModifyingCertificates);
        }
        if configuration.bundle_policy != self.configuration.bundle_policy {
            return Err(Error::ErrModifyingBundlePolicy);
        }
        if configuration.rtcp_mux_policy != self.configuration.rtcp_mux_policy {
            return Err(Error::ErrModifyingRTCPMuxPolicy);
        }
        if configuration.ice_candidate_pool_size != self.configuration.ice_candidate_pool_size
            && self.local_description().is_some()
        {
            return Err(Error::ErrModifyingICECandidatePoolSize);
        }
        configuration
            .ice_servers
            .truncate(configuration::MAX_ICE_SERVERS);
        for server in &configuration.ice_servers {
            server.validate()?;
        }

        // Every check passed: the configuration is stored, and the ICE agent's transport
        // setting follows; candidates already added stay, and the new setting applies from
        // the next gathering (RFC 9429, Section 4.1.18).
        if configuration.ice_transport_policy != self.configuration.ice_transport_policy {
            let candidate_types =
                if configuration.ice_transport_policy == RTCIceTransportPolicy::Relay {
                    vec![ice::candidate::CandidateType::Relay]
                } else {
                    vec![]
                };
            self.ice_transport_mut()
                .agent
                .set_candidate_types(candidate_types);
        }
        self.configuration.ice_transport_policy = configuration.ice_transport_policy;
        self.configuration.ice_candidate_pool_size = configuration.ice_candidate_pool_size;
        self.configuration.ice_servers = configuration.ice_servers;

        Ok(())
    }

    /// Creates a new data channel with the given label.
    ///
    /// The returned handle borrows the peer connection. To reach the channel again later,
    /// keep its [`RTCDataChannelId`] (from [`RTCDataChannel::id`]) and pass it to
    /// [`Self::data_channel`].
    ///
    /// A channel created here is not immediately usable: unless it was negotiated
    /// out-of-band, its SCTP stream is established by the in-band DCEP handshake, and sending
    /// before then fails. Wait for [`RTCDataChannelEvent::OnOpen`].
    ///
    /// # Parameters
    ///
    /// - `label`: The channel label. Labels need not be unique.
    /// - `options`: Optional configuration such as ordering, reliability and out-of-band
    ///   negotiation. Defaults are used when `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The peer connection is closed (`ErrConnectionClosed`)
    /// - The label or sub-protocol exceeds the 65535 bytes the DCEP OPEN message can carry
    ///   (`ErrLabelTooLarge`, `ErrProtocolTooLarge`)
    /// - `negotiated` names a stream id that already carries a data channel
    ///   (`ErrDataChannelIdInUse`), or 65535 (`ErrMaxDataChannelID`)
    ///
    /// # Specification
    ///
    /// See [createDataChannel](https://www.w3.org/TR/webrtc/#dom-peerconnection-createdatachannel)
    ///
    /// [`RTCDataChannelId`]: crate::data_channel::RTCDataChannelId
    /// [`RTCDataChannel::id`]: crate::data_channel::RTCDataChannel::id
    /// [`RTCDataChannelEvent::OnOpen`]: crate::peer_connection::event::RTCDataChannelEvent::OnOpen
    pub fn create_data_channel(
        &mut self,
        label: &str,
        options: Option<RTCDataChannelInit>,
    ) -> Result<RTCDataChannel<'_>> {
        // https://www.w3.org/TR/webrtc/#peer-to-peer-data-api (Step #2)
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        // RFC 8832 section 5.1: the DATA_CHANNEL_OPEN carries the label behind a 16-bit
        // length (W3C createDataChannel: a longer one throws a TypeError).
        if label.len() > 65535 {
            return Err(Error::ErrLabelTooLarge);
        }

        let mut params = DataChannelParameters {
            label: label.to_owned(),
            ..Default::default()
        };

        // `None` means "the dictionary defaults", which is what `RTCDataChannelInit::default()`
        // spells out. Taking that route rather than leaving `params` on its derived default
        // keeps a single definition of those defaults — notably `ordered`, which is `true`.
        let options = options.unwrap_or_default();

        // https://www.w3.org/TR/webrtc/#peer-to-peer-data-api (Step #16)
        if options.max_packet_life_time.is_some() && options.max_retransmits.is_some() {
            return Err(Error::ErrRetransmitsOrPacketLifeTime);
        }

        // Ordered indicates if data is allowed to be delivered out of order. The
        // default value of true, guarantees that data will be delivered in order.
        // https://www.w3.org/TR/webrtc/#peer-to-peer-data-api (Step #9)
        params.ordered = options.ordered;

        // https://www.w3.org/TR/webrtc/#peer-to-peer-data-api (Step #7)
        params.max_packet_life_time = options.max_packet_life_time;

        // https://www.w3.org/TR/webrtc/#peer-to-peer-data-api (Step #8)
        params.max_retransmits = options.max_retransmits;

        // https://www.w3.org/TR/webrtc/#peer-to-peer-data-api (Step #10)
        params.protocol = options.protocol;

        // https://www.w3.org/TR/webrtc/#peer-to-peer-data-api (Step #11)
        if params.protocol.len() > 65535 {
            return Err(Error::ErrProtocolTooLarge);
        }

        // https://www.w3.org/TR/webrtc/#peer-to-peer-data-api (Step #12)
        //
        // `negotiated` doubles as the out-of-band stream id. When it is set the id is fixed by
        // the application and known now; when it is not, the channel is announced in-band and
        // its stream id has to wait for the DTLS role, per RFC 8832 §6. Nothing is guessed
        // here — see `assign_stream_ids`.
        params.negotiated = options.negotiated;
        if let Some(id) = options.negotiated {
            // An SCTP association has at most 65535 streams, numbered from 0 (W3C
            // createDataChannel: an id of 65535 throws a TypeError).
            if id == u16::MAX {
                return Err(Error::ErrMaxDataChannelID);
            }
            // RFC 8831 section 6.5: "If it attempts to reuse a stream that is part of an
            // existing data channel, the addition MUST fail"; W3C createDataChannel throws
            // an OperationError when the id "is being used by an existing RTCDataChannel",
            // whoever opened it. A second channel used to be accepted and took over the
            // first one's stream.
            if self.data_channels.stream_id_in_use(&id) {
                return Err(Error::ErrDataChannelIdInUse);
            }
            // W3C createDataChannel: "If [[DataChannelId]] is equal to or greater than the
            // transport's [[MaxChannels]] ... throw an OperationError": once the association
            // is connected and the stream count known.
            if self
                .sctp_transport()
                .max_channels()
                .is_some_and(|max_channels| id >= max_channels)
            {
                return Err(Error::ErrDataChannelIdAboveMaxChannels);
            }
        }

        // The registry assigns the handle. Note this happens before any dial: the channel is
        // addressable from the moment it exists, whether or not it has a stream id yet.
        // WebRTC Priority Control API 4.3: [[DataChannelPriority]] is the option's priority,
        // carried in the DCEP DATA_CHANNEL_OPEN when the channel is dialed.
        let mut internal = RTCDataChannelInternal::new(params);
        internal.priority = options.priority;
        let id = self.data_channels.insert(internal);

        // A data channel needs an association: after one was closed with `a=sctp-port:0`
        // (RFC 8841 section 10.5), the next offer asks for a new one.
        if self.sctp_transport().port_zero && self.sctp_transport().staged.is_none() {
            self.sctp_transport_mut().staged = Some(SctpRenegotiation::Replace);
        }

        // https://www.w3.org/TR/webrtc/#peer-to-peer-data-api (Step #23)
        // Open the channel's data transport immediately when an SCTP association already
        // exists. The DTLS role is necessarily resolved by then, so a stream id can be
        // assigned right here rather than waiting for a connected procedure that has passed.
        //
        // The role guard is not redundant with the association check. In practice an
        // association only exists once a description has been applied, which resolves the
        // role — but if it somehow is not resolved, there is no correct parity to pick, and
        // "wait for the connected procedure" is the right answer rather than an error. That is
        // the ordinary path for every channel created before negotiation.
        //
        // Without an association but with the DTLS role already negotiated (an answer has been
        // applied), the channel still gets its id now: W3C createDataChannel initializes
        // [[DataChannelId]] whenever "the DTLS role of the SCTP transport has already been
        // negotiated".
        let dtls_role = self.dtls_transport().role();
        if matches!(dtls_role, RTCDtlsRole::Client | RTCDtlsRole::Server) {
            let max_channels = self.sctp_transport().max_channels();
            self.data_channels
                .assign_stream_ids(dtls_role, max_channels)?;
        }
        // Only an association that is up. One still in its handshake (both sides initiate
        // when DTLS connects, so there is always such a moment) dials every waiting channel
        // when it comes up, on `SCTPHandshakeComplete`; one that has ended, which the
        // endpoint may still hold, carries nothing any more.
        if let Some(handle) = self
            .sctp_transport()
            .sctp_associations
            .iter()
            .find(|(_, association)| !association.is_ended() && !association.is_handshaking())
            .map(|(handle, _)| *handle)
            && matches!(dtls_role, RTCDtlsRole::Client | RTCDtlsRole::Server)
        {
            let data_channel = self
                .data_channels
                .get_mut(&id)
                .ok_or(Error::ErrDataChannelNotExisted)?;
            if data_channel.ready_state == RTCDataChannelState::Connecting
                && data_channel.data_channel.is_none()
            {
                data_channel.dial(handle.0)?;
                // An in-band channel waits for its DATA_CHANNEL_ACK under the same deadline
                // as one dialed when the association came up: a lost ACK must not leave it
                // connecting for ever.
                if !data_channel.negotiated {
                    data_channel.handshake_deadline = self
                        .setting_engine
                        .data_channel
                        .dcep_handshake_timeout
                        .map(|timeout| self.pipeline_context.now + timeout);
                }
            }
        }

        self.trigger_negotiation_needed();

        Ok(RTCDataChannel {
            id,
            peer_connection: self,
        })
    }

    /// Returns the senders of the connection: the sender of every transceiver that is not
    /// stopped, in the order the transceivers were added, whatever its direction and whether
    /// or not it has a track (W3C `CollectSenders`).
    ///
    /// # Specification
    ///
    /// See [getSenders](https://www.w3.org/TR/webrtc/#dom-peerconnection-getsenders)
    pub fn get_senders(&self) -> impl Iterator<Item = RTCRtpSenderId> + use<'_> {
        self.rtp_transceivers
            .iter()
            .enumerate()
            .filter(|(_, transceiver)| !transceiver.is_stopped())
            .map(|(id, _)| RTCRtpSenderId(id))
    }

    /// Returns the receivers of the connection: the receiver of every transceiver that is not
    /// stopped, in the order the transceivers were added, whatever its direction (W3C
    /// `CollectReceivers`).
    ///
    /// # Specification
    ///
    /// See [getReceivers](https://www.w3.org/TR/webrtc/#dom-peerconnection-getreceivers)
    pub fn get_receivers(&self) -> impl Iterator<Item = RTCRtpReceiverId> + use<'_> {
        self.rtp_transceivers
            .iter()
            .enumerate()
            .filter(|(_, transceiver)| !transceiver.is_stopped())
            .map(|(id, _)| RTCRtpReceiverId(id))
    }

    /// Returns an iterator over the `RTCRtpTransceiver` objects.
    ///
    /// The `RTCRtpTransceiver` objects represent the combination of an `RTCRtpSender`
    /// and an `RTCRtpReceiver` that share a common mid.
    ///
    /// # Specification
    ///
    /// See [getTransceivers](https://www.w3.org/TR/webrtc/#dom-peerconnection-gettranseceivers)
    pub fn get_transceivers(&self) -> impl Iterator<Item = RTCRtpTransceiverId> {
        0..self.rtp_transceivers.len()
    }

    /// Returns the transceivers removed from the set of transceivers since the last call, and
    /// forgets them.
    ///
    /// A transceiver id is its index in [`get_transceivers`](Self::get_transceivers), so a
    /// removal moves every later transceiver's id down by one. Transceivers are removed when a
    /// rollback undoes the remote offer that created them (RFC 9429 section 5.7), and when an
    /// answer (local or remote) leaves a stopped transceiver's m= section rejected (W3C
    /// webrtc-pc 4.4.1.6). Each id is the one the transceiver had
    /// when it was removed, in removal order: removing them in this order from a list that
    /// mirrors the transceivers keeps it in step.
    pub fn take_removed_transceivers(&mut self) -> Vec<RTCRtpTransceiverId> {
        std::mem::take(&mut self.removed_transceivers)
    }

    /// Adds a media track to the peer connection.
    ///
    /// The track goes to the first transceiver of its kind whose sender has no track, that is
    /// not stopping and whose sender has never been used to send (its negotiated direction
    /// never was sendrecv or sendonly); that transceiver's direction gains "send". Without
    /// one, a new sendrecv transceiver is created. The sender's associated stream is the
    /// track's own stream id.
    ///
    /// # Returns
    ///
    /// Returns the ID of the `RTCRtpSender` that will send this track.
    ///
    /// # Errors
    ///
    /// - [`Error::ErrConnectionClosed`] when the peer connection is closed (W3C
    ///   `InvalidStateError`)
    /// - [`Error::InvalidAccessError`] when a sender of the connection already sends a track
    ///   with this track's id
    ///
    /// # Specification
    ///
    /// See [addTrack](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-addtrack)
    pub fn add_track(&mut self, track: MediaStreamTrack) -> Result<RTCRtpSenderId> {
        if self.is_closed() {
            return Err(Error::ErrConnectionClosed);
        }
        if self.has_sender_for_track(&track) {
            return Err(Error::InvalidAccessError);
        }

        let reusable = self.rtp_transceivers.iter().position(|transceiver| {
            !transceiver.stopped()
                && transceiver.kind() == track.kind()
                && !transceiver.used_to_send()
                && transceiver
                    .sender()
                    .as_ref()
                    .is_some_and(|sender| !sender.has_track())
        });
        if let Some(id) = reusable {
            return self.attach_track_to_transceiver(id, track);
        }

        let send_encodings = self.send_encodings_from_track(&track);
        let (track, send_encodings, codec_preferences) =
            self.normalize_sender_track(track, send_encodings)?;
        let mut transceiver = self.new_transceiver_from_track(
            track,
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendrecv,
                streams: vec![],
                send_encodings,
            },
        )?;
        if !codec_preferences.is_empty() {
            transceiver.set_codec_preferences(codec_preferences, &self.media_engine)?;
        }
        Ok(RTCRtpSenderId(self.add_rtp_transceiver(transceiver)))
    }

    /// Gives the sender of the transceiver `id`, which has no track, `track` to send, as W3C
    /// `addTrack` does for the transceiver it picks: the direction gains "send", and a
    /// transceiver a remote offer created now survives a rollback of that offer (RFC 9429,
    /// Section 5.7). For a caller that chooses the transceiver itself.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer connection is closed, if a sender already sends this
    /// track, or if `id` is not a transceiver of the track's kind that is not stopping and
    /// whose sender has no track.
    ///
    /// # Specification
    ///
    /// See [addTrack](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-addtrack)
    pub fn add_track_to_transceiver(
        &mut self,
        id: RTCRtpTransceiverId,
        track: MediaStreamTrack,
    ) -> Result<RTCRtpSenderId> {
        if self.is_closed() {
            return Err(Error::ErrConnectionClosed);
        }
        if self.has_sender_for_track(&track) {
            return Err(Error::InvalidAccessError);
        }
        if id >= self.rtp_transceivers.len()
            || self.rtp_transceivers[id].stopped()
            || self.rtp_transceivers[id].kind() != track.kind()
            || self.rtp_transceivers[id]
                .sender()
                .as_ref()
                .is_none_or(|sender| sender.has_track())
        {
            return Err(Error::ErrRTPSenderNotExisted);
        }
        self.attach_track_to_transceiver(id, track)
    }

    /// Makes sure the sender of the transceiver `id` has encodings with SSRCs, which a sender
    /// created without a track for a transceiver that does not send (one a remote offer
    /// created, or `recvonly` / `inactive`) gets only when it needs them.
    ///
    /// Every transceiver has a sender; [`RTCRtpTransceiver::set_direction`] to a sending
    /// direction and [`RTCRtpSender::replace_track`] do this themselves, so calling it is
    /// only needed to read the SSRCs earlier. It changes neither the direction nor what a
    /// rollback does with the transceiver.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer connection is closed or `id` is not a transceiver.
    pub fn ensure_transceiver_sender(&mut self, id: RTCRtpTransceiverId) -> Result<()> {
        if self.is_closed() {
            return Err(Error::ErrConnectionClosed);
        }
        if id >= self.rtp_transceivers.len() {
            return Err(Error::ErrRTPSenderNotExisted);
        }
        if self.rtp_transceivers[id].stopped() {
            return Ok(());
        }
        self.ensure_send_encodings(id)
    }

    /// Removes the track of a sender (W3C `removeTrack`).
    ///
    /// The sender's track becomes null and it stops sending (an RTCP BYE goes out for each of
    /// its streams); the sender itself stays, with its parameters and streams, and still
    /// appears in [`get_senders`](Self::get_senders). The transceiver's direction loses
    /// "send" (sendrecv becomes recvonly, sendonly becomes inactive) and the
    /// negotiation-needed flag is updated. Nothing happens when the transceiver is stopping
    /// or the sender has no track.
    ///
    /// # Errors
    ///
    /// - [`Error::ErrConnectionClosed`] when the peer connection is closed (W3C
    ///   `InvalidStateError`)
    /// - [`Error::ErrRTPSenderNotExisted`] when the sender is not this connection's (W3C
    ///   `InvalidAccessError`)
    ///
    /// # Specification
    ///
    /// See [removeTrack](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-removetrack)
    pub fn remove_track(&mut self, sender_id: RTCRtpSenderId) -> Result<()> {
        if self.is_closed() {
            return Err(Error::ErrConnectionClosed);
        }
        let Some(transceiver) = self.rtp_transceivers.get_mut(sender_id.0) else {
            return Err(Error::ErrRTPSenderNotExisted);
        };
        if transceiver.stopped() {
            return Ok(());
        }
        let Some(sender) = transceiver.sender_mut().as_mut() else {
            return Ok(());
        };
        if !sender.has_track() {
            return Ok(());
        }
        sender.detach_track(&mut self.interceptor);

        let has_recv = transceiver.direction().has_recv();
        transceiver.set_direction(RTCRtpTransceiverDirection::from_send_recv(false, has_recv));

        self.trigger_negotiation_needed();
        Ok(())
    }

    /// Creates a new `RTCRtpTransceiver` whose sender sends `track`, and adds it to the set
    /// of transceivers.
    ///
    /// # Parameters
    ///
    /// * `track` - The media stream track the transceiver's sender gets.
    /// * `init` - Optional direction (any; sendrecv by default), streams and send encodings.
    ///
    /// # Returns
    ///
    /// Returns the ID of the created transceiver.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer connection is closed, or if the send encodings are not
    /// valid (see [`add_transceiver_from_kind`](Self::add_transceiver_from_kind)).
    ///
    /// # Specification
    ///
    /// See [addTransceiver](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-addtransceiver)
    pub fn add_transceiver_from_track(
        &mut self,
        track: MediaStreamTrack,
        init: Option<RTCRtpTransceiverInit>,
    ) -> Result<RTCRtpTransceiverId> {
        if self.is_closed() {
            return Err(Error::ErrConnectionClosed);
        }

        let mut init = init.unwrap_or(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendrecv,
            streams: vec![],
            send_encodings: vec![],
        });

        let send_encodings = if init.send_encodings.is_empty() {
            self.send_encodings_from_track(&track)
        } else {
            let mut send_encodings = std::mem::take(&mut init.send_encodings);
            validate_send_encodings(track.kind(), &mut send_encodings)?;
            let implemented: Vec<crate::rtp_transceiver::rtp_sender::RTCRtpCodec> = self
                .media_engine
                .get_codecs_by_kind(track.kind())
                .into_iter()
                .map(|codec| codec.rtp_codec)
                .collect();
            crate::rtp_transceiver::rtp_sender::internal::validate_scalability_modes(
                track.kind(),
                &mut send_encodings,
                &implemented,
                Error::ErrOperationError,
            )?;
            send_encodings
        };
        let (track, send_encodings, codec_preferences) =
            self.normalize_sender_track(track, send_encodings)?;
        init.send_encodings = send_encodings;

        let mut transceiver = self.new_transceiver_from_track(track, init)?;
        if !codec_preferences.is_empty() {
            transceiver.set_codec_preferences(codec_preferences, &self.media_engine)?;
        }

        Ok(self.add_rtp_transceiver(transceiver))
    }

    /// Creates a new transceiver for the given media kind and adds it to the set of
    /// transceivers. Its sender has no track ([`RTCRtpSender::track`] is `None`) until
    /// [`RTCRtpSender::replace_track`] or [`add_track`](Self::add_track) gives it one.
    ///
    /// # Parameters
    ///
    /// - `kind`: Audio or video.
    /// - `init`: Optional direction, streams and send encodings. Without it the direction is
    ///   sendrecv (W3C `RTCRtpTransceiverInit.direction`).
    ///
    /// # Errors
    ///
    /// - [`Error::ErrConnectionClosed`] when the peer connection is closed
    /// - [`Error::ErrPeerConnAddTransceiverFromKindSupport`] when the kind is `Unspecified`,
    ///   or the direction is `Unspecified` or `Stopped` (W3C `TypeError`; `Application` is
    ///   the fork's RTP-in-`m=application` extension and is accepted)
    /// - [`Error::TypeError`] for a rid that is not RFC 8851 section 10 syntax,
    ///   [`Error::ErrRTPSenderRidNil`] when some but not all encodings have a rid and
    ///   [`Error::ErrRTPSenderRIDCollision`] for a repeated rid (all W3C `TypeError`)
    /// - [`Error::RangeError`] for a `scale_resolution_down_by` below 1.0 or a negative
    ///   `max_framerate`
    /// - [`Error::ErrRTPTransceiverCodecUnsupported`] for an encoding whose codec the engine
    ///   cannot send (W3C `OperationError`)
    ///
    /// The send encodings are otherwise taken as W3C `addTransceiver` takes them: for audio
    /// `scale_resolution_down_by` and `max_framerate` are removed; at most
    /// [`MAX_SEND_ENCODINGS`] are kept; video encodings without `scale_resolution_down_by`
    /// get 1.0 when another has one and otherwise halve per layer from the last (4, 2, 1);
    /// a single encoding loses its rid. Without send encodings the sender has one, which the
    /// engine fills in.
    ///
    /// # Specification
    ///
    /// See [addTransceiver](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-addtransceiver)
    pub fn add_transceiver_from_kind(
        &mut self,
        kind: RtpCodecKind,
        init: Option<RTCRtpTransceiverInit>,
    ) -> Result<RTCRtpTransceiverId> {
        if self.is_closed() {
            return Err(Error::ErrConnectionClosed);
        }
        // W3C: a kind other than audio or video is a TypeError. The fork also carries RTP in
        // `m=application` sections (SMPTE ST 336 / KLV, `RtpCodecKind::Application`), an
        // engine extension the W3C API has no kind for; only `Unspecified` is refused.
        if kind == RtpCodecKind::Unspecified {
            return Err(Error::ErrPeerConnAddTransceiverFromKindSupport);
        }

        let mut init = init.unwrap_or(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendrecv,
            streams: vec![],
            send_encodings: vec![],
        });
        if matches!(
            init.direction,
            RTCRtpTransceiverDirection::Unspecified | RTCRtpTransceiverDirection::Stopped
        ) {
            return Err(Error::ErrPeerConnAddTransceiverFromKindSupport);
        }

        let explicit_encodings = !init.send_encodings.is_empty();
        if explicit_encodings {
            validate_send_encodings(kind, &mut init.send_encodings)?;
            let implemented: Vec<crate::rtp_transceiver::rtp_sender::RTCRtpCodec> = self
                .media_engine
                .get_codecs_by_kind(kind)
                .into_iter()
                .map(|codec| codec.rtp_codec)
                .collect();
            crate::rtp_transceiver::rtp_sender::internal::validate_scalability_modes(
                kind,
                &mut init.send_encodings,
                &implemented,
                Error::ErrOperationError,
            )?;
        }
        let mut codec_preferences = vec![];
        // A sender that may send has its encodings (SSRCs) from the start, so that the first
        // offer describes them; one that does not gets them when it first needs them.
        if init.direction.has_send() || explicit_encodings {
            let (encodings, preferences) =
                self.new_send_encodings(kind, std::mem::take(&mut init.send_encodings))?;
            init.send_encodings = encodings;
            codec_preferences = preferences;
        }

        let mut transceiver = RTCRtpTransceiverInternal::new(kind, None, init);
        if !codec_preferences.is_empty() {
            transceiver.set_codec_preferences(codec_preferences, &self.media_engine)?;
        }

        Ok(self.add_rtp_transceiver(transceiver))
    }

    /// Returns a handle to the [`RTCDataChannel`] with the given id, or `None` if no such
    /// channel exists on this peer connection.
    ///
    /// [`RTCDataChannel`]: crate::data_channel::RTCDataChannel
    pub fn data_channel(&mut self, id: RTCDataChannelId) -> Option<RTCDataChannel<'_>> {
        if self.data_channels.contains(&id) {
            Some(RTCDataChannel {
                id,
                peer_connection: self,
            })
        } else {
            None
        }
    }

    /// The SCTP transport over which data channels are carried.
    ///
    /// `None` until SCTP has been negotiated — that is, until a description establishing an
    /// SCTP association has been applied by both sides. A connection carrying only media never
    /// has one.
    ///
    /// This is the **only** transport accessor on `RTCPeerConnection`, matching the W3C
    /// interface, which exposes `sctp` and nothing else. The DTLS and ICE transports are
    /// reached by walking from here (or from a sender or receiver):
    ///
    /// ```text
    /// pc.sctp()?.transport().ice_transport()
    /// ```
    ///
    /// ## Specifications
    ///
    /// * [W3C](https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-sctp)
    pub fn sctp(&self) -> Option<RTCSctpTransport<'_>> {
        if self.sctp_transport().is_started {
            Some(RTCSctpTransport {
                peer_connection: self,
            })
        } else {
            None
        }
    }

    /// Asks for the SCTP association to be replaced by a new one.
    ///
    /// The next offer carries a new `a=sctp-port` (RFC 8841 section 10.5: "If the offerer
    /// wants to close an SCTP association and immediately establish a new SCTP association,
    /// it MUST associate an SDP 'sctp-port' attribute with a new ... attribute value"). When
    /// that exchange completes, the association is closed, its data channels with it, and a
    /// new one is established over the same DTLS transport; data channels created from then
    /// on, and those created earlier that had no association to open on yet, open on the
    /// new one. It also brings back an association closed with
    /// [`Self::close_sctp_association`]. Nothing changes until an offer is made and answered.
    pub fn replace_sctp_association(&mut self) {
        self.sctp_transport_mut().staged = Some(SctpRenegotiation::Replace);
        self.trigger_negotiation_needed();
    }

    /// Asks for the SCTP association to be closed without a new one.
    ///
    /// The next offer, or the answer to the peer's next offer, carries `a=sctp-port:0`
    /// (RFC 8841 sections 10.3 and 10.5). When that exchange completes the association is
    /// closed and every data channel with it; the DTLS transport and the media it carries are
    /// not affected. Offers keep saying 0 until a data channel is created or
    /// [`Self::replace_sctp_association`] is called.
    pub fn close_sctp_association(&mut self) {
        self.sctp_transport_mut().staged = Some(SctpRenegotiation::Close);
        self.trigger_negotiation_needed();
    }

    /// Asks for the data section to be rejected, which closes the SCTP association and the
    /// DTLS association under it.
    ///
    /// RFC 8841 section 10.5: "If the offerer wants to close an existing SCTP association and
    /// the underlying DTLS association ..., it MUST assign a zero port value to the 'm=' line
    /// associated with the SCTP and DTLS associations". The next offer carries the data
    /// section with port zero; so does the answer to the peer's next offer, should that come
    /// first (section 10.3: an answerer that does not accept the "m=" line). When the
    /// exchange completes the association is closed and every data channel with it. The DTLS
    /// association is closed too when the data section was the only one that used it: the
    /// next description that sets a section up establishes a new DTLS association, with a
    /// new `a=tls-id`. With BUNDLE and media sections the transport is theirs as well, and
    /// stays; to close the SCTP association alone, whatever the session carries, use
    /// [`Self::close_sctp_association`].
    ///
    /// A data channel created afterwards brings a new data section with the next offer, and
    /// a new association on a new `a=sctp-port`.
    pub fn reject_data_section(&mut self) {
        self.sctp_transport_mut().staged = Some(SctpRenegotiation::Reject);
        self.trigger_negotiation_needed();
    }

    /// Brings the SCTP transport in line with what a completed offer/answer exchange
    /// negotiated for the data section (RFC 8841 sections 10.3 and 10.4).
    ///
    /// The first association is started (and initiated once DTLS is connected). A rejected
    /// data section or an `a=sctp-port` of zero establishes none and closes the one that
    /// exists; a new `a=sctp-port` on either side closes it and establishes a new one. The
    /// data channels of a closed association are closed with it.
    fn apply_sctp_negotiation(&mut self, now: Instant, negotiated: SctpNegotiation) -> Result<()> {
        let refused = matches!(
            negotiated,
            SctpNegotiation::Rejected | SctpNegotiation::PortZero
        );
        if self.sctp_transport().closes_on(negotiated) {
            self.get_sctp_handler()
                .close_for_renegotiation(now, !refused);
        } else if refused && !self.data_channels.is_empty() {
            // Nothing runs, and nothing will: the channels waiting for an association fail.
            self.get_sctp_handler().close_for_renegotiation(now, false);
        }
        match self.sctp_transport_mut().negotiate(negotiated)? {
            SctpNegotiationOutcome::Started | SctpNegotiationOutcome::Replaced => {
                // Nothing happens here before DTLS is connected: the handler initiates then.
                self.get_sctp_handler().connect(now)?;
            }
            SctpNegotiationOutcome::Closed | SctpNegotiationOutcome::Unchanged => {}
        }
        Ok(())
    }

    /// Returns a handle to the [`RTCRtpSender`] with the given id, or `None` if no such
    /// sender exists on this peer connection. Every transceiver has a sender, whether or not
    /// it has a track and whatever its direction.
    ///
    /// [`RTCRtpSender`]: crate::rtp_transceiver::rtp_sender::RTCRtpSender
    pub fn rtp_sender(&mut self, id: RTCRtpSenderId) -> Option<RTCRtpSender<'_>> {
        if id.0 < self.rtp_transceivers.len() {
            Some(RTCRtpSender {
                id,
                peer_connection: self,
            })
        } else {
            None
        }
    }

    /// Returns a handle to the [`RTCRtpReceiver`] with the given id, or `None` if no such
    /// receiver exists on this peer connection. Every transceiver has a receiver, whatever
    /// its direction.
    ///
    /// [`RTCRtpReceiver`]: crate::rtp_transceiver::rtp_receiver::RTCRtpReceiver
    pub fn rtp_receiver(&mut self, id: RTCRtpReceiverId) -> Option<RTCRtpReceiver<'_>> {
        if id.0 < self.rtp_transceivers.len() {
            Some(RTCRtpReceiver {
                id,
                peer_connection: self,
            })
        } else {
            None
        }
    }

    /// Returns a handle to the [`RTCRtpTransceiver`] with the given id, or `None` if no such
    /// transceiver exists on this peer connection.
    ///
    /// [`RTCRtpTransceiver`]: crate::rtp_transceiver::RTCRtpTransceiver
    pub fn rtp_transceiver(&mut self, id: RTCRtpTransceiverId) -> Option<RTCRtpTransceiver<'_>> {
        if id < self.rtp_transceivers.len() {
            Some(RTCRtpTransceiver {
                id,
                peer_connection: self,
            })
        } else {
            None
        }
    }

    /// Returns a snapshot of accumulated statistics.
    ///
    /// This method creates an immutable snapshot of WebRTC statistics
    /// at the given timestamp. When `selector` is `StatsSelector::None`,
    /// the returned `RTCStatsReport` contains statistics for all aspects
    /// of the peer connection. When a sender or receiver is specified,
    /// only statistics relevant to that sender/receiver are included.
    ///
    /// # Statistics included by selector
    ///
    /// - `StatsSelector::None` - All statistics for the entire connection
    /// - `StatsSelector::Sender(id)` - Outbound RTP streams for the sender
    ///   and all referenced stats (transport, codec, remote inbound, etc.)
    /// - `StatsSelector::Receiver(id)` - Inbound RTP streams for the receiver
    ///   and all referenced stats (transport, codec, remote outbound, etc.)
    ///
    /// # Parameters
    ///
    /// * `now` - The timestamp to use for all stats in the report. This is
    ///   passed explicitly to support deterministic testing.
    /// * `selector` - Controls which statistics are included in the report.
    ///
    /// # Returns
    ///
    /// An `RTCStatsReport` containing snapshots of the selected statistics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::Instant;
    /// use rtc::peer_connection::RTCPeerConnectionBuilder;
    /// use rtc::statistics::StatsSelector;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    ///
    /// // Get all stats
    /// let report = pc.get_stats(Instant::now(), StatsSelector::None);
    ///
    /// // Access peer connection stats
    /// if let Some(pc_stats) = report.peer_connection() {
    ///     println!("Data channels opened: {}", pc_stats.data_channels_opened);
    /// }
    ///
    /// // Iterate over inbound RTP streams
    /// for stream in report.inbound_rtp_streams() {
    ///     println!("SSRC {}: {} packets received", stream.received_rtp_stream_stats.rtp_stream_stats.ssrc, stream.received_rtp_stream_stats.packets_received);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [getStats](https://www.w3.org/TR/webrtc/#widl-RTCPeerConnection-getStats-Promise-RTCStatsReport--MediaStreamTrack-selector) and
    /// [The stats selection algorithm](https://www.w3.org/TR/webrtc/#the-stats-selection-algorithm)
    pub fn get_stats(&mut self, now: Instant, selector: StatsSelector) -> RTCStatsReport {
        // Update ICE agent stats before taking snapshot
        self.update_ice_agent_stats(now);
        // The transport and data channel states, from the objects themselves
        self.update_transport_stats();
        self.update_data_channel_stats();
        // RTP streams whose SSRC is no longer bound go, before the codecs they referenced
        self.retire_rtp_stream_stats();
        // Update codec stats from transceivers before taking snapshot
        self.update_codec_stats();
        // The media source of each track a sender has attached
        self.update_media_source_stats();
        self.pipeline_context
            .stats
            .snapshot_with_selector(now, selector)
    }

    /// [`get_stats`](Self::get_stats), refusing a selector that is not this connection's.
    ///
    /// W3C `getStats(selector)` rejects with `InvalidAccessError` when the selector matches no
    /// sender or receiver of the connection; `get_stats` answers such a selector with an empty
    /// report, which cannot be told from a sender that has no stream yet.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidAccessError`] when `selector` names a sender or receiver this peer
    /// connection does not have.
    pub fn try_get_stats(
        &mut self,
        now: Instant,
        selector: StatsSelector,
    ) -> Result<RTCStatsReport> {
        if !self.stats_selector_is_ours(&selector) {
            return Err(Error::InvalidAccessError);
        }
        Ok(self.get_stats(now, selector))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_channel::state::RTCDataChannelState;
    use crate::peer_connection::configuration::setting_engine::SctpMaxMessageSize;
    use crate::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    use crate::peer_connection::transport::RTCIceComponent;
    use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
    use sctp::AssociationHandle;

    #[test]
    fn with_sctp_receive_buffer_size_sets_and_clamps() {
        let setting_engine = SettingEngineBuilder::new()
            .with_sctp_max_receive_buffer_size(200_000)
            .build();

        let builder = RTCPeerConnectionBuilder::new().with_setting_engine(setting_engine);
        assert_eq!(
            builder.setting_engine.sctp_max_receive_buffer_size,
            Some(200_000)
        );

        // Values below the RFC 9260 §3.3.2 floor (1500 bytes), including 0, are clamped up so
        // they cannot break the SCTP handshake.
        for input in [0u32, 500, 1499] {
            let setting_engine = SettingEngineBuilder::new()
                .with_sctp_max_receive_buffer_size(input)
                .build();
            let builder = RTCPeerConnectionBuilder::new().with_setting_engine(setting_engine);
            assert_eq!(
                builder.setting_engine.sctp_max_receive_buffer_size,
                Some(1500),
                "input {input} should clamp up to the 1500-byte floor"
            );
        }
    }

    // The graph the spec exposes: `pc.sctp` is the only way in, and the rest is walked.
    #[test]
    fn sctp_is_none_until_sctp_is_negotiated() {
        let pc = RTCPeerConnectionBuilder::new()
            .build(Instant::now())
            .unwrap();
        assert!(
            pc.sctp().is_none(),
            "nothing has been negotiated, so there is no SCTP transport to expose"
        );
    }

    /// W3C 4.9: the certificates a connection generates when none is configured include an
    /// ECDSA P-256 one signed with SHA-256; its fingerprint values are lowercase hex in the
    /// RFC 4572 syntax (W3C 5.5.1 `RTCDtlsFingerprint.value`).
    #[test]
    fn the_generated_certificate_is_ecdsa_p256_with_sha256() {
        use x509_parser::prelude::FromDer;
        let pc = RTCPeerConnectionBuilder::new()
            .build(Instant::now())
            .unwrap();
        let certificates = &pc.dtls_transport().certificates;
        assert_eq!(certificates.len(), 1);
        let der = certificates[0]
            .dtls_certificate
            .certificate
            .first()
            .expect("a certificate")
            .clone();
        let (_, parsed) =
            x509_parser::certificate::X509Certificate::from_der(der.as_ref()).expect("X.509");
        assert_eq!(
            parsed.signature_algorithm.algorithm,
            x509_parser::oid_registry::OID_SIG_ECDSA_WITH_SHA256
        );
        let key = parsed.public_key();
        assert_eq!(
            key.algorithm.algorithm,
            x509_parser::oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY
        );
        let curve = key
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .expect("a named curve");
        assert_eq!(curve, x509_parser::oid_registry::OID_EC_P256);

        let crypto = crypto::default_provider().unwrap();
        let fingerprints = certificates[0].get_fingerprints(crypto.crypto()).unwrap();
        assert_eq!(fingerprints[0].algorithm, "sha-256");
        let value = &fingerprints[0].value;
        assert_eq!(value.len(), 32 * 3 - 1, "{value}");
        assert!(
            value.split(':').all(|byte| byte.len() == 2
                && byte
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))),
            "lowercase hex pairs separated by colons: {value}"
        );
    }

    #[test]
    fn the_transport_graph_is_walkable_and_ids_identify() {
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(Instant::now())
            .unwrap();
        // `start()` is what negotiation calls once both descriptions carry an m=application
        // section; it is the predicate `sctp()` keys off.
        pc.sctp_transport_mut()
            .start(
                crate::peer_connection::transport::sctp::capabilities::SCTPTransportCapabilities {
                    max_message_size: 0,
                },
                5000,
                5000,
            )
            .expect("start");

        let sctp = pc.sctp().expect("SCTP is negotiated");
        let dtls = sctp.transport();
        let ice = dtls.ice_transport();

        // Three transports, three identities.
        assert_ne!(sctp.id(), dtls.id());
        assert_ne!(dtls.id(), ice.id());
        assert_ne!(sctp.id(), ice.id());

        // Ids are stored, not minted per call: walking twice yields the same identity.
        let dtls_again = pc.sctp().unwrap().transport();
        assert_eq!(dtls.id(), dtls_again.id());
        assert_eq!(ice.id(), dtls_again.ice_transport().id());

        // The default configuration caps messages at 64 KiB and the peer advertised no limit,
        // so the negotiated value is this endpoint's cap.
        assert_eq!(Some(65536), sctp.max_message_size());
        // No association yet, so no negotiated stream count.
        assert_eq!(None, sctp.max_channels());
        assert_eq!(RTCIceComponent::Rtp, ice.component());
    }

    // W3C types `maxMessageSize` `unrestricted double` so that an implementation with no limit
    // can report +Infinity. This one always has a limit — the working buffer is a real
    // allocation — so a configuration naming no limit resolves to the implementation ceiling,
    // and the value reported is the value enforced.
    #[test]
    fn max_message_size_with_no_configured_limit_reports_the_ceiling() {
        let setting_engine = SettingEngineBuilder::new()
            .with_sctp_max_message_size(SctpMaxMessageSize::Bounded(0))
            .build();
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_setting_engine(setting_engine)
            .build(Instant::now())
            .unwrap();
        pc.sctp_transport_mut()
            .start(
                crate::peer_connection::transport::sctp::capabilities::SCTPTransportCapabilities {
                    max_message_size: 0,
                },
                5000,
                5000,
            )
            .expect("start");

        assert_eq!(
            Some(SctpMaxMessageSize::MAX_MESSAGE_SIZE),
            pc.sctp().expect("negotiated").max_message_size()
        );
    }

    // `RTCRtpSender.transport` / `RTCRtpReceiver.transport` come from the per-object
    // `[[SenderTransport]]` / `[[ReceiverTransport]]` slots, filled when the transceiver is
    // associated by negotiation. Before that the spec reports null.
    #[test]
    fn sender_and_receiver_transport_are_none_until_the_transceiver_is_associated() {
        let mut pc = media_pc();
        // `add_track` creates a sendrecv transceiver, so this one has both a sender and a
        // receiver while still being unassociated.
        let track = MediaStreamTrack::new(
            "stream".to_owned(),
            "track".to_owned(),
            "label".to_owned(),
            RtpCodecKind::Audio,
            vec![],
        );
        let sender_id = pc.add_track(track).expect("add track");
        let receiver_id = RTCRtpReceiverId::from(sender_id.0);

        assert!(pc.rtp_transceivers[sender_id.0].mid().is_none());
        assert!(
            pc.rtp_sender(sender_id)
                .expect("sender")
                .transport()
                .is_none(),
            "an unassociated sender has a null transport"
        );
        assert!(
            pc.rtp_receiver(receiver_id)
                .expect("receiver")
                .transport()
                .is_none(),
            "an unassociated receiver has a null transport"
        );

        // Applying a local offer associates the transceiver. This is the offerer's window: a mid
        // exists, but no answer has arrived so DTLS has not started — and a browser reports a
        // transport here, which is why the predicate is association rather than "DTLS is up".
        let offer = pc.create_offer(None).expect("create offer");
        pc.set_local_description(Instant::now(), offer)
            .expect("set local description");
        assert!(pc.rtp_transceivers[sender_id.0].mid().is_some());
        assert!(
            !pc.dtls_transport().is_started(),
            "no answer yet, so DTLS has not been brought up"
        );

        let sender_transport_id = pc
            .rtp_sender(sender_id)
            .expect("sender")
            .transport()
            .expect("an associated sender has a transport")
            .id();
        let receiver_transport_id = pc
            .rtp_receiver(receiver_id)
            .expect("receiver")
            .transport()
            .expect("an associated receiver has a transport")
            .id();

        // Under bundling both directions share one DTLS transport, as the spec says...
        assert_eq!(sender_transport_id, receiver_transport_id);
        // ...and it is the same transport the rest of the graph names.
        assert_eq!(sender_transport_id, pc.dtls_transport().id);
        // Its state is `New` until the handshake begins: a transport that exists but has not
        // connected, exactly as a browser reports in this window.
        assert_eq!(RTCDtlsTransportState::New, pc.dtls_transport().state());
    }

    // `with_discard_local_candidates_during_ice_restart` has to reach `apply_restart`, not just
    // land in the struct. Applying a restart with it set must empty the local candidates the
    // agent had gathered; with it unset they survive.
    //
    // This is the setting that makes a socket-rebinding ICE restart work (webrtc#868): retained
    // candidates name addresses nothing is bound to any more, so checks written for them go
    // nowhere and the restarted generation never leaves `Checking`.
    #[test]
    fn discard_local_candidates_during_ice_restart_reaches_apply_restart() {
        fn restart_with(discard: bool) -> usize {
            let setting_engine = SettingEngineBuilder::new()
                .with_discard_local_candidates_during_ice_restart(discard)
                .build();
            let mut pc = RTCPeerConnectionBuilder::new()
                .with_setting_engine(setting_engine)
                .build(Instant::now())
                .unwrap();

            // Gather one host candidate so there is something to keep or drop.
            pc.add_local_candidate(RTCIceCandidateInit {
                candidate: "candidate:1 1 udp 2130706431 127.0.0.1 5000 typ host".to_owned(),
                ..Default::default()
            })
            .expect("add local candidate");
            assert_eq!(
                1,
                pc.ice_transport().get_local_candidates().unwrap().len(),
                "precondition: the agent holds the gathered candidate"
            );

            pc.ice_transport_mut()
                .generate_restart_credentials(
                    "newufrag".to_owned(),
                    "newpasswordlongenough".to_owned(),
                )
                .expect("stage restart");
            pc.apply_ice_restart(Instant::now())
                .expect("apply ice restart");

            pc.ice_transport().get_local_candidates().unwrap().len()
        }

        assert_eq!(
            0,
            restart_with(true),
            "with discard enabled the stale generation's candidates are dropped"
        );
        assert_eq!(
            1,
            restart_with(false),
            "the default keeps them, which is the pre-existing behaviour"
        );
    }

    // Two connections must never report the same transport as each other's. This is the case a
    // per-connection counter or a small-integer scheme gets wrong.
    #[test]
    fn transports_of_two_peer_connections_are_never_equal() {
        let mut ids = vec![];
        for _ in 0..2 {
            let mut pc = RTCPeerConnectionBuilder::new()
                .build(Instant::now())
                .unwrap();
            pc.sctp_transport_mut()
                .start(
                    crate::peer_connection::transport::sctp::capabilities::SCTPTransportCapabilities {
                        max_message_size: 0,
                    },
                    5000,
                    5000,
                )
                .expect("start");
            let sctp = pc.sctp().expect("SCTP is negotiated");
            ids.push((
                sctp.id(),
                sctp.transport().id(),
                sctp.transport().ice_transport().id(),
            ));
        }

        let (a_sctp, a_dtls, a_ice) = ids[0];
        let (b_sctp, b_dtls, b_ice) = ids[1];
        assert_ne!(a_sctp, b_sctp);
        assert_ne!(a_dtls, b_dtls);
        assert_ne!(a_ice, b_ice);
    }

    /// An association still in its handshake is not dialed on: the channel gets its stream id
    /// (the DTLS role is known) and waits for `SCTPHandshakeComplete`, which dials every
    /// waiting channel. A channel created on an established association is dialed at once
    /// (`data_sent_before_the_ack_arrives_on_an_unordered_channel`).
    #[test]
    fn create_data_channel_waits_for_an_association_still_in_its_handshake() {
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(Instant::now())
            .unwrap();

        // The resolved DTLS role that always accompanies an association in practice, and an
        // association as `connect` leaves it: its INIT sent, nothing answered yet.
        pc.dtls_transport_mut().dtls_role = RTCDtlsRole::Client;
        pc.sctp_transport_mut()
            .sctp_associations
            .insert(AssociationHandle(0), sctp::Association::default());

        let _dc = pc.create_data_channel("test", None).unwrap();

        let internal = pc
            .data_channels
            .values()
            .next()
            .expect("data channel must be stored internally");
        assert!(internal.data_channel.is_none());
        assert_eq!(internal.ready_state, RTCDataChannelState::Connecting);
        assert_eq!(
            internal.stream_id,
            Some(0),
            "the DTLS client must take an even stream id (RFC 8832 §6)"
        );
    }

    /// The mirror of the case above: with no resolved DTLS role there is no correct parity, so
    /// the channel is created without a stream id and waits for the connected procedure rather
    /// than being dialed or rejected.
    #[test]
    fn create_data_channel_defers_stream_id_when_dtls_role_unresolved() {
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(Instant::now())
            .unwrap();
        pc.sctp_transport_mut()
            .sctp_associations
            .insert(AssociationHandle(0), sctp::Association::default());

        let dc = pc.create_data_channel("test", None).unwrap();
        let id = dc.id();

        let internal = pc.data_channels.get(&id).unwrap();
        assert_eq!(internal.stream_id, None, "no parity is knowable yet");
        assert!(
            internal.data_channel.is_none(),
            "a channel with no stream id cannot be dialed"
        );
    }

    /// W3C "set the RTCSessionDescription": the answer negotiates the DTLS role, and every
    /// in-band channel gets its id then (here, the DTLS client's even ids), before any SCTP
    /// association exists; a channel created after that gets one at once.
    #[test]
    fn answer_assigns_data_channel_ids_by_dtls_role() {
        let now = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new().build(now).unwrap();
        let first = pc.create_data_channel("first", None).unwrap().id();
        assert_eq!(pc.data_channels.get(&first).unwrap().stream_id, None);

        let offer = pc.create_offer(None).unwrap();
        pc.set_local_description(now, offer.clone()).unwrap();
        assert_eq!(
            pc.data_channels.get(&first).unwrap().stream_id,
            None,
            "an offer alone negotiates no DTLS role"
        );
        // The remote side answers `passive`: this side is the DTLS client.
        let answer =
            RTCSessionDescription::answer(offer.sdp.replace("actpass", "passive")).unwrap();
        pc.set_remote_description(now, answer).unwrap();
        assert!(pc.sctp_transport().sctp_associations.is_empty());

        let first_id = pc.data_channels.get(&first).unwrap().stream_id;
        assert_eq!(first_id, Some(0));
        let second = pc.create_data_channel("second", None).unwrap().id();
        assert_eq!(pc.data_channels.get(&second).unwrap().stream_id, Some(2));
    }

    /// An offer that restarts ICE carries the new credentials and none of the candidates
    /// gathered under the old ones; they come back as the new gathering phase finds them.
    #[test]
    fn ice_restart_offer_carries_no_previous_candidates() {
        let now = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new().build(now).unwrap();
        pc.create_data_channel("x", None).unwrap();
        let offer = pc.create_offer(None).unwrap();
        pc.set_local_description(now, offer).unwrap();
        pc.add_local_candidate(RTCIceCandidateInit {
            candidate: "candidate:1 1 udp 2130706431 127.0.0.1 5000 typ host".to_owned(),
            ..Default::default()
        })
        .unwrap();
        let again = pc.create_offer(None).unwrap();
        assert!(again.sdp.contains("a=candidate:"), "{}", again.sdp);

        pc.restart_ice();
        let restart = pc.create_offer(None).unwrap();
        assert!(!restart.sdp.contains("a=candidate:"), "{}", restart.sdp);
    }

    // ---- Rollback (RFC 9429, Section 5.7) ----

    use crate::peer_connection::configuration::media_engine::MediaEngine;
    use crate::rtp_transceiver::RTCRtpTransceiverInit;

    fn media_pc() -> RTCPeerConnection {
        let mut me = MediaEngine::default();
        me.register_default_codecs().unwrap();
        RTCPeerConnectionBuilder::new()
            .with_media_engine(me)
            .build(Instant::now())
            .unwrap()
    }

    /// Builds an audio+video offer from a freshly-created peer connection.
    fn audio_video_offer() -> RTCSessionDescription {
        let mut offerer = media_pc();
        offerer
            .add_transceiver_from_kind(
                RtpCodecKind::Audio,
                Some(RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Recvonly,
                    streams: vec![],
                    send_encodings: vec![],
                }),
            )
            .unwrap();
        offerer
            .add_transceiver_from_kind(
                RtpCodecKind::Video,
                Some(RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Recvonly,
                    streams: vec![],
                    send_encodings: vec![],
                }),
            )
            .unwrap();
        offerer.create_offer(None).unwrap()
    }

    fn rollback() -> RTCSessionDescription {
        RTCSessionDescription {
            sdp_type: RTCSdpType::Rollback,
            sdp: String::new(),
            parsed: None,
        }
    }

    #[test]
    fn set_remote_rollback_removes_transceivers_created_by_remote_offer() {
        let offer = audio_video_offer();

        let mut pc = media_pc();
        pc.set_remote_description(Instant::now(), offer).unwrap();

        // Applying the remote offer implicitly creates two transceivers, each associated
        // with an "m=" section.
        assert_eq!(pc.rtp_transceivers.len(), 2);
        assert_eq!(pc.signaling_state, RTCSignalingState::HaveRemoteOffer);
        assert!(pc.rtp_transceivers.iter().all(|t| t.mid().is_some()));

        // Rolling back the offer must stop and remove those transceivers and return to stable.
        pc.set_remote_description(Instant::now(), rollback())
            .unwrap();

        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);
        assert!(
            pc.rtp_transceivers.is_empty(),
            "transceivers created by a rolled-back remote offer must be removed"
        );
    }

    #[test]
    fn set_local_rollback_disassociates_but_keeps_app_created_transceivers() {
        // A locally-initiated offer: the transceivers are created by the application, so
        // rolling back the local offer via set_local_description must disassociate them
        // (clear their mids) but must NOT remove them. This exercises the same rollback
        // cleanup path as set_remote_description, per RFC 9429 Section 5.7.
        let mut pc = media_pc();
        pc.add_transceiver_from_kind(
            RtpCodecKind::Audio,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                streams: vec![],
                send_encodings: vec![],
            }),
        )
        .unwrap();

        let offer = pc.create_offer(None).unwrap();
        pc.set_local_description(Instant::now(), offer).unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::HaveLocalOffer);
        assert_eq!(pc.rtp_transceivers.len(), 1);
        assert!(pc.rtp_transceivers[0].mid().is_some());

        pc.set_local_description(Instant::now(), rollback())
            .unwrap();

        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);
        assert_eq!(
            pc.rtp_transceivers.len(),
            1,
            "application-created transceivers must not be removed by rollback"
        );
        assert!(
            pc.rtp_transceivers[0].mid().is_none(),
            "rolled-back transceiver must be disassociated from its m= section"
        );
    }

    #[test]
    fn rollback_keeps_transceiver_with_track_attached_via_add_track() {
        let offer = audio_video_offer();

        let mut pc = media_pc();
        pc.set_remote_description(Instant::now(), offer).unwrap();
        assert_eq!(pc.rtp_transceivers.len(), 2);

        // Attach a local track. add_track reuses the sender-less audio transceiver that was
        // created by the remote offer, giving it a sender.
        let track = MediaStreamTrack::new(
            "stream".to_owned(),
            "track".to_owned(),
            "label".to_owned(),
            RtpCodecKind::Audio,
            vec![],
        );
        pc.add_track(track).unwrap();

        pc.set_remote_description(Instant::now(), rollback())
            .unwrap();

        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);
        // The video transceiver (no track) is removed; the audio transceiver with the attached
        // track is kept but disassociated (mid cleared) so a future offer can re-add it.
        assert_eq!(
            pc.rtp_transceivers.len(),
            1,
            "transceiver with a track attached via add_track must not be removed"
        );
        let kept = &pc.rtp_transceivers[0];
        assert_eq!(kept.kind(), RtpCodecKind::Audio);
        assert!(kept.sender().is_some());
        assert!(
            kept.mid().is_none(),
            "kept transceiver must be disassociated from its m= section on rollback"
        );
    }

    #[test]
    fn rollback_keeps_transceiver_negotiated_by_a_previous_exchange() {
        // First, complete a full offer/answer so an incoming transceiver becomes part of the
        // stable state (its mid is recorded in the current remote description).
        let offer = audio_video_offer();
        let mut pc = media_pc();
        pc.set_remote_description(Instant::now(), offer).unwrap();
        assert_eq!(pc.rtp_transceivers.len(), 2);
        let answer = pc.create_answer(None).unwrap();
        pc.set_local_description(Instant::now(), answer).unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);
        let negotiated_mids: Vec<_> = pc
            .rtp_transceivers
            .iter()
            .map(|t| t.mid().clone())
            .collect();
        assert!(negotiated_mids.iter().all(|m| m.is_some()));

        // Now a renegotiation arrives and is rolled back. The transceivers negotiated by the
        // FIRST exchange must survive with their mids intact — rollback only undoes the pending
        // (second) transaction, not committed state.
        let reoffer = audio_video_offer();
        pc.set_remote_description(Instant::now(), reoffer).unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::HaveRemoteOffer);

        pc.set_remote_description(Instant::now(), rollback())
            .unwrap();

        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);
        assert_eq!(
            pc.rtp_transceivers.len(),
            2,
            "previously-negotiated transceivers must not be removed by a renegotiation rollback"
        );
        let mids_after: Vec<_> = pc
            .rtp_transceivers
            .iter()
            .map(|t| t.mid().clone())
            .collect();
        assert_eq!(
            mids_after, negotiated_mids,
            "previously-negotiated transceivers must keep their mid across rollback"
        );
    }

    #[test]
    fn add_track_then_rollback_remote_offer_then_create_offer_includes_track() {
        // RFC 9429, Section 5.7: "an application may call addTrack, then call
        // setRemoteDescription with an offer, then roll back that offer, then call createOffer
        // and have an "m=" section for the added track appear in the generated offer."
        let mut pc = media_pc();

        // 1. addTrack — creates a local sendrecv audio transceiver with a sender.
        let track = MediaStreamTrack::new(
            "stream".to_owned(),
            "track".to_owned(),
            "label".to_owned(),
            RtpCodecKind::Audio,
            vec![],
        );
        pc.add_track(track).unwrap();
        assert_eq!(pc.rtp_transceivers.len(), 1);

        // 2. setRemoteDescription with a remote (video-only) offer. This reuses no existing
        //    transceiver (different kind), so it creates a second, remote-originated one.
        let mut video_offerer = media_pc();
        video_offerer
            .add_transceiver_from_kind(
                RtpCodecKind::Video,
                Some(RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Recvonly,
                    streams: vec![],
                    send_encodings: vec![],
                }),
            )
            .unwrap();
        let remote_offer = video_offerer.create_offer(None).unwrap();
        pc.set_remote_description(Instant::now(), remote_offer)
            .unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::HaveRemoteOffer);
        // The audio transceiver (with our track) got associated with the offer's m= section.
        assert!(
            pc.rtp_transceivers
                .iter()
                .any(|t| t.kind() == RtpCodecKind::Audio && t.sender().is_some())
        );

        // 3. Roll back that offer.
        pc.set_remote_description(Instant::now(), rollback())
            .unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);

        // The audio transceiver with the attached track must survive (disassociated), while the
        // remote-created video transceiver must be gone.
        assert_eq!(
            pc.rtp_transceivers.len(),
            1,
            "the add_track transceiver must survive rollback; the remote one must be removed"
        );
        let kept = &pc.rtp_transceivers[0];
        assert_eq!(kept.kind(), RtpCodecKind::Audio);
        assert!(kept.sender().is_some());
        assert!(kept.mid().is_none(), "must be disassociated after rollback");

        // 4. createOffer — an m= section for the added (audio) track must appear.
        let offer = pc.create_offer(None).unwrap();
        assert_eq!(
            offer.sdp.matches("m=audio").count(),
            1,
            "createOffer after rollback must emit an m=audio section for the added track"
        );
        // The transceiver has been re-associated (given a mid) for the new offer.
        assert!(pc.rtp_transceivers[0].mid().is_some());
    }

    #[test]
    fn add_track_then_rollback_local_offer_then_answer_remote_still_renegotiates_track() {
        // Polite-peer glare scenario (RFC 9429, Section 5.7): the application calls addTrack and
        // sends its own offer, then a remote offer arrives (collision). The polite peer rolls
        // back its local offer, applies the remote offer, and answers it. The locally-added
        // track was never negotiated, so it must still be pending and appear in a subsequent
        // offer — mirroring the RFC's addTrack/rollback/createOffer guarantee for the local case.
        let mut pc = media_pc();

        // 1. addTrack (audio) — local sendrecv audio transceiver with a sender.
        let track = MediaStreamTrack::new(
            "stream".to_owned(),
            "track".to_owned(),
            "label".to_owned(),
            RtpCodecKind::Audio,
            vec![],
        );
        pc.add_track(track).unwrap();

        // 2. set_local_description(our offer) — enters have-local-offer, audio gets a mid.
        let local_offer = pc.create_offer(None).unwrap();
        pc.set_local_description(Instant::now(), local_offer)
            .unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::HaveLocalOffer);
        assert!(pc.rtp_transceivers[0].mid().is_some());

        // 3. A remote (video) offer arrives — glare.
        let mut video_offerer = media_pc();
        video_offerer
            .add_transceiver_from_kind(
                RtpCodecKind::Video,
                Some(RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Recvonly,
                    streams: vec![],
                    send_encodings: vec![],
                }),
            )
            .unwrap();
        let remote_offer = video_offerer.create_offer(None).unwrap();

        // 4. Roll back our local offer (via set_local_description, the polite-peer path).
        pc.set_local_description(Instant::now(), rollback())
            .unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);
        // Our audio transceiver survives (has a track/sender) but is disassociated.
        assert_eq!(pc.rtp_transceivers.len(), 1);
        assert_eq!(pc.rtp_transceivers[0].kind(), RtpCodecKind::Audio);
        assert!(pc.rtp_transceivers[0].sender().is_some());
        assert!(pc.rtp_transceivers[0].mid().is_none());

        // 5. Apply the remote offer, then answer it.
        pc.set_remote_description(Instant::now(), remote_offer)
            .unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::HaveRemoteOffer);
        let answer = pc.create_answer(None).unwrap();
        // The answer only covers the remote's video m= section; our audio track is not yet
        // negotiated, so it must NOT appear in the answer.
        assert_eq!(answer.sdp.matches("m=video").count(), 1);
        assert_eq!(answer.sdp.matches("m=audio").count(), 0);
        pc.set_local_description(Instant::now(), answer).unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);

        // 6. The locally-added track was never negotiated, so a follow-up offer must include an
        //    m=audio section for it (alongside the now-negotiated video section).
        let followup_offer = pc.create_offer(None).unwrap();
        assert_eq!(
            followup_offer.sdp.matches("m=audio").count(),
            1,
            "the added track must appear in the offer generated after rollback + answer"
        );
        assert_eq!(followup_offer.sdp.matches("m=video").count(), 1);
        assert!(
            pc.rtp_transceivers
                .iter()
                .find(|t| t.kind() == RtpCodecKind::Audio)
                .unwrap()
                .mid()
                .is_some(),
            "audio transceiver must be re-associated for the follow-up offer"
        );
    }

    #[test]
    fn re_negotiation_with_simulcast_tracks() {
        use crate::peer_connection::configuration::media_engine::MIME_TYPE_VP8;
        use crate::rtp_transceiver::rtp_receiver::internal::RTCRtpReceiverInternal;
        use crate::rtp_transceiver::rtp_sender::{
            RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters,
            RTCRtpHeaderExtensionCapability,
        };

        fn simulcast_pc() -> RTCPeerConnection {
            let mut me = MediaEngine::default();
            me.register_default_codecs().unwrap();
            for uri in [
                ::sdp::extmap::SDES_MID_URI,
                ::sdp::extmap::SDES_RTP_STREAM_ID_URI,
                ::sdp::extmap::SDES_REPAIR_RTP_STREAM_ID_URI,
            ] {
                me.register_header_extension(
                    RTCRtpHeaderExtensionCapability {
                        uri: uri.to_owned(),
                    },
                    RtpCodecKind::Video,
                    None,
                )
                .unwrap();
            }
            RTCPeerConnectionBuilder::new()
                .with_media_engine(me)
                .build(Instant::now())
                .unwrap()
        }

        fn vp8() -> RTCRtpCodec {
            RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            }
        }

        fn simulcast_track(track_id: &str, layers: &[(&str, u32)]) -> MediaStreamTrack {
            MediaStreamTrack::new(
                format!("stream-{track_id}"),
                track_id.to_owned(),
                format!("label-{track_id}"),
                RtpCodecKind::Video,
                layers
                    .iter()
                    .map(|(rid, ssrc)| RTCRtpEncodingParameters {
                        rtp_coding_parameters: RTCRtpCodingParameters {
                            rid: (*rid).to_owned(),
                            ssrc: Some(*ssrc),
                            ..Default::default()
                        },
                        codec: vp8(),
                        ..Default::default()
                    })
                    .collect(),
            )
        }

        fn negotiate(offerer: &mut RTCPeerConnection, answerer: &mut RTCPeerConnection) {
            let offer = offerer.create_offer(None).unwrap();
            offerer
                .set_local_description(Instant::now(), offer.clone())
                .unwrap();
            answerer
                .set_remote_description(Instant::now(), offer)
                .unwrap();
            let answer = answerer.create_answer(None).unwrap();
            answerer
                .set_local_description(Instant::now(), answer.clone())
                .unwrap();
            offerer
                .set_remote_description(Instant::now(), answer)
                .unwrap();
        }

        fn receiver_by_mid<'a>(
            pc: &'a mut RTCPeerConnection,
            mid: &str,
        ) -> &'a mut RTCRtpReceiverInternal {
            pc.rtp_transceivers
                .iter_mut()
                .find(|t| t.mid().as_deref() == Some(mid))
                .and_then(|t| t.receiver_mut().as_mut())
                .expect("receiver for mid")
        }

        // The SSRCs the remote learns from the RID header extension of the first packets.
        let first_layers = [("low", 1001u32), ("mid", 1002), ("high", 1003)];
        let second_layers = [("low", 2001u32), ("mid", 2002), ("high", 2003)];

        let mut offerer = simulcast_pc();
        let mut answerer = simulcast_pc();

        offerer
            .add_track(simulcast_track("first", &first_layers))
            .unwrap();
        negotiate(&mut offerer, &mut answerer);
        assert_eq!(answerer.signaling_state, RTCSignalingState::Stable);

        let first_mid = offerer.rtp_transceivers[0]
            .mid()
            .clone()
            .expect("first track mid");

        // Simulate what `bind_by_rid` records when the first packet of each layer arrives with
        // its RID header extension.
        {
            let receiver = receiver_by_mid(&mut answerer, &first_mid);
            for (rid, ssrc) in first_layers {
                receiver
                    .get_coding_parameter_mut_by_rid(rid)
                    .expect("coding for rid")
                    .ssrc = Some(ssrc);
                receiver
                    .track_mut()
                    .set_codec_ssrc_by_rid(vp8(), ssrc, &rid.to_owned());
            }
        }

        // Renegotiate to add a second simulcast track, as a sender does when it starts
        // publishing another video. The first track's m-line is unchanged.
        offerer
            .add_track(simulcast_track("second", &second_layers))
            .unwrap();
        negotiate(&mut offerer, &mut answerer);
        assert_eq!(answerer.signaling_state, RTCSignalingState::Stable);
        assert_eq!(answerer.rtp_transceivers.len(), 2);

        // The sender stops attaching RID header extensions once the SSRC is acknowledged, so the
        // bindings learned before the renegotiation must survive it.
        let receiver = receiver_by_mid(&mut answerer, &first_mid);
        for (rid, ssrc) in first_layers {
            let coding = receiver
                .get_coding_parameters()
                .iter()
                .find(|coding| coding.rid == rid)
                .expect("coding for rid");
            assert_eq!(
                coding.ssrc,
                Some(ssrc),
                "SSRC learned for rid {rid} must be kept across renegotiation"
            );
            assert_eq!(
                receiver
                    .track()
                    .codec(ssrc)
                    .map(|codec| codec.mime_type.as_str()),
                Some(MIME_TYPE_VP8),
                "codec bound for rid {rid} must be kept across renegotiation"
            );
        }
    }

    // ---- Negotiation edge cases (JSEP RFC 8829, W3C addIceCandidate) ----

    fn remote(sdp_type: RTCSdpType, sdp: &str) -> RTCSessionDescription {
        RTCSessionDescription {
            sdp_type,
            sdp: sdp.to_owned(),
            parsed: None,
        }
    }

    /// An offer as a browser writes it under the `balanced` bundle policy: a BUNDLE group whose
    /// m-sections each have their own ICE credentials.
    const PER_SECTION_UFRAG_OFFER: &str = "v=0\r\n\
o=- 4962303333179871722 1 IN IP4 0.0.0.0\r\n\
s=-\r\n\
t=0 0\r\n\
a=ice-options:trickle\r\n\
a=group:BUNDLE a1 v1\r\n\
m=audio 10100 UDP/TLS/RTP/SAVPF 111\r\n\
c=IN IP4 203.0.113.100\r\n\
a=mid:a1\r\n\
a=sendrecv\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=ice-ufrag:ETEn\r\n\
a=ice-pwd:OtSK0WpNtpUjkY4+86js7ZQl\r\n\
a=fingerprint:sha-256 19:E2:1C:3B:4B:9F:81:E6:B8:5C:F4:A5:A8:D8:73:04:BB:05:2F:70:9F:04:A9:0E:05:E9:26:33:E8:70:88:A2\r\n\
a=setup:actpass\r\n\
a=rtcp-mux\r\n\
m=video 10102 UDP/TLS/RTP/SAVPF 96\r\n\
c=IN IP4 203.0.113.100\r\n\
a=mid:v1\r\n\
a=sendrecv\r\n\
a=rtpmap:96 VP8/90000\r\n\
a=ice-ufrag:BGKk\r\n\
a=ice-pwd:mqyWsAjvtKwTGnvhPztQ9mIf\r\n\
a=fingerprint:sha-256 19:E2:1C:3B:4B:9F:81:E6:B8:5C:F4:A5:A8:D8:73:04:BB:05:2F:70:9F:04:A9:0E:05:E9:26:33:E8:70:88:A2\r\n\
a=setup:actpass\r\n\
a=rtcp-mux\r\n";

    fn candidate(line: &str, mid: Option<&str>, ufrag: Option<&str>) -> RTCIceCandidateInit {
        RTCIceCandidateInit {
            candidate: line.to_owned(),
            sdp_mid: mid.map(str::to_owned),
            username_fragment: ufrag.map(str::to_owned),
            ..Default::default()
        }
    }

    /// RFC 9429 section 5.8.2: "Any 'a=remote-candidates' attributes MUST be parsed as
    /// specified in [RFC8839], Section 5.2, but their values are ignored".
    #[test]
    fn a_malformed_remote_candidates_line_refuses_the_description() {
        let offer = audio_video_offer();
        for (line, accepted) in [
            (
                "a=remote-candidates:1 192.0.2.3 45664 2 192.0.2.3 45665",
                true,
            ),
            ("a=remote-candidates:1 192.0.2.3", false),
            ("a=remote-candidates:1 192.0.2.3 port", false),
        ] {
            let sdp = offer
                .sdp
                .replacen("a=mid:", &format!("{line}\r\na=mid:"), 1);
            let result = media_pc()
                .set_remote_description(Instant::now(), RTCSessionDescription::offer(sdp).unwrap());
            assert_eq!(result.is_ok(), accepted, "{line}: {result:?}");
        }
    }

    /// RFC 8838 section 9: a trickled candidate without a usernameFragment whose line has a
    /// `ufrag` extension naming another ICE generation is stale: ignored, not refused.
    #[test]
    fn a_candidate_line_whose_ufrag_names_another_generation_is_ignored() {
        let mut pc = media_pc();
        pc.set_remote_description(
            Instant::now(),
            remote(RTCSdpType::Offer, PER_SECTION_UFRAG_OFFER),
        )
        .unwrap();
        let answer = pc.create_answer(None).unwrap();
        pc.set_local_description(Instant::now(), answer).unwrap();

        let line = "candidate:1 1 udp 2113929471 203.0.113.100 10100 typ host";
        pc.add_remote_candidate(candidate(&format!("{line} ufrag OLDG"), Some("a1"), None))
            .expect("a stale candidate is ignored, not refused");
        assert!(pc.ice_transport().get_remote_candidates().is_empty());
        assert!(
            !pc.remote_description().unwrap().sdp.contains("OLDG"),
            "nor recorded"
        );
        pc.add_remote_candidate(candidate(&format!("{line} ufrag ETEn"), Some("a1"), None))
            .unwrap();
        assert_eq!(pc.ice_transport().get_remote_candidates().len(), 1);
    }

    #[test]
    fn per_section_ufrags_in_a_bundle_group_use_the_tagged_sections() {
        let mut pc = media_pc();
        pc.set_remote_description(
            Instant::now(),
            remote(RTCSdpType::Offer, PER_SECTION_UFRAG_OFFER),
        )
        .expect("a BUNDLE group's m-sections may have their own ICE credentials");
        // The transport takes them with the answer.
        let answer = pc.create_answer(None).unwrap();
        pc.set_local_description(Instant::now(), answer).unwrap();
        assert_eq!(pc.ice_transport().get_remote_user_credentials().0, "ETEn");
        assert_eq!(pc.can_trickle_ice_candidates(), Some(true));

        // A candidate of the second m-section is its own (BUNDLE-replaced) transport's: it is
        // accepted and recorded in that m-section, not given to the agent.
        let line = "candidate:1 1 udp 2113929471 203.0.113.100 10100 typ host";
        pc.add_remote_candidate(candidate(line, Some("v1"), Some("BGKk")))
            .unwrap();
        assert!(pc.ice_transport().get_remote_candidates().is_empty());
        pc.add_remote_candidate(candidate(line, Some("a1"), None))
            .unwrap();
        assert_eq!(pc.ice_transport().get_remote_candidates().len(), 1);

        let sdp = pc.remote_description().unwrap().sdp.clone();
        let video = sdp.find("m=video").unwrap();
        assert_eq!(sdp[..video].matches("a=candidate:").count(), 1);
        assert_eq!(sdp[video..].matches("a=candidate:").count(), 1);
        assert!(sdp.ends_with(&format!("a={line}\r\n")));

        // The usernameFragment must be its media section's.
        assert_eq!(
            pc.add_remote_candidate(candidate(line, Some("a1"), Some("BGKk"))),
            Err(Error::ErrIceCandidateUsernameFragmentMismatch)
        );
        assert_eq!(
            pc.add_remote_candidate(candidate("", None, Some("no such ufrag"))),
            Err(Error::ErrIceCandidateUsernameFragmentMismatch)
        );
        assert_eq!(
            pc.add_remote_candidate(candidate(line, Some("nope"), None)),
            Err(Error::ErrIceCandidateMediaSectionNotFound)
        );

        // End-of-candidates without a media section marks every one, once.
        pc.add_remote_candidate(candidate("", None, None)).unwrap();
        pc.add_remote_candidate(candidate("", Some("v1"), None))
            .unwrap();
        let sdp = &pc.remote_description().unwrap().sdp;
        assert_eq!(sdp.matches("a=end-of-candidates\r\n").count(), 2);
    }

    /// RFC 8838 section 14: a remote candidate that follows the end-of-candidates indication
    /// of its generation is ignored: the ICE agent does not take it and the remote
    /// description does not show it after `a=end-of-candidates`.
    #[test]
    fn remote_candidates_after_end_of_candidates_are_ignored() {
        let mut pc = media_pc();
        pc.set_remote_description(
            Instant::now(),
            remote(RTCSdpType::Offer, PER_SECTION_UFRAG_OFFER),
        )
        .unwrap();
        let line = "candidate:1 1 udp 2113929471 203.0.113.100 10100 typ host";
        pc.add_remote_candidate(candidate(line, Some("a1"), None))
            .unwrap();
        let held = pc.ice_transport().get_remote_candidates().len();
        let recorded = |pc: &RTCPeerConnection| {
            pc.remote_description()
                .unwrap()
                .sdp
                .matches("a=candidate:")
                .count()
        };
        let lines = recorded(&pc);

        // End-of-candidates, then one more candidate.
        pc.add_remote_candidate(candidate("", Some("a1"), None))
            .unwrap();
        assert!(
            pc.remote_description()
                .unwrap()
                .sdp
                .contains("a=end-of-candidates")
        );
        let late = "candidate:2 1 udp 2113929471 203.0.113.101 10101 typ host";
        pc.add_remote_candidate(candidate(late, Some("a1"), None))
            .unwrap();
        assert_eq!(pc.ice_transport().get_remote_candidates().len(), held);
        assert_eq!(recorded(&pc), lines);
        // What does not parse is still an error.
        assert!(
            pc.add_remote_candidate(candidate("candidate:nonsense", Some("a1"), None))
                .is_err()
        );
    }

    #[test]
    fn trickled_candidates_are_capped_and_single_line() {
        let mut pc = media_pc();
        pc.set_remote_description(
            Instant::now(),
            remote(RTCSdpType::Offer, PER_SECTION_UFRAG_OFFER),
        )
        .unwrap();

        // A line break or NUL inside the value is refused, and nothing is recorded.
        for bad in [
            "candidate:1 1 udp 2113929471 203.0.113.100 10100 typ host\r\na=evil",
            "candidate:1 1 udp 2113929471 203.0.113.100 10100 typ host\na=evil",
            "candidate:1 1 udp 2113929471 203.0.113.100 10100 typ host\0",
        ] {
            assert!(matches!(
                pc.add_remote_candidate(candidate(bad, Some("a1"), None)),
                Err(Error::SdpInvalidValue(_))
            ));
        }
        assert!(!pc.remote_description().unwrap().sdp.contains("evil"));

        // The same candidate twice is recorded once.
        let line = "candidate:1 1 udp 2113929471 203.0.113.100 10100 typ host";
        pc.add_remote_candidate(candidate(line, Some("a1"), None))
            .unwrap();
        pc.add_remote_candidate(candidate(line, Some("a1"), None))
            .unwrap();
        assert_eq!(
            pc.remote_description()
                .unwrap()
                .sdp
                .matches("a=candidate:")
                .count(),
            1
        );

        for i in 0..100_000u32 {
            let port = 1024 + i % 60_000;
            let line = format!(
                "candidate:{i} 1 udp 2113929471 203.0.113.{} {port} typ host",
                i % 250
            );
            pc.add_remote_candidate(candidate(&line, Some("a1"), None))
                .unwrap();
        }

        assert!(pc.ice_transport().get_remote_candidates().len() <= MAX_TRICKLED_REMOTE_CANDIDATES);
        assert!(pc.stats().remote_candidates.len() <= MAX_TRICKLED_REMOTE_CANDIDATES);
        let description = pc.remote_description().unwrap();
        assert!(description.sdp.matches("a=candidate:").count() <= MAX_TRICKLED_REMOTE_CANDIDATES);
        let recorded = description.parsed.as_ref().unwrap().media_descriptions[0]
            .attributes
            .iter()
            .filter(|a| a.key == ATTR_KEY_CANDIDATE)
            .count();
        assert!(recorded <= MAX_TRICKLED_REMOTE_CANDIDATES);

        // A malformed candidate past the cap is still refused.
        assert!(
            pc.add_remote_candidate(candidate("candidate:garbage", Some("a1"), None))
                .is_err()
        );

        // A new remote description starts a new budget.
        pc.set_remote_description(
            Instant::now(),
            remote(RTCSdpType::Offer, PER_SECTION_UFRAG_OFFER),
        )
        .unwrap();
        assert_eq!(pc.trickled_remote_candidates, 0);
    }

    #[test]
    fn sections_without_ssrc_lines_are_answered() {
        // RFC 8843 §9.2: a=ssrc is optional; the MID header extension identifies each section.
        let offer = PER_SECTION_UFRAG_OFFER
            .replace("a=mid:a1\r\n", "a=mid:a1\r\na=msid:stream audio-track\r\n")
            .replace("a=mid:v1\r\n", "a=mid:v1\r\na=msid:stream video-track\r\n");
        let mut pc = media_pc();
        pc.set_remote_description(Instant::now(), remote(RTCSdpType::Offer, &offer))
            .unwrap();
        let answer = pc.create_answer(None).unwrap();
        pc.set_local_description(Instant::now(), answer)
            .expect("two media sections without a=ssrc");
        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);
    }

    #[test]
    fn the_answer_takes_the_dtls_role_the_offer_left() {
        for (offered, answered) in [
            ("a=setup:active", "a=setup:passive"),
            ("a=setup:passive", "a=setup:active"),
            ("a=setup:actpass", "a=setup:active"),
        ] {
            let offer = PER_SECTION_UFRAG_OFFER.replace("a=setup:actpass", offered);
            let mut pc = media_pc();
            pc.set_remote_description(Instant::now(), remote(RTCSdpType::Offer, &offer))
                .unwrap();
            let answer = pc.create_answer(None).unwrap();
            assert!(answer.sdp.contains(answered), "{offered}: {}", answer.sdp);
            assert!(!answer.sdp.contains(offered) || offered == answered);
        }
    }

    #[test]
    fn an_offer_without_media_sections_is_answered_without_starting_transports() {
        let offer = media_pc().create_offer(None).unwrap();
        assert!(!offer.sdp.contains("m="));

        let mut pc = media_pc();
        pc.set_remote_description(Instant::now(), offer).unwrap();
        let answer = pc.create_answer(None).unwrap();
        pc.set_local_description(Instant::now(), answer).unwrap();
        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);
        assert_eq!(pc.ice_transport().state(), RTCIceTransportState::New);

        // The next offer that has an m-section starts them, with its answer (a rollback of the
        // offer has nothing to undo, RFC 9429 section 5.7).
        pc.set_remote_description(Instant::now(), audio_video_offer())
            .unwrap();
        assert_eq!(pc.ice_transport().state(), RTCIceTransportState::New);
        let answer = pc.create_answer(None).unwrap();
        pc.set_local_description(Instant::now(), answer).unwrap();
        assert_ne!(pc.ice_transport().state(), RTCIceTransportState::New);
    }

    #[test]
    fn a_remote_offer_can_be_applied_again_and_rolled_back() {
        let mut pc = media_pc();
        pc.set_remote_description(Instant::now(), audio_video_offer())
            .unwrap();
        pc.set_remote_description(Instant::now(), audio_video_offer())
            .expect("have-remote-offer takes another remote offer");
        assert_eq!(pc.signaling_state, RTCSignalingState::HaveRemoteOffer);
        pc.set_remote_description(Instant::now(), rollback())
            .unwrap();
        pc.set_remote_description(Instant::now(), audio_video_offer())
            .expect("a remote offer after a rollback");
        // Either method rolls a remote offer back (RFC 9429 section 5.7).
        pc.set_local_description(Instant::now(), rollback())
            .expect("a remote offer is rolled back through set_local_description too");
        assert_eq!(pc.signaling_state, RTCSignalingState::Stable);
    }

    #[test]
    fn provisional_answers_repeat_and_keep_the_offerer_controlling() {
        let mut offerer = media_pc();
        offerer
            .add_transceiver_from_kind(
                RtpCodecKind::Audio,
                Some(crate::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
            )
            .unwrap();
        let offer = offerer.create_offer(None).unwrap();
        offerer
            .set_local_description(Instant::now(), offer.clone())
            .unwrap();

        let mut answerer = media_pc();
        answerer
            .set_remote_description(Instant::now(), offer)
            .unwrap();
        let answer = answerer.create_answer(None).unwrap();
        let pranswer = remote(RTCSdpType::Pranswer, &answer.sdp);
        answerer
            .set_local_description(Instant::now(), pranswer.clone())
            .unwrap();
        answerer
            .set_local_description(Instant::now(), pranswer.clone())
            .expect("have-local-pranswer takes another provisional answer");
        assert_eq!(
            answerer.signaling_state,
            RTCSignalingState::HaveLocalPranswer
        );

        offerer
            .set_remote_description(Instant::now(), pranswer.clone())
            .unwrap();
        assert_eq!(offerer.ice_transport().role(), RTCIceRole::Controlling);
        offerer
            .set_remote_description(Instant::now(), pranswer)
            .expect("have-remote-pranswer takes another provisional answer");
        offerer
            .set_remote_description(Instant::now(), remote(RTCSdpType::Answer, &answer.sdp))
            .unwrap();
        assert_eq!(offerer.signaling_state, RTCSignalingState::Stable);
        assert_eq!(offerer.ice_transport().role(), RTCIceRole::Controlling);
    }

    /// RFC 8445 section 6.1.1: "Once the roles are determined for a session, they persist
    /// throughout the lifetime of the session. The roles can be redetermined as part of an ICE
    /// restart, but an ICE agent MUST NOT redetermine the role as part of an ICE restart
    /// unless [...] the controlling agent is full, and switches to lite". The offerer of the
    /// first exchange is the controlling agent; a restart the other side offers changes
    /// nothing; when the controlling agent comes back lite, the full peer takes the role.
    #[test]
    fn ice_roles_persist_across_a_restart_and_follow_a_peer_that_becomes_lite() {
        let now = Instant::now();
        let mut first = media_pc();
        first
            .add_transceiver_from_kind(RtpCodecKind::Audio, None)
            .unwrap();
        let mut second = media_pc();
        let exchange = |offerer: &mut RTCPeerConnection,
                        answerer: &mut RTCPeerConnection,
                        ice_restart: bool,
                        munge: &dyn Fn(&str) -> String| {
            let offer = offerer
                .create_offer(Some(RTCOfferOptions { ice_restart }))
                .unwrap();
            offerer.set_local_description(now, offer.clone()).unwrap();
            answerer
                .set_remote_description(now, remote(RTCSdpType::Offer, &munge(&offer.sdp)))
                .unwrap();
            let answer = answerer.create_answer(None).unwrap();
            answerer.set_local_description(now, answer.clone()).unwrap();
            offerer.set_remote_description(now, answer).unwrap();
        };
        let keep = |sdp: &str| sdp.to_owned();

        exchange(&mut first, &mut second, false, &keep);
        assert_eq!(first.ice_transport().role(), RTCIceRole::Controlling);
        assert_eq!(second.ice_transport().role(), RTCIceRole::Controlled);
        let first_ufrag = first
            .ice_transport()
            .get_local_user_credentials()
            .0
            .to_owned();

        // The controlled side offers an ICE restart: the roles stay.
        exchange(&mut second, &mut first, true, &keep);
        assert_ne!(
            first.ice_transport().get_local_user_credentials().0,
            first_ufrag,
            "an ICE restart"
        );
        assert_eq!(first.ice_transport().role(), RTCIceRole::Controlling);
        assert_eq!(second.ice_transport().role(), RTCIceRole::Controlled);

        // And when the controlling side offers one: they stay as well.
        exchange(&mut first, &mut second, true, &keep);
        assert_eq!(first.ice_transport().role(), RTCIceRole::Controlling);
        assert_eq!(second.ice_transport().role(), RTCIceRole::Controlled);

        // The controlling agent restarts as a lite implementation: the full peer controls.
        let lite = |sdp: &str| sdp.replacen("t=0 0\r\n", "t=0 0\r\na=ice-lite\r\n", 1);
        assert!(lite("t=0 0\r\n").contains("a=ice-lite"));
        exchange(&mut first, &mut second, true, &lite);
        assert_eq!(second.ice_transport().role(), RTCIceRole::Controlling);
        assert_eq!(
            second
                .get_stats(now, crate::statistics::StatsSelector::None)
                .transport()
                .map(|t| t.ice_role),
            Some(RTCIceRole::Controlling)
        );
    }

    #[test]
    fn descriptions_offer_trickle_and_a_fingerprint_per_certificate() {
        use crate::peer_connection::certificate::RTCCertificate;
        use crate::peer_connection::configuration::RTCConfigurationBuilder;

        let certificate = || {
            let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            RTCCertificate::from_key_pair(kp).unwrap()
        };
        let mut me = MediaEngine::default();
        me.register_default_codecs().unwrap();
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(me)
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_certificates(vec![certificate(), certificate()])
                    .build(),
            )
            .build(Instant::now())
            .unwrap();
        pc.add_transceiver_from_kind(
            RtpCodecKind::Audio,
            Some(crate::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
        )
        .unwrap();
        let offer = pc.create_offer(None).unwrap();
        assert!(offer.sdp.contains("a=ice-options:trickle ice2\r\n"));
        assert_eq!(offer.sdp.matches("a=fingerprint:sha-256 ").count(), 2);

        // The other side takes both and trickles back.
        let mut answerer = media_pc();
        answerer
            .set_remote_description(Instant::now(), offer)
            .unwrap();
        let answer = answerer.create_answer(None).unwrap();
        assert!(answer.sdp.contains("a=ice-options:trickle ice2\r\n"));
    }

    /// RFC 8445 section 14.2: an agent that wants a Ta other than the default proposes it
    /// (`a=ice-pacing`, RFC 8839 section 5.5), and "Both agents MUST use the higher out of the
    /// two proposed values"; RFC 8445 section 10: both say `ice2`.
    #[test]
    fn a_proposed_ice_pacing_is_signalled_and_both_agents_use_the_higher_value() {
        use std::time::Duration;
        let peer = |ta: Option<Duration>| {
            let mut me = MediaEngine::default();
            me.register_default_codecs().unwrap();
            RTCPeerConnectionBuilder::new()
                .with_media_engine(me)
                .with_setting_engine(SettingEngineBuilder::new().with_ice_pacing(ta).build())
                .build(Instant::now())
                .unwrap()
        };
        let mut offerer = peer(Some(Duration::from_millis(80)));
        let mut answerer = peer(Some(Duration::from_millis(20)));
        offerer
            .add_transceiver_from_kind(RtpCodecKind::Audio, None)
            .unwrap();
        let now = Instant::now();
        let offer = offerer.create_offer(None).unwrap();
        assert!(offer.sdp.contains("a=ice-pacing:80\r\n"), "{}", offer.sdp);
        offerer.set_local_description(now, offer.clone()).unwrap();
        answerer.set_remote_description(now, offer).unwrap();
        let answer = answerer.create_answer(None).unwrap();
        assert!(answer.sdp.contains("a=ice-pacing:20\r\n"), "{}", answer.sdp);
        answerer.set_local_description(now, answer.clone()).unwrap();
        offerer.set_remote_description(now, answer).unwrap();

        assert_eq!(
            Duration::from_millis(80),
            offerer.ice_transport().agent.pacing()
        );
        assert_eq!(
            Duration::from_millis(80),
            answerer.ice_transport().agent.pacing()
        );
        assert!(offerer.remote_ice_options().contains(&"ice2".to_owned()));
        assert!(
            answerer
                .remote_ice_options()
                .contains(&"trickle".to_owned())
        );

        // The default Ta is not proposed.
        let mut plain = peer(None);
        plain
            .add_transceiver_from_kind(RtpCodecKind::Audio, None)
            .unwrap();
        assert!(
            !plain
                .create_offer(None)
                .unwrap()
                .sdp
                .contains("a=ice-pacing")
        );
    }

    /// `SettingEngineBuilder::with_mid_generator` was stored and never read.
    #[test]
    fn mid_generator_names_new_transceivers() {
        let mut me = MediaEngine::default();
        me.register_default_codecs().unwrap();
        let setting_engine = SettingEngineBuilder::new()
            .with_mid_generator(|max_mid| format!("custom_{}", max_mid + 1))
            .build();
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(me)
            .with_setting_engine(setting_engine)
            .build(Instant::now())
            .unwrap();
        for kind in [RtpCodecKind::Audio, RtpCodecKind::Video] {
            pc.add_transceiver_from_kind(
                kind,
                Some(crate::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
            )
            .unwrap();
        }
        let offer = pc.create_offer(None).unwrap();
        assert!(offer.sdp.contains("a=mid:custom_0\r\n"), "{}", offer.sdp);
        assert!(offer.sdp.contains("a=mid:custom_1\r\n"), "{}", offer.sdp);
    }
}
