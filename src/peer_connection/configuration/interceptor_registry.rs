//! Interceptor Registry - Configuration helpers for RTP/RTCP interceptor chains.
//!
//! This module provides convenience functions for configuring common interceptor
//! combinations used in WebRTC applications. Interceptors process RTP/RTCP packets
//! as they flow through the media pipeline, enabling features like:
//!
//! - **NACK** - Negative acknowledgement for packet loss recovery (RFC 4585)
//! - **RTCP Reports** - Sender/Receiver reports for quality monitoring (RFC 3550)
//! - **TWCC** - Transport-wide congestion control for bandwidth estimation
//! - **Simulcast** - Multi-resolution video streaming support
//!
//! # Interceptor Chain Architecture
//!
//! A chain is a flat list of interceptors ordered by **distance from the wire**: the first is
//! closest to the network, the last closest to the application. Each interceptor declares that
//! distance as a [`Slot`], so the position is a property of the
//! interceptor rather than of the order the helpers below happened to be called in — which is what
//! lets them be called in any order. Direction is a property of the walk rather than of the list:
//!
//! ```text
//! read   (network → application)   forward:  first → … → last
//! write  (application → network)   reverse:  last  → … → first
//! ```
//!
//! One list serves both directions, so "closest to the wire" means one thing rather than opposite
//! things per direction.
//!
//! [`register_default_interceptors`] composes this chain, listed wire-to-application:
//!
//! ```text
//!   wire-most   [NACK Responder]    buffers sent RTP, retransmits on NACK
//!               [NACK Generator]    detects gaps in inbound RTP, emits NACK
//!               [TWCC Receiver]     records arrivals, emits TransportLayerCC
//!               [Receiver Report]   emits RR from inbound RTP statistics
//!    app-most   [Sender Report]     emits SR, filters hop-by-hop RTCP
//!                     ↓
//!               [Noop]              ends the inbound RTCP path
//! ```
//!
//! The NACK responder is wire-most because its retransmissions must still pass everything between
//! it and the network; the generator is above it because loss has to be detected from arrivals.
//! The arrival recorders come before the report generators, and before anything that delays or
//! re-stamps a packet.
//!
//! When adding an interceptor that **delays** a packet (jitter buffer, pacer) or **generates**
//! one (FEC repair, a recovered packet), its position stops being a preference and becomes a
//! correctness property. The named slots carry those rules; one of your own goes at
//! `Slot::from(n)`, and they are spaced so there is room between any two. The
//! rules are documented on [`Slot`],
//! [`Registry`] and on the interceptor trait itself.
//!
//! # Quick Start
//!
//! For most applications, use [`register_default_interceptors`] to enable
//! standard WebRTC functionality:
//!
//! ```no_run
//! # use std::time::Instant;
//! use rtc::interceptor::Registry;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//! use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
//! use rtc::peer_connection::configuration::media_engine::MediaEngine;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut media_engine = MediaEngine::default();
//! let registry = Registry::new();
//!
//! // Register NACK, RTCP reports, simulcast headers, and TWCC receiver.
//! // Note this takes `&mut media_engine`: it registers the RTCP feedback types and
//! // header extensions the interceptors need, so pass that same engine to the registry.
//! let registry = register_default_interceptors(registry, &mut media_engine)?;
//!
//! let pc = RTCPeerConnectionBuilder::new()
//!     .with_media_engine(media_engine)
//!     .with_interceptor_registry(registry)
//!     .build(Instant::now())?;
//! # Ok(())
//! # }
//! ```
//!
//! # Custom Configuration
//!
//! For fine-grained control, configure individual interceptors:
//!
//! ```no_run
//! # use std::time::Instant;
//! use rtc::interceptor::Registry;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//! use rtc::peer_connection::configuration::interceptor_registry::{configure_nack, configure_twcc};
//! use rtc::peer_connection::configuration::media_engine::MediaEngine;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut media_engine = MediaEngine::default();
//! let registry = Registry::new();
//!
//! // Only enable NACK (no TWCC, no reports)
//! let registry = configure_nack(registry, &mut media_engine);
//!
//! // Or enable full TWCC for bandwidth estimation
//! let registry = configure_twcc(registry, &mut media_engine)?;
//!
//! // Handed over unbuilt: the peer connection builds the chain, and `build` composes by slot
//! // rather than by the order the helpers ran in.
//! let registry = registry;
//!
//! let pc = RTCPeerConnectionBuilder::new()
//!     .with_media_engine(media_engine)
//!     .with_interceptor_registry(registry)
//!     .build(Instant::now())?;
//! # Ok(())
//! # }
//! ```
//!
//! # Available Configurations
//!
//! | Function | Description |
//! |----------|-------------|
//! | [`register_default_interceptors`] | Standard WebRTC setup (NACK + Reports + TWCC Receiver) |
//! | [`configure_nack`] | NACK generator and responder for loss recovery |
//! | [`configure_rtcp_reports`] | The RTCP session: reports, CNAME, BYE, RFC 3550 / RFC 4585 timing |
//! | [`configure_twcc`] | Full TWCC (sender + receiver) |
//! | [`configure_twcc_sender_only`] | TWCC sender only (remote generates feedback) |
//! | [`configure_twcc_receiver_only`] | TWCC receiver only (generates feedback for remote) |
//! | [`configure_simulcast_extension_headers`] | RTP extensions for simulcast |
//!
//! # References
//!
//! - [RFC 4585](https://datatracker.ietf.org/doc/html/rfc4585) - RTP/AVPF (NACK)
//! - [RFC 3550](https://datatracker.ietf.org/doc/html/rfc3550) - RTP (SR/RR)
//! - [draft-holmer-rmcat-transport-wide-cc](https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01) - TWCC

use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::peer_connection::configuration::remote_bitrate_limit::{
    REMOTE_BITRATE_LIMIT_SLOT, RemoteBitrateLimitInterceptor,
};
use crate::rtp_transceiver::rtp_sender::rtcp_parameters::{
    RTCP_FB_ACK_CCFB, TYPE_RTCP_FB_ACK, TYPE_RTCP_FB_CCM, TYPE_RTCP_FB_NACK,
    TYPE_RTCP_FB_TRANSPORT_CC,
};
use crate::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RTCRtpHeaderExtensionCapability,
    RTCRtpHeaderExtensionEncryption, RTCRtpHeaderExtensionParameters, RtpCodecKind,
};
use crate::rtp_transceiver::{PayloadType, RTCRtpTransceiverDirection, SSRC};
use interceptor::{
    BandwidthEstimator, CircuitBreakerBuilder, CircuitBreakerHandle, CongestionControlBuilder,
    CongestionControlHandle, Gcc, KeyFrameRequestInterceptor, NackGeneratorBuilder,
    NackResponderBuilder, PacerBuilder, PerRtpSession, Rfc8888Builder, RtcpSessionBuilder,
    TstnResponderBuilder, TwccReceiverBuilder, TwccSenderBuilder, XrReportBuilder,
};
use std::time::Duration;

/// The chain registry these helpers take and return, and the positions they place interceptors at.
///
/// Re-exported so the helpers and the type they operate on can be named from one path — every
/// example here reaches for both, and the definitions live in `rtc-interceptor` because the chain
/// does.
pub use interceptor::{Registry, Slot};
use shared::error::Result;

/// Registers a standard set of interceptors for typical WebRTC usage.
///
/// This function configures the following interceptors:
/// - **NACK**: Detects packet loss and requests retransmissions (video only)
/// - **RTCP Reports**: Generates Sender Reports (SR) and Receiver Reports (RR)
/// - **Simulcast Headers**: Enables RTP extensions for multi-resolution streaming
/// - **Congestion control feedback**: RFC 8888 (`ack ccfb`) and transport-wide congestion
///   control (`transport-cc`) are both offered, and each stream runs on one of them: RFC 8888
///   when the peer accepted it, TWCC otherwise (RFC 8888 section 6)
/// - **Congestion control**: Google Congestion Control ([`Gcc`]) over that feedback, with a
///   pacer that releases media at its target (RFC 8834 section 7)
/// - **TMMBR**: offered (`ccm tmmbr`), and honoured for the streams that negotiated it
///   (RFC 8834 section 5.1.6, RFC 5104)
/// - **RTP circuit breaker**: stops a flow whose receiver has gone or that persistently
///   overloads the path (RFC 8083; RFC 8834 section 7.1)
/// - **Key-frame requests**: Delivers inbound PLI and FIR to the application, the encoder that
///   has to answer them (fork addition; see [`configure_key_frame_requests`])
///
/// # Congestion control is on
///
/// RFC 8834 section 7 requires a WebRTC endpoint to adapt its RTP traffic to the capacity of
/// the path and to implement the RTP circuit breaker, so the standard set does both. The
/// estimate is what the application's encoder should produce: read it from
/// [`DefaultInterceptorHandles::congestion_control`]
/// (see [`register_default_interceptors_with_handles`]), from the statistics report
/// (`availableOutgoingBitrate`), or keep using the fork's pull-style
/// [`GccHandle`](interceptor::GccHandle) by placing a
/// [`GccInterceptor`](interceptor::GccInterceptor) in [`Slot::CongestionControl`], which replaces
/// the estimator registered here (a slot holds one interceptor) while the pacer follows it.
/// Media written faster than the target is queued by the pacer, not sent.
///
/// An application that brings its own congestion control, or runs where none is wanted (a
/// loopback test, a closed network with reserved capacity), opts out explicitly with
/// [`register_default_interceptors_without_congestion_control`].
///
/// # Parameters
///
/// * `registry` - The interceptor registry to configure
/// * `media_engine` - The media engine to register RTCP feedback and header extensions
///
/// # Returns
///
/// A new registry with the configured interceptor chain.
///
/// # Examples
///
/// ```
/// use rtc::interceptor::Registry;
/// use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = register_default_interceptors(registry, &mut media_engine)?;
/// # Ok(())
/// # }
/// ```
///
/// # Customization
///
/// If you need to customize which interceptors are loaded, copy the code from
/// this function and remove or modify the unwanted interceptors.
///
/// # Errors
///
/// Returns an error if a header extension an interceptor requires cannot be registered on the
/// media engine — see [`MediaEngine::register_header_extension`].
pub fn register_default_interceptors(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
    register_default_interceptors_with_handles(registry, media_engine)
        .map(|(registry, _handles)| registry)
}

/// What an application holds on to from the standard interceptor set.
#[derive(Clone)]
pub struct DefaultInterceptorHandles {
    /// The congestion controller of the first transport (the only one while every m= section
    /// is bundled): the target bit rate for the encoder, and where the limits from signalling
    /// go (`b=AS` / `b=TIAS`, a path change). Every transport's: [`Self::transports`].
    pub congestion_control: CongestionControlHandle,
    /// The RTP circuit breaker of the first transport: which flows have ceased transmission
    /// and why, and how one is restarted. Every transport's: [`Self::transports`].
    pub circuit_breaker: CircuitBreakerHandle,
    /// The congestion controller and circuit breaker of each transport (each RTP session,
    /// RFC 8834 section 4.4), by its RTP session number
    /// ([`RTCDtlsTransport::rtp_session`](crate::peer_connection::transport::RTCDtlsTransport::rtp_session)).
    pub transports: TransportHandles,
}

/// The congestion controller and circuit breaker handles of each transport of a peer
/// connection, by RTP session number (0 is the first transport). A transport's appear when
/// its first stream is bound; they stay while the transport has streams.
#[derive(Clone, Default)]
pub struct TransportHandles {
    shared: std::sync::Arc<std::sync::Mutex<TransportHandleTable>>,
}

#[derive(Default)]
struct TransportHandleTable {
    congestion_control: std::collections::BTreeMap<usize, CongestionControlHandle>,
    circuit_breakers: std::collections::BTreeMap<usize, CircuitBreakerHandle>,
}

impl TransportHandles {
    fn table(&self) -> std::sync::MutexGuard<'_, TransportHandleTable> {
        self.shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The RTP session numbers that have a congestion controller.
    pub fn sessions(&self) -> Vec<usize> {
        self.table().congestion_control.keys().copied().collect()
    }

    /// The congestion controller of the transport of RTP session `session`.
    pub fn congestion_control(&self, session: usize) -> Option<CongestionControlHandle> {
        self.table().congestion_control.get(&session).cloned()
    }

    /// The circuit breaker of the transport of RTP session `session`.
    pub fn circuit_breaker(&self, session: usize) -> Option<CircuitBreakerHandle> {
        self.table().circuit_breakers.get(&session).cloned()
    }

    /// The connection's target: the sum of the transports' targets, in bits per second.
    pub fn target_bitrate(&self) -> f64 {
        self.table()
            .congestion_control
            .values()
            .map(CongestionControlHandle::target_bitrate)
            .sum()
    }

    /// The circuit breaker handle of `session`, made the first time it is asked for.
    fn breaker_for(&self, session: usize) -> CircuitBreakerHandle {
        self.table()
            .circuit_breakers
            .entry(session)
            .or_default()
            .clone()
    }

    fn insert_congestion_control(&self, session: usize, handle: CongestionControlHandle) {
        self.table().congestion_control.insert(session, handle);
    }
}

/// The settings of the standard interceptor set. The default of each is what the RFCs say;
/// the other value is the behaviour of a browser or of an earlier version of this crate.
///
/// ```
/// use rtc::interceptor::Registry;
/// use rtc::peer_connection::configuration::interceptor_registry::{
///     CongestionFeedback, DefaultInterceptorOptions, register_default_interceptors_with_options,
/// };
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let mut options = DefaultInterceptorOptions::default();
/// // Offer transport-wide congestion control only, as browsers do.
/// options.congestion_feedback = CongestionFeedback::Twcc;
/// let (registry, handles) =
///     register_default_interceptors_with_options(Registry::new(), &mut media_engine, &options)?;
/// # let _ = (registry, handles);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DefaultInterceptorOptions {
    /// Which congestion control feedback is offered and accepted. The default,
    /// [`CongestionFeedback::Negotiated`], offers RFC 8888 and transport-wide congestion
    /// control together and runs each stream on the one the peer accepted.
    pub congestion_feedback: CongestionFeedback,
    /// Whether a TMMBR limits a stream that did not negotiate `a=rtcp-fb:<pt> ccm tmmbr`
    /// (RFC 5104 sections 7.1 and 7.2). `false` by default: only a negotiated TMMBR is
    /// honoured. See
    /// [`CongestionControlBuilder::with_unnegotiated_tmmbr`](interceptor::CongestionControlBuilder::with_unnegotiated_tmmbr).
    pub unnegotiated_tmmbr: bool,
    /// Whether the pacer lets a packet inside its budget leave as it is written (`true`, the
    /// default) or holds every packet for its next timeout. See
    /// [`PacerBuilder::with_immediate_release`](interceptor::PacerBuilder::with_immediate_release).
    pub pacer_immediate_release: bool,
    /// Whether the path is probed for capacity above the target with short clusters of
    /// packets, as libwebrtc does. `true` by default: RFC 8836 section 2 asks that a
    /// congestion controller "adapt as quickly as possible to initial network conditions"
    /// (requirement 4, a SHOULD) and names probing during setup as one way, and with it a
    /// path of 2.5 Mbit/s is found in under a second from a 300 kbit/s start, against about
    /// 26 seconds without. A cluster the application's own media does not fill is filled with
    /// padding-only packets on the RTX stream, which carry no media and which receivers drop
    /// (none without RTX negotiated). `false` sends only what the application writes. See
    /// [`CongestionControlBuilder::with_bandwidth_probing`](interceptor::CongestionControlBuilder::with_bandwidth_probing).
    pub bandwidth_probing: bool,
}

impl Default for DefaultInterceptorOptions {
    fn default() -> Self {
        Self {
            congestion_feedback: CongestionFeedback::default(),
            unnegotiated_tmmbr: false,
            pacer_immediate_release: true,
            bandwidth_probing: true,
        }
    }
}

/// [`register_default_interceptors`], returning the handles of the congestion controller and
/// the circuit breaker it installs.
///
/// # Errors
///
/// As [`register_default_interceptors`].
pub fn register_default_interceptors_with_handles(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<(Registry, DefaultInterceptorHandles)> {
    register_default_interceptors_with_options(
        registry,
        media_engine,
        &DefaultInterceptorOptions::default(),
    )
}

/// [`register_default_interceptors_with_handles`] with settings other than the defaults.
///
/// # Errors
///
/// As [`register_default_interceptors`].
pub fn register_default_interceptors_with_options(
    registry: Registry,
    media_engine: &mut MediaEngine,
    options: &DefaultInterceptorOptions,
) -> Result<(Registry, DefaultInterceptorHandles)> {
    // Order is not decided here — `Registry::build` decides it. These may be called in
    // any sequence.
    let registry = configure_nack(registry, media_engine);

    configure_simulcast_extension_headers(media_engine)?;

    // The per-packet feedback of both directions: what this endpoint's packets are numbered
    // with and reported in, and the reports about the remote's.
    register_congestion_feedback(media_engine, options.congestion_feedback)?;
    // Per transport, with the congestion controller below: each transport numbers its
    // packets and is estimated on its own (the remote reports each transport's sequence).
    let registry = with_congestion_feedback_senders(registry, options.congestion_feedback, true);
    let registry = with_congestion_feedback_recorders(registry, options.congestion_feedback);

    // A media sender implements TMMBR (RFC 8834 section 5.1.6), and it is in use where the
    // session names it (RFC 5104 section 7.1).
    configure_tmmbr(media_engine);

    // One circuit breaker per transport (RFC 8083 judges each RTP session's flows on its own
    // RTCP), given to that transport's congestion controller.
    let transports = TransportHandles::default();
    let circuit_breaker = transports.breaker_for(0);
    let registry = {
        let transports = transports.clone();
        registry.with_per_rtp_session(
            Slot::CircuitBreaker,
            PerRtpSession::with_first_for_sessions(
                CircuitBreakerBuilder::new().build_with_handle(&circuit_breaker),
                move |session| {
                    CircuitBreakerBuilder::new().build_with_handle(&transports.breaker_for(session))
                },
            ),
        )
    };

    // The estimator runs on whichever per-packet feedback each stream negotiated: RFC 8888
    // when the peer accepted `ack ccfb`, transport-wide congestion control otherwise.
    //
    // One controller, bound and pacer per transport: each transport is a path of its own
    // (RFC 8836 section 2; an RTP session each, RFC 8834 section 4.4). The handle reads the
    // first transport's controller.
    let initial_target = Gcc::default().target_bitrate();
    let congestion_control_builder = {
        let transports = transports.clone();
        let unnegotiated_tmmbr = options.unnegotiated_tmmbr;
        let bandwidth_probing = options.bandwidth_probing;
        move |session: usize| {
            CongestionControlBuilder::new(Gcc::default())
                .with_circuit_breaker(transports.breaker_for(session))
                .with_unnegotiated_tmmbr(unnegotiated_tmmbr)
                .with_bandwidth_probing(bandwidth_probing)
        }
    };
    let (congestion_control, handle) = congestion_control_builder(0).build_with_handle();
    transports.insert_congestion_control(0, handle.clone());
    let pacer_immediate_release = options.pacer_immediate_release;
    let registry = registry
        .with_per_rtp_session(
            Slot::CongestionControl,
            PerRtpSession::with_first_for_sessions(congestion_control, {
                let transports = transports.clone();
                move |session| {
                    let (controller, handle) =
                        congestion_control_builder(session).build_with_handle();
                    transports.insert_congestion_control(session, handle);
                    controller
                }
            }),
        )
        // The remote description's `b=TIAS` / `b=AS` bounds the estimate on its way to the
        // pacer (RFC 9429 section 5.10); the peer connection feeds it when an answer is
        // applied.
        .with_per_rtp_session(
            Slot::Custom(REMOTE_BITRATE_LIMIT_SLOT),
            PerRtpSession::new(move || RemoteBitrateLimitInterceptor::new(initial_target)),
        )
        .with_per_rtp_session(
            Slot::Pacer,
            PerRtpSession::new(move || {
                PacerBuilder::new()
                    .with_target_bitrate(initial_target)
                    .with_immediate_release(pacer_immediate_release)
                    .build()
            }),
        );

    let registry = configure_rtcp_reports(registry);
    let registry = configure_extended_reports(registry);
    let registry = configure_tradeoff_notifications(registry);
    configure_receiver_reference_time(media_engine);

    let registry = configure_key_frame_requests(registry);
    let registry = configure_remb(registry);

    // Last, so the ids of the extensions registered above stay what they were.
    configure_default_header_extensions(media_engine)?;
    configure_abs_send_time(media_engine)?;

    Ok((
        registry,
        DefaultInterceptorHandles {
            congestion_control: handle,
            circuit_breaker,
            transports,
        },
    ))
}

/// The standard set without congestion control: no estimator, no pacer, no transport-wide
/// sequence numbers on outgoing packets, no circuit breaker. NACK, RTCP reports, congestion
/// control feedback for the remote (RFC 8888 or transport-wide, as negotiated), and key-frame
/// requests are as in [`register_default_interceptors`].
///
/// This is the explicit opt-out. RFC 8834 section 7 requires congestion control and the RTP
/// circuit breaker of a WebRTC endpoint: use this only when the application provides them
/// itself (its own interceptors, [`configure_congestion_control`] with its own estimator) or
/// when the traffic never leaves a network where they are not needed.
///
/// # Errors
///
/// As [`register_default_interceptors`].
pub fn register_default_interceptors_without_congestion_control(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
    let registry = configure_nack(registry, media_engine);

    configure_simulcast_extension_headers(media_engine)?;

    let feedback = CongestionFeedback::default();
    register_congestion_feedback(media_engine, feedback)?;
    let registry = with_congestion_feedback_recorders(registry, feedback);

    let registry = configure_rtcp_reports(registry);
    let registry = configure_extended_reports(registry);
    let registry = configure_tradeoff_notifications(registry);
    configure_receiver_reference_time(media_engine);

    let registry = configure_key_frame_requests(registry);

    // Last, so the ids of the extensions registered above stay what they were.
    configure_default_header_extensions(media_engine)?;

    Ok(registry)
}

/// Registers the header extensions every WebRTC endpoint is expected to offer, beside the
/// ones the interceptors above need:
///
/// - **MID** (`urn:ietf:params:rtp-hdrext:sdes:mid`) for audio as well as video: RFC 9143
///   section 15 has an endpoint that offers a BUNDLE group offer it in every bundled RTP
///   section, and RFC 9429 section 5.2.1 lists it among the extensions of any m= section.
///   The sender stamps it (`RTCRtpSender::write_rtp`), and a receiver finds the m= section of
///   an SSRC no description declared by it.
/// - **Client-to-mixer audio level** (`urn:ietf:params:rtp-hdrext:ssrc-audio-level`, RFC
///   6464) for audio: RFC 8834 section 5.2.2 ("RECOMMENDED"). The application writes the
///   level into the packets it sends; a receiver reports the level it reads as the audio
///   level of its synchronization sources.
/// - **Mixer-to-client audio level** (`urn:ietf:params:rtp-hdrext:csrc-audio-level`, RFC
///   6465) for audio, receive only: RFC 8834 section 5.2.3 makes it optional; an endpoint
///   that implements it and does not mix states `recvonly` (RFC 6465 section 5). A receiver
///   reports the levels as the audio level of its contributing sources.
/// - **Coordination of video orientation** (`urn:3gpp:video-orientation`) for video: the
///   application writes and reads it.
/// - **Dependency Descriptor** (the AV1 RTP specification, appendix A) for video: the layer
///   structure a forwarder that cannot parse the payload routes by (W3C webrtc-svc section 4,
///   SFrame). The application writes it (`rtp::codec::dependency_descriptor`).
///
/// The two audio level extensions are offered encrypted as well as in the clear (RFC 6904
/// section 4.1 best-effort encryption): RFC 8834 sections 5.2.2 and 5.2.3 require that an
/// implementation can encrypt them and RECOMMEND that it does. A peer that implements RFC
/// 6904 takes the encrypted form, one that does not (browsers) the clear one.
/// [`MediaEngine::set_header_extension_encryption`] with
/// [`RTCRtpHeaderExtensionEncryption::Clear`] offers them in the clear only.
///
/// Part of [`register_default_interceptors`].
///
/// # Errors
///
/// Returns an error if a header extension cannot be registered (no free id).
pub fn configure_default_header_extensions(media_engine: &mut MediaEngine) -> Result<()> {
    for (uri, kind, direction) in [
        (::sdp::extmap::SDES_MID_URI, RtpCodecKind::Audio, None),
        (::sdp::extmap::AUDIO_LEVEL_URI, RtpCodecKind::Audio, None),
        (
            rtp::extension::CSRC_AUDIO_LEVEL_URI,
            RtpCodecKind::Audio,
            Some(RTCRtpTransceiverDirection::Recvonly),
        ),
        (
            ::sdp::extmap::VIDEO_ORIENTATION_URI,
            RtpCodecKind::Video,
            None,
        ),
        // The AV1 RTP specification's Dependency Descriptor (appendix A): what a forwarder
        // that cannot read the payload (SFrame, W3C webrtc-svc section 4) routes layers by.
        (
            ::rtp::codec::dependency_descriptor::DEPENDENCY_DESCRIPTOR_URI,
            RtpCodecKind::Video,
            None,
        ),
    ] {
        media_engine.register_header_extension(
            RTCRtpHeaderExtensionCapability {
                uri: uri.to_owned(),
            },
            kind,
            direction,
        )?;
    }
    for uri in [
        ::sdp::extmap::AUDIO_LEVEL_URI,
        rtp::extension::CSRC_AUDIO_LEVEL_URI,
    ] {
        media_engine
            .set_header_extension_encryption(uri, RTCRtpHeaderExtensionEncryption::BestEffort)?;
    }
    Ok(())
}

/// The receive-side variant of congestion control (draft-ietf-rmcat-gcc-02 section 3): a
/// REMB for every remote stream that negotiated `goog-remb` and neither transport-wide
/// congestion control nor RFC 8888, so a sender that only understands REMB still hears what
/// the path carries; and the abs-send-time header extension stamped on the packets of every
/// local stream that negotiated it, as they leave the pacer. Part of
/// [`register_default_interceptors`], which also registers abs-send-time on video
/// ([`configure_abs_send_time`]).
pub fn configure_remb(registry: Registry) -> Registry {
    registry
        .with(
            Slot::Custom(interceptor::REMB_GENERATOR_SLOT),
            interceptor::RembGeneratorBuilder::new().build(),
        )
        .with(
            Slot::Custom(interceptor::ABS_SEND_TIME_SLOT),
            interceptor::AbsSendTimeInterceptor::new(),
        )
}

/// Registers the abs-send-time header extension
/// (`http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time`) on video, so that it is
/// offered beside transport-wide congestion control and `ack ccfb`, and answered when a peer
/// offers it: a peer that runs neither (REMB with abs-send-time, the receive-side variant of
/// draft-ietf-rmcat-gcc-02 section 3) gets its send times, stamped by the
/// [`configure_remb`] interceptor, and REMB from this side. Part of
/// [`register_default_interceptors`]; registered after the other extensions, so their ids
/// stay as they were.
pub fn configure_abs_send_time(media_engine: &mut MediaEngine) -> Result<()> {
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::ABS_SEND_TIME_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;
    Ok(())
}

/// Offers TMMBR for audio and video: `a=rtcp-fb:<pt> ccm tmmbr` (RFC 5104 section 7.1).
///
/// A WebRTC endpoint that sends media implements TMMBR (RFC 8834 section 5.1.6): the
/// congestion controller keeps its target under the limit a TMMBR sets and answers with a
/// TMMBN. It does so for the streams that negotiated the message, which is what this
/// registers; a peer that does not answer `ccm tmmbr` (browsers do not) negotiates without it.
/// Part of [`register_default_interceptors`].
pub fn configure_tmmbr(media_engine: &mut MediaEngine) {
    for kind in [RtpCodecKind::Video, RtpCodecKind::Audio] {
        media_engine.register_feedback(
            RTCPFeedback {
                typ: TYPE_RTCP_FB_CCM.to_owned(),
                parameter: "tmmbr".to_owned(),
            },
            kind,
        );
    }
}

/// Registers what `feedback` needs negotiated, on audio and video codecs.
fn register_congestion_feedback(
    media_engine: &mut MediaEngine,
    feedback: CongestionFeedback,
) -> Result<()> {
    for kind in [RtpCodecKind::Video, RtpCodecKind::Audio] {
        if feedback.offers_twcc() {
            media_engine.register_feedback(
                RTCPFeedback {
                    typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
                    parameter: "".to_owned(),
                },
                kind,
            );
            media_engine.register_header_extension(
                RTCRtpHeaderExtensionCapability {
                    uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
                },
                kind,
                None,
            )?;
        }
        if feedback.offers_rfc8888() {
            // `a=rtcp-fb:<pt> ack ccfb` (RFC 8888 section 6). No header extension: RFC 8888
            // reports against the RTP sequence number, which is in every packet already.
            register_ccfb_feedback(media_engine, kind);
        }
    }
    Ok(())
}

/// What numbers this endpoint's packets for the feedback about them. Only transport-wide
/// congestion control needs anything: RFC 8888 reports against the RTP sequence number.
///
/// `per_transport`: a numbering per transport (an RTP session each, RFC 8834 section 4.4),
/// for a congestion controller that runs per transport too.
fn with_congestion_feedback_senders(
    registry: Registry,
    feedback: CongestionFeedback,
    per_transport: bool,
) -> Registry {
    match (feedback.offers_twcc(), per_transport) {
        (false, _) => registry,
        (true, false) => registry.with(Slot::TwccSender, TwccSenderBuilder::new().build()),
        (true, true) => registry.with_per_rtp_session(
            Slot::TwccSender,
            PerRtpSession::new(|| TwccSenderBuilder::new().build()),
        ),
    }
}

/// What records the remote's packets and reports them. With both formats on offer both
/// recorders are in the chain, and each stream is reported by exactly one of them: the one
/// [`negotiated_congestion_feedback`](interceptor::negotiated_congestion_feedback) names.
fn with_congestion_feedback_recorders(
    registry: Registry,
    feedback: CongestionFeedback,
) -> Registry {
    // Each transport's arrivals are reported on that transport (the remote numbers each
    // transport on its own).
    let registry = if feedback.offers_twcc() {
        registry.with_per_rtp_session(
            Slot::TwccReceiver,
            PerRtpSession::new(|| TwccReceiverBuilder::new().build()),
        )
    } else {
        registry
    };
    if feedback.offers_rfc8888() {
        registry.with_per_rtp_session(
            Slot::Rfc8888,
            PerRtpSession::new(|| Rfc8888Builder::new().build()),
        )
    } else {
        registry
    }
}

/// Installs the RTP circuit breaker (RFC 8083) at [`Slot::CircuitBreaker`] with the RFC's
/// recommended parameters, and returns the handle that reports what it stopped.
///
/// It needs nothing negotiated: it reads the report blocks of the RTCP sender and receiver
/// reports every RTP endpoint sends. A flow it stops is restarted only by the application,
/// through the handle.
pub fn configure_circuit_breaker(registry: Registry) -> (Registry, CircuitBreakerHandle) {
    let (breaker, handle) = CircuitBreakerBuilder::new().build();
    (registry.with(Slot::CircuitBreaker, breaker), handle)
}

/// Delivers inbound key-frame requests (RTCP PLI and FIR) to the application.
///
/// The chain's terminus ends every inbound RTCP packet no interceptor vouches for, and no
/// interceptor can answer a key-frame request: only the encoder can, and the encoder is the
/// application. This registers [`KeyFrameRequestInterceptor`] at
/// [`Slot::KeyFrameRequests`], which marks them for delivery, so the application reads them as
/// `RTCMessage::RtcpPacket` and can send a key frame. Part of
/// [`register_default_interceptors`] (a fork addition: upstream swallows them).
///
/// # Examples
///
/// ```
/// use rtc::interceptor::Registry;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_key_frame_requests;
///
/// let registry = configure_key_frame_requests(Registry::new());
/// ```
pub fn configure_key_frame_requests(registry: Registry) -> Registry {
    registry.with(Slot::KeyFrameRequests, KeyFrameRequestInterceptor::new())
}

/// Configures NACK (Negative Acknowledgement) interceptors for packet loss recovery.
///
/// This function registers the following:
/// - **NACK Generator**: Monitors incoming RTP packets and generates NACK requests for missing packets
/// - **NACK Responder**: Buffers outgoing RTP packets and retransmits them when NACK requests arrive
/// - **RTCP Feedback**: Registers "nack" and "nack pli" feedback types for video codecs
///
/// # How NACK Works
///
/// 1. Receiver detects missing packets by tracking sequence numbers
/// 2. Receiver sends RTCP NACK listing missing sequence numbers
/// 3. Sender retransmits the requested packets from its buffer
///
/// # Parameters
///
/// * `registry` - The interceptor registry to configure
/// * `media_engine` - The media engine to register NACK feedback capability
///
/// # Examples
///
/// ```
/// use rtc::interceptor::Registry;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_nack;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = configure_nack(registry, &mut media_engine);
/// ```
///
/// # References
///
/// - [RFC 4585](https://datatracker.ietf.org/doc/html/rfc4585) - Extended RTP Profile for RTCP-Based Feedback
pub fn configure_nack(registry: Registry, media_engine: &mut MediaEngine) -> Registry {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_NACK.to_owned(),
            parameter: "".to_owned(),
        },
        RtpCodecKind::Video,
    );
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_NACK.to_owned(),
            parameter: "pli".to_owned(),
        },
        RtpCodecKind::Video,
    );

    registry
        .with(Slot::NackResponder, NackResponderBuilder::new().build())
        .with(Slot::NackGenerator, NackGeneratorBuilder::new().build())
}

/// Configures RTCP: the RTCP session of the connection.
///
/// Registers [`RtcpSessionInterceptor`](interceptor::RtcpSessionInterceptor) at
/// [`Slot::RtcpSession`], closest to the wire. It is the connection's whole RTCP voice:
///
/// - **Sender reports (SR)** for every SSRC that sent RTP in the last two report intervals
///   (RTX and FEC SSRCs included): NTP and RTP timestamps, packet and octet counts.
/// - **Receiver reports (RR)** otherwise, and reception report blocks for every remote stream:
///   fraction lost, cumulative loss, extended highest sequence number, interarrival jitter,
///   last SR and the delay since (RFC 3550 6.4, Appendix A.3).
/// - **One CNAME** (RFC 7022) in an SDES for every reporting SSRC, and a BYE for an SSRC that
///   stops and for all of them when the connection closes.
/// - **`T_rr_interval` of zero**, the RFC 4585 section 4.2 default when no `trr-int` is
///   signalled: see [`configure_rtcp_reports_with`] for the browsers' one second.
/// - **Timing** by RFC 3550 6.3 (interval from the member count, the average packet size and
///   the RTCP bandwidth, randomised, with timer reconsideration) and the RTP/AVPF rules of
///   RFC 4585 3.5: feedback the other interceptors and the application write (NACK, PLI, FIR,
///   TWCC, REMB, ...) leaves as early RTCP inside the same bandwidth, in compound packets
///   (reduced-size only when negotiated), from this connection's SSRC.
///
/// The peer connection starts the session when DTLS is up and gives it the connection's
/// CNAME. What a session description negotiates beyond that reaches it as an
/// [`RtcpSessionControl`](interceptor::RtcpSessionControl) (bandwidth from `b=` lines,
/// `a=rtcp-rsize`, `trr-int`) or through
/// [`RtcpSessionBuilder`](interceptor::RtcpSessionBuilder) when the chain is built by hand:
///
/// ```
/// use rtc::interceptor::{Registry, RtcpBandwidth, RtcpSessionBuilder, Slot};
/// use std::time::Duration;
///
/// let registry = Registry::new().with(
///     Slot::RtcpSession,
///     RtcpSessionBuilder::new()
///         .with_bandwidth(RtcpBandwidth {
///             session: Some(1_500_000),
///             ..Default::default()
///         })
///         .with_t_rr_interval(Duration::from_millis(500))
///         .build(),
/// );
/// ```
///
/// # Parameters
///
/// * `registry` - The interceptor registry to configure
///
/// # Examples
///
/// ```
/// use rtc::interceptor::Registry;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_rtcp_reports;
///
/// let registry = Registry::new();
/// let registry = configure_rtcp_reports(registry);
/// ```
///
/// # References
///
/// - [RFC 3550 Section 6](https://datatracker.ietf.org/doc/html/rfc3550#section-6) - RTCP
/// - [RFC 4585 Section 3](https://datatracker.ietf.org/doc/html/rfc4585#section-3) - RTP/AVPF timing
/// - [RFC 8108](https://datatracker.ietf.org/doc/html/rfc8108) - several SSRCs in one session
pub fn configure_rtcp_reports(registry: Registry) -> Registry {
    configure_rtcp_reports_with(
        registry,
        RtcpSessionBuilder::new().with_t_rr_interval(Duration::ZERO),
    )
}

/// [`configure_rtcp_reports`] with the RTCP session built from `session`, for the settings a
/// session description does not carry.
///
/// The one [`configure_rtcp_reports`] itself sets is `T_rr_interval`, the minimum interval
/// between regular RTCP packets under RTP/AVPF: zero, as RFC 4585 section 4.2 has it when
/// `trr-int` is not signalled ("If trr-int is not specified, a default of 0 is assumed"), so
/// regular reports are spaced by the RTCP bandwidth alone (RFC 3550 section 6.2: 5% of the
/// session bandwidth). Browsers space them about a second apart whatever the bandwidth; that
/// is `RtcpSessionBuilder::new()` as it comes
/// ([`RTCP_SESSION_DEFAULT_T_RR_INTERVAL`](interceptor::RTCP_SESSION_DEFAULT_T_RR_INTERVAL)):
///
/// ```
/// use rtc::interceptor::{Registry, RtcpSessionBuilder};
/// use rtc::peer_connection::configuration::interceptor_registry::configure_rtcp_reports_with;
///
/// // Regular reports at most once a second, as browsers send them.
/// let registry = configure_rtcp_reports_with(Registry::new(), RtcpSessionBuilder::new());
/// ```
///
/// A `trr-int` this endpoint announces in its description replaces either value when the
/// answer is applied.
pub fn configure_rtcp_reports_with(registry: Registry, session: RtcpSessionBuilder) -> Registry {
    // An RTCP session per RTP session: one per transport when sections are not bundled
    // (RFC 3550 section 6, RFC 8834 section 4.4).
    registry.with_per_rtp_session(Slot::RtcpSession, session.build_per_rtp_session())
}

/// Adds the RTCP XR report blocks a receiver writes about each source (RFC 3611 section 4:
/// Loss RLE, Duplicate RLE, Packet Receipt Times, Statistics Summary, VoIP Metrics) for the
/// remote streams that negotiated them with `a=rtcp-xr` (section 5.1). A stream that did not
/// gets none. Part of [`register_default_interceptors`].
///
/// ```
/// use rtc::interceptor::Registry;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_extended_reports;
///
/// let registry = configure_extended_reports(Registry::new());
/// # let _ = registry;
/// ```
pub fn configure_extended_reports(registry: Registry) -> Registry {
    registry.with(Slot::ExtendedReports, XrReportBuilder::new().build())
}

/// Adds the temporal-spatial trade-off notifications (RFC 5104 section 4.3.3): a local media
/// sender whose stream negotiated `ccm tstr` answers each request it receives with a TSTN
/// carrying the index it will use. The request itself still reaches the application, which
/// owns the encoder. Part of [`register_default_interceptors`].
pub fn configure_tradeoff_notifications(registry: Registry) -> Registry {
    registry.with(
        Slot::TradeoffNotifications,
        TstnResponderBuilder::new().build(),
    )
}

/// Adds RTP stream pause and resume (RFC 7728) and offers it for audio and video:
/// `a=rtcp-fb:<pt> ccm pause` (section 9; the full implementation, `config=1`, without
/// `nowait`). Returns the handle through which the application asks a remote stream to pause
/// or resume, pauses its own streams by local decision and reads where each stream is.
///
/// The interceptor sits at [`Slot::PauseResume`] and acts for the streams whose section
/// negotiated `ccm pause`; answers follow section 9.1 (the complementary `config`, `nowait`
/// only when offered). Not part of [`register_default_interceptors`]: no browser implements it.
///
/// # Examples
///
/// ```
/// use rtc::interceptor::Registry;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_pause_resume;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// let mut media_engine = MediaEngine::default();
/// let (registry, handle) = configure_pause_resume(Registry::new(), &mut media_engine);
/// assert_eq!(handle.state(0x1234), None);
/// # let _ = registry;
/// ```
pub fn configure_pause_resume(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> (Registry, interceptor::PauseResumeHandle) {
    configure_pause_resume_with(
        registry,
        media_engine,
        interceptor::PauseResumeBuilder::new(),
        false,
    )
}

/// [`configure_pause_resume`] with the interceptor's parameters and, with `nowait`, the
/// `nowait` attribute in offers (RFC 7728 section 9.1: "If the offerer believes that itself
/// and the intended answerer are likely the only endpoints in the RTP session").
pub fn configure_pause_resume_with(
    registry: Registry,
    media_engine: &mut MediaEngine,
    builder: interceptor::PauseResumeBuilder,
    nowait: bool,
) -> (Registry, interceptor::PauseResumeHandle) {
    let parameter = interceptor::PauseCapability { nowait, config: 1 }.parameter();
    for kind in [RtpCodecKind::Video, RtpCodecKind::Audio] {
        media_engine.register_feedback(
            RTCPFeedback {
                typ: TYPE_RTCP_FB_CCM.to_owned(),
                parameter: parameter.clone(),
            },
            kind,
        );
    }
    let (pause_resume, handle) = builder.build();
    (registry.with(Slot::PauseResume, pause_resume), handle)
}

/// Negotiates receiver-side round trip time measurement for video (`a=rtcp-fb:<pt> rrtr`,
/// libwebrtc's feedback name for RTCP XR receiver reference times, RFC 3611 section 4.4).
///
/// With it negotiated, the receiver report interceptor ([`configure_rtcp_reports`]) sends a
/// receiver reference time block with each receiver report of a video stream; the remote sender
/// answers with a DLRR block (section 4.5), and the stream's `remote-outbound-rtp` stats report
/// `roundTripTime`, `totalRoundTripTime` and `roundTripTimeMeasurements`. The sender report
/// interceptor answers reference times whether or not this is negotiated, as libwebrtc does.
/// Part of [`register_default_interceptors`].
///
/// # Examples
///
/// ```
/// use rtc::peer_connection::configuration::interceptor_registry::configure_receiver_reference_time;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// let mut media_engine = MediaEngine::default();
/// configure_receiver_reference_time(&mut media_engine);
/// ```
pub fn configure_receiver_reference_time(media_engine: &mut MediaEngine) {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: interceptor::RTCP_FB_RRTR.to_owned(),
            parameter: "".to_owned(),
        },
        RtpCodecKind::Video,
    );
}

/// Registers RTP header extensions required for simulcast streaming.
///
/// Simulcast allows sending multiple resolutions/qualities of the same video
/// simultaneously. This function registers the following header extensions:
///
/// - **SDES MID** (`urn:ietf:params:rtp-hdrext:sdes:mid`): Media identification
/// - **SDES RtpStreamId** (`urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id`): Stream identification
/// - **SDES RepairedRtpStreamId** (`urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id`): Repair stream identification
///
/// # Parameters
///
/// * `media_engine` - The media engine to register header extensions
///
/// # Errors
///
/// Returns an error if header extension registration fails.
///
/// # Examples
///
/// ```
/// use rtc::peer_connection::configuration::interceptor_registry::configure_simulcast_extension_headers;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// configure_simulcast_extension_headers(&mut media_engine)?;
/// # Ok(())
/// # }
/// ```
///
/// # References
///
/// - [RFC 8852](https://datatracker.ietf.org/doc/html/rfc8852) - RTP Stream Identifier Source Description Extensions
pub fn configure_simulcast_extension_headers(media_engine: &mut MediaEngine) -> Result<()> {
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: ::sdp::extmap::SDES_MID_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: ::sdp::extmap::SDES_RTP_STREAM_ID_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: ::sdp::extmap::SDES_REPAIR_RTP_STREAM_ID_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    Ok(())
}

/// Configures full TWCC (Transport-Wide Congestion Control) for bandwidth estimation.
///
/// This function enables both sending and receiving TWCC feedback:
/// - **TWCC Sender**: Adds transport-wide sequence numbers to outgoing RTP packets
/// - **TWCC Receiver**: Generates TransportLayerCC RTCP feedback for incoming packets
///
/// # How TWCC Works
///
/// 1. Sender adds a transport-wide sequence number to each RTP packet
/// 2. Receiver records arrival time of each packet by sequence number
/// 3. Receiver periodically sends TransportLayerCC RTCP packets with timing info
/// 4. Sender uses feedback to estimate available bandwidth
///
/// # When to Use
///
/// Use full TWCC when you need bandwidth estimation in both directions,
/// such as in a two-way video call where both peers send media.
///
/// # Parameters
///
/// * `registry` - The interceptor registry to configure
/// * `media_engine` - The media engine to register feedback and header extensions
///
/// # Errors
///
/// Returns an error if header extension registration fails.
///
/// # Examples
///
/// ```
/// use rtc::interceptor::Registry;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_twcc;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = configure_twcc(registry, &mut media_engine)?;
/// # Ok(())
/// # }
/// ```
///
/// # References
///
/// - [draft-holmer-rmcat-transport-wide-cc](https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01)
pub fn configure_twcc(registry: Registry, media_engine: &mut MediaEngine) -> Result<Registry> {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            ..Default::default()
        },
        RtpCodecKind::Video,
    );
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            ..Default::default()
        },
        RtpCodecKind::Audio,
    );
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Audio,
        None,
    )?;

    Ok(registry
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .with(Slot::TwccReceiver, TwccReceiverBuilder::new().build()))
}

/// Configures TWCC sender only (the remote peer generates feedback).
///
/// This function enables only the TWCC sender interceptor, which adds
/// transport-wide sequence numbers to outgoing RTP packets. The remote
/// peer is expected to generate and send TransportLayerCC feedback.
///
/// # When to Use
///
/// Use sender-only TWCC when:
/// - You are sending media but not receiving (e.g., streaming/broadcasting)
/// - The remote peer handles feedback generation
/// - You want to minimize local processing overhead
///
/// # Parameters
///
/// * `registry` - The interceptor registry to configure
/// * `media_engine` - The media engine to register feedback and header extensions
///
/// # Errors
///
/// Returns an error if header extension registration fails.
///
/// # Examples
///
/// ```
/// use rtc::interceptor::Registry;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_twcc_sender_only;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = configure_twcc_sender_only(registry, &mut media_engine)?;
/// # Ok(())
/// # }
/// ```
pub fn configure_twcc_sender_only(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            parameter: "".to_owned(),
        },
        RtpCodecKind::Video,
    );

    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            parameter: "".to_owned(),
        },
        RtpCodecKind::Audio,
    );

    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Audio,
        None,
    )?;

    Ok(registry.with(Slot::TwccSender, TwccSenderBuilder::new().build()))
}

/// Configures TWCC receiver only (generates feedback for the remote sender).
///
/// This function enables only the TWCC receiver interceptor, which:
/// - Tracks arrival times of incoming RTP packets with TWCC sequence numbers
/// - Generates TransportLayerCC RTCP feedback packets periodically
/// - Sends feedback to the remote sender for bandwidth estimation
///
/// This is the default TWCC configuration used by [`register_default_interceptors`].
///
/// # When to Use
///
/// Use receiver-only TWCC when:
/// - You are receiving media but not sending (e.g., viewer in a broadcast)
/// - The remote peer adds TWCC sequence numbers and needs feedback
/// - You want to help the sender estimate available bandwidth
///
/// # Parameters
///
/// * `registry` - The interceptor registry to configure
/// * `media_engine` - The media engine to register feedback and header extensions
///
/// # Errors
///
/// Returns an error if header extension registration fails.
///
/// # Examples
///
/// ```
/// use rtc::interceptor::Registry;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_twcc_receiver_only;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = configure_twcc_receiver_only(registry, &mut media_engine)?;
/// # Ok(())
/// # }
/// ```
pub fn configure_twcc_receiver_only(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            ..Default::default()
        },
        RtpCodecKind::Video,
    );
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            ..Default::default()
        },
        RtpCodecKind::Audio,
    );
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Audio,
        None,
    )?;

    Ok(registry.with(Slot::TwccReceiver, TwccReceiverBuilder::new().build()))
}

/// `a=rtcp-fb:<pt> ack ccfb` (RFC 8888 section 5) on every codec of `kind`.
fn register_ccfb_feedback(media_engine: &mut MediaEngine, kind: RtpCodecKind) {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_ACK.to_owned(),
            parameter: RTCP_FB_ACK_CCFB.to_owned(),
        },
        kind,
    );
}

/// Negotiates RFC 8888 congestion control feedback and reports arrivals with it, without a
/// congestion controller.
///
/// Registers `a=rtcp-fb:<pt> ack ccfb` (RFC 8888 section 5) on audio and video codecs and the
/// RFC 8888 recorder in [`Slot::Rfc8888`], which reports every received packet of a stream that
/// negotiated it, with the ECN codepoint it arrived with, about every 100 ms. What the reports
/// say becomes statistics on both sides: the receiver's `inbound-rtp`
/// `packetsReportedAsLost` / `packetsReportedAsLostButRecovered`, the sender's
/// `remote-inbound-rtp` `packetsReceivedWithEct1`, `packetsReceivedWithCe`,
/// `packetsReportedAsLost`, `packetsReportedAsLostButRecovered` and
/// `packetsWithBleachedEct1Marking`. With ECN on
/// ([`SettingEngineBuilder::with_ecn`](crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::with_ecn)),
/// a stream that negotiated it is sent ECT(1) (L4S).
///
/// [`register_default_interceptors`] does this already, beside transport-wide congestion
/// control; this helper is for a chain built piece by piece. A peer that does not offer or
/// accept `ack ccfb` negotiates without it, and nothing changes for that stream. A stream that
/// did negotiate it is reported here and not by the TWCC receiver. Use
/// [`configure_congestion_control`] to also run a congestion controller on the reports.
///
/// # Examples
///
/// ```
/// use rtc::interceptor::Registry;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_congestion_control_feedback;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// let mut media_engine = MediaEngine::default();
/// let registry = configure_congestion_control_feedback(Registry::new(), &mut media_engine);
/// ```
pub fn configure_congestion_control_feedback(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Registry {
    for kind in [RtpCodecKind::Video, RtpCodecKind::Audio] {
        register_ccfb_feedback(media_engine, kind);
    }
    registry.with(Slot::Rfc8888, Rfc8888Builder::new().build())
}

/// Which congestion control feedback is offered, and so which the remote may report arrivals
/// with.
///
/// **A stream runs on one format, never both.** Both resolve into the same `PacketReport`s and
/// the estimator cannot tell them apart, so a stream reported in both would have every packet
/// counted twice and the estimate wrong by a factor of two in the direction that causes
/// congestion. Offering both is a different thing, and is what RFC 8888 section 6 expects:
/// "an SDP offer might indicate support for both the congestion control feedback mechanism
/// specified in this memo and one or more alternative congestion control feedback mechanisms
/// that offer substantially the same semantics. In this case, the answering party SHOULD
/// include only one of the offered congestion control feedback mechanisms in its answer."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum CongestionFeedback {
    /// Both on offer, one in use per stream: RFC 8888 when the peer accepted `ack ccfb`,
    /// transport-wide congestion control otherwise (a browser answers `transport-cc` only).
    /// As an answerer this endpoint keeps `ack ccfb` and drops `transport-cc` when it was
    /// offered both. The default.
    #[default]
    Negotiated,
    /// Transport-wide congestion control only: `ack ccfb` is neither offered nor accepted.
    /// What browsers offer.
    Twcc,
    /// RFC 8888 congestion control feedback only. Carries ECN, which TWCC cannot. A peer
    /// that does not accept `ack ccfb` then sends no per-packet feedback at all.
    Rfc8888,
}

impl CongestionFeedback {
    fn offers_twcc(self) -> bool {
        matches!(self, Self::Negotiated | Self::Twcc)
    }

    fn offers_rfc8888(self) -> bool {
        matches!(self, Self::Negotiated | Self::Rfc8888)
    }
}

/// Configure send-side congestion control around `estimator`.
///
/// Places interceptors at the slots the chain contract reserves for them:
///
/// | Slot | Interceptor | Why there |
/// |---|---|---|
/// | [`Slot::CongestionControl`] | send history and feedback ingest | the only position that sees every byte that leaves |
/// | [`Slot::TwccSender`] | transport-wide sequence numbers (not with [`CongestionFeedback::Rfc8888`]) | so the history keys on a number that already exists |
/// | [`REMOTE_BITRATE_LIMIT_SLOT`] | bounds the estimate by the remote description's `b=TIAS` / `b=AS` | between the controller, which announces the estimate, and the pacer, which reads it |
/// | [`Slot::Pacer`] | paces departures | above the two, so `packet.now` is the release instant |
/// | [`Slot::TwccReceiver`] and / or [`Slot::Rfc8888`] | records arrivals, reports them to the remote | an arrival recorder, so it precedes the jitter buffer |
///
/// The first three are this endpoint's own control loop: number what leaves, ingest the feedback
/// that comes back, pace to the result. The recorder is the other half — it serves the *remote's*
/// estimator, and without it a symmetric pair of peers running this helper would both wait for
/// feedback neither ever sends.
///
/// The order is declared, not implied by the order these are added, so this composes with
/// [`configure_nack`] and the rest in any sequence.
///
/// [`register_default_interceptors`] installs the same thing around [`Gcc`], with the circuit
/// breaker; this is for another estimator, or a chain built piece by piece. A slot holds one
/// interceptor, so calling this after the default set replaces its estimator and pacer.
///
/// # Examples
///
/// ```
/// use rtc::interceptor::Gcc;
/// use rtc::peer_connection::configuration::interceptor_registry::{
///     CongestionFeedback, Registry, configure_congestion_control,
/// };
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let registry = configure_congestion_control(
///     Registry::new(),
///     Gcc::default(),
///     CongestionFeedback::Twcc,
///     &mut media_engine,
/// )?;
/// let registry = registry.build();
/// # Ok(())
/// # }
/// ```
/// # Errors
///
/// Returns an error if the TWCC header extension cannot be registered on the media engine.
pub fn configure_congestion_control<E: BandwidthEstimator + 'static>(
    registry: Registry,
    estimator: E,
    feedback: CongestionFeedback,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
    // The remote needs to know how to report. RFC 8888 needs no header extension — it reports
    // against the RTP sequence number — so only TWCC registers one. Without `ack ccfb` in the
    // description the remote has no reason to send RFC 8888 reports, and an estimator that
    // never receives feedback holds its initial rate for the life of the connection.
    register_congestion_feedback(media_engine, feedback)?;

    // The pacer starts at the estimator's own starting rate. Left at its default it would
    // release at 1 Mbit/s until the first feedback moved the estimate, whatever the estimator
    // said it wanted to start at.
    let initial_target = estimator.target_bitrate();
    let registry = registry
        .with(
            Slot::CongestionControl,
            CongestionControlBuilder::new(estimator).build(),
        )
        // The remote description's `b=TIAS` / `b=AS` bounds the estimate on its way to the
        // pacer (RFC 9429 section 5.10).
        .with(
            Slot::Custom(REMOTE_BITRATE_LIMIT_SLOT),
            RemoteBitrateLimitInterceptor::new(initial_target),
        )
        .with(
            Slot::Pacer,
            PacerBuilder::new()
                .with_target_bitrate(initial_target)
                .build(),
        );

    // The sequence numbers the send history keys on (TWCC only), and the other half of the
    // loop: what this endpoint reports about what it *receives*, so the remote's estimator has
    // something to work with. A stream is reported by one recorder, never both.
    // One estimator for the connection (`estimator` is one instance), so one numbering.
    let registry = with_congestion_feedback_senders(registry, feedback, false);
    Ok(with_congestion_feedback_recorders(registry, feedback))
}

/// Creates a [`StreamInfo`](interceptor::StreamInfo) from RTC types for interceptor binding.
///
/// This helper converts RTC codec and header extension information into the format
/// expected by the interceptor layer when binding local or remote streams.
#[allow(clippy::too_many_arguments)]
pub(crate) fn create_stream_info(
    ssrc: SSRC,
    ssrc_rtx: Option<SSRC>,
    ssrc_fec: Option<SSRC>,
    payload_type: PayloadType,
    payload_type_rtx: Option<PayloadType>,
    fec_format: Option<&crate::rtp_transceiver::rtp_sender::rtp_codec::FecFormat>,
    codec: &RTCRtpCodec,
    header_extensions: &[RTCRtpHeaderExtensionParameters],
    section_codecs: &[RTCRtpCodecParameters],
) -> interceptor::StreamInfo {
    let rtp_header_extensions: Vec<interceptor::RTPHeaderExtension> = header_extensions
        .iter()
        .map(|h| interceptor::RTPHeaderExtension {
            id: h.id,
            uri: h.uri.clone(),
        })
        .collect();

    let feedbacks: Vec<_> = codec
        .rtcp_feedback
        .iter()
        .map(|f| interceptor::RTCPFeedback {
            typ: f.typ.clone(),
            parameter: f.parameter.clone(),
        })
        .collect();

    interceptor::StreamInfo {
        ssrc,
        ssrc_rtx,
        ssrc_fec,
        payload_type,
        payload_type_rtx,
        payload_type_fec: fec_format.map(|format| format.payload_type),
        rtp_header_extensions,
        mime_type: codec.mime_type.clone(),
        clock_rate: codec.clock_rate,
        channels: codec.channels,
        sdp_fmtp_line: codec.sdp_fmtp_line.clone(),
        rtcp_feedback: feedbacks,
        // Which FEC coder the repair flow needs, and its parameters (`repair-window`).
        mime_type_fec: fec_format
            .map(|format| format.mime_type.clone())
            .unwrap_or_default(),
        sdp_fmtp_line_fec: fec_format
            .map(|format| format.sdp_fmtp_line.clone())
            .unwrap_or_default(),
        // RFC 7160 section 4.3 (RFC 8834 section 4.3): the other media formats of the m=
        // section and their clock rates, for a source that switches between them on one SSRC.
        // Repair formats are left out: RTX is de-encapsulated to the media format before the
        // chain, and FEC has an SSRC of its own.
        payload_clock_rates: section_codecs
            .iter()
            .filter(|c| {
                c.payload_type != payload_type
                    && !crate::peer_connection::handler::endpoint::is_repair_mime_type(
                        &c.rtp_codec.mime_type,
                    )
            })
            .map(|c| (c.payload_type, c.rtp_codec.clock_rate))
            .collect(),
    }
}

/// Adds ULPFEC (RFC 5109) carried in RED (RFC 2198) for video (`a=rtpmap:<red> red/90000`,
/// `a=rtpmap:<ulpfec> ulpfec/90000`), in both directions, with the FEC placed as RFC 5109
/// section 14.2 has it: in the same packets as the media it protects.
///
/// Every video stream bound to the chain is then sent as RED packets, FEC data is produced
/// after each frame or five packets, whichever comes first, and travels as a redundant block
/// of the next media packet. Received RED is taken apart, lost packets rebuilt, and the media
/// delivered under its own payload type, whichever of the two placements the sender used. FEC
/// replaces FlexFEC at [`Slot::FecEncoder`] / [`Slot::FecDecoder`]: a chain runs one FEC scheme.
///
/// **Browsers need the other placement.** libwebrtc sends FEC in RED packets of its own and
/// drops a RED packet with more than one block, so towards Chrome, and for video with
/// full-size packets (a redundant block holds at most 1023 octets), use
/// [`configure_ulpfec_with_placement`] with
/// [`RedPlacement::OwnPacket`](interceptor::RedPlacement::OwnPacket).
///
/// `red_payload_type` and `ulpfec_payload_type` are the payload types **in use on the
/// connection**. Register `video/red` and [`MIME_TYPE_ULP_FEC`] on the [`MediaEngine`] with the
/// same numbers; the engine offers and answers them like any codec. When the remote side makes
/// the offer and numbers them differently, the negotiated numbers are the ones to pass here.
///
/// For other shapes (uneven protection levels, `onelevelonly`, a separate FEC stream) build
/// the interceptors with [`UlpfecSendBuilder`](interceptor::UlpfecSendBuilder) and
/// [`UlpfecReceiveBuilder`](interceptor::UlpfecReceiveBuilder).
///
/// [`MIME_TYPE_ULP_FEC`]: crate::peer_connection::configuration::media_engine::MIME_TYPE_ULP_FEC
pub fn configure_ulpfec(
    registry: Registry,
    red_payload_type: PayloadType,
    ulpfec_payload_type: PayloadType,
) -> Registry {
    configure_ulpfec_with_placement(
        registry,
        red_payload_type,
        ulpfec_payload_type,
        interceptor::RedPlacement::default(),
    )
}

/// [`configure_ulpfec`] with the placement of FEC data in the RED stream chosen:
/// [`RedPlacement::WithNextMedia`](interceptor::RedPlacement::WithNextMedia), the form of
/// RFC 5109 section 14.2 and the default, or
/// [`RedPlacement::OwnPacket`](interceptor::RedPlacement::OwnPacket), the form libwebrtc
/// sends and the only one it reads.
pub fn configure_ulpfec_with_placement(
    registry: Registry,
    red_payload_type: PayloadType,
    ulpfec_payload_type: PayloadType,
    placement: interceptor::RedPlacement,
) -> Registry {
    registry
        .with(
            Slot::FecEncoder,
            interceptor::UlpfecSendBuilder::red(red_payload_type, ulpfec_payload_type)
                .with_red_placement(placement)
                .with_flush_on_marker(true)
                .build(),
        )
        .with(
            Slot::FecDecoder,
            interceptor::UlpfecReceiveBuilder::red(red_payload_type, ulpfec_payload_type).build(),
        )
}

#[cfg(test)]
mod ulpfec_tests {
    use super::*;

    #[test]
    fn configure_ulpfec_fills_both_fec_slots() {
        let registry = configure_ulpfec(Registry::new(), 116, 117);
        let names: Vec<String> = registry.slots().into_iter().map(|(_, name)| name).collect();
        assert_eq!(
            vec![
                "UlpfecSendInterceptor".to_owned(),
                "UlpfecReceiveInterceptor".to_owned()
            ],
            names
        );
    }
}

#[cfg(test)]
mod slot_order_tests {
    use super::*;

    /// Just the positions, for the tests that are about ordering rather than identity.
    fn slots(registry: &Registry) -> Vec<Slot> {
        registry.slots().into_iter().map(|(slot, _)| slot).collect()
    }

    /// The hazard this type exists for: with append-only helpers, TWCC spans NACK and no call
    /// order produces the documented ordering. Here the two orders must be indistinguishable.
    #[test]
    fn helper_call_order_does_not_affect_the_chain() {
        let mut media_engine = MediaEngine::default();

        let nack_first = configure_twcc(
            configure_nack(Registry::new(), &mut media_engine),
            &mut media_engine,
        )
        .expect("twcc");

        let mut media_engine = MediaEngine::default();
        let twcc_first = configure_nack(
            configure_twcc(Registry::new(), &mut media_engine).expect("twcc"),
            &mut media_engine,
        );

        assert_eq!(slots(&nack_first), slots(&twcc_first));
    }

    /// Whatever a registry is asked for, it emits wire-to-application.
    #[test]
    fn the_default_chain_is_emitted_in_slot_order() {
        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)
            .expect("default interceptors");

        let slots = slots(&registry);
        assert!(
            slots.windows(2).all(|pair| pair[0] <= pair[1]),
            "default chain is not wire-to-application: {slots:?}"
        );
        assert_eq!(
            vec![
                Slot::RtcpSession,
                Slot::CongestionControl,
                Slot::Custom(interceptor::ABS_SEND_TIME_SLOT),
                Slot::TwccSender,
                Slot::Custom(REMOTE_BITRATE_LIMIT_SLOT),
                Slot::CircuitBreaker,
                Slot::Pacer,
                Slot::NackResponder,
                Slot::TwccReceiver,
                Slot::Rfc8888,
                Slot::Custom(interceptor::REMB_GENERATOR_SLOT),
                Slot::ExtendedReports,
                Slot::NackGenerator,
                Slot::KeyFrameRequests,
                Slot::TradeoffNotifications,
            ],
            slots
        );
    }

    /// The three slots congestion control occupies land wire-to-application, whatever order the
    /// helpers ran in. Getting this wrong means the send history records a packet *before* the
    /// TWCC sender has numbered it, and the estimator cannot match feedback to what it sent.
    #[test]
    fn congestion_control_occupies_its_three_slots_in_order() {
        use interceptor::Gcc;

        let mut media_engine = MediaEngine::default();
        // Deliberately after another helper, to show the order does not matter.
        let registry = configure_nack(Registry::new(), &mut media_engine);
        let registry = configure_congestion_control(
            registry,
            Gcc::default(),
            CongestionFeedback::Twcc,
            &mut media_engine,
        )
        .expect("congestion control");

        assert_eq!(
            vec![
                Slot::CongestionControl,
                Slot::TwccSender,
                // The remote description's send limit, between the estimate and the pacer.
                Slot::Custom(REMOTE_BITRATE_LIMIT_SLOT),
                Slot::Pacer,
                Slot::NackResponder,
                Slot::TwccReceiver,
                Slot::NackGenerator,
            ],
            slots(&registry)
        );
    }

    /// **D7.** RFC 8888 reports against the RTP sequence number, so it needs no TWCC sender — and
    /// must not get one. Two senders would number every packet twice and the estimator, which
    /// cannot tell the formats apart, would count every packet twice with it.
    #[test]
    fn rfc8888_does_not_also_install_the_twcc_sender() {
        use interceptor::Gcc;

        let mut media_engine = MediaEngine::default();
        let registry = configure_congestion_control(
            Registry::new(),
            Gcc::default(),
            CongestionFeedback::Rfc8888,
            &mut media_engine,
        )
        .expect("congestion control");

        assert_eq!(
            vec![
                Slot::CongestionControl,
                Slot::Custom(REMOTE_BITRATE_LIMIT_SLOT),
                Slot::Pacer,
                Slot::Rfc8888
            ],
            slots(&registry),
            "RFC 8888 needs no transport-wide sequence numbers"
        );
    }

    /// RFC 8834 section 7: a WebRTC endpoint adapts its RTP traffic to the path and implements
    /// the RTP circuit breaker (section 7.1), so the standard set carries an estimator, the
    /// pacer that enforces its target, and the breaker.
    #[test]
    fn the_default_chain_has_congestion_control_and_a_circuit_breaker() {
        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)
            .expect("default interceptors");

        let named: Vec<(Slot, String)> = registry.slots();
        for (slot, name) in [
            (Slot::CongestionControl, "CongestionControlInterceptor<Gcc>"),
            (Slot::TwccSender, "TwccSenderInterceptor"),
            (Slot::CircuitBreaker, "CircuitBreakerInterceptor"),
            (Slot::Pacer, "PacerInterceptor"),
        ] {
            assert!(
                named.contains(&(slot, name.to_owned())),
                "{name} is missing from the default chain: {named:?}"
            );
        }
    }

    /// The opt-out is explicit, and is the set without the four congestion-control slots.
    #[test]
    fn the_opt_out_chain_has_no_congestion_control() {
        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors_without_congestion_control(
            Registry::new(),
            &mut media_engine,
        )
        .expect("interceptors");

        assert_eq!(
            vec![
                Slot::RtcpSession,
                Slot::NackResponder,
                Slot::TwccReceiver,
                Slot::Rfc8888,
                Slot::ExtendedReports,
                Slot::NackGenerator,
                Slot::KeyFrameRequests,
                Slot::TradeoffNotifications,
            ],
            slots(&registry)
        );
    }

    /// A bare number puts an interceptor between two named slots — the reason they are spaced.
    #[test]
    fn a_custom_interceptor_fits_between_named_slots() {
        let mut media_engine = MediaEngine::default();
        let registry = configure_twcc(Registry::new(), &mut media_engine)
            .expect("twcc")
            .with(Slot::from(2_500), interceptor::NoopInterceptor::new());

        assert_eq!(
            vec![Slot::TwccSender, Slot::from(2_500), Slot::TwccReceiver],
            slots(&registry)
        );
    }

    /// A slot holds one interceptor, so a helper cannot quietly end up with two of anything by
    /// being called twice — the position is the identity.
    #[test]
    fn a_slot_holds_one_interceptor() {
        let registry = Registry::new()
            .with(Slot::Pacer, interceptor::NoopInterceptor::new())
            .with(Slot::Pacer, interceptor::NoopInterceptor::new());

        assert_eq!(vec![Slot::Pacer], slots(&registry));
    }

    /// What the default chain is actually made of, by name. The ordering tests above prove the
    /// positions are right; this proves the right interceptors are in them — a chain assembled from
    /// several helpers has no other single view of what it ended up containing.
    #[test]
    fn the_default_chain_names_what_it_registered() {
        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)
            .expect("default interceptors");

        assert_eq!(
            vec![
                (Slot::RtcpSession, "RtcpSessionInterceptor".to_owned()),
                (
                    Slot::CongestionControl,
                    "CongestionControlInterceptor<Gcc>".to_owned()
                ),
                (
                    Slot::Custom(interceptor::ABS_SEND_TIME_SLOT),
                    "AbsSendTimeInterceptor".to_owned()
                ),
                (Slot::TwccSender, "TwccSenderInterceptor".to_owned()),
                (
                    Slot::Custom(REMOTE_BITRATE_LIMIT_SLOT),
                    "RemoteBitrateLimitInterceptor".to_owned()
                ),
                (Slot::CircuitBreaker, "CircuitBreakerInterceptor".to_owned()),
                (Slot::Pacer, "PacerInterceptor".to_owned()),
                (Slot::NackResponder, "NackResponderInterceptor".to_owned()),
                (Slot::TwccReceiver, "TwccReceiverInterceptor".to_owned()),
                (Slot::Rfc8888, "Rfc8888Interceptor".to_owned()),
                (
                    Slot::Custom(interceptor::REMB_GENERATOR_SLOT),
                    "RembGeneratorInterceptor".to_owned()
                ),
                (Slot::ExtendedReports, "XrReportInterceptor".to_owned()),
                (Slot::NackGenerator, "NackGeneratorInterceptor".to_owned()),
                (
                    Slot::KeyFrameRequests,
                    "KeyFrameRequestInterceptor".to_owned()
                ),
                (
                    Slot::TradeoffNotifications,
                    "TstnResponderInterceptor".to_owned()
                ),
            ],
            registry.slots()
        );
    }

    /// The recorder this helper places and the one `register_default_interceptors` places share a
    /// slot, so a chain that asks for both carries one of them, not two. Two arrival recorders
    /// would report every packet to the remote twice, and its estimator cannot tell the reports
    /// apart — it would read the path as carrying double what it does.
    #[test]
    fn the_twcc_recorder_is_not_registered_twice() {
        use interceptor::Gcc;

        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)
            .expect("default interceptors");
        let registry = configure_congestion_control(
            registry,
            Gcc::default(),
            CongestionFeedback::Twcc,
            &mut media_engine,
        )
        .expect("congestion control");

        let recorders = registry
            .slots()
            .into_iter()
            .filter(|(slot, _)| *slot == Slot::TwccReceiver)
            .count();
        assert_eq!(
            1, recorders,
            "one arrival recorder, however many helpers asked for one"
        );
    }

    /// RFC 8888 section 6: an offer may name RFC 8888 beside another congestion control
    /// feedback mechanism, so the standard set offers `ack ccfb` and `transport-cc` on every
    /// codec and carries a recorder for each. Which one reports a stream is decided per stream
    /// (`a_stream_is_reported_in_one_feedback_format` in `rtc-interceptor`).
    #[test]
    fn the_default_set_offers_rfc8888_beside_transport_cc() {
        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)
            .expect("default interceptors");

        let recorders: Vec<Slot> = slots(&registry)
            .into_iter()
            .filter(|slot| *slot == Slot::TwccReceiver || *slot == Slot::Rfc8888)
            .collect();
        assert_eq!(vec![Slot::TwccReceiver, Slot::Rfc8888], recorders);

        for kind in [RtpCodecKind::Video, RtpCodecKind::Audio] {
            for codec in media_engine.get_codecs_by_kind(kind) {
                let has = |typ: &str, parameter: &str| {
                    codec
                        .rtp_codec
                        .rtcp_feedback
                        .iter()
                        .any(|f| f.typ == typ && f.parameter == parameter)
                };
                assert!(has("ack", "ccfb"), "{}", codec.rtp_codec.mime_type);
                assert!(has("transport-cc", ""), "{}", codec.rtp_codec.mime_type);
                assert!(has("ccm", "tmmbr"), "{}", codec.rtp_codec.mime_type);
            }
        }
    }

    /// The browser setting: transport-wide congestion control only, with no trace of RFC 8888.
    #[test]
    fn the_twcc_only_setting_neither_offers_nor_records_rfc8888() {
        let mut media_engine = MediaEngine::default();
        let mut options = DefaultInterceptorOptions::default();
        options.congestion_feedback = CongestionFeedback::Twcc;
        let (registry, _handles) = register_default_interceptors_with_options(
            Registry::new(),
            &mut media_engine,
            &options,
        )
        .expect("default interceptors");

        assert!(!slots(&registry).contains(&Slot::Rfc8888));
        assert!(slots(&registry).contains(&Slot::TwccReceiver));
        for codec in media_engine.get_codecs_by_kind(RtpCodecKind::Video) {
            assert!(
                !codec
                    .rtp_codec
                    .rtcp_feedback
                    .iter()
                    .any(|f| f.typ == "ack" && f.parameter == "ccfb")
            );
        }
    }

    /// RFC 8888 asked for over the default set: the default already carries both recorders, a
    /// slot holds one interceptor, and so there are two recorders, one per format, and none
    /// twice. Upstream asserted the same two slots as a hazard (every packet reported twice);
    /// here each stream is reported by one of them
    /// (`a_stream_is_reported_in_one_feedback_format`).
    #[test]
    fn rfc8888_alongside_the_defaults_leaves_two_recorders() {
        use interceptor::Gcc;

        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)
            .expect("default interceptors");
        let registry = configure_congestion_control(
            registry,
            Gcc::default(),
            CongestionFeedback::Rfc8888,
            &mut media_engine,
        )
        .expect("congestion control");

        let recorders: Vec<Slot> = slots(&registry)
            .into_iter()
            .filter(|slot| *slot == Slot::TwccReceiver || *slot == Slot::Rfc8888)
            .collect();
        assert_eq!(vec![Slot::TwccReceiver, Slot::Rfc8888], recorders);
    }
}
