//! Advanced configuration engine for WebRTC peer connections.
//!
//! The `SettingEngine` provides low-level control over WebRTC transport behavior,
//! timeouts, security settings, and network configuration. Unlike the standard
//! `RTCConfiguration` which focuses on standards-compliant WebRTC settings, the
//! `SettingEngine` allows for advanced customization and optimization for specific
//! deployment scenarios.
//!
//! # Key Configuration Areas
//!
//! - **ICE Timeouts**: Configure connection health monitoring and keepalive intervals
//! - **NAT Traversal**: Set up 1:1 NAT mappings for cloud deployments (e.g., AWS EC2)
//! - **DTLS Security**: Control certificate verification and DTLS role behavior
//! - **Replay Protection**: Configure anti-replay windows for DTLS, SRTP, and SRTCP
//! - **Network Types**: Restrict candidate gathering to specific network types
//!
//! # Examples
//!
//! ## Configuring ICE timeouts for unstable networks
//!
//! ```
//! use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
//! use std::time::Duration;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Increase timeouts for mobile or unstable networks
//! let setting_engine = SettingEngineBuilder::new()
//!     .with_ice_timeouts(
//!         Some(Duration::from_secs(10)),  // disconnected_timeout (default: 5s)
//!         Some(Duration::from_secs(30)),  // failed_timeout (default: 25s)
//!         Some(Duration::from_secs(3)),   // keep_alive_interval (default: 2s)
//!     )
//!     .build();
//!
//! // Use with RTCConfiguration
//! // let mut config = RTCConfiguration::default();
//! // config.setting_engine = Some(setting_engine);
//! # Ok(())
//! # }
//! ```
//!
//! ## Setting up 1:1 NAT for cloud deployments
//!
//! ```
//! use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
//! use rtc::peer_connection::transport::RTCIceCandidateType;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Configure for AWS EC2 instance with Elastic IP
//! // Private IP: 10.0.1.5, Public IP: 54.123.45.67
//! let setting_engine = SettingEngineBuilder::new()
//!     .with_nat_1to1_ips(
//!         vec!["54.123.45.67".to_string()],
//!         RTCIceCandidateType::Host, // Use public IP for host candidates
//!     )
//!     .build();
//!
//! // This tells ICE to advertise the public IP instead of the private one
//! # Ok(())
//! # }
//! ```
//!
//! ## Configuring replay protection for security-critical applications
//!
//! ```
//! use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Increase replay protection window sizes
//! let setting_engine = SettingEngineBuilder::new()
//!     .with_dtls_replay_protection_window(128)  // DTLS anti-replay
//!     .with_srtp_replay_protection_window(256)  // SRTP anti-replay
//!     .with_srtcp_replay_protection_window(128) // SRTCP anti-replay
//!     .build();
//!
//! // Larger windows protect against more packet reordering but use more memory
//! # Ok(())
//! # }
//! ```
//!
//! ## Restricting network types for controlled environments
//!
//! ```
//! use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
//! use ice::network_type::NetworkType;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Only gather IPv4 UDP candidates (no IPv6, no TCP)
//! let setting_engine = SettingEngineBuilder::new()
//!     .with_network_types(vec![NetworkType::Udp4])
//!     .build();
//!
//! // This reduces candidate gathering time and SDP size
//! # Ok(())
//! # }
//! ```
//!
//! # See Also
//!
//! - [`RTCConfiguration`](crate::peer_connection::configuration::RTCConfiguration) - Standard WebRTC configuration
//! - [`MediaEngine`](crate::peer_connection::configuration::media_engine::MediaEngine) - Codec registration
//! - [RFC 8445 - ICE](https://datatracker.ietf.org/doc/html/rfc8445)
//! - [RFC 8446 - TLS 1.3 (DTLS basis)](https://datatracker.ietf.org/doc/html/rfc8446)

#[cfg(test)]
mod setting_engine_test;

use std::net::IpAddr;
use std::sync::Arc;

use crypto::RTCCryptoProvider;
use dtls::cipher_suite::CipherSuiteId;
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
//TODO: use ice::agent::agent_config::{InterfaceFilterFn, IpFilterFn};
use ice::agent::remote_policy::RemoteAddressFilter;
use ice::mdns::MulticastDnsMode;
use ice::network_type::NetworkType;
use ice::{NominationAcceptance, UnauthenticatedRequests};
//TODO: use ice::udp_network::UDPNetwork;
use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
use crate::peer_connection::transport::ice::candidate_type::RTCIceCandidateType;
use std::time::Duration;

/// Equal to UDP MTU
pub(crate) const RECEIVE_MTU: usize = 1460;

/// ICE timeout configuration for connection health monitoring.
///
/// These timeouts control how ICE determines connection state transitions
/// and when to send keepalive packets. Adjust these for different network
/// conditions (mobile, satellite, etc.).
#[derive(Default, Clone)]
pub struct Timeout {
    /// Duration without network activity before ICE is considered disconnected.
    /// Default: 5 seconds.
    pub ice_disconnected_timeout: Option<Duration>,

    /// Duration without network activity before ICE is considered failed after disconnected.
    /// Default: 25 seconds.
    pub ice_failed_timeout: Option<Duration>,

    /// How often ICE sends keepalive packets when there's no media flow.
    /// Default: 2 seconds. If media is flowing, no keepalives are sent.
    pub ice_keepalive_interval: Option<Duration>,

    /// Controls how often ICE sends binding requests for a candidate pair.
    /// When combined with `ice_max_binding_requests`, controls how long ICE will attempt
    /// to connect a candidate.
    pub ice_check_interval: Option<Duration>,

    /// The max amount of binding requests ICE will send over a candidate pair for validation
    /// or nomination, if after max_binding_requests the candidate is yet to answer a binding
    /// request or a nomination we set the pair as failed.
    /// When combined with `ice_check_interval`, controls how long ICE will attempt
    /// to connect a candidate.
    pub ice_max_binding_requests: Option<u16>,

    /// Minimum wait time before accepting host candidates.
    pub ice_host_acceptance_min_wait: Option<Duration>,

    /// Minimum wait time before accepting server reflexive candidates.
    pub ice_srflx_acceptance_min_wait: Option<Duration>,

    /// Minimum wait time before accepting peer reflexive candidates.
    pub ice_prflx_acceptance_min_wait: Option<Duration>,

    /// Minimum wait time before accepting relay candidates.
    pub ice_relay_acceptance_min_wait: Option<Duration>,
}

/// Data-channel configuration for in-band channels.
#[derive(Clone)]
pub struct DataChannel {
    /// Maximum time to wait for a peer's `DATA_CHANNEL_ACK` before failing an
    /// in-band data channel. `None` disables the timeout.
    pub dcep_handshake_timeout: Option<Duration>,
}

impl Default for DataChannel {
    fn default() -> Self {
        Self {
            dcep_handshake_timeout: Some(Duration::from_secs(30)),
        }
    }
}

/// MulticastDNS configuration for mDNS.
#[derive(Clone)]
pub struct MulticastDNS {
    /// Duration without network activity before mDNS query is considered failed.
    /// Default: 10 seconds.
    pub timeout: Option<Duration>,
    /// Represents the different Multicast modes that ICE can run.
    pub mode: MulticastDnsMode,
    /// Controls the local name for this agent. If none is specified a random one will be generated.
    pub local_name: String,
    /// Control mDNS local IP address
    pub local_ip: Option<IpAddr>,
}

impl Default for MulticastDNS {
    fn default() -> Self {
        Self {
            timeout: Some(Duration::from_secs(10)),
            // Safari and Chrome emit only mDNS ("<uuid>.local") host candidates
            // by default (to avoid leaking private IPs). With Disabled those are
            // silently dropped, leaving no usable remote candidates from such an
            // offer; QueryOnly resolves them via mDNS without publishing our own
            // host IPs as mDNS names. This matches the MulticastDnsMode enum's
            // own #[default].
            mode: MulticastDnsMode::QueryOnly,
            local_name: "".to_string(),
            local_ip: None,
        }
    }
}

/// ICE candidate gathering and filtering configuration.
///
/// Controls which types of candidates are gathered, NAT mappings,
/// and custom network filtering.
#[derive(Default, Clone)]
pub struct Candidates {
    /// Enable ICE Lite mode (only respond to connectivity checks, don't initiate).
    pub ice_lite: bool,

    /// Restrict candidate gathering to specific network types (e.g., UDP4, UDP6, TCP4).
    pub ice_network_types: Vec<NetworkType>,
    //TODO: pub interface_filter: Arc<Option<InterfaceFilterFn>>,
    //TODO: pub ip_filter: Arc<Option<IpFilterFn>>,
    /// External IP addresses for 1:1 NAT mappings (e.g., AWS Elastic IP).
    pub nat_1to1_ips: Vec<String>,

    /// Candidate type to use for NAT 1:1 IPs (Host or Srflx).
    pub nat_1to1_ip_candidate_type: RTCIceCandidateType,
    /// Static ICE username fragment (ufrag) for reproducible sessions.
    pub username_fragment: String,

    /// Static ICE password for reproducible sessions.
    pub password: String,

    /// Whether to discard local candidates during ICE restart.
    pub discard_local_candidates_during_ice_restart: bool,

    /// Allow gathering loopback candidates (useful for some VM configurations).
    /// Note: This is non-standard per RFC 8445.
    ///
    /// Not read by this engine, which gathers no candidates (see the deprecated
    /// `SettingEngineBuilder::with_include_loopback_candidate`).
    pub include_loopback_candidate: bool,

    /// Lets connectivity checks go to loopback / link-local remote addresses from local
    /// candidates outside that scope. See
    /// `SettingEngineBuilder::with_remote_candidate_scopes`.
    pub allow_loopback_remote_candidates: bool,
    /// See `SettingEngineBuilder::with_remote_candidate_scopes`.
    pub allow_link_local_remote_candidates: bool,
    /// See `SettingEngineBuilder::with_remote_address_filter`.
    pub remote_address_filter: Option<RemoteAddressFilter>,
}

/// Where the ICE agent follows RFC 8445 / RFC 8489 by default and a browser (libwebrtc)
/// behaviour, or one of this fork's hardenings, can be chosen instead. Every default is the
/// RFC's.
#[derive(Default, Clone)]
pub struct IceBehaviour {
    /// See [`SettingEngineBuilder::with_ice_tie_breaker`].
    pub tie_breaker: Option<u64>,
    /// See [`SettingEngineBuilder::with_ice_nomination_acceptance`].
    pub nomination_acceptance: NominationAcceptance,
    /// See [`SettingEngineBuilder::with_ice_nomination_on_consent_checks`].
    pub nominate_on_consent_checks: bool,
    /// See [`SettingEngineBuilder::with_ice_unauthenticated_requests`].
    pub unauthenticated_requests: UnauthenticatedRequests,
    /// See [`SettingEngineBuilder::with_ice_data_from_selected_pair_only`].
    pub data_from_selected_pair_only: bool,
    /// See [`SettingEngineBuilder::with_ice_data_before_nomination`].
    pub send_data_before_nomination: bool,
}

/// Replay attack protection window sizes.
///
/// Larger windows provide better protection against packet reordering
/// but consume more memory. Set to 0 to disable replay protection (not recommended).
#[derive(Default, Copy, Clone)]
pub struct ReplayProtection {
    /// DTLS replay protection window size (in packets).
    pub dtls: usize,

    /// SRTP replay protection window size (in packets).
    pub srtp: usize,

    /// SRTCP replay protection window size (in packets).
    pub srtcp: usize,
}

/// Maximum message size for SCTP data channels.
///
/// Controls the maximum size of messages that can be sent through data channels.
/// Per [RFC 8841](https://datatracker.ietf.org/doc/html/rfc8841), the default is 64KB.
#[derive(Copy, Clone)]
#[non_exhaustive]
pub enum SctpMaxMessageSize {
    /// Fixed maximum message size in bytes.
    Bounded(u32),

    /// No practical limit (uses MAX_MESSAGE_SIZE internally).
    Unbounded,
}

impl SctpMaxMessageSize {
    /// Default message size per RFC 8841 (64KB).
    pub const DEFAULT_MESSAGE_SIZE: u32 = 65536;

    /// Maximum message size (256KB).
    pub const MAX_MESSAGE_SIZE: u32 = 262144;

    /// Returns the message size as `usize`.
    pub fn as_usize(&self) -> usize {
        match self {
            Self::Bounded(result) => (*result).min(Self::MAX_MESSAGE_SIZE) as usize,
            Self::Unbounded => Self::MAX_MESSAGE_SIZE as usize,
        }
    }
}

impl Default for SctpMaxMessageSize {
    fn default() -> Self {
        // https://datatracker.ietf.org/doc/html/rfc8841#section-6.1-4
        // > If the SDP "max-message-size" attribute is not present, the default value is 64K.
        Self::Bounded(Self::DEFAULT_MESSAGE_SIZE)
    }
}

/// Advanced configuration engine for fine-tuning WebRTC behavior.
///
/// `SettingEngine` provides granular control over transport-level settings that
/// are not exposed through the standard WebRTC API. Use this to optimize for
/// specific deployment scenarios, network conditions, or security requirements.
///
/// # Configuration Categories
///
/// - **Timeout**: ICE connection health monitoring and keepalive
/// - **TURN**: Allocation maintenance behavior
/// - **Candidates**: NAT traversal, network filtering, ICE credentials
/// - **Replay Protection**: Anti-replay window sizes for DTLS/SRTP/SRTCP
/// - **DTLS**: Certificate verification and role selection
/// - **Media Engine**: Codec registration behavior
/// - **SCTP**: Data channel message size limits
///
/// # Examples
///
/// ## Basic usage with RTCConfiguration
///
/// ```
/// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
/// use std::time::Duration;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let setting_engine = SettingEngineBuilder::new()
///     // Configure timeouts
///     .with_ice_timeouts(
///         Some(Duration::from_secs(10)),
///         Some(Duration::from_secs(30)),
///         Some(Duration::from_secs(3)),
///     )
///     .build();
///
/// // Use with peer connection configuration
/// // let api = APIBuilder::new().with_setting_engine(setting_engine).build();
/// # Ok(())
/// # }
/// ```
///
/// # See Also
///
/// - [W3C WebRTC Spec](https://www.w3.org/TR/webrtc/)
/// - [RFC 8445 - ICE](https://datatracker.ietf.org/doc/html/rfc8445)
#[derive(Default, Clone)]
pub struct SettingEngine {
    pub(crate) crypto_provider: Option<Arc<dyn RTCCryptoProvider>>,
    pub(crate) timeout: Timeout,
    pub(crate) data_channel: DataChannel,
    pub(crate) turn_allocation_refresh_interval_cap: Option<Duration>,
    pub(crate) candidates: Candidates,
    pub(crate) ice: IceBehaviour,
    pub(crate) multicast_dns: MulticastDNS,
    pub(crate) replay_protection: ReplayProtection,
    pub(crate) sdp_media_level_fingerprints: bool,
    pub(crate) disable_sdp_tls_id: bool,
    pub(crate) dtls_use_srtp_on_every_association: bool,
    pub(crate) accept_lowercase_fingerprints: bool,
    /// Answers and subsequent offers repeat the BUNDLE attributes in every bundled m=
    /// section instead of carrying them in the tagged one only (RFC 9143 section 7.1.3); see
    /// [`SettingEngineBuilder::with_bundle_attributes_repeated`].
    /// Inverted so that the derived default is "repeated".
    pub(crate) bundle_attributes_tagged_only: bool,
    /// [`SettingEngineBuilder::with_max_bundle_as_must_bundle`].
    /// Inverted so that the derived default is "honoured".
    pub(crate) max_bundle_ignored: bool,
    /// [`SettingEngineBuilder::with_implicit_rollback`].
    /// Inverted so that the derived default is "implicit rollback on".
    pub(crate) explicit_rollback_only: bool,
    pub(crate) answering_dtls_role: RTCDtlsRole,
    pub(crate) disable_certificate_fingerprint_verification: bool,
    pub(crate) allow_insecure_verification_algorithm: bool,
    pub(crate) disable_media_engine_copy: bool,
    pub(crate) disable_media_engine_multiple_codecs: bool,
    pub(crate) srtp_protection_profiles: Vec<SrtpProtectionProfile>,
    pub(crate) dtls_cipher_suites: Vec<CipherSuiteId>,
    pub(crate) receive_mtu: usize,
    pub(crate) mid_generator: Option<Arc<dyn Fn(isize) -> String + Send + Sync>>,
    /// Determines the max size of any message that may be sent through an SCTP transport.
    pub(crate) sctp_max_message_size: SctpMaxMessageSize,
    /// Overrides the SCTP receive-buffer size (the a_rwnd flow-control window), in bytes.
    /// `None` uses the rtc-sctp default (`INITIAL_RECV_BUF_SIZE`, 1 MiB).
    pub(crate) sctp_max_receive_buffer_size: Option<u32>,
    /// Overrides the outbound SCTP DATA-packet budget, converted to a payload
    /// budget via rtc-sctp's `max_payload_size_for_mtu`. `None` uses the rtc-sctp
    /// default (`INITIAL_MTU`, 1191 — the TURN-relayed IPv6 minimum-MTU budget).
    pub(crate) sctp_mtu: Option<u32>,
    /// SCTP streams share the bytes sent by weight (RFC 8260 section 3.6, RFC 8831 section
    /// 6.4). `None` is the default, on.
    pub(crate) sctp_weighted_fair_queueing: Option<bool>,
    /// SCTP user message interleaving (RFC 8260) is announced. `None` is the default, on.
    pub(crate) sctp_message_interleaving: Option<bool>,
    /// The SCTP zero checksum (RFC 9653) is announced as acceptable. `None` is the default,
    /// on.
    pub(crate) sctp_zero_checksum: Option<bool>,
    /// A message over 16 KB is refused on an association without message interleaving
    /// (RFC 8831 section 6.6). `None` is the default, on.
    pub(crate) sctp_message_size_limit_without_interleaving: Option<bool>,
    pub(crate) ignore_rid_pause_for_recv: bool,
    /// [`SettingEngineBuilder::with_rid_pause_marks`].
    pub(crate) rid_pause_marks: bool,
    pub(crate) write_ssrc_attributes_for_simulcast: bool,
    /// The application's socket layer reports each received datagram's ECN codepoint and
    /// applies the one each sent datagram carries ([`SettingEngineBuilder::with_ecn`]).
    pub(crate) ecn: bool,
}

impl SettingEngine {
    /// The crypto provider configured on this engine, if any.
    ///
    /// `None` means no provider has been set, so building a peer connection will resolve the
    /// feature-selected built-in.
    ///
    /// Callers assembling additional components around a peer connection — an async wrapper's
    /// TURN client, for instance — read the provider from here and pass it to
    /// [`with_crypto_provider`](SettingEngineBuilder::with_crypto_provider) before building, so the whole
    /// connection provably shares one provider instead of resolving a second.
    pub fn crypto_provider(&self) -> Option<&Arc<dyn RTCCryptoProvider>> {
        self.crypto_provider.as_ref()
    }

    /// Set crypto provider on this engine.
    #[doc(hidden)]
    pub fn set_crypto_provider(&mut self, crypto_provider: Arc<dyn RTCCryptoProvider>) {
        self.crypto_provider = Some(crypto_provider);
    }

    /// Returns the multicast DNS configuration.
    pub fn multicast_dns(&self) -> &MulticastDNS {
        &self.multicast_dns
    }

    /// Returns the configured maximum interval between TURN allocation Refresh requests.
    ///
    /// `None` preserves the TURN client's default cadence of half the lifetime advertised by
    /// the server.
    pub fn turn_allocation_refresh_interval_cap(&self) -> Option<Duration> {
        self.turn_allocation_refresh_interval_cap
    }

    /// Whether an ICE restart discards the local candidates gathered by the previous generation.
    ///
    /// Set through
    /// [`with_discard_local_candidates_during_ice_restart`](SettingEngineBuilder::with_discard_local_candidates_during_ice_restart),
    /// where the reasoning lives.
    ///
    /// Read by the layer that owns the sockets, because the two decisions are one decision.
    /// Discarding the old candidates is only necessary when the transport under them is being
    /// replaced, and replacing that transport is only safe when the candidates naming it are
    /// discarded — so an async wrapper treats this as "the sockets are replaced on restart" and
    /// rebinds them, rather than exposing a second switch the two halves could disagree on.
    pub fn discard_local_candidates_during_ice_restart(&self) -> bool {
        self.candidates.discard_local_candidates_during_ice_restart
    }

    /// The ICE credentials configured on this engine.
    ///
    /// Both empty (the default) means every peer connection generates fresh random
    /// credentials when its ICE agent is created.
    pub fn ice_credentials(&self) -> (&str, &str) {
        (
            self.candidates.username_fragment.as_str(),
            self.candidates.password.as_str(),
        )
    }

    /// Set ICE credentials on this engine.
    #[doc(hidden)]
    pub fn set_ice_credentials(&mut self, username_fragment: String, password: String) {
        self.candidates.username_fragment = username_fragment;
        self.candidates.password = password;
    }
}

/// Fluent registry for [`SettingEngine`].
///
/// Mirrors [`RTCConfigurationBuilder`](crate::peer_connection::configuration::RTCConfigurationBuilder),
/// so a peer connection is configured in one style throughout rather than switching between a
/// fluent registry and a sequence of `&mut self` setters.
///
/// [`build`](Self::build) is infallible: every setting is either always valid or normalised on
/// the way in, so there is no failure mode to report.
#[derive(Default)]
pub struct SettingEngineBuilder(SettingEngine);

impl SettingEngineBuilder {
    /// A registry with every setting at its default.
    pub fn new() -> Self {
        Self::default()
    }

    /// Selects the cryptographic provider used by peer connections built with this setting engine.
    ///
    /// The provider is resolved once at peer-connection construction and shared with ICE, DTLS,
    /// SRTP, certificate, and fingerprint operations. Different peer connections may select
    /// different providers in the same process.
    pub fn with_crypto_provider(mut self, provider: Arc<dyn RTCCryptoProvider>) -> Self {
        self.0.crypto_provider = Some(provider);
        self
    }

    /// Overrides the default SRTP protection profiles.
    ///
    /// SRTP profiles define the encryption algorithms used for media streams.
    /// Only override this if you need specific security requirements or
    /// compatibility with non-standard implementations.
    ///
    /// # Parameters
    ///
    /// * `profiles` - List of SRTP protection profiles to use
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Use specific SRTP profile
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_srtp_protection_profiles(vec![
    ///         SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
    ///     ])
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_srtp_protection_profiles(mut self, profiles: Vec<SrtpProtectionProfile>) -> Self {
        self.0.srtp_protection_profiles = profiles;
        self
    }

    /// Restricts the DTLS cipher suites offered during the handshake.
    ///
    /// An empty list (the default) uses the WebRTC default set: the `dtls` crate's built-in
    /// suites without AES-256-CBC-SHA (AES-128-GCM and ChaCha20-Poly1305; browsers negotiate
    /// GCM). List a CBC suite here to offer it. The default offers **both** ECDHE_ECDSA and
    /// ECDHE_RSA suites. That is deliberate — the local
    /// certificate is not known when the list is compiled — but it means a remote peer may
    /// select an ECDHE_RSA suite that an ECDSA certificate cannot satisfy, and the
    /// handshake then stalls with the connection stuck in `Connecting`.
    ///
    /// Certificates generated by this crate are ECDSA (P-256), so an application that does
    /// not supply its own RSA certificate can pin the ECDSA suites and remove that
    /// possibility:
    ///
    /// ```
    /// use dtls::cipher_suite::CipherSuiteId;
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_dtls_cipher_suites(vec![
    ///         CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
    ///         CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
    ///         CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
    ///     ])
    ///     .build();
    /// ```
    ///
    /// The order is a preference order. Every suite named must be one the `dtls` crate
    /// implements, or building the transport fails with `ErrInvalidCipherSuite`; a list
    /// that filters down to nothing usable fails with `ErrNoAvailableCipherSuites`.
    pub fn with_dtls_cipher_suites(mut self, cipher_suites: Vec<CipherSuiteId>) -> Self {
        self.0.dtls_cipher_suites = cipher_suites;
        self
    }

    /// Caps the interval between TURN allocation Refresh requests.
    ///
    /// By default, TURN allocations are refreshed at half the lifetime advertised by the server.
    /// A shorter cap can keep an otherwise idle client-to-server NAT mapping active. Values below
    /// one second are rounded up by the TURN client.
    pub fn with_turn_allocation_refresh_interval_cap(mut self, cap: Duration) -> Self {
        self.0.turn_allocation_refresh_interval_cap = Some(cap);
        self
    }

    /// Configures ICE timeout behavior for connection health monitoring.
    ///
    /// These timeouts control when ICE transitions between connection states
    /// and when keepalive packets are sent. Adjust these for different network
    /// conditions:
    /// - Increase for unstable networks (mobile, satellite)
    /// - Decrease for low-latency applications
    ///
    /// # Parameters
    ///
    /// * `disconnected_timeout` - Duration without activity before considered disconnected (default: 5s)
    /// * `failed_timeout` - Duration after disconnected before considered failed (default: 25s)
    /// * `keep_alive_interval` - How often to send keepalives when idle (default: 2s)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use std::time::Duration;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Conservative settings for mobile networks
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_ice_timeouts(
    ///         Some(Duration::from_secs(10)),  // Longer before disconnected
    ///         Some(Duration::from_secs(40)),  // Longer before failed
    ///         Some(Duration::from_secs(5)),   // Less frequent keepalives
    ///     )
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8445 §16 - Timers](https://datatracker.ietf.org/doc/html/rfc8445#section-16)
    pub fn with_ice_timeouts(
        mut self,
        disconnected_timeout: Option<Duration>,
        failed_timeout: Option<Duration>,
        keep_alive_interval: Option<Duration>,
    ) -> Self {
        self.0.timeout.ice_disconnected_timeout = disconnected_timeout;
        self.0.timeout.ice_failed_timeout = failed_timeout;
        self.0.timeout.ice_keepalive_interval = keep_alive_interval;
        self
    }

    /// Configures the DCEP handshake timeout for in-band data channels.
    ///
    /// # Parameters
    ///
    /// * `timeout` - Maximum time to wait for the peer's `DATA_CHANNEL_ACK`,
    ///   or `None` to disable the timeout.
    pub fn with_dcep_handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.0.data_channel.dcep_handshake_timeout = timeout;
        self
    }

    /// Configures ICE connection attempt behavior, including number of connection attempts
    /// per candidate, and the amount of time between connection attempts.
    ///
    /// The default settings configure ICE to attempt to connect a candidate for up to 1.4 seconds.
    ///
    /// # Parameters
    ///
    /// * `check_interval` - The delay between each connection attempt (default: 200 ms)
    /// * `max_binding_requests` - Maximum number of connection attempts per candidate (default: 7)
    pub fn with_ice_connection_attempts(
        mut self,
        check_interval: Option<Duration>,
        max_binding_requests: Option<u16>,
    ) -> Self {
        self.0.timeout.ice_check_interval = check_interval;
        self.0.timeout.ice_max_binding_requests = max_binding_requests;
        self
    }

    /// Sets minimum wait time before accepting host candidates.
    ///
    /// # Parameters
    ///
    /// * `t` - Minimum wait duration, or `None` for immediate acceptance
    pub fn with_host_acceptance_min_wait(mut self, t: Option<Duration>) -> Self {
        self.0.timeout.ice_host_acceptance_min_wait = t;
        self
    }

    /// Sets minimum wait time before accepting server reflexive candidates.
    ///
    /// Server reflexive candidates are discovered through STUN servers.
    ///
    /// # Parameters
    ///
    /// * `t` - Minimum wait duration, or `None` for immediate acceptance
    pub fn with_srflx_acceptance_min_wait(mut self, t: Option<Duration>) -> Self {
        self.0.timeout.ice_srflx_acceptance_min_wait = t;
        self
    }

    /// Sets minimum wait time before accepting peer reflexive candidates.
    ///
    /// Peer reflexive candidates are discovered during connectivity checks.
    ///
    /// # Parameters
    ///
    /// * `t` - Minimum wait duration, or `None` for immediate acceptance
    pub fn with_prflx_acceptance_min_wait(mut self, t: Option<Duration>) -> Self {
        self.0.timeout.ice_prflx_acceptance_min_wait = t;
        self
    }

    /// Sets minimum wait time before accepting relay candidates.
    ///
    /// Relay candidates are provided by TURN servers.
    ///
    /// # Parameters
    ///
    /// * `t` - Minimum wait duration, or `None` for immediate acceptance
    pub fn with_relay_acceptance_min_wait(mut self, t: Option<Duration>) -> Self {
        self.0.timeout.ice_relay_acceptance_min_wait = t;
        self
    }

    /*todo:
    /// set_udp_network allows ICE traffic to come through Ephemeral or UDPMux.
    /// UDPMux drastically simplifying deployments where ports will need to be opened/forwarded.
    /// UDPMux should be started prior to creating PeerConnections.
    pub fn with_udp_network(mut self, udp_network: UDPNetwork) -> Self {
        self.0.udp_network = udp_network;
    }*/

    /// Configures ICE Lite mode.
    ///
    /// In ICE Lite mode, the agent only responds to connectivity checks
    /// but does not initiate them. This is typically used by servers that
    /// have public IP addresses and don't need full ICE functionality.
    ///
    /// # Parameters
    ///
    /// * `lite` - `true` to enable ICE Lite, `false` for full ICE
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Enable ICE Lite for a publicly accessible server
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_lite(true)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8445 §2.7 - Lite Implementation](https://datatracker.ietf.org/doc/html/rfc8445#section-2.7)
    pub fn with_lite(mut self, lite: bool) -> Self {
        self.0.candidates.ice_lite = lite;
        self
    }

    /// Restricts candidate gathering to specific network types.
    ///
    /// This reduces the number of candidates gathered, which can speed up
    /// connection establishment and reduce SDP size. Useful when you know
    /// certain network types won't work in your deployment.
    ///
    /// # Parameters
    ///
    /// * `candidate_types` - List of allowed network types (e.g., UDP4, UDP6, TCP4)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use ice::network_type::NetworkType;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Only use IPv4 UDP (most common case)
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_network_types(vec![NetworkType::Udp4])
    ///     .build();
    ///
    /// // Or allow both IPv4 and IPv6 UDP
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_network_types(vec![NetworkType::Udp4, NetworkType::Udp6])
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_network_types(mut self, candidate_types: Vec<NetworkType>) -> Self {
        self.0.candidates.ice_network_types = candidate_types;
        self
    }

    /*todo:
    /// set_interface_filter sets the filtering functions when gathering ICE candidates
    /// This can be used to exclude certain network interfaces from ICE. Which may be
    /// useful if you know a certain interface will never succeed, or if you wish to reduce
    /// the amount of information you wish to expose to the remote peer
    pub fn with_interface_filter(mut self, filter: InterfaceFilterFn) -> Self {
        self.0.candidates.interface_filter = Arc::new(Some(filter));
        self
    }


    /// set_ip_filter sets the filtering functions when gathering ICE candidates
    /// This can be used to exclude certain ip from ICE. Which may be
    /// useful if you know a certain ip will never succeed, or if you wish to reduce
    /// the amount of information you wish to expose to the remote peer
    pub fn with_ip_filter(mut self, filter: IpFilterFn) -> Self {
        self.0.candidates.ip_filter = Arc::new(Some(filter));
    }*/

    /// Configures 1:1 NAT IP mapping for cloud deployments.
    ///
    /// This is essential for WebRTC servers running on cloud instances (e.g., AWS EC2)
    /// that have a private IP address but are accessible via a public IP through 1:1 NAT.
    ///
    /// # Parameters
    ///
    /// * `ips` - List of external/public IP addresses
    /// * `candidate_type` - How to advertise the public IPs:
    ///   - `RTCIceCandidateType::Host`: Replace private IP with public IP (mDNS disabled)
    ///   - `RTCIceCandidateType::Srflx`: Add public IP as server reflexive candidate
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use rtc::peer_connection::transport::RTCIceCandidateType;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // AWS EC2: Private IP 10.0.1.5, Elastic IP 54.123.45.67
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_nat_1to1_ips(
    ///         vec!["54.123.45.67".to_string()],
    ///         RTCIceCandidateType::Host,
    ///     )
    ///     .build();
    ///
    /// // Or use Srflx to keep private IP available
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_nat_1to1_ips(
    ///         vec!["54.123.45.67".to_string()],
    ///         RTCIceCandidateType::Srflx,
    ///     )
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Note
    ///
    /// - With `Host` type, the private IP is not advertised to the peer
    /// - With `Srflx` type, both private and public IPs are available
    /// - Cannot use STUN servers when using `Srflx` type
    /// - Cannot use with mDNS when using `Host` type
    ///
    /// # How it applies
    ///
    /// The sans-I/O engine gathers no candidates: the mapping is applied to the host
    /// candidates the application adds with `add_local_candidate`. With `Host` a mapped host
    /// candidate is announced on the public address (it stays bound to the local one); with
    /// `Srflx` a server-reflexive candidate on the public address is announced beside it. Each
    /// entry is `"<public ip>"` or `"<public ip>/<local ip>"`. An invalid list, `Host` with
    /// mDNS `QueryAndGather`, or a type the candidate policy excludes fails peer connection
    /// creation.
    pub fn with_nat_1to1_ips(
        mut self,
        ips: Vec<String>,
        candidate_type: RTCIceCandidateType,
    ) -> Self {
        self.0.candidates.nat_1to1_ips = ips;
        self.0.candidates.nat_1to1_ip_candidate_type = candidate_type;
        self
    }

    /// Sets the DTLS role to use when answering an offer.
    ///
    /// The DTLS role determines whether this peer acts as a DTLS client
    /// (initiating the handshake) or server (waiting for handshake). Normally
    /// this is negotiated automatically, but you can override it for debugging
    /// or compatibility with non-compliant implementations.
    ///
    /// # Parameters
    ///
    /// * `role` - DTLS role to use:
    ///   - `DTLSRole::Client`: Act as DTLS client, send ClientHello
    ///   - `DTLSRole::Server`: Act as DTLS server, wait for ClientHello
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success
    /// * `Err(Error)` if role is not Client or Server
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use rtc::peer_connection::transport::RTCDtlsRole;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Force this peer to always act as DTLS client when answering
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_answering_dtls_role(RTCDtlsRole::Client)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8842 - DTLS for WebRTC](https://datatracker.ietf.org/doc/html/rfc8842)
    pub fn with_answering_dtls_role(mut self, role: RTCDtlsRole) -> Self {
        // Deliberately unvalidated. `Unspecified` and `Auto` are not errors here: both
        // consumers already handle them — `to_connection_role()` maps `Unspecified` to
        // `ConnectionRole::Unspecified`, which the answer path detects and replaces with
        // `DEFAULT_DTLS_ROLE_ANSWER`, and the role-selection `match` falls through to the
        // ICE-derived default. Rejecting them contradicted behaviour that already worked.
        self.0.answering_dtls_role = role;
        self
    }

    /// Sets the timeout for multicast DNS resolution.
    pub fn with_multicast_dns_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.0.multicast_dns.timeout = timeout;
        self
    }

    /// set_ice_multicast_dns_mode controls if ice queries and generates mDNS ICE Candidates
    pub fn with_multicast_dns_mode(mut self, multicast_dns_mode: MulticastDnsMode) -> Self {
        self.0.multicast_dns.mode = multicast_dns_mode;
        self
    }

    /// set_ice_multicast_dns_host_name sets a static HostName to be used by ice instead of generating one on startup
    /// This should only be used for a single PeerConnection. Having multiple PeerConnections with the same HostName will cause
    /// undefined behavior
    pub fn with_multicast_dns_local_name(mut self, local_name: String) -> Self {
        self.0.multicast_dns.local_name = local_name;
        self
    }

    /// Sets the local IP address to use for multicast DNS.
    pub fn with_multicast_dns_local_ip(mut self, local_ip: Option<IpAddr>) -> Self {
        self.0.multicast_dns.local_ip = local_ip;
        self
    }

    /// Sets static ICE credentials for reproducible sessions.
    ///
    /// By default, ICE generates random credentials (ufrag/password) for each
    /// session. Setting static credentials allows for signalless WebRTC or
    /// reproducible testing environments.
    ///
    /// # Parameters
    ///
    /// * `username_fragment` - ICE username fragment (ufrag)
    /// * `password` - ICE password
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Set static credentials for reproducible testing
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_ice_credentials(
    ///         "test_ufrag".to_string(),
    ///         "test_password".to_string(),
    ///     )
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Security Note
    ///
    /// Only use static credentials in controlled environments. Random credentials
    /// provide better security for production deployments.
    pub fn with_ice_credentials(mut self, username_fragment: String, password: String) -> Self {
        self.0.candidates.username_fragment = username_fragment;
        self.0.candidates.password = password;
        self
    }

    /// Disables DTLS certificate fingerprint verification.
    ///
    /// **Warning**: Disabling fingerprint verification removes a critical
    /// security check and should only be used for testing or debugging.
    ///
    /// # Parameters
    ///
    /// * `is_disabled` - `true` to disable verification, `false` to enable
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Only for testing/debugging!
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_disable_certificate_fingerprint_verification(true)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_disable_certificate_fingerprint_verification(mut self, is_disabled: bool) -> Self {
        self.0.disable_certificate_fingerprint_verification = is_disabled;
        self
    }

    /// Allows insecure signature verification algorithms.
    ///
    /// Some signature algorithms are known to be vulnerable or deprecated.
    /// This setting allows their use for compatibility with legacy systems.
    ///
    /// **Warning**: Only enable this if absolutely necessary for compatibility.
    ///
    /// # Parameters
    ///
    /// * `is_allowed` - `true` to allow insecure algorithms, `false` to disallow
    pub fn with_allow_insecure_verification_algorithm(mut self, is_allowed: bool) -> Self {
        self.0.allow_insecure_verification_algorithm = is_allowed;
        self
    }

    /// Sets the DTLS replay protection window size.
    ///
    /// The replay protection window prevents attackers from re-sending captured
    /// packets. Larger windows protect against more packet reordering but use
    /// more memory. Set to 0 to disable (not recommended).
    ///
    /// # Parameters
    ///
    /// * `n` - Window size in packets (0 = disabled)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Increase window for high-latency or reordering networks
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_dtls_replay_protection_window(128)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 6347 §4.1.2.6 - Anti-Replay](https://datatracker.ietf.org/doc/html/rfc6347#section-4.1.2.6)
    pub fn with_dtls_replay_protection_window(mut self, n: usize) -> Self {
        self.0.replay_protection.dtls = n;
        self
    }

    /// Sets the SRTP replay protection window size.
    ///
    /// SRTP replay protection prevents replay attacks on encrypted media packets.
    /// Adjust the window size based on expected packet reordering in your network.
    ///
    /// The default is 1024 packets. A NACK retransmission sent without RTX reuses the lost
    /// packet's sequence number and arrives after every packet sent since, so a window smaller
    /// than the packets sent during a few NACK rounds refuses late repairs as too old.
    ///
    /// # Parameters
    ///
    /// * `n` - Window size in packets (0 = disabled, not recommended)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // A wider window for a high packet rate
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_srtp_replay_protection_window(4096)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 3711 §3.3.2 - Replay Protection](https://datatracker.ietf.org/doc/html/rfc3711#section-3.3.2)
    pub fn with_srtp_replay_protection_window(mut self, n: usize) -> Self {
        self.0.replay_protection.srtp = n;
        self
    }

    /// Sets the SRTCP replay protection window size.
    ///
    /// SRTCP replay protection applies to RTCP control packets. Usually
    /// a smaller window is sufficient since RTCP packets are less frequent.
    ///
    /// # Parameters
    ///
    /// * `n` - Window size in packets (0 = disabled, not recommended)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Smaller window sufficient for RTCP
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_srtcp_replay_protection_window(64)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_srtcp_replay_protection_window(mut self, n: usize) -> Self {
        self.0.replay_protection.srtcp = n;
        self
    }

    /// Allows gathering of loopback candidates.
    ///
    /// By default, loopback candidates (127.x.x.x, ::1) are not gathered per
    /// RFC 8445. However, some VM configurations map public IPs to the loopback
    /// interface, making this necessary.
    ///
    /// # Parameters
    ///
    /// * `allow_loopback` - `true` to gather loopback candidates, `false` to skip
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Enable for certain VM configurations
    /// # #[allow(deprecated)]
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_include_loopback_candidate(true)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Note
    ///
    /// This is non-standard behavior per [RFC 8445 §5.1.1.1](https://datatracker.ietf.org/doc/html/rfc8445#section-5.1.1.1).
    /// Use with caution.
    ///
    /// # Not read by this engine
    ///
    /// The sans-I/O engine gathers no candidates (the application adds them), so this value is
    /// stored for API compatibility with pion and never read.
    #[deprecated(
        note = "a no-op: the sans-I/O engine gathers no candidates; add a loopback candidate \
                with `add_local_candidate` instead"
    )]
    pub fn with_include_loopback_candidate(mut self, allow_loopback: bool) -> Self {
        self.0.candidates.include_loopback_candidate = allow_loopback;
        self
    }

    /// Discards previously gathered local candidates when an ICE restart is applied.
    ///
    /// By default the restarted generation keeps its local candidates, which avoids re-gathering
    /// addresses that are usually still valid. [RFC 8445 §9] describes a restart as flushing all
    /// state except the roles and gathering anew, so keeping them is an optimisation rather than
    /// the specified behaviour — it is sound only while the underlying sockets outlive the
    /// restart.
    ///
    /// Set this when they do not. If the transport rebinds its sockets as part of recovery — for
    /// example an application that replaces its UDP sockets after the platform invalidated them —
    /// the retained candidates name addresses nothing is bound to any more. Connectivity checks
    /// are then written for a local address with no socket behind it and silently go nowhere, so
    /// the restarted generation exchanges credentials successfully and never leaves `Checking`.
    ///
    /// # Parameters
    ///
    /// * `discard` - `true` to drop local candidates on restart, `false` (default) to keep them
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Pairs with a transport that rebinds its sockets during ICE restart.
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_discard_local_candidates_during_ice_restart(true)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8445 §9 - ICE Restarts](https://datatracker.ietf.org/doc/html/rfc8445#section-9)
    ///
    /// [RFC 8445 §9]: https://datatracker.ietf.org/doc/html/rfc8445#section-9
    pub fn with_discard_local_candidates_during_ice_restart(mut self, discard: bool) -> Self {
        self.0
            .candidates
            .discard_local_candidates_during_ice_restart = discard;
        self
    }

    /// Allows connectivity checks to loopback and / or link-local remote addresses.
    ///
    /// Remote candidates are chosen by the peer. By default a loopback remote candidate
    /// (`127.0.0.0/8`, `::1`) is paired only with a loopback local candidate, and a link-local
    /// one (`169.254.0.0/16`, `fe80::/10`, which includes cloud metadata services) only with a
    /// link-local local candidate, so a remote peer cannot make this host send checks to its
    /// own services or its link's metadata address. Candidates that are never a unicast
    /// destination (unspecified, multicast, broadcast, port 0) are dropped regardless
    /// ([RFC 8445 §5.1.1.1]).
    ///
    /// [RFC 8445 §5.1.1.1]: https://datatracker.ietf.org/doc/html/rfc8445#section-5.1.1.1
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// // Pair loopback remote candidates with any local candidate; keep link-local ones scoped.
    /// let _setting_engine = SettingEngineBuilder::new()
    ///     .with_remote_candidate_scopes(true, false)
    ///     .build();
    /// ```
    pub fn with_remote_candidate_scopes(mut self, loopback: bool, link_local: bool) -> Self {
        self.0.candidates.allow_loopback_remote_candidates = loopback;
        self.0.candidates.allow_link_local_remote_candidates = link_local;
        self
    }

    /// Fixes the ICE tiebreaker (RFC 8445 section 5.2), which is random otherwise. It decides
    /// who keeps the controlling role when both agents claim it (section 7.3.1.1): the larger
    /// one. For reproducible sessions and tests.
    pub fn with_ice_tie_breaker(mut self, tie_breaker: u64) -> Self {
        self.0.ice.tie_breaker = Some(tie_breaker);
        self
    }

    /// Which pair a controlled ICE agent uses when the controlling agent nominates more than
    /// one.
    ///
    /// The default, [`NominationAcceptance::HighestPriority`], is RFC 8445 section 8.1.1: the
    /// nominated pair with the highest priority (a nominated pair of lower priority takes over
    /// when consent is lost on the selected one). [`NominationAcceptance::Latest`] is
    /// libwebrtc's rule: the latest nomination wins (with its `NOMINATION` attribute, the
    /// highest value), whatever the pair's priority; the session then follows a browser that
    /// moves to another pair and stops answering on the one it left.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use rtc::ice::NominationAcceptance;
    ///
    /// let _setting_engine = SettingEngineBuilder::new()
    ///     .with_ice_nomination_acceptance(NominationAcceptance::Latest)
    ///     .build();
    /// ```
    pub fn with_ice_nomination_acceptance(mut self, acceptance: NominationAcceptance) -> Self {
        self.0.ice.nomination_acceptance = acceptance;
        self
    }

    /// Makes the controlling ICE agent's consent checks carry USE-CANDIDATE, as libwebrtc's
    /// do. Off by default: RFC 8445 section 7.1.2 has the attribute sent "in order to nominate
    /// a candidate pair", once (section 8.1.1), and a consent check is a plain Binding request
    /// (RFC 7675 section 5.1). Without it the agent repeats its nomination only when the peer
    /// shows it lost it (a role conflict after the nomination).
    pub fn with_ice_nomination_on_consent_checks(mut self, enabled: bool) -> Self {
        self.0.ice.nominate_on_consent_checks = enabled;
        self
    }

    /// What a STUN Binding request that fails the ICE short-term credential check gets.
    ///
    /// The default, [`UnauthenticatedRequests::Reject`], is RFC 8489 section 9.1.3: 400 (Bad
    /// Request) without MESSAGE-INTEGRITY or USERNAME, 401 (Unauthenticated) for an unknown
    /// username or a MESSAGE-INTEGRITY that does not match. The responses are rate limited,
    /// never longer than the request, and unsigned. [`UnauthenticatedRequests::Drop`] answers
    /// nothing (what this crate did before).
    pub fn with_ice_unauthenticated_requests(mut self, requests: UnauthenticatedRequests) -> Self {
        self.0.ice.unauthenticated_requests = requests;
        self
    }

    /// Accepts data (DTLS, SRTP) only from the selected candidate pair's remote address.
    ///
    /// Off by default: RFC 8445 section 12.2 has an agent "prepared to receive data on any of
    /// the candidates provided in the most recent candidate exchange", and data is accepted
    /// from the remote candidate of any valid pair (one a connectivity check of this agent
    /// succeeded on). A peer that sends before it nominates, or from a pair it moved to, is
    /// then heard. Turning this on restores the fork's hardening: everything from another
    /// address is dropped before DTLS sees it.
    pub fn with_ice_data_from_selected_pair_only(mut self, enabled: bool) -> Self {
        self.0.ice.data_from_selected_pair_only = enabled;
        self
    }

    /// Lets data be sent on the best valid candidate pair before a pair is selected (RFC 8445
    /// section 12.1: "An ICE agent MAY send data on any valid pair before selected pairs have
    /// been produced"). Off by default. With it a DTLS server answers a ClientHello that
    /// arrives before the nomination does.
    pub fn with_ice_data_before_nomination(mut self, enabled: bool) -> Self {
        self.0.ice.send_data_before_nomination = enabled;
        self
    }

    /// Sets a filter asked about every remote candidate's address (an mDNS candidate's once it
    /// resolves) before the ICE agent holds it; `false` drops the candidate, so no check is ever
    /// sent there. Use it to apply the host's own network policy to peer-chosen destinations.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    /// use std::sync::Arc;
    ///
    /// // Drop every remote candidate on a loopback address.
    /// let _setting_engine = SettingEngineBuilder::new()
    ///     .with_remote_address_filter(Arc::new(|addr: std::net::SocketAddr| {
    ///         !addr.ip().is_loopback()
    ///     }))
    ///     .build();
    /// ```
    pub fn with_remote_address_filter(mut self, filter: RemoteAddressFilter) -> Self {
        self.0.candidates.remote_address_filter = Some(filter);
        self
    }

    /// Controls where DTLS fingerprints are placed in SDP.
    ///
    /// By default, fingerprints are placed at the session level. Setting this
    /// to `true` places them at the media level instead, which improves
    /// compatibility with some WebRTC implementations.
    ///
    /// # Parameters
    ///
    /// * `sdp_media_level_fingerprints` - `true` for media-level, `false` for session-level
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Use media-level fingerprints for better compatibility
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_sdp_media_level_fingerprints(true)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_sdp_media_level_fingerprints(mut self, sdp_media_level_fingerprints: bool) -> Self {
        self.0.sdp_media_level_fingerprints = sdp_media_level_fingerprints;
        self
    }

    /// Leaves the `a=tls-id` attribute (RFC 8842 section 4) out of offers and answers.
    ///
    /// By default every offer carries the DTLS association's `tls-id` on its first m-section
    /// (the BUNDLE tag), and an answer carries one when the offer did: the value stays the same
    /// while the association is kept and changes when a new one is asked for. Peers that do not
    /// know the attribute ignore it. Set `true` only for a peer that cannot take an unknown
    /// attribute. A received `a=tls-id` is read either way.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_disable_sdp_tls_id(true)
    ///     .build();
    /// ```
    pub fn with_disable_sdp_tls_id(mut self, is_disabled: bool) -> Self {
        self.0.disable_sdp_tls_id = is_disabled;
        self
    }

    /// Offers the DTLS `use_srtp` extension on every association, as browsers do, instead of
    /// only on one that carries SRTP media.
    ///
    /// RFC 5764 section 4.1: "The use_srtp extension MUST only be used when the data being
    /// transported is RTP or RTCP". By default the engine follows it: as the DTLS client it
    /// offers `use_srtp` when the session has an audio or video section, and a
    /// data-channel-only session is set up without it. When such a session gains a media
    /// section later, a new DTLS association is established for it (the offer carries a new
    /// `a=tls-id`, RFC 8842): a peer that does not act on `tls-id`, a browser for one, will
    /// not follow, and the media cannot flow. (As the DTLS server the engine takes a profile
    /// whenever the client offers one.)
    ///
    /// Set `true` to talk to such peers when media may be added to a data-channel-only
    /// session, or to peers that refuse an association without `use_srtp` (pion-lineage
    /// stacks fail their DTLS transport when no SRTP profile was negotiated).
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_dtls_use_srtp_on_every_association(true)
    ///     .build();
    /// ```
    pub fn with_dtls_use_srtp_on_every_association(mut self, on_every_association: bool) -> Self {
        self.0.dtls_use_srtp_on_every_association = on_every_association;
        self
    }

    /// Reads lower-case hex digits in a remote `a=fingerprint`, as browsers do.
    ///
    /// RFC 8122 section 5 defines the fingerprint as upper-case hex (`2UHEX *(":" 2UHEX)`), and
    /// by default a description with anything else is refused as malformed. Set `true` for a
    /// peer that writes lower-case digits.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_lowercase_fingerprints_accepted(true)
    ///     .build();
    /// ```
    pub fn with_lowercase_fingerprints_accepted(mut self, is_accepted: bool) -> Self {
        self.0.accept_lowercase_fingerprints = is_accepted;
        self
    }

    /// Whether answers and subsequent offers repeat the BUNDLE attributes (the IDENTICAL and
    /// TRANSPORT categories of RFC 8859: `a=ice-ufrag`, `a=ice-pwd`, `a=setup`, media-level
    /// `a=fingerprint`, `a=rtcp-mux`, `a=rtcp-mux-only`, `a=rtcp-rsize`, candidates) in every
    /// bundled m= section. The default is `true`.
    ///
    /// RFC 9143 section 7.1.3 (and RFC 9429 sections 5.2.2 and 5.3.1): "In a subsequent offer
    /// or in an answer ... the offerer and answerer MUST include IDENTICAL and TRANSPORT
    /// multiplexing category SDP attributes (BUNDLE attributes) only in the tagged 'm='
    /// section" and "MUST NOT include such attributes in any other bundled 'm=' section".
    /// `false` writes that form.
    ///
    /// It is not the default because no browser takes it: given an answer or a subsequent
    /// offer whose second bundled section has no `a=rtcp-mux` of its own, Chromium and WebKit
    /// refuse the description with "rtcp-mux must be enabled when BUNDLE is enabled" and
    /// Firefox with "m-section at level 1 is missing a=rtcp-mux, which is required by
    /// rtcpMuxPolicy" (browser matrix, 2026-11-22). Browsers themselves repeat the
    /// attributes.
    ///
    /// Either form is accepted from the remote side whatever this is set to: the tagged
    /// section's attributes apply to every bundled section.
    pub fn with_bundle_attributes_repeated(mut self, repeated: bool) -> Self {
        self.0.bundle_attributes_tagged_only = !repeated;
        self
    }

    /// Whether a remote offer that arrives while a local offer is pending rolls the local
    /// offer back and is applied, in one `set_remote_description` call. The default is `true`.
    ///
    /// W3C webrtc-pc section 4.4.2, the `setRemoteDescription` steps: a description of type
    /// "offer" that "is invalid for the current connection.[[SignalingState]] as described in
    /// [RFC9429]" has the local description set to `{type: "rollback"}` first, and is then
    /// set. This engine's
    /// `set_remote_description` is that operation, browsers perform it and "perfect
    /// negotiation" relies on it. RFC 9429 does not forbid it: its state machine (section
    /// 3.2) is kept, because the rollback is applied first (section 5.7) and the offer is
    /// then applied in `stable` (section 5.6).
    ///
    /// With `false` the layer above does the rollback: a remote offer in `have-local-offer`
    /// is refused, as RFC 9429 section 5.6 has it for a description whose type is not valid
    /// in the current state.
    ///
    /// An offer that is refused after the implicit rollback leaves the local offer pending,
    /// as if nothing had been called; one that is applied emits the `stable` and then the
    /// `have-remote-offer` signaling state.
    pub fn with_implicit_rollback(mut self, implicit_rollback: bool) -> Self {
        self.0.explicit_rollback_only = !implicit_rollback;
        self
    }

    /// Whether the bundle policy `max-bundle` is honoured as the policy RFC 9429 names
    /// `must-bundle`. The default is `true`.
    ///
    /// W3C webrtc-pc section 4.2.5 (`RTCBundlePolicy`) defines `max-bundle` ("Gather ICE
    /// candidates for only one track. If the remote endpoint is not bundle-aware, negotiate
    /// only one media track") and has no `must-bundle`; RFC 9429 section 4.1.1 introduces
    /// "an identically defined 'must-bundle' policy". So both names select the one policy:
    /// every m= section of an initial offer but the first is bundle-only.
    ///
    /// RFC 9429 section 4.1.1 also says "'max-bundle' is considered deprecated, and
    /// implementations compliant with this specification SHOULD ignore attempts by the
    /// application to select this bundle policy (although some phase-out period may be
    /// necessary to avoid application breakage)". `false` does that: a configuration with
    /// `RTCBundlePolicy::MaxBundle` then behaves as the default policy, `balanced`.
    pub fn with_max_bundle_as_must_bundle(mut self, honoured: bool) -> Self {
        self.0.max_bundle_ignored = !honoured;
        self
    }

    // SetICETCPMux enables ICE-TCP when set to a non-nil value. Make sure that
    // NetworkTypeTCP4 or NetworkTypeTCP6 is enabled as well.
    //pub fn SetICETCPMux(&mut self, tcpMux ice.TCPMux) {
    //    self.0.iceTCPMux = tcpMux
    //}

    // SetICEProxyDialer sets the proxy dialer interface based on golang.org/x/net/proxy.
    //pub fn SetICEProxyDialer(&mut self, d proxy.Dialer) {
    //    self.0.iceProxyDialer = d
    //}

    /// Prevents the MediaEngine from being copied for each PeerConnection.
    ///
    /// By default, each PeerConnection gets a copy of the MediaEngine, allowing
    /// independent codec configurations. Disabling this allows sharing a single
    /// MediaEngine and modifying it after PeerConnection creation.
    ///
    /// # Parameters
    ///
    /// * `is_disabled` - `true` to share MediaEngine, `false` to copy (default)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Share MediaEngine across connections
    /// # #[allow(deprecated)]
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_disable_media_engine_copy(true)
    ///     .build();
    ///
    /// // Warning: Don't share MediaEngine between multiple PeerConnections
    /// // unless you understand the implications
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Warning
    ///
    /// When disabled, ensure you don't share the same MediaEngine between
    /// multiple PeerConnections unless you specifically intend to do so.
    ///
    /// # Not read by this engine
    ///
    /// A PeerConnection takes its `MediaEngine` by value from the builder, so it always has
    /// its own; there is no shared engine to copy or not. This value is stored for API
    /// compatibility with pion and never read.
    #[deprecated(
        note = "a no-op: a peer connection always owns its MediaEngine (the builder takes it \
                by value), so there is no copy to disable"
    )]
    pub fn with_disable_media_engine_copy(mut self, is_disabled: bool) -> Self {
        self.0.disable_media_engine_copy = is_disabled;
        self
    }

    /// Disables negotiating different codecs for different media sections.
    ///
    /// By default, each media section in the SDP can negotiate different codecs,
    /// which is the spec-compliant behavior. This setting forces all media
    /// sections to use the same codecs.
    ///
    /// # Parameters
    ///
    /// * `is_disabled` - `true` to use single codec set, `false` for per-section (default)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Force same codecs for all media sections
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_disable_media_engine_multiple_codecs(true)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Deprecation Note
    ///
    /// This setting is targeted for removal in a future release (4.2.0 or later).
    ///
    /// # What it changes
    ///
    /// By default every remote description adds the formats of each of its audio and video
    /// sections to the codecs the connection has negotiated, so a second video section that
    /// offers only H.264 is answered with H.264 even when the first one negotiated VP8
    /// (RFC 9429, Section 5.10). A format is kept once, under the first payload type that
    /// named it. With `true`, only the first section of each kind (in the first remote
    /// description that has one) decides the codecs, and later sections are answered from
    /// that set.
    pub fn with_disable_media_engine_multiple_codecs(mut self, is_disabled: bool) -> Self {
        self.0.disable_media_engine_multiple_codecs = is_disabled;
        self
    }

    /// Sets the MTU size for the receive buffer.
    ///
    /// This controls the maximum size of packets that can be received. Leave
    /// at 0 to use the default MTU (1460 bytes, equal to UDP MTU).
    ///
    /// # Parameters
    ///
    /// * `receive_mtu` - MTU size in bytes, or 0 for default
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Use larger MTU for jumbo frames
    /// # #[allow(deprecated)]
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_receive_mtu(9000)
    ///     .build();
    ///
    /// // Or use default
    /// # #[allow(deprecated)]
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_receive_mtu(0)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Not read by this engine
    ///
    /// The sans-I/O engine reads no sockets: the application receives each datagram into its
    /// own buffer and hands it over whole, so there is no receive buffer to size. This value
    /// is stored for API compatibility with pion and never read.
    #[deprecated(
        note = "a no-op: the sans-I/O engine reads no sockets; size the application's own \
                receive buffer instead"
    )]
    pub fn with_receive_mtu(mut self, receive_mtu: usize) -> Self {
        self.0.receive_mtu = receive_mtu;
        self
    }

    /// Sets a custom MID (media stream ID) generator function.
    ///
    /// By default, MIDs are generated automatically. This allows you to provide
    /// a custom generation scheme, useful for reducing complexity when handling
    /// SDP offer/answer collisions.
    ///
    /// # Parameters
    ///
    /// * `f` - Function that takes the highest seen numeric MID and returns a new MID string
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Generate MIDs with a custom prefix
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_mid_generator(|max_mid| format!("custom_{}", max_mid + 1))
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Note
    ///
    /// - MIDs should be generated without leaking user information (e.g., randomly)
    /// - MIDs should be 3 bytes or less for efficient RTP header extension encoding
    /// - The `isize` argument is the greatest seen _numeric_ MID (doesn't include non-numeric MIDs)
    ///
    /// # See Also
    ///
    /// - [RFC 8843 - MID](https://datatracker.ietf.org/doc/html/rfc8843)
    ///
    /// `create_offer` calls it for each transceiver that has no mid yet, then moves the
    /// argument on (to the generated mid when it is a greater number, else by one), so two
    /// new transceivers of one offer get different arguments.
    pub fn with_mid_generator(
        mut self,
        f: impl Fn(isize) -> String + Send + Sync + 'static,
    ) -> Self {
        self.0.mid_generator = Some(Arc::new(f));
        self
    }

    /// Sets the maximum message size for SCTP data channels.
    ///
    /// This controls the largest message that can be sent through a data channel.
    /// Larger messages will be fragmented or rejected depending on the configuration.
    ///
    /// # Parameters
    ///
    /// * `max_message_size` - Maximum size (Bounded or Unbounded)
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::setting_engine::{
    ///     SctpMaxMessageSize, SettingEngineBuilder,
    /// };
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Use default 64KB
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_sctp_max_message_size(SctpMaxMessageSize::Bounded(
    ///         SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE,
    ///     ))
    ///     .build();
    ///
    /// // Or allow larger messages
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_sctp_max_message_size(SctpMaxMessageSize::Bounded(256 * 1024)) // 256KB
    ///     .build();
    ///
    /// // Or unbounded (uses MAX_MESSAGE_SIZE internally)
    /// let setting_engine = SettingEngineBuilder::new()
    ///     .with_sctp_max_message_size(SctpMaxMessageSize::Unbounded)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [RFC 8841 §6.1 - max-message-size](https://datatracker.ietf.org/doc/html/rfc8841#section-6.1)
    pub fn with_sctp_max_message_size(mut self, max_message_size: SctpMaxMessageSize) -> Self {
        self.0.sctp_max_message_size = max_message_size;
        self
    }

    /// Overrides the SCTP receive-buffer size (the a_rwnd flow-control window), in bytes.
    ///
    /// This bounds how much unacknowledged data a peer may have in flight toward this
    /// endpoint — a bandwidth-delay-product ceiling. Lowering it reduces per-connection
    /// memory (the buffer fills only under load), which matters for servers holding many
    /// connections; but a smaller window can throttle throughput on high-latency,
    /// high-bandwidth paths, where more data must be in flight to keep the pipe full.
    ///
    /// **Bounds.** RFC 9260 §3.3.2 requires an advertised initial a_rwnd of at least **1500
    /// bytes**; smaller values (including `0`) are raised to that floor here, because a
    /// sub-1500 window makes the peer reject this endpoint's INIT/INIT-ACK and the SCTP
    /// association never establishes. The window should also be **≥ the largest SCTP
    /// message this endpoint will receive** ([`SettingEngineBuilder::with_sctp_max_message_size`], default
    /// 64 KiB): a buffer smaller than one message cannot hold it for reassembly, so a
    /// full-size inbound message would stall that receive direction. `0` here is *not*
    /// "unbounded" (unlike some other knobs) — to keep the default window, leave this
    /// unset (the default is `INITIAL_RECV_BUF_SIZE`, 1 MiB).
    pub fn with_sctp_max_receive_buffer_size(mut self, size: u32) -> Self {
        // RFC 9260 §3.3.2 (INIT) and §3.3.3 (INIT ACK) forbid advertising an initial a_rwnd
        // below 1500 bytes ("The Advertised Receiver Window Credit MUST NOT be smaller than
        // 1500. A receiver of an INIT chunk with the a_rwnd value set to a value smaller than
        // 1500 MUST discard the packet [and] SHOULD send [...] an ABORT chunk."). This crate
        // enforces it in `ChunkInit::check()` (ErrInitAdvertisedReceiver1500), so a
        // sub-1500 (or 0) value would silently break the handshake. Clamp up to that floor.
        const MIN_SCTP_RECEIVE_BUFFER_SIZE: u32 = 1500;
        if size < MIN_SCTP_RECEIVE_BUFFER_SIZE {
            log::warn!(
                "sctp receive buffer size {size} is below the RFC 9260 minimum; raising to \
                 {MIN_SCTP_RECEIVE_BUFFER_SIZE} bytes"
            );
        }

        self.0.sctp_max_receive_buffer_size = Some(size.max(MIN_SCTP_RECEIVE_BUFFER_SIZE));
        self
    }

    /// Overrides the SCTP MTU: the size budget, in bytes, for each outbound DATA packet
    /// (common header plus bundled DATA chunks) this endpoint emits. A SACK keeps within it
    /// too, carrying the gap blocks and duplicate TSNs that fit. Other control packets
    /// (INIT, INIT ACK, RECONFIG, FORWARD TSN, shutdown) marshal without consulting this value.
    ///
    /// Each SCTP packet becomes one DTLS record carried in one UDP datagram, so the wire
    /// size is this value plus the DTLS record overhead (13 bytes of header and what the
    /// cipher suite adds: 24 bytes with AES-GCM, 16 with ChaCha20-Poly1305), the UDP and IP
    /// headers, and 4 bytes of TURN ChannelData framing when relayed.
    ///
    /// Left unset, the budget follows the path: RFC 8831 section 5 says the initial path MTU
    /// at the IP layer "SHOULD NOT exceed 1200 bytes for IPv4 and 1280 bytes for IPv6", and
    /// the association does not probe for more, so an SCTP packet is what is left of that
    /// under the headers of the selected candidate pair and the negotiated DTLS cipher suite
    /// (1135 bytes over IPv4 and UDP with AES-GCM, 1195 over IPv6), recomputed when ICE
    /// selects another pair. Until a pair is selected it is 1191 (the TURN-relayed IPv6
    /// budget, webrtc-rs/rtc#178). Set this only for paths with a known different budget:
    /// raise it where the path genuinely carries more (fewer, larger packets cut per-packet
    /// overhead), lower it for tunnels with an even smaller MTU. A value set here is used as
    /// it is on every path.
    ///
    /// The per-chunk payload budget is derived from this value by the inverse of the
    /// default derivation (minus the 12-byte common header and 16-byte DATA chunk header,
    /// rounded down to the SCTP 4-byte chunk-padding boundary), so a single maximum-size
    /// DATA chunk always marshals within this budget. Values below 32 — the smallest
    /// representable padded DATA packet — are raised to 32 with a warning.
    pub fn with_sctp_mtu(mut self, mtu: u32) -> Self {
        self.0.sctp_mtu = Some(mtu);
        self
    }

    /// Whether SCTP sends from its data channels by weighted fair queueing (RFC 8260 section
    /// 3.6), each channel's share of the bytes in proportion to its priority. On by default:
    /// RFC 8831 section 6.4 says the priorities of data channels "MUST be interpreted as
    /// weighted-fair-queuing scheduling priorities per the definition of the corresponding
    /// stream scheduler supporting interleaving in [RFC8260]". `false` sends the messages in
    /// the order they were written, whatever their channel, and the priority of a channel is
    /// then carried to the peer and not otherwise used.
    pub fn with_sctp_weighted_fair_queueing(mut self, enabled: bool) -> Self {
        self.0.sctp_weighted_fair_queueing = Some(enabled);
        self
    }

    /// Whether SCTP announces user message interleaving (RFC 8260). On by default: RFC 8831
    /// sections 6.1 and 6.6 say it "SHOULD be used", so that a large message on one data
    /// channel does not hold up the others. It is used when the peer announces it too;
    /// otherwise the association sends DATA chunks, and nothing else changes. `false` does
    /// not announce it, which is what a browser that has not turned it on does.
    pub fn with_sctp_message_interleaving(mut self, enabled: bool) -> Self {
        self.0.sctp_message_interleaving = Some(enabled);
        self
    }

    /// Whether SCTP announces that it accepts packets with a zero checksum (RFC 9653) and
    /// sends them to a peer that announces the same. On by default: the association runs over
    /// DTLS, whose record protection detects errors better than the CRC32c (RFC 9653 section
    /// 6, "SCTP over DTLS"), and section 5.2 says an endpoint "SHOULD use zero as the checksum"
    /// then. A peer that does not announce it gets a CRC32c on every packet, and must send
    /// one. `false` does not announce it.
    pub fn with_sctp_zero_checksum(mut self, enabled: bool) -> Self {
        self.0.sctp_zero_checksum = Some(enabled);
        self
    }

    /// Whether a message over 16 KB is refused when the SCTP association does not interleave
    /// user messages. On by default: RFC 8831 section 6.6 says "As long as message
    /// interleaving is not supported, the sender SHOULD limit the maximum message size to
    /// 16 KB to avoid monopolization", since such a message holds up every other data channel
    /// until all of it has been sent. With the limit,
    /// [`RTCSctpTransport::max_message_size`](crate::peer_connection::transport::RTCSctpTransport::max_message_size)
    /// reports at most 16384 once the association is up without interleaving, and `send`
    /// refuses a larger message. Between two endpoints that both interleave (two of this
    /// engine, by default) the limit does not apply.
    ///
    /// `false` is what browsers do: they send messages up to the peer's `max-message-size`
    /// whether or not the association interleaves, and current browsers do not announce
    /// interleaving. An application that sends more than 16 KB at a time to a browser sets
    /// this to `false`.
    pub fn with_sctp_message_size_limit_without_interleaving(mut self, enabled: bool) -> Self {
        self.0.sctp_message_size_limit_without_interleaving = Some(enabled);
        self
    }

    /// Writes the pause mark `~` of `a=simulcast` (RFC 8853 section 5.2) although RTP stream
    /// pause and resume (RFC 7728) is not negotiated: for an inactive encoding of a sender,
    /// and for a stream the offer being answered marks. The default is `false`.
    ///
    /// RFC 8853 section 5.2: "The use of [the pause mark] MUST be accompanied by support
    /// for RTP stream pause/resume [RFC7728] ... signaled under the same 'm=' line", and
    /// section 5.3.2: an answerer "MUST NOT" mark a stream paused when the offer shows no
    /// such support. The engine does not implement RFC 7728 and never signals it, so by
    /// default it writes no `~`: an inactive encoding is listed and not sent, and an offered
    /// `~` is answered without the mark. `true` writes the mark all the same, as libwebrtc
    /// does for inactive layers.
    pub fn with_rid_pause_marks(mut self, rid_pause_marks: bool) -> Self {
        self.0.rid_pause_marks = rid_pause_marks;
        self
    }

    /// With [`Self::with_rid_pause_marks`], controls whether the `~` an offer puts on a
    /// stream it asks to receive is left out of the answer's `send` list.
    ///
    /// # Parameters
    ///
    /// * `ignore_rid_pause_for_recv` - `true` to leave the mark out, `false` to repeat it
    pub fn with_ignore_rid_pause_for_recv(mut self, ignore_rid_pause_for_recv: bool) -> Self {
        self.0.ignore_rid_pause_for_recv = ignore_rid_pause_for_recv;
        self
    }

    /// Controls whether to ignore SSRC attribute in SDP's sendonly or sendrecv for simulcast
    ///
    /// # Parameters
    ///
    /// * `write_ssrc_attributes_for_simulcast` - `true` to write, `false` to ignore
    pub fn with_write_ssrc_attributes_for_simulcast(
        mut self,
        write_ssrc_attributes_for_simulcast: bool,
    ) -> Self {
        self.0.write_ssrc_attributes_for_simulcast = write_ssrc_attributes_for_simulcast;
        self
    }

    /// Explicit Congestion Notification (RFC 3168) and L4S (RFC 9331) on RTP media.
    ///
    /// Turn this on when the application's socket layer carries ECN both ways:
    ///
    /// * **Receive**: each datagram handed to `handle_read` names the codepoint it arrived with
    ///   in [`TransportContext::ecn`](shared::TransportContext::ecn) (from the `IP_RECVTOS` /
    ///   `IPV6_RECVTCLASS` control message; `None` for Not-ECT).
    /// * **Send**: each datagram `poll_write` returns names the codepoint to set in
    ///   [`TransportContext::ecn`](shared::TransportContext::ecn) (`IP_TOS` / `IPV6_TCLASS`;
    ///   `None` for Not-ECT).
    ///
    /// With it on, every RTP packet (RTX included) of a stream whose codec negotiated RFC 8888
    /// congestion control feedback (`a=rtcp-fb:<pt> ack ccfb`, see
    /// `configure_congestion_control_feedback`) is sent ECT(1), the L4S identifier: a sender
    /// marks only where the receiver reports the CE marks back. STUN, DTLS, SCTP and RTCP are
    /// never marked. Inbound RTP streams count their ECT(1) and CE receptions
    /// (`packetsReceivedWithEct1`, `packetsReceivedWithCe`) and outbound ones their ECT(1)
    /// packets (`packetsSentWithEct1`); with it off those members are left out of the stats,
    /// since the engine cannot see the IP header itself. Off by default.
    pub fn with_ecn(mut self, enabled: bool) -> Self {
        self.0.ecn = enabled;
        self
    }

    /// Finalises the settings.
    pub fn build(self) -> SettingEngine {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression guard for the Safari mDNS interop fix. Safari (and Chrome)
    // emit only mDNS "<uuid>.local" host candidates by default; a default
    // SettingEngine must accept and resolve them (QueryOnly), not silently
    // discard them (Disabled).
    #[test]
    fn test_default_multicast_dns_mode_is_query_only() {
        assert_eq!(MulticastDNS::default().mode, MulticastDnsMode::QueryOnly);
        assert_eq!(
            SettingEngine::default().multicast_dns.mode,
            MulticastDnsMode::QueryOnly
        );
    }

    #[test]
    fn test_turn_allocation_refresh_interval_cap() {
        assert_eq!(
            SettingEngine::default().turn_allocation_refresh_interval_cap(),
            None
        );

        let cap = Duration::from_secs(30);
        let setting_engine = SettingEngineBuilder::new()
            .with_turn_allocation_refresh_interval_cap(cap)
            .build();

        assert_eq!(
            setting_engine.turn_allocation_refresh_interval_cap(),
            Some(cap)
        );
    }

    #[test]
    fn test_ice_credentials_roundtrip() {
        let setting_engine = SettingEngine::default();
        assert_eq!(setting_engine.ice_credentials(), ("", ""));

        let setting_engine = SettingEngineBuilder::new()
            .with_ice_credentials("ufrag".to_owned(), "password".to_owned())
            .build();
        assert_eq!(setting_engine.ice_credentials(), ("ufrag", "password"));

        let mut setting_engine = SettingEngine::default();
        setting_engine.set_ice_credentials("other_ufrag".to_owned(), "other_password".to_owned());
        assert_eq!(
            setting_engine.ice_credentials(),
            ("other_ufrag", "other_password")
        );
    }
}
