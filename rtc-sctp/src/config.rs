use crate::util::{
    AssociationIdGenerator, RandomAssociationIdGenerator, RandomSource,
    SourcedAssociationIdGenerator,
};

use crate::association::pmtud::PathMtuDiscoveryConfig;
use crate::{RtoConfig, TimerConfig};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// The smallest a_rwnd an INIT or INIT ACK may carry (RFC 9260 3.3.2, 3.3.3).
pub(crate) const MIN_ADVERTISED_RECEIVER_WINDOW: u32 = 1500;

/// MTU for inbound packet (from DTLS)
pub(crate) const RECEIVE_MTU: usize = 8192;
/// Initial MTU for outgoing packets (to DTLS): bounds the assembled SCTP
/// packet (common header + bundled chunks). Each SCTP packet becomes one
/// DTLS record carried in one UDP datagram, so the wire size is roughly
/// `INITIAL_MTU` + ~37 bytes of DTLS record overhead + 48 bytes of IPv6/UDP
/// headers. 1191 keeps that within the 1280-byte IPv6 minimum MTU advertised
/// by common tunnel paths (WireGuard, Tailscale); the previous 1228
/// overflowed it (~1313 wire bytes), and because retransmissions re-bundle
/// to the same oversized packet, a dropped flight stalled forever with no
/// surfaced error. 1191 is the exact TURN-relayed IPv6 budget
/// (1280 - 40 IPv6 - 8 UDP - 4 TURN ChannelData - 37 DTLS), the derivation
/// from pion/sctp#476, adopted by webrtc-rs/webrtc#807 (webrtc v0.17.2).
pub(crate) const INITIAL_MTU: u32 = 1191;
pub(crate) const INITIAL_RECV_BUF_SIZE: u32 = 1024 * 1024;
pub(crate) const COMMON_HEADER_SIZE: u32 = 12;
pub(crate) const DATA_CHUNK_HEADER_SIZE: u32 = 16;
/// Floor for [`max_payload_size_for_mtu`]: the smallest representable padded
/// DATA packet — the 12-byte common header, the 16-byte DATA chunk header, and
/// a 1..=4-byte payload padded to the 4-byte chunk boundary.
pub const MIN_DATA_PACKET_MTU: u32 = COMMON_HEADER_SIZE + DATA_CHUNK_HEADER_SIZE + 4;

/// Derive an [`EndpointConfig::max_payload_size`] value from an outbound
/// DATA-packet budget: the largest DATA packet (common header plus bundled
/// DATA chunks) associations may emit, in bytes. Control packets (INIT,
/// INIT ACK, SACK, RECONFIG, FORWARD TSN, shutdown) marshal without
/// consulting this value.
///
/// This is the inverse of the default derivation: `mtu` minus the two fixed
/// headers, rounded down to the SCTP 4-byte chunk-padding boundary, so a
/// single maximum-size DATA chunk always marshals to at most `mtu` bytes —
/// exactly as the default budget does for `INITIAL_MTU` (1191, the
/// TURN-relayed IPv6 minimum-MTU budget). Budgets below
/// [`MIN_DATA_PACKET_MTU`] cannot satisfy that promise and are raised to it
/// with a warning.
pub fn max_payload_size_for_mtu(mtu: u32) -> u32 {
    if mtu < MIN_DATA_PACKET_MTU {
        log::warn!(
            "sctp mtu {mtu} is below the smallest representable DATA packet; raising to \
             {MIN_DATA_PACKET_MTU} bytes"
        );
    }
    let mtu = mtu.max(MIN_DATA_PACKET_MTU);
    (mtu - (COMMON_HEADER_SIZE + DATA_CHUNK_HEADER_SIZE)) & !3
}
pub(crate) const DEFAULT_MAX_MESSAGE_SIZE: u32 = 262144;

/// How an association picks the stream whose data it sends next: the stream schedulers of
/// RFC 8260 section 3.
///
/// Without user message interleaving a message that is part sent is finished before another
/// stream is served, so a scheduler chooses between messages. With interleaving
/// ([`TransportConfig::with_message_interleaving`], when the peer supports it too) it chooses
/// for every chunk, and a large message no longer holds the others up.
///
/// A stream's priority is set with [`Stream::set_priority`](crate::Stream::set_priority).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamScheduler {
    /// Messages leave in the order they were written, whatever their stream (RFC 8260
    /// section 3.1).
    #[default]
    FirstComeFirstServed,
    /// The streams with something to send take turns: a message each, or a chunk each when
    /// interleaving (section 3.2).
    RoundRobin,
    /// Round robin that changes stream only when a new packet is started, so a packet
    /// carries the data of one stream and its loss holds up that stream alone (section 3.3).
    RoundRobinPerPacket,
    /// The stream with the highest priority goes first, as long as it has something to send;
    /// streams of equal priority take turns (section 3.4).
    Priority,
    /// Each stream gets the same share of the bytes sent (section 3.5).
    FairCapacity,
    /// Each stream gets a share of the bytes sent in proportion to its priority, taken as
    /// its weight (section 3.6, which RFC 8831 section 6.4 asks of WebRTC).
    WeightedFairQueueing,
}

/// Config collects the arguments to create_association construction into
/// a single structure
#[derive(Debug, Clone)]
pub struct TransportConfig {
    sctp_port: u16,
    remote_sctp_port: u16,
    max_receive_buffer_size: u32,
    max_message_size: u32,
    max_receive_message_size: Option<u32>,
    max_num_outbound_streams: u16,
    max_num_inbound_streams: u16,
    timer_config: TimerConfig,
    rto_config: RtoConfig,
    stream_scheduler: StreamScheduler,
    valid_cookie_life: Duration,
    heartbeat_interval: Option<Duration>,
    slow_start_growth_limit: u32,
    max_burst: Option<u32>,
    sack_delay: Duration,
    partial_reliability: bool,
    message_interleaving: bool,
    zero_checksum: bool,
    path_mtu_discovery: Option<PathMtuDiscoveryConfig>,
    zero_window_overcommit: bool,
    strict_zero_window_drop: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        TransportConfig {
            sctp_port: 5000,
            remote_sctp_port: 5000,
            max_receive_buffer_size: INITIAL_RECV_BUF_SIZE,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            max_receive_message_size: None,
            max_num_outbound_streams: u16::MAX,
            max_num_inbound_streams: u16::MAX,
            timer_config: TimerConfig::default(),
            rto_config: RtoConfig::default(),
            stream_scheduler: StreamScheduler::default(),
            valid_cookie_life: Duration::from_secs(60),
            heartbeat_interval: Some(Duration::from_secs(30)),
            slow_start_growth_limit: 1,
            max_burst: Some(4),
            sack_delay: Duration::from_millis(200),
            partial_reliability: true,
            message_interleaving: false,
            zero_checksum: false,
            path_mtu_discovery: None,
            zero_window_overcommit: false,
            strict_zero_window_drop: false,
        }
    }
}

impl TransportConfig {
    /// Whether a receiver that advertised a closed window (a_rwnd 0) still takes the next
    /// in-sequence DATA chunk when nothing is readable: the chunk that would complete a
    /// message the full buffer holds the start of (webrtc-rs/webrtc#822), up to one message
    /// beyond the buffer. Off by default: RFC 9260 section 6.2, "When the receiver's
    /// advertised window is 0, the receiver MUST drop any new incoming DATA chunk with a TSN
    /// larger than the largest TSN received so far". Without it a buffer full of incomplete
    /// messages stays full: what is written must fit the buffer, which it does when the
    /// largest message accepted (`with_max_receive_message_size`) is not larger than the
    /// receive buffer. While the advertised window is open, a full buffer takes that chunk
    /// either way (the RFC rule binds a closed advertised window only), and so does an
    /// association that negotiated user message interleaving (RFC 8260), whatever this
    /// setting: several part-received I-DATA messages, each smaller than the buffer, can fill
    /// it together with none of them complete.
    pub fn with_zero_window_overcommit(mut self, value: bool) -> Self {
        self.zero_window_overcommit = value;
        self
    }

    /// See [`with_zero_window_overcommit`](Self::with_zero_window_overcommit).
    pub fn zero_window_overcommit(&self) -> bool {
        self.zero_window_overcommit
    }

    /// RFC 9260 section 6.2 to the letter: once a SACK advertised a_rwnd 0, every new DATA
    /// chunk above the largest TSN received is dropped, with
    /// [`with_zero_window_overcommit`](Self::with_zero_window_overcommit) and with user
    /// message interleaving (RFC 8260) alike. Off by default.
    ///
    /// It can deadlock interleaved messages. With I-DATA several part-received messages,
    /// each smaller than the receive buffer, can fill it together with none of them
    /// complete: nothing is readable, so the application cannot free any of it; the window
    /// stays closed; and the chunk that would complete one of them is above the largest TSN,
    /// so it is dropped on every retransmission. (Six 16 KiB messages on six streams into a
    /// 16 KiB buffer deliver none.) Without interleaving it can deadlock a message larger than
    /// the buffer the same way. Use it only where every message fits the buffer and I-DATA is
    /// not negotiated, or where the RFC form matters more than delivery.
    pub fn with_strict_zero_window_drop(mut self, value: bool) -> Self {
        self.strict_zero_window_drop = value;
        self
    }

    /// See [`with_strict_zero_window_drop`](Self::with_strict_zero_window_drop).
    pub fn strict_zero_window_drop(&self) -> bool {
        self.strict_zero_window_drop
    }

    /// Path MTU discovery (DPLPMTUD, RFC 8899 section 6.2, with the PAD chunk of RFC 4820):
    /// once established, the association confirms its packet size (what
    /// [`Association::set_path_mtu`](crate::Association::set_path_mtu) set, else the
    /// default) with a probe, searches for a larger one up to
    /// [`PathMtuDiscoveryConfig::with_max_path_mtu`], and falls back to it when the path
    /// stops carrying the larger size (RFC 9260 section 7.3; RFC 8261 section 4: SCTP over
    /// DTLS "MUST implement and use" a discovery method that works without ICMP). `None`, the
    /// crate's default, keeps the packet size where the transport sets it: the transport
    /// knows the largest packet worth probing for, so it turns discovery on. The `rtc` peer
    /// connection does, by default (`SettingEngineBuilder::with_sctp_path_mtu_discovery`).
    pub fn with_path_mtu_discovery(mut self, value: Option<PathMtuDiscoveryConfig>) -> Self {
        self.path_mtu_discovery = value;
        self
    }

    /// The path MTU discovery settings, see
    /// [`with_path_mtu_discovery`](Self::with_path_mtu_discovery).
    pub fn path_mtu_discovery(&self) -> Option<PathMtuDiscoveryConfig> {
        self.path_mtu_discovery
    }

    /// Sets L of RFC 9260 section 7.2.1: in slow start one SACK grows the congestion window
    /// by at most the bytes it acknowledges and at most L packets (L x PMDCS). The RFC says L
    /// SHOULD be 1 and MAY be larger (RFC 3465 discusses the choice): 1 is the default. A
    /// receiver that acknowledges many packets with one SACK, as one that reads its socket in
    /// batches does, makes a sender with L = 1 leave slow start slowly; a larger L restores
    /// the faster ramp at the price the RFC names (a burst after such a SACK, and trust in
    /// the receiver not to split its acknowledgements). Zero counts as one.
    pub fn with_slow_start_growth_limit(mut self, value: u32) -> Self {
        self.slow_start_growth_limit = value.max(1);
        self
    }

    /// L, see [`with_slow_start_growth_limit`](Self::with_slow_start_growth_limit).
    pub fn slow_start_growth_limit(&self) -> u32 {
        self.slow_start_growth_limit
    }

    /// Whether PR-SCTP (RFC 3758) is announced to the peer and used. On by default, as WebRTC
    /// data channels need it (RFC 8831 section 6.1). Off, neither chunk 192 nor the
    /// Forward-TSN-Supported parameter is announced, no message is ever abandoned, and a
    /// FORWARD TSN from the peer is answered as an unrecognized chunk.
    pub fn with_partial_reliability(mut self, value: bool) -> Self {
        self.partial_reliability = value;
        self
    }

    /// See [`with_partial_reliability`](Self::with_partial_reliability).
    pub fn partial_reliability(&self) -> bool {
        self.partial_reliability
    }

    /// Whether user message interleaving (RFC 8260) is announced to the peer. When the peer
    /// announces it too, user data travels in I-DATA chunks: the fragments of messages on
    /// different streams may be interleaved, so a large message on one stream no longer
    /// holds up the others, and the [stream scheduler](Self::with_stream_scheduler) chooses
    /// the stream for every chunk. RFC 8831 section 6.1 says WebRTC data channels SHOULD use
    /// it. Off by default; an application reads whole messages either way, so it needs no
    /// change to turn it on.
    pub fn with_message_interleaving(mut self, value: bool) -> Self {
        self.message_interleaving = value;
        self
    }

    /// See [`with_message_interleaving`](Self::with_message_interleaving).
    pub fn message_interleaving(&self) -> bool {
        self.message_interleaving
    }

    /// Says that the association runs over DTLS (RFC 8261), which detects errors better than
    /// SCTP's CRC32c does, and so allows the zero checksum of RFC 9653 with the "SCTP over
    /// DTLS" error detection method (section 6):
    ///
    /// - the INIT or INIT ACK carries the Zero Checksum Acceptable parameter, and packets
    ///   that arrive with a checksum of zero are taken, their CRC32c not computed;
    /// - when the peer announces the same, packets are sent with a checksum of zero and
    ///   their CRC32c is not computed either. The packets RFC 9653 section 5.2 excepts keep
    ///   a correct one: an INIT, a COOKIE ECHO, an answer to an out-of-the-blue packet.
    ///
    /// Off by default: every packet carries its CRC32c and one without is dropped. It MUST
    /// NOT be turned on for an association that does not run over DTLS; a WebRTC data
    /// channel transport always does.
    pub fn with_zero_checksum(mut self, value: bool) -> Self {
        self.zero_checksum = value;
        self
    }

    /// See [`with_zero_checksum`](Self::with_zero_checksum).
    pub fn zero_checksum(&self) -> bool {
        self.zero_checksum
    }

    /// Sets SACK.Delay (RFC 9260 sections 6.2 and 16): how long the acknowledgement of a DATA
    /// chunk may wait for a second one. Defaults to 200 ms. The RFC forbids more than 500 ms,
    /// so a longer delay is taken as 500 ms.
    pub fn with_sack_delay(mut self, value: Duration) -> Self {
        self.sack_delay = value.min(Duration::from_millis(500));
        self
    }

    /// SACK.Delay, see [`with_sack_delay`](Self::with_sack_delay).
    pub fn sack_delay(&self) -> Duration {
        self.sack_delay
    }

    /// Sets Max.Burst (RFC 9260 sections 6.1 D and 16): before DATA is sent the congestion
    /// window is brought down to what is outstanding plus this many packets, so that one
    /// SACK for many packets does not release as many at once. Defaults to 4, the value the
    /// RFC recommends. `None` applies no limit: a peer that acknowledges in batches (one that
    /// reads its socket in bursts) otherwise has this side's window cut back on every SACK.
    pub fn with_max_burst(mut self, value: Option<u32>) -> Self {
        self.max_burst = value;
        self
    }

    /// Max.Burst, see [`with_max_burst`](Self::with_max_burst).
    pub fn max_burst(&self) -> Option<u32> {
        self.max_burst
    }

    /// Sets HB.interval (RFC 9260 8.3, 16): an association whose path has been idle for an RTO
    /// plus this long sends a HEARTBEAT, which measures the round trip and shows that the peer
    /// is still there. One left unanswered counts toward
    /// [`TimerConfig::max_t3_rtx_retrans`](crate::TimerConfig). Defaults to 30 seconds; `None`
    /// sends no HEARTBEAT.
    pub fn with_heartbeat_interval(mut self, value: Option<Duration>) -> Self {
        self.heartbeat_interval = value;
        self
    }

    /// HB.interval, see [`with_heartbeat_interval`](Self::with_heartbeat_interval).
    pub fn heartbeat_interval(&self) -> Option<Duration> {
        self.heartbeat_interval
    }

    /// Sets Valid.Cookie.Life: how long after an INIT ACK its State Cookie is accepted in a
    /// COOKIE ECHO (RFC 9260 5.1.3, 16). Later it is refused with a "Stale Cookie" error and
    /// the peer starts again. Defaults to 60 seconds.
    pub fn with_valid_cookie_life(mut self, value: Duration) -> Self {
        self.valid_cookie_life = value;
        self
    }

    /// Valid.Cookie.Life, see [`with_valid_cookie_life`](Self::with_valid_cookie_life).
    pub fn valid_cookie_life(&self) -> Duration {
        self.valid_cookie_life
    }

    /// Sets this endpoint's SCTP port, the source port of what it sends (RFC 8841 5: its own
    /// `a=sctp-port`). Defaults to 5000.
    pub fn with_sctp_port(mut self, value: u16) -> Self {
        self.sctp_port = value;
        self
    }

    /// Sets the peer's SCTP port, the destination port of the INIT this endpoint sends when it
    /// initiates (RFC 8841 5: the remote `a=sctp-port`). Defaults to 5000. An endpoint that
    /// accepts an association answers on the ports of the INIT it received.
    pub fn with_remote_sctp_port(mut self, value: u16) -> Self {
        self.remote_sctp_port = value;
        self
    }

    /// Sets the advertised receive window (a_rwnd), bounding how much unacknowledged data a peer
    /// may have in flight toward this endpoint. At least 1500: RFC 9260 3.3.2 and 3.3.3 forbid
    /// a smaller a_rwnd in the INIT and INIT ACK, so a smaller value is raised to it.
    pub fn with_max_receive_buffer_size(mut self, value: u32) -> Self {
        self.max_receive_buffer_size = value.max(MIN_ADVERTISED_RECEIVER_WINDOW);
        self
    }

    /// Sets the largest message this endpoint will send, which is the peer's limit (RFC 8841
    /// 6.1: the remote `max-message-size`). Also the largest it will accept unless
    /// [`with_max_receive_message_size`](Self::with_max_receive_message_size) sets that apart.
    pub fn with_max_message_size(mut self, value: u32) -> Self {
        self.max_message_size = value;
        self
    }

    /// Sets the largest message this endpoint will accept, which is the limit it advertised
    /// itself (RFC 8841 6.1: the local `max-message-size`). Each direction has its own limit;
    /// the receive buffer keeps room for one message of this size beyond its bound, so a
    /// message larger than the buffer can still be reassembled.
    pub fn with_max_receive_message_size(mut self, value: u32) -> Self {
        self.max_receive_message_size = Some(value);
        self
    }

    /// Sets how many outbound streams to request during the handshake. At least 1: RFC 9260
    /// 3.3.2 and 3.3.3 forbid 0 in the INIT and INIT ACK.
    pub fn with_max_num_outbound_streams(mut self, value: u16) -> Self {
        self.max_num_outbound_streams = value.max(1);
        self
    }

    /// Sets how many inbound streams this endpoint will accept. At least 1, as for the
    /// outbound streams.
    pub fn with_max_num_inbound_streams(mut self, value: u16) -> Self {
        self.max_num_inbound_streams = value.max(1);
        self
    }

    /// Overrides the retransmission limits; see [`TimerConfig`].
    pub fn with_timer_config(mut self, value: TimerConfig) -> Self {
        self.timer_config = value;
        self
    }

    /// Sets RTO.Initial, RTO.Min and RTO.Max (RFC 9260 sections 6.3.1 and 16); see
    /// [`RtoConfig`]. The defaults are the RFC's: 1, 1 and 60 seconds. With
    /// [`TimerConfig::max_t3_rtx_retrans`] (Association.Max.Retrans) they bound how long an
    /// unanswered peer is retransmitted to before the association fails.
    pub fn with_rto_config(mut self, value: RtoConfig) -> Self {
        self.rto_config = value;
        self
    }

    /// Chooses how the next message to send is picked among the streams.
    pub fn with_stream_scheduler(mut self, value: StreamScheduler) -> Self {
        self.stream_scheduler = value;
        self
    }

    /// The configured SCTP port.
    pub fn sctp_port(&self) -> u16 {
        self.sctp_port
    }

    /// The configured SCTP port of the peer.
    pub fn remote_sctp_port(&self) -> u16 {
        self.remote_sctp_port
    }

    /// The configured receive window in bytes.
    pub fn max_receive_buffer_size(&self) -> u32 {
        self.max_receive_buffer_size
    }

    /// The configured maximum message size to send, in bytes.
    pub fn max_message_size(&self) -> u32 {
        self.max_message_size
    }

    /// The configured maximum message size to accept, in bytes: the send limit unless set
    /// apart with [`with_max_receive_message_size`](Self::with_max_receive_message_size).
    pub fn max_receive_message_size(&self) -> u32 {
        self.max_receive_message_size
            .unwrap_or(self.max_message_size)
    }

    /// The configured outbound stream count.
    pub fn max_num_outbound_streams(&self) -> u16 {
        self.max_num_outbound_streams
    }

    /// The configured inbound stream count.
    pub fn max_num_inbound_streams(&self) -> u16 {
        self.max_num_inbound_streams
    }

    /// The configured retransmission limits.
    pub fn timer_config(&self) -> TimerConfig {
        self.timer_config
    }

    /// The configured RTO bounds.
    pub fn rto_config(&self) -> RtoConfig {
        self.rto_config
    }

    /// The configured stream scheduler.
    pub fn stream_scheduler(&self) -> StreamScheduler {
        self.stream_scheduler
    }
}

/// Global configuration for the endpoint, affecting all associations
///
/// Default values should be suitable for most internet applications.
#[derive(Clone)]
pub struct EndpointConfig {
    pub(crate) max_payload_size: u32,

    /// AID generator factory
    ///
    /// Create a aid generator for local aid in Endpoint struct
    pub(crate) aid_generator_factory:
        Arc<dyn (Fn() -> Box<dyn AssociationIdGenerator + Send>) + Send + Sync>,

    /// Where the endpoint's associations draw their random values from.
    pub(crate) random: RandomSource,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl EndpointConfig {
    /// Create a default configuration
    pub fn new() -> Self {
        let aid_factory: fn() -> Box<dyn AssociationIdGenerator + Send> =
            || Box::<RandomAssociationIdGenerator>::default();
        Self {
            max_payload_size: max_payload_size_for_mtu(INITIAL_MTU),
            aid_generator_factory: Arc::new(aid_factory),
            random: RandomSource::default(),
        }
    }

    /// Draws every random value of the endpoint and its associations from `provider`'s
    /// `random()`: the verification tags (with the default generator, which this replaces;
    /// set [`Self::aid_generator`] after this call for another), the initial TSNs, the State
    /// Cookies made without [`ServerConfig::cookie_authentication`], the Initiate Tag of an
    /// INIT ACK for an existing association, HEARTBEAT nonces and the HEARTBEAT timer's
    /// jitter.
    ///
    /// Without it (the default) they come from `rand`'s thread-local CSPRNG. This is how the
    /// other crates of the workspace take their randomness (`docs/randomness-audit.md`), and
    /// what lets a test that seeds the provider replay a run exactly.
    pub fn random_source(&mut self, provider: Arc<dyn crypto::RTCCryptoProvider>) -> &mut Self {
        let random = RandomSource::new(Some(provider));
        self.random = random.clone();
        self.aid_generator_factory = Arc::new(move || {
            Box::new(SourcedAssociationIdGenerator(random.clone()))
                as Box<dyn AssociationIdGenerator + Send>
        });
        self
    }

    /// Supply a custom Association ID generator factory
    ///
    /// Called once by each `Endpoint` constructed from this configuration to obtain the AID
    /// generator which will be used to generate the AIDs used for incoming packets on all
    /// associations involving that  `Endpoint`. A custom AID generator allows applications to embed
    /// information in local association IDs, e.g. to support stateless packet-level load balancers.
    ///
    /// `EndpointConfig::new()` applies a default random AID generator factory. This functions
    /// accepts any customized AID generator to reset AID generator factory that implements
    /// the `AssociationIdGenerator` trait.
    pub fn aid_generator<
        F: Fn() -> Box<dyn AssociationIdGenerator + Send> + Send + Sync + 'static,
    >(
        &mut self,
        factory: F,
    ) -> &mut Self {
        self.aid_generator_factory = Arc::new(factory);
        self
    }

    /// Maximum payload size accepted from peers.
    ///
    /// The default is suitable for typical internet applications. Applications which expect to run
    /// on networks supporting Ethernet jumbo frames or similar should set this appropriately.
    pub fn max_payload_size(&mut self, value: u32) -> &mut Self {
        self.max_payload_size = value;
        self
    }

    /// Get the current value of `max_payload_size`
    ///
    /// While most parameters don't need to be readable, this must be exposed to allow higher-level
    /// layers to determine how large a receive buffer to allocate to
    /// support an externally-defined `EndpointConfig`.
    ///
    /// While `get_` accessors are typically unidiomatic in Rust, we favor concision for setters,
    /// which will be used far more heavily.
    pub fn get_max_payload_size(&self) -> u32 {
        self.max_payload_size
    }
}

impl fmt::Debug for EndpointConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("EndpointConfig")
            .field("max_payload_size", &self.max_payload_size)
            .field("aid_generator_factory", &"[ elided ]")
            .field("random", &self.random)
            .finish()
    }
}

/// Parameters governing incoming associations
///
/// Default values should be suitable for most internet applications.
#[derive(Clone)]
pub struct ServerConfig {
    /// Transport configuration to use for incoming associations
    pub transport: Arc<TransportConfig>,

    /// Maximum number of concurrent associations
    pub(crate) concurrent_associations: u32,

    /// The crypto provider State Cookies are authenticated with, when one was given.
    pub(crate) cookie_provider: Option<Arc<dyn crypto::RTCCryptoProvider>>,
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("ServerConfig")
            .field("transport", &self.transport)
            .field("concurrent_associations", &self.concurrent_associations)
            .field("cookie_authentication", &self.cookie_provider.is_some())
            .finish()
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            transport: Arc::new(TransportConfig::default()),
            concurrent_associations: 100_000,
            cookie_provider: None,
        }
    }
}

impl ServerConfig {
    /// Create a default configuration with a particular handshake token key
    pub fn new(transport: TransportConfig) -> Self {
        ServerConfig {
            transport: Arc::new(transport),
            concurrent_associations: 100_000,
            cookie_provider: None,
        }
    }

    /// Gives the endpoint a crypto provider to authenticate State Cookies with, and makes
    /// the handshake stateless on the accepting side, as RFC 9260 sections 5.1 and 5.1.3
    /// have it.
    ///
    /// With a provider, the State Cookie of an INIT ACK holds everything the association is
    /// made from, the time it was made, and an HMAC-SHA-256 over them under a random key of
    /// the endpoint's (replaced every hour). The endpoint answers an INIT and keeps nothing:
    /// [`Endpoint::handle`](crate::Endpoint::handle) returns `None` for it and the INIT ACK
    /// leaves by [`Endpoint::poll_transmit`](crate::Endpoint::poll_transmit). The
    /// association is made, and returned as
    /// [`DatagramEvent::NewAssociation`](crate::DatagramEvent::NewAssociation), when a
    /// COOKIE ECHO brings back a cookie whose MAC verifies and which is no older than
    /// [`TransportConfig::with_valid_cookie_life`]; it is established at once.
    ///
    /// Without a provider (the default) the cookie is 32 random bytes and the endpoint makes
    /// the association when the INIT arrives, remembering the cookie to compare it with the
    /// one echoed. `rtc-sctp` names no cryptographic implementation of its own, so the MAC
    /// is there only when the application supplies the provider.
    pub fn cookie_authentication(
        &mut self,
        provider: Arc<dyn crypto::RTCCryptoProvider>,
    ) -> &mut Self {
        self.cookie_provider = Some(provider);
        self
    }

    /// Maximum number of associations the endpoint holds at once. An INIT that would start
    /// one more is refused.
    ///
    /// A transport that carries a single association, such as WebRTC's SCTP over one DTLS
    /// transport (RFC 8261), should set this to 1.
    pub fn concurrent_associations(&mut self, value: u32) -> &mut Self {
        self.concurrent_associations = value;
        self
    }
}

/// Configuration for outgoing associations
///
/// Default values should be suitable for most internet applications.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Transport configuration to use
    pub transport: Arc<TransportConfig>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            transport: Arc::new(TransportConfig::default()),
        }
    }
}

impl ClientConfig {
    /// Create a default configuration with a particular cryptographic configuration
    pub fn new(transport: TransportConfig) -> Self {
        ClientConfig {
            transport: Arc::new(transport),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_max_payload_size_fits_ipv6_min_mtu() {
        // INITIAL_MTU bounds the assembled SCTP packet. The default is the
        // exact TURN-relayed IPv6 budget (pion/sctp#476, webrtc-rs/webrtc#807):
        // the 1280-byte IPv6 minimum MTU (RFC 8200) minus IPv6, UDP, and TURN
        // ChannelData headers and DTLS record overhead.
        assert_eq!(INITIAL_MTU, 1280 - 40 - 8 - 4 - 37);
        let config = EndpointConfig::default();
        assert_eq!(
            config.get_max_payload_size(),
            (INITIAL_MTU - (COMMON_HEADER_SIZE + DATA_CHUNK_HEADER_SIZE)) & !3
        );
        // A single maximum-size DATA chunk must marshal within INITIAL_MTU:
        // common header + the chunk header and payload, padded to 4 bytes.
        let padded_chunk =
            (DATA_CHUNK_HEADER_SIZE + config.get_max_payload_size()).next_multiple_of(4);
        assert!(COMMON_HEADER_SIZE + padded_chunk <= INITIAL_MTU);
    }

    #[test]
    fn max_payload_size_for_mtu_derives_the_payload_budget() {
        // `max_payload_size_for_mtu(INITIAL_MTU)` must reproduce the default
        // payload budget exactly.
        assert_eq!(
            max_payload_size_for_mtu(INITIAL_MTU),
            EndpointConfig::default().get_max_payload_size()
        );

        // Rounded down to the 4-byte padding boundary: the last MTU of one
        // padding window and the first of the next straddle a 4-byte step.
        assert_eq!(max_payload_size_for_mtu(1203), 1172);
        assert_eq!(max_payload_size_for_mtu(1204), 1176);

        // Values below MIN_DATA_PACKET_MTU behave exactly as the 32-byte
        // floor: the smallest representable padded DATA packet, a 4-byte
        // payload budget.
        for mtu in [0, 31, 32] {
            assert_eq!(max_payload_size_for_mtu(mtu), 4, "mtu {mtu}");
        }

        // Upper edge: the derivation must not overflow.
        assert_eq!(
            max_payload_size_for_mtu(u32::MAX),
            (u32::MAX - (COMMON_HEADER_SIZE + DATA_CHUNK_HEADER_SIZE)) & !3
        );
    }
}
