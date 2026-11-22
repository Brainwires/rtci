use crate::association::{
    state::{AckMode, AckState, AssociationState},
    stats::AssociationStats,
};
use crate::chunk::chunk_header::CHUNK_HEADER_SIZE;
use crate::chunk::{
    Chunk, ErrorCause, ErrorCauseUnrecognizedChunkType, INVALID_MANDATORY_PARAMETER,
    INVALID_STREAM_IDENTIFIER, MISSING_MANDATORY_PARAMETER, NO_USER_DATA, PROTOCOL_VIOLATION,
    STALE_COOKIE_ERROR, UNRECOGNIZED_CHUNK_TYPE, UNRECOGNIZED_PARAMETERS, UNRESOLVABLE_ADDRESS,
    USER_INITIATED_ABORT,
    chunk_abort::ChunkAbort,
    chunk_cookie_ack::ChunkCookieAck,
    chunk_cookie_echo::ChunkCookieEcho,
    chunk_error::ChunkError,
    chunk_forward_tsn::ChunkForwardTsn,
    chunk_forward_tsn::ChunkForwardTsnStream,
    chunk_heartbeat::ChunkHeartbeat,
    chunk_heartbeat_ack::ChunkHeartbeatAck,
    chunk_init::ChunkInit,
    chunk_init::ChunkInitAck,
    chunk_payload_data::ChunkPayloadData,
    chunk_payload_data::{MessageId, MessageReliability, PayloadProtocolIdentifier},
    chunk_reconfig::ChunkReconfig,
    chunk_selective_ack::{ChunkSelectiveAck, SELECTIVE_ACK_HEADER_SIZE},
    chunk_shutdown::ChunkShutdown,
    chunk_shutdown_ack::ChunkShutdownAck,
    chunk_shutdown_complete::ChunkShutdownComplete,
    chunk_type::CT_FORWARD_TSN,
    chunk_unknown::ChunkUnknown,
};
use crate::config::{COMMON_HEADER_SIZE, DATA_CHUNK_HEADER_SIZE, ServerConfig, TransportConfig};
use crate::packet::{CommonHeader, Packet};
use crate::param::{
    Param, UNRECOGNIZED_PARAMETER,
    param_forward_tsn_supported::ParamForwardTsnSupported,
    param_heartbeat_info::ParamHeartbeatInfo,
    param_outgoing_reset_request::ParamOutgoingResetRequest,
    param_reconfig_response::{ParamReconfigResponse, ReconfigResult},
    param_state_cookie::ParamStateCookie,
    param_supported_extensions::ParamSupportedExtensions,
    param_uknown::ParamUnknown,
};
use crate::queue::{
    payload_queue::PayloadQueue,
    pending_queue::{PendingQueue, ResetMarker},
};
use crate::shared::{AssociationEventInner, AssociationId, EndpointEvent, EndpointEventInner};
use crate::util::{
    constant_time_eq, get_padding_size, sna16lt, sna32gt, sna32gte, sna32lt, sna32lte,
};
use crate::{AssociationEvent, Payload, Side};
use shared::error::{Error, Result};
use shared::{TransportContext, TransportMessage, TransportProtocol};
use stream::{Stream, StreamEvent, StreamId, StreamState};
use timer::{ACK_INTERVAL, RtoManager, Timer, TimerTable};

use crate::association::stream::RecvSendState;
use bytes::{Bytes, BytesMut};
use log::{debug, error, trace, warn};
use rand::random;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;

pub(crate) mod state;
pub(crate) mod stats;
pub(crate) mod stream;
pub(crate) mod timer;

#[cfg(test)]
mod association_test;
#[cfg(any(fuzzing, feature = "bench"))]
pub(crate) mod recovery_bench;

/// Incoming stream reset requests held at once while they wait for the peer's TSN or for the
/// application to drain a stream. RFC 6525 has a peer keep one request in flight; a request
/// beyond this many is answered Denied and not stored.
pub(crate) const MAX_PENDING_RECONFIG_REQUESTS: usize = 64;

/// Sequence numbers of incoming reset requests already performed, remembered so a
/// retransmission is answered again without being performed a second time.
pub(crate) const MAX_COMPLETED_RECONFIG_REQUESTS: usize = 64;

/// Reset requests of this side's own, sent in answer to the peer's, that may await the peer's
/// response at once. Past it a peer request is still performed and answered, but not echoed.
pub(crate) const MAX_OUTSTANDING_RECONFIGS: usize = 64;

/// How long an accepting association waits for the COOKIE ECHO after an INIT before it gives
/// itself up, in milliseconds. A peer that is still trying sends something within RTO.Max
/// (60 s): another INIT if the INIT ACK was lost, or the COOKIE ECHO. Twice that leaves room
/// for the last retransmission to arrive.
pub(crate) const HALF_OPEN_LIFETIME: u64 = 120_000;

/// The most TSNs kept outstanding, from the Cumulative TSN Ack Point to the next TSN to assign.
///
/// RFC 9260 6.1: fewer ordered messages of a stream may be outstanding than the Stream
/// Sequence Number space holds, or the receiver cannot order them (it compares 16-bit serial
/// numbers, which works within half the space). Every message takes at least one TSN, so
/// bounding the TSNs bounds the messages of every stream. It also keeps the receiver's Gap Ack
/// Blocks within their 16-bit offsets.
pub(crate) const MAX_OUTSTANDING_TSNS: u32 = 0x7fff;

/// The Host Name Address parameter (RFC 9260 3.3.2.1.4), deprecated: an INIT or INIT ACK that
/// carries one is answered with an ABORT.
const PARAM_HOST_NAME_ADDRESS: u16 = 11;

/// The State Cookie parameter, for the "Missing Mandatory Parameter" cause.
const PARAM_STATE_COOKIE: u16 = 7;

/// T5-shutdown-guard (RFC 9260 9.2, 16): five times RTO.Max, in milliseconds.
pub(crate) const T5_SHUTDOWN_GUARD: u64 = 5 * 60_000;

/// What an accepted INIT said about its sender, kept with the State Cookie sent in answer
/// and taken into the TCB when that cookie comes back (RFC 9260 5.1.3: "the State Cookie
/// carries the information needed to create the association"; here the association holds
/// it, see the note on [`Association::handle_cookie_echo`]).
#[derive(Debug, Clone)]
struct CookieTcb {
    created_at: Instant,
    peer_verification_tag: u32,
    peer_initial_tsn: u32,
    peer_rwnd: u32,
    inbound_streams: u16,
    outbound_streams: u16,
    use_forward_tsn: bool,
    /// This side's port and the peer's, as the INIT's packet had them.
    source_port: u16,
    destination_port: u16,
}

/// The optional parameters of an INIT or INIT ACK, as far as the engine reads them.
#[derive(Default)]
struct HandshakeParams {
    cookie: Option<Bytes>,
    /// Unrecognized parameters the sender asked to hear about, each as it arrived.
    unrecognized: Vec<Bytes>,
    /// A Host Name Address parameter, as it arrived.
    host_name: Option<Bytes>,
    forward_tsn: bool,
}

/// Error causes reported for one received packet, at most.
const MAX_ERROR_CAUSES_PER_PACKET: usize = 16;

/// Parameter types the engine has no parser for but RFC 9260 defines for INIT / INIT ACK:
/// IPv4 Address, IPv6 Address, Unrecognized Parameter, Cookie Preservative, Supported Address
/// Types. Accepted and ignored: an association over DTLS has one path (RFC 8261), and a
/// longer cookie lifetime is the receiver's to grant or not (RFC 9260 5.2.6).
const IGNORED_HANDSHAKE_PARAMS: [u16; 5] = [5, 6, 8, 9, 12];

/// Reasons why an association might be lost
#[derive(Debug, Error, Clone, PartialEq)]
#[non_exhaustive]
pub enum AssociationError {
    /// Handshake failed
    #[error("handshake failed due to {0}")]
    HandshakeFailed(String),
    /// The peer violated the QUIC specification as understood by this implementation
    #[error("transport error")]
    TransportError,
    /// The peer's QUIC stack aborted the association automatically
    #[error("aborted by peer")]
    AssociationClosed,
    /// The peer closed the association
    #[error("closed by peer")]
    ApplicationClosed,
    /// The peer is unable to continue processing this association, usually due to having restarted
    #[error("reset by peer")]
    Reset,
    /// Communication with the peer has lapsed for longer than the negotiated idle timeout
    ///
    /// If neither side is sending keep-alives, an association will time out after a long enough idle
    /// period even if the peer is still reachable
    #[error("timed out")]
    TimedOut,
    /// The local application closed the association
    #[error("closed")]
    LocallyClosed,
}

/// Events of interest to the application
#[derive(Debug)]
#[non_exhaustive]
pub enum Event {
    /// Handshake was failed
    HandshakeFailed {
        /// Reason that the association was closed
        reason: AssociationError,
    },

    /// The association was successfully established
    Connected,
    /// The association was lost
    ///
    /// Emitted if the peer closes the association or an error is encountered.
    AssociationLost {
        /// Reason that the association was closed
        reason: AssociationError,
        /// The stream the loss was reported against.
        id: StreamId,
    },
    /// The association closed, after an `AssociationLost` for each of its streams. Emitted
    /// whether or not it had streams, so an application that keeps state beside the
    /// association (a pre-negotiated data channel that never carried data) learns of it.
    AssociationClosed {
        /// Reason that the association was closed
        reason: AssociationError,
    },
    /// Stream events
    Stream(StreamEvent),
    /// One or more application datagrams have been received
    DatagramReceived,
}

/// Selection is stable even after fragments leave either queue.
#[derive(Debug, Copy, Clone)]
struct MessageToAbandon {
    id: MessageId,
    // TSN of an inflight candidate; None when selected from pending.
    // This permits a direct lookup for whole messages. Fragmented messages
    // and pending selections use the index keyed by `id`.
    sent_tsn: Option<u32>,
}

///Association represents an SCTP association
//13.2.  Parameters Necessary per Association (i.e., the TCB)
//Peer : Tag value to be sent in every packet and is received
//Verification: in the INIT or INIT ACK chunk.
//Tag :
//
//My : Tag expected in every inbound packet and sent in the
//Verification: INIT or INIT ACK chunk.
//
//Tag :
//State : A state variable indicating what state the association
// : is in, i.e., COOKIE-WAIT, COOKIE-ECHOED, ESTABLISHED,
// : SHUTDOWN-PENDING, SHUTDOWN-SENT, SHUTDOWN-RECEIVED,
// : SHUTDOWN-ACK-SENT.
//
// No Closed state is illustrated since if a
// association is Closed its TCB SHOULD be removed.
pub struct Association {
    side: Side,
    state: AssociationState,
    handshake_completed: bool,
    max_message_size: u32,
    /// The largest message accepted from the peer: what this side advertised (RFC 8841 6.1).
    max_receive_message_size: u32,
    will_send_shutdown: bool,
    bytes_received: usize,
    bytes_sent: usize,

    pub(crate) peer_verification_tag: u32,
    my_verification_tag: u32,
    pub(crate) my_next_tsn: u32,
    peer_last_tsn: u32,
    // for RTT measurement
    min_tsn2measure_rtt: u32,
    will_send_forward_tsn: bool,
    will_retransmit_fast: bool,
    will_retransmit_reconfig: bool,
    /// True only while the in-flight queue may still hold chunks flagged for
    /// T3-rtx retransmission (set when the timer marks them, cleared once the
    /// scan has re-sent them all). Lets `gather_outbound` skip the O(in-flight)
    /// retransmit scan entirely in the steady state, where nothing is ever
    /// marked — that scan was the single hottest function in the send profile.
    t3_retransmit_pending: bool,

    will_send_shutdown_ack: bool,
    will_send_shutdown_complete: bool,

    // Reconfig
    my_next_rsn: u32,
    reconfigs: HashMap<u32, ChunkReconfig>,
    reconfig_requests: HashMap<u32, ParamOutgoingResetRequest>,
    completed_reconfig_requests: VecDeque<u32>,

    // Non-RFC internal data
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    transport_protocol: TransportProtocol,

    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
    my_max_num_inbound_streams: u16,
    my_max_num_outbound_streams: u16,
    /// The stream counts this side is configured to offer, before a peer's INIT or INIT ACK
    /// narrowed them.
    configured_inbound_streams: u16,
    configured_outbound_streams: u16,
    my_cookie: Option<ParamStateCookie>,
    /// What the INIT answered with `my_cookie` said, applied when the cookie is echoed.
    cookie_tcb: Option<CookieTcb>,
    /// Valid.Cookie.Life (RFC 9260 16): how long a State Cookie is accepted after it was made.
    valid_cookie_life: Duration,
    /// How many times a Stale Cookie error sent this side back to a new INIT.
    stale_cookie_restarts: usize,
    /// The first DATA chunk of an association is acknowledged at once (RFC 9260 5.1).
    first_data_received: bool,
    /// Set while a packet is processed whose DATA must be acknowledged at once: it came with
    /// the COOKIE ECHO (RFC 9260 5.1.5), or in SHUTDOWN-SENT (9.2).
    sack_packet_immediately: bool,
    /// Set by a chunk handler: the chunks after it in the packet are discarded.
    discard_rest_of_packet: bool,

    pub(crate) payload_queue: PayloadQueue,
    pub(crate) inflight_queue: PayloadQueue,
    pub(crate) pending_queue: PendingQueue,
    control_queue: VecDeque<Packet>,
    stream_queue: VecDeque<u16>,

    pub(crate) mtu: u32,
    // max DATA chunk payload size
    max_payload_size: u32,
    cumulative_tsn_ack_point: u32,
    advanced_peer_tsn_ack_point: u32,
    use_forward_tsn: bool,
    /// Max stream-sequence-number per *ordered* stream among abandoned chunks
    /// currently in the forward-TSN window `(cumulative_tsn_ack_point,
    /// advanced_peer_tsn_ack_point]`. Maintained incrementally as chunks are
    /// abandoned (the two RFC 3758 C2 loops) so that `create_forward_tsn` is
    /// O(streams) instead of rescanning the whole in-flight window — which, for
    /// PR-SCTP data channels, ran ~1000 hashmap probes per FORWARD-TSN and was
    /// ~9% of send CPU in profiles. Unordered chunks are omitted: the receiver
    /// ignores the per-stream list for them (it advances by `new_cumulative_tsn`
    /// alone), so reporting them was pure waste.
    fwd_tsn_stream_map: FxHashMap<u16, u16>,

    pub(crate) rto_mgr: RtoManager,
    timers: TimerTable,

    // Congestion control parameters
    max_receive_buffer_size: u32,
    // my congestion window size
    pub(crate) cwnd: u32,
    // calculated peer's receiver windows size
    rwnd: u32,
    // slow start threshold
    pub(crate) ssthresh: u32,
    partial_bytes_acked: u32,
    pub(crate) in_fast_recovery: bool,
    fast_recover_exit_point: u32,

    // Chunks stored for retransmission
    stored_init: Option<ChunkInit>,
    stored_cookie_echo: Option<ChunkCookieEcho>,
    next_stream_generation: u64,
    next_message_id: u64,
    /// Per-chunk lookups on the receive path; SIDs are bounded by the
    /// negotiated stream count, so the faster non-SipHash hasher is safe.
    pub(crate) streams: FxHashMap<StreamId, StreamState>,
    /// Bytes held in every stream's reassembly queue, kept as a running total so the receive
    /// window is not recomputed by walking every stream on each DATA chunk.
    reassembly_bytes: usize,
    /// Streams whose reassembly queue holds a readable message.
    readable_streams: FxHashSet<StreamId>,
    /// Streams whose reassembly queue holds anything at all; the only ones a FORWARD TSN can
    /// change.
    streams_with_data: FxHashSet<StreamId>,

    events: VecDeque<Event>,
    endpoint_events: VecDeque<EndpointEventInner>,
    error: Option<AssociationError>,
    /// Set by [`close`](Self::close): the association is over, whatever state it was in.
    ended: bool,
    /// `ended`, as the endpoint that routes to this association sees it: an ended association
    /// takes no more packets and no longer counts against the endpoint's limit.
    ended_flag: Arc<AtomicBool>,
    /// `Drained` is reported to the endpoint once.
    drained_emitted: bool,
    /// Error causes to report for the packet being processed, sent as one ERROR chunk when
    /// its last chunk has been handled.
    pending_error_causes: Vec<ErrorCause>,

    // per inbound packet context
    delayed_ack_triggered: bool,
    immediate_ack_triggered: bool,

    pub(crate) stats: AssociationStats,
    ack_state: AckState,

    // for testing
    pub(crate) ack_mode: AckMode,
}

impl Default for Association {
    fn default() -> Self {
        Association {
            side: Side::default(),
            state: AssociationState::default(),
            handshake_completed: false,
            max_message_size: 0,
            max_receive_message_size: 0,
            will_send_shutdown: false,
            bytes_received: 0,
            bytes_sent: 0,

            peer_verification_tag: 0,
            my_verification_tag: 0,
            my_next_tsn: 0,
            peer_last_tsn: 0,
            // for RTT measurement
            min_tsn2measure_rtt: 0,
            will_send_forward_tsn: false,
            will_retransmit_fast: false,
            will_retransmit_reconfig: false,
            t3_retransmit_pending: false,

            will_send_shutdown_ack: false,
            will_send_shutdown_complete: false,

            // Reconfig
            my_next_rsn: 0,
            reconfigs: HashMap::default(),
            reconfig_requests: HashMap::default(),
            completed_reconfig_requests: VecDeque::new(),

            // Non-RFC internal data
            remote_addr: SocketAddr::from_str("0.0.0.0:0").unwrap(),
            local_addr: SocketAddr::from_str("0.0.0.0:0").unwrap(),
            transport_protocol: TransportProtocol::UDP,

            source_port: 0,
            destination_port: 0,
            my_max_num_inbound_streams: 0,
            my_max_num_outbound_streams: 0,
            configured_inbound_streams: 0,
            configured_outbound_streams: 0,
            my_cookie: None,
            cookie_tcb: None,
            valid_cookie_life: Duration::from_secs(60),
            stale_cookie_restarts: 0,
            first_data_received: false,
            sack_packet_immediately: false,
            discard_rest_of_packet: false,

            payload_queue: PayloadQueue::default(),
            inflight_queue: PayloadQueue::default(),
            pending_queue: PendingQueue::default(),
            control_queue: VecDeque::default(),
            stream_queue: VecDeque::default(),

            mtu: 0,
            // max DATA chunk payload size
            max_payload_size: 0,
            cumulative_tsn_ack_point: 0,
            advanced_peer_tsn_ack_point: 0,
            use_forward_tsn: false,
            fwd_tsn_stream_map: FxHashMap::default(),

            rto_mgr: RtoManager::default(),
            timers: TimerTable::default(),

            // Congestion control parameters
            max_receive_buffer_size: 0,
            // my congestion window size
            cwnd: 0,
            // calculated peer's receiver windows size
            rwnd: 0,
            // slow start threshold
            ssthresh: 0,
            partial_bytes_acked: 0,
            in_fast_recovery: false,
            fast_recover_exit_point: 0,

            // Chunks stored for retransmission
            stored_init: None,
            stored_cookie_echo: None,
            next_stream_generation: 0,
            next_message_id: 0,
            streams: FxHashMap::default(),
            reassembly_bytes: 0,
            readable_streams: FxHashSet::default(),
            streams_with_data: FxHashSet::default(),

            events: VecDeque::default(),
            endpoint_events: VecDeque::default(),
            error: None,
            ended: false,
            ended_flag: Arc::new(AtomicBool::new(false)),
            drained_emitted: false,
            pending_error_causes: vec![],

            // per inbound packet context
            delayed_ack_triggered: false,
            immediate_ack_triggered: false,

            stats: AssociationStats::default(),
            ack_state: AckState::default(),

            // for testing
            ack_mode: AckMode::default(),
        }
    }
}

impl Association {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        server_config: Option<Arc<ServerConfig>>,
        config: Arc<TransportConfig>,
        max_payload_size: u32,
        local_aid: AssociationId,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        protocol: TransportProtocol,
        now: Instant,
    ) -> Self {
        let side = if server_config.is_some() {
            Side::Server
        } else {
            Side::Client
        };

        // It's a bit strange, but we're going backwards from the calculation in
        // config.rs to get max_payload_size from INITIAL_MTU.
        let mtu = max_payload_size.saturating_add(COMMON_HEADER_SIZE + DATA_CHUNK_HEADER_SIZE);

        // RFC 4960 Sec 7.2.1
        // The initial cwnd before DATA transmission or after a sufficiently
        // long idle period MUST be set to min(4*MTU, max (2*MTU, 4380bytes)).
        // Written in total form: the previous `(2 * mtu).clamp(4380, 4 * mtu)`
        // panicked for effective MTUs below ~1095 (`Ord::clamp` with
        // min > max) and overflowed near `u32::MAX`, both reachable through
        // `EndpointConfig::max_payload_size` and MTU-derived payload budgets.
        let cwnd = mtu.saturating_mul(2).max(4380).min(mtu.saturating_mul(4));
        // RFC 4960 requires an unpredictable initial TSN. SCTP remains usable without an RTC
        // crypto provider, so this deliberately uses `rand`'s thread-local CSPRNG.
        let mut tsn = random::<u32>();
        if tsn == 0 {
            tsn += 1;
        }

        let mut this = Association {
            side,
            handshake_completed: false,
            max_receive_buffer_size: config.max_receive_buffer_size(),
            max_message_size: config.max_message_size(),
            max_receive_message_size: config.max_receive_message_size(),
            my_max_num_outbound_streams: config.max_num_outbound_streams(),
            my_max_num_inbound_streams: config.max_num_inbound_streams(),
            configured_outbound_streams: config.max_num_outbound_streams(),
            configured_inbound_streams: config.max_num_inbound_streams(),
            valid_cookie_life: config.valid_cookie_life(),
            max_payload_size,
            // RFC 8841 5: each side's `a=sctp-port`. An accepting side takes the INIT's ports
            // instead (`handle_init`).
            source_port: config.sctp_port(),
            destination_port: config.remote_sctp_port(),

            rto_mgr: RtoManager::new(),
            timers: TimerTable::new(config.timer_config()),
            pending_queue: PendingQueue::with_scheduler(config.stream_scheduler()),

            mtu,
            cwnd,
            remote_addr,
            local_addr,
            transport_protocol: protocol,

            my_verification_tag: local_aid,
            my_next_tsn: tsn,
            my_next_rsn: tsn,
            min_tsn2measure_rtt: tsn,
            cumulative_tsn_ack_point: tsn - 1,
            advanced_peer_tsn_ack_point: tsn - 1,
            error: None,

            ..Default::default()
        };

        if !side.is_client() {
            // The accepting side exists from the peer's INIT on. Without a COOKIE ECHO it
            // must not exist for ever (and an INIT that is not valid starts no handshake at
            // all), so the wait is timed from the start.
            this.timers.start(Timer::HalfOpen, now, HALF_OPEN_LIFETIME);
        }

        if side.is_client() {
            let mut init = ChunkInit {
                initial_tsn: this.my_next_tsn,
                num_outbound_streams: this.my_max_num_outbound_streams,
                num_inbound_streams: this.my_max_num_inbound_streams,
                initiate_tag: this.my_verification_tag,
                advertised_receiver_window_credit: this.max_receive_buffer_size,
                ..Default::default()
            };
            init.set_supported_extensions();

            this.set_state(AssociationState::CookieWait);
            this.stored_init = Some(init);
            let _ = this.send_init();
            this.timers
                .start(Timer::T1Init, now, this.rto_mgr.get_rto());
        }

        this
    }

    /// Returns application-facing event
    ///
    /// Associations should be polled for events after:
    /// - a call was made to `handle_event`
    /// - a call was made to `handle_timeout`
    #[must_use]
    pub fn poll(&mut self) -> Option<Event> {
        if let Some(x) = self.events.pop_front() {
            return Some(x);
        }

        /*TODO: if let Some(event) = self.streams.poll() {
            return Some(Event::Stream(event));
        }*/

        if let Some(err) = self.error.take() {
            return Some(Event::HandshakeFailed { reason: err });
        }

        None
    }

    /// Return endpoint-facing event
    #[must_use]
    pub fn poll_endpoint_event(&mut self) -> Option<EndpointEvent> {
        self.endpoint_events.pop_front().map(EndpointEvent)
    }

    /// Returns the next time at which `handle_timeout` should be called
    ///
    /// The value returned may change after:
    /// - the application performed some I/O on the association
    /// - a call was made to `handle_transmit`
    /// - a call to `poll_transmit` returned `Some`
    /// - a call was made to `handle_timeout`
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.timers.next_timeout()
    }

    /// Returns packets to transmit
    ///
    /// Associations should be polled for transmit after:
    /// - the application performed some I/O on the Association
    /// - a call was made to `handle_event`
    /// - a call was made to `handle_timeout`
    #[must_use]
    pub fn poll_transmit(&mut self, now: Instant) -> Option<TransportMessage<Payload>> {
        let (contents, keep_open) = self.gather_outbound(now);
        if !keep_open && !self.ended {
            // The SHUTDOWN COMPLETE just gathered is the last packet of a graceful shutdown
            // this side started: RFC 9260 9.2 removes the association once it is sent. It
            // stayed in SHUTDOWN-SENT for good, with nothing left to happen.
            if let Err(err) = self.close(AssociationError::LocallyClosed) {
                error!("[{}] failed to close association: {err}", self.side);
            }
        }
        if contents.is_empty() {
            None
        } else {
            self.bytes_sent = self
                .bytes_sent
                .saturating_add(contents.iter().map(Bytes::len).sum());
            trace!(
                "[{}] sending {} bytes (total {} datagrams)",
                self.side,
                contents.iter().fold(0, |l, c| l + c.len()),
                contents.len()
            );
            Some(TransportMessage {
                now,
                transport: TransportContext {
                    local_addr: self.local_addr,
                    peer_addr: self.remote_addr,
                    ecn: None,
                    transport_protocol: Default::default(),
                },
                message: Payload::RawEncode(contents),
            })
        }
    }

    /// Process timer expirations
    ///
    /// Executes protocol logic, potentially preparing signals (including application `Event`s,
    /// `EndpointEvent`s and outgoing datagrams) that should be extracted through the relevant
    /// methods.
    ///
    /// It is most efficient to call this immediately after the system clock reaches the latest
    /// `Instant` that was output by `poll_timeout`; however spurious extra calls will simply
    /// no-op and therefore are safe.
    pub fn handle_timeout(&mut self, now: Instant) {
        for &timer in &Timer::VALUES {
            let (expired, failure, n_rtos) = self.timers.is_expired(timer, now);
            if !expired {
                continue;
            }
            self.timers.set(timer, None);
            //trace!("{:?} timeout", timer);

            if timer == Timer::Ack {
                self.on_ack_timeout();
            } else if failure {
                self.on_retransmission_failure(timer);
            } else {
                self.on_retransmission_timeout(timer, n_rtos, now);
                if self.state() == AssociationState::Closed {
                    break;
                }
                self.timers.start(timer, now, self.rto_mgr.get_rto());
            }
        }
    }

    /// Process `AssociationEvent`s generated by the associated `Endpoint`
    ///
    /// Will execute protocol logic upon receipt of an association event, in turn preparing signals
    /// (including application `Event`s, `EndpointEvent`s and outgoing datagrams) that should be
    /// extracted through the relevant methods.
    pub fn handle_event(&mut self, event: AssociationEvent) {
        match event.0 {
            AssociationEventInner::Datagram(transmit) => {
                // If this packet could initiate a migration and we're a client or a server that
                // forbids migration, drop the datagram. This could be relaxed to heuristically
                // permit NAT-rebinding-like migration.
                /*TODO:if remote != self.remote && self.server_config.as_ref().map_or(true, |x| !x.migration)
                {
                    trace!("discarding packet from unrecognized peer {}", remote);
                    return;
                }*/

                if let Payload::PartialDecode(partial_decode) = transmit.message {
                    let len = COMMON_HEADER_SIZE as usize + partial_decode.remaining.len();
                    debug!("[{}] recving {} bytes", self.side, len);
                    self.bytes_received = self.bytes_received.saturating_add(len);

                    let pkt = match partial_decode.finish() {
                        Ok(p) => p,
                        Err(err) => {
                            warn!("[{}] unable to parse SCTP packet {}", self.side, err);
                            return;
                        }
                    };

                    if let Err(err) = self.handle_inbound(pkt, transmit.now) {
                        error!("handle_inbound got err: {}", err);
                        let _ = self.close(AssociationError::TransportError);
                    }
                } else {
                    trace!("discarding invalid partial_decode");
                }
            } //TODO:
        }
    }

    /// Returns Association statistics
    pub fn stats(&self) -> AssociationStats {
        self.stats
    }

    /// Whether the Association is in the process of being established
    ///
    /// If this returns `false`, the Association may be either established or closed, signaled by the
    /// emission of a `Connected` or `AssociationLost` message respectively.
    pub fn is_handshaking(&self) -> bool {
        !self.handshake_completed
    }

    /// The number of streams negotiated for this association: the smaller of the inbound and
    /// outbound counts the two endpoints agreed on in INIT/INIT ACK.
    ///
    /// `None` while the association is still handshaking. Before the peer's INIT (or INIT ACK) has
    /// been processed, the two counts still hold this endpoint's *configured* limits rather than
    /// anything agreed, so reporting them would overstate what the association can carry.
    ///
    /// This is what [RFC 8831] data channels are limited by, and what W3C
    /// `RTCSctpTransport.maxChannels` reports.
    ///
    /// [RFC 8831]: https://datatracker.ietf.org/doc/html/rfc8831
    pub fn negotiated_max_streams(&self) -> Option<u16> {
        if self.is_handshaking() {
            None
        } else {
            Some(
                self.my_max_num_inbound_streams
                    .min(self.my_max_num_outbound_streams),
            )
        }
    }

    /// Whether the Association is closed
    ///
    /// Closed Associations cannot transport any further data. An association becomes closed when
    /// either peer application intentionally closes it, or when either transport layer detects an
    /// error such as a time-out or certificate validation failure.
    ///
    /// A `AssociationLost` event is emitted with details when the association becomes closed.
    pub fn is_closed(&self) -> bool {
        self.state == AssociationState::Closed
    }

    /// Whether the association is over: closed by either side, by an error, or by a handshake
    /// that failed.
    ///
    /// Unlike [`is_closed`](Self::is_closed), false for an association still handshaking in
    /// SCTP's initial CLOSED state (RFC 9260 section 4), which has not ended.
    pub fn is_ended(&self) -> bool {
        self.ended
    }

    /// Whether there is no longer any need to keep the association around
    ///
    /// Closed associations become drained after a brief timeout to absorb any remaining in-flight
    /// packets from the peer. All drained associations have been closed.
    pub fn is_drained(&self) -> bool {
        self.state.is_drained()
    }

    /// The Verification Tag this association expects in the packets it receives (RFC 9260
    /// section 8.5): its own Initiate Tag.
    pub fn verification_tag(&self) -> u32 {
        self.my_verification_tag
    }

    /// Look up whether we're the client or server of this Association
    pub fn side(&self) -> Side {
        self.side
    }

    /// The latest socket address for this Association's peer
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Smoothed round-trip time, or zero before the first RTT measurement.
    /// Retransmission timeout backoff does not change this estimate.
    pub fn rtt(&self) -> Duration {
        Duration::from_millis(self.rto_mgr.srtt)
    }

    /// The local IP address which was used when the peer established
    /// the association
    ///
    /// This can be different from the address the endpoint is bound to, in case
    /// the endpoint is bound to a wildcard address like `0.0.0.0` or `::`.
    ///
    /// This will return `None` for clients.
    ///
    /// Retrieving the local IP address is currently supported on the following
    /// platforms:
    /// - Linux
    ///
    /// On all non-supported platforms the local IP address will not be available,
    /// and the method will return `None`.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Shutdown initiates the shutdown sequence. The method blocks until the
    /// shutdown sequence is completed and the association is closed, or until the
    /// passed context is done, in which case the context's error is returned.
    pub fn shutdown(&mut self) -> Result<()> {
        debug!("[{}] closing association..", self.side);

        let state = self.state();
        if state != AssociationState::Established {
            return Err(Error::ErrShutdownNonEstablished);
        }

        // Attempt a graceful shutdown. RFC 9260 9.2: SHUTDOWN-PENDING lasts until everything
        // the application handed over has been sent and acknowledged. This tested a counter
        // that was never updated, so SHUTDOWN went out at once, ahead of the DATA still in
        // flight or queued, and the queued DATA was never sent.
        self.set_state(AssociationState::ShutdownPending);

        if self.inflight_queue.is_empty() && self.pending_queue.is_empty() {
            // No more outstanding, send shutdown.
            self.send_shutdown();
        }

        Ok(())
    }

    /// Moves SHUTDOWN-PENDING on to SHUTDOWN-SENT and queues the SHUTDOWN.
    ///
    /// The endpoint's `Drained` goes out with it, as it always has: the owner flushes this
    /// association's final packets and may then stop routing to it. It used to be emitted by
    /// `shutdown()` itself, which with DATA still outstanding cut the association off from the
    /// SACKs it was waiting for.
    fn send_shutdown(&mut self) {
        self.will_send_shutdown = true;
        self.awake_write_loop();
        self.set_state(AssociationState::ShutdownSent);
        self.emit_drained();
    }

    /// RFC 9260 9.2: the T5-shutdown-guard timer bounds the whole shutdown, however often the
    /// peer's packets restart T2-shutdown.
    fn start_shutdown_guard(&mut self, now: Instant) {
        if self.timers.get(Timer::T5ShutdownGuard).is_none() {
            self.timers
                .start(Timer::T5ShutdownGuard, now, T5_SHUTDOWN_GUARD);
        }
    }

    /// Tells the endpoint to stop routing to this association, once.
    fn emit_drained(&mut self) {
        if !self.drained_emitted {
            self.drained_emitted = true;
            self.endpoint_events.push_back(EndpointEventInner::Drained);
        }
    }

    /// The flag the endpoint reads to learn that this association has ended.
    pub(crate) fn ended_flag(&self) -> Arc<AtomicBool> {
        self.ended_flag.clone()
    }

    /// Aborts the association (RFC 9260 §9.1): queues an ABORT chunk and closes the association.
    ///
    /// Unlike [`shutdown`](Self::shutdown) this needs no round trip, which is what closing a
    /// WebRTC peer connection calls for: W3C `close()` tears the association down "by sending an
    /// SCTP ABORT chunk". The ABORT carries a "User-Initiated Abort" error cause (RFC 9260
    /// §3.3.10.12), which a peer takes as an intentional close rather than an error.
    ///
    /// The ABORT is sent by the next [`poll_transmit`](Self::poll_transmit). Anything not handed to
    /// `poll_transmit` before this call is discarded, so drain it first if it should still go out.
    /// A no-op on a closed association.
    pub fn abort(&mut self) -> Result<()> {
        if self.ended {
            return Ok(());
        }
        self.abort_with(
            vec![ErrorCause {
                code: USER_INITIATED_ABORT,
                ..Default::default()
            }],
            AssociationError::LocallyClosed,
        )
    }

    /// Sends an ABORT with `causes` to the peer and ends the association with `reason`
    /// (RFC 9260 9.1). The ABORT goes alone in its packet, with the peer's tag; before the
    /// peer's tag is known (no INIT ACK yet) there is no one to send it to.
    fn abort_with(&mut self, causes: Vec<ErrorCause>, reason: AssociationError) -> Result<()> {
        if self.ended {
            return Ok(());
        }
        if self.peer_verification_tag != 0 {
            let packet = self.abort_packet(self.peer_verification_tag, false, causes);
            self.control_queue.push_back(packet);
            self.awake_write_loop();
        }
        self.close(reason)
    }

    /// A packet holding one ABORT chunk, sent with Verification Tag `tag`. `reflected` sets
    /// the T bit: the tag is the one of the packet being answered, not the receiver's own
    /// (RFC 9260 8.4, 8.5.1).
    fn abort_packet(&self, tag: u32, reflected: bool, causes: Vec<ErrorCause>) -> Packet {
        Packet {
            common_header: CommonHeader {
                verification_tag: tag,
                source_port: self.source_port,
                destination_port: self.destination_port,
            },
            chunks: vec![Box::new(ChunkAbort {
                error_causes: causes,
                tag_reflected: reflected,
            })],
        }
    }

    fn protocol_violation(text: &str) -> ErrorCause {
        ErrorCause {
            code: PROTOCOL_VIOLATION,
            raw: Bytes::copy_from_slice(text.as_bytes()),
        }
    }

    /// Close ends the SCTP Association and cleans up any state
    pub fn close(&mut self, reason: AssociationError) -> Result<()> {
        // Keyed on `ended`, not on the CLOSED state: an accepting association is in SCTP's
        // initial CLOSED state until the COOKIE ECHO, so an ABORT or an error during its
        // handshake used to close nothing and leave it handshaking for good.
        if !self.ended {
            self.ended = true;
            // The endpoint stops routing to an ended association and frees its place for the
            // next one (RFC 9260 9.1: the association is removed from the record). The owner
            // may keep the association itself to read how it ended.
            self.ended_flag.store(true, Ordering::Relaxed);
            self.set_state(AssociationState::Closed);

            debug!("[{}] closing association..", self.side);

            self.close_all_timers();

            for si in self.streams.keys().cloned().collect::<Vec<u16>>() {
                self.unregister_stream(si, reason.clone());
            }
            self.events.push_back(Event::AssociationClosed {
                reason: reason.clone(),
            });

            debug!("[{}] association closed", self.side);
            debug!(
                "[{}] stats nDATAs (in) : {}",
                self.side,
                self.stats.get_num_datas()
            );
            debug!(
                "[{}] stats nSACKs (in) : {}",
                self.side,
                self.stats.get_num_sacks()
            );
            debug!(
                "[{}] stats nT3Timeouts : {}",
                self.side,
                self.stats.get_num_t3timeouts()
            );
            debug!(
                "[{}] stats nAckTimeouts: {}",
                self.side,
                self.stats.get_num_ack_timeouts()
            );
            debug!(
                "[{}] stats nFastRetrans: {}",
                self.side,
                self.stats.get_num_fast_retrans()
            );
        }

        Ok(())
    }

    /// open_stream opens a stream
    pub fn open_stream(
        &mut self,
        stream_identifier: StreamId,
        default_payload_type: PayloadProtocolIdentifier,
    ) -> Result<Stream<'_>> {
        if self.streams.contains_key(&stream_identifier) {
            return Err(Error::ErrStreamAlreadyExist);
        }

        // RFC 9260 5.1.1, 6.5: the outgoing stream ids are 0 to min(own OS, peer's MIS) - 1.
        // DATA on any other is answered by the peer with an ERROR and thrown away.
        if self.my_max_num_outbound_streams != 0
            && stream_identifier >= self.my_max_num_outbound_streams
        {
            return Err(Error::ErrStreamCreateFailed);
        }

        if let Some(s) = self.create_stream(stream_identifier, false, default_payload_type) {
            Ok(s)
        } else {
            Err(Error::ErrStreamCreateFailed)
        }
    }

    /// accept_stream accepts a stream
    pub fn accept_stream(&mut self) -> Option<Stream<'_>> {
        self.stream_queue
            .pop_front()
            .map(move |stream_identifier| Stream {
                stream_identifier,
                association: self,
            })
    }

    /// stream returns a stream
    pub fn stream(&mut self, stream_identifier: StreamId) -> Result<Stream<'_>> {
        if !self.streams.contains_key(&stream_identifier) {
            Err(Error::ErrStreamNotExisted)
        } else {
            Ok(Stream {
                stream_identifier,
                association: self,
            })
        }
    }

    /// The identifiers of every stream currently open on this association.
    pub fn stream_ids(&self) -> Vec<StreamId> {
        self.streams.keys().cloned().collect()
    }

    /// The bytes of every SCTP packet handed out by `poll_transmit`, common headers included.
    pub(crate) fn bytes_sent(&self) -> usize {
        self.bytes_sent
    }

    /// The bytes of every SCTP packet handed in through `handle_event`, common headers included.
    pub(crate) fn bytes_received(&self) -> usize {
        self.bytes_received
    }

    /// max_message_size returns the maximum message size you can send.
    pub(crate) fn max_message_size(&self) -> u32 {
        self.max_message_size
    }

    /// set_max_message_size sets the maximum message size you can send.
    pub(crate) fn set_max_message_size(&mut self, max_message_size: u32) {
        self.max_message_size = max_message_size;
    }

    /// unregister_stream un-registers a stream from the association
    /// The caller should hold the association write lock.
    fn unregister_stream(&mut self, stream_identifier: StreamId, reason: AssociationError) {
        if let Some(mut s) = self.streams.remove(&stream_identifier) {
            debug!("[{}] unregister_stream {}", self.side, stream_identifier);
            self.reindex_stream(stream_identifier, s.get_num_bytes_in_reassembly_queue());
            self.events.push_back(Event::AssociationLost {
                reason,
                id: stream_identifier,
            });
            s.state = RecvSendState::Closed;
        }
    }

    /// Re-run any reset request that was answered In Progress because
    /// `stream_identifier` still had data the application had not collected
    /// Called when that stream drains.
    ///
    /// The reply is queued like any other control packet; a request naming
    /// several streams is retried as a whole and simply defers again if another
    /// of its streams is still readable.
    pub(crate) fn retry_deferred_resets(&mut self, stream_identifier: StreamId) {
        let pending: Vec<ParamOutgoingResetRequest> = self
            .reconfig_requests
            .values()
            .filter(|p| p.stream_identifiers.contains(&stream_identifier))
            .cloned()
            .collect();
        if pending.is_empty() {
            return;
        }

        let mut reply = vec![];
        for p in pending {
            if let Err(err) = self.reset_streams_if_any(&p, true, &mut reply) {
                debug!("[{}] retry of deferred reset failed: {:?}", self.side, err);
            }
        }
        for packet in reply {
            self.control_queue.push_back(packet);
        }
        self.awake_write_loop();
    }

    /// set_state atomically sets the state of the Association.
    fn set_state(&mut self, new_state: AssociationState) {
        if new_state != self.state {
            debug!(
                "[{}] state change: '{}' => '{}'",
                self.side, self.state, new_state,
            );
        }
        self.state = new_state;
    }

    /// state atomically returns the state of the Association.
    pub(crate) fn state(&self) -> AssociationState {
        self.state
    }

    /// caller must hold self.lock
    fn send_init(&mut self) -> Result<()> {
        if let Some(stored_init) = &self.stored_init {
            debug!("[{}] sending INIT", self.side);

            let outbound = Packet {
                common_header: CommonHeader {
                    source_port: self.source_port,
                    destination_port: self.destination_port,
                    verification_tag: self.peer_verification_tag,
                },
                chunks: vec![Box::new(stored_init.clone())],
            };

            self.control_queue.push_back(outbound);
            self.awake_write_loop();

            Ok(())
        } else {
            Err(Error::ErrInitNotStoredToSend)
        }
    }

    /// caller must hold self.lock
    fn send_cookie_echo(&mut self) -> Result<()> {
        if let Some(stored_cookie_echo) = &self.stored_cookie_echo {
            debug!("[{}] sending COOKIE-ECHO", self.side);

            let outbound = Packet {
                common_header: CommonHeader {
                    source_port: self.source_port,
                    destination_port: self.destination_port,
                    verification_tag: self.peer_verification_tag,
                },
                chunks: vec![Box::new(stored_cookie_echo.clone())],
            };

            self.control_queue.push_back(outbound);
            self.awake_write_loop();

            Ok(())
        } else {
            Err(Error::ErrCookieEchoNotStoredToSend)
        }
    }

    /// handle_inbound parses incoming raw packets
    fn handle_inbound(&mut self, p: Packet, now: Instant) -> Result<()> {
        // RFC 9260 9.1: an association that has ended is gone. Whatever still arrives for it
        // (a copy of the COOKIE ECHO, DATA in flight) is discarded.
        if self.ended {
            trace!(
                "[{}] discarding a packet for an ended association",
                self.side
            );
            return Ok(());
        }

        if let Err(err) = p.check_packet() {
            warn!("[{}] failed validating packet {}", self.side, err);
            return Ok(());
        }

        // RFC 9260 8.5.1 E: a SHUTDOWN ACK while this side is still setting the association
        // up belongs to an association it no longer has. It is answered as an out-of-the-blue
        // packet (8.4): SHUTDOWN COMPLETE with the tag of the SHUTDOWN ACK and the T bit.
        if matches!(
            self.state(),
            AssociationState::CookieWait | AssociationState::CookieEchoed
        ) && p.chunks.iter().any(|c| c.as_any().is::<ChunkShutdownAck>())
        {
            let packet = Packet {
                common_header: CommonHeader {
                    verification_tag: p.common_header.verification_tag,
                    source_port: self.source_port,
                    destination_port: self.destination_port,
                },
                chunks: vec![Box::new(ChunkShutdownComplete {
                    tag_reflected: true,
                })],
            };
            self.control_queue.push_back(packet);
            self.awake_write_loop();
            return Ok(());
        }

        if !self.accepts_verification_tag(&p) {
            debug!(
                "[{}] discarding a packet with Verification Tag {}",
                self.side, p.common_header.verification_tag
            );
            return Ok(());
        }

        self.handle_chunk_start();

        // RFC 9260 9.1: a packet that carries an ABORT is not answered. The ABORT is taken
        // first, so nothing queued for the chunks bundled before it goes out.
        if let Some(abort) = p.chunks.iter().find(|c| c.as_any().is::<ChunkAbort>()) {
            self.handle_chunk(&p, abort, now)?;
            return Ok(());
        }

        // RFC 9260 9.2: in SHUTDOWN-SENT any packet from the peer shows it is still there
        // (it is sending what it had queued): the retransmission count starts over and so
        // does T2-shutdown.
        if self.state() == AssociationState::ShutdownSent {
            self.timers.reset_retrans(Timer::T2Shutdown);
            if self.timers.get(Timer::T2Shutdown).is_some() {
                self.timers.stop(Timer::T2Shutdown);
                self.timers
                    .start(Timer::T2Shutdown, now, self.rto_mgr.get_rto());
            }
        }

        for c in &p.chunks {
            // `false`: the rest of the packet is discarded. An association that a chunk ended
            // processes none of the chunks after it either.
            if !self.handle_chunk(&p, c, now)? || self.ended || self.discard_rest_of_packet {
                break;
            }
        }

        self.handle_chunk_end(now);

        Ok(())
    }

    /// RFC 9260 8.5, 8.5.1: whether a received packet carries the Verification Tag it must.
    ///
    /// A packet with an INIT has tag 0 (and nothing else: `check_packet`). A packet with an
    /// ABORT or a SHUTDOWN COMPLETE has this side's tag, or the peer's tag with the T bit set
    /// (the sender had no TCB and reflected the tag it was sent). Every other packet has this
    /// side's tag.
    fn accepts_verification_tag(&self, p: &Packet) -> bool {
        let tag = p.common_header.verification_tag;
        for chunk in &p.chunks {
            let any = chunk.as_any();
            if any.downcast_ref::<ChunkInit>().is_some_and(|c| !c.is_ack) {
                return tag == 0;
            }
            let reflected = any
                .downcast_ref::<ChunkAbort>()
                .map(|c| c.tag_reflected)
                .or_else(|| {
                    any.downcast_ref::<ChunkShutdownComplete>()
                        .map(|c| c.tag_reflected)
                });
            if let Some(reflected) = reflected {
                return if reflected {
                    tag != 0 && tag == self.peer_verification_tag
                } else {
                    tag == self.my_verification_tag
                };
            }
        }
        tag == self.my_verification_tag
    }

    fn handle_chunk_start(&mut self) {
        self.delayed_ack_triggered = false;
        self.immediate_ack_triggered = false;
        self.pending_error_causes.clear();
        self.sack_packet_immediately = false;
        self.discard_rest_of_packet = false;
    }

    /// Queues an error cause for the ERROR chunk that answers the packet being processed.
    fn report_error(&mut self, cause: ErrorCause) {
        if self.pending_error_causes.len() < MAX_ERROR_CAUSES_PER_PACKET {
            self.pending_error_causes.push(cause);
        }
    }

    /// Sends the causes collected for this packet as one ERROR chunk, no larger than the MTU.
    fn flush_error_causes(&mut self) {
        if self.pending_error_causes.is_empty() || self.ended {
            self.pending_error_causes.clear();
            return;
        }
        let room = (self.mtu as usize)
            .saturating_sub(COMMON_HEADER_SIZE as usize + CHUNK_HEADER_SIZE)
            & !3;
        let mut used = 0;
        let mut causes = vec![];
        for mut cause in std::mem::take(&mut self.pending_error_causes) {
            let header = crate::chunk::ERROR_CAUSE_HEADER_LENGTH;
            if used + header >= room {
                break;
            }
            // A cause that quotes what was received (an unrecognized chunk) can be as large
            // as the packet it came in: it is cut to what fits.
            let fits = room - used - header;
            if cause.raw.len() > fits {
                cause.raw.truncate(fits);
            }
            used += cause.length() + get_padding_size(cause.length());
            causes.push(cause);
        }
        if !causes.is_empty() {
            let packet = self.create_packet(vec![Box::new(ChunkError {
                error_causes: causes,
            })]);
            self.control_queue.push_back(packet);
            self.awake_write_loop();
        }
    }

    fn handle_chunk_end(&mut self, now: Instant) {
        self.flush_error_causes();
        if self.immediate_ack_triggered {
            self.ack_state = AckState::Immediate;
            self.timers.stop(Timer::Ack);
            self.awake_write_loop();
        } else if self.delayed_ack_triggered {
            // Will send delayed ack in the next ack timeout
            self.ack_state = AckState::Delay;
            self.timers.start(Timer::Ack, now, ACK_INTERVAL);
        }
    }

    /// Handles one chunk. `Ok(false)` stops the processing of its packet: the chunks that
    /// follow are discarded.
    #[allow(clippy::borrowed_box)]
    fn handle_chunk(&mut self, p: &Packet, chunk: &Box<dyn Chunk>, now: Instant) -> Result<bool> {
        // A chunk that is not valid in itself (an INIT with a zero Initiate Tag, an a_rwnd
        // below the minimum) is discarded with the rest of its packet. It is no reason to
        // close an association: anyone who can reach this endpoint can send one.
        if let Err(err) = chunk.check() {
            warn!("[{}] discarding an invalid chunk: {}", self.side, err);
            if let Some(c) = chunk.as_any().downcast_ref::<ChunkInit>() {
                self.refuse_invalid_init(p, c, &err);
            }
            return Ok(false);
        }
        let chunk_any = chunk.as_any();
        let packets = if let Some(c) = chunk_any.downcast_ref::<ChunkInit>() {
            if c.is_ack {
                self.handle_init_ack(p, c, now)?
            } else {
                self.handle_init(p, c, now)?
            }
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkAbort>() {
            let mut err_str = String::new();
            for e in &c.error_causes {
                if matches!(e.code, USER_INITIATED_ABORT) {
                    debug!("User initiated abort received");
                    // The peer aborted the association: its streams are lost with it, which
                    // is not the stream reset `Reset` reports for a channel's own close.
                    let _ = self.close(AssociationError::AssociationClosed);
                    return Ok(false);
                }
                err_str += &format!("({})", e);
            }
            return Err(Error::ErrAbortChunk(err_str));
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkError>() {
            self.handle_error(c, now);
            // RFC 9260 §3.3.10 (RFC 4960 §3.3.10): "An Operation Error is not considered fatal
            // in and of itself". Only an ABORT ends the association, so report the causes and
            // carry on with the rest of the packet.
            let mut err_str = String::new();
            for e in &c.error_causes {
                err_str += &format!("({})", e);
            }
            warn!(
                "[{}] received ERROR chunk, with following errors: {}",
                self.side, err_str
            );
            vec![]
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkHeartbeat>() {
            self.handle_heartbeat(c)?
        } else if chunk_any.downcast_ref::<ChunkHeartbeatAck>().is_some() {
            // The engine sends no HEARTBEAT yet, so there is none to match this against.
            trace!("[{}] HEARTBEAT ACK", self.side);
            vec![]
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkCookieEcho>() {
            self.handle_cookie_echo(p, c, now)?
        } else if chunk_any.downcast_ref::<ChunkCookieAck>().is_some() {
            self.handle_cookie_ack()?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkPayloadData>() {
            self.handle_data(c)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkSelectiveAck>() {
            match self.handle_sack(c, now) {
                Ok(packets) => packets,
                Err(err) => {
                    // RFC 9260 6.2.1, 12.4: a SACK that acknowledges a TSN this side never
                    // sent is a protocol violation, and the association is aborted. It was
                    // closed without telling the peer (or, for the cumulative TSN, ignored).
                    warn!("[{}] aborting on an invalid SACK: {}", self.side, err);
                    self.abort_with(
                        vec![Self::protocol_violation(
                            "SACK acknowledges a TSN that was not sent",
                        )],
                        AssociationError::TransportError,
                    )?;
                    return Ok(false);
                }
            }
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkReconfig>() {
            self.handle_reconfig(c)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkForwardTsn>() {
            self.handle_forward_tsn(c)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkShutdown>() {
            self.handle_shutdown(c, now)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkShutdownAck>() {
            self.handle_shutdown_ack(c)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkShutdownComplete>() {
            self.handle_shutdown_complete(c)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkUnknown>() {
            return Ok(self.handle_unknown_chunk(c));
        } else {
            return Err(Error::ErrChunkTypeUnhandled);
        };

        if !packets.is_empty() {
            let mut buf: VecDeque<_> = packets.into_iter().collect();
            self.control_queue.append(&mut buf);
            self.awake_write_loop();
        }

        Ok(true)
    }

    /// RFC 9260 3.2: a chunk of an unrecognized type is handled by the upper two bits of the
    /// type. Returns whether the chunks after it are processed.
    fn handle_unknown_chunk(&mut self, c: &ChunkUnknown) -> bool {
        debug!(
            "[{}] unrecognized chunk type {}: {}{}",
            self.side,
            c.typ.0,
            if c.stops_processing() { "stop" } else { "skip" },
            if c.is_reported() { ", report" } else { "" },
        );
        if c.is_reported()
            && let Ok(raw) = c.marshal()
        {
            // The cause holds the chunk: type, flags, length and value.
            self.report_error(ErrorCause {
                code: UNRECOGNIZED_CHUNK_TYPE,
                raw,
            });
        }
        !c.stops_processing()
    }

    /// RFC 9260 3.3.2, 3.3.3: what follows the discarding of an INIT or INIT ACK that failed
    /// its checks. A zero Initiate Tag in an INIT is discarded silently. The other failures
    /// (a_rwnd below 1500, no outbound or no inbound streams) are answered with an ABORT sent
    /// to the chunk's Initiate Tag. The state of an existing association does not change,
    /// with the one exception the RFC makes: an INIT ACK in COOKIE-WAIT with a zero Initiate
    /// Tag or no streams is the answer to this side's INIT, and destroys the TCB.
    fn refuse_invalid_init(&mut self, p: &Packet, c: &ChunkInit, err: &Error) {
        let cause = ErrorCause {
            code: INVALID_MANDATORY_PARAMETER,
            ..Default::default()
        };
        let ends_handshake = c.is_ack
            && self.state() == AssociationState::CookieWait
            && (c.initiate_tag == 0 || c.num_outbound_streams == 0 || c.num_inbound_streams == 0);
        let abort = if c.initiate_tag != 0 {
            Some(self.abort_packet(c.initiate_tag, false, vec![cause]))
        } else if ends_handshake {
            // The peer gave no tag to send to: its own packet's tag is reflected.
            Some(self.abort_packet(p.common_header.verification_tag, true, vec![cause]))
        } else {
            None
        };
        if c.is_ack && self.state() != AssociationState::CookieWait {
            // RFC 9260 3.3.3: outside COOKIE-WAIT such an INIT ACK is discarded silently.
            return;
        }
        if let Some(mut abort) = abort {
            if !c.is_ack {
                // The answer to an INIT goes between the ports its packet came between.
                abort.common_header.source_port = p.common_header.destination_port;
                abort.common_header.destination_port = p.common_header.source_port;
            }
            self.control_queue.push_back(abort);
            self.awake_write_loop();
        }
        // An accepting association that was made for this INIT and has seen no valid one has
        // nothing to keep: it ends now and gives its place back.
        let unused_acceptor = !c.is_ack
            && self.side == Side::Server
            && self.state() == AssociationState::Closed
            && self.cookie_tcb.is_none();
        if ends_handshake || unused_acceptor {
            let reason = AssociationError::HandshakeFailed(err.to_string());
            self.error = Some(reason.clone());
            let _ = self.close(reason);
        }
    }

    /// RFC 9260 3.3.10: an ERROR is not fatal in itself. One cause is acted on: "Stale Cookie
    /// Error" in COOKIE-ECHOED (5.2.6), where the cookie this side echoed had outlived its
    /// lifetime. The setup is tried again with a new INIT, a bounded number of times.
    fn handle_error(&mut self, c: &ChunkError, now: Instant) {
        if self.state() != AssociationState::CookieEchoed
            || !c.error_causes.iter().any(|e| e.code == STALE_COOKIE_ERROR)
        {
            return;
        }
        self.timers.stop(Timer::T1Cookie);
        self.stored_cookie_echo = None;
        self.stale_cookie_restarts += 1;
        if self.stale_cookie_restarts > self.timers.max_retrans(Timer::T1Init) {
            let reason =
                AssociationError::HandshakeFailed(Error::ErrHandshakeCookieEcho.to_string());
            self.error = Some(reason.clone());
            let _ = self.close(reason);
            return;
        }
        debug!("[{}] stale cookie: sending a new INIT", self.side);
        // What the INIT ACK said is void with its cookie.
        self.peer_verification_tag = 0;
        let mut init = ChunkInit {
            initial_tsn: self.my_next_tsn,
            num_outbound_streams: self.configured_outbound_streams,
            num_inbound_streams: self.configured_inbound_streams,
            initiate_tag: self.my_verification_tag,
            advertised_receiver_window_credit: self.max_receive_buffer_size,
            ..Default::default()
        };
        init.set_supported_extensions();
        self.stored_init = Some(init);
        self.set_state(AssociationState::CookieWait);
        let _ = self.send_init();
        self.timers
            .start(Timer::T1Init, now, self.rto_mgr.get_rto());
    }

    /// Reads the optional parameters of a received INIT or INIT ACK (RFC 9260 3.3.2, 3.3.3).
    ///
    /// An unrecognized parameter is handled by the upper two bits of its type (RFC 9260
    /// 3.2.1): it ends the processing of the parameters after it or is skipped, and is
    /// reported or not.
    fn process_handshake_params(&self, params: &[Box<dyn Param>]) -> HandshakeParams {
        let mut out = HandshakeParams::default();
        for param in params {
            let any = param.as_any();
            if let Some(v) = any.downcast_ref::<ParamStateCookie>() {
                out.cookie = Some(v.cookie.clone());
            } else if let Some(v) = any.downcast_ref::<ParamSupportedExtensions>() {
                if v.chunk_types.contains(&CT_FORWARD_TSN) {
                    out.forward_tsn = true;
                }
            } else if any.downcast_ref::<ParamForwardTsnSupported>().is_some() {
                // RFC 3758 3.3.1: this parameter alone announces PR-SCTP.
                out.forward_tsn = true;
            } else if let Some(v) = any.downcast_ref::<ParamUnknown>() {
                if v.typ() == PARAM_HOST_NAME_ADDRESS {
                    out.host_name = param.marshal().ok();
                    continue;
                }
                if IGNORED_HANDSHAKE_PARAMS.contains(&v.typ()) {
                    continue;
                }
                if v.is_reported()
                    && let Ok(raw) = param.marshal()
                {
                    out.unrecognized.push(raw);
                }
                if v.stops_processing() {
                    break;
                }
            }
        }
        out
    }

    fn handle_init(&mut self, p: &Packet, i: &ChunkInit, now: Instant) -> Result<Vec<Packet>> {
        let state = self.state();
        debug!("[{}] chunkInit received in state '{}'", self.side, state);

        if state == AssociationState::ShutdownAckSent {
            // RFC 9260 9.2: an INIT in SHUTDOWN-ACK-SENT (the SHUTDOWN COMPLETE was lost and
            // the peer starts over) is discarded and the SHUTDOWN ACK sent again.
            self.will_send_shutdown_ack = true;
            self.awake_write_loop();
            return Ok(vec![]);
        }
        if state != AssociationState::Closed
            && state != AssociationState::CookieWait
            && state != AssociationState::CookieEchoed
        {
            // RFC 9260 5.2.2: an unexpected INIT is answered and changes nothing. It used to
            // be an error, and an error closed the association: a late copy of the peer's own
            // INIT ended an established association.
            return Ok(vec![self.answer_unexpected_init(i)]);
        }

        let params = self.process_handshake_params(&i.params);
        if let Some(host_name) = params.host_name {
            // RFC 9260 5.1.2: an INIT with a Host Name Address is answered with an ABORT.
            debug!("[{}] INIT with a Host Name Address: ABORT", self.side);
            let mut abort = self.abort_packet(
                i.initiate_tag,
                false,
                vec![ErrorCause {
                    code: UNRESOLVABLE_ADDRESS,
                    raw: host_name,
                }],
            );
            abort.common_header.source_port = p.common_header.destination_port;
            abort.common_header.destination_port = p.common_header.source_port;
            if state == AssociationState::Closed && self.cookie_tcb.is_none() {
                let reason =
                    AssociationError::HandshakeFailed(Error::ErrHandshakeInitAck.to_string());
                self.error = Some(reason.clone());
                self.close(reason)?;
            }
            return Ok(vec![abort]);
        }

        // RFC 9260 5.1.1: this side sends on min(own OS, peer's MIS) streams and receives on
        // min(own MIS, peer's OS). Taken from the configured counts each time, so an INIT sent
        // again with other values is not narrowed by the one before it.
        let inbound_streams =
            std::cmp::min(i.num_outbound_streams, self.configured_inbound_streams);
        let outbound_streams =
            std::cmp::min(i.num_inbound_streams, self.configured_outbound_streams);
        let source_port = p.common_header.destination_port;
        let destination_port = p.common_header.source_port;

        // A State Cookie for this INIT: a new one for a new attempt (another Initiate Tag) or
        // when the one in hand has outlived its lifetime, the same one for an INIT sent again,
        // so that the cookie of an INIT ACK already under way stays good.
        let reuse = self.my_cookie.is_some()
            && self.cookie_tcb.as_ref().is_some_and(|tcb| {
                tcb.peer_verification_tag == i.initiate_tag
                    && now.saturating_duration_since(tcb.created_at) < self.valid_cookie_life
            });
        if !reuse {
            self.my_cookie = Some(ParamStateCookie::new());
        }
        let created_at = match (&self.cookie_tcb, reuse) {
            (Some(tcb), true) => tcb.created_at,
            _ => now,
        };
        let tcb = CookieTcb {
            created_at,
            peer_verification_tag: i.initiate_tag,
            peer_initial_tsn: i.initial_tsn,
            peer_rwnd: i.advertised_receiver_window_credit,
            inbound_streams,
            outbound_streams,
            use_forward_tsn: params.forward_tsn,
            source_port,
            destination_port,
        };

        // RFC 9260 5.2.1: in COOKIE-WAIT and COOKIE-ECHOED the INIT is answered with this
        // side's own INIT parameters and nothing in the TCB changes: what the INIT said is
        // kept with the cookie and taken when the cookie comes back. In CLOSED the accepting
        // association has no TCB to protect, and takes it now.
        if state == AssociationState::Closed {
            self.apply_cookie_tcb(&tcb);
            if !self.use_forward_tsn {
                warn!("[{}] not using ForwardTSN (on init)", self.side);
            }
        }
        self.cookie_tcb = Some(tcb);

        let mut init_ack = ChunkInit {
            is_ack: true,
            initial_tsn: self.my_next_tsn,
            num_outbound_streams: outbound_streams,
            num_inbound_streams: inbound_streams,
            initiate_tag: self.my_verification_tag,
            advertised_receiver_window_credit: self.max_receive_buffer_size,
            ..Default::default()
        };

        if let Some(my_cookie) = &self.my_cookie {
            init_ack.params = vec![Box::new(my_cookie.clone())];
        }

        // RFC 9260 3.2.2, 3.3.3: the unrecognized parameters the INIT asked to hear about go
        // back in the INIT ACK, each in an Unrecognized Parameter parameter.
        for raw in params.unrecognized {
            init_ack
                .params
                .push(Box::new(ParamUnknown::new(UNRECOGNIZED_PARAMETER, raw)));
        }

        init_ack.set_supported_extensions();

        if state == AssociationState::Closed {
            // The accepting side holds this association from the INIT on. If no COOKIE ECHO
            // follows it must not be held for ever: every INIT restarts the wait.
            self.timers.stop(Timer::HalfOpen);
            self.timers.start(Timer::HalfOpen, now, HALF_OPEN_LIFETIME);
        }

        Ok(vec![Packet {
            common_header: CommonHeader {
                verification_tag: i.initiate_tag,
                source_port,
                destination_port,
            },
            chunks: vec![Box::new(init_ack)],
        }])
    }

    /// Takes into the TCB what the peer's INIT said (RFC 9260 5.1 B, 5.2.4 B).
    fn apply_cookie_tcb(&mut self, tcb: &CookieTcb) {
        self.my_max_num_inbound_streams = tcb.inbound_streams;
        self.my_max_num_outbound_streams = tcb.outbound_streams;
        self.peer_verification_tag = tcb.peer_verification_tag;
        self.source_port = tcb.source_port;
        self.destination_port = tcb.destination_port;

        // 13.2 This is the last TSN received in sequence.  This value
        // is set initially by taking the peer's initial TSN,
        // received in the INIT or INIT ACK chunk, and
        // subtracting one from it.
        self.peer_last_tsn = tcb.peer_initial_tsn.wrapping_sub(1);

        // Adopt the peer's advertised receive window and seed ssthresh from it,
        // mirroring handle_init_ack (and Pion's shared init path). RFC 4960
        // §7.2.1 (Slow-Start) permits initialising ssthresh to the advertised
        // receiver window; without this the answerer keeps ssthresh at its
        // initial 0, so cwnd never starts below it, slow-start never runs, and
        // cwnd only grows linearly under congestion avoidance (§7.2.2).
        self.rwnd = tcb.peer_rwnd;
        debug!("[{}] initial rwnd={}", self.side, self.rwnd);
        self.ssthresh = self.rwnd;
        self.use_forward_tsn = tcb.use_forward_tsn;
    }

    /// RFC 9260 5.2.2: the INIT ACK for an INIT that arrives while the association exists. It
    /// goes to the INIT's Initiate Tag and carries a new one of its own; the association and
    /// its TCB stay as they are.
    ///
    /// The cookie it carries is not one this association will accept, so a COOKIE ECHO that
    /// answers it is discarded: restarting an association (5.2.4, action A) is not supported.
    fn answer_unexpected_init(&self, i: &ChunkInit) -> Packet {
        let mut initiate_tag = random::<u32>();
        if initiate_tag == 0 {
            initiate_tag = 1;
        }
        let mut init_ack = ChunkInit {
            is_ack: true,
            initial_tsn: self.my_next_tsn,
            num_outbound_streams: self.my_max_num_outbound_streams,
            num_inbound_streams: self.my_max_num_inbound_streams,
            initiate_tag,
            advertised_receiver_window_credit: self.max_receive_buffer_size,
            params: vec![Box::new(ParamStateCookie::new())],
        };
        init_ack.set_supported_extensions();
        Packet {
            common_header: CommonHeader {
                verification_tag: i.initiate_tag,
                source_port: self.source_port,
                destination_port: self.destination_port,
            },
            chunks: vec![Box::new(init_ack)],
        }
    }

    fn handle_init_ack(
        &mut self,
        p: &Packet,
        i: &ChunkInitAck,
        now: Instant,
    ) -> Result<Vec<Packet>> {
        let state = self.state();
        debug!("[{}] chunkInitAck received in state '{}'", self.side, state);
        if state != AssociationState::CookieWait {
            // RFC 4960
            // 5.2.3.  Unexpected INIT ACK
            //   If an INIT ACK is received by an endpoint in any state other than the
            //   COOKIE-WAIT state, the endpoint should discard the INIT ACK chunk.
            //   An unexpected INIT ACK usually indicates the processing of an old or
            //   duplicated INIT chunk.
            return Ok(vec![]);
        }

        // Checked before anything is taken from the chunk: an INIT ACK between other ports
        // is not this association's.
        if self.source_port != p.common_header.destination_port
            || self.destination_port != p.common_header.source_port
        {
            warn!("[{}] handle_init_ack: port mismatch", self.side);
            return Ok(vec![]);
        }

        // RFC 9260 5.1.1: own OS against the peer's MIS, own MIS against the peer's OS.
        self.my_max_num_inbound_streams =
            std::cmp::min(i.num_outbound_streams, self.configured_inbound_streams);
        self.my_max_num_outbound_streams =
            std::cmp::min(i.num_inbound_streams, self.configured_outbound_streams);
        self.peer_verification_tag = i.initiate_tag;
        self.peer_last_tsn = i.initial_tsn.wrapping_sub(1);

        self.rwnd = i.advertised_receiver_window_credit;
        debug!("[{}] initial rwnd={}", self.side, self.rwnd);

        // RFC 4690 Sec 7.2.1
        //  o  The initial value of ssthresh MAY be arbitrarily high (for
        //     example, implementations MAY use the size of the receiver
        //     advertised window).
        self.ssthresh = self.rwnd;
        trace!(
            "[{}] updated cwnd={} ssthresh={} inflight={} (INI)",
            self.side,
            self.cwnd,
            self.ssthresh,
            self.inflight_queue.get_num_bytes()
        );

        self.timers.stop(Timer::T1Init);
        self.stored_init = None;

        let params = self.process_handshake_params(&i.params);
        self.use_forward_tsn |= params.forward_tsn;
        if !self.use_forward_tsn {
            warn!("[{}] not using ForwardTSN (on initAck)", self.side);
        }

        if let Some(host_name) = params.host_name {
            // RFC 9260 3.3.3, 5.1.2: an INIT ACK with a Host Name Address is answered with
            // an ABORT, and the attempt is over.
            let reason = AssociationError::HandshakeFailed(Error::ErrHandshakeInitAck.to_string());
            self.error = Some(reason.clone());
            self.abort_with(
                vec![ErrorCause {
                    code: UNRESOLVABLE_ADDRESS,
                    raw: host_name,
                }],
                reason,
            )?;
            return Ok(vec![]);
        }

        let Some(cookie) = params.cookie else {
            // RFC 9260 3.3.3: the State Cookie is mandatory. An INIT ACK without one cannot
            // be answered: ABORT "Missing Mandatory Parameter" (one parameter, type 7), and
            // the attempt is over.
            let mut raw = BytesMut::with_capacity(6);
            raw.extend_from_slice(&1u32.to_be_bytes());
            raw.extend_from_slice(&PARAM_STATE_COOKIE.to_be_bytes());
            let reason = AssociationError::HandshakeFailed(Error::ErrInitAckNoCookie.to_string());
            self.error = Some(reason.clone());
            self.abort_with(
                vec![ErrorCause {
                    code: MISSING_MANDATORY_PARAMETER,
                    raw: raw.freeze(),
                }],
                reason,
            )?;
            return Ok(vec![]);
        };

        self.stored_cookie_echo = Some(ChunkCookieEcho { cookie });

        if params.unrecognized.is_empty() {
            self.send_cookie_echo()?;
        } else {
            // RFC 9260 3.2.2, 3.3.3: the unrecognized parameters the INIT ACK asked to
            // hear about are reported in an ERROR chunk bundled with the COOKIE ECHO,
            // which stays the first chunk of the packet. A retransmission carries the
            // COOKIE ECHO alone.
            let mut raw = BytesMut::new();
            for (n, param) in params.unrecognized.iter().enumerate() {
                raw.extend_from_slice(param);
                if n + 1 != params.unrecognized.len() {
                    raw.extend_from_slice(&[0u8; 3][..get_padding_size(param.len())]);
                }
            }
            let error = ChunkError {
                error_causes: vec![ErrorCause {
                    code: UNRECOGNIZED_PARAMETERS,
                    raw: raw.freeze(),
                }],
            };
            let cookie_echo = self
                .stored_cookie_echo
                .clone()
                .ok_or(Error::ErrCookieEchoNotStoredToSend)?;
            let packet = self.create_packet(vec![Box::new(cookie_echo), Box::new(error)]);
            self.control_queue.push_back(packet);
            self.awake_write_loop();
        }

        self.timers
            .start(Timer::T1Cookie, now, self.rto_mgr.get_rto());

        self.set_state(AssociationState::CookieEchoed);

        Ok(vec![])
    }

    fn handle_heartbeat(&self, c: &ChunkHeartbeat) -> Result<Vec<Packet>> {
        trace!("[{}] chunkHeartbeat", self.side);
        if let Some(p) = c.params.first() {
            if let Some(hbi) = p.as_any().downcast_ref::<ParamHeartbeatInfo>() {
                return Ok(vec![Packet {
                    common_header: CommonHeader {
                        verification_tag: self.peer_verification_tag,
                        source_port: self.source_port,
                        destination_port: self.destination_port,
                    },
                    chunks: vec![Box::new(ChunkHeartbeatAck {
                        params: vec![Box::new(ParamHeartbeatInfo {
                            heartbeat_information: hbi.heartbeat_information.clone(),
                        })],
                    })],
                }]);
            } else {
                warn!(
                    "[{}] failed to handle Heartbeat, no ParamHeartbeatInfo",
                    self.side,
                );
            }
        }

        Ok(vec![])
    }

    /// RFC 9260 5.1.5 and 5.2.4: a COOKIE ECHO.
    ///
    /// The State Cookie of this implementation is not a self-contained, MAC-protected TCB:
    /// the association exists from the INIT on (see `HALF_OPEN_LIFETIME`), so the cookie is
    /// 32 random bytes and what it stands for is kept beside it (`CookieTcb`). It is
    /// authenticated by comparing it, in constant time, with the one this association sent,
    /// which no one who has not seen the INIT ACK can produce; that is what the MAC is for.
    /// Its creation time and the peer's tag and ports are checked from the kept copy.
    ///
    /// With one cookie per association there is no cookie whose tags differ from the TCB's,
    /// so of Table 12 only the actions for matching tags arise: B and D (enter or stay in
    /// ESTABLISHED, send COOKIE ACK) for the cookie in hand, and the silent discard of C for
    /// any other. Restarting an association (action A) is not supported.
    fn handle_cookie_echo(
        &mut self,
        p: &Packet,
        c: &ChunkCookieEcho,
        now: Instant,
    ) -> Result<Vec<Packet>> {
        let state = self.state();
        debug!("[{}] COOKIE-ECHO received in state '{}'", self.side, state);

        // RFC 9260 5.1.5 2), 3): a cookie that is not the one sent, or that comes between
        // other ports, has its whole packet discarded, DATA included.
        let (Some(my_cookie), Some(tcb)) = (&self.my_cookie, self.cookie_tcb.clone()) else {
            debug!("[{}] COOKIE-ECHO received before initialization", self.side);
            self.discard_rest_of_packet = true;
            return Ok(vec![]);
        };
        if !constant_time_eq(&my_cookie.cookie, &c.cookie)
            || p.common_header.source_port != tcb.destination_port
            || p.common_header.destination_port != tcb.source_port
        {
            self.discard_rest_of_packet = true;
            return Ok(vec![]);
        }

        match state {
            AssociationState::Closed
            | AssociationState::CookieWait
            | AssociationState::CookieEchoed => {
                // RFC 9260 5.1.5 4): past its lifetime the cookie is refused with an ERROR
                // "Stale Cookie", which tells the peer by how many microseconds.
                let age = now.saturating_duration_since(tcb.created_at);
                if age > self.valid_cookie_life {
                    let staleness = (age - self.valid_cookie_life).as_micros();
                    let staleness = u32::try_from(staleness).unwrap_or(u32::MAX);
                    self.discard_rest_of_packet = true;
                    return Ok(vec![Packet {
                        common_header: CommonHeader {
                            verification_tag: tcb.peer_verification_tag,
                            source_port: tcb.source_port,
                            destination_port: tcb.destination_port,
                        },
                        chunks: vec![Box::new(ChunkError {
                            error_causes: vec![ErrorCause {
                                code: STALE_COOKIE_ERROR,
                                raw: Bytes::copy_from_slice(&staleness.to_be_bytes()),
                            }],
                        })],
                    }]);
                }

                // RFC 9260 5.2.4 B: after an INIT collision the peer's tag is the one that
                // came with this cookie.
                if state != AssociationState::Closed {
                    self.apply_cookie_tcb(&tcb);
                }

                self.timers.stop(Timer::T1Init);
                self.stored_init = None;

                self.timers.stop(Timer::T1Cookie);
                self.stored_cookie_echo = None;
                self.timers.stop(Timer::HalfOpen);

                self.events.push_back(Event::Connected);
                self.set_state(AssociationState::Established);
                self.handshake_completed = true;
                // RFC 9260 5.1.5 7): DATA that came with the COOKIE ECHO is acknowledged
                // at once.
                self.sack_packet_immediately = true;
            }
            // RFC 9260 5.2.4 D, and case E of 5.2: the cookie of the association that exists
            // (the COOKIE ACK was lost) is acknowledged again, whatever its age.
            _ => {}
        };

        Ok(vec![Packet {
            common_header: CommonHeader {
                verification_tag: self.peer_verification_tag,
                source_port: self.source_port,
                destination_port: self.destination_port,
            },
            chunks: vec![Box::new(ChunkCookieAck {})],
        }])
    }

    fn handle_cookie_ack(&mut self) -> Result<Vec<Packet>> {
        let state = self.state();
        debug!("[{}] COOKIE-ACK received in state '{}'", self.side, state);
        if state != AssociationState::CookieEchoed {
            // RFC 4960
            // 5.2.5.  Handle Duplicate COOKIE-ACK.
            //   At any state other than COOKIE-ECHOED, an endpoint should silently
            //   discard a received COOKIE ACK chunk.
            return Ok(vec![]);
        }

        self.timers.stop(Timer::T1Cookie);
        self.stored_cookie_echo = None;

        self.events.push_back(Event::Connected);
        self.set_state(AssociationState::Established);
        self.handshake_completed = true;

        Ok(vec![])
    }

    fn handle_data(&mut self, d: &ChunkPayloadData) -> Result<Vec<Packet>> {
        debug!(
            "[{}] DATA: tsn={} peer_last_tsn={} immediateSack={} len={}, unordered={}",
            self.side,
            d.tsn,
            self.peer_last_tsn,
            d.immediate_sack,
            d.user_data.len(),
            d.unordered,
        );
        self.stats.inc_datas();

        // RFC 9260 section 6.2: a DATA chunk with no user data is answered with an ABORT
        // carrying the "No User Data" cause. Accepting one would cost receive state without
        // counting against the byte-based receive window.
        if d.user_data.is_empty() {
            debug!(
                "[{}] DATA tsn={} has no user data: aborting",
                self.side, d.tsn
            );
            let abort = ChunkAbort {
                error_causes: vec![ErrorCause {
                    code: NO_USER_DATA,
                    raw: Bytes::copy_from_slice(&d.tsn.to_be_bytes()),
                }],
                ..Default::default()
            };
            let packet = self.create_packet(vec![Box::new(abort)]);
            self.control_queue.push_back(packet);
            self.awake_write_loop();
            self.close(AssociationError::TransportError)?;
            return Err(Error::ErrAbortChunk(NO_USER_DATA.to_string()));
        }

        // A stream id at or past the inbound stream count negotiated in INIT/INIT-ACK is not
        // one the peer may use (RFC 9260 6.5); creating state for it would let a peer make us
        // hold up to 65536 streams.
        //
        // RFC 9260 6.5: such a chunk is still acknowledged (it only is not delivered), and
        // answered with an ERROR "Invalid Stream Identifier". Its TSN is recorded without the
        // payload. Left unrecorded, as it was, the cumulative TSN could never pass it: the
        // peer retransmitted it for ever and in the end every chunk after it was refused.
        if self.my_max_num_inbound_streams != 0
            && d.stream_identifier >= self.my_max_num_inbound_streams
        {
            debug!(
                "[{}] discard DATA on stream {} (negotiated inbound streams: {})",
                self.side, d.stream_identifier, self.my_max_num_inbound_streams
            );
            let can_push = self.payload_queue.can_push(d, self.peer_last_tsn);
            if can_push {
                self.payload_queue.push(
                    ChunkPayloadData {
                        user_data: Bytes::new(),
                        ..d.clone()
                    },
                    self.peer_last_tsn,
                );
                let mut raw = BytesMut::with_capacity(4);
                raw.extend_from_slice(&d.stream_identifier.to_be_bytes());
                raw.extend_from_slice(&[0, 0]);
                self.report_error(ErrorCause {
                    code: INVALID_STREAM_IDENTIFIER,
                    raw: raw.freeze(),
                });
            } else {
                self.payload_queue.record_duplicate(d.tsn);
            }
            return self.handle_peer_last_tsn_and_acknowledgement(d.immediate_sack || !can_push);
        }

        let can_push = self.payload_queue.can_push(d, self.peer_last_tsn);
        let mut stream_handle_data = false;
        if can_push {
            if self.get_or_create_stream(d.stream_identifier).is_some() {
                if self.get_my_receiver_window_credit() > 0 {
                    // Pass the new chunk to stream level as soon as it arrives
                    self.payload_queue.push(d.clone(), self.peer_last_tsn);
                    stream_handle_data = true;
                } else {
                    // Receive buffer is full. Two kinds of chunk are still worth taking,
                    // because refusing them is not something the application can relieve by
                    // draining.
                    //
                    // The first fills a gap below the highest TSN already queued.
                    let fills_gap = self
                        .payload_queue
                        .get_last_tsn_received()
                        .is_some_and(|last_tsn| sna32lt(d.tsn, *last_tsn));

                    // The second is the next in-sequence chunk when nothing is readable at
                    // all, and it is what keeps a full buffer from becoming permanent. Bytes
                    // are released only when the application reads; `is_readable()` is
                    // head-of-line blocked by an incomplete chunk set; and the chunk that
                    // would complete that set is exactly `peer_last_tsn + 1`. Dropping it
                    // leaves the window at zero with no way to reopen — every retransmission
                    // is refused for the same reason, forever.
                    // See <https://github.com/webrtc-rs/webrtc/issues/822>.
                    //
                    // Guarded on nothing being readable so this stays an escape from deadlock
                    // rather than a licence to overrun the bound. A merely slow receiver has
                    // data to take and must be made to take it. Without the guard, the chunk
                    // accepted here is `peer_last_tsn + 1` — precisely the one that advances
                    // the cumulative ack — so every chunk would qualify and
                    // `max_receive_buffer_size` would stop bounding anything.
                    let unblocks_reassembly =
                        d.tsn == self.peer_last_tsn.wrapping_add(1) && !self.has_readable_data();

                    // Either kind may take the receiver past `max_receive_buffer_size`, which
                    // is what lets a message larger than the buffer be reassembled at all. But
                    // the headroom this needs is one message, so neither kind is taken past
                    // one inbound message (the size this side advertised) beyond the buffer.
                    let within_headroom = self.bytes_in_reassembly_queues() + d.user_data.len()
                        <= self.max_receive_buffer_size as usize
                            + self.max_receive_message_size as usize;

                    if (fills_gap || unblocks_reassembly) && within_headroom {
                        debug!(
                            "[{}] receive buffer full, but accepted {} with tsn={} ssn={}",
                            self.side,
                            if fills_gap {
                                "as this is a missing chunk"
                            } else {
                                "as the in-sequence chunk that unblocks reassembly"
                            },
                            d.tsn,
                            d.stream_sequence_number
                        );
                        self.payload_queue.push(d.clone(), self.peer_last_tsn);
                        stream_handle_data = true;
                    } else {
                        debug!(
                            "[{}] receive buffer full. dropping DATA with tsn={} ssn={}",
                            self.side, d.tsn, d.stream_sequence_number
                        );
                    }
                }
            } else {
                // silently discard the data. (sender will retry on T3-rtx timeout)
                debug!("[{}] discard {}", self.side, d.stream_sequence_number);
                return Ok(vec![]);
            }
        } else {
            self.payload_queue.record_duplicate(d.tsn);
        }

        // RFC 9260 section 6.2: a repeat is listed in a SACK sent at once. So is the first
        // DATA chunk of the association (5.1), DATA that came with the COOKIE ECHO (5.1.5),
        // and DATA received in SHUTDOWN-SENT (9.2), which is also answered with the SHUTDOWN
        // again.
        let first = !self.first_data_received;
        self.first_data_received = true;
        let mut immediate_sack =
            d.immediate_sack || !can_push || first || self.sack_packet_immediately;
        if self.state() == AssociationState::ShutdownSent {
            immediate_sack = true;
            self.will_send_shutdown = true;
            self.awake_write_loop();
        }

        if stream_handle_data && let Some(s) = self.streams.get_mut(&d.stream_identifier) {
            self.events.push_back(Event::DatagramReceived);
            let bytes_before = s.get_num_bytes_in_reassembly_queue();
            if s.handle_data(d) && s.reassembly_queue.is_readable() {
                self.events.push_back(Event::Stream(StreamEvent::Readable {
                    id: s.stream_identifier,
                }));
            }
            self.reindex_stream(d.stream_identifier, bytes_before);
        }

        self.handle_peer_last_tsn_and_acknowledgement(immediate_sack)
    }

    fn handle_sack(&mut self, d: &ChunkSelectiveAck, now: Instant) -> Result<Vec<Packet>> {
        trace!(
            "[{}] {}, SACK: cumTSN={} a_rwnd={}",
            self.side,
            self.cumulative_tsn_ack_point,
            d.cumulative_tsn_ack,
            d.advertised_receiver_window_credit
        );
        let state = self.state();
        if state != AssociationState::Established
            && state != AssociationState::ShutdownPending
            && state != AssociationState::ShutdownReceived
        {
            return Ok(vec![]);
        }

        self.stats.inc_sacks();

        if sna32gt(self.cumulative_tsn_ack_point, d.cumulative_tsn_ack) {
            // RFC 4960 sec 6.2.1.  Processing a Received SACK
            // D)
            //   i) If Cumulative TSN Ack is less than the Cumulative TSN Ack
            //      Point, then drop the SACK.  Since Cumulative TSN Ack is
            //      monotonically increasing, a SACK whose Cumulative TSN Ack is
            //      less than the Cumulative TSN Ack Point indicates an out-of-
            //      order SACK.

            debug!(
                "[{}] SACK Cumulative ACK {} is older than ACK point {}",
                self.side, d.cumulative_tsn_ack, self.cumulative_tsn_ack_point
            );

            return Ok(vec![]);
        }

        // A SACK may not acknowledge DATA this side never sent (RFC 9260 6.2.1, 12.4): it is
        // an error, and the caller aborts the association. Nothing is taken from it.
        if sna32gte(d.cumulative_tsn_ack, self.my_next_tsn) {
            debug!(
                "[{}] SACK Cumulative ACK {} is beyond the next TSN {}",
                self.side, d.cumulative_tsn_ack, self.my_next_tsn
            );
            return Err(Error::ErrTsnRequestNotExist);
        }

        // Process selective ack
        let (bytes_acked_per_stream, total_bytes_acked, htna) =
            self.process_selective_ack(d, now)?;

        let mut cum_tsn_ack_point_advanced = false;
        if sna32lt(self.cumulative_tsn_ack_point, d.cumulative_tsn_ack) {
            trace!(
                "[{}] SACK: cumTSN advanced: {} -> {}",
                self.side, self.cumulative_tsn_ack_point, d.cumulative_tsn_ack
            );

            self.cumulative_tsn_ack_point = d.cumulative_tsn_ack;
            cum_tsn_ack_point_advanced = true;
            self.on_cumulative_tsn_ack_point_advanced(total_bytes_acked, now);
        }

        self.release_stream_buffers(&bytes_acked_per_stream);

        // New rwnd value
        // RFC 4960 sec 6.2.1.  Processing a Received SACK
        // D)
        //   ii) Set rwnd equal to the newly received a_rwnd minus the number
        //       of bytes still outstanding after processing the Cumulative
        //       TSN Ack and the Gap Ack Blocks.

        // acknowledged payload bytes were already released from the in-flight queue
        let bytes_outstanding = self.inflight_queue.get_num_bytes() as u32;
        if bytes_outstanding >= d.advertised_receiver_window_credit {
            self.rwnd = 0;
        } else {
            self.rwnd = d.advertised_receiver_window_credit - bytes_outstanding;
        }

        // The highest TSN this SACK acknowledges: every outstanding TSN below it is one the
        // SACK reports missing (RFC 9260 7.2.4).
        let highest_reported = d
            .gap_ack_blocks
            .iter()
            .map(|g| d.cumulative_tsn_ack.wrapping_add(g.end as u32))
            .fold(d.cumulative_tsn_ack, |highest, tsn| {
                if sna32gt(tsn, highest) { tsn } else { highest }
            });
        self.process_fast_retransmission(
            d.cumulative_tsn_ack,
            htna,
            highest_reported,
            cum_tsn_ack_point_advanced,
            now,
        )?;

        if self.use_forward_tsn {
            // RFC 3758 Sec 3.5 C1
            if sna32lt(
                self.advanced_peer_tsn_ack_point,
                self.cumulative_tsn_ack_point,
            ) {
                self.advanced_peer_tsn_ack_point = self.cumulative_tsn_ack_point;
                // Window reset: everything previously tracked is now at/below
                // the cumulative ack point, so start the stream map fresh.
                self.fwd_tsn_stream_map.clear();
            }

            self.advance_peer_ack_point();
            self.awake_write_loop();
        }

        self.postprocess_sack(state, cum_tsn_ack_point_advanced, now);

        Ok(vec![])
    }

    fn handle_reconfig(&mut self, c: &ChunkReconfig) -> Result<Vec<Packet>> {
        trace!("[{}] handle_reconfig", self.side);

        let mut pp = vec![];

        if let Some(param_a) = &c.param_a {
            self.handle_reconfig_param(param_a, &mut pp)?;
        }

        if let Some(param_b) = &c.param_b {
            self.handle_reconfig_param(param_b, &mut pp)?;
        }

        Ok(pp)
    }

    fn handle_forward_tsn(&mut self, c: &ChunkForwardTsn) -> Result<Vec<Packet>> {
        trace!("[{}] FwdTSN: {}", self.side, c);

        if !self.use_forward_tsn {
            warn!("[{}] received FwdTSN but not enabled", self.side);
            // Return an error chunk
            let cerr = ChunkError {
                error_causes: vec![ErrorCauseUnrecognizedChunkType::default()],
            };

            let outbound = Packet {
                common_header: CommonHeader {
                    verification_tag: self.peer_verification_tag,
                    source_port: self.source_port,
                    destination_port: self.destination_port,
                },
                chunks: vec![Box::new(cerr)],
            };
            return Ok(vec![outbound]);
        }

        // From RFC 3758 Sec 3.6:
        //   Note, if the "New Cumulative TSN" value carried in the arrived
        //   FORWARD TSN chunk is found to be behind or at the current cumulative
        //   TSN point, the data receiver MUST treat this FORWARD TSN as out-of-
        //   date and MUST NOT update its Cumulative TSN.  The receiver SHOULD
        //   send a SACK to its peer (the sender of the FORWARD TSN) since such a
        //   duplicate may indicate the previous SACK was lost in the network.

        trace!(
            "[{}] should send ack? newCumTSN={} peer_last_tsn={}",
            self.side, c.new_cumulative_tsn, self.peer_last_tsn
        );
        if sna32lte(c.new_cumulative_tsn, self.peer_last_tsn) {
            trace!("[{}] sending ack on Forward TSN", self.side);
            self.ack_state = AckState::Immediate;
            self.timers.stop(Timer::Ack);
            self.awake_write_loop();
            return Ok(vec![]);
        }

        // From RFC 3758 Sec 3.6:
        //   the receiver MUST perform the same TSN handling, including duplicate
        //   detection, gap detection, SACK generation, cumulative TSN
        //   advancement, etc. as defined in RFC 2960 [2]---with the following
        //   exceptions and additions.

        //   When a FORWARD TSN chunk arrives, the data receiver MUST first update
        //   its cumulative TSN point to the value carried in the FORWARD TSN
        //   chunk,

        // Advance peer_last_tsn. Drop only the chunks actually queued below the new point and
        // jump straight to it: stepping one TSN at a time let a FORWARD-TSN about 2^31 ahead
        // spin for billions of iterations.
        while let Some(&front) = self.payload_queue.sorted.front() {
            if !sna32lte(front, c.new_cumulative_tsn) || self.payload_queue.pop(front).is_none() {
                break;
            }
        }
        let prev_peer_last_tsn = self.peer_last_tsn;
        self.peer_last_tsn = c.new_cumulative_tsn;

        // Report new peer_last_tsn value and abandoned largest SSN value to
        // corresponding streams so that the abandoned chunks can be removed
        // from the reassemblyQueue.
        for forwarded in &c.streams {
            if let Some(s) = self.streams.get_mut(&forwarded.identifier) {
                let bytes_before = s.get_num_bytes_in_reassembly_queue();
                s.handle_forward_tsn_for_ordered(forwarded.sequence);
                if s.reassembly_queue.is_readable() {
                    self.events.push_back(Event::Stream(StreamEvent::Readable {
                        id: s.stream_identifier,
                    }));
                }
                self.reindex_stream(forwarded.identifier, bytes_before);
            }
        }

        // TSN may be forwarded for unordered chunks. ForwardTSN chunk does not
        // report which stream identifier it skipped for unordered chunks.
        // Therefore, we need to broadcast this event to all existing streams for
        // unordered chunks. A stream with an empty reassembly queue has nothing to
        // forward and nothing to read, so only the streams holding data are visited.
        let with_data: Vec<StreamId> = self.streams_with_data.iter().copied().collect();
        for id in with_data {
            if let Some(s) = self.streams.get_mut(&id) {
                let bytes_before = s.get_num_bytes_in_reassembly_queue();
                s.handle_forward_tsn_for_unordered(c.new_cumulative_tsn);
                if s.reassembly_queue.is_readable() {
                    self.events.push_back(Event::Stream(StreamEvent::Readable {
                        id: s.stream_identifier,
                    }));
                }
                self.reindex_stream(id, bytes_before);
            }
        }

        // A stored reset request the new cumulative TSN reached is performed now, after the
        // streams have taken what the FORWARD TSN made readable.
        let mut reset_reply = vec![];
        self.reset_streams_reached_since(prev_peer_last_tsn, &mut reset_reply)?;
        let mut reply = self.handle_peer_last_tsn_and_acknowledgement(false)?;
        reset_reply.append(&mut reply);
        Ok(reset_reply)
    }

    fn handle_shutdown(&mut self, c: &ChunkShutdown, now: Instant) -> Result<Vec<Packet>> {
        let state = self.state();

        if state == AssociationState::Established
            || state == AssociationState::ShutdownReceived
            || state == AssociationState::ShutdownPending
        {
            // RFC 9260 9.2: a SHUTDOWN is taken in SHUTDOWN-PENDING too (both sides are
            // shutting down and the peer's SHUTDOWN came first).
            //
            // RFC 9260 9.2: the SHUTDOWN's Cumulative TSN Ack acknowledges our DATA up to it,
            // and the receiver checks by it that all its outstanding DATA has arrived. A
            // SHUTDOWN that crossed our last SACK is the only acknowledgement left for the
            // data in flight, so without this the association waited for T3-rtx.
            self.acknowledge_by_shutdown(c.cumulative_tsn_ack, now)?;
            if self.state() != state {
                // The acknowledgement drained the queue from SHUTDOWN-RECEIVED, which
                // already moved on to SHUTDOWN-ACK-SENT.
                return Ok(vec![]);
            }

            if !self.inflight_queue.is_empty() || !self.pending_queue.is_empty() {
                self.set_state(AssociationState::ShutdownReceived);
            } else {
                // No more outstanding, send shutdown ack.
                self.will_send_shutdown_ack = true;
                self.set_state(AssociationState::ShutdownAckSent);

                self.awake_write_loop();
            }
        } else if state == AssociationState::ShutdownSent {
            self.will_send_shutdown_ack = true;
            self.set_state(AssociationState::ShutdownAckSent);

            self.awake_write_loop();
        }

        Ok(vec![])
    }

    /// Processes a SHUTDOWN's Cumulative TSN Ack as a SACK without gap blocks (RFC 9260 9.2).
    ///
    /// The peer's receive window is left as it was: a SHUTDOWN does not carry one.
    fn acknowledge_by_shutdown(&mut self, cumulative_tsn_ack: u32, now: Instant) -> Result<()> {
        if !sna32gt(cumulative_tsn_ack, self.cumulative_tsn_ack_point)
            || sna32gte(cumulative_tsn_ack, self.my_next_tsn)
        {
            return Ok(());
        }
        let outstanding = self.inflight_queue.get_num_bytes() as u32;
        let sack = ChunkSelectiveAck {
            cumulative_tsn_ack,
            advertised_receiver_window_credit: self.rwnd.saturating_add(outstanding),
            gap_ack_blocks: vec![],
            duplicate_tsn: vec![],
        };
        self.handle_sack(&sack, now)?;
        Ok(())
    }

    fn handle_shutdown_ack(&mut self, _: &ChunkShutdownAck) -> Result<Vec<Packet>> {
        let state = self.state();
        if state == AssociationState::ShutdownSent || state == AssociationState::ShutdownAckSent {
            self.timers.stop(Timer::T2Shutdown);
            self.will_send_shutdown_complete = true;

            self.awake_write_loop();
        }

        Ok(vec![])
    }

    fn handle_shutdown_complete(&mut self, _: &ChunkShutdownComplete) -> Result<Vec<Packet>> {
        let state = self.state();
        if state == AssociationState::ShutdownAckSent {
            self.timers.stop(Timer::T2Shutdown);
            self.close(AssociationError::AssociationClosed)?;
        }

        Ok(vec![])
    }

    /// A common routine for handle_data and handle_forward_tsn routines
    fn handle_peer_last_tsn_and_acknowledgement(
        &mut self,
        sack_immediately: bool,
    ) -> Result<Vec<Packet>> {
        let mut reply = vec![];
        let prev_peer_last_tsn = self.peer_last_tsn;

        // Try to advance peer_last_tsn

        // From RFC 3758 Sec 3.6:
        //   .. and then MUST further advance its cumulative TSN point locally
        //   if possible
        // Meaning, if peer_last_tsn+1 points to a chunk that is received,
        // advance peer_last_tsn until peer_last_tsn+1 points to unreceived chunk.
        //debug!("[{}] peer_last_tsn = {}", self.side, self.peer_last_tsn);
        // TSNs are serial numbers (RFC 4960 §1.6): the cumulative point wraps past u32::MAX,
        // which a peer reaches at once with an initial TSN of 0 or a FORWARD-TSN to u32::MAX.
        while self
            .payload_queue
            .pop(self.peer_last_tsn.wrapping_add(1))
            .is_some()
        {
            self.peer_last_tsn = self.peer_last_tsn.wrapping_add(1);
            //debug!("[{}] peer_last_tsn = {}", self.side, self.peer_last_tsn);
        }

        // Perform the stored reset requests the cumulative TSN has just reached, each once.
        // A request reached earlier and still stored waits for its stream to drain
        // (`retry_deferred_resets`), so it is not answered again here.
        self.reset_streams_reached_since(prev_peer_last_tsn, &mut reply)?;

        let has_packet_loss = !self.payload_queue.is_empty();
        if has_packet_loss {
            trace!(
                "[{}] packetloss: {}",
                self.side,
                self.payload_queue
                    .get_gap_ack_blocks_string(self.peer_last_tsn)
            );
        }

        if (self.ack_state != AckState::Immediate
            && !sack_immediately
            && !has_packet_loss
            && self.ack_mode == AckMode::Normal)
            || self.ack_mode == AckMode::AlwaysDelay
        {
            if self.ack_state == AckState::Idle {
                self.delayed_ack_triggered = true;
            } else {
                self.immediate_ack_triggered = true;
            }
        } else {
            self.immediate_ack_triggered = true;
        }

        Ok(reply)
    }

    #[allow(clippy::borrowed_box)]
    fn handle_reconfig_param(
        &mut self,
        raw: &Box<dyn Param>,
        reply: &mut Vec<Packet>,
    ) -> Result<()> {
        if let Some(p) = raw.as_any().downcast_ref::<ParamOutgoingResetRequest>() {
            let rsn = p.reconfig_request_sequence_number;
            // A retransmission of a request already held or already performed is answered
            // again, but not performed again (RFC 6525 section 5.2.1).
            if self.reconfig_requests.contains_key(&rsn) {
                reply.push(self.create_reconfig_response(rsn, ReconfigResult::InProgress));
                return Ok(());
            }
            if self.completed_reconfig_requests.contains(&rsn) {
                reply.push(self.create_reconfig_response(rsn, ReconfigResult::SuccessPerformed));
                return Ok(());
            }
            if self.reconfig_requests.len() >= MAX_PENDING_RECONFIG_REQUESTS {
                debug!(
                    "[{}] deny reset request rsn={}: {} requests already pending",
                    self.side,
                    rsn,
                    self.reconfig_requests.len()
                );
                reply.push(self.create_reconfig_response(rsn, ReconfigResult::Denied));
                return Ok(());
            }
            self.reconfig_requests.insert(rsn, p.clone());
            self.reset_streams_if_any(p, true, reply)?;
            Ok(())
        } else if let Some(p) = raw.as_any().downcast_ref::<ParamReconfigResponse>() {
            // RFC 6525 5.1.1: "In progress" is not the outcome. The request stays outstanding
            // (and its timer running), so the final response still finds it.
            if p.result != ReconfigResult::InProgress
                && let Some(request) = self.reconfigs.remove(&p.reconfig_response_sequence_number)
                && matches!(
                    p.result,
                    ReconfigResult::SuccessPerformed | ReconfigResult::SuccessNop
                )
            {
                self.reset_outgoing_sequence_numbers(&request);
            }
            if self.reconfigs.is_empty() {
                self.timers.stop(Timer::Reconfig);
            }
            Ok(())
        } else {
            // A parameter this side does not handle. It is no reason to end the association.
            debug!("[{}] ignoring RE-CONFIG parameter {}", self.side, raw);
            Ok(())
        }
    }

    /// RFC 6525 5.1.2: once the peer has performed our Outgoing SSN Reset Request, the
    /// streams it named send again from SSN 0, which is what the peer now expects. A stream
    /// still registered here (the peer did not reset its own direction too, or the channel
    /// above reuses the stream) kept its old SSN, so the peer held every later ordered message
    /// back waiting for SSN 0.
    fn reset_outgoing_sequence_numbers(&mut self, request: &ChunkReconfig) {
        for param in [&request.param_a, &request.param_b].into_iter().flatten() {
            if let Some(reset) = param.as_any().downcast_ref::<ParamOutgoingResetRequest>() {
                for id in &reset.stream_identifiers {
                    if let Some(stream) = self.streams.get_mut(id) {
                        stream.sequence_number = 0;
                    }
                }
            }
        }
    }

    fn process_selective_ack(
        &mut self,
        d: &ChunkSelectiveAck,
        now: Instant,
    ) -> Result<(FxHashMap<u16, i64>, i64, u32)> {
        let mut bytes_acked_per_stream = FxHashMap::default();
        let mut total_bytes_acked = 0;
        let mut newly_acked_data = false;
        // Abandoned DATA can precede the earliest outstanding TSN. RFC 9260
        // 6.3.2 R3 applies to that outstanding DATA, including gap acknowledgments.
        let earliest_outstanding = self.inflight_queue.sorted.iter().copied().find(|tsn| {
            self.inflight_queue
                .get(*tsn)
                .is_some_and(ChunkPayloadData::is_outstanding)
        });

        // New ack point, so pop all ACKed packets from inflight_queue
        // We add 1 because the "currentAckPoint" has already been popped from the inflight queue
        // For the first SACK we take care of this by setting the ackpoint to cumAck - 1
        let mut i = self.cumulative_tsn_ack_point.wrapping_add(1);
        //log::debug!("[{}] i={} d={}", self.name, i, d.cumulative_tsn_ack);
        while sna32lte(i, d.cumulative_tsn_ack) {
            if let Some(mut c) = self.inflight_queue.pop(i) {
                if c.acknowledge() {
                    newly_acked_data |= c.nsent > 0;

                    let n_bytes_acked = c.user_data.len() as i64;
                    total_bytes_acked += n_bytes_acked;
                    // A late SACK for a retired stream must not release bytes
                    // belonging to a new channel that reused its SID.
                    if self.is_current_stream_data(&c) {
                        *bytes_acked_per_stream
                            .entry(c.stream_identifier)
                            .or_default() += n_bytes_acked;
                    }

                    // RFC 4960 sec 6.3.1.  RTO Calculation
                    //   C4)  When data is in flight and when allowed by rule C5 below, a new
                    //        RTT measurement MUST be made each round trip.  Furthermore, new
                    //        RTT measurements SHOULD be made no more than once per round trip
                    //        for a given destination transport address.
                    //   C5)  Karn's algorithm: RTT measurements MUST NOT be made using
                    //        packets that were retransmitted (and thus for which it is
                    //        ambiguous whether the reply was for the first instance of the
                    //        chunk or for a later instance)
                    if !c.abandoned() && c.nsent == 1 && sna32gte(c.tsn, self.min_tsn2measure_rtt) {
                        self.min_tsn2measure_rtt = self.my_next_tsn;
                        if let Some(since) = &c.since {
                            let rtt = now.duration_since(*since);
                            let srtt = self.rto_mgr.set_new_rtt(rtt.as_millis() as u64);
                            trace!(
                                "[{}] SACK: measured-rtt={} srtt={} new-rto={}",
                                self.side,
                                rtt.as_millis(),
                                srtt,
                                self.rto_mgr.get_rto()
                            );
                        } else {
                            error!("[{}] invalid c.since", self.side);
                        }
                    }
                }

                if self.in_fast_recovery && c.tsn == self.fast_recover_exit_point {
                    debug!("[{}] exit fast-recovery", self.side);
                    self.in_fast_recovery = false;
                }
            } else {
                return Err(Error::ErrInflightQueueTsnPop);
            }

            i = i.wrapping_add(1);
        }

        let mut htna = d.cumulative_tsn_ack;

        // Record peer acknowledgments independently of local payload release.
        for g in &d.gap_ack_blocks {
            for i in g.start..=g.end {
                let tsn = d.cumulative_tsn_ack.wrapping_add(i as u32);

                let newly_acknowledged = self.inflight_queue.acknowledge(tsn);
                let n_bytes_acked = if newly_acknowledged {
                    self.inflight_queue.release_payload(tsn) as i64
                } else {
                    0
                };

                if let Some(c) = self.inflight_queue.get(tsn) {
                    if newly_acknowledged {
                        newly_acked_data |= c.nsent > 0;
                        total_bytes_acked += n_bytes_acked;
                        if self.is_current_stream_data(c) {
                            *bytes_acked_per_stream
                                .entry(c.stream_identifier)
                                .or_default() += n_bytes_acked;
                        }

                        trace!("[{}] tsn={} has been sacked", self.side, c.tsn);

                        if !c.abandoned() && c.nsent == 1 {
                            self.min_tsn2measure_rtt = self.my_next_tsn;
                            if let Some(since) = &c.since {
                                let rtt = now.duration_since(*since);
                                let srtt = self.rto_mgr.set_new_rtt(rtt.as_millis() as u64);
                                trace!(
                                    "[{}] SACK: measured-rtt={} srtt={} new-rto={}",
                                    self.side,
                                    rtt.as_millis(),
                                    srtt,
                                    self.rto_mgr.get_rto()
                                );
                            } else {
                                error!("[{}] invalid c.since", self.side);
                            }
                        }

                        if sna32lt(htna, tsn) {
                            htna = tsn;
                        }
                    }
                } else {
                    return Err(Error::ErrTsnRequestNotExist);
                }
            }
        }

        // RFC 9260 8.1-8.2: an acknowledgment of new DATA clears the error
        // counter, including a late SACK after local abandonment. Payload
        // release does not acknowledge DATA; duplicates and never-sent TSNs
        // assigned only for FORWARD TSN do not count as newly acknowledged DATA.
        if newly_acked_data {
            self.timers.reset_retrans(Timer::T3RTX);
        }
        if earliest_outstanding.is_some_and(|tsn| {
            sna32lte(tsn, d.cumulative_tsn_ack)
                || self.inflight_queue.get(tsn).is_some_and(|c| c.acknowledged)
        }) {
            // Postprocessing restarts T3 with the current RTO if DATA/FORWARD
            // TSN remains outstanding.
            self.timers.set(Timer::T3RTX, None);
        }
        Ok((bytes_acked_per_stream, total_bytes_acked, htna))
    }

    fn on_cumulative_tsn_ack_point_advanced(&mut self, total_bytes_acked: i64, now: Instant) {
        // Every addition below saturates: cwnd doubles per round trip in slow start and is
        // bounded by nothing else, so after about 2 GiB acknowledged a plain `+=` wrapped it
        // to a tiny window (and panicked with overflow checks on).
        let total_bytes_acked = u32::try_from(total_bytes_acked.max(0)).unwrap_or(u32::MAX);
        // RFC 4096, sec 6.3.2.  Retransmission Timer Rules
        //   R2)  Whenever all outstanding data sent to an address have been
        //        acknowledged, turn off the T3-rtx timer of that address.
        if self.inflight_queue.is_empty() {
            trace!(
                "[{}] SACK: no more packet in-flight (pending={})",
                self.side,
                self.pending_queue.len()
            );
            self.timers.stop(Timer::T3RTX);
        } else {
            trace!("[{}] T3-rtx timer start (pt2)", self.side);
            self.timers
                .start_if_idle(Timer::T3RTX, now, self.rto_mgr.get_rto());
        }

        // Update congestion control parameters
        if self.cwnd <= self.ssthresh {
            // RFC 4096, sec 7.2.1.  Slow-Start
            //   o  When cwnd is less than or equal to ssthresh, an SCTP endpoint MUST
            //		use the slow-start algorithm to increase cwnd only if the current
            //      congestion window is being fully utilized, an incoming SACK
            //      advances the Cumulative TSN Ack Point, and the data sender is not
            //      in Fast Recovery.  Only when these three conditions are met can
            //      the cwnd be increased; otherwise, the cwnd MUST not be increased.
            //		If these conditions are met, then cwnd MUST be increased by, at
            //      most, the lesser of 1) the total size of the previously
            //      outstanding DATA chunk(s) acknowledged, and 2) the destination's
            //      path MTU.
            if !self.in_fast_recovery && !self.pending_queue.is_empty() {
                self.cwnd = self
                    .cwnd
                    .saturating_add(std::cmp::min(total_bytes_acked, self.cwnd)); // TCP way
                // self.cwnd += min32(uint32(total_bytes_acked), self.mtu) // SCTP way (slow)
                trace!(
                    "[{}] updated cwnd={} ssthresh={} acked={} (SS)",
                    self.side, self.cwnd, self.ssthresh, total_bytes_acked
                );
            } else {
                trace!(
                    "[{}] cwnd did not grow: cwnd={} ssthresh={} acked={} FR={} pending={}",
                    self.side,
                    self.cwnd,
                    self.ssthresh,
                    total_bytes_acked,
                    self.in_fast_recovery,
                    self.pending_queue.len()
                );
            }
        } else {
            // RFC 4096, sec 7.2.2.  Congestion Avoidance
            //   o  Whenever cwnd is greater than ssthresh, upon each SACK arrival
            //      that advances the Cumulative TSN Ack Point, increase
            //      partial_bytes_acked by the total number of bytes of all new chunks
            //      acknowledged in that SACK including chunks acknowledged by the new
            //      Cumulative TSN Ack and by Gap Ack Blocks.
            self.partial_bytes_acked = self.partial_bytes_acked.saturating_add(total_bytes_acked);

            //   o  When partial_bytes_acked is equal to or greater than cwnd and
            //      before the arrival of the SACK the sender had cwnd or more bytes
            //      of data outstanding (i.e., before arrival of the SACK, flight size
            //      was greater than or equal to cwnd), increase cwnd by MTU, and
            //      reset partial_bytes_acked to (partial_bytes_acked - cwnd).
            if self.partial_bytes_acked >= self.cwnd && !self.pending_queue.is_empty() {
                self.partial_bytes_acked -= self.cwnd;
                self.cwnd = self.cwnd.saturating_add(self.mtu);
                trace!(
                    "[{}] updated cwnd={} ssthresh={} acked={} (CA)",
                    self.side, self.cwnd, self.ssthresh, total_bytes_acked
                );
            }
        }
    }

    fn process_fast_retransmission(
        &mut self,
        cum_tsn_ack_point: u32,
        htna: u32,
        highest_reported: u32,
        cum_tsn_ack_point_advanced: bool,
        now: Instant,
    ) -> Result<()> {
        // HTNA algorithm - RFC 4960 Sec 7.2.4
        // Increment missIndicator of each chunks that the SACK reported missing
        // when either of the following is met:
        // a)  Not in fast-recovery
        //     miss indications are incremented only for missing TSNs prior to the
        //     highest TSN newly acknowledged in the SACK.
        // b)  In fast-recovery AND the Cumulative TSN Ack Point advanced
        //     the miss indications are incremented for all TSNs reported missing
        //     in the SACK.
        if !self.in_fast_recovery || cum_tsn_ack_point_advanced {
            let max_tsn = if !self.in_fast_recovery {
                // a) increment only for missing TSNs prior to the HTNA
                htna
            } else {
                // b) increment for all TSNs reported missing, which are those below the
                //    highest TSN the SACK acknowledges. DATA sent after that is not reported
                //    missing, only not acknowledged yet: counting it, as the whole in-flight
                //    queue was counted here, retransmitted DATA that was not lost and
                //    abandoned partially reliable messages that would have arrived.
                highest_reported
            };

            let mut tsn = cum_tsn_ack_point.wrapping_add(1);
            while sna32lt(tsn, max_tsn) {
                if let Some(c) = self.inflight_queue.get_mut(tsn) {
                    if c.is_outstanding() && c.miss_indicator < 3 {
                        c.miss_indicator += 1;
                        if c.miss_indicator == 3 && !self.in_fast_recovery {
                            // 2)  If not in Fast Recovery, adjust the ssthresh and cwnd of the
                            //     destination address(es) to which the missing DATA chunks were
                            //     last sent, according to the formula described in Section 7.2.3.
                            self.in_fast_recovery = true;
                            self.fast_recover_exit_point = htna;
                            self.ssthresh = std::cmp::max(self.cwnd / 2, 4 * self.mtu);
                            self.cwnd = self.ssthresh;
                            self.partial_bytes_acked = 0;
                            self.will_retransmit_fast = true;

                            trace!(
                                "[{}] updated cwnd={} ssthresh={} inflight={} (FR)",
                                self.side,
                                self.cwnd,
                                self.ssthresh,
                                self.inflight_queue.get_num_bytes()
                            );
                        }
                    }
                } else {
                    return Err(Error::ErrTsnRequestNotExist);
                }

                tsn = tsn.wrapping_add(1);
            }
        } else if self.use_forward_tsn {
            // In Fast Recovery with no Cumulative TSN Ack advance, the HTNA
            // rule above counts no new miss indications, so a later loss of
            // a partially reliable message waited for T3-rtx (and its cwnd
            // collapse) before it was abandoned: under steady loss an
            // unreliable channel then delivered a fraction of its messages.
            // A missing chunk below the HTNA whose retransmission budget is
            // already spent (RFC 3758 3.5 A3, RFC 7496 3.1) is never sent
            // again, so counting it changes no congestion state: it reaches
            // the fast retransmit path, which abandons it and sends FORWARD
            // TSN (RFC 3758 3.5 C1-C3) without waiting for the timer.
            let mut tsn = cum_tsn_ack_point.wrapping_add(1);
            while sna32lt(tsn, htna) {
                let exhausted = self.inflight_queue.get(tsn).is_some_and(|c| {
                    c.is_outstanding()
                        && c.miss_indicator < 3
                        && self.retransmission_policy_exhausted(c, now, true)
                });
                if exhausted && let Some(c) = self.inflight_queue.get_mut(tsn) {
                    c.miss_indicator += 1;
                    if c.miss_indicator == 3 {
                        self.will_retransmit_fast = true;
                    }
                }
                tsn = tsn.wrapping_add(1);
            }
        }

        if self.in_fast_recovery && cum_tsn_ack_point_advanced {
            self.will_retransmit_fast = true;
        }

        Ok(())
    }

    /// The caller must hold the lock. This method was only added because the
    /// linter was complaining about the "cognitive complexity" of handle_sack.
    fn postprocess_sack(
        &mut self,
        state: AssociationState,
        mut should_awake_write_loop: bool,
        now: Instant,
    ) {
        if !self.inflight_queue.is_empty() {
            // Start timer. (noop if already started)
            trace!("[{}] T3-rtx timer start (pt3)", self.side);
            self.timers
                .start_if_idle(Timer::T3RTX, now, self.rto_mgr.get_rto());
        } else if !self.pending_queue.is_empty() {
            // Queued DATA still goes out before the shutdown proceeds (RFC 9260 9.2).
        } else if state == AssociationState::ShutdownPending {
            // No more outstanding, send shutdown.
            should_awake_write_loop = true;
            self.send_shutdown();
        } else if state == AssociationState::ShutdownReceived {
            // No more outstanding, send shutdown ack.
            should_awake_write_loop = true;
            self.will_send_shutdown_ack = true;
            self.set_state(AssociationState::ShutdownAckSent);
        }

        if should_awake_write_loop {
            self.awake_write_loop();
        }
    }

    /// Streams named by `p` that still hold a complete message the application
    /// has not collected, so a reset naming them cannot be performed yet.
    ///
    /// Only *readable* data counts: an incomplete fragment set can never be
    /// completed once the peer has reset, so it is discardable and must not
    /// hold the reset open forever.
    fn streams_awaiting_drain(&self, p: &ParamOutgoingResetRequest) -> Vec<StreamId> {
        p.stream_identifiers
            .iter()
            .copied()
            .filter(|id| {
                self.streams
                    .get(id)
                    .is_some_and(|s| s.reassembly_queue.is_readable())
            })
            .collect()
    }

    fn reset_streams_if_any(
        &mut self,
        p: &ParamOutgoingResetRequest,
        respond: bool,
        reply: &mut Vec<Packet>,
    ) -> Result<()> {
        let mut result = ReconfigResult::SuccessPerformed;
        let mut sis_to_reset = vec![];

        if sna32lte(p.sender_last_tsn, self.peer_last_tsn) {
            debug!(
                "[{}] resetStream(): senderLastTSN={} <= peer_last_tsn={}",
                self.side, p.sender_last_tsn, self.peer_last_tsn
            );

            let draining = self.streams_awaiting_drain(p);
            let mut seen = FxHashSet::default();

            for id in &p.stream_identifiers {
                if draining.contains(id) || !seen.insert(*id) {
                    continue;
                }
                if let Some(stream) = self.streams.get(id) {
                    // RFC 8831 section 6.7: the receiver of a reset resets its own outgoing
                    // stream too, unless it already has (the peer's request is then the
                    // second half of a close this side started). Echoing it again would
                    // send a reset after the stream id is free, and reset the next channel
                    // that takes the id.
                    let outgoing_open = (stream.state as u8) & 0x1 != 0;
                    if respond && outgoing_open {
                        sis_to_reset.push(*id);
                    }
                    self.unregister_stream(*id, AssociationError::Reset);
                } else if respond
                    && (self.my_max_num_inbound_streams == 0
                        || *id < self.my_max_num_inbound_streams)
                {
                    // A stream this side never sent or received on (a pre-negotiated data
                    // channel left idle) has no state here, but the application still
                    // holds it: report the reset, and reset the outgoing direction too.
                    // An id past the negotiated stream count names no such channel.
                    sis_to_reset.push(*id);
                    self.events.push_back(Event::AssociationLost {
                        reason: AssociationError::Reset,
                        id: *id,
                    });
                }
            }

            if draining.is_empty() {
                self.reconfig_requests
                    .remove(&p.reconfig_request_sequence_number);
                if !self
                    .completed_reconfig_requests
                    .contains(&p.reconfig_request_sequence_number)
                {
                    if self.completed_reconfig_requests.len() >= MAX_COMPLETED_RECONFIG_REQUESTS {
                        self.completed_reconfig_requests.pop_front();
                    }
                    self.completed_reconfig_requests
                        .push_back(p.reconfig_request_sequence_number);
                }
            } else {
                debug!(
                    "[{}] resetStream(): deferring reset of {:?}, application has not drained",
                    self.side, draining
                );
                result = ReconfigResult::InProgress;
                // Keep only the streams still waiting, so a retry performs each reset once.
                self.reconfig_requests.insert(
                    p.reconfig_request_sequence_number,
                    ParamOutgoingResetRequest {
                        stream_identifiers: draining,
                        ..p.clone()
                    },
                );
            }
        } else {
            debug!(
                "[{}] resetStream(): senderLastTSN={} > peer_last_tsn={}",
                self.side, p.sender_last_tsn, self.peer_last_tsn
            );
            result = ReconfigResult::InProgress;
        }

        // Answer incoming reset requests with the same reset request, but with
        // reconfig_response_sequence_number.
        if !sis_to_reset.is_empty() && self.reconfigs.len() >= MAX_OUTSTANDING_RECONFIGS {
            debug!(
                "[{}] resetStream(): not echoing reset of {:?}, {} requests unanswered",
                self.side,
                sis_to_reset,
                self.reconfigs.len()
            );
        } else if !sis_to_reset.is_empty() {
            let rsn = self.generate_next_rsn();
            let tsn = self.my_next_tsn.wrapping_sub(1);

            let c = ChunkReconfig {
                param_a: Some(Box::new(ParamOutgoingResetRequest {
                    reconfig_request_sequence_number: rsn,
                    reconfig_response_sequence_number: p.reconfig_request_sequence_number,
                    sender_last_tsn: tsn,
                    stream_identifiers: sis_to_reset,
                })),
                ..Default::default()
            };

            self.reconfigs.insert(rsn, c.clone()); // store in the map for retransmission

            let p = self.create_packet(vec![Box::new(c)]);
            reply.push(p);
        }

        let packet = self.create_reconfig_response(p.reconfig_request_sequence_number, result);

        debug!("[{}] RESET RESPONSE: {}", self.side, packet);

        reply.push(packet);

        Ok(())
    }

    /// Performs the stored reset requests whose sender's last TSN the cumulative TSN reached
    /// since it stood at `prev_peer_last_tsn`.
    fn reset_streams_reached_since(
        &mut self,
        prev_peer_last_tsn: u32,
        reply: &mut Vec<Packet>,
    ) -> Result<()> {
        if self.peer_last_tsn == prev_peer_last_tsn || self.reconfig_requests.is_empty() {
            return Ok(());
        }
        let peer_last_tsn = self.peer_last_tsn;
        let reached: Vec<ParamOutgoingResetRequest> = self
            .reconfig_requests
            .values()
            .filter(|p| {
                sna32gt(p.sender_last_tsn, prev_peer_last_tsn)
                    && sna32lte(p.sender_last_tsn, peer_last_tsn)
            })
            .cloned()
            .collect();
        for rst_req in reached {
            self.reset_streams_if_any(&rst_req, false, reply)?;
        }
        Ok(())
    }

    fn create_reconfig_response(&self, rsn: u32, result: ReconfigResult) -> Packet {
        self.create_packet(vec![Box::new(ChunkReconfig {
            param_a: Some(Box::new(ParamReconfigResponse {
                reconfig_response_sequence_number: rsn,
                result,
            })),
            param_b: None,
        })])
    }

    /// create_packet wraps chunks in a packet.
    /// The caller should hold the read lock.
    pub(crate) fn create_packet(&self, chunks: Vec<Box<dyn Chunk>>) -> Packet {
        Packet {
            common_header: CommonHeader {
                verification_tag: self.peer_verification_tag,
                source_port: self.source_port,
                destination_port: self.destination_port,
            },
            chunks,
        }
    }

    /// Marshal a single control chunk into one SCTP packet, bypassing the
    /// `Vec<Box<dyn Chunk>>` + `Packet` allocations of `create_packet(..).marshal()`.
    /// Feeds the borrowed chunk straight to the shared framing path
    /// ([`Packet::write_framed`]). Used on the hot SACK / FORWARD-TSN send path
    /// (a SACK is emitted roughly every 1-2 inbound DATA chunks). The caller holds
    /// the lock.
    fn marshal_control_chunk(&self, chunk: &dyn Chunk) -> Result<Bytes> {
        let common_header = CommonHeader {
            verification_tag: self.peer_verification_tag,
            source_port: self.source_port,
            destination_port: self.destination_port,
        };
        // common header + chunk header + value + up to 3 bytes of trailing padding.
        let mut buf = BytesMut::with_capacity(
            COMMON_HEADER_SIZE as usize + CHUNK_HEADER_SIZE + chunk.value_length() + 3,
        );
        Packet::write_framed(&common_header, std::iter::once(chunk), &mut buf)?;
        Ok(buf.freeze())
    }

    /// create_stream creates a stream. The caller should hold the lock and check no stream exists for this id.
    fn create_stream(
        &mut self,
        stream_identifier: StreamId,
        accept: bool,
        default_payload_type: PayloadProtocolIdentifier,
    ) -> Option<Stream<'_>> {
        let mut s = StreamState::new(
            self.side,
            stream_identifier,
            self.max_payload_size,
            default_payload_type,
        );

        s.generation = self.next_stream_generation;
        self.next_stream_generation = self.next_stream_generation.wrapping_add(1);

        if accept {
            self.stream_queue.push_back(stream_identifier);
            self.events.push_back(Event::Stream(StreamEvent::Opened {
                id: stream_identifier,
            }));
        }

        let replaced_bytes = self
            .streams
            .insert(stream_identifier, s)
            .map_or(0, |old| old.get_num_bytes_in_reassembly_queue());
        self.reindex_stream(stream_identifier, replaced_bytes);

        Some(Stream {
            stream_identifier,
            association: self,
        })
    }

    /// get_or_create_stream gets or creates a stream. The caller should hold the lock.
    fn get_or_create_stream(&mut self, stream_identifier: StreamId) -> Option<Stream<'_>> {
        if self.streams.contains_key(&stream_identifier) {
            Some(Stream {
                stream_identifier,
                association: self,
            })
        } else {
            self.create_stream(
                stream_identifier,
                true,
                PayloadProtocolIdentifier::default(),
            )
        }
    }

    /// Whether any stream currently holds a complete message the application could read.
    ///
    /// Distinguishes a receiver that is merely slow — it has data to take, and back-pressure
    /// should make it take it — from one wedged behind an incomplete chunk set, which cannot
    /// drain anything however attentive it is. Only the second justifies accepting a chunk
    /// into a full receive buffer.
    fn has_readable_data(&self) -> bool {
        !self.readable_streams.is_empty()
    }

    fn bytes_in_reassembly_queues(&self) -> usize {
        self.reassembly_bytes
    }

    /// Brings the running totals up to date after stream `id`'s reassembly queue changed
    /// from holding `bytes_before` bytes. A stream no longer in `streams` counts as empty.
    ///
    /// Every change to a reassembly queue goes through here, so the receive window and
    /// "is anything readable" cost the same however many streams the peer opened.
    pub(crate) fn reindex_stream(&mut self, id: StreamId, bytes_before: usize) {
        let (bytes_after, readable, holds_data) = match self.streams.get(&id) {
            Some(s) => (
                s.get_num_bytes_in_reassembly_queue(),
                s.reassembly_queue.is_readable(),
                !s.reassembly_queue.is_empty(),
            ),
            None => (0, false, false),
        };
        self.reassembly_bytes = self
            .reassembly_bytes
            .saturating_sub(bytes_before)
            .saturating_add(bytes_after);
        if readable {
            self.readable_streams.insert(id);
        } else {
            self.readable_streams.remove(&id);
        }
        if holds_data {
            self.streams_with_data.insert(id);
        } else {
            self.streams_with_data.remove(&id);
        }
    }

    pub(crate) fn get_my_receiver_window_credit(&self) -> u32 {
        let bytes_queued = u32::try_from(self.bytes_in_reassembly_queues()).unwrap_or(u32::MAX);
        self.max_receive_buffer_size.saturating_sub(bytes_queued)
    }

    /// gather_outbound gathers outgoing packets. The returned bool value set to
    /// false means the association should be closed down after the final send.
    fn gather_outbound(&mut self, now: Instant) -> (Vec<Bytes>, bool) {
        let mut raw_packets = vec![];

        if !self.control_queue.is_empty() {
            for p in self.control_queue.drain(..) {
                if let Ok(raw) = p.marshal() {
                    raw_packets.push(raw);
                } else {
                    warn!("[{}] failed to serialize a control packet", self.side);
                    continue;
                }
            }
        }

        let state = self.state();
        match state {
            AssociationState::Established => {
                raw_packets = self.gather_data_packets_to_retransmit(raw_packets, now);
                if self.state() == AssociationState::Closed {
                    return (vec![], false);
                }
                raw_packets = self.gather_outbound_data_and_reconfig_packets(raw_packets, now);
                if self.state() == AssociationState::Closed {
                    return (vec![], false);
                }
                raw_packets = self.gather_outbound_fast_retransmission_packets(raw_packets, now);
                if self.state() == AssociationState::Closed {
                    return (vec![], false);
                }
                raw_packets = self.gather_outbound_sack_packets(raw_packets);
                raw_packets = self.gather_outbound_forward_tsn_packets(raw_packets);
                (raw_packets, true)
            }
            AssociationState::ShutdownPending
            | AssociationState::ShutdownSent
            | AssociationState::ShutdownReceived => {
                raw_packets = self.gather_data_packets_to_retransmit(raw_packets, now);
                if self.state() == AssociationState::Closed {
                    return (vec![], false);
                }
                // RFC 9260 9.2: no new data is accepted, but what is already queued is still
                // sent, by the endpoint shutting down and by the one that received SHUTDOWN.
                // (In SHUTDOWN-SENT nothing is queued: SHUTDOWN waited for the queue.)
                if state != AssociationState::ShutdownSent {
                    raw_packets = self.gather_outbound_data_and_reconfig_packets(raw_packets, now);
                    if self.state() == AssociationState::Closed {
                        return (vec![], false);
                    }
                }
                raw_packets = self.gather_outbound_fast_retransmission_packets(raw_packets, now);
                if self.state() == AssociationState::Closed {
                    return (vec![], false);
                }
                raw_packets = self.gather_outbound_sack_packets(raw_packets);
                raw_packets = self.gather_outbound_forward_tsn_packets(raw_packets);
                // Everything handed over is sent and acknowledged (a queue can also empty by
                // abandonment, with no SACK to notice it): the shutdown proceeds.
                if self.inflight_queue.is_empty() && self.pending_queue.is_empty() {
                    if state == AssociationState::ShutdownPending {
                        self.send_shutdown();
                    } else if state == AssociationState::ShutdownReceived {
                        self.will_send_shutdown_ack = true;
                        self.set_state(AssociationState::ShutdownAckSent);
                    }
                }
                self.gather_outbound_shutdown_packets(raw_packets, now)
            }
            AssociationState::ShutdownAckSent => {
                self.gather_outbound_shutdown_packets(raw_packets, now)
            }
            _ => (raw_packets, true),
        }
    }

    fn gather_data_packets_to_retransmit(
        &mut self,
        mut raw_packets: Vec<Bytes>,
        now: Instant,
    ) -> Vec<Bytes> {
        // Nothing is ever flagged for T3-rtx in the steady state, so skip the
        // full in-flight scan unless the T3-rtx timer has actually marked chunks.
        if self.t3_retransmit_pending
            && let Err(err) = self.get_data_packets_to_retransmit(now, &mut raw_packets)
        {
            self.fail_message_queue(err);
            raw_packets.clear();
        }
        raw_packets
    }

    fn gather_outbound_data_and_reconfig_packets(
        &mut self,
        mut raw_packets: Vec<Bytes>,
        now: Instant,
    ) -> Vec<Bytes> {
        // Pop unsent data chunks from the pending queue to send as much as
        // cwnd and rwnd allow.
        let (chunks, sis_to_reset) = self.pop_pending_data_chunks_to_send(now);
        if self.state() == AssociationState::Closed {
            return vec![];
        }
        if !chunks.is_empty() {
            // Start timer. (noop if already started)
            trace!("[{}] T3-rtx timer start (pt1)", self.side);
            self.timers
                .start_if_idle(Timer::T3RTX, now, self.rto_mgr.get_rto());

            self.bundle_data_chunks_into_packets(chunks, &mut raw_packets);
        }

        if !sis_to_reset.is_empty() || self.will_retransmit_reconfig {
            if self.will_retransmit_reconfig {
                self.will_retransmit_reconfig = false;
                debug!(
                    "[{}] retransmit {} RECONFIG chunk(s)",
                    self.side,
                    self.reconfigs.len()
                );
                for c in self.reconfigs.values() {
                    let p = self.create_packet(vec![Box::new(c.clone())]);
                    if let Ok(raw) = p.marshal() {
                        raw_packets.push(raw);
                    } else {
                        warn!(
                            "[{}] failed to serialize a RECONFIG packet to be retransmitted",
                            self.side,
                        );
                    }
                }
            }

            if !sis_to_reset.is_empty() {
                let rsn = self.generate_next_rsn();
                let tsn = self.my_next_tsn.wrapping_sub(1);
                debug!(
                    "[{}] sending RECONFIG: rsn={} tsn={} streams={:?}",
                    self.side,
                    rsn,
                    self.my_next_tsn.wrapping_sub(1),
                    sis_to_reset
                );

                let c = ChunkReconfig {
                    param_a: Some(Box::new(ParamOutgoingResetRequest {
                        reconfig_request_sequence_number: rsn,
                        sender_last_tsn: tsn,
                        stream_identifiers: sis_to_reset,
                        ..Default::default()
                    })),
                    ..Default::default()
                };
                self.reconfigs.insert(rsn, c.clone()); // store in the map for retransmission

                let p = self.create_packet(vec![Box::new(c)]);
                if let Ok(raw) = p.marshal() {
                    raw_packets.push(raw);
                } else {
                    warn!(
                        "[{}] failed to serialize a RECONFIG packet to be transmitted",
                        self.side
                    );
                }
            }

            if !self.reconfigs.is_empty() {
                self.timers
                    .start(Timer::Reconfig, now, self.rto_mgr.get_rto());
            }
        }

        raw_packets
    }

    fn gather_outbound_fast_retransmission_packets(
        &mut self,
        mut raw_packets: Vec<Bytes>,
        now: Instant,
    ) -> Vec<Bytes> {
        if self.will_retransmit_fast {
            self.will_retransmit_fast = false;

            let mut to_fast_retrans: Vec<ChunkPayloadData> = vec![];
            let mut fast_retrans_size = COMMON_HEADER_SIZE;

            let mut i = 0;
            loop {
                let tsn = self.cumulative_tsn_ack_point.wrapping_add(i + 1);
                if let Some(c) = self.inflight_queue.get(tsn) {
                    if !c.is_fast_retransmit_candidate() {
                        i += 1;
                        continue;
                    }

                    // Only the retry being considered needs a policy check.
                    // Retire an exhausted candidate's whole message first.
                    match self.abandon_retransmit_candidate(tsn, now) {
                        Ok(true) => {
                            to_fast_retrans.retain(|chunk| {
                                self.inflight_queue
                                    .get(chunk.tsn)
                                    .is_some_and(|c| !c.abandoned())
                            });
                            fast_retrans_size = COMMON_HEADER_SIZE
                                + to_fast_retrans
                                    .iter()
                                    .map(|c| {
                                        (DATA_CHUNK_HEADER_SIZE + c.user_data.len() as u32)
                                            .next_multiple_of(4)
                                    })
                                    .sum::<u32>();
                            i += 1;
                            continue;
                        }
                        Ok(false) => {}
                        Err(err) => {
                            self.fail_message_queue(err);
                            return vec![];
                        }
                    }
                    let Some(c) = self.inflight_queue.get(tsn) else {
                        break;
                    };

                    // RFC 4960 Sec 7.2.4 Fast Retransmit on Gap Reports
                    //  3)  Determine how many of the earliest (i.e., lowest TSN) DATA chunks
                    //      marked for retransmission will fit into a single packet, subject
                    //      to constraint of the path MTU of the destination transport
                    //      address to which the packet is being sent.  Call this value K.
                    //      Retransmit those K DATA chunks in a single packet.  When a Fast
                    //      Retransmit is being performed, the sender SHOULD ignore the value
                    //      of cwnd and SHOULD NOT delay retransmission for this single
                    //		packet.

                    // Padded wire size, the same accounting
                    // bundle_data_chunks_into_packets uses for bundle
                    // decisions.
                    let data_chunk_size =
                        (DATA_CHUNK_HEADER_SIZE + c.user_data.len() as u32).next_multiple_of(4);
                    if self.mtu < fast_retrans_size + data_chunk_size {
                        break;
                    }

                    fast_retrans_size += data_chunk_size;
                } else {
                    break; // end of pending data
                }

                if let Some(c) = self.inflight_queue.get(tsn) {
                    to_fast_retrans.push(c.clone());
                }
                i += 1;
            }

            for chunk in &mut to_fast_retrans {
                if let Some(c) = self.inflight_queue.get_mut(chunk.tsn) {
                    c.nsent += 1;
                    chunk.nsent = c.nsent;
                    self.stats.inc_fast_retrans();
                    trace!(
                        "[{}] fast-retransmit: tsn={} sent={} htna={}",
                        self.side, c.tsn, c.nsent, self.fast_recover_exit_point
                    );
                }
            }
            self.bundle_data_chunks_into_packets(to_fast_retrans, &mut raw_packets);
        }

        raw_packets
    }

    fn gather_outbound_sack_packets(&mut self, mut raw_packets: Vec<Bytes>) -> Vec<Bytes> {
        if self.ack_state == AckState::Immediate {
            self.ack_state = AckState::Idle;
            let sack = self.create_selective_ack_chunk();
            debug!("[{}] sending SACK: {}", self.side, sack);
            if let Ok(raw) = self.marshal_control_chunk(&sack) {
                raw_packets.push(raw);
            } else {
                warn!("[{}] failed to serialize a SACK packet", self.side);
            }
        }

        raw_packets
    }

    fn gather_outbound_forward_tsn_packets(&mut self, mut raw_packets: Vec<Bytes>) -> Vec<Bytes> {
        /*log::debug!(
            "[{}] gatherOutboundForwardTSNPackets {}",
            self.name,
            self.will_send_forward_tsn
        );*/
        if self.will_send_forward_tsn {
            self.will_send_forward_tsn = false;
            if sna32gt(
                self.advanced_peer_tsn_ack_point,
                self.cumulative_tsn_ack_point,
            ) {
                let fwd_tsn = self.create_forward_tsn();
                if let Ok(raw) = self.marshal_control_chunk(&fwd_tsn) {
                    raw_packets.push(raw);
                } else {
                    warn!("[{}] failed to serialize a Forward TSN packet", self.side);
                }
            }
        }

        raw_packets
    }

    fn gather_outbound_shutdown_packets(
        &mut self,
        mut raw_packets: Vec<Bytes>,
        now: Instant,
    ) -> (Vec<Bytes>, bool) {
        let mut ok = true;

        if self.will_send_shutdown {
            self.will_send_shutdown = false;

            // RFC 9260 9.2: the SHUTDOWN carries the TSN of the last DATA chunk received in
            // sequence from the peer, which is what a SACK would acknowledge, not this side's
            // own acknowledgement point.
            let shutdown = ChunkShutdown {
                cumulative_tsn_ack: self.peer_last_tsn,
            };

            if let Ok(raw) = self.create_packet(vec![Box::new(shutdown)]).marshal() {
                self.timers
                    .start(Timer::T2Shutdown, now, self.rto_mgr.get_rto());
                self.start_shutdown_guard(now);
                raw_packets.push(raw);
            } else {
                warn!("[{}] failed to serialize a Shutdown packet", self.side);
            }
        } else if self.will_send_shutdown_ack {
            self.will_send_shutdown_ack = false;

            let shutdown_ack = ChunkShutdownAck {};

            if let Ok(raw) = self.create_packet(vec![Box::new(shutdown_ack)]).marshal() {
                self.timers
                    .start(Timer::T2Shutdown, now, self.rto_mgr.get_rto());
                raw_packets.push(raw);
            } else {
                warn!("[{}] failed to serialize a ShutdownAck packet", self.side);
            }
        } else if self.will_send_shutdown_complete {
            self.will_send_shutdown_complete = false;

            let shutdown_complete = ChunkShutdownComplete::default();

            if let Ok(raw) = self
                .create_packet(vec![Box::new(shutdown_complete)])
                .marshal()
            {
                raw_packets.push(raw);
                ok = false;
            } else {
                warn!(
                    "[{}] failed to serialize a ShutdownComplete packet",
                    self.side
                );
            }
        }

        (raw_packets, ok)
    }

    /// get_data_packets_to_retransmit is called when T3-rtx is timed out and retransmit outstanding data chunks
    /// that are not acked or abandoned yet.
    fn get_data_packets_to_retransmit(
        &mut self,
        now: Instant,
        raw_packets: &mut Vec<Bytes>,
    ) -> Result<()> {
        let awnd = std::cmp::min(self.cwnd, self.rwnd);
        let mut chunks: Vec<ChunkPayloadData> = vec![];
        let mut bytes_to_send = 0;
        let mut done = false;
        let mut i = 0;
        // Assume we will re-send every flagged chunk; flip back on if we stop
        // early (a marked chunk that doesn't fit awnd, or a zero-window probe)
        // so the next gather_outbound still scans.
        let mut chunks_remaining = false;
        while !done {
            let tsn = self.cumulative_tsn_ack_point.wrapping_add(i + 1);
            if let Some(c) = self.inflight_queue.get(tsn) {
                if !c.retransmit {
                    i += 1;
                    continue;
                }

                // A T3-marked candidate can expire while waiting for the send
                // window. Recheck it now (RFC 3758 TR4), without a window scan.
                if self.abandon_retransmit_candidate(tsn, now)? {
                    chunks.retain(|chunk| {
                        self.inflight_queue
                            .get(chunk.tsn)
                            .is_some_and(|c| !c.abandoned())
                    });
                    bytes_to_send = chunks.iter().map(|c| c.user_data.len()).sum();
                    i += 1;
                    continue;
                }
                let Some(c) = self.inflight_queue.get(tsn) else {
                    break;
                };

                if i == 0 && self.rwnd < c.user_data.len() as u32 {
                    // Send it as a zero window probe
                    done = true;
                    chunks_remaining = true;
                } else if bytes_to_send + c.user_data.len() > awnd as usize {
                    chunks_remaining = true;
                    break;
                }

                bytes_to_send += c.user_data.len();
            } else {
                break; // end of pending data
            }

            if let Some(c) = self.inflight_queue.get(tsn) {
                chunks.push(c.clone());
            }
            i += 1;
        }

        // Cleared once the whole in-flight window has been rescanned with nothing
        // left flagged; kept set while awnd/zero-window left chunks behind.
        self.t3_retransmit_pending = chunks_remaining;

        // A later candidate can abandon an earlier fragment already selected
        // into this batch. Commit attempts only after whole-message retirement.
        for chunk in &mut chunks {
            if let Some(c) = self.inflight_queue.get_mut(chunk.tsn) {
                c.retransmit = false;
                c.nsent += 1;
                chunk.nsent = c.nsent;
                trace!(
                    "[{}] retransmitting tsn={} ssn={} sent={}",
                    self.side, c.tsn, c.stream_sequence_number, c.nsent
                );
            }
        }
        self.bundle_data_chunks_into_packets(chunks, raw_packets);
        Ok(())
    }

    fn release_stream_buffers(&mut self, bytes_acked_per_stream: &FxHashMap<u16, i64>) {
        for (si, n_bytes_acked) in bytes_acked_per_stream {
            if *n_bytes_acked > 0 {
                // Report the exact bytes released for this stream (acknowledged OR
                // abandoned — both funnel through bytes_acked_per_stream) so upper
                // layers can decrement their own send-buffer accounting. Unlike the
                // edge-triggered BufferedAmountLow advisory below, this fires on
                // every release with the byte delta.
                self.events
                    .push_back(Event::Stream(StreamEvent::BufferedAmountReleased {
                        id: *si,
                        n_bytes: *n_bytes_acked as usize,
                    }));
            }
            if let Some(s) = self.streams.get_mut(si)
                && s.on_buffer_released(*n_bytes_acked)
            {
                trace!("StreamEvent::BufferedAmountLow");
                self.events
                    .push_back(Event::Stream(StreamEvent::BufferedAmountLow { id: *si }))
            }
        }
    }

    /// RFC 3758 section 3.5 C2-C4. Retain the stream map until the peer catches up.
    fn advance_peer_ack_point(&mut self) {
        let mut tsn = self.advanced_peer_tsn_ack_point.wrapping_add(1);
        while let Some(c) = self.inflight_queue.get(tsn) {
            if !c.abandoned() {
                break;
            }
            let (unordered, si, ssn) = (c.unordered, c.stream_identifier, c.stream_sequence_number);
            self.advanced_peer_tsn_ack_point = tsn;
            self.note_abandoned_for_forward_tsn(unordered, si, ssn);
            tsn = tsn.wrapping_add(1);
        }
        if sna32gt(
            self.advanced_peer_tsn_ack_point,
            self.cumulative_tsn_ack_point,
        ) {
            self.will_send_forward_tsn = true;
        } else {
            self.fwd_tsn_stream_map.clear();
        }
    }

    fn timed_data_expired(&self, c: &ChunkPayloadData, now: Instant) -> bool {
        self.use_forward_tsn
            && c.reliability
                .deadline()
                .is_some_and(|deadline| now >= deadline)
    }

    /// Application bytes of `stream_identifier` that have left the send queue (see
    /// [`Stream::bytes_dequeued`]); 0 for a stream this association does not hold.
    pub fn stream_bytes_dequeued(&self, stream_identifier: StreamId) -> u64 {
        self.streams
            .get(&stream_identifier)
            .map_or(0, |s| s.bytes_dequeued)
    }

    /// Credits a chunk leaving the send queue to its stream's `bytes_dequeued`.
    fn note_dequeued(&mut self, c: &ChunkPayloadData) {
        if !matches!(
            c.payload_type,
            PayloadProtocolIdentifier::String | PayloadProtocolIdentifier::Binary
        ) || !self.is_current_stream_data(c)
        {
            return;
        }
        if let Some(s) = self.streams.get_mut(&c.stream_identifier) {
            s.bytes_dequeued += c.user_data.len() as u64;
        }
    }

    fn is_current_stream_data(&self, c: &ChunkPayloadData) -> bool {
        self.streams
            .get(&c.stream_identifier)
            .is_some_and(|s| s.generation == c.stream_generation)
    }

    /// A positive deadline can expire at any time. Timed(0) and Rexmit limits
    /// instead apply when this particular DATA is considered for retransmission.
    fn retransmission_policy_exhausted(
        &self,
        c: &ChunkPayloadData,
        now: Instant,
        is_candidate: bool,
    ) -> bool {
        if !self.use_forward_tsn {
            return false;
        }
        match c.reliability {
            MessageReliability::Reliable => false,
            MessageReliability::Timed { deadline } => {
                now >= deadline && (Some(deadline) != c.created_at || is_candidate)
            }
            // RFC 7496 3.1: the limit excludes the first transmission and counts
            // both fast and timer-based retries. nsent includes that first send.
            MessageReliability::Rexmit { max_retransmits } => {
                is_candidate && c.nsent > max_retransmits
            }
        }
    }

    fn abandon_retransmit_candidate(&mut self, tsn: u32, now: Instant) -> Result<bool> {
        let c = self
            .inflight_queue
            .get(tsn)
            .ok_or_else(|| Error::OtherSctpErr("missing retransmission candidate".into()))?;
        if !self.retransmission_policy_exhausted(c, now, true) {
            return Ok(false);
        }
        let message = MessageToAbandon {
            id: c.message_id.ok_or_else(|| {
                Error::OtherSctpErr("outbound DATA has no message identity".into())
            })?,
            sent_tsn: Some(tsn),
        };
        if self.abandon_message(message)? {
            self.on_messages_abandoned(now);
        }
        Ok(true)
    }

    /// Select identities without changing ACK, retry or buffer state. Only a
    /// fragment selected for recovery can exhaust that message's retry budget.
    fn unretransmittable_messages(
        &self,
        now: Instant,
        is_candidate: impl Fn(&ChunkPayloadData) -> bool,
    ) -> Result<Vec<MessageToAbandon>> {
        let mut messages = vec![];
        let mut selected = FxHashSet::default();
        for &tsn in &self.inflight_queue.sorted {
            let c = self
                .inflight_queue
                .get(tsn)
                .ok_or_else(|| Error::OtherSctpErr("missing inflight message fragment".into()))?;
            if c.is_outstanding()
                && self.retransmission_policy_exhausted(c, now, is_candidate(c))
                && let Some(id) = c.message_id
                && selected.insert(id)
            {
                messages.push(MessageToAbandon {
                    id,
                    sent_tsn: Some(tsn),
                });
            }
        }
        Ok(messages)
    }

    /// RFC 3758 A2/A3: abandon all fragments by identity, including Gap-ACKed
    /// siblings and an unsent tail. Each payload is released at most once.
    /// FORWARD TSN and timers are updated after the complete operation.
    fn abandon_message(&mut self, message: MessageToAbandon) -> Result<bool> {
        let whole_tsn = message.sent_tsn.filter(|&tsn| {
            self.inflight_queue.get(tsn).is_some_and(|c| {
                c.message_id == Some(message.id) && c.beginning_fragment && c.ending_fragment
            })
        });
        let mut inflight = whole_tsn.map_or_else(
            || self.inflight_queue.message_tsns(message.id),
            |tsn| vec![tsn],
        );
        let mut released_per_stream = FxHashMap::default();
        let mut changed = false;
        let tail = self.pending_queue.drain_message(message.id)?;
        let assign_tsns = !inflight.is_empty()
            || tail
                .first()
                .is_some_and(|c| !c.beginning_fragment || !c.unordered);
        for mut c in tail {
            self.note_dequeued(&c);
            if assign_tsns {
                c.tsn = self.generate_next_tsn();
                inflight.push(c.tsn);
                self.inflight_queue.push_no_check(c);
            } else {
                if self.is_current_stream_data(&c) {
                    *released_per_stream.entry(c.stream_identifier).or_default() +=
                        c.user_data.len() as i64;
                }
                changed = true;
            }
        }
        for tsn in inflight {
            if let Some(c) = self.inflight_queue.get_mut(tsn) {
                changed |= !c.abandoned();
                c.mark_abandoned();
                let (si, generation) = (c.stream_identifier, c.stream_generation);
                let released = self.inflight_queue.release_payload(tsn) as i64;
                if released > 0
                    && self
                        .streams
                        .get(&si)
                        .is_some_and(|s| s.generation == generation)
                {
                    *released_per_stream.entry(si).or_default() += released;
                }
            }
        }
        self.release_stream_buffers(&released_per_stream);
        Ok(changed)
    }

    fn fail_message_queue(&mut self, err: Error) {
        error!("[{}] inconsistent message queue: {err}", self.side);
        if let Err(err) = self.close(AssociationError::TransportError) {
            error!("[{}] failed to close association: {err}", self.side);
        }
        self.control_queue.clear();
        self.emit_drained();
    }

    fn on_messages_abandoned(&mut self, now: Instant) {
        self.advance_peer_ack_point();
        // RFC 3758 C5: recovery must continue even with no DATA left to retry.
        if sna32gt(
            self.advanced_peer_tsn_ack_point,
            self.cumulative_tsn_ack_point,
        ) {
            self.timers
                .start_if_idle(Timer::T3RTX, now, self.rto_mgr.get_rto());
        }
    }

    fn abandon_unretransmittable_messages(
        &mut self,
        now: Instant,
        is_candidate: impl Fn(&ChunkPayloadData) -> bool,
    ) -> Result<()> {
        let mut changed = false;
        for message in self.unretransmittable_messages(now, is_candidate)? {
            changed |= self.abandon_message(message)?;
        }
        if changed {
            self.on_messages_abandoned(now);
        }
        Ok(())
    }

    /// An unsent unordered message can be dropped without assigning TSNs.
    /// A selected fragment tail instead needs the whole-message abandonment path.
    /// Timed(0) permits first transmissions until an actual retry is considered.
    fn pending_message_expired(&self, c: &ChunkPayloadData, now: Instant) -> bool {
        (!c.beginning_fragment || c.unordered)
            && c.reliability.deadline() != c.created_at
            && self.timed_data_expired(c, now)
    }

    fn pending_message_to_abandon(&self) -> Result<MessageToAbandon> {
        Ok(MessageToAbandon {
            id: self
                .pending_queue
                .peek()
                .and_then(|c| c.message_id)
                .ok_or_else(|| {
                    Error::OtherSctpErr("outbound DATA has no message identity".into())
                })?,
            sent_tsn: None,
        })
    }

    /// pop_pending_data_chunks_to_send pops chunks from the pending queues as many as
    /// the cwnd and rwnd allows to send.
    fn pop_pending_data_chunks_to_send(
        &mut self,
        now: Instant,
    ) -> (Vec<ChunkPayloadData>, Vec<u16>) {
        let mut chunks = vec![];
        let mut sis_to_reset = vec![]; // stream identifiers to reset
        if !self.pending_queue.is_empty() {
            // RFC 4960 sec 6.1.  Transmission of DATA Chunks
            //   A) At any given time, the data sender MUST NOT transmit new data to
            //      any destination transport address if its peer's rwnd indicates
            //      that the peer has no buffer space (i.e., rwnd is 0; see Section
            //      6.2.1).  However, regardless of the value of rwnd (including if it
            //      is 0), the data sender can always have one DATA chunk in flight to
            //      the receiver if allowed by cwnd (see rule B, below).

            loop {
                let Some(c) = self.pending_queue.peek() else {
                    if let Some(reset) = self.pending_queue.pop_ready_reset() {
                        sis_to_reset.push(reset.stream_identifier);
                        continue;
                    }
                    break;
                };
                let (beginning_fragment, unordered, data_len) =
                    (c.beginning_fragment, c.unordered, c.user_data.len());

                if data_len == 0 {
                    self.fail_message_queue(Error::OtherSctpErr(
                        "outbound DATA has no user data".into(),
                    ));
                    return (vec![], vec![]);
                }

                // RFC 3758 timed reliability: a message whose lifetime has run
                // out must be abandoned even if it was never transmitted. Doing
                // this here, ahead of the window checks and before a TSN is
                // allocated, means there is no gap for the peer to reconcile and
                // no ForwardTSN to send.
                if self.pending_message_expired(c, now) {
                    match self
                        .pending_message_to_abandon()
                        .and_then(|message| self.abandon_message(message))
                    {
                        Ok(true) => self.on_messages_abandoned(now),
                        Ok(false) => {}
                        Err(err) => {
                            self.fail_message_queue(err);
                            return (vec![], vec![]);
                        }
                    }
                    continue;
                }

                if self.inflight_queue.get_num_bytes() + data_len > self.cwnd as usize {
                    break; // would exceeds cwnd
                }

                if self.my_next_tsn.wrapping_sub(self.cumulative_tsn_ack_point)
                    > MAX_OUTSTANDING_TSNS
                {
                    break; // the receiver could no longer order what is outstanding
                }

                if data_len > self.rwnd as usize {
                    break; // no more rwnd
                }

                if let Some(chunk) = self.move_pending_data_chunk_to_inflight_queue(
                    beginning_fragment,
                    unordered,
                    now,
                ) {
                    self.rwnd -= data_len as u32;
                    chunks.push(chunk);
                } else {
                    self.fail_message_queue(Error::OtherSctpErr(
                        "failed to pop pending DATA".into(),
                    ));
                    return (vec![], vec![]);
                }
            }

            // the data sender can always have one DATA chunk in flight to the receiver
            if chunks.is_empty() && self.inflight_queue.is_empty() {
                // Send zero window probe
                if let Some(c) = self.pending_queue.peek() {
                    let (beginning_fragment, unordered) = (c.beginning_fragment, c.unordered);

                    if let Some(chunk) = self.move_pending_data_chunk_to_inflight_queue(
                        beginning_fragment,
                        unordered,
                        now,
                    ) {
                        chunks.push(chunk);
                    } else {
                        self.fail_message_queue(Error::OtherSctpErr(
                            "failed to pop pending DATA".into(),
                        ));
                        return (vec![], vec![]);
                    }
                }
            }
        }

        (chunks, sis_to_reset)
    }

    /// bundle_data_chunks_into_packets packs DATA chunks into packets. It tries to bundle
    /// DATA chunks into a packet so long as the resulting packet size does not exceed
    /// the path MTU.
    fn bundle_data_chunks_into_packets(
        &self,
        chunks: Vec<ChunkPayloadData>,
        raw_packets: &mut Vec<Bytes>,
    ) {
        // RFC 4960 sec 6.1.  Transmission of DATA Chunks
        //   Multiple DATA chunks committed for transmission MAY be bundled in a
        //   single packet.  Furthermore, DATA chunks being retransmitted MAY be
        //   bundled with new DATA chunks, as long as the resulting packet size
        //   does not exceed the path MTU.
        //
        // Marshal each bundle straight into `raw_packets` from the borrowed
        // chunks: no intermediate `Vec<Packet>`, no `Box<dyn Chunk>` per chunk.
        // The chunks are already retained in the in-flight queue, so this send
        // copy is throwaway.
        if chunks.is_empty() {
            return;
        }
        let common_header = CommonHeader {
            verification_tag: self.peer_verification_tag,
            source_port: self.source_port,
            destination_port: self.destination_port,
        };

        // First pass: split the chunks into MTU-bounded datagrams and total up
        // their marshalled (4-byte-padded) length. The whole burst is then
        // written into ONE buffer and `split_to` hands out each datagram as a
        // zero-copy `Bytes` view sharing that single allocation — one malloc per
        // burst instead of one per packet on the hot send path. The bundle
        // boundaries are computed once here and reused below, so the MTU-split
        // rule lives in exactly one place.
        let hdr = COMMON_HEADER_SIZE as usize;
        let mut bundles: Vec<(usize, usize)> = Vec::new();
        let mut total_len = 0usize;
        let mut bundle_start = 0;
        let mut bundle_len = hdr;
        for (i, chunk) in chunks.iter().enumerate() {
            // Marshalled chunk size: header + payload, padded up to the SCTP
            // 4-byte boundary. Bundle decisions must use this wire size —
            // deciding on raw payload sizes admitted bundles that marshalled
            // past the MTU (e.g. payloads of 1147 + 16 pass a payload-only
            // check at an MTU of 1191 but serialize to a 1208-byte packet).
            let wire =
                (DATA_CHUNK_HEADER_SIZE as usize + chunk.user_data.len()).next_multiple_of(4);
            // Close the current bundle before a chunk whose padded wire size
            // would push the datagram past the MTU.
            if bundle_len + wire > self.mtu as usize && i > bundle_start {
                bundles.push((bundle_start, i));
                total_len += bundle_len;
                bundle_start = i;
                bundle_len = hdr;
            }
            bundle_len += wire;
        }
        bundles.push((bundle_start, chunks.len()));
        total_len += bundle_len;

        // Second pass: marshal each datagram into the shared buffer.
        let mut buf = BytesMut::with_capacity(total_len);
        for (start, end) in bundles {
            match Packet::write_framed(
                &common_header,
                chunks[start..end].iter().map(|c| c as &dyn Chunk),
                &mut buf,
            ) {
                Ok(_) => {
                    let plen = buf.len();
                    raw_packets.push(buf.split_to(plen).freeze());
                }
                Err(_) => {
                    warn!("[{}] failed to serialize a DATA packet", self.side);
                    buf.clear();
                }
            }
        }
    }

    /// generate_next_tsn returns the my_next_tsn and increases it. The caller should hold the lock.
    fn generate_next_tsn(&mut self) -> u32 {
        let tsn = self.my_next_tsn;
        self.my_next_tsn = self.my_next_tsn.wrapping_add(1);
        tsn
    }

    /// generate_next_rsn returns the my_next_rsn and increases it. The caller should hold the lock.
    fn generate_next_rsn(&mut self) -> u32 {
        let rsn = self.my_next_rsn;
        self.my_next_rsn = self.my_next_rsn.wrapping_add(1);
        rsn
    }

    /// Builds the SACK, keeping the gap blocks nearest the cumulative TSN and then the repeats
    /// that fit, so the packet carrying it stays within the MTU.
    fn create_selective_ack_chunk(&mut self) -> ChunkSelectiveAck {
        let fixed = COMMON_HEADER_SIZE as usize + CHUNK_HEADER_SIZE + SELECTIVE_ACK_HEADER_SIZE;
        let room = (self.mtu as usize).saturating_sub(fixed) / 4;
        let mut gap_ack_blocks = self.payload_queue.get_gap_ack_blocks(self.peer_last_tsn);
        gap_ack_blocks.truncate(room);
        let mut duplicate_tsn = self.payload_queue.pop_duplicates();
        duplicate_tsn.truncate(room - gap_ack_blocks.len());
        ChunkSelectiveAck {
            cumulative_tsn_ack: self.peer_last_tsn,
            advertised_receiver_window_credit: self.get_my_receiver_window_credit(),
            gap_ack_blocks,
            duplicate_tsn,
        }
    }

    /// Record an abandoned chunk into the forward-TSN stream map (RFC 3758 C4),
    /// called from the two C2 loops as `advanced_peer_tsn_ack_point` advances
    /// over each newly-abandoned in-flight chunk. Only *ordered* streams are
    /// tracked: the receiver ignores the per-stream SSN list for unordered
    /// chunks (it advances purely by `new_cumulative_tsn`). Keeps the greatest
    /// SSN seen per stream, which is the value RFC 3758 C4 requires to report.
    ///
    /// A stream's entry may briefly outlive the chunk that set it (until the
    /// window closes and the map is cleared), so a stale SSN can be re-reported;
    /// that is safe because the receiver only advances a stream forward and the
    /// SSN always corresponds to a really-abandoned chunk. The `u16` SSN compare
    /// (`sna16lt`) is sound because the window span is bounded by rwnd — a
    /// stream cannot lap the full 65536-sequence space before the window closes.
    fn note_abandoned_for_forward_tsn(&mut self, unordered: bool, si: u16, ssn: u16) {
        if unordered {
            return;
        }
        self.fwd_tsn_stream_map
            .entry(si)
            .and_modify(|cur| {
                if sna16lt(*cur, ssn) {
                    *cur = ssn;
                }
            })
            .or_insert(ssn);
    }

    /// Test-only observer for the incremental forward-TSN stream map, so the
    /// endpoint tests can assert it is cleared once the forward-TSN window
    /// closes (the C1/C3 clear paths, which the unit tests can't reach).
    #[cfg(test)]
    pub(crate) fn fwd_tsn_stream_map_is_empty(&self) -> bool {
        self.fwd_tsn_stream_map.is_empty()
    }

    /// create_forward_tsn generates ForwardTSN chunk.
    /// This method will be be called if use_forward_tsn is set to false.
    fn create_forward_tsn(&self) -> ChunkForwardTsn {
        // RFC 3758 Sec 3.5 C4: report, once per ordered stream, the greatest
        // stream-sequence-number among abandoned chunks in the forward-TSN
        // window. This is maintained incrementally in `fwd_tsn_stream_map` (see
        // its declaration and the two C2 loops that feed it), so we no longer
        // rescan `(cumulative_tsn_ack_point, advanced_peer_tsn_ack_point]` with
        // a per-TSN hashmap probe on every FORWARD-TSN — that scan was O(rwnd)
        // (~1000 probes/call for a 1 MB window) and dominated the send profile.
        let mut fwd_tsn = ChunkForwardTsn {
            new_cumulative_tsn: self.advanced_peer_tsn_ack_point,
            streams: Vec::with_capacity(self.fwd_tsn_stream_map.len()),
        };
        for (si, ssn) in &self.fwd_tsn_stream_map {
            fwd_tsn.streams.push(ChunkForwardTsnStream {
                identifier: *si,
                sequence: *ssn,
            });
        }
        // `trace!` evaluates its arguments lazily, so the stream list is only
        // formatted when trace logging is enabled -- no per-FORWARD-TSN string
        // allocation on the hot send path (this fires often for PR-SCTP data
        // channels, which is exactly where it was showing up in profiles).
        trace!(
            "[{}] building fwd_tsn: newCumulativeTSN={} cumTSN={} streams={:?}",
            self.side, fwd_tsn.new_cumulative_tsn, self.cumulative_tsn_ack_point, fwd_tsn.streams
        );

        fwd_tsn
    }

    /// Move the chunk peeked with self.pending_queue.peek() to the inflight_queue.
    fn move_pending_data_chunk_to_inflight_queue(
        &mut self,
        beginning_fragment: bool,
        unordered: bool,
        now: Instant,
    ) -> Option<ChunkPayloadData> {
        if let Some(mut c) = self.pending_queue.pop(beginning_fragment, unordered) {
            // Assign TSN
            c.tsn = self.generate_next_tsn();

            // RTT baseline only; maxPacketLifeTime measures from `created_at`.
            c.since = Some(now);
            c.nsent = 1; // being sent for the first time

            trace!(
                "[{}] sending ppi={} tsn={} ssn={} sent={} len={} ({},{})",
                self.side,
                c.ppid(),
                c.tsn,
                c.stream_sequence_number,
                c.nsent,
                c.user_data.len(),
                c.beginning_fragment,
                c.ending_fragment
            );

            self.inflight_queue.push_no_check(c.clone());
            self.note_dequeued(&c);

            Some(c)
        } else {
            error!("[{}] failed to pop from pending queue", self.side);
            None
        }
    }

    /// Queues an outgoing stream-reset marker (RFC 6525). Its retransmission
    /// timer starts when the RE-CONFIG request is emitted, not when queued.
    pub(crate) fn send_reset_request(
        &mut self,
        _now: Instant,
        stream_identifier: StreamId,
    ) -> Result<()> {
        let state = self.state();
        if state != AssociationState::Established {
            return Err(Error::ErrResetPacketInStateNotExist);
        }

        self.pending_queue
            .push_reset(ResetMarker { stream_identifier });
        self.awake_write_loop();

        Ok(())
    }

    /// Allocate an identity before consuming input or changing stream state.
    pub(crate) fn allocate_message_id(&mut self) -> Result<MessageId> {
        let state = self.state();
        if state != AssociationState::Established {
            return Err(Error::ErrPayloadDataStateNotExist);
        }

        let id = MessageId::new(self.next_message_id)
            .ok_or_else(|| Error::OtherSctpErr("message identity exhausted".into()))?;
        // MessageId::new has already checked that this increment cannot overflow.
        self.next_message_id += 1;
        Ok(id)
    }

    /// send_payload_data sends the data chunks with their allocated identity.
    ///
    /// The queueing instant is already recorded on each chunk by `Stream::packetize`, so this
    /// does not need one of its own.
    pub(crate) fn send_payload_data(&mut self, id: MessageId, mut chunks: Vec<ChunkPayloadData>) {
        for c in &mut chunks {
            c.message_id = Some(id);
        }
        self.pending_queue.push_message(chunks);

        self.awake_write_loop();
    }

    /// buffered_amount returns total amount (in bytes) of currently buffered user data.
    /// This is used only by testing.
    pub(crate) fn buffered_amount(&self) -> usize {
        self.pending_queue.get_num_bytes() + self.inflight_queue.get_num_bytes()
    }

    fn awake_write_loop(&self) {
        // No Op on Purpose
    }

    fn close_all_timers(&mut self) {
        // Close all retransmission & ack timers
        for timer in Timer::VALUES {
            self.timers.stop(timer);
        }
    }

    fn on_ack_timeout(&mut self) {
        trace!(
            "[{}] ack timed out (ack_state: {})",
            self.side, self.ack_state
        );
        self.stats.inc_ack_timeouts();
        self.ack_state = AckState::Immediate;
        self.awake_write_loop();
    }

    fn on_retransmission_timeout(&mut self, timer_id: Timer, n_rtos: usize, now: Instant) {
        match timer_id {
            Timer::T1Init => {
                if let Err(err) = self.send_init() {
                    debug!(
                        "[{}] failed to retransmit init (n_rtos={}): {:?}",
                        self.side, n_rtos, err
                    );
                }
            }

            Timer::T1Cookie => {
                if let Err(err) = self.send_cookie_echo() {
                    debug!(
                        "[{}] failed to retransmit cookie-echo (n_rtos={}): {:?}",
                        self.side, n_rtos, err
                    );
                }
            }

            Timer::T2Shutdown => {
                debug!(
                    "[{}] retransmission of shutdown timeout (n_rtos={})",
                    self.side, n_rtos
                );
                let state = self.state();
                match state {
                    AssociationState::ShutdownSent => {
                        self.will_send_shutdown = true;
                        self.awake_write_loop();
                    }
                    AssociationState::ShutdownAckSent => {
                        self.will_send_shutdown_ack = true;
                        self.awake_write_loop();
                    }
                    _ => {}
                }
            }

            Timer::T3RTX => {
                self.stats.inc_t3timeouts();
                self.rto_mgr.backoff();
                // Refresh before C2 or mark_all_to_retrasmit reads abandoned().
                if let Err(err) =
                    self.abandon_unretransmittable_messages(now, ChunkPayloadData::is_outstanding)
                {
                    self.fail_message_queue(err);
                    return;
                }

                // RFC 4960 sec 6.3.3
                //  E1)  For the destination address for which the timer expires, adjust
                //       its ssthresh with rules defined in Section 7.2.3 and set the
                //       cwnd <- MTU.
                // RFC 4960 sec 7.2.3
                //   When the T3-rtx timer expires on an address, SCTP should perform slow
                //   start by:
                //      ssthresh = max(cwnd/2, 4*MTU)
                //      cwnd = 1*MTU

                self.ssthresh = std::cmp::max(self.cwnd / 2, 4 * self.mtu);
                self.cwnd = self.mtu;
                trace!(
                    "[{}] updated cwnd={} ssthresh={} inflight={} (RTO)",
                    self.side,
                    self.cwnd,
                    self.ssthresh,
                    self.inflight_queue.get_num_bytes()
                );

                // RFC 3758 sec 3.5
                //  A5) Any time the T3-rtx timer expires, on any destination, the sender
                //  SHOULD try to advance the "Advanced.Peer.Ack.Point" by following
                //  the procedures outlined in C2 - C5.
                if self.use_forward_tsn {
                    self.advance_peer_ack_point();
                }

                debug!(
                    "[{}] T3-rtx timed out: n_rtos={} cwnd={} ssthresh={}",
                    self.side, n_rtos, self.cwnd, self.ssthresh
                );

                self.inflight_queue.mark_all_to_retrasmit();
                self.t3_retransmit_pending = true;
                self.awake_write_loop();
            }

            Timer::Reconfig => {
                self.will_retransmit_reconfig = true;
                self.awake_write_loop();
            }

            _ => {}
        }
    }

    fn on_retransmission_failure(&mut self, id: Timer) {
        match id {
            // A handshake that runs out of retransmissions is over (RFC 9260 5.1 A, C). It
            // used to only report HandshakeFailed and stay in COOKIE-WAIT / COOKIE-ECHOED, so
            // whatever watched the association saw it connecting for good.
            Timer::T1Init => {
                error!("[{}] retransmission failure: T1-init", self.side);
                let reason =
                    AssociationError::HandshakeFailed(Error::ErrHandshakeInitAck.to_string());
                self.error = Some(reason.clone());
                if let Err(err) = self.close(reason) {
                    error!("[{}] failed to close association: {err}", self.side);
                }
            }

            Timer::T1Cookie => {
                error!("[{}] retransmission failure: T1-cookie", self.side);
                let reason =
                    AssociationError::HandshakeFailed(Error::ErrHandshakeCookieEcho.to_string());
                self.error = Some(reason.clone());
                if let Err(err) = self.close(reason) {
                    error!("[{}] failed to close association: {err}", self.side);
                }
            }

            Timer::T2Shutdown => {
                // RFC 9260 9.2: past the limit the peer is unreachable and the association is
                // over. This only logged, and the timer was not started again: the association
                // stayed in SHUTDOWN-SENT (or SHUTDOWN-ACK-SENT) for good.
                error!("[{}] retransmission failure: T2-shutdown", self.side);
                if let Err(err) = self.close(AssociationError::TimedOut) {
                    error!("[{}] failed to close association: {err}", self.side);
                }
            }

            Timer::T5ShutdownGuard => {
                // RFC 9260 9.2: the shutdown did not finish in time. The association is
                // aborted and the upper layer told.
                error!("[{}] T5-shutdown-guard expired", self.side);
                if let Err(err) = self.abort_with(vec![], AssociationError::TimedOut) {
                    error!("[{}] failed to close association: {err}", self.side);
                }
            }

            Timer::HalfOpen => {
                debug!("[{}] no COOKIE ECHO followed the INIT", self.side);
                let reason =
                    AssociationError::HandshakeFailed(Error::ErrHandshakeCookieEcho.to_string());
                self.error = Some(reason.clone());
                if let Err(err) = self.close(reason) {
                    error!("[{}] failed to close association: {err}", self.side);
                }
            }

            Timer::T3RTX => {
                // Reached only with a finite `TimerConfig::max_t3_rtx_retrans`; the default
                // is unlimited because a WebRTC peer learns of a lost path from ICE. RFC 9260
                // 8.1: once the limit is exceeded the peer is unreachable and the association
                // ends. Returning without re-arming the timer, as this did, left it running
                // with no retransmission and no FORWARD TSN for ever.
                error!("[{}] retransmission failure: T3-rtx (DATA)", self.side);
                if let Err(err) = self.close(AssociationError::TimedOut) {
                    error!("[{}] failed to close association: {err}", self.side);
                }
            }

            _ => {}
        }
    }

    /// Whether no timers are running
    #[cfg(test)]
    pub(crate) fn is_idle(&self) -> bool {
        Timer::VALUES
            .iter()
            //.filter(|&&t| t != Timer::KeepAlive && t != Timer::PushNewCid)
            .filter_map(|&t| Some((t, self.timers.get(t)?)))
            .min_by_key(|&(_, time)| time)
            //.map_or(true, |(timer, _)| timer == Timer::Idle)
            .is_none()
    }
}
