use crate::peer_connection::configuration::setting_engine::SctpMaxMessageSize;
use crate::peer_connection::sdp::SctpNegotiation;
use crate::peer_connection::transport::RTCTransportId;
use crate::peer_connection::transport::sctp::capabilities::SCTPTransportCapabilities;
use crate::peer_connection::transport::sctp::state::RTCSctpTransportState;
use sctp::{Association, AssociationHandle};
use shared::error::{Error, Result};
use shared::{TransportContext, TransportProtocol};
use std::collections::HashMap;
use std::sync::Arc;

pub(crate) mod capabilities;
pub(crate) mod state;

/// The stream-count ceiling used when no negotiated value is available yet.
///
/// Not the spec's `maxChannels` — that is the negotiated minimum, reported by
/// [`SctpTransport::max_channels`]. This is only the "no constraint known" fallback.
pub(crate) const SCTP_MAX_CHANNELS: u16 = u16::MAX;

/// Associations one DTLS transport carries. WebRTC runs exactly one SCTP association over
/// each DTLS transport (RFC 8261 section 4, RFC 8831 section 6.1), so an INIT for a second
/// one is refused.
pub(crate) const MAX_SCTP_ASSOCIATIONS_PER_DTLS_TRANSPORT: u32 = 1;

/// RFC 8831 section 6.6: the largest message sent on an association that does not interleave
/// user messages, "16 KB".
pub(crate) const MAX_MESSAGE_SIZE_WITHOUT_INTERLEAVING: u32 = 16 * 1024;

/// The size of this side's send buffer per data channel: the `canSendSize` that W3C
/// webrtc-pc 6.1.1.2 ("the size of the local send buffer") makes the floor of
/// `[[MaxBufferSize]]`. The spec leaves the size to the implementation; 16 MiB is Chromium's,
/// so an application that keeps `bufferedAmount` under it by back-pressure
/// (`bufferedAmountLowThreshold`) behaves the same against both.
pub(crate) const DEFAULT_SEND_BUFFER_SIZE: u32 = 16 * 1024 * 1024;

/// The SCTP port this side advertises (`a=sctp-port`) for its first association: the value
/// every browser uses.
pub(crate) const DEFAULT_SCTP_PORT: u16 = 5000;

/// What lies under the SCTP association, as far as the size of its packets goes: the selected
/// ICE candidate pair and the DTLS record protection.
///
/// RFC 8831 section 5: "The initial Path MTU at the IP layer SHOULD NOT exceed 1200 bytes for
/// IPv4 and 1280 bytes for IPv6." The association does not probe the path (no RFC 4821
/// discovery), so that initial value is the one it keeps, and an SCTP packet is what is left
/// of it under the headers below.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct SctpPath {
    /// The selected pair's addresses are IPv6.
    pub(crate) ipv6: bool,
    /// The selected pair runs over TCP (RFC 6544), with the framing of RFC 4571.
    pub(crate) tcp: bool,
    /// The local candidate is a relayed one: the data travels in TURN ChannelData.
    pub(crate) relayed: bool,
    /// What a protected DTLS record adds to its payload: its header, and what the negotiated
    /// version and cipher suite add (explicit nonce, tag, padding; for DTLS 1.3 the inner
    /// content type; a connection id).
    pub(crate) dtls_record_overhead: usize,
}

impl SctpPath {
    /// RFC 8831 section 5: the IP-layer path MTU an association starts from.
    const IPV4_PATH_MTU: u32 = 1200;
    const IPV6_PATH_MTU: u32 = 1280;
    /// The record overhead assumed while no cipher suite is negotiated: a DTLS 1.2 record
    /// (RFC 6347 section 4.1: a 13-byte header) of an AEAD suite with an 8-byte explicit
    /// nonce and a 16-byte tag (AES-GCM), the largest of the AEAD records; a DTLS 1.3 record
    /// is smaller.
    pub(crate) const DEFAULT_DTLS_RECORD_OVERHEAD: usize = 13 + 24;

    /// The largest SCTP packet (common header and chunks) that fits the path: the IP-layer
    /// MTU less the IP header, the UDP header (or the TCP header and the two-byte frame
    /// length of RFC 4571), the four-byte TURN ChannelData header on a relayed candidate, and
    /// the DTLS record overhead.
    pub(crate) fn packet_budget(&self) -> u32 {
        let (path_mtu, ip_header) = if self.ipv6 {
            (Self::IPV6_PATH_MTU, 40)
        } else {
            (Self::IPV4_PATH_MTU, 20)
        };
        let transport_header = if self.tcp { 20 + 2 } else { 8 };
        let turn_header = if self.relayed { 4 } else { 0 };
        path_mtu
            .saturating_sub(ip_header + transport_header + turn_header)
            .saturating_sub(u32::try_from(self.dtls_record_overhead).unwrap_or(u32::MAX))
            .max(::sctp::MIN_DATA_PACKET_MTU)
    }
}

/// What the application asked the next offer to do with the SCTP association (RFC 8841
/// section 10.5).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum SctpRenegotiation {
    /// Close it and establish a new one: the offer carries a new `a=sctp-port`.
    Replace,
    /// Close it and establish none: the offer carries `a=sctp-port:0`.
    Close,
    /// Close it together with the DTLS association under it: the data section of the offer
    /// (or of the answer to the peer's next offer) is rejected, its m= line port zero.
    Reject,
}

/// What a completed offer/answer exchange did to the SCTP transport.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum SctpNegotiationOutcome {
    /// Nothing to do: no association was negotiated and none exists, or the one that exists
    /// is the one negotiated.
    Unchanged,
    /// The first association of this transport was negotiated.
    Started,
    /// The association was closed by signalling and none replaces it.
    Closed,
    /// The association was closed by signalling and a new one replaces it.
    Replaced,
}

/// SCTPTransport provides details about the SCTP transport.
///
/// Not `Default`: `id` and `dtls_transport_id` identify *this* connection's transports, and a
/// default-constructed id would compare equal across connections — the one thing
/// [`RTCTransportId`] must never do. Nothing constructed one this way.
pub(crate) struct SctpTransport {
    pub(crate) id: RTCTransportId,
    pub(crate) dtls_transport_id: RTCTransportId,

    pub(crate) sctp_endpoint: Option<::sctp::Endpoint>,
    pub(crate) sctp_transport_config: Option<::sctp::TransportConfig>,
    pub(crate) sctp_associations: HashMap<AssociationHandle, Association>,

    // SCTPTransportState doesn't have an enum to distinguish between New/Connecting
    // so we need a dedicated field
    pub(crate) is_started: bool,

    /// W3C `[[SctpTransport]]` is not null: an applied offer described an SCTP association
    /// (RFC 8841 section 10.2), and no answer has closed it since (sections 10.3, 10.4). The
    /// transport is exposed ("connecting" until its association is up) from then on.
    pub(crate) described: bool,
    /// W3C `[[LastStableStateSctpTransport]]`: `described` in the last stable state, what a
    /// rollback brings back.
    pub(crate) last_stable_described: bool,

    // The *configured* ceiling from SettingEngine — an input to the negotiation below, not the
    // value W3C `maxMessageSize` reports. See `negotiated_max_message_size`.
    pub(crate) max_message_size: SctpMaxMessageSize,

    // The negotiated [[MaxMessageSize]] slot: the result of reconciling the configured ceiling
    // above with the peer's `max-message-size` SDP attribute, computed once in `start()`.
    // `None` before the association has been negotiated.
    pub(crate) negotiated_max_message_size: Option<u32>,
    /// W3C `[[MaxBufferSize]]`: the larger of the peer's `max-message-size` and this side's
    /// send buffer (`DEFAULT_SEND_BUFFER_SIZE`), once negotiated (webrtc-pc 6.1.1.2).
    pub(crate) negotiated_max_buffer_size: Option<u32>,
    /// A fixed send buffer limit that replaces `[[MaxBufferSize]]`, when the application set
    /// one (`SettingEngineBuilder::with_data_channel_max_buffer_size`).
    pub(crate) max_buffer_size_override: Option<u32>,

    // Optional override for the SCTP receive-buffer size (a_rwnd flow-control window),
    // in bytes. None uses the sctp crate default (INITIAL_RECV_BUF_SIZE, 1 MiB).
    pub(crate) max_receive_buffer_size: Option<u32>,

    // Optional override for the outbound SCTP DATA-packet budget, applied to the endpoint's
    // `EndpointConfig` in `start()`. None uses the sctp crate default (INITIAL_MTU, 1191).
    pub(crate) mtu: Option<u32>,

    // Streams share the bytes sent by weight (RFC 8260 section 3.6), each data channel's
    // priority being its stream's weight (RFC 8831 section 6.4). On unless the application
    // turned it off, which gives first-come-first-served.
    pub(crate) weighted_fair_queueing: bool,

    // User message interleaving (RFC 8260) is announced to the peer and used when the peer
    // announces it too (RFC 8831 sections 6.1 and 6.6: it "SHOULD be used"). On by default.
    pub(crate) message_interleaving: bool,

    // The zero checksum of RFC 9653 is announced as acceptable and used when the peer accepts
    // it too: the association runs over DTLS, which is the alternate error detection method
    // the RFC defines (section 6). On by default.
    pub(crate) zero_checksum: bool,

    // The stream count asked for and accepted in each direction
    // (`SettingEngineBuilder::with_sctp_max_streams`); `None` keeps the association's 65535.
    pub(crate) max_streams: Option<u16>,

    // RTO.Initial / RTO.Min / RTO.Max (`SettingEngineBuilder::with_sctp_rto`); `None` keeps
    // RFC 9260's.
    pub(crate) rto: Option<::sctp::RtoConfig>,

    // Association.Max.Retrans (`SettingEngineBuilder::with_sctp_max_retransmissions`); `None`
    // keeps RFC 9260's 10.
    pub(crate) max_retransmissions: Option<usize>,

    // RFC 8831 section 6.6: "As long as message interleaving is not supported, the sender
    // SHOULD limit the maximum message size to 16 KB to avoid monopolization." On by default:
    // on an association that did not negotiate interleaving, a message over
    // `MAX_MESSAGE_SIZE_WITHOUT_INTERLEAVING` is refused.
    pub(crate) limit_message_size_without_interleaving: bool,

    // The crypto provider State Cookies are authenticated with (RFC 9260 section 5.1.3). With
    // one the accepting side of the handshake keeps no state before the COOKIE ECHO. The
    // endpoint's random values (verification tags, initial TSNs, HEARTBEAT nonces and jitter)
    // come from its `random()` too, as ICE's and DTLS's do. `None` only in unit tests that
    // build a transport by hand.
    pub(crate) cookie_provider: Option<Arc<dyn crypto::RTCCryptoProvider>>,

    /// The largest SCTP packet the path below carries, as worked out from the selected
    /// candidate pair and the DTLS cipher suite ([`SctpPath::packet_budget`]). `None` until a
    /// pair is selected. `mtu` above, when the application set it, takes its place.
    pub(crate) path_mtu: Option<u32>,

    // The largest message accepted from the peer: the `max-message-size` this side advertised
    // (RFC 8841 6.1), which is not the negotiated send limit above. 0 before `start()`.
    pub(crate) receive_message_limit: usize,

    /// The SCTP port this side advertises in `a=sctp-port` and uses as source port: the one
    /// of the current association, or of the next one before any was negotiated.
    pub(crate) local_port: u16,

    /// The `(local, remote)` SCTP ports the last completed offer/answer exchange negotiated,
    /// which are the ports of the association in use (RFC 8841 section 9.3: each endpoint
    /// uses one port as client and server port). `None` while no association is negotiated.
    pub(crate) negotiated_ports: Option<(u16, u16)>,

    /// What the application staged for the next offer.
    pub(crate) staged: Option<SctpRenegotiation>,

    /// Whether the DTLS transport under this one is connected: the association is initiated
    /// when it becomes so (RFC 8261 section 6.1), or at once when an association is
    /// negotiated over a DTLS transport that already is.
    pub(crate) dtls_connected: bool,

    /// The last exchange closed the association with `a=sctp-port:0` (RFC 8841 section 9.3)
    /// and none has been negotiated since: offers go on saying 0 until the application asks
    /// for an association again.
    pub(crate) port_zero: bool,

    /// The last association ended without signalling and the endpoint has let go of it; see
    /// [`Self::association_lost`], which also covers one that ended and is still held.
    pub(crate) lost: bool,
}

impl SctpTransport {
    pub(crate) fn new(
        max_message_size: SctpMaxMessageSize,
        max_receive_buffer_size: Option<u32>,
        mtu: Option<u32>,
        id: RTCTransportId,
        dtls_transport_id: RTCTransportId,
    ) -> Self {
        Self {
            id,
            dtls_transport_id,
            sctp_endpoint: None,
            sctp_transport_config: None,
            sctp_associations: HashMap::new(),

            is_started: false,
            described: false,
            last_stable_described: false,
            max_message_size,
            negotiated_max_message_size: None,
            negotiated_max_buffer_size: None,
            max_buffer_size_override: None,
            max_receive_buffer_size,
            mtu,
            weighted_fair_queueing: true,
            message_interleaving: true,
            zero_checksum: true,
            max_streams: None,
            rto: None,
            max_retransmissions: None,
            limit_message_size_without_interleaving: true,
            cookie_provider: None,
            path_mtu: None,
            receive_message_limit: 0,
            local_port: DEFAULT_SCTP_PORT,
            negotiated_ports: None,
            staged: None,
            dtls_connected: false,
            port_zero: false,
            lost: false,
        }
    }

    /// Whether the association ended without signalling (an ABORT, a timeout, a SHUTDOWN)
    /// and has not been replaced. RFC 8841 section 9.3: "SCTP associations might be closed
    /// without SDP signaling -- for example, in case of a failure. ... This requires a new SDP
    /// offer/answer exchange. New (different than the ones currently used) SCTP ports MUST be
    /// used by both endpoints", so the next offer or answer carries a new port.
    pub(crate) fn association_lost(&self) -> bool {
        self.is_started
            && (self.lost
                || (!self.sctp_associations.is_empty()
                    && self.sctp_associations.values().all(Self::ended)))
    }

    /// A port for a new association: never 0 (which closes, RFC 8841 section 9.3) and never
    /// the port in use ("a new (different than the ones currently used) SCTP port").
    fn next_port(&self) -> u16 {
        match self.local_port.checked_add(1) {
            Some(port) => port,
            None => DEFAULT_SCTP_PORT,
        }
    }

    /// The `a=sctp-port` of the next offer (RFC 8841 sections 10.2 and 10.5).
    ///
    /// The port in use, unless the association is to be replaced (asked for by the
    /// application, or needed because the last one ended without signalling), which takes a
    /// new port, or closed, which takes 0. The same answer every time until a negotiation
    /// completes, so an offer created twice says the same thing.
    pub(crate) fn offer_port(&self) -> u16 {
        match self.staged {
            Some(SctpRenegotiation::Close) => 0,
            Some(SctpRenegotiation::Replace) => self.next_port(),
            // A rejected section carries no `a=sctp-port`.
            Some(SctpRenegotiation::Reject) => self.local_port,
            None if self.port_zero => 0,
            None if self.association_lost() => self.next_port(),
            None => self.local_port,
        }
    }

    /// The `a=sctp-port` of the answer to an offer whose data section says
    /// `a=sctp-port:<offered>` (RFC 8841 section 10.3).
    ///
    /// "If the offer contained a new (different than the one currently used) SCTP port
    /// value, the answerer MUST also associate a new SCTP port value. If the offer contained a
    /// zero SCTP port value, or if the answerer does not accept the SCTP association, the
    /// answerer MUST also associate a zero SCTP port value".
    pub(crate) fn answer_port(&self, offered: u16) -> u16 {
        if offered == 0 || self.staged == Some(SctpRenegotiation::Close) {
            return 0;
        }
        let offer_has_a_new_port = self
            .negotiated_ports
            .is_some_and(|(_, remote)| remote != offered);
        if offer_has_a_new_port
            || self.association_lost()
            || self.staged == Some(SctpRenegotiation::Replace)
        {
            self.next_port()
        } else {
            self.local_port
        }
    }

    /// Applies what a completed offer/answer exchange negotiated for the data section
    /// (RFC 8841 sections 10.3 and 10.4).
    ///
    /// When this closes or replaces a running transport, the caller has had its associations
    /// aborted first (`SctpHandler::close_for_renegotiation`): this only drops or replaces
    /// the configuration they ran with.
    pub(crate) fn negotiate(
        &mut self,
        negotiated: SctpNegotiation,
    ) -> Result<SctpNegotiationOutcome> {
        let (local_port, remote_port, remote_max_message_size) = match negotiated {
            SctpNegotiation::NoSection => return Ok(SctpNegotiationOutcome::Unchanged),
            SctpNegotiation::Rejected | SctpNegotiation::PortZero => {
                self.staged = None;
                self.port_zero = negotiated == SctpNegotiation::PortZero;
                if !self.is_started {
                    return Ok(SctpNegotiationOutcome::Unchanged);
                }
                self.stop();
                if negotiated == SctpNegotiation::Rejected {
                    // RFC 8841 section 10.5: "If the offerer wants to establish an SCTP
                    // association, and another SCTP association was previously closed, the
                    // offerer MUST associate an SDP 'sctp-port' attribute with a new attribute
                    // value"; only one closed with `a=sctp-port:0` may have its port again.
                    self.local_port = self.next_port();
                }
                return Ok(SctpNegotiationOutcome::Closed);
            }
            SctpNegotiation::Association {
                local_port,
                remote_port,
                remote_max_message_size,
            } => (local_port, remote_port, remote_max_message_size),
        };
        self.staged = None;
        self.port_zero = false;

        let outcome = if !self.is_started {
            SctpNegotiationOutcome::Started
        } else if self.negotiated_ports == Some((local_port, remote_port)) {
            return Ok(SctpNegotiationOutcome::Unchanged);
        } else {
            // RFC 8841 section 9.3: "The existing SCTP association is closed, and the new
            // SCTP association is established, if one or both endpoints signal a new SCTP
            // port."
            self.stop();
            SctpNegotiationOutcome::Replaced
        };
        self.start(
            SCTPTransportCapabilities {
                max_message_size: remote_max_message_size,
            },
            local_port,
            remote_port,
        )?;
        Ok(outcome)
    }

    /// Whether applying `negotiated` ends the association this transport runs.
    pub(crate) fn closes_on(&self, negotiated: SctpNegotiation) -> bool {
        self.is_started
            && match negotiated {
                SctpNegotiation::NoSection => false,
                SctpNegotiation::Rejected | SctpNegotiation::PortZero => true,
                SctpNegotiation::Association {
                    local_port,
                    remote_port,
                    ..
                } => self.negotiated_ports != Some((local_port, remote_port)),
            }
    }

    /// Forgets the association this transport was negotiated for, back to the state before
    /// `start()`. The port this side advertised is remembered, so the next one differs.
    fn stop(&mut self) {
        self.sctp_endpoint = None;
        self.sctp_transport_config = None;
        self.sctp_associations.clear();
        self.is_started = false;
        self.negotiated_max_message_size = None;
        self.negotiated_max_buffer_size = None;
        self.receive_message_limit = 0;
        self.negotiated_ports = None;
        self.lost = false;
    }

    /// Schedules the association `start()` builds by weighted fair queueing (the default),
    /// or first come, first served.
    pub(crate) fn with_weighted_fair_queueing(mut self, enabled: bool) -> Self {
        self.weighted_fair_queueing = enabled;
        self
    }

    /// Whether the association `start()` builds announces user message interleaving
    /// (RFC 8260).
    pub(crate) fn with_message_interleaving(mut self, enabled: bool) -> Self {
        self.message_interleaving = enabled;
        self
    }

    /// Whether the association `start()` builds announces that it accepts a zero checksum
    /// (RFC 9653).
    pub(crate) fn with_zero_checksum(mut self, enabled: bool) -> Self {
        self.zero_checksum = enabled;
        self
    }

    /// The stream count the association `start()` builds asks for and accepts in each
    /// direction; `None` keeps the default.
    pub(crate) fn with_max_streams(mut self, streams: Option<u16>) -> Self {
        self.max_streams = streams;
        self
    }

    /// RTO.Initial, RTO.Min and RTO.Max of the association `start()` builds; `None` keeps
    /// the defaults.
    pub(crate) fn with_rto(mut self, rto: Option<::sctp::RtoConfig>) -> Self {
        self.rto = rto;
        self
    }

    /// Association.Max.Retrans of the association `start()` builds; `None` keeps the default.
    pub(crate) fn with_max_retransmissions(mut self, limit: Option<usize>) -> Self {
        self.max_retransmissions = limit;
        self
    }

    /// Whether a message over 16 KB is refused on an association without message
    /// interleaving (RFC 8831 section 6.6).
    pub(crate) fn with_message_size_limit_without_interleaving(mut self, enabled: bool) -> Self {
        self.limit_message_size_without_interleaving = enabled;
        self
    }

    /// A fixed `[[MaxBufferSize]]` in place of the W3C rule's, or `None` for that rule.
    pub(crate) fn with_max_buffer_size(mut self, limit: Option<u32>) -> Self {
        self.max_buffer_size_override = limit;
        self
    }

    /// Authenticates the State Cookies of the endpoint `start()` builds with an HMAC from
    /// `provider` (RFC 9260 section 5.1.3), and draws the endpoint's random values from
    /// `provider.random()`.
    pub(crate) fn with_cookie_provider(
        mut self,
        provider: Arc<dyn crypto::RTCCryptoProvider>,
    ) -> Self {
        self.cookie_provider = Some(provider);
        self
    }

    /// The largest SCTP packet an association of this transport sends: what the application
    /// configured, else what the path is known to carry, else `None` (the `rtc-sctp` default,
    /// 1191 bytes).
    pub(crate) fn packet_budget(&self) -> Option<u32> {
        self.mtu.or(self.path_mtu)
    }

    pub(crate) fn calc_message_size(remote_max_message_size: u32, can_send_size: u32) -> u32 {
        if remote_max_message_size == 0 && can_send_size == 0 {
            u32::MAX
        } else if remote_max_message_size == 0 {
            can_send_size
        } else if can_send_size == 0 || can_send_size > remote_max_message_size {
            remote_max_message_size
        } else {
            can_send_size
        }
    }

    /// The single association this transport carries, if one has been created.
    ///
    /// `sctp_associations` is a map because the endpoint API is written for the general case, but
    /// a peer connection negotiates exactly one SCTP association. One that has ended is passed
    /// over for a live one, should both be present until the endpoint drains the old one.
    pub(crate) fn association(&self) -> Option<&Association> {
        self.sctp_associations
            .values()
            .find(|association| !Self::ended(association))
            .or_else(|| self.sctp_associations.values().next())
    }

    /// An association that is over: closed after its handshake, or during it (an ABORT, a
    /// handshake that ran out of retransmissions). One still handshaking is in SCTP's initial
    /// `CLOSED` state too (RFC 9260 section 4), which is not an end.
    fn ended(association: &Association) -> bool {
        association.is_ended()
    }

    /// W3C `SctpTransport.state`.
    ///
    /// Derived from the association rather than tracked separately: the previous `state` field was
    /// assigned once at construction and never updated or read, so any getter over it would have
    /// reported `Connecting` for the lifetime of the connection.
    pub(crate) fn state(&self) -> RTCSctpTransportState {
        // An association that ended during its handshake is `closed` (W3C webrtc 6.1.1: the
        // transport is closed when the association is), not `connecting` for good.
        match self.association() {
            // The association ended and the endpoint has let go of it.
            None if self.lost => RTCSctpTransportState::Closed,
            None => RTCSctpTransportState::Connecting,
            Some(association) if Self::ended(association) => RTCSctpTransportState::Closed,
            Some(association) if association.is_handshaking() => RTCSctpTransportState::Connecting,
            Some(_) => RTCSctpTransportState::Connected,
        }
    }

    /// W3C `SctpTransport.maxMessageSize`, in bytes.
    ///
    /// `None` until the association has been negotiated, at which point it is the reconciliation of
    /// this endpoint's configured ceiling with the peer's `max-message-size` SDP attribute
    /// ([RFC 8841 §6]).
    ///
    /// Always finite. The spec types the attribute `unrestricted double` so that an
    /// implementation with no limit can report positive infinity; this one always has a limit,
    /// because the value also sizes a real allocation — see `start()`.
    ///
    /// [RFC 8841 §6]: https://datatracker.ietf.org/doc/html/rfc8841#section-6
    ///
    /// RFC 8831 section 6.6: once the association is established without user message
    /// interleaving, a large message would hold up every other channel until it is sent, and
    /// "the sender SHOULD limit the maximum message size to 16 KB". The value reported, and
    /// enforced, is then at most that, unless the application lifted the limit
    /// (`SettingEngineBuilder::with_sctp_message_size_limit_without_interleaving`).
    pub(crate) fn max_message_size(&self) -> Option<u32> {
        let negotiated = self.negotiated_max_message_size?;
        Some(if self.limits_message_size_without_interleaving() {
            negotiated.min(MAX_MESSAGE_SIZE_WITHOUT_INTERLEAVING)
        } else {
            negotiated
        })
    }

    /// W3C `[[MaxBufferSize]]`: the most a data channel's `bufferedAmount` may reach, `None`
    /// until the association has been negotiated (W3C: "initially null"). A limit the
    /// application set takes its place.
    pub(crate) fn max_buffer_size(&self) -> Option<u32> {
        self.max_buffer_size_override
            .or(self.negotiated_max_buffer_size)
    }

    /// Whether the 16 KB limit of RFC 8831 section 6.6 applies: it is on, and the association
    /// is established without user message interleaving.
    fn limits_message_size_without_interleaving(&self) -> bool {
        self.limit_message_size_without_interleaving
            && self.association().is_some_and(|association| {
                !Self::ended(association)
                    && !association.is_handshaking()
                    && !association.message_interleaving()
            })
    }

    /// Refuses an application message of `size` bytes over [`Self::max_message_size`], with
    /// an error that says which limit it is over: the negotiated one
    /// (`ErrOutboundPacketTooLarge`), or the 16 KB of an association without message
    /// interleaving (`ErrMessageTooLargeWithoutInterleaving`, which names the limit and the
    /// setting that lifts it). Before negotiation nothing is refused here.
    pub(crate) fn check_message_size(&self, size: usize) -> Result<()> {
        let Some(negotiated) = self.negotiated_max_message_size else {
            return Ok(());
        };
        if size > negotiated as usize {
            return Err(Error::ErrOutboundPacketTooLarge);
        }
        if size > MAX_MESSAGE_SIZE_WITHOUT_INTERLEAVING as usize
            && self.limits_message_size_without_interleaving()
        {
            return Err(Error::ErrMessageTooLargeWithoutInterleaving {
                size,
                limit: MAX_MESSAGE_SIZE_WITHOUT_INTERLEAVING,
            });
        }
        Ok(())
    }

    /// W3C `SctpTransport.maxChannels`: the minimum of the negotiated inbound and outbound
    /// stream counts.
    ///
    /// `None` until the association reaches the connected state, matching the spec's "this
    /// attribute's value will be null until the SCTP transport goes into the `connected` state".
    pub(crate) fn max_channels(&self) -> Option<u16> {
        self.association()?.negotiated_max_streams()
    }

    /// Start the SCTPTransport. Since both local and remote parties must mutually
    /// create an SCTPTransport, SCTP SO (Simultaneous Open) is used to establish
    /// a connection over SCTP.
    ///
    /// RFC 8841 section 9.3: "both SCTP endpoints MUST initiate the SCTP association (i.e.,
    /// both SCTP endpoints take the 'active' role)", whatever their DTLS roles, so the
    /// endpoint built here is the same in both: the SCTP handler initiates from it when DTLS
    /// is connected, and it takes the peer's INIT, should that come first.
    pub(crate) fn start(
        &mut self,
        remote_caps: SCTPTransportCapabilities,
        local_port: u16,
        remote_port: u16,
    ) -> Result<()> {
        if self.is_started {
            return Ok(());
        }
        self.is_started = true;
        // A started association is a transport that exists (`described`).
        self.described = true;
        self.local_port = local_port;
        self.negotiated_ports = Some((local_port, remote_port));
        self.lost = false;

        // W3C §6.1.1.2 defines `canSendSize` as what this endpoint can actually send, and allows
        // 0 only when the implementation "can handle messages of any size". This one cannot: the
        // working buffer below is a real allocation, so the ceiling is `MAX_MESSAGE_SIZE`. A
        // configured 0 therefore resolves to that ceiling rather than to "unlimited".
        //
        // Without this, `calc_message_size(0, 0)` yields `u32::MAX` and the two lines below try to
        // allocate a 4 GiB buffer and configure an unbounded message size — an OOM waiting for the
        // first peer that advertises no limit. Reporting `u32::MAX` while enforcing something far
        // smaller would be worse than either: `maxMessageSize` is a promise to the application
        // about what it may pass to `send()`, so the value reported and the value enforced have to
        // be the same one.
        let can_send_size = match self.max_message_size.as_usize() as u32 {
            0 => SctpMaxMessageSize::MAX_MESSAGE_SIZE,
            configured => configured,
        };
        let max_message_size =
            SctpTransport::calc_message_size(remote_caps.max_message_size, can_send_size);

        // This is the spec's [[MaxMessageSize]] slot. It was previously computed here, used to size
        // the buffer and the transport config, and then discarded, which left nothing for
        // `maxMessageSize` to report.
        self.negotiated_max_message_size = Some(max_message_size);
        // W3C 6.1.1.2: [[MaxBufferSize]] is the larger of the remote's max-message-size and
        // canSendSize, "the size of the local send buffer" (the remote's 0, "any size", leaves
        // this side's, which is never 0 here). The send buffer is not the message-size ceiling
        // above: messages are bounded by the working buffer, the queue of them by
        // `DEFAULT_SEND_BUFFER_SIZE`.
        self.negotiated_max_buffer_size = Some(
            remote_caps
                .max_message_size
                .max(can_send_size)
                .max(DEFAULT_SEND_BUFFER_SIZE),
        );

        // RFC 8841 6.1: each side's `max-message-size` limits what the *other* side sends. So
        // what this side accepts is what it advertised (`can_send_size`, which is what
        // `populate_sdp` writes), not the negotiated minimum: that minimum is only the send
        // limit, and receiving by it refused every message larger than the peer's own limit
        // (64 KiB when the peer's SDP omits the attribute) although this side had promised to
        // take it.
        self.receive_message_limit = can_send_size as usize;

        let mut sctp_endpoint_config = ::sctp::EndpointConfig::default();
        if let Some(provider) = &self.cookie_provider {
            sctp_endpoint_config.random_source(provider.clone());
        }
        if let Some(mtu) = self.packet_budget() {
            sctp_endpoint_config.max_payload_size(::sctp::max_payload_size_for_mtu(mtu));
        }
        let scheduler = if self.weighted_fair_queueing {
            ::sctp::StreamScheduler::WeightedFairQueueing
        } else {
            ::sctp::StreamScheduler::FirstComeFirstServed
        };
        let mut sctp_transport_config = ::sctp::TransportConfig::default()
            .with_max_message_size(max_message_size)
            .with_max_receive_message_size(can_send_size)
            .with_sctp_port(local_port)
            .with_remote_sctp_port(remote_port)
            .with_stream_scheduler(scheduler)
            // RFC 8831 sections 6.1 and 6.6: message interleaving "SHOULD be used". It is
            // announced, and used when the peer announces it too; otherwise the association
            // sends DATA chunks, as before.
            .with_message_interleaving(self.message_interleaving)
            // RFC 9653 section 6: SCTP over DTLS is an alternate error detection method, so
            // the CRC32c may be left out. Announced, and used when the peer announces it too.
            .with_zero_checksum(self.zero_checksum);
        if let Some(recv_buf) = self.max_receive_buffer_size {
            sctp_transport_config = sctp_transport_config.with_max_receive_buffer_size(recv_buf);
        }
        if let Some(streams) = self.max_streams {
            sctp_transport_config = sctp_transport_config
                .with_max_num_outbound_streams(streams)
                .with_max_num_inbound_streams(streams);
        }
        if let Some(rto) = self.rto {
            sctp_transport_config = sctp_transport_config.with_rto_config(rto);
        }
        if let Some(limit) = self.max_retransmissions {
            let mut timers = sctp_transport_config.timer_config();
            timers.max_t3_rtx_retrans = limit;
            sctp_transport_config = sctp_transport_config.with_timer_config(timers);
        }

        // One association per DTLS transport: once this side has initiated its own, or has
        // taken the peer's INIT, the endpoint starts no other.
        let mut server_config = ::sctp::ServerConfig::new(sctp_transport_config.clone());
        server_config.concurrent_associations(MAX_SCTP_ASSOCIATIONS_PER_DTLS_TRANSPORT);
        // RFC 9260 sections 5.1 and 5.1.3: the State Cookie carries a MAC, and the endpoint
        // keeps nothing for an INIT it has answered. The association then appears with the
        // COOKIE ECHO, already established.
        if let Some(provider) = &self.cookie_provider {
            server_config.cookie_authentication(provider.clone());
        }
        self.sctp_endpoint = Some(::sctp::Endpoint::new(
            TransportContext::default().local_addr, // placeholder; rewritten per-transmit by the ICE handler
            TransportProtocol::UDP, // placeholder; rewritten per-transmit by the ICE handler
            sctp_endpoint_config.into(),
            Some(server_config.into()),
        ));
        self.sctp_transport_config = Some(sctp_transport_config);

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::peer_connection::transport::{RTCTransportId, TransportKind};

    /// A fixed nonce keeps test ids deterministic while still distinguishing the kinds.
    fn test_transport_id(kind: TransportKind) -> RTCTransportId {
        RTCTransportId::new(0xabcd_ef01_2345_6789, kind)
    }
    use super::*;

    /// An association that has not finished its handshake is `connecting`, although SCTP's
    /// own state machine starts it in `CLOSED`: the accepting side's association was reported
    /// `closed` from the moment it was created.
    #[test]
    fn a_handshaking_association_is_connecting() {
        let mut transport = started_transport(SctpMaxMessageSize::Bounded(65536), 65536);
        transport
            .sctp_associations
            .insert(AssociationHandle(0), Association::default());
        assert_eq!(transport.state(), RTCSctpTransportState::Connecting);
        assert_eq!(
            None,
            transport.max_channels(),
            "a handshaking association negotiated nothing"
        );
    }

    /// An association that ended during its handshake (an ABORT, a handshake that ran out of
    /// retransmissions) is `closed`, not `connecting` for good (B5).
    #[test]
    fn an_association_that_ended_in_its_handshake_is_closed() {
        let mut transport = started_transport(SctpMaxMessageSize::Bounded(65536), 65536);
        let mut association = Association::default();
        association
            .close(sctp::AssociationError::HandshakeFailed(
                "no INIT ACK".to_owned(),
            ))
            .expect("close");
        assert!(association.is_handshaking());
        transport
            .sctp_associations
            .insert(AssociationHandle(0), association);
        assert_eq!(transport.state(), RTCSctpTransportState::Closed);
    }

    fn started_transport(
        configured: SctpMaxMessageSize,
        remote_max_message_size: u32,
    ) -> SctpTransport {
        let mut transport = SctpTransport::new(
            configured,
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport
            .start(
                SCTPTransportCapabilities {
                    max_message_size: remote_max_message_size,
                },
                5000,
                5000,
            )
            .expect("start");
        transport
    }

    // `maxMessageSize` is the *negotiated* value, not the configured ceiling. Configure 64 KiB
    // and have the peer advertise 16 KiB: reporting the configured value would answer 65536.
    #[test]
    fn max_message_size_reports_the_negotiated_value_not_the_configured_one() {
        let transport = started_transport(SctpMaxMessageSize::Bounded(65536), 16384);
        assert_eq!(Some(16384), transport.max_message_size());
    }

    // The reverse direction, so the test cannot pass by simply echoing the remote's number.
    #[test]
    fn max_message_size_takes_the_smaller_of_the_two_limits() {
        let transport = started_transport(SctpMaxMessageSize::Bounded(16384), 65536);
        assert_eq!(Some(16384), transport.max_message_size());
    }

    // Neither side names a limit. This implementation still has one, so `canSendSize` resolves
    // to `MAX_MESSAGE_SIZE` rather than to "unlimited" (W3C §6.1.1.2 allows 0 only for an
    // implementation that can handle any size). Reporting `u32::MAX` here would promise the
    // application 4 GiB messages and then refuse them.
    #[test]
    fn no_limit_on_either_side_resolves_to_the_implementation_ceiling() {
        let transport = started_transport(SctpMaxMessageSize::Bounded(0), 0);
        assert_eq!(
            Some(SctpMaxMessageSize::MAX_MESSAGE_SIZE),
            transport.max_message_size()
        );
        assert_eq!(
            SctpMaxMessageSize::MAX_MESSAGE_SIZE as usize,
            transport.receive_message_limit,
            "what this side accepts is the ceiling it advertises in place of 0"
        );
    }

    // RFC 8841 6.1: each side's `max-message-size` limits what the other side sends. Accept
    // 256 KiB and have the peer accept 16 KiB (or omit the attribute, which means 64 KiB): this
    // side sends at most the peer's limit, and still takes messages up to its own.
    #[test]
    fn receive_limit_is_what_this_side_advertised_not_the_negotiated_minimum() {
        for remote in [16384, SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE] {
            let transport = started_transport(SctpMaxMessageSize::Unbounded, remote);
            assert_eq!(Some(remote), transport.max_message_size(), "send limit");
            assert_eq!(
                SctpMaxMessageSize::MAX_MESSAGE_SIZE as usize,
                transport.receive_message_limit,
                "receive limit with a remote limit of {remote}"
            );
            let config = transport
                .sctp_transport_config
                .as_ref()
                .expect("client transport config");
            assert_eq!(remote, config.max_message_size());
            assert_eq!(
                SctpMaxMessageSize::MAX_MESSAGE_SIZE,
                config.max_receive_message_size()
            );
        }
    }

    // RFC 8841 5: the remote `a=sctp-port` is the destination port of the INIT.
    #[test]
    fn start_applies_the_remote_sctp_port() {
        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport
            .start(
                SCTPTransportCapabilities {
                    max_message_size: 0,
                },
                5000,
                6000,
            )
            .expect("start");
        let config = transport
            .sctp_transport_config
            .expect("client transport config");
        assert_eq!(5000, config.sctp_port());
        assert_eq!(6000, config.remote_sctp_port());
    }

    #[test]
    fn max_message_size_is_none_before_start() {
        let transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        assert_eq!(None, transport.max_message_size());
    }

    // No association yet: the spec's initial state, and nothing to report for maxChannels.
    #[test]
    fn state_and_max_channels_before_any_association() {
        let transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        assert_eq!(RTCSctpTransportState::Connecting, transport.state());
        assert_eq!(None, transport.max_channels());
    }

    // Upstream's test inserts a default `Association`, which its engine reports as closed. Here
    // a default association is still handshaking (`connecting`, see
    // `a_handshaking_association_is_connecting`), so the association is closed explicitly: the
    // transport must then report Closed rather than the Connecting it was constructed with.
    #[test]
    fn state_follows_a_closed_association() {
        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        let mut association = Association::default();
        association
            .close(sctp::AssociationError::LocallyClosed)
            .expect("close");
        assert!(association.is_ended());
        transport
            .sctp_associations
            .insert(AssociationHandle(0), association);
        assert_eq!(RTCSctpTransportState::Closed, transport.state());
        assert_eq!(
            None,
            transport.max_channels(),
            "a closed association negotiated nothing"
        );
    }

    #[test]
    fn start_applies_configured_receive_buffer_size() {
        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            Some(200_000),
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport
            .start(
                SCTPTransportCapabilities {
                    max_message_size: 0,
                },
                5000,
                5000,
            )
            .expect("start");
        assert_eq!(
            transport
                .sctp_transport_config
                .expect("client transport config")
                .max_receive_buffer_size(),
            200_000
        );
    }

    #[test]
    fn start_without_override_uses_default_receive_buffer_size() {
        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport
            .start(
                SCTPTransportCapabilities {
                    max_message_size: 0,
                },
                5000,
                5000,
            )
            .expect("start");
        // `None` keeps the sctp crate default (INITIAL_RECV_BUF_SIZE = 1 MiB).
        assert_eq!(
            transport
                .sctp_transport_config
                .expect("client transport config")
                .max_receive_buffer_size(),
            1024 * 1024
        );
    }

    // Starting a Client transport builds the endpoint from an `EndpointConfig`, so we can
    // assert the configured MTU flowed through `start()` as the derived payload budget:
    // mtu minus the common and DATA chunk headers, rounded down to the 4-byte boundary.
    #[test]
    fn start_applies_configured_mtu() {
        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            Some(1500),
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport
            .start(
                SCTPTransportCapabilities {
                    max_message_size: 0,
                },
                5000,
                5000,
            )
            .expect("start");
        assert_eq!(
            transport
                .sctp_endpoint
                .expect("client endpoint")
                .endpoint_config()
                .get_max_payload_size(),
            (1500 - (12 + 16)) & !3
        );
    }

    fn scheduler_after_start(transport: SctpTransport) -> ::sctp::StreamScheduler {
        let mut transport = transport;
        transport
            .start(
                SCTPTransportCapabilities {
                    max_message_size: 0,
                },
                5000,
                5000,
            )
            .expect("start");
        transport
            .sctp_transport_config
            .expect("client transport config")
            .stream_scheduler()
    }

    /// RFC 8831 section 6.4: the priorities of data channels "MUST be interpreted as
    /// weighted-fair-queuing scheduling priorities per the definition of the corresponding
    /// stream scheduler supporting interleaving in [RFC8260]": that scheduler is the one an
    /// association gets unless the application says otherwise. It used to be opt-in.
    #[test]
    fn start_schedules_by_weighted_fair_queueing_by_default() {
        assert_eq!(
            ::sctp::StreamScheduler::WeightedFairQueueing,
            scheduler_after_start(new_transport())
        );
    }

    #[test]
    fn start_applies_weighted_fair_queueing_when_asked() {
        assert_eq!(
            ::sctp::StreamScheduler::WeightedFairQueueing,
            scheduler_after_start(new_transport().with_weighted_fair_queueing(true))
        );
    }

    #[test]
    fn start_schedules_first_come_first_served_when_asked() {
        assert_eq!(
            ::sctp::StreamScheduler::FirstComeFirstServed,
            scheduler_after_start(new_transport().with_weighted_fair_queueing(false))
        );
    }

    /// RFC 8831 sections 6.1 and 6.6 (message interleaving "SHOULD be used") and RFC 9653
    /// section 5.2 (over DTLS an endpoint "SHOULD use zero as the checksum"): both are
    /// announced by default, and each can be turned off.
    #[test]
    fn start_announces_interleaving_and_the_zero_checksum_by_default() {
        let mut transport = new_transport();
        transport
            .start(
                SCTPTransportCapabilities {
                    max_message_size: 0,
                },
                5000,
                5000,
            )
            .expect("start");
        let config = transport.sctp_transport_config.expect("config");
        assert!(config.message_interleaving());
        assert!(config.zero_checksum());

        let mut transport = new_transport()
            .with_message_interleaving(false)
            .with_zero_checksum(false);
        transport
            .start(
                SCTPTransportCapabilities {
                    max_message_size: 0,
                },
                5000,
                5000,
            )
            .expect("start");
        let config = transport.sctp_transport_config.expect("config");
        assert!(!config.message_interleaving());
        assert!(!config.zero_checksum());
    }

    /// RFC 8831 section 5: "The initial Path MTU at the IP layer SHOULD NOT exceed 1200 bytes
    /// for IPv4 and 1280 bytes for IPv6." An SCTP packet of the budget, in its DTLS record,
    /// under the headers of the path, is exactly that large at the IP layer, whatever the
    /// path, the DTLS version and the cipher suite; the fixed 1191 gave 1256 bytes over IPv4.
    #[test]
    fn the_packet_budget_keeps_the_ip_packet_within_the_initial_path_mtu() {
        // DTLS 1.2: AES-GCM, ChaCha20-Poly1305, AES-CCM-8, AES-256-CBC-SHA; DTLS 1.3 (a
        // five-byte unified header and the inner content type): a 16-byte tag, AES-CCM-8, and a
        // 16-byte tag with an eight-byte connection id.
        for dtls_record_overhead in [
            13 + 24usize,
            13 + 16,
            13 + 16,
            13 + 52,
            5 + 17,
            5 + 9,
            5 + 8 + 17,
        ] {
            for ipv6 in [false, true] {
                for tcp in [false, true] {
                    for relayed in [false, true] {
                        let path = SctpPath {
                            ipv6,
                            tcp,
                            relayed,
                            dtls_record_overhead,
                        };
                        let budget = path.packet_budget();
                        let ip_header = if ipv6 { 40 } else { 20 };
                        let transport = if tcp { 20 + 2 } else { 8 };
                        let turn = if relayed { 4 } else { 0 };
                        let on_the_wire =
                            budget + dtls_record_overhead as u32 + turn + transport + ip_header;
                        assert_eq!(on_the_wire, if ipv6 { 1280 } else { 1200 }, "{path:?}");
                    }
                }
            }
        }
        let udp_gcm = |ipv6| SctpPath {
            ipv6,
            tcp: false,
            relayed: false,
            dtls_record_overhead: SctpPath::DEFAULT_DTLS_RECORD_OVERHEAD,
        };
        assert_eq!(udp_gcm(false).packet_budget(), 1135);
        assert_eq!(udp_gcm(true).packet_budget(), 1195);
    }

    /// A budget the application configured (`SettingEngineBuilder::with_sctp_mtu`) is used as
    /// it is; without one the path's is, once a pair is selected.
    #[test]
    fn a_configured_mtu_takes_the_place_of_the_paths() {
        let mut transport = new_transport();
        assert_eq!(transport.packet_budget(), None);
        transport.path_mtu = Some(1135);
        assert_eq!(transport.packet_budget(), Some(1135));

        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            Some(1400),
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport.path_mtu = Some(1135);
        assert_eq!(transport.packet_budget(), Some(1400));
    }

    /// One DTLS transport carries one SCTP association: INITs that would start more on the
    /// accepting side are refused, whatever tags they carry.
    #[test]
    fn the_accepting_side_holds_one_association_per_dtls_transport() {
        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::Bounded(65536),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport
            .start(
                SCTPTransportCapabilities {
                    max_message_size: 65536,
                },
                5000,
                5000,
            )
            .expect("start");

        let now = std::time::Instant::now();
        let peer: std::net::SocketAddr = "127.0.0.1:4444".parse().unwrap();
        let mut client_ep = ::sctp::Endpoint::new(
            peer,
            TransportProtocol::UDP,
            ::sctp::EndpointConfig::default().into(),
            None,
        );

        let mut new_associations = 0;
        for _ in 0..1000 {
            let (_ch, mut conn) = client_ep
                .connect(
                    now,
                    ::sctp::ClientConfig::new(::sctp::TransportConfig::default()),
                    "127.0.0.1:5000".parse().unwrap(),
                )
                .expect("connect");
            while let Some(t) = conn.poll_transmit(now) {
                let ::sctp::Payload::RawEncode(contents) = t.message else {
                    continue;
                };
                for dgram in contents {
                    let server_ep = transport.sctp_endpoint.as_mut().expect("endpoint");
                    if let Some((ch, ::sctp::DatagramEvent::NewAssociation(a))) =
                        server_ep.handle(now, peer, None, dgram)
                    {
                        new_associations += 1;
                        transport.sctp_associations.insert(ch, a);
                    }
                }
            }
        }

        assert_eq!(new_associations, 1);
        assert_eq!(transport.sctp_associations.len(), 1);
    }

    /// RFC 9260 section 5.1: after its INIT ACK the endpoint "MUST NOT allocate any resources
    /// or keep any states for the new association", so that INITs cost it nothing. With the
    /// crypto provider the peer connection gives it, the endpoint answers a thousand INITs
    /// and holds no association for any of them.
    #[test]
    fn the_accepting_side_keeps_nothing_for_an_init() {
        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::Bounded(65536),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        )
        .with_cookie_provider(crypto::default_provider().expect("test crypto provider"));
        transport
            .start(
                SCTPTransportCapabilities {
                    max_message_size: 65536,
                },
                5000,
                5000,
            )
            .expect("start");

        let now = std::time::Instant::now();
        let peer: std::net::SocketAddr = "127.0.0.1:4444".parse().unwrap();
        let mut client_ep = ::sctp::Endpoint::new(
            peer,
            TransportProtocol::UDP,
            ::sctp::EndpointConfig::default().into(),
            None,
        );
        let mut init_acks = 0;
        for _ in 0..1000 {
            let (_ch, mut conn) = client_ep
                .connect(
                    now,
                    ::sctp::ClientConfig::new(::sctp::TransportConfig::default()),
                    "127.0.0.1:5000".parse().unwrap(),
                )
                .expect("connect");
            while let Some(t) = conn.poll_transmit(now) {
                let ::sctp::Payload::RawEncode(contents) = t.message else {
                    continue;
                };
                for dgram in contents {
                    let server_ep = transport.sctp_endpoint.as_mut().expect("endpoint");
                    assert!(
                        server_ep.handle(now, peer, None, dgram).is_none(),
                        "an INIT makes no association"
                    );
                    while let Some(answer) = server_ep.poll_transmit() {
                        let ::sctp::Payload::RawEncode(packets) = answer.message else {
                            continue;
                        };
                        // The first chunk of the answer is an INIT ACK (type 2).
                        init_acks += packets.iter().filter(|p| p[12] == 2).count();
                    }
                }
            }
        }
        assert_eq!(init_acks, 1000, "every INIT is answered");
        assert!(transport.sctp_associations.is_empty());
    }

    fn new_transport() -> SctpTransport {
        SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        )
    }

    fn association(local_port: u16, remote_port: u16) -> SctpNegotiation {
        SctpNegotiation::Association {
            local_port,
            remote_port,
            remote_max_message_size: 65536,
        }
    }

    /// RFC 8841 sections 10.3 and 10.4: the first exchange that negotiates an association
    /// starts the transport between the two `a=sctp-port` values; the same ports again
    /// change nothing; no data section changes nothing.
    #[test]
    fn negotiating_an_association_starts_the_transport_once() {
        let mut transport = new_transport();
        assert_eq!(
            transport.negotiate(SctpNegotiation::NoSection).unwrap(),
            SctpNegotiationOutcome::Unchanged
        );
        assert!(!transport.is_started);

        assert!(!transport.closes_on(association(5000, 6000)));
        assert_eq!(
            transport.negotiate(association(5000, 6000)).unwrap(),
            SctpNegotiationOutcome::Started
        );
        assert!(transport.is_started);
        assert_eq!(transport.negotiated_ports, Some((5000, 6000)));
        let config = transport.sctp_transport_config.as_ref().expect("config");
        assert_eq!(
            (config.sctp_port(), config.remote_sctp_port()),
            (5000, 6000)
        );
        assert_eq!(transport.max_message_size(), Some(65536));

        for same in [association(5000, 6000), SctpNegotiation::NoSection] {
            assert!(!transport.closes_on(same));
            assert_eq!(
                transport.negotiate(same).unwrap(),
                SctpNegotiationOutcome::Unchanged
            );
            assert!(transport.is_started);
        }
    }

    /// RFC 8841 section 9.3: "The existing SCTP association is closed, and the new SCTP
    /// association is established, if one or both endpoints signal a new SCTP port."
    #[test]
    fn a_new_port_on_either_side_replaces_the_association() {
        for (local, remote) in [(5001, 6000), (5000, 6001), (5001, 6001)] {
            let mut transport = new_transport();
            transport.negotiate(association(5000, 6000)).unwrap();
            assert!(transport.closes_on(association(local, remote)));
            assert_eq!(
                transport
                    .negotiate(SctpNegotiation::Association {
                        local_port: local,
                        remote_port: remote,
                        remote_max_message_size: 1200,
                    })
                    .unwrap(),
                SctpNegotiationOutcome::Replaced
            );
            assert!(transport.is_started);
            assert_eq!(transport.negotiated_ports, Some((local, remote)));
            let config = transport.sctp_transport_config.as_ref().expect("config");
            assert_eq!(
                (config.sctp_port(), config.remote_sctp_port()),
                (local, remote)
            );
            assert_eq!(
                transport.max_message_size(),
                Some(1200),
                "the new association is negotiated afresh"
            );
            assert_eq!(transport.local_port, local);
        }
    }

    /// RFC 8841 sections 10.3 and 10.4: "If the SDP 'sctp-port' attribute in the answer
    /// contains an attribute value of zero, the offerer MUST NOT establish an SCTP
    /// association. If, in addition, an SCTP association exists, the offerer MUST close it",
    /// and the same for an m= line with port zero. Port 0 used to be handed to the
    /// association as its peer's port.
    #[test]
    fn port_zero_and_a_rejected_section_establish_nothing_and_close_what_exists() {
        for refusal in [SctpNegotiation::PortZero, SctpNegotiation::Rejected] {
            let mut transport = new_transport();
            assert!(!transport.closes_on(refusal));
            assert_eq!(
                transport.negotiate(refusal).unwrap(),
                SctpNegotiationOutcome::Unchanged
            );
            assert!(!transport.is_started, "{refusal:?}");
            assert!(transport.sctp_endpoint.is_none());

            transport.negotiate(association(5000, 6000)).unwrap();
            assert!(transport.closes_on(refusal));
            assert_eq!(
                transport.negotiate(refusal).unwrap(),
                SctpNegotiationOutcome::Closed
            );
            assert!(!transport.is_started, "{refusal:?}");
            assert!(transport.sctp_endpoint.is_none());
            assert!(transport.sctp_transport_config.is_none());
            assert_eq!(transport.negotiated_ports, None);
            assert_eq!(transport.max_message_size(), None);
        }
    }

    /// RFC 8841 section 10.2 and 10.5: the port an offer carries. The port in use; a new
    /// one to replace the association; zero to close it, and zero from then on until an
    /// association is asked for again, which takes a port again.
    #[test]
    fn the_offer_carries_the_port_in_use_a_new_one_or_zero() {
        let mut transport = new_transport();
        assert_eq!(transport.offer_port(), DEFAULT_SCTP_PORT);
        transport.negotiate(association(5000, 6000)).unwrap();
        assert_eq!(transport.offer_port(), 5000);

        transport.staged = Some(SctpRenegotiation::Replace);
        let new_port = transport.offer_port();
        assert_ne!(new_port, 5000, "different than the one currently used");
        assert_ne!(new_port, 0);
        assert_eq!(transport.offer_port(), new_port, "the same offer twice");
        transport.negotiate(association(new_port, 6001)).unwrap();
        assert_eq!(transport.staged, None, "consumed by the exchange");
        assert_eq!(transport.offer_port(), new_port);

        transport.staged = Some(SctpRenegotiation::Close);
        assert_eq!(transport.offer_port(), 0);
        transport.negotiate(SctpNegotiation::PortZero).unwrap();
        assert_eq!(transport.offer_port(), 0, "closed until asked for again");

        transport.staged = Some(SctpRenegotiation::Replace);
        let reopened = transport.offer_port();
        assert_ne!(reopened, 0);
        assert_ne!(
            reopened, new_port,
            "different than the value associated with the previous SCTP association"
        );
        transport.negotiate(association(reopened, 6002)).unwrap();
        assert!(transport.is_started);
        assert_eq!(transport.offer_port(), reopened);
    }

    /// RFC 8841 section 10.3: "If the offer contained a new (different than the one
    /// currently used) SCTP port value, the answerer MUST also associate a new SCTP port
    /// value. If the offer contained a zero SCTP port value, or if the answerer does not
    /// accept the SCTP association, the answerer MUST also associate a zero SCTP port value".
    /// The answer used to say 5000 whatever the offer said.
    #[test]
    fn the_answer_follows_the_port_of_the_offer() {
        let mut transport = new_transport();
        assert_eq!(
            transport.answer_port(6000),
            DEFAULT_SCTP_PORT,
            "first offer"
        );
        assert_eq!(transport.answer_port(0), 0);

        transport.negotiate(association(5000, 6000)).unwrap();
        assert_eq!(
            transport.answer_port(6000),
            5000,
            "the same port: no change"
        );
        assert_eq!(transport.answer_port(0), 0);
        let new_port = transport.answer_port(6001);
        assert_ne!(new_port, 5000, "a new port for a new port");
        assert_ne!(new_port, 0);

        transport.staged = Some(SctpRenegotiation::Close);
        assert_eq!(
            transport.answer_port(6000),
            0,
            "the application does not accept the association"
        );

        // Section 10.5: after a close by port zero, the port of the association that was
        // closed may be used for the next one.
        transport.negotiate(SctpNegotiation::PortZero).unwrap();
        assert_eq!(transport.answer_port(6000), 5000);
    }

    /// The port after 65535 is not 0, which would close the association.
    #[test]
    fn a_new_port_is_never_zero() {
        let mut transport = new_transport();
        transport.negotiate(association(65535, 6000)).unwrap();
        transport.staged = Some(SctpRenegotiation::Replace);
        assert_eq!(transport.offer_port(), DEFAULT_SCTP_PORT);
    }

    /// RFC 8841 section 9.3: both endpoints initiate, so the endpoint `start` builds is the
    /// same whatever the DTLS role: it has the configuration to initiate with, and it takes
    /// the peer's INIT when that arrives first. A DTLS client's endpoint used to refuse it.
    #[test]
    fn the_started_endpoint_initiates_and_accepts() {
        let mut transport = new_transport();
        transport.negotiate(association(5000, 5000)).unwrap();
        assert!(transport.sctp_transport_config.is_some());

        let now = std::time::Instant::now();
        let peer: std::net::SocketAddr = "127.0.0.1:4444".parse().unwrap();
        let mut peer_ep = ::sctp::Endpoint::new(
            peer,
            TransportProtocol::UDP,
            ::sctp::EndpointConfig::default().into(),
            None,
        );
        let (_ch, mut conn) = peer_ep
            .connect(
                now,
                ::sctp::ClientConfig::new(::sctp::TransportConfig::default()),
                "127.0.0.1:5000".parse().unwrap(),
            )
            .expect("connect");
        let init = match conn.poll_transmit(now).expect("INIT").message {
            ::sctp::Payload::RawEncode(mut contents) => contents.remove(0),
            _ => panic!("an encoded INIT"),
        };
        let endpoint = transport.sctp_endpoint.as_mut().expect("endpoint");
        assert!(matches!(
            endpoint.handle(now, peer, None, init),
            Some((_, ::sctp::DatagramEvent::NewAssociation(_)))
        ));
    }
}
