use crate::peer_connection::configuration::setting_engine::SctpMaxMessageSize;
use crate::peer_connection::sdp::SctpNegotiation;
use crate::peer_connection::transport::RTCTransportId;
use crate::peer_connection::transport::sctp::capabilities::SCTPTransportCapabilities;
use crate::peer_connection::transport::sctp::state::RTCSctpTransportState;
use sctp::{Association, AssociationHandle};
use shared::error::Result;
use shared::{TransportContext, TransportProtocol};
use std::collections::HashMap;

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

/// The SCTP port this side advertises (`a=sctp-port`) for its first association: the value
/// every browser uses.
pub(crate) const DEFAULT_SCTP_PORT: u16 = 5000;

/// What the application asked the next offer to do with the SCTP association (RFC 8841
/// section 10.5).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum SctpRenegotiation {
    /// Close it and establish a new one: the offer carries a new `a=sctp-port`.
    Replace,
    /// Close it and establish none: the offer carries `a=sctp-port:0`.
    Close,
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

    // The *configured* ceiling from SettingEngine — an input to the negotiation below, not the
    // value W3C `maxMessageSize` reports. See `negotiated_max_message_size`.
    pub(crate) max_message_size: SctpMaxMessageSize,

    // The negotiated [[MaxMessageSize]] slot: the result of reconciling the configured ceiling
    // above with the peer's `max-message-size` SDP attribute, computed once in `start()`.
    // `None` before the association has been negotiated.
    pub(crate) negotiated_max_message_size: Option<u32>,

    // Optional override for the SCTP receive-buffer size (a_rwnd flow-control window),
    // in bytes. None uses the sctp crate default (INITIAL_RECV_BUF_SIZE, 1 MiB).
    pub(crate) max_receive_buffer_size: Option<u32>,

    // Optional override for the outbound SCTP DATA-packet budget, applied to the endpoint's
    // `EndpointConfig` in `start()`. None uses the sctp crate default (INITIAL_MTU, 1191).
    pub(crate) mtu: Option<u32>,

    // Streams share the bytes sent by weight (RFC 8260 section 3.6), off by default.
    pub(crate) weighted_fair_queueing: bool,

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
            max_message_size,
            negotiated_max_message_size: None,
            max_receive_buffer_size,
            mtu,
            weighted_fair_queueing: false,
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
        self.receive_message_limit = 0;
        self.negotiated_ports = None;
        self.lost = false;
    }

    /// Schedules the association `start()` builds by weighted fair queueing.
    pub(crate) fn with_weighted_fair_queueing(mut self, enabled: bool) -> Self {
        self.weighted_fair_queueing = enabled;
        self
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
    pub(crate) fn max_message_size(&self) -> Option<u32> {
        self.negotiated_max_message_size
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

        // RFC 8841 6.1: each side's `max-message-size` limits what the *other* side sends. So
        // what this side accepts is what it advertised (`can_send_size`, which is what
        // `populate_sdp` writes), not the negotiated minimum: that minimum is only the send
        // limit, and receiving by it refused every message larger than the peer's own limit
        // (64 KiB when the peer's SDP omits the attribute) although this side had promised to
        // take it.
        self.receive_message_limit = can_send_size as usize;

        let mut sctp_endpoint_config = ::sctp::EndpointConfig::default();
        if let Some(mtu) = self.mtu {
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
            .with_stream_scheduler(scheduler);
        if let Some(recv_buf) = self.max_receive_buffer_size {
            sctp_transport_config = sctp_transport_config.with_max_receive_buffer_size(recv_buf);
        }

        // One association per DTLS transport: once this side has initiated its own, or has
        // taken the peer's INIT, the endpoint starts no other.
        let mut server_config = ::sctp::ServerConfig::new(sctp_transport_config.clone());
        server_config.concurrent_associations(MAX_SCTP_ASSOCIATIONS_PER_DTLS_TRANSPORT);
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

    #[test]
    fn start_applies_weighted_fair_queueing_when_asked() {
        let transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        )
        .with_weighted_fair_queueing(true);
        assert_eq!(
            ::sctp::StreamScheduler::WeightedFairQueueing,
            scheduler_after_start(transport)
        );
    }

    #[test]
    fn start_keeps_first_come_first_served_by_default() {
        let transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        assert_eq!(
            ::sctp::StreamScheduler::FirstComeFirstServed,
            scheduler_after_start(transport)
        );
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
