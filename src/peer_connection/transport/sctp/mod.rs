use crate::peer_connection::configuration::setting_engine::SctpMaxMessageSize;
use crate::peer_connection::transport::RTCTransportId;
use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
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
        }
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

    /// An association that completed its handshake and has since closed. One still handshaking
    /// is in SCTP's initial `CLOSED` state too (RFC 9260 section 4), which is not an end.
    fn ended(association: &Association) -> bool {
        association.is_closed() && !association.is_handshaking()
    }

    /// W3C `SctpTransport.state`.
    ///
    /// Derived from the association rather than tracked separately: the previous `state` field was
    /// assigned once at construction and never updated or read, so any getter over it would have
    /// reported `Connecting` for the lifetime of the connection.
    pub(crate) fn state(&self) -> RTCSctpTransportState {
        match self.association() {
            None => RTCSctpTransportState::Connecting,
            Some(association) if association.is_handshaking() => RTCSctpTransportState::Connecting,
            Some(association) if association.is_closed() => RTCSctpTransportState::Closed,
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
    pub(crate) fn start(
        &mut self,
        dtls_role: RTCDtlsRole,
        remote_caps: SCTPTransportCapabilities,
        local_port: u16,
        _remote_port: u16,
    ) -> Result<()> {
        if self.is_started {
            return Ok(());
        }
        self.is_started = true;

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
            .with_stream_scheduler(scheduler);
        if let Some(recv_buf) = self.max_receive_buffer_size {
            sctp_transport_config = sctp_transport_config.with_max_receive_buffer_size(recv_buf);
        }
        //TODO: add remote_port support

        if dtls_role == RTCDtlsRole::Client {
            self.sctp_endpoint = Some(sctp::Endpoint::new(
                TransportContext::default().local_addr, // placeholder; rewritten per-transmit by the ICE handler
                TransportProtocol::UDP, // placeholder; rewritten per-transmit by the ICE handler
                sctp_endpoint_config.into(),
                None,
            ));
            self.sctp_transport_config = Some(sctp_transport_config);
        } else {
            self.sctp_endpoint = Some(::sctp::Endpoint::new(
                TransportContext::default().local_addr, // placeholder; rewritten per-transmit by the ICE handler
                TransportProtocol::UDP, // placeholder; rewritten per-transmit by the ICE handler
                sctp_endpoint_config.into(),
                Some(::sctp::ServerConfig::new(sctp_transport_config).into()),
            ));
        }

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
                RTCDtlsRole::Client,
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
                RTCDtlsRole::Client,
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
                RTCDtlsRole::Client,
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
                RTCDtlsRole::Client,
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
                RTCDtlsRole::Client,
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
}
