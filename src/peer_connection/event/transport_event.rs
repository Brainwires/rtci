//! Events of one of the connection's transports, naming it.
//!
//! W3C webrtc-pc fires `statechange`, `gatheringstatechange`, `selectedcandidatepairchange`
//! (sections 5.5, 5.6) and `error` at the `RTCIceTransport` or `RTCDtlsTransport` object they
//! concern, and webrtc-extensions 7 the candidate pair events. A peer connection with several
//! transports (an m= section outside a BUNDLE group has one of its own, RFC 9429 section
//! 5.2.1) has several such objects; [`RTCTransportEvent`] is one of those events with the
//! transport it is fired at.

use crate::peer_connection::rtc_error::RTCError;
use crate::peer_connection::state::ice_gathering_state::RTCIceGatheringState;
use crate::peer_connection::transport::RTCTransportId;
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
use crate::peer_connection::transport::ice::candidate_pair::RTCIceCandidatePair;
use crate::peer_connection::transport::ice::state::RTCIceTransportState;

/// An event fired at one transport of the connection.
///
/// `ice_transport` and `dtls_transport` are the ids of the transport's
/// [`RTCIceTransport`](crate::peer_connection::transport::RTCIceTransport) and
/// [`RTCDtlsTransport`](crate::peer_connection::transport::RTCDtlsTransport), the ones a
/// sender's, receiver's or the SCTP transport's `transport()` returns for the sections on it;
/// [`RTCPeerConnection::dtls_transport_by_id`] gives the handle back.
///
/// [`RTCPeerConnection::dtls_transport_by_id`]: crate::peer_connection::RTCPeerConnection::dtls_transport_by_id
#[derive(Clone, Debug)]
pub struct RTCTransportEvent {
    /// The id of the transport's ICE transport.
    pub ice_transport: RTCTransportId,
    /// The id of the transport's DTLS transport.
    pub dtls_transport: RTCTransportId,
    /// What happened.
    pub event: RTCTransportEventKind,
}

/// What happened to a transport; each kind is one of the events the single-transport
/// variants of `RTCPeerConnectionEvent` report for the default transport.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum RTCTransportEventKind {
    /// `RTCIceTransport` `statechange` (as `OnIceTransportStateChange`).
    IceStateChange(RTCIceTransportState),
    /// `RTCIceTransport` `gatheringstatechange` (as `OnIceGathererStateChange`).
    GatheringStateChange(RTCIceGatheringState),
    /// `RTCIceTransport` `selectedcandidatepairchange` (as `OnSelectedCandidatePairChange`).
    SelectedCandidatePairChange(RTCIceCandidatePair),
    /// webrtc-extensions 7 `icecandidatepairadd` (as `OnIceCandidatePairAdd`).
    CandidatePairAdd(RTCIceCandidatePair),
    /// webrtc-extensions 7 `icecandidatepairnominate` (as `OnIceCandidatePairNominate`).
    CandidatePairNominate(RTCIceCandidatePair),
    /// webrtc-extensions 7 `icecandidatepairremove` (as `OnIceCandidatePairRemove`).
    CandidatePairRemove(RTCIceCandidatePair),
    /// `RTCDtlsTransport` `statechange` (as `OnDtlsTransportStateChange`).
    DtlsStateChange(RTCDtlsTransportState),
    /// `RTCDtlsTransport` `error` (as `OnDtlsTransportError`).
    DtlsError(RTCError),
}

/// Why a transport needs a new set of local candidates
/// ([`RTCLocalCandidatesNeededEvent::reason`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RTCLocalCandidatesNeededReason {
    /// An ICE restart for a new DTLS association: one this side asked for
    /// (`RTCPeerConnection::renew_dtls_association`, or an offer that replaces a data-only
    /// association to key SRTP), or one the peer's offer asked for (a new `a=tls-id`, RFC 8842
    /// section 5). The association runs on a new 3-tuple (RFC 8842 section 5.1).
    NewDtlsAssociation,
    /// The same, asked for by the connection itself because an SRTP master key neared its
    /// lifetime (automatic re-keying, RFC 5764 section 4.4;
    /// `SettingEngineBuilder::with_srtp_automatic_rekeying`).
    SrtpRekeying,
    /// The transport replaced the one an answer closed when it rejected every m= section (W3C
    /// webrtc-pc 4.4.1.4, RFC 9429 section 5.11): a new ICE agent, whose DTLS association
    /// runs on a new 3-tuple (RFC 8842 section 5.1).
    TransportReplaced,
    /// An ICE restart dropped the candidates because
    /// `SettingEngineBuilder::with_discard_local_candidates_during_ice_restart(true)`; no
    /// address is refused.
    DiscardedBySetting,
}

impl RTCLocalCandidatesNeededReason {
    /// Whether the candidates must be on transport addresses the transport did not use
    /// before: every reason but [`Self::DiscardedBySetting`].
    pub fn needs_new_addresses(self) -> bool {
        self != Self::DiscardedBySetting
    }
}

/// `OnLocalCandidatesNeeded`: a transport holds none of the local candidates it had and needs
/// a new set, gathered by the application (the engine has no sockets).
///
/// For every reason but [`RTCLocalCandidatesNeededReason::DiscardedBySetting`], the UDP
/// transport addresses the transport used before ([`Self::refused_addresses`]) are refused:
/// [`RTCPeerConnection::add_local_candidate`] returns
/// `Error::ErrICECandidateAddressOfPreviousDtlsAssociation` for a UDP candidate on one of
/// them. The application binds new ports, adds a candidate for each with `sdp_mid` set to
/// [`Self::mids`]`[0]`, signals each to the peer (`OnIceCandidateEvent`) and ends the
/// generation with an empty candidate for the same mid. The previous sockets keep carrying
/// the transport's packets until a candidate pair on a new one is selected
/// (`SelectedCandidatePairChange`), or the transport closes: close them then, not before.
///
/// [`RTCPeerConnection::add_local_candidate`]: crate::peer_connection::RTCPeerConnection::add_local_candidate
#[derive(Clone, Debug)]
pub struct RTCLocalCandidatesNeededEvent {
    /// The id of the transport's ICE transport.
    pub ice_transport: RTCTransportId,
    /// The id of the transport's DTLS transport.
    pub dtls_transport: RTCTransportId,
    /// The mids of the local description's m= sections on the transport, in order: the first
    /// is the one its candidates name (`sdpMid`, W3C webrtc-pc 5.6).
    pub mids: Vec<String>,
    /// The index of that first section in the local description (`sdpMLineIndex`).
    pub sdp_mline_index: Option<u16>,
    /// Why.
    pub reason: RTCLocalCandidatesNeededReason,
    /// The UDP transport addresses refused for the transport's local candidates: those of
    /// the candidates it held before. Empty for `DiscardedBySetting`.
    pub refused_addresses: Vec<std::net::SocketAddr>,
}
