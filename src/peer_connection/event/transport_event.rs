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
