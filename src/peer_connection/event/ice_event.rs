//! ICE candidate event types.
//!
//! Contains ICE candidate information emitted during candidate gathering.

use crate::peer_connection::transport::ice::candidate::RTCIceCandidate;

/// ICE candidate event (W3C `RTCPeerConnectionIceEvent`).
///
/// Fired for each local candidate the connection surfaces, which the application sends to
/// the remote peer over its signalling channel, and at the end of gathering (W3C webrtc-pc
/// section 5.6):
///
/// - a candidate whose [`end_of_candidates`](RTCIceCandidate::end_of_candidates) is set (its
///   `candidate` attribute is the empty string) when a generation has finished gathering, with
///   that generation's `usernameFragment`;
/// - then, once no transport gathers any more, a `None` candidate: the legacy "gathering is
///   complete" indication, which follows the gathering state's change to `complete`.
///
/// # Candidate Types
///
/// - **Host** - Local network interface address
/// - **Server Reflexive (srflx)** - Public address discovered via STUN
/// - **Peer Reflexive (prflx)** - Address discovered during connectivity checks
/// - **Relay** - Address allocated on TURN server
///
/// # Examples
///
/// ```
/// use rtc::peer_connection::event::RTCPeerConnectionEvent;
/// use rtc::peer_connection::transport::RTCIceCandidateType;
///
/// # fn handle_event(event: RTCPeerConnectionEvent) {
/// match event {
///     RTCPeerConnectionEvent::OnIceCandidateEvent(ice_event) => match ice_event.candidate {
///         Some(candidate) if candidate.end_of_candidates => {
///             // Signal the end of this generation's candidates.
///         }
///         Some(candidate) => {
///             // Only send relay candidates (for privacy), say.
///             if candidate.typ == RTCIceCandidateType::Relay {
///                 println!("Sending relay candidate: {}", candidate.address);
///             }
///             if let Some(url) = &ice_event.url {
///                 println!("Gathered from URL: {url}");
///             }
///         }
///         None => println!("gathering complete"),
///     },
///     _ => {}
/// }
/// # }
/// ```
///
/// # Specification
///
/// See [RTCPeerConnectionIceEvent](https://www.w3.org/TR/webrtc/#rtcpeerconnectioniceevent)
#[derive(Default, Clone, Debug)]
pub struct RTCPeerConnectionIceEvent {
    /// W3C `candidate`: the candidate surfaced, the end-of-candidates indication, or `None`
    /// once gathering is complete.
    pub candidate: Option<RTCIceCandidate>,

    /// W3C `url`: the STUN or TURN URL the candidate was gathered from, `None` for a host
    /// candidate and for the end-of-gathering indications.
    pub url: Option<String>,

    /// The id of the ICE transport the candidate is (or the indication is for): the one the
    /// candidate's `sdp_mid` section runs over. Not a W3C member: with several transports
    /// (RFC 9429 section 5.2.1) it says which one gathered it. `None` for the null candidate
    /// of the connection's `icecandidate` once every transport has finished gathering.
    pub ice_transport: Option<crate::peer_connection::transport::RTCTransportId>,
}
