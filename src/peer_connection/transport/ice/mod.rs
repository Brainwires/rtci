use crate::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use crate::peer_connection::state::ice_gathering_state::RTCIceGatheringState;
use crate::peer_connection::transport::RTCTransportId;
use crate::peer_connection::transport::ice::candidate::RTCIceCandidate;
use crate::peer_connection::transport::ice::candidate_pair::RTCIceCandidatePair;
use crate::peer_connection::transport::ice::component::RTCIceComponent;
use crate::peer_connection::transport::ice::parameters::RTCIceParameters;
use crate::peer_connection::transport::ice::role::RTCIceRole;
use crate::peer_connection::transport::ice::state::RTCIceTransportState;
use crypto::RTCCryptoProvider;
use ice::candidate::Candidate;
use ice::tcp_type::TcpType;
use ice::{Agent, AgentConfig};
use shared::error::{Error, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

pub(crate) mod candidate;
pub(crate) mod candidate_pair;
pub(crate) mod candidate_type;
pub(crate) mod component;
pub(crate) mod parameters;
pub(crate) mod protocol;
pub(crate) mod role;
pub(crate) mod server;
pub(crate) mod state;

/// ICETransport allows an application access to information about the ICE
/// transport over which packets are sent and received.
pub(crate) struct IceTransport {
    pub(crate) agent: Agent,

    pub(crate) id: RTCTransportId,

    pub(crate) ice_gathering_state: RTCIceGatheringState,
    pub(crate) ice_connection_state: RTCIceConnectionState,

    /// The media section (mid, index) of the local description whose transport this is: the
    /// first section of the BUNDLE group. The `sdpMid` / `sdpMLineIndex` of the candidates the
    /// connection surfaces (W3C webrtc-pc section 5.6, "surface the candidate").
    pub(crate) local_media_section: Option<(String, u16)>,

    /// While a local offer's ICE restart can still be rolled back
    /// ([`Agent::apply_restart_revertible`]): the gathering state and the generation's
    /// username fragment announced before it, which a rollback announces again.
    pub(crate) gathering_before_local_restart: Option<(RTCIceGatheringState, Option<String>)>,

    /// The UDP transport addresses of the local candidates of the DTLS association a new one
    /// replaced (RFC 8842 sections 5.1 and 6: the new association needs a new 3-tuple, "not
    /// recently used for any other DTLS association"). A local candidate on one of them is
    /// refused until the next ICE restart that is not for a new association.
    pub(crate) previous_association_addresses: Vec<SocketAddr>,

    /// While a local offer's ICE restart can still be rolled back: the addresses refused
    /// before it, which a rollback restores.
    pub(crate) previous_association_addresses_before_local_restart: Option<Vec<SocketAddr>>,

    /// The transport dropped its local candidates (a new DTLS association, a replacement, or
    /// the discarding setting): `OnLocalCandidatesNeeded` is fired, with this reason, when
    /// the next local description begins the transport's gathering.
    pub(crate) candidates_needed:
        Option<crate::peer_connection::event::RTCLocalCandidatesNeededReason>,

    /// Whether W3C `[[IceRole]]` has left "unknown": set by the first offer processed, local
    /// (controlling) or remote (by RFC 8445's rules), and kept for the life of the transport.
    /// The role itself is the agent's, which an ICE role conflict may change (RFC 8445
    /// section 7.3.1.1).
    pub(crate) role_determined: bool,
}

impl IceTransport {
    /// creates a new IceTransport
    pub(crate) fn new(
        now: Instant,
        agent_config: AgentConfig,
        crypto_provider: Arc<dyn RTCCryptoProvider>,
        id: RTCTransportId,
    ) -> Result<Self> {
        let agent = Agent::new(now, Arc::new(agent_config), crypto_provider)?;

        Ok(IceTransport {
            agent,
            id,
            ice_gathering_state: RTCIceGatheringState::New,
            // W3C 4.4.1.1: [[IceConnectionState]] starts "new".
            ice_connection_state: RTCIceConnectionState::New,
            local_media_section: None,
            gathering_before_local_restart: None,
            previous_association_addresses: Vec::new(),
            previous_association_addresses_before_local_restart: None,
            candidates_needed: None,
            role_determined: false,
        })
    }

    /// Fills in what a local candidate the connection surfaces carries besides itself: the
    /// ICE generation (`usernameFragment`) and the media section (`sdpMid`, `sdpMLineIndex`).
    pub(crate) fn describe_local_candidate(&self, candidate: &mut RTCIceCandidate) {
        candidate.username_fragment = Some(self.agent.get_local_credentials().ufrag.clone());
        if let Some((mid, index)) = &self.local_media_section {
            candidate.sdp_mid = Some(mid.clone());
            candidate.sdp_mline_index = Some(*index);
        }
    }

    /// get_local_parameters returns the ICE parameters of the ICEGatherer.
    pub(crate) fn get_local_parameters(&self) -> Result<RTCIceParameters> {
        let (frag, pwd) = self.get_local_user_credentials();

        Ok(RTCIceParameters {
            username_fragment: frag.to_string(),
            password: pwd.to_string(),
            ice_lite: false,
        })
    }

    /// get_local_candidates returns the sequence of valid local candidates associated with the ICEGatherer.
    pub(crate) fn get_local_candidates(&self) -> Result<Vec<RTCIceCandidate>> {
        Ok(IceTransport::rtc_ice_candidates_from_ice_candidates(
            self.agent.get_local_candidates(),
        ))
    }

    /// The local candidates gathered for the staged ICE restart, which it keeps in any case
    /// ([`ice::Agent::get_restart_generation_local_candidates`]).
    pub(crate) fn get_restart_generation_local_candidates(&self) -> Vec<RTCIceCandidate> {
        IceTransport::rtc_ice_candidates_from_ice_candidates(
            &self.agent.get_restart_generation_local_candidates(),
        )
    }

    /// Returns the local user credentials.
    pub(crate) fn get_local_user_credentials(&self) -> (&str, &str) {
        (
            self.agent.get_local_credentials().ufrag.as_str(),
            self.agent.get_local_credentials().pwd.as_str(),
        )
    }

    /// W3C `IceTransport.getRemoteParameters()`: the remote ICE parameters received via
    /// `setRemoteDescription`.
    ///
    /// `None` if they have not been received yet. Note the difference from
    /// [`Self::get_remote_user_credentials`], which reports absent credentials as a pair of empty
    /// strings — a caller cannot tell those from a peer that genuinely sent empty ones, and the
    /// spec is explicit that this returns null.
    pub(crate) fn get_remote_parameters(&self) -> Option<RTCIceParameters> {
        let (username_fragment, password) = self.get_remote_user_credentials();
        if username_fragment.is_empty() && password.is_empty() {
            return None;
        }

        Some(RTCIceParameters {
            username_fragment: username_fragment.to_string(),
            password: password.to_string(),
            ice_lite: false,
        })
    }

    /// W3C `IceTransport.gatheringState`.
    ///
    /// The spec types this as `RTCIceGathererState`, a second enum whose values are identical to
    /// `RTCIceGatheringState`'s (`new`/`gathering`/`complete`). This crate carries one enum for
    /// both.
    pub(crate) fn gathering_state(&self) -> RTCIceGatheringState {
        self.ice_gathering_state
    }

    /// W3C `IceTransport.component`.
    ///
    /// Always [`RTCIceComponent::Rtp`]. RTCP multiplexing is required here — `RTCRtcpMuxPolicy`
    /// has the single value `"require"` — and for a muxed transport the spec itself specifies this
    /// value, so it is conformance rather than a simplification.
    pub(crate) fn component(&self) -> RTCIceComponent {
        RTCIceComponent::Rtp
    }

    /// webrtc-extensions 7 `[[CandidatePairs]]`: the agent's candidate pairs.
    pub(crate) fn get_candidate_pairs(&self) -> Vec<RTCIceCandidatePair> {
        self.agent
            .get_candidate_pairs()
            .iter()
            .map(|(local, remote)| self.exposed_pair(local, remote))
            .collect()
    }

    /// A pair of the agent as the application sees it: the remote candidate with its address
    /// withheld unless the application supplied that address (see [`Self::exposed_remote`]).
    pub(crate) fn exposed_pair(
        &self,
        local: &ice::candidate::Candidate,
        remote: &ice::candidate::Candidate,
    ) -> RTCIceCandidatePair {
        RTCIceCandidatePair::new(local.into(), self.exposed_remote(remote))
    }

    /// W3C webrtc-pc 4.8.1 (`RTCIceCandidate.address`): "By default, the user agent MUST leave
    /// the address attribute as null for any exposed remote candidate. Once a RTCPeerConnection
    /// instance learns on an address by the web application using addIceCandidate, the user
    /// agent can expose the address". The addresses the application supplied are those of the
    /// remote candidates it signalled (in a description or with `add_remote_candidate`); a
    /// peer-reflexive candidate the agent learned from a check, at another address, is exposed
    /// with an empty (null) address.
    pub(crate) fn exposed_remote(&self, remote: &ice::candidate::Candidate) -> RTCIceCandidate {
        let mut exposed: RTCIceCandidate = remote.into();
        let learned = remote.candidate_type() != ice::candidate::CandidateType::PeerReflexive
            || self.agent.get_remote_candidates().iter().any(|signalled| {
                signalled.candidate_type() != ice::candidate::CandidateType::PeerReflexive
                    && signalled.address() == remote.address()
            });
        if !learned {
            exposed.address = String::new();
        }
        exposed
    }

    /// The agent's candidates of the listed pair that matches `pair` (webrtc-extensions 7.2:
    /// local and remote each with the same candidate string, sdpMid, sdpMLineIndex and
    /// usernameFragment, a null one matching only null).
    pub(crate) fn find_candidate_pair(
        &self,
        pair: &RTCIceCandidatePair,
    ) -> Option<(ice::candidate::Candidate, ice::candidate::Candidate)> {
        fn matches(ours: &RTCIceCandidate, theirs: &RTCIceCandidate) -> bool {
            // A remote candidate whose address was withheld has no candidate string of its
            // own: it is the one with the same id (and the same rest).
            let same = if ours.address.is_empty() {
                theirs.address.is_empty()
                    && ours.id == theirs.id
                    && ours.port == theirs.port
                    && ours.typ == theirs.typ
            } else {
                ours.candidate().ok() == theirs.candidate().ok()
            };
            same && ours.sdp_mid == theirs.sdp_mid
                && ours.sdp_mline_index == theirs.sdp_mline_index
                && ours.username_fragment == theirs.username_fragment
        }
        self.agent
            .get_candidate_pairs()
            .into_iter()
            .find(|(local, remote)| {
                let candidate = self.exposed_pair(local, remote);
                matches(candidate.local(), pair.local())
                    && matches(candidate.remote(), pair.remote())
            })
    }

    /// W3C `IceTransport.getSelectedCandidatePair()`.
    ///
    /// `None` until ICE has nominated a pair.
    pub(crate) fn get_selected_candidate_pair(&self) -> Option<RTCIceCandidatePair> {
        let (local, remote) = self.agent.get_selected_candidate_pair()?;
        Some(self.exposed_pair(local, remote))
    }

    /// W3C `IceTransport.getRemoteCandidates()`: the remote candidates received so far.
    pub(crate) fn get_remote_candidates(&self) -> Vec<RTCIceCandidate> {
        IceTransport::rtc_ice_candidates_from_ice_candidates(self.agent.get_remote_candidates())
    }

    /// Returns the remote user credentials.
    pub(crate) fn get_remote_user_credentials(&self) -> (&str, &str) {
        if let Some(remote_credentials) = self.agent.get_remote_credentials() {
            (
                remote_credentials.ufrag.as_str(),
                remote_credentials.pwd.as_str(),
            )
        } else {
            ("", "")
        }
    }

    /// Conversion for ice_candidates
    fn rtc_ice_candidates_from_ice_candidates(
        ice_candidates: &[Candidate],
    ) -> Vec<RTCIceCandidate> {
        ice_candidates.iter().map(|c| c.into()).collect()
    }

    pub(crate) fn have_remote_credentials_change(&self, new_ufrag: &str, new_pwd: &str) -> bool {
        let (ufrag, upwd) = self.get_remote_user_credentials();
        ufrag != new_ufrag || upwd != new_pwd
    }

    pub(crate) fn set_remote_credentials(
        &mut self,
        remote_ufrag: String,
        remote_pwd: String,
    ) -> Result<()> {
        if remote_ufrag.is_empty() {
            return Err(Error::ErrRemoteUfragEmpty);
        } else if remote_pwd.is_empty() {
            return Err(Error::ErrRemotePwdEmpty);
        }

        self.agent
            .set_remote_credentials(remote_ufrag, remote_pwd)?;

        Ok(())
    }

    /// Adds a new remote candidate. `Ok(false)` when the agent dropped it (past its cap, or of a
    /// network type it doesn't use); an active TCP candidate, never dialled, is still `Ok(true)`.
    pub(crate) fn add_remote_candidate(&mut self, c: Candidate) -> Result<bool> {
        // cannot check for network yet because it might not be applied
        // when mDNS hostame is used.
        if c.tcp_type() == TcpType::Active && !(self.agent.is_lite() && self.agent.is_remote_lite())
        {
            // TCP Candidates with tcptype active will probe server passive ones, so
            // no need to do anything with them. Two lite agents send no checks: the agent
            // takes the candidate (RFC 6544 section 6.1).
            log::info!("Ignoring remote candidate with tcpType active: {c}");
            return Ok(true);
        }

        self.agent.add_remote_candidate(c)
    }

    pub(crate) fn add_local_candidate(&mut self, c: Candidate) -> Result<bool> {
        self.agent.add_local_candidate(c)
    }

    /// Before an ICE restart is applied: when it sets up a new DTLS association
    /// (`new_association`), the UDP transport addresses of the local candidates the agent
    /// holds are refused from now on (RFC 8842 sections 5.1 and 6); otherwise nothing is
    /// refused any more. Returns the addresses refused before.
    pub(crate) fn retire_local_addresses(&mut self, new_association: bool) -> Vec<SocketAddr> {
        let retired = if new_association {
            self.current_generation_udp_addresses()
        } else {
            Vec::new()
        };
        std::mem::replace(&mut self.previous_association_addresses, retired)
    }

    /// The UDP transport addresses of the local candidates of the ICE generation in use: the
    /// agent's, less those given for a restart that is staged (they are the next
    /// generation's).
    pub(crate) fn current_generation_udp_addresses(&self) -> Vec<SocketAddr> {
        let next: Vec<SocketAddr> = self
            .agent
            .get_restart_generation_local_candidates()
            .iter()
            .filter(|c| c.network_type().is_udp())
            .map(|c| c.addr())
            .collect();
        let mut addresses: Vec<SocketAddr> = self
            .agent
            .get_local_candidates()
            .iter()
            .filter(|c| c.network_type().is_udp())
            .map(|c| c.addr())
            .filter(|a| !next.contains(a))
            .collect();
        addresses.sort();
        addresses.dedup();
        addresses
    }

    /// Whether `c` is a UDP candidate on a transport address of the DTLS association a new
    /// one replaced ([`Self::retire_local_addresses`]).
    pub(crate) fn on_previous_association_address(&self, c: &Candidate) -> Option<SocketAddr> {
        if !c.network_type().is_udp() {
            return None;
        }
        let addr = c.addr();
        self.previous_association_addresses
            .contains(&addr)
            .then_some(addr)
    }

    /// Role indicates the current role of the ICE transport.
    pub(crate) fn role(&self) -> RTCIceRole {
        if self.agent.role() {
            RTCIceRole::Controlling
        } else {
            RTCIceRole::Controlled
        }
    }

    /// W3C `RTCIceTransport.role` (`[[IceRole]]`): "unknown" until the first offer is
    /// processed, then the agent's role.
    pub(crate) fn w3c_role(&self) -> RTCIceRole {
        if self.role_determined {
            self.role()
        } else {
            RTCIceRole::Unspecified
        }
    }

    /// set current role of the ICE transport.
    pub(crate) fn set_role(&mut self, role: RTCIceRole) {
        self.agent.set_role(role == RTCIceRole::Controlling);
    }

    pub(crate) fn state(&self) -> RTCIceTransportState {
        self.agent.state().into()
    }

    /// Stages ICE-restart credentials so an offer can advertise them.
    ///
    /// Does not disturb the live session; see [`ice::Agent::generate_restart_credentials`].
    pub(crate) fn generate_restart_credentials(
        &mut self,
        ufrag: String,
        pwd: String,
    ) -> Result<()> {
        self.agent.generate_restart_credentials(ufrag, pwd)
    }

    /// Whether an ICE restart has been staged but not yet applied.
    pub(crate) fn has_pending_restart(&self) -> bool {
        self.agent.has_pending_restart()
    }

    /// Forgets a staged ICE restart; see [`ice::Agent::discard_restart_credentials`].
    pub(crate) fn discard_restart_credentials(&mut self) {
        self.agent.discard_restart_credentials();
    }

    /// Applies a staged ICE restart, restarting the agent's timers at `now`.
    pub(crate) fn apply_restart(
        &mut self,
        now: Instant,
        keep_local_candidates: bool,
    ) -> Result<()> {
        self.agent.apply_restart(now, keep_local_candidates)
    }

    pub(crate) fn start(
        &mut self,
        now: Instant,
        local_ice_role: RTCIceRole,
        remote_ice_parameters: RTCIceParameters,
    ) -> Result<()> {
        if self.state() != RTCIceTransportState::New {
            return Err(Error::ErrICETransportNotInNew);
        }

        self.agent.set_remote_lite(remote_ice_parameters.ice_lite);
        self.agent.start_connectivity_checks(
            now,
            local_ice_role == RTCIceRole::Controlling,
            remote_ice_parameters.username_fragment,
            remote_ice_parameters.password,
        )?;

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

    fn transport() -> IceTransport {
        let crypto_provider =
            crypto::default_provider().expect("a built-in crypto provider is enabled for tests");
        IceTransport::new(
            Instant::now(),
            AgentConfig::default(),
            crypto_provider,
            test_transport_id(TransportKind::Ice),
        )
        .expect("ice transport")
    }

    // W3C types this `RTCIceGathererState`; this crate carries the structurally identical
    // `RTCIceGatheringState` for both. The field was already assigned by the negotiation paths —
    // only the accessor was missing.
    #[test]
    fn gathering_state_reports_the_tracked_field() {
        let mut ice_transport = transport();
        assert_eq!(RTCIceGatheringState::New, ice_transport.gathering_state());

        ice_transport.ice_gathering_state = RTCIceGatheringState::Gathering;
        assert_eq!(
            RTCIceGatheringState::Gathering,
            ice_transport.gathering_state()
        );

        ice_transport.ice_gathering_state = RTCIceGatheringState::Complete;
        assert_eq!(
            RTCIceGatheringState::Complete,
            ice_transport.gathering_state()
        );
    }

    // The spec is explicit that this returns null before the remote description supplies
    // credentials. `get_remote_user_credentials()` reports that case as a pair of empty strings,
    // which a caller cannot distinguish from a peer that sent empty ones.
    #[test]
    fn remote_parameters_are_none_until_credentials_arrive() {
        let mut ice_transport = transport();
        assert_eq!(("", ""), ice_transport.get_remote_user_credentials());
        assert!(
            ice_transport.get_remote_parameters().is_none(),
            "no remote description has been applied"
        );

        ice_transport
            .set_remote_credentials(
                "remoteUfrag".to_owned(),
                "remotePasswordThatIsLongEnough".to_owned(),
            )
            .expect("set remote credentials");

        let params = ice_transport
            .get_remote_parameters()
            .expect("credentials have been applied");
        assert_eq!("remoteUfrag", params.username_fragment);
        assert_eq!("remotePasswordThatIsLongEnough", params.password);
    }

    // Under required RTCP multiplexing the spec itself specifies "rtp" for a transport carrying
    // both, so this is conformance rather than a stand-in.
    #[test]
    fn component_is_rtp_under_rtcp_mux() {
        assert_eq!(RTCIceComponent::Rtp, transport().component());
    }

    #[test]
    fn selected_candidate_pair_and_remote_candidates_are_empty_before_ice_runs() {
        let ice_transport = transport();
        assert!(ice_transport.get_selected_candidate_pair().is_none());
        assert!(ice_transport.get_remote_candidates().is_empty());
    }
}
