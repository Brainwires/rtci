//! Which m= section runs over which transport (RFC 9429 sections 4.1.1, 5.2.1, 5.3.1; RFC 9143
//! section 7).
//!
//! A BUNDLE group is one transport; every other m= section that is not rejected has a transport
//! of its own, with its own ICE credentials and candidates, DTLS association and SRTP keys. The
//! layout follows the descriptions:
//!
//! - a remote offer gives each section outside its BUNDLE group a transport, created then and
//!   started with the answer;
//! - an offer this side makes under the `max-compat` bundle policy gives each section a
//!   transport of its own;
//! - an answer, remote or local, settles it: the sections it bundles move to the transport of
//!   the group's tagged section, and a transport left without a section is closed;
//! - a rollback restores the layout of the current descriptions.
//!
//! The first transport (the one the connection is built with) carries the first group. Its
//! description handling is the one the single-transport engine had; the other transports are
//! started from the part of the description that names their sections.

use super::*;
use crate::peer_connection::configuration::RTCBundlePolicy;
use crate::peer_connection::event::{RTCPeerConnectionEvent, RTCPeerConnectionIceEvent};
use crate::peer_connection::handler::dtls::DtlsHandlerContext;
use crate::peer_connection::handler::ice::IceHandlerContext;
use crate::peer_connection::handler::srtp::SrtpHandlerContext;
use crate::peer_connection::handler::transport_set::TransportId;
use crate::peer_connection::sdp::{
    add_candidates_to_media_descriptions, bundle_group_mids, extract_fingerprints,
    extract_ice_details, get_mid_value, is_rejected_media,
};
use crate::peer_connection::transport::ice::IceTransport;
use crate::peer_connection::transport::ice::candidate::{
    RTCIceCandidate, RTCIceServerTransportProtocol, rtc_ice_candidates_from_ice_candidates,
};
use crate::peer_connection::transport::{RTCTransportId, TransportKind};
use ::sdp::description::common::Attribute;
use ::sdp::description::session::{ATTR_KEY_GROUP, SessionDescription};
use rand::RngExt;

/// The ICE attributes that belong to a transport (RFC 8859 category TRANSPORT): each
/// transport's sections carry its own.
const TRANSPORT_ICE_ATTRIBUTES: [&str; 4] =
    ["ice-ufrag", "ice-pwd", "candidate", "end-of-candidates"];

/// The m= sections of a description, grouped by the transport they share: the BUNDLE group's
/// sections that are not rejected, then each other section that is not rejected on its own,
/// in the order of the first section of each.
pub(crate) fn transport_groups(desc: &SessionDescription) -> Vec<Vec<String>> {
    let bundle: Vec<&str> = bundle_group_mids(desc);
    let live: Vec<&str> = desc
        .media_descriptions
        .iter()
        .filter(|m| !is_rejected_media(m))
        .filter_map(|m| get_mid_value(m).map(String::as_str))
        .collect();
    let mut groups: Vec<Vec<String>> = vec![];
    let mut bundled_at = None;
    for mid in live {
        if bundle.contains(&mid) {
            match bundled_at {
                Some(index) => {
                    let group: &mut Vec<String> = &mut groups[index];
                    group.push(mid.to_owned());
                }
                None => {
                    bundled_at = Some(groups.len());
                    groups.push(vec![mid.to_owned()]);
                }
            }
        } else {
            groups.push(vec![mid.to_owned()]);
        }
    }
    groups
}

/// The part of `desc` that describes the sections `mids`: the session's attributes, with the
/// BUNDLE group restricted to them, and their m= sections. It is what one transport is
/// started and checked from.
pub(crate) fn description_for(desc: &SessionDescription, mids: &[String]) -> SessionDescription {
    let mut part = desc.clone();
    part.media_descriptions
        .retain(|m| get_mid_value(m).is_some_and(|mid| mids.contains(mid)));
    let bundle: Vec<String> = bundle_group_mids(desc)
        .into_iter()
        .filter(|mid| mids.iter().any(|m| m == mid))
        .map(str::to_owned)
        .collect();
    part.attributes.retain(|a| {
        a.key != ATTR_KEY_GROUP
            || !a
                .value
                .as_deref()
                .is_some_and(|value| value.starts_with("BUNDLE"))
    });
    if !bundle.is_empty() {
        part.attributes.push(Attribute::new(
            ATTR_KEY_GROUP.to_owned(),
            Some(format!("BUNDLE {}", bundle.join(" "))),
        ));
    }
    part
}

impl RTCPeerConnection {
    /// Adds a transport with the connection's settings: a new ICE agent (its own
    /// credentials), a DTLS transport with the connection's certificates, and SRTP contexts
    /// that follow the connection's header encryption.
    pub(crate) fn add_transport(&mut self) -> Result<TransportId> {
        let now = self.pipeline_context.now;
        let mut agent_config =
            internal::ice_agent_config(&self.configuration, &self.setting_engine)?;
        // A transport's credentials are its own (RFC 8839 section 5.4: per transport); fixed
        // ones from the settings are the first transport's.
        agent_config.local_ufrag = String::new();
        agent_config.local_pwd = String::new();
        let crypto_provider = self
            .setting_engine
            .crypto_provider
            .clone()
            .unwrap_or_else(|| self.dtls_transport().crypto_provider.clone());
        let nonce: u64 = rand::rng().random();
        let ice_transport_id = RTCTransportId::new(nonce, TransportKind::Ice);
        let dtls_transport_id = RTCTransportId::new(nonce, TransportKind::Dtls);
        let ice_transport =
            IceTransport::new(now, agent_config, crypto_provider.clone(), ice_transport_id)?;
        let certificates = self.dtls_transport().certificates.clone();
        let dtls_transport = internal::new_dtls_transport(
            &self.setting_engine,
            certificates,
            dtls_transport_id,
            ice_transport_id,
            crypto_provider,
        )?;
        let default_srtp = &self
            .pipeline_context
            .transports
            .default()
            .srtp_handler_context;
        let mut srtp = SrtpHandlerContext {
            rtp_header_encryption_policy: default_srtp.rtp_header_encryption_policy,
            ..Default::default()
        };
        srtp.set_cryptex(default_srtp.cryptex);
        srtp.set_encrypted_header_extensions(default_srtp.encrypted_header_extensions);
        Ok(self.pipeline_context.transports.insert(
            IceHandlerContext::new(ice_transport),
            DtlsHandlerContext::new(dtls_transport),
            srtp,
        ))
    }

    /// Puts each group of m= sections on one transport: the one a section of the group is on
    /// already (its first section's first), else a new one. The first group is on the
    /// default transport. Sections in no group are taken off their transport, and a
    /// transport left without a section is closed.
    pub(crate) fn apply_transport_layout(&mut self, groups: &[Vec<String>]) -> Result<()> {
        if groups.is_empty() {
            return Ok(());
        }
        let mut targets: Vec<TransportId> = vec![];
        for (index, group) in groups.iter().enumerate() {
            let transports = &self.pipeline_context.transports;
            let existing = group
                .iter()
                .filter_map(|mid| transports.assignment(mid))
                .find(|id| !targets.contains(id));
            let target = match existing {
                Some(id) => id,
                // The first group, nothing assigned yet: the transport the connection has.
                None if index == 0 && !targets.contains(&transports.default_id()) => {
                    transports.default_id()
                }
                None => self.add_transport()?,
            };
            targets.push(target);
        }
        let in_groups: Vec<&String> = groups.iter().flatten().collect();
        let transports = &mut self.pipeline_context.transports;
        for (group, target) in groups.iter().zip(&targets) {
            for mid in group {
                transports.assign(mid, *target);
            }
        }
        transports.set_default(targets[0]);
        for mid in self
            .rtp_transceivers
            .iter()
            .filter_map(|t| t.mid().clone())
            .filter(|mid| !in_groups.contains(&mid))
            .collect::<Vec<_>>()
        {
            self.pipeline_context.transports.unassign(&mid);
        }
        let data = self.data_section_mid_in(groups);
        let transports = &mut self.pipeline_context.transports;
        if let Some(data) = data {
            let id = transports.transport_id_for(&data);
            transports.set_data(id);
        } else {
            transports.set_data(targets[0]);
        }
        let default = transports.default_id();
        for id in transports.ids() {
            if id != default && transports.mids_on(id).is_empty() {
                log::debug!("transport {id:?} carries no m= section any more: closed");
                if let Some(mut bundle) = transports.remove(id) {
                    let _ = sansio::Protocol::close(
                        &mut bundle.ice_handler_context.ice_transport.agent,
                    );
                }
            }
        }
        Ok(())
    }

    /// The mid of the data section among `groups`: the one no transceiver has.
    fn data_section_mid_in(&self, groups: &[Vec<String>]) -> Option<String> {
        groups.iter().flatten().find_map(|mid| {
            (!self
                .rtp_transceivers
                .iter()
                .any(|t| t.mid().as_deref() == Some(mid.as_str())))
            .then(|| mid.clone())
        })
    }

    /// The layout of the current descriptions, after a rollback (RFC 9429 section 5.7): the
    /// most recent answer's, or one transport for everything before there was one.
    pub(crate) fn restore_transport_layout(&mut self) {
        let answer = [
            &self.current_local_description,
            &self.current_remote_description,
        ]
        .into_iter()
        .flatten()
        .find(|d| d.sdp_type == RTCSdpType::Answer)
        .and_then(|d| d.parsed.clone());
        let groups = answer.as_ref().map(transport_groups).unwrap_or_default();
        if groups.is_empty() {
            let transports = &mut self.pipeline_context.transports;
            let default = transports.default_id();
            for id in transports.ids() {
                if id != default {
                    transports.remove(id);
                }
            }
            for mid in self
                .rtp_transceivers
                .iter()
                .filter_map(|t| t.mid().clone())
                .collect::<Vec<_>>()
            {
                self.pipeline_context.transports.unassign(&mid);
            }
            return;
        }
        if let Err(err) = self.apply_transport_layout(&groups) {
            log::warn!("restoring the transport layout: {err}");
        }
    }

    /// The part of `desc` the default transport is set up from: all of it while there is one
    /// transport, else the sections on the default transport.
    pub(crate) fn default_transport_view(&self, desc: &SessionDescription) -> SessionDescription {
        let transports = &self.pipeline_context.transports;
        if transports.len() == 1 {
            return desc.clone();
        }
        let default = transports.default_id();
        let mids: Vec<String> = desc
            .media_descriptions
            .iter()
            .filter_map(get_mid_value)
            .filter(|mid| transports.transport_id_for(mid) == default)
            .cloned()
            .collect();
        description_for(desc, &mids)
    }

    /// RFC 9429 section 5.8.3 for each transport a remote description sets up: its ICE
    /// credentials, candidates and fingerprints are present, well formed and do not
    /// conflict.
    pub(crate) fn check_remote_transports(&self, desc: &SessionDescription) -> Result<()> {
        for group in transport_groups(desc) {
            let part = description_for(desc, &group);
            if extract_ice_details(&part)?.is_some() {
                extract_fingerprints(&part)?;
            }
        }
        if transport_groups(desc).is_empty() && extract_ice_details(desc)?.is_some() {
            extract_fingerprints(desc)?;
        }
        Ok(())
    }

    /// `set_remote_description`: the layout the description implies, then the transports
    /// take its parameters (an answer's now, an offer's with the local answer).
    pub(crate) fn apply_remote_transports(
        &mut self,
        now: Instant,
        parsed: &SessionDescription,
        we_offer: bool,
    ) -> Result<()> {
        let groups = transport_groups(parsed);
        if groups.len() > 1 || self.pipeline_context.transports.len() > 1 {
            self.apply_transport_layout(&groups)?;
        }
        let view = self.default_transport_view(parsed);
        if we_offer {
            self.apply_remote_transport(now, &view, true, None)?;
            self.start_other_transports(now, parsed, true)?;
        } else {
            self.defer_remote_transport(&view)?;
        }
        Ok(())
    }

    /// `set_local_description` of an answer: the layout the answer settles, then the
    /// default transport takes the remote offer's parameters as it did with one transport,
    /// and every other transport is set up from its sections of the offer.
    pub(crate) fn apply_local_answer_transports(
        &mut self,
        now: Instant,
        local_answer: Option<&SessionDescription>,
    ) -> Result<()> {
        let groups = local_answer.map(transport_groups).unwrap_or_default();
        if self.pipeline_context.transports.len() > 1 {
            self.apply_transport_layout(&groups)?;
        }
        let remote = self.remote_description().and_then(|r| r.parsed.clone());
        if let Some(pending) = self.pending_remote_transport.take()
            && let Some(parsed) = &remote
        {
            // The offer's sections the answer accepted on the default transport: a section
            // the answer rejected (under `balanced`, a second one of a type offered outside a
            // BUNDLE group) is no transport's.
            let transports = &self.pipeline_context.transports;
            let default = transports.default_id();
            let accepted: Vec<String> = groups
                .iter()
                .flatten()
                .filter(|mid| transports.transport_id_for(mid) == default)
                .cloned()
                .collect();
            let live = transport_groups(parsed);
            let view = if local_answer.is_none()
                || live.iter().flatten().all(|mid| accepted.contains(mid))
            {
                self.default_transport_view(parsed)
            } else {
                description_for(parsed, &accepted)
            };
            self.apply_remote_transport(now, &view, false, Some(pending.ice_restart))?;
        }
        if let Some(parsed) = &remote {
            self.start_other_transports(now, parsed, false)?;
        }
        Ok(())
    }

    /// Gives every transport but the default one the parameters of its sections of the remote
    /// description: the first time it starts it, later it follows them as the default
    /// transport does (`apply_remote_transport`).
    fn start_other_transports(
        &mut self,
        now: Instant,
        parsed: &SessionDescription,
        we_offer: bool,
    ) -> Result<()> {
        let default = self.pipeline_context.transports.default_id();
        for id in self.pipeline_context.transports.ids() {
            if id == default {
                continue;
            }
            let mids = self.pipeline_context.transports.mids_on(id);
            let part = description_for(parsed, &mids);
            if part.media_descriptions.is_empty() {
                continue;
            }
            self.with_transport(id, |pc| {
                pc.apply_remote_transport(now, &part, we_offer, None)
            })?;
        }
        Ok(())
    }

    /// An offer under the `max-compat` bundle policy (RFC 9429 section 4.1.1: "gather ICE
    /// candidates for each media track"; one transport per m= section): each section that has
    /// no transport yet gets one of its own. The first section of an initial offer keeps the
    /// connection's first transport.
    pub(crate) fn plan_offer_transports(&mut self, d: &SessionDescription) -> Result<()> {
        if self.effective_bundle_policy() != RTCBundlePolicy::MaxCompat {
            return Ok(());
        }
        let transports = &self.pipeline_context.transports;
        let mut groups: Vec<(Option<TransportId>, Vec<String>)> = vec![];
        for m in &d.media_descriptions {
            if is_rejected_media(m) {
                continue;
            }
            let Some(mid) = get_mid_value(m) else {
                continue;
            };
            match transports.assignment(mid) {
                Some(id) => match groups.iter_mut().find(|(on, _)| *on == Some(id)) {
                    Some((_, group)) => group.push(mid.clone()),
                    None => groups.push((Some(id), vec![mid.clone()])),
                },
                None => groups.push((None, vec![mid.clone()])),
            }
        }
        // The default transport's group first: it is the one the first section had.
        let default = transports.default_id();
        if let Some(index) = groups.iter().position(|(on, _)| *on == Some(default)) {
            let group = groups.remove(index);
            groups.insert(0, group);
        }
        let groups: Vec<Vec<String>> = groups.into_iter().map(|(_, group)| group).collect();
        self.apply_transport_layout(&groups)
    }

    /// Writes into a description this side generates each transport's own ICE attributes in
    /// the sections on a transport other than the default one: its credentials, its
    /// candidates (in its first section, RFC 9429 section 5.2.1) and its default destination
    /// in `m=` / `c=`. The default transport's sections keep what `populate_sdp` wrote.
    pub(crate) fn write_transport_attributes(&self, d: &mut SessionDescription) {
        let transports = &self.pipeline_context.transports;
        if transports.len() == 1 {
            return;
        }
        let default = transports.default_id();
        for id in transports.ids() {
            if id == default {
                continue;
            }
            let Some(bundle) = transports.transport(id) else {
                continue;
            };
            let ice = &bundle.ice_handler_context.ice_transport;
            let (ufrag, pwd) = ice.get_local_user_credentials();
            let candidates =
                rtc_ice_candidates_from_ice_candidates(&ice.agent.get_local_candidates_to_signal());
            let mut first = true;
            for m in &mut d.media_descriptions {
                if is_rejected_media(m)
                    || !get_mid_value(m).is_some_and(|mid| transports.transport_id_for(mid) == id)
                {
                    continue;
                }
                m.attributes
                    .retain(|a| !TRANSPORT_ICE_ATTRIBUTES.contains(&a.key.as_str()));
                m.media_name.port.value = 9;
                m.connection_information =
                    Some(::sdp::description::common::ConnectionInformation {
                        network_type: "IN".to_owned(),
                        address_type: "IP4".to_owned(),
                        address: Some(::sdp::description::common::Address {
                            address: "0.0.0.0".to_owned(),
                            ttl: None,
                            range: None,
                        }),
                    });
                m.attributes.push(Attribute::new(
                    "ice-ufrag".to_owned(),
                    Some(ufrag.to_owned()),
                ));
                m.attributes
                    .push(Attribute::new("ice-pwd".to_owned(), Some(pwd.to_owned())));
                if first {
                    first = false;
                    let taken = std::mem::take(m);
                    *m = match add_candidates_to_media_descriptions(
                        &candidates,
                        taken.clone(),
                        ice.ice_gathering_state,
                    ) {
                        Ok(with) => with,
                        Err(_) => taken,
                    };
                }
            }
        }
    }

    /// Where a local or remote candidate goes: the transport of the section its `sdpMid` (or
    /// `sdpMLineIndex`, in `desc`) names; the default one without either.
    pub(crate) fn transport_of_candidate(
        &self,
        sdp_mid: Option<&str>,
        sdp_mline_index: Option<u16>,
        desc: Option<&SessionDescription>,
    ) -> TransportId {
        let transports = &self.pipeline_context.transports;
        let mid = sdp_mid.map(str::to_owned).or_else(|| {
            let index = usize::from(sdp_mline_index?);
            desc?
                .media_descriptions
                .get(index)
                .and_then(get_mid_value)
                .cloned()
        });
        mid.map_or(transports.default_id(), |mid| {
            transports.transport_id_for(&mid)
        })
    }

    /// The local description's first section on each transport other than the default one:
    /// the `sdpMid` / `sdpMLineIndex` its candidates name (W3C 5.6), recorded on the
    /// transport when a local description is set. Such a transport starts gathering then.
    pub(crate) fn describe_other_transports(&mut self, local: &SessionDescription) {
        let default = self.pipeline_context.transports.default_id();
        for id in self.pipeline_context.transports.ids() {
            if id == default {
                continue;
            }
            let section = local
                .media_descriptions
                .iter()
                .enumerate()
                .find_map(|(index, m)| {
                    let mid = get_mid_value(m)?;
                    (self.pipeline_context.transports.transport_id_for(mid) == id)
                        .then(|| (mid.clone(), u16::try_from(index).unwrap_or(u16::MAX)))
                });
            if let Some(bundle) = self.pipeline_context.transports.transport_mut(id) {
                let ice = &mut bundle.ice_handler_context.ice_transport;
                if section.is_some() {
                    ice.local_media_section = section;
                }
                if ice.ice_gathering_state == RTCIceGatheringState::New {
                    ice.ice_gathering_state = RTCIceGatheringState::Gathering;
                }
            }
        }
    }

    /// The local candidates of every transport other than the default one, in the local
    /// description as it is read (`populate_local_candidates`).
    pub(crate) fn populate_other_transports_candidates(&self, d: &mut SessionDescription) {
        self.write_transport_attributes(d);
    }

    /// `add_local_candidate` for a transport other than the default one: the candidate is
    /// the agent's, and announced with the transport's section; an empty one ends the
    /// transport's gathering (RFC 8838 section 13) with its end-of-candidates candidate.
    pub(crate) fn add_other_local_candidate(
        &mut self,
        local_candidate: RTCIceCandidateInit,
    ) -> Result<()> {
        if self.is_closed() {
            return Err(Error::ErrConnectionClosed);
        }
        let value = local_candidate
            .candidate
            .strip_prefix("candidate:")
            .unwrap_or(local_candidate.candidate.as_str());
        if value.is_empty() {
            if self.ice_transport().ice_gathering_state == RTCIceGatheringState::Complete {
                return Ok(());
            }
            // Held back while the engine's TCP listeners or TURN allocations of this
            // transport are being made (RFC 8838 section 13), as on the default transport.
            if self.defer_end_of_gathering() {
                return Ok(());
            }
            let mut end = RTCIceCandidate::end_of_candidates_for(None, None, None);
            self.ice_transport().describe_local_candidate(&mut end);
            self.ice_transport_mut()
                .agent
                .set_local_gathering_complete();
            self.ice_transport_mut().ice_gathering_state = RTCIceGatheringState::Complete;
            self.pipeline_context.event_outs.push_back(
                RTCPeerConnectionEvent::OnIceCandidateEvent(RTCPeerConnectionIceEvent {
                    candidate: Some(end),
                    url: None,
                }),
            );
            return Ok(());
        }
        let candidate = ::ice::candidate::unmarshal_candidate(value)?;
        let known = self.ice_transport().agent.get_local_candidates().len();
        if !self.ice_transport_mut().add_local_candidate(candidate)? {
            return Ok(());
        }
        let added: Vec<RTCIceCandidate> = self
            .ice_transport()
            .agent
            .get_local_candidates()
            .iter()
            .skip(known)
            .map(RTCIceCandidate::from)
            .collect();
        for mut rtc_candidate in added {
            self.ice_transport()
                .describe_local_candidate(&mut rtc_candidate);
            // As on the default transport (W3C webrtc-pc 4.8.1): a relay candidate names the
            // protocol to its TURN server.
            if rtc_candidate.typ == crate::peer_connection::transport::RTCIceCandidateType::Relay {
                let url = local_candidate.url.as_deref();
                if rtc_candidate.url.is_none() {
                    rtc_candidate.url = url.map(str::to_owned);
                }
                rtc_candidate.relay_protocol = local_candidate
                    .relay_protocol
                    .filter(|protocol| *protocol != RTCIceServerTransportProtocol::Unspecified)
                    .unwrap_or_else(|| {
                        url.map_or_else(Default::default, internal::relay_protocol_of_turn_url)
                    });
            }
            self.pipeline_context.event_outs.push_back(
                RTCPeerConnectionEvent::OnIceCandidateEvent(RTCPeerConnectionIceEvent {
                    candidate: Some(rtc_candidate),
                    url: local_candidate.url.clone(),
                }),
            );
        }
        // RFC 6544 section 4.1: the TCP candidates of the same address, the engine's own,
        // for this transport.
        self.gather_tcp_candidates(value);
        Ok(())
    }

    /// The connection's transports: for each, the mid and m= line index of its first section,
    /// the one whose `sdpMid` / `sdpMLineIndex` its candidates carry, the default transport
    /// first. The sections are those of the local description, or of the remote offer before
    /// it is answered. While every section is bundled there is one entry; before any
    /// description, none.
    ///
    /// RFC 9429 section 5.2.1 gives each transport candidates of its own: the application
    /// gathers for every entry, on local addresses no other transport uses, and passes each
    /// candidate to [`add_local_candidate`](Self::add_local_candidate) with that `sdp_mid`.
    pub fn ice_transport_sections(&self) -> Vec<(String, u16)> {
        let desc = self
            .pending_local_description
            .as_ref()
            .or(self.current_local_description.as_ref())
            .or(self.pending_remote_description.as_ref())
            .or(self.current_remote_description.as_ref())
            .and_then(|d| d.parsed.as_ref());
        let Some(desc) = desc else {
            return vec![];
        };
        let transports = &self.pipeline_context.transports;
        let mut seen: Vec<TransportId> = vec![];
        let mut sections: Vec<(TransportId, String, u16)> = vec![];
        for (index, m) in desc.media_descriptions.iter().enumerate() {
            if is_rejected_media(m) {
                continue;
            }
            let Some(mid) = get_mid_value(m) else {
                continue;
            };
            let id = transports.transport_id_for(mid);
            if seen.contains(&id) {
                continue;
            }
            seen.push(id);
            sections.push((id, mid.clone(), u16::try_from(index).unwrap_or(u16::MAX)));
        }
        let default = transports.default_id();
        sections.sort_by_key(|(id, _, _)| *id != default);
        sections
            .into_iter()
            .map(|(_, mid, index)| (mid, index))
            .collect()
    }
}
