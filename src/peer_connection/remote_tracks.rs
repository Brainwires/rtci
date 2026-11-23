//! Remote tracks by description, not by media (W3C webrtc-pc 4.4.1.6 "set the
//! RTCSessionDescription", 5.1.1 "process remote tracks", 5.4 "stop the RTCRtpTransceiver",
//! 9.3): once a description is applied, the transceivers' `[[Receptive]]` and
//! `[[FiredDirection]]` slots are updated, the receivers' associated remote streams are set
//! from the `a=msid` lines, and the application is told, in the spec's order, which tracks
//! were muted, which streams they left and joined, and which tracks it now receives
//! (`track`); a track whose transceiver stopped is ended.

use super::RTCPeerConnection;
use crate::media_stream::MediaStreamId;
use crate::media_stream::track_state::MediaStreamTrackState;
use crate::peer_connection::event::{
    RTCPeerConnectionEvent, RTCRemoteStreamsChange, RTCRemoteTrackEventInit, RTCTrackEvent,
};
use crate::peer_connection::sdp::{
    RTCSdpType, get_mid_value, get_peer_direction, is_rejected_media, media_msid,
};
use crate::peer_connection::state::signaling_state::RTCSignalingState;
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::internal::RTCRtpTransceiverInternal;
use crate::rtp_transceiver::{RTCRtpReceiverId, RTCRtpTransceiverId};
use sdp::description::session::SessionDescription;
use std::collections::HashSet;

/// What applying a description tells the application, in the order W3C 4.4.1.6 fires it:
/// mutes, then stream removals and additions, then track events.
#[derive(Default)]
struct RemoteTrackChanges {
    mute: Vec<RTCRtpTransceiverId>,
    streams: Vec<(RTCRtpTransceiverId, Vec<MediaStreamId>, Vec<MediaStreamId>)>,
    track_events: Vec<RTCRtpTransceiverId>,
}

fn receives(direction: RTCRtpTransceiverDirection) -> bool {
    matches!(
        direction,
        RTCRtpTransceiverDirection::Sendrecv | RTCRtpTransceiverDirection::Recvonly
    )
}

fn does_not_receive(direction: RTCRtpTransceiverDirection) -> bool {
    matches!(
        direction,
        RTCRtpTransceiverDirection::Sendonly | RTCRtpTransceiverDirection::Inactive
    )
}

/// The media sections of `parsed` that are associated with a transceiver: (transceiver,
/// section index).
fn associated_sections(
    transceivers: &[RTCRtpTransceiverInternal],
    parsed: &SessionDescription,
) -> Vec<(RTCRtpTransceiverId, usize)> {
    parsed
        .media_descriptions
        .iter()
        .enumerate()
        .filter_map(|(index, media)| {
            let mid = get_mid_value(media)?;
            transceivers
                .iter()
                .position(|t| t.mid().as_deref() == Some(mid.as_str()))
                .map(|id| (id, index))
        })
        .collect()
}

impl RTCPeerConnection {
    /// The id of the session's "default" remote MediaStream, for a media section with no
    /// `a=msid` line (RFC 9429 section 5.8: "a random msid-id value is generated for a
    /// 'default' MediaStream for the session, if not already present").
    fn default_remote_stream_id(&mut self) -> MediaStreamId {
        self.default_remote_stream_id
            .get_or_insert_with(|| shared::util::math_rand_alpha(16))
            .clone()
    }

    /// W3C 4.4.1.6 for a local description that was just applied: `[[Receptive]]` follows
    /// the direction each section states; an answer that stops the transceiver receiving
    /// removes and mutes its remote track.
    pub(super) fn after_local_description(&mut self, sdp_type: RTCSdpType) {
        let Some(parsed) = self
            .local_description()
            .and_then(|description| description.parsed)
        else {
            self.after_description(sdp_type);
            return;
        };
        let mut changes = RemoteTrackChanges::default();
        for (id, index) in associated_sections(&self.rtp_transceivers, &parsed) {
            let transceiver = &mut self.rtp_transceivers[id];
            if transceiver.is_stopped() {
                continue;
            }
            let direction = get_peer_direction(&parsed.media_descriptions[index]);
            transceiver.set_receptive(receives(direction));
            if !matches!(sdp_type, RTCSdpType::Answer | RTCSdpType::Pranswer) {
                // What a local offer prepares the receiver for is set by
                // `prepare_offered_receive` (RFC 3264 section 5.1).
                continue;
            }
            if does_not_receive(direction) && transceiver.fired_direction().is_some_and(receives) {
                let (removed, added) = transceiver
                    .receiver_mut()
                    .as_mut()
                    .map(|receiver| receiver.set_remote_streams(vec![]))
                    .unwrap_or_default();
                changes.streams.push((id, removed, added));
                changes.mute.push(id);
            }
            transceiver.set_fired_direction(Some(direction));
        }
        self.announce_remote_track_changes(changes);
        self.after_description(sdp_type);
    }

    /// W3C 4.4.1.6 for a remote description that was just applied (and for a rollback,
    /// given the signaling state before it): "process remote tracks" for each section.
    pub(super) fn after_remote_description(
        &mut self,
        sdp_type: RTCSdpType,
        prior_state: RTCSignalingState,
        msid_sections: HashSet<String>,
        renewed: Vec<RTCRtpTransceiverId>,
    ) {
        let mut ended = Vec::new();
        let mut changes = RemoteTrackChanges::default();
        // RFC 8830 section 3 (`with_msid_appdata_change_renews_track`): a new msid-appdata is
        // a new track: the receiver's track ends, and a new one takes its place, announced
        // with a track event as a receiver's first track is.
        for id in renewed {
            let Some(receiver) = self.rtp_transceivers[id].receiver_mut() else {
                continue;
            };
            receiver.end_track();
            self.announce_receiver_track_ended(id);
            if let Some(receiver) = self.rtp_transceivers[id].receiver_mut() {
                receiver.renew_track();
            }
            self.rtp_transceivers[id].set_fired_direction(None);
        }
        if sdp_type == RTCSdpType::Rollback {
            // Rolling back a remote offer: every transceiver goes back to the streams of the
            // last stable state and the direction it negotiated then.
            if prior_state == RTCSignalingState::HaveRemoteOffer {
                for id in 0..self.rtp_transceivers.len() {
                    let transceiver = &self.rtp_transceivers[id];
                    let msids = transceiver
                        .receiver()
                        .as_ref()
                        .map(|receiver| receiver.last_stable_remote_streams().to_vec())
                        .unwrap_or_default();
                    let direction = transceiver.current_direction();
                    self.process_remote_tracks(id, direction, msids, &mut changes);
                }
            }
        } else if let Some(parsed) = self
            .remote_description()
            .and_then(|description| description.parsed.clone())
        {
            for (id, index) in associated_sections(&self.rtp_transceivers, &parsed) {
                let media = &parsed.media_descriptions[index];
                let direction = if is_rejected_media(media) {
                    RTCRtpTransceiverDirection::Inactive
                } else {
                    get_peer_direction(media).reverse()
                };
                let msids = if receives(direction) {
                    match media_msid(media) {
                        Some((stream_ids, _)) => stream_ids,
                        None => vec![self.default_remote_stream_id()],
                    }
                } else {
                    vec![]
                };
                // RFC 8830 section 3: "When a session description is updated to no longer list
                // any 'msid' attribute on a specific media description, the recipient can
                // signal to its application that the corresponding MediaStreamTrack has
                // ended", under `with_msid_removal_ends_track(true)`. By default the W3C
                // webrtc-pc model governs: the track stays, in the session's default stream,
                // and is muted only when the section stops sending (RFC 8830 section 3 too: a
                // direction change "will not end the MediaStreamTrack").
                if receives(direction)
                    && media_msid(media).is_none()
                    && get_mid_value(media).is_some_and(|mid| msid_sections.contains(mid))
                {
                    ended.push(id);
                }
                self.process_remote_tracks(id, direction, msids, &mut changes);
            }
        }
        self.announce_remote_track_changes(changes);
        for id in ended {
            if let Some(receiver) = self.rtp_transceivers[id].receiver_mut() {
                receiver.end_track();
            }
            self.announce_receiver_track_ended(id);
        }
        self.after_description(sdp_type);
    }

    /// The transceivers whose receiver a remote description `parsed` gives a new
    /// msid-appdata (one that names a track, other than the one the receiver's track was
    /// last described with), when a new appdata renews the track
    /// (`with_msid_appdata_change_renews_track`); empty otherwise.
    pub(super) fn sections_with_new_msid_appdata(
        &self,
        parsed: Option<&SessionDescription>,
    ) -> Vec<RTCRtpTransceiverId> {
        if !self.setting_engine.msid_appdata_change_renews_track {
            return vec![];
        }
        let Some(parsed) = parsed else {
            return vec![];
        };
        associated_sections(&self.rtp_transceivers, parsed)
            .into_iter()
            .filter(|&(id, index)| {
                let media = &parsed.media_descriptions[index];
                let Some(receiver) = self.rtp_transceivers[id].receiver().as_ref() else {
                    return false;
                };
                let previous = receiver.remote_track_id();
                !is_rejected_media(media)
                    && !previous.is_empty()
                    && media_msid(media)
                        .is_some_and(|(_, appdata)| !appdata.is_empty() && appdata != previous)
            })
            .map(|(id, _)| id)
            .collect()
    }

    /// The mids of the remote description's media sections that list an `a=msid`, when the
    /// removal of every such line ends the track (`with_msid_removal_ends_track`); empty
    /// otherwise.
    pub(super) fn remote_sections_with_msid(&self) -> HashSet<String> {
        if !self.setting_engine.msid_removal_ends_track {
            return HashSet::new();
        }
        self.remote_description()
            .and_then(|description| description.parsed.as_ref())
            .map(|parsed| {
                parsed
                    .media_descriptions
                    .iter()
                    .filter(|media| media_msid(media).is_some())
                    .filter_map(|media| get_mid_value(media).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// W3C 5.1.1 "process remote tracks".
    fn process_remote_tracks(
        &mut self,
        id: RTCRtpTransceiverId,
        direction: RTCRtpTransceiverDirection,
        msids: Vec<MediaStreamId>,
        changes: &mut RemoteTrackChanges,
    ) {
        let transceiver = &mut self.rtp_transceivers[id];
        let Some(receiver) = transceiver.receiver_mut().as_mut() else {
            return;
        };
        let (removed, added) = receiver.set_remote_streams(msids);
        let streams_added = !added.is_empty();
        if !removed.is_empty() || streams_added {
            changes.streams.push((id, removed, added));
        }
        let fired = transceiver.fired_direction();
        if receives(direction) && (!fired.is_some_and(receives) || streams_added) {
            changes.track_events.push(id);
        }
        if does_not_receive(direction) {
            transceiver.set_receptive(false);
            if fired.is_some_and(receives) {
                changes.mute.push(id);
            }
        }
        transceiver.set_fired_direction(match direction {
            RTCRtpTransceiverDirection::Unspecified => None,
            direction => Some(direction),
        });
    }

    /// Queues the events of `changes` in the spec's order. A track that is ended, or already
    /// muted, is not muted again.
    fn announce_remote_track_changes(&mut self, changes: RemoteTrackChanges) {
        let track_id =
            |pc: &RTCPeerConnection, id: RTCRtpTransceiverId| -> Option<(String, bool, bool)> {
                let receiver = pc.rtp_transceivers.get(id)?.receiver().as_ref()?;
                let track = receiver.track();
                Some((
                    track.track_id().clone(),
                    track.muted(),
                    track.ready_state() == MediaStreamTrackState::Ended,
                ))
            };
        for id in changes.mute {
            let Some((track, muted, ended)) = track_id(self, id) else {
                continue;
            };
            if muted || ended {
                continue;
            }
            if let Some(receiver) = self.rtp_transceivers[id].receiver_mut() {
                receiver.track_mut().set_muted(true);
            }
            self.pipeline_context
                .event_outs
                .push_back(RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnMute(
                    track,
                )));
        }
        for (id, removed, added) in changes.streams {
            let Some((track_id, ..)) = track_id(self, id) else {
                continue;
            };
            self.pipeline_context
                .event_outs
                .push_back(RTCPeerConnectionEvent::OnTrack(
                    RTCTrackEvent::OnStreamsChanged(RTCRemoteStreamsChange {
                        track_id,
                        removed,
                        added,
                    }),
                ));
        }
        for id in changes.track_events {
            let Some((track_id, ..)) = track_id(self, id) else {
                continue;
            };
            let stream_ids = self.rtp_transceivers[id]
                .receiver()
                .as_ref()
                .map(|receiver| receiver.remote_streams().to_vec())
                .unwrap_or_default();
            self.pipeline_context
                .event_outs
                .push_back(RTCPeerConnectionEvent::OnTrack(
                    RTCTrackEvent::OnRemoteTrack(RTCRemoteTrackEventInit {
                        receiver_id: RTCRtpReceiverId(id),
                        transceiver_id: id,
                        track_id,
                        stream_ids,
                    }),
                ));
        }
    }

    /// What follows any applied description: the receiver track of a transceiver the
    /// description stopped is ended (W3C 5.4 "stop sending and receiving"; a stopped
    /// transceiver has no associated remote streams), and in a stable state the remote
    /// streams are what a later rollback returns to.
    fn after_description(&mut self, sdp_type: RTCSdpType) {
        let stable = self.signaling_state == RTCSignalingState::Stable;
        for id in 0..self.rtp_transceivers.len() {
            let transceiver = &mut self.rtp_transceivers[id];
            let stopping = transceiver.stopped();
            let is_stopped = transceiver.is_stopped();
            let Some(receiver) = transceiver.receiver_mut().as_mut() else {
                continue;
            };
            if is_stopped {
                receiver.clear_remote_streams();
            }
            if stable {
                receiver.save_stable_remote_streams();
            }
            if stopping {
                receiver.end_track();
                self.announce_receiver_track_ended(id);
            }
        }
        // Last: what the description leaves for queued tasks, in the order it caused them.
        // W3C webrtc-pc "set a session description" fires, in this order, signalingstatechange,
        // `error` at each channel of errorList (`assign_data_channel_ids`), the mutes, the
        // stream changes and the track events: all queued by now. An answer that closes the
        // SCTP association (RFC 8841 sections 10.3 and 10.4) closes the underlying data
        // transport of its channels, for which "the user agent MUST queue a task" each
        // ("Announcing a data channel as closed": `error` when the transport closed with an
        // error, then `close`), and the SCTP transport's own state follows. They are queued
        // here, channel by channel in the order the channels were created, then the SCTP
        // transport's `statechange`; the transports a description left unused close last.
        if matches!(sdp_type, RTCSdpType::Answer | RTCSdpType::Pranswer) {
            self.settle_description_events();
        }
        self.announce_sctp_closed_by_answer();
        if stable && sdp_type == RTCSdpType::Answer {
            self.close_unused_transports();
        }
    }

    /// A transceiver left the set of transceivers (a rollback of the offer that created it,
    /// or the answer that rejected its stopped section): its receiver's track ends, if it had
    /// not already.
    pub(super) fn end_removed_transceivers_track(
        &mut self,
        removed: &mut RTCRtpTransceiverInternal,
    ) {
        if let Some(receiver) = removed.receiver_mut() {
            receiver.end_track();
            if !receiver.take_unannounced_end() {
                return;
            }
            let track_id = receiver.track().track_id().clone();
            self.pipeline_context
                .event_outs
                .push_back(RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnClose(
                    track_id,
                )));
        }
    }
}
