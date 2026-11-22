//! RFC 3550 6.6 and W3C webrtc 9.3: an inbound BYE for an SSRC of a remote track mutes the
//! track (`OnMute`); it does not end it.

use super::*;
use crate::media_stream::track::MediaStreamTrack;
use crate::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use crate::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use interceptor::StreamInfo;
use sansio::Protocol;
use shared::TransportContext;

const SSRC: u32 = 1000;

#[derive(Default)]
struct NullChain;

impl Protocol<TaggedPacket, TaggedPacket, ()> for NullChain {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, _: TaggedPacket) -> Result<()> {
        Ok(())
    }
    fn poll_read(&mut self) -> Option<TaggedPacket> {
        None
    }
    fn handle_write(&mut self, _: TaggedPacket) -> Result<()> {
        Ok(())
    }
    fn poll_write(&mut self) -> Option<TaggedPacket> {
        None
    }
    fn handle_event(&mut self, _: ()) -> Result<()> {
        Ok(())
    }
    fn poll_event(&mut self) -> Option<()> {
        None
    }
    fn handle_timeout(&mut self, _: Instant) -> Result<()> {
        Ok(())
    }
    fn poll_timeout(&mut self) -> Option<Instant> {
        None
    }
    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Interceptor for NullChain {
    fn bind_local_stream(&mut self, _: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _: &StreamInfo) {}
}

fn vp8() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: "video/VP8".to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: String::new(),
        rtcp_feedback: vec![],
    }
}

fn coding() -> RTCRtpCodingParameters {
    RTCRtpCodingParameters {
        rid: String::new(),
        ssrc: Some(SSRC),
        rtx: None,
        fec: None,
        ..Default::default()
    }
}

fn transceiver() -> RTCRtpTransceiverInternal {
    let mut transceiver = RTCRtpTransceiverInternal::new(
        RtpCodecKind::Video,
        None,
        RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            streams: vec![],
            send_encodings: vec![],
        },
    );
    let receiver = transceiver.receiver_mut().as_mut().unwrap();
    receiver.set_coding_parameters(vec![coding()]);
    receiver.set_codec_preferences(vec![RTCRtpCodecParameters {
        rtp_codec: vp8(),
        payload_type: 96,
    }]);
    receiver.set_track(MediaStreamTrack::new(
        "stream".to_string(),
        "remote-track".to_string(),
        "label".to_string(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: coding(),
            active: true,
            codec: vp8(),
            max_bitrate: 0,
            max_framerate: None,
            scale_resolution_down_by: None,
            priority: Default::default(),
            network_priority: None,
        }],
    ));
    transceiver
}

fn goodbye(sources: Vec<u32>) -> TaggedRTCMessageInternal {
    TaggedRTCMessageInternal {
        now: Instant::now(),
        transport: TransportContext::default(),
        message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(vec![Box::new(
            Goodbye {
                sources,
                reason: Default::default(),
            },
        )]))),
    }
}

/// Feed `message`; return the track events (as "mute:<id>" / "close:<id>") and the track's
/// state and muted flag after.
fn events_after(message: TaggedRTCMessageInternal) -> (Vec<String>, MediaStreamTrackState, bool) {
    let mut ctx = InterceptorHandlerContext {
        is_dtls_handshake_complete: true,
        ..Default::default()
    };
    let mut transceivers = vec![transceiver()];
    let media_engine = MediaEngine::default();
    let mut chain = NullChain;
    let mut stats = RTCStatsAccumulator::default();
    let mut handler = InterceptorHandler::new(
        &mut ctx,
        &mut transceivers,
        &media_engine,
        &mut chain,
        &mut stats,
    );
    handler.handle_read(message).expect("handle_read");

    let events = std::iter::from_fn(|| handler.poll_event())
        .filter_map(|event| match event.event {
            RTCEventInternal::RTCPeerConnectionEvent(RTCPeerConnectionEvent::OnTrack(
                RTCTrackEvent::OnClose(track_id),
            )) => Some(format!("close:{track_id}")),
            RTCEventInternal::RTCPeerConnectionEvent(RTCPeerConnectionEvent::OnTrack(
                RTCTrackEvent::OnMute(track_id),
            )) => Some(format!("mute:{track_id}")),
            _ => None,
        })
        .collect();
    let track = transceivers[0].receiver().as_ref().unwrap().track();
    (events, track.ready_state(), track.muted())
}

#[test]
fn a_bye_for_the_tracks_ssrc_mutes_it_and_does_not_end_it() {
    let (events, state, muted) = events_after(goodbye(vec![SSRC]));
    assert_eq!(vec!["mute:remote-track".to_string()], events);
    assert_eq!(MediaStreamTrackState::Live, state);
    assert!(muted);
}

#[test]
fn a_bye_for_another_ssrc_changes_nothing() {
    let (events, state, muted) = events_after(goodbye(vec![4242]));
    assert!(events.is_empty());
    assert_eq!(MediaStreamTrackState::Live, state);
    assert!(!muted);
}
