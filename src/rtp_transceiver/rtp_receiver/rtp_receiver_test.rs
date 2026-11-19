//! Ported from the async `webrtc` crate's `rtp_receiver_test.rs` to the sans-IO API.
//!
//! The old tests connected two peers over a virtual network and handled the remote track in an
//! `on_track` callback; here the pair is driven in memory by
//! [`crate::peer_connection::test_util::Pair`] and the remote track is announced by
//! [`RTCTrackEvent::OnOpen`].

use super::*;
use crate::media_stream::MediaStreamTrack;
use crate::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use crate::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent, RTCTrackEventInit};
use crate::peer_connection::test_util::{Pair, new_pair_with, send_until_seen, signal_pair};
use crate::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RTCRtpHeaderExtensionCapability,
};

const EXTENSIONS: [&str; 3] = [
    "urn:ietf:params:rtp-hdrext:sdes:mid",
    "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
    "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
];

fn vp8() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: "".to_owned(),
        rtcp_feedback: vec![],
    }
}

fn media_engine() -> MediaEngine {
    let mut me = MediaEngine::default();
    me.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: vp8(),
            payload_type: 96,
        },
        RtpCodecKind::Video,
    )
    .expect("vp8");
    for uri in EXTENSIONS {
        me.register_header_extension(
            RTCRtpHeaderExtensionCapability {
                uri: uri.to_owned(),
            },
            RtpCodecKind::Video,
            None,
        )
        .expect("extension");
    }
    me
}

fn track_open(pair: &Pair) -> Option<RTCTrackEventInit> {
    pair.answerer_seen.events.iter().find_map(|e| match e {
        RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => Some(init.clone()),
        _ => None,
    })
}

/// Replaced: the old test overrode the receiver's parameters with `set_rtp_parameters` (an
/// Opus codec and three header extensions) and checked that the remote track then reported
/// them. The sans-IO receiver has no setter: its parameters are what negotiation agreed. This
/// checks that the receiver reports exactly that — the negotiated codec, with the payload type
/// the media arrives on, and the three header extensions both sides registered — and that the
/// remote track's codec for the arriving SSRC is the same codec.
#[test]
fn test_set_rtp_parameters() -> Result<()> {
    let (mut sender, mut receiver) = new_pair_with(media_engine(), media_engine())?;

    let ssrc = 0x5555_5555;
    let sender_id = sender.add_track(MediaStreamTrack::new(
        "webrtc-rs".to_owned(),
        "video".to_owned(),
        "video".to_owned(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: vp8(),
            ..Default::default()
        }],
    ))?;

    signal_pair(&mut sender, &mut receiver)?;
    let mut pair = Pair::new(sender, receiver);
    pair.connect()?;

    let mut sequence_number = 0;
    let packet = send_until_seen(&mut pair, sender_id, ssrc, 96, 0xAA, &mut sequence_number);
    let open = track_open(&pair).expect("the first packet opens the remote track");
    assert_eq!(open.ssrc, ssrc);

    let mut rtp_receiver = pair
        .answerer
        .rtp_receiver(open.receiver_id)
        .expect("receiver");

    let incoming_track_codec = rtp_receiver
        .track()
        .codec(ssrc)
        .expect("the arriving SSRC has a codec")
        .clone();

    let parameters = rtp_receiver.get_parameters().rtp_parameters.clone();
    let mut uris: Vec<&str> = parameters
        .header_extensions
        .iter()
        .map(|h| h.uri.as_str())
        .collect();
    uris.sort_unstable();
    let mut expected = EXTENSIONS.to_vec();
    expected.sort_unstable();
    assert_eq!(uris, expected);

    let negotiated = parameters
        .codecs
        .iter()
        .find(|c| c.payload_type == packet.header.payload_type)
        .expect("the payload type the media arrives on is negotiated");
    assert_eq!(
        negotiated.rtp_codec.mime_type,
        incoming_track_codec.mime_type
    );
    assert_eq!(
        negotiated.rtp_codec.clock_rate,
        incoming_track_codec.clock_rate
    );
    assert_eq!(negotiated.rtp_codec.channels, incoming_track_codec.channels);
    assert_eq!(
        negotiated.rtp_codec.sdp_fmtp_line,
        incoming_track_codec.sdp_fmtp_line
    );
    assert_eq!(incoming_track_codec.mime_type, MIME_TYPE_VP8);

    pair.close()
}

// Not ported: test_rtp_receiver_set_read_deadline. It asserted that `TrackRemote::read_rtp`
// and `RTCRtpReceiver::read_rtcp` time out under `tokio::time::timeout` once no more media
// arrives. The sans-IO receiver has no reader to block on: inbound RTP and RTCP are surfaced
// through `RTCPeerConnection::poll_read`, which never waits, so there is no read deadline to
// test.
