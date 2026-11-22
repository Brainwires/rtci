//! RFC 4588 5: an RTX packet reaches the interceptor chain as the original packet it carries, so
//! the NACK generator, the receiver report and a jitter buffer see the repair on the primary
//! stream.

use super::*;
use crate::media_stream::track::MediaStreamTrack;
use crate::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use crate::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use bytes::Bytes;
use interceptor::StreamInfo;
use sansio::Protocol;
use shared::TransportContext;

const PRIMARY_SSRC: u32 = 1000;
const RTX_SSRC: u32 = 2000;
const PRIMARY_PT: u8 = 96;
const RTX_PT: u8 = 97;

/// Records what the chain is handed on the read leg.
#[derive(Default)]
struct RecordingChain {
    reads: VecDeque<TaggedPacket>,
    writes: VecDeque<TaggedPacket>,
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for RecordingChain {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<()> {
        self.reads.push_back(msg);
        Ok(())
    }
    fn poll_read(&mut self) -> Option<TaggedPacket> {
        None
    }
    fn handle_write(&mut self, msg: TaggedPacket) -> Result<()> {
        self.writes.push_back(msg);
        Ok(())
    }
    fn poll_write(&mut self) -> Option<TaggedPacket> {
        self.writes.pop_front()
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

impl Interceptor for RecordingChain {
    fn bind_local_stream(&mut self, _: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _: &StreamInfo) {}
}

fn coding() -> RTCRtpCodingParameters {
    RTCRtpCodingParameters {
        rid: String::new(),
        ssrc: Some(PRIMARY_SSRC),
        rtx: Some(RTCRtpRtxParameters { ssrc: RTX_SSRC }),
        fec: None,
        ..Default::default()
    }
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

/// A receive transceiver whose primary stream is paired with an RTX stream (`a=ssrc-group:FID`),
/// already established: its track has a codec, so no bind happens on the first packet.
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
    receiver.set_codec_preferences(vec![
        RTCRtpCodecParameters {
            rtp_codec: vp8(),
            payload_type: PRIMARY_PT,
        },
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: "video/rtx".to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: format!("apt={PRIMARY_PT}"),
                rtcp_feedback: vec![],
            },
            payload_type: RTX_PT,
        },
    ]);
    receiver.set_track(MediaStreamTrack::new(
        "stream".to_string(),
        "track".to_string(),
        "label".to_string(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: coding(),
            active: true,
            codec: vp8(),
            max_bitrate: 0,
            max_framerate: None,
            scale_resolution_down_by: None,
        }],
    ));
    transceiver
}

fn rtx_packet(payload: &'static [u8]) -> TaggedRTCMessageInternal {
    TaggedRTCMessageInternal {
        now: Instant::now(),
        transport: TransportContext::default(),
        message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(rtp::Packet {
            header: rtp::Header {
                version: 2,
                marker: true,
                payload_type: RTX_PT,
                sequence_number: 9,
                timestamp: 12_345,
                ssrc: RTX_SSRC,
                ..Default::default()
            },
            payload: Bytes::from_static(payload),
        }))),
    }
}

/// Hand `message` to an interceptor handler past the handshake; return what the chain received.
fn chain_sees(message: TaggedRTCMessageInternal) -> Vec<rtp::Packet> {
    let mut ctx = InterceptorHandlerContext {
        is_dtls_handshake_complete: true,
        ..Default::default()
    };
    let mut transceivers = vec![transceiver()];
    let media_engine = MediaEngine::default();
    let mut chain = RecordingChain::default();
    let mut stats = RTCStatsAccumulator::default();
    InterceptorHandler::new(
        &mut ctx,
        &mut transceivers,
        &media_engine,
        &mut chain,
        &mut stats,
    )
    .handle_read(message)
    .expect("handle_read");

    chain
        .reads
        .into_iter()
        .map(|tagged| match tagged.message.packet {
            Packet::Rtp(packet) => packet,
            _ => panic!("expected an RTP packet"),
        })
        .collect()
}

#[test]
fn the_chain_sees_the_original_packet_an_rtx_packet_carries() {
    // OSN 42, then the original payload.
    let seen = chain_sees(rtx_packet(&[0x00, 0x2A, 0xDE, 0xAD]));

    assert_eq!(1, seen.len());
    let packet = &seen[0];
    assert_eq!(PRIMARY_SSRC, packet.header.ssrc);
    assert_eq!(PRIMARY_PT, packet.header.payload_type);
    assert_eq!(42, packet.header.sequence_number);
    assert_eq!(12_345, packet.header.timestamp);
    assert!(packet.header.marker);
    assert_eq!(&[0xDE, 0xAD], &packet.payload[..]);
}

/// A padding-only probe has no OSN; it reaches the chain as it came, so the TWCC recorder still
/// counts its arrival.
#[test]
fn a_padding_only_rtx_probe_reaches_the_chain_unchanged() {
    let seen = chain_sees(rtx_packet(&[0x00]));

    assert_eq!(1, seen.len());
    assert_eq!(RTX_SSRC, seen[0].header.ssrc);
    assert_eq!(RTX_PT, seen[0].header.payload_type);
    assert_eq!(9, seen[0].header.sequence_number);
}

/// Hand `messages` to an interceptor handler past the handshake, the primary stream having
/// its statistics object; return that object.
fn stats_after(
    messages: Vec<TaggedRTCMessageInternal>,
) -> crate::statistics::accumulator::InboundRtpStreamAccumulator {
    let mut ctx = InterceptorHandlerContext {
        is_dtls_handshake_complete: true,
        ..Default::default()
    };
    let mut transceivers = vec![transceiver()];
    let media_engine = MediaEngine::default();
    let mut chain = RecordingChain::default();
    let mut stats = RTCStatsAccumulator::default();
    stats.get_or_create_inbound_rtp_streams(
        PRIMARY_SSRC,
        RtpCodecKind::Video,
        "track",
        "0",
        Some(RTX_SSRC),
        None,
        0,
    );
    for message in messages {
        InterceptorHandler::new(
            &mut ctx,
            &mut transceivers,
            &media_engine,
            &mut chain,
            &mut stats,
        )
        .handle_read(message)
        .expect("handle_read");
    }
    stats
        .inbound_rtp_streams
        .remove(&PRIMARY_SSRC)
        .expect("the stream's statistics")
}

/// webrtc-stats 8.5 `retransmittedPacketsReceived`: retransmissions. A padding-only RTX packet
/// (a bandwidth probe, RFC 4588 section 4) repeats no packet; it was counted as one, before
/// de-encapsulation found there was nothing in it.
#[test]
fn a_padding_only_rtx_probe_is_not_a_retransmission() {
    let stream = stats_after(vec![rtx_packet(&[]), rtx_packet(&[0x00])]);
    assert_eq!(0, stream.retransmitted_packets_received);
    assert_eq!(0, stream.retransmitted_bytes_received);
}

/// A retransmission is counted with the payload it repeats: the two bytes of the original
/// sequence number in front of it (RFC 4588 section 4) are not payload of the stream.
#[test]
fn a_retransmission_is_counted_with_the_payload_it_repeats() {
    let stream = stats_after(vec![rtx_packet(&[0x00, 0x2A, 0xDE, 0xAD, 0xBE])]);
    assert_eq!(1, stream.retransmitted_packets_received);
    assert_eq!(3, stream.retransmitted_bytes_received);
}
