//! RFC 8083 section 4.5 at the peer connection: a flow the RTP circuit breaker ceased or
//! restarted is announced for the sender and encoding it belongs to, and a ceased encoding
//! takes no share of the congestion controller's target.

use super::*;
use crate::peer_connection::RTCPeerConnectionBuilder;
use crate::rtp_transceiver::rtp_sender::{
    RTCRtpCodingParameters, RTCRtpEncodingParameters, RTCRtpRtxParameters, RtpCodecKind,
};
use crate::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use interceptor::{AttributedPacket, CircuitBreakerNotice, CircuitBreakerReason, StreamInfo};
use sansio::Protocol;
use shared::TransportContext;
use std::time::Duration;

/// Hands out on `poll_read` what was queued: the chain application-ward of the breaker.
#[derive(Default)]
struct ReadChain {
    reads: VecDeque<TaggedPacket>,
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for ReadChain {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, _: TaggedPacket) -> Result<()> {
        Ok(())
    }
    fn poll_read(&mut self) -> Option<TaggedPacket> {
        self.reads.pop_front()
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

impl Interceptor for ReadChain {
    fn bind_local_stream(&mut self, _: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _: &StreamInfo) {}
}

/// What `OnCircuitBreaker` carried.
#[derive(Debug, PartialEq)]
struct Told {
    sender: RTCRtpSenderId,
    rid: Option<String>,
    ssrc: u32,
    ceased: Option<CircuitBreakerReason>,
    restart_after: Duration,
}

/// Hands `notice` to the connection's interceptor handler as the breaker's chain would, and
/// returns the events the application is given for it.
fn announce(
    pc: &mut crate::peer_connection::RTCPeerConnection,
    notice: CircuitBreakerNotice,
) -> Vec<Told> {
    hand(
        pc,
        AttributedPacket::new(Packet::Rtcp(vec![]))
            .with(Attribute::Custom(std::sync::Arc::new(notice))),
    )
}

/// Hands `message` to the connection's interceptor handler as its chain would on the read
/// leg, and returns the `OnCircuitBreaker` events the application is given for it.
fn hand(
    pc: &mut crate::peer_connection::RTCPeerConnection,
    message: AttributedPacket,
) -> Vec<Told> {
    let mut chain = ReadChain::default();
    chain.reads.push_back(TaggedPacket {
        now: Instant::now(),
        transport: TransportContext::default(),
        message,
    });
    let media_engine = MediaEngine::default();
    let context = &mut pc.pipeline_context;
    context
        .interceptor_handler_context
        .is_dtls_handshake_complete = true;
    {
        let mut handler = InterceptorHandler::new(
            &mut context.interceptor_handler_context,
            &mut pc.rtp_transceivers,
            &media_engine,
            &mut chain,
            &mut context.stats,
            None,
        );
        while handler.poll_read().is_some() {}
    }
    context
        .interceptor_handler_context
        .event_outs
        .drain(..)
        .filter_map(|tagged| match tagged.event {
            RTCEventInternal::RTCPeerConnectionEvent(
                RTCPeerConnectionEvent::OnCircuitBreaker {
                    sender,
                    rid,
                    ssrc,
                    ceased,
                    restart_after,
                },
            ) => Some(Told {
                sender,
                rid,
                ssrc,
                ceased,
                restart_after,
            }),
            _ => None,
        })
        .collect()
}

const HIGH: u32 = 0x1001;
const LOW: u32 = 0x1002;
const HIGH_RTX: u32 = 0x2001;
const LOW_RTX: u32 = 0x2002;
const VOICE: u32 = 0x3001;

fn encoding(rid: &str, ssrc: u32, rtx: Option<u32>) -> RTCRtpEncodingParameters {
    RTCRtpEncodingParameters {
        active: true,
        rtp_coding_parameters: RTCRtpCodingParameters {
            rid: rid.to_owned(),
            ssrc: Some(ssrc),
            rtx: rtx.map(|ssrc| RTCRtpRtxParameters { ssrc }),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// A connection that sends a simulcast video (rids `h` and `l`, each with an RTX flow) and a
/// voice stream, with a target of 900 kbit/s to divide.
fn connection() -> (
    crate::peer_connection::RTCPeerConnection,
    RTCRtpSenderId,
    RTCRtpSenderId,
) {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs().unwrap();
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())
        .unwrap();
    let mut add = |kind: RtpCodecKind, send_encodings: Vec<RTCRtpEncodingParameters>| {
        RTCRtpSenderId::from(
            pc.add_transceiver_from_kind(
                kind,
                Some(RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Sendonly,
                    streams: vec![],
                    send_encodings,
                }),
            )
            .unwrap(),
        )
    };
    let video = add(
        RtpCodecKind::Video,
        vec![
            encoding("h", HIGH, Some(HIGH_RTX)),
            encoding("l", LOW, Some(LOW_RTX)),
        ],
    );
    let voice = add(RtpCodecKind::Audio, vec![encoding("", VOICE, None)]);
    pc.pipeline_context
        .interceptor_handler_context
        .transport_targets
        .insert(0, 900_000.0);
    pc.reallocate_target_bitrate();
    (pc, video, voice)
}

fn shares(
    pc: &mut crate::peer_connection::RTCPeerConnection,
    id: RTCRtpSenderId,
) -> Vec<(u32, f64)> {
    pc.rtp_sender(id).unwrap().target_bitrates().to_vec()
}

fn notice(
    ssrc: u32,
    ceased: Option<CircuitBreakerReason>,
    restart_after: Duration,
) -> CircuitBreakerNotice {
    CircuitBreakerNotice {
        ssrc,
        ceased,
        restart_after,
    }
}

/// `OnCircuitBreaker` names the sender, the RID of the encoding and the flow, whether the
/// flow is the encoding's media SSRC or its RTX SSRC; an encoding without a RID has none; a
/// restart is told with `ceased: None`; a flow no sender sends is not announced.
#[test]
fn a_ceased_flow_is_announced_for_its_sender_and_the_rid_of_its_encoding() {
    let (mut pc, video, voice) = connection();
    let hold = Duration::from_millis(125);

    assert_eq!(
        vec![Told {
            sender: video,
            rid: Some("l".to_owned()),
            ssrc: LOW_RTX,
            ceased: Some(CircuitBreakerReason::Congestion),
            restart_after: Duration::from_secs(3),
        }],
        announce(
            &mut pc,
            notice(
                LOW_RTX,
                Some(CircuitBreakerReason::Congestion),
                Duration::from_secs(3)
            )
        )
    );
    assert_eq!(
        vec![Told {
            sender: video,
            rid: Some("h".to_owned()),
            ssrc: HIGH,
            ceased: Some(CircuitBreakerReason::MediaTimeout),
            restart_after: hold,
        }],
        announce(
            &mut pc,
            notice(HIGH, Some(CircuitBreakerReason::MediaTimeout), hold)
        )
    );
    assert_eq!(
        vec![Told {
            sender: voice,
            rid: None,
            ssrc: VOICE,
            ceased: Some(CircuitBreakerReason::MediaTimeout),
            restart_after: hold,
        }],
        announce(
            &mut pc,
            notice(VOICE, Some(CircuitBreakerReason::MediaTimeout), hold)
        )
    );
    assert_eq!(
        vec![Told {
            sender: voice,
            rid: None,
            ssrc: VOICE,
            ceased: None,
            restart_after: Duration::ZERO,
        }],
        announce(&mut pc, notice(VOICE, None, Duration::ZERO))
    );
    assert!(
        announce(
            &mut pc,
            notice(0x7777, Some(CircuitBreakerReason::RtcpTimeout), hold)
        )
        .is_empty()
    );
}

/// A ceased encoding sends nothing, so it takes no share of the target: what it had goes to
/// the encodings that still send, and it has its share again when it is restarted. A ceased
/// RTX flow leaves its encoding's share alone (the media still leaves).
#[test]
fn a_ceased_encoding_takes_no_share_of_the_target_until_it_is_restarted() {
    let (mut pc, video, voice) = connection();
    let hold = Duration::from_millis(125);
    let timeout = Some(CircuitBreakerReason::MediaTimeout);
    assert_eq!(
        vec![(HIGH, 300_000.0), (LOW, 300_000.0)],
        shares(&mut pc, video)
    );
    assert_eq!(vec![(VOICE, 300_000.0)], shares(&mut pc, voice));

    announce(&mut pc, notice(LOW_RTX, timeout, hold));
    assert_eq!(
        vec![(HIGH, 300_000.0), (LOW, 300_000.0)],
        shares(&mut pc, video),
        "the RTX flow is not the encoding"
    );

    announce(&mut pc, notice(LOW, timeout, hold));
    assert_eq!(vec![(HIGH, 450_000.0)], shares(&mut pc, video));
    assert_eq!(vec![(VOICE, 450_000.0)], shares(&mut pc, voice));

    announce(&mut pc, notice(VOICE, timeout, hold));
    assert_eq!(vec![(HIGH, 900_000.0)], shares(&mut pc, video));
    assert!(shares(&mut pc, voice).is_empty());

    // A later target is divided the same way.
    pc.pipeline_context
        .interceptor_handler_context
        .transport_targets
        .insert(0, 600_000.0);
    pc.reallocate_target_bitrate();
    assert_eq!(vec![(HIGH, 600_000.0)], shares(&mut pc, video));

    announce(&mut pc, notice(LOW, None, Duration::ZERO));
    assert_eq!(
        vec![(HIGH, 300_000.0), (LOW, 300_000.0)],
        shares(&mut pc, video)
    );
    announce(&mut pc, notice(VOICE, None, Duration::ZERO));
    assert_eq!(vec![(VOICE, 200_000.0)], shares(&mut pc, voice));
}

/// While the pacer has the source paused the streams' target is zero and the congestion
/// controller's estimate rides along (`PacerPause`): `availableOutgoingBitrate` stays the
/// estimate. A flow that ceases or restarts during the pause has the (zero) target divided
/// again, and the estimate is still what the congestion controller said: dividing is not a
/// new estimate.
#[test]
fn a_flow_ceasing_while_the_source_is_paused_leaves_the_estimate_alone() {
    let (mut pc, _video, _voice) = connection();
    let estimate = |pc: &crate::peer_connection::RTCPeerConnection| {
        pc.pipeline_context
            .stats
            .outgoing_estimates
            .get(&0)
            .copied()
    };
    // The pacer's pause as the chain hands it over: a target of zero, the estimate with it.
    hand(
        &mut pc,
        AttributedPacket::new(Packet::Rtcp(vec![]))
            .with(Attribute::TargetBitrateChanged {
                bits_per_second: 0.0,
            })
            .with(Attribute::Custom(std::sync::Arc::new(
                interceptor::PacerPause {
                    target_bits_per_second: 250_000.0,
                },
            ))),
    );
    assert_eq!(
        Some(&0.0),
        pc.pipeline_context
            .interceptor_handler_context
            .transport_targets
            .get(&0),
        "the streams are paused"
    );
    assert_eq!(Some(250_000.0), estimate(&pc));

    let told = announce(
        &mut pc,
        notice(
            VOICE,
            Some(CircuitBreakerReason::MediaTimeout),
            Duration::from_millis(125),
        ),
    );
    assert_eq!(1, told.len());
    assert_eq!(Some(250_000.0), estimate(&pc), "a flow ceased in the pause");

    let told = announce(&mut pc, notice(VOICE, None, Duration::ZERO));
    assert_eq!(1, told.len());
    assert_eq!(
        Some(250_000.0),
        estimate(&pc),
        "a flow restarted in the pause"
    );
}
