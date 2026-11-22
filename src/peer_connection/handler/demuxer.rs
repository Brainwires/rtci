use crate::peer_connection::event::TaggedRTCEventInternal;
use crate::peer_connection::message::internal::{
    DTLSMessage, RTCMessageInternal, RTPMessage, STUNMessage, TaggedRTCMessageInternal,
};

use crate::statistics::accumulator::RTCStatsAccumulator;
use log::{debug, error, trace};
use shared::error::Error;
use std::collections::VecDeque;
use std::time::Instant;

/// What a datagram is, by its first byte (RFC 7983 section 7 as updated by RFC 9443 section 3):
///
/// ```text
///              +----------------+
///              |        [0..3] -+--> forward to STUN
///              |                |
///              |       [4..15] -+--> DROP
///              |                |
///              |      [16..19] -+--> forward to ZRTP
///              |                |
///  packet -->  |      [20..63] -+--> forward to DTLS
///              |                |
///              |      [64..79] -+--> forward to TURN Channel
///              |                |    (if from TURN server), else QUIC
///              |     [80..127] -+--> forward to QUIC
///              |                |
///              |    [128..191] -+--> forward to RTP/RTCP
///              |                |
///              |    [192..255] -+--> forward to QUIC
///              +----------------+
/// ```
///
/// This endpoint speaks STUN, DTLS and SRTP on the transport. It has no ZRTP and no QUIC, and
/// TURN channel framing never reaches it (the caller's TURN client removes it before
/// `handle_read`), so every other value is dropped here: "If the value does not match any
/// known range, then the packet MUST be dropped".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Demuxed {
    Stun,
    Dtls,
    Srtp,
    Drop,
}

fn demux(first_byte: u8) -> Demuxed {
    match first_byte {
        0..=3 => Demuxed::Stun,
        20..=63 => Demuxed::Dtls,
        128..=191 => Demuxed::Srtp,
        _ => Demuxed::Drop,
    }
}

#[derive(Default)]
pub(crate) struct DemuxerHandlerContext {
    /// Whether every datagram that reaches local port 5353 is mDNS, whatever port it came
    /// from: true when this peer connection answers for `.local` names (mDNS mode
    /// `QueryAndGather`). RFC 6762 Section 6.7: a "legacy unicast" query comes from a port
    /// other than 5353 and must still be answered. Off otherwise, so that an ICE socket an
    /// application happens to bind on port 5353 keeps its DTLS and media.
    pub(crate) mdns_legacy_unicast: bool,
    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<TaggedRTCEventInternal>,
}

/// DemuxerHandler implements demuxing of STUN/DTLS/RTP/RTCP Protocol packets
pub(crate) struct DemuxerHandler<'a> {
    ctx: &'a mut DemuxerHandlerContext,
    stats: &'a mut RTCStatsAccumulator,
}

impl<'a> DemuxerHandler<'a> {
    pub(crate) fn new(
        ctx: &'a mut DemuxerHandlerContext,
        stats: &'a mut RTCStatsAccumulator,
    ) -> Self {
        DemuxerHandler { ctx, stats }
    }

    pub(crate) fn name(&self) -> &'static str {
        "DemuxerHandler"
    }
}

impl<'a>
    sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, TaggedRTCEventInternal>
    for DemuxerHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = TaggedRTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessageInternal) -> Result<(), Self::Error> {
        if let RTCMessageInternal::Raw(message) = msg.message {
            // Every datagram is a packet received on the transport; its bytes count only when
            // it is DTLS or SRTP (webrtc-stats `RTCTransportStats.bytesReceived`: payload bytes,
            // "not including headers, padding or ICE connectivity checks"). What is neither is
            // STUN, or mDNS from the host's mDNS socket.
            let is_mdns = msg.transport.local_addr.port() == mdns::MDNS_PORT
                && (msg.transport.peer_addr.port() == mdns::MDNS_PORT
                    || self.ctx.mdns_legacy_unicast);
            let is_payload = !is_mdns
                && message
                    .first()
                    .is_some_and(|first| matches!(demux(*first), Demuxed::Dtls | Demuxed::Srtp));
            self.stats
                .transport
                .on_packet_received(message.len(), is_payload);

            if message.is_empty() {
                error!("drop invalid packet due to zero length");
            } else if is_mdns {
                // mDNS from the host's mDNS socket goes to the ICE agent, which resolves remote
                // `.local` candidates and answers for its own. RFC 7983's first-byte ranges
                // don't apply to DNS: a message ID of 20-63 or 128-191 would otherwise send it
                // to DTLS or SRTP.
                self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessageInternal::Stun(STUNMessage::Raw(message)),
                });
            } else {
                let message = match demux(message[0]) {
                    Demuxed::Stun => RTCMessageInternal::Stun(STUNMessage::Raw(message)),
                    Demuxed::Dtls => RTCMessageInternal::Dtls(DTLSMessage::Raw(message)),
                    Demuxed::Srtp => RTCMessageInternal::Rtp(RTPMessage::Raw(message)),
                    // Dropped before the ICE agent: it is not STUN, so it neither marks a
                    // remote candidate as heard from nor costs a log line or an error per
                    // datagram (RFC 7983 section 7 allows an alert; a peer could flood it).
                    Demuxed::Drop => {
                        trace!(
                            "drop datagram from {:?}: first byte {} is in no demultiplexing range",
                            msg.transport.peer_addr, message[0]
                        );
                        return Ok(());
                    }
                };
                self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                    now: msg.now,
                    transport: msg.transport,
                    message,
                });
            }
        } else {
            debug!("drop non-RAW packet {:?}", msg.message);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessageInternal) -> Result<(), Self::Error> {
        // Every datagram is a packet sent on the transport; its bytes count unless it is STUN
        // (webrtc-stats `RTCTransportStats.bytesSent`: payload bytes, "not including headers,
        // padding or ICE connectivity checks").
        let is_payload = !matches!(msg.message, RTCMessageInternal::Stun(_));
        match msg.message {
            RTCMessageInternal::Raw(message)
            | RTCMessageInternal::Stun(STUNMessage::Raw(message))
            | RTCMessageInternal::Dtls(DTLSMessage::Raw(message))
            | RTCMessageInternal::Rtp(RTPMessage::Raw(message)) => {
                self.stats
                    .transport
                    .on_packet_sent(message.len(), is_payload);

                self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessageInternal::Raw(message),
                });
            }
            _ => {
                debug!("drop non-RAW packet {:?}", msg.message);
            }
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: TaggedRTCEventInternal) -> shared::error::Result<()> {
        self.ctx.event_outs.push_back(evt);
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.ctx.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        None
    }

    fn close(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use sansio::Protocol;
    use shared::{TransportContext, TransportProtocol};

    fn try_read(local: &str, peer: &str, first_byte: u8) -> Option<RTCMessageInternal> {
        try_read_with(DemuxerHandlerContext::default(), local, peer, first_byte)
    }

    fn try_read_with(
        mut ctx: DemuxerHandlerContext,
        local: &str,
        peer: &str,
        first_byte: u8,
    ) -> Option<RTCMessageInternal> {
        let mut stats = RTCStatsAccumulator::new();
        let mut handler = DemuxerHandler::new(&mut ctx, &mut stats);
        let mut message = BytesMut::from(&[0u8; 12][..]);
        message[0] = first_byte;
        handler
            .handle_read(TaggedRTCMessageInternal {
                now: Instant::now(),
                transport: TransportContext {
                    local_addr: local.parse().unwrap(),
                    peer_addr: peer.parse().unwrap(),
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: RTCMessageInternal::Raw(message),
            })
            .unwrap();
        let read = handler.poll_read().map(|read| read.message);
        assert!(handler.poll_read().is_none(), "one datagram, one message");
        read
    }

    fn read(local: &str, peer: &str, first_byte: u8) -> RTCMessageInternal {
        try_read(local, peer, first_byte).expect("the datagram is forwarded")
    }

    /// RFC 7983 section 7 and RFC 9443 section 3, every first byte: 0 to 3 is STUN, 20 to 63
    /// DTLS, 128 to 191 RTP / RTCP; 4 to 19, 64 to 127 and 192 to 255 (no ZRTP, no QUIC, TURN
    /// channels unwrapped by the caller) are dropped and reach no handler.
    #[test]
    fn every_first_byte_goes_to_its_protocol_or_is_dropped() {
        for first_byte in 0..=255u8 {
            let read = try_read("192.168.1.2:50000", "192.168.1.9:40000", first_byte);
            match first_byte {
                0..=3 => assert!(
                    matches!(read, Some(RTCMessageInternal::Stun(_))),
                    "first byte {first_byte} is STUN"
                ),
                20..=63 => assert!(
                    matches!(read, Some(RTCMessageInternal::Dtls(_))),
                    "first byte {first_byte} is DTLS"
                ),
                128..=191 => assert!(
                    matches!(read, Some(RTCMessageInternal::Rtp(_))),
                    "first byte {first_byte} is RTP / RTCP"
                ),
                4..=19 | 64..=127 | 192..=255 => {
                    assert!(read.is_none(), "first byte {first_byte} is dropped")
                }
            }
        }
    }

    /// An mDNS message whose ID falls in the DTLS or SRTP first-byte range still reaches ICE
    /// when it comes from the mDNS socket; elsewhere RFC 7983 applies as before.
    #[test]
    fn mdns_from_the_mdns_socket_goes_to_ice_whatever_its_first_byte() {
        for first_byte in [0u8, 22, 63, 128, 191, 255] {
            assert!(
                matches!(
                    read("0.0.0.0:5353", "192.168.1.9:5353", first_byte),
                    RTCMessageInternal::Stun(_)
                ),
                "first byte {first_byte}"
            );
        }
        assert!(matches!(
            read("192.168.1.2:50000", "192.168.1.9:5353", 22),
            RTCMessageInternal::Dtls(_)
        ));
        assert!(matches!(
            read("192.168.1.2:50000", "192.168.1.9:40000", 128),
            RTCMessageInternal::Rtp(_)
        ));
    }

    /// RFC 6762 Section 6.7: a legacy unicast query reaches port 5353 from another port. A
    /// peer connection that answers for its `.local` names takes it as mDNS; one that does not
    /// demultiplexes it by RFC 7983 like any datagram (an ICE socket on port 5353 keeps its
    /// DTLS).
    #[test]
    fn a_legacy_unicast_query_reaches_ice_when_this_peer_answers_mdns() {
        let responder = || DemuxerHandlerContext {
            mdns_legacy_unicast: true,
            ..Default::default()
        };
        for first_byte in [0u8, 22, 128, 255] {
            assert!(
                matches!(
                    try_read_with(responder(), "0.0.0.0:5353", "192.168.1.9:40000", first_byte),
                    Some(RTCMessageInternal::Stun(_))
                ),
                "first byte {first_byte}"
            );
        }
        assert!(matches!(
            read("0.0.0.0:5353", "192.168.1.9:40000", 22),
            RTCMessageInternal::Dtls(_)
        ));
        // Only port 5353 is the mDNS socket.
        assert!(matches!(
            try_read_with(responder(), "192.168.1.2:50000", "192.168.1.9:40000", 22),
            Some(RTCMessageInternal::Dtls(_))
        ));
    }

    /// The whole pipeline: a datagram whose first byte is in no demultiplexing range, sent
    /// from a remote candidate's address, does not reach the ICE agent. It used to be handed
    /// to it as "STUN", and the agent, finding no STUN in it, still recorded the candidate as
    /// heard from (and logged a warning per datagram).
    #[test]
    fn out_of_range_datagrams_do_not_reach_the_ice_agent() {
        use crate::peer_connection::RTCPeerConnectionBuilder;
        use crate::peer_connection::transport::{
            CandidateConfig, CandidateHostConfig, RTCIceCandidate,
        };
        use shared::TaggedBytesMut;

        let now = Instant::now();
        let local = "10.0.0.1:5000";
        let remote = "10.0.0.2:5000";
        let peer = |addr: &str| {
            let addr: std::net::SocketAddr = addr.parse().unwrap();
            let mut pc = RTCPeerConnectionBuilder::new().build(now).unwrap();
            let host = CandidateHostConfig {
                base_config: CandidateConfig {
                    network: "udp".to_owned(),
                    address: addr.ip().to_string(),
                    port: addr.port(),
                    component: 1,
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host()
            .unwrap();
            pc.add_local_candidate(RTCIceCandidate::from(&host).to_json().unwrap())
                .unwrap();
            pc
        };
        let mut offerer = peer(local);
        let mut answerer = peer(remote);
        offerer.create_data_channel("data", None).unwrap();
        let offer = offerer.create_offer(None).unwrap();
        offerer.set_local_description(now, offer.clone()).unwrap();
        answerer.set_remote_description(now, offer).unwrap();
        let answer = answerer.create_answer(None).unwrap();
        answerer.set_local_description(now, answer.clone()).unwrap();
        offerer.set_remote_description(now, answer).unwrap();

        let last_received = |pc: &crate::peer_connection::RTCPeerConnection| {
            pc.ice_transport()
                .agent
                .get_remote_candidates()
                .iter()
                .find(|candidate| {
                    candidate.addr() == remote.parse::<std::net::SocketAddr>().unwrap()
                })
                .expect("the remote candidate")
                .last_received()
        };
        assert_eq!(last_received(&offerer), None);

        for first_byte in [4u8, 15, 16, 19, 64, 79, 80, 127, 192, 255] {
            offerer
                .handle_read(TaggedBytesMut {
                    now: now + std::time::Duration::from_millis(5),
                    transport: TransportContext {
                        local_addr: local.parse().unwrap(),
                        peer_addr: remote.parse().unwrap(),
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&[first_byte; 16][..]),
                })
                .unwrap();
            assert_eq!(
                last_received(&offerer),
                None,
                "a datagram with first byte {first_byte} reached the ICE agent"
            );
        }
    }
}
