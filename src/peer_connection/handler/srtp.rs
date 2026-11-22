use crate::peer_connection::event::{
    RTCEventInternal, RTCPeerConnectionEvent, TaggedRTCEventInternal,
};
use crate::peer_connection::message::internal::{
    RTCMessageInternal, RTPMessage, TaggedRTCMessageInternal,
};

use crate::peer_connection::cryptex::RTCRtpHeaderEncryptionPolicy;
use interceptor::Packet;
use log::debug;
use shared::error::{Error, Result};
use shared::marshal::{Marshal, Unmarshal};
use shared::util::is_rtcp;
use srtp::context::Context;
use srtp::cryptex::Cryptex;
use srtp::header_extension::EncryptedHeaderExtensions;
use std::collections::VecDeque;
use std::time::Instant;

#[derive(Default)]
pub(crate) struct SrtpHandlerContext {
    pub(crate) local_srtp_context: Option<Context>,
    pub(crate) remote_srtp_context: Option<Context>,

    /// `RTCRtpHeaderEncryptionPolicy` (webrtc-extensions); see `peer_connection::cryptex`.
    pub(crate) rtp_header_encryption_policy: RTCRtpHeaderEncryptionPolicy,
    /// What the negotiated session says about Cryptex (RFC 9335), applied to the contexts
    /// now and to ones a DTLS handshake hands over later.
    pub(crate) cryptex: Cryptex,
    /// The header extension ids negotiated encrypted (RFC 6904), applied to the contexts now
    /// and to ones a DTLS handshake hands over later.
    pub(crate) encrypted_header_extensions: EncryptedHeaderExtensions,

    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<TaggedRTCEventInternal>,
    /// The newest instant a read or write carried, for the events the contexts raise.
    pub(crate) now: Option<Instant>,
}

impl SrtpHandlerContext {
    /// Records how the SRTP contexts use Cryptex and applies it to the ones in place.
    pub(crate) fn set_cryptex(&mut self, cryptex: Cryptex) {
        self.cryptex = cryptex;
        if let Some(context) = self.local_srtp_context.as_mut() {
            context.set_cryptex(cryptex);
        }
        if let Some(context) = self.remote_srtp_context.as_mut() {
            context.set_cryptex(cryptex);
        }
    }
}

impl SrtpHandlerContext {
    /// Records the header extensions the session encrypts (RFC 6904) and applies them to the
    /// contexts in place, in both directions.
    pub(crate) fn set_encrypted_header_extensions(&mut self, ids: EncryptedHeaderExtensions) {
        self.encrypted_header_extensions = ids;
        for context in [
            self.local_srtp_context.as_mut(),
            self.remote_srtp_context.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            context.set_encrypted_header_extensions(ids);
        }
    }
}

/// SrtpHandler implements SRTP/RTP/RTCP Protocols handling
pub(crate) struct SrtpHandler<'a> {
    ctx: &'a mut SrtpHandlerContext,
}

impl<'a> SrtpHandler<'a> {
    pub(crate) fn new(ctx: &'a mut SrtpHandlerContext) -> Self {
        SrtpHandler { ctx }
    }

    pub(crate) fn name(&self) -> &'static str {
        "SrtpHandler"
    }

    /// What the SRTP contexts have to say (`srtp::context::Context::poll_event`), as the
    /// connection's events: a key near the end of its lifetime, a key that reached it (the
    /// transport fails), a Cryptex violation.
    fn drain_context_events(&mut self) {
        use srtp::keying::{ContextEvent, PacketKind};
        // Contexts raise events only while protecting or unprotecting, which a read or a
        // write carrying an instant drives.
        let Some(now) = self.ctx.now else {
            return;
        };
        let mut events = Vec::new();
        for (outbound, context) in [
            (true, self.ctx.local_srtp_context.as_mut()),
            (false, self.ctx.remote_srtp_context.as_mut()),
        ] {
            let Some(context) = context else { continue };
            while let Some(event) = context.poll_event() {
                events.push(match event {
                    ContextEvent::KeyLifetimeExpiring {
                        kind, remaining, ..
                    } => RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnSrtpKeyLifetimeExpiring {
                            outbound,
                            rtcp: kind == PacketKind::Rtcp,
                            remaining,
                        },
                    ),
                    ContextEvent::KeyExhausted { .. } => RTCEventInternal::SRTPKeyExhausted,
                    ContextEvent::CryptexRequiredViolation { ssrc } => {
                        RTCEventInternal::RTCPeerConnectionEvent(
                            RTCPeerConnectionEvent::OnCryptexRequiredViolation(ssrc),
                        )
                    }
                    _ => continue,
                });
            }
        }
        for event in events {
            self.ctx
                .event_outs
                .push_back(TaggedRTCEventInternal { now, event });
        }
    }
}

impl<'a>
    sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, TaggedRTCEventInternal>
    for SrtpHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = TaggedRTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        self.ctx.now = Some(self.ctx.now.map_or(msg.now, |now| now.max(msg.now)));
        if let RTCMessageInternal::Rtp(RTPMessage::Raw(message)) = msg.message {
            debug!("srtp read {:?}", msg.transport.peer_addr);

            #[allow(clippy::collapsible_else_if)]
            if is_rtcp(&message) {
                if let Some(context) = self.ctx.remote_srtp_context.as_mut() {
                    let mut decrypted = context.decrypt_rtcp(&message)?;
                    // RFC 8834 section 4.1 (RFC 3550 section 6.1): of a compound packet, the
                    // packets that can be understood are processed. One of a known type that
                    // fails its own parse is passed on as a raw packet; it does not cost the
                    // others. The framing (version, lengths) still has to hold.
                    let rtcp_packets = rtcp::packet::unmarshal_lenient(&mut decrypted)?;
                    if rtcp_packets.is_empty() {
                        return Err(Error::Other("empty rtcp_packets".to_string()));
                    }

                    self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                        now: msg.now,
                        transport: msg.transport,
                        message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(
                            rtcp_packets,
                        ))),
                    });
                } else {
                    return Err(Error::Other(format!(
                        "remote_srtp_context is not set yet for rtcp_packet {:?}",
                        msg.transport.peer_addr
                    )));
                }
            } else {
                if let Some(context) = self.ctx.remote_srtp_context.as_mut() {
                    let mut decrypted = context.decrypt_rtp(&message)?;
                    let rtp_packet = rtp::Packet::unmarshal(&mut decrypted)?;

                    self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                        now: msg.now,
                        transport: msg.transport,
                        message: RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(
                            rtp_packet,
                        ))),
                    });
                } else {
                    return Err(Error::Other(format!(
                        "remote_srtp_context is not set yet for rtp_packet {:?}",
                        msg.transport.peer_addr
                    )));
                }
            }
        } else {
            debug!("bypass srtp read {:?}", msg.transport.peer_addr);
            self.ctx.read_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        self.ctx.now = Some(self.ctx.now.map_or(msg.now, |now| now.max(msg.now)));
        if let RTCMessageInternal::Rtp(message) = msg.message {
            debug!("srtp write {:?}", msg.transport.peer_addr);

            let encrypted = match message {
                RTPMessage::Packet(Packet::Rtcp(rtcp_packets)) => {
                    if rtcp_packets.is_empty() {
                        return Err(Error::Other("empty rtcp_packets".to_string()));
                    };

                    if let Some(context) = self.ctx.local_srtp_context.as_mut() {
                        let packet = rtcp::packet::marshal(&rtcp_packets)?;
                        context.encrypt_rtcp(&packet)?
                    } else {
                        return Err(Error::Other(format!(
                            "local_srp_context is not set yet for rtcp_packet {:?}",
                            msg.transport.peer_addr
                        )));
                    }
                }
                RTPMessage::Packet(Packet::Rtp(rtp_message)) => {
                    if let Some(context) = self.ctx.local_srtp_context.as_mut() {
                        let packet = rtp_message.marshal()?;
                        match context.encrypt_rtp(&packet) {
                            Ok(encrypted) => encrypted,
                            // A packet index protects one packet only: a retransmission of
                            // the same packet is protected again, but a different packet with an
                            // already sent sequence number is dropped.
                            Err(Error::SrtpIndexReused(ssrc, seq)) => {
                                debug!(
                                    "srtp write: dropped ssrc={ssrc} seq={seq}, index already used"
                                );
                                return Ok(());
                            }
                            Err(err) => return Err(err),
                        }
                    } else {
                        return Err(Error::Other(format!(
                            "local_srtp_context is not set yet for rtp_packet {:?}",
                            msg.transport.peer_addr
                        )));
                    }
                }
                // RFC 8827 section 6.5: no RTP or RTCP leaves unprotected. Nothing above this
                // handler writes serialized packets; one that did would pass the SRTP contexts
                // by, so it is refused instead of forwarded.
                RTPMessage::Raw(_) => {
                    return Err(Error::Other(
                        "serialized rtp/rtcp is never written past srtp unprotected".to_string(),
                    ));
                }
                RTPMessage::TrackPacket(_) => {
                    return Err(Error::Other(
                        "application level track message should never reach here".to_string(),
                    ));
                }
                RTPMessage::Packet(_) => {
                    return Err(Error::Other(
                        "unsupported packet kind for srtp write".to_string(),
                    ));
                }
            };

            self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                now: msg.now,
                transport: msg.transport,
                message: RTCMessageInternal::Rtp(RTPMessage::Raw(encrypted)),
            });
        } else {
            // Bypass
            debug!("Bypass srtp write {:?}", msg.transport.peer_addr);
            self.ctx.write_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, mut evt: TaggedRTCEventInternal) -> Result<()> {
        if let RTCEventInternal::DTLSHandshakeComplete(local_srtp_context, remote_srtp_context) =
            &mut evt.event
        {
            debug!("srtp recv dtls handshake complete");

            self.ctx.local_srtp_context = local_srtp_context.take();
            self.ctx.remote_srtp_context = remote_srtp_context.take();
            let cryptex = self.ctx.cryptex;
            self.ctx.set_cryptex(cryptex);
            let encrypted = self.ctx.encrypted_header_extensions;
            self.ctx.set_encrypted_header_extensions(encrypted);
        }

        self.ctx.event_outs.push_back(evt);

        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.drain_context_events();
        self.ctx.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<()> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        None
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use sansio::Protocol;
    use shared::TransportContext;

    fn write(ctx: &mut SrtpHandlerContext, message: RTPMessage) -> Result<()> {
        SrtpHandler::new(ctx).handle_write(TaggedRTCMessageInternal {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: RTCMessageInternal::Rtp(message),
        })
    }

    fn rtp_packet() -> rtp::Packet {
        rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number: 1,
                timestamp: 1,
                ssrc: 0x1234_5678,
                ..Default::default()
            },
            payload: bytes::Bytes::from_static(b"media"),
        }
    }

    /// RFC 8827 section 6.5 (and RFC 5764 section 5.1: no SRTP processing before the handshake
    /// has keyed the contexts): RTP and RTCP written before DTLS completes are refused, and
    /// nothing is queued for the wire.
    #[test]
    fn rtp_and_rtcp_are_not_sent_before_the_srtp_keys_exist() {
        let mut ctx = SrtpHandlerContext::default();
        assert!(write(&mut ctx, RTPMessage::Packet(Packet::Rtp(rtp_packet()))).is_err());
        let receiver_report: Box<dyn rtcp::packet::Packet> =
            Box::new(rtcp::receiver_report::ReceiverReport::default());
        assert!(
            write(
                &mut ctx,
                RTPMessage::Packet(Packet::Rtcp(vec![receiver_report]))
            )
            .is_err()
        );
        assert!(SrtpHandler::new(&mut ctx).poll_write().is_none());
    }

    /// RFC 8827 section 6.5: a serialized RTP packet handed to the SRTP handler is not passed
    /// on as it is, with or without SRTP contexts.
    #[test]
    fn serialized_rtp_is_never_forwarded_unprotected() {
        let mut ctx = SrtpHandlerContext::default();
        let raw = BytesMut::from(&rtp_packet().marshal().unwrap()[..]);
        assert!(write(&mut ctx, RTPMessage::Raw(raw)).is_err());
        assert!(SrtpHandler::new(&mut ctx).poll_write().is_none());
    }

    /// RFC 5764 section 5.1: inbound SRTP and SRTCP before the handshake completes are not
    /// processed: an error, and nothing reaches the handlers above.
    #[test]
    fn inbound_srtp_before_the_handshake_is_not_processed() {
        let mut ctx = SrtpHandlerContext::default();
        let rtp = BytesMut::from(&rtp_packet().marshal().unwrap()[..]);
        let mut rtcp = BytesMut::from(&[0u8; 12][..]);
        rtcp[0] = 0x80;
        rtcp[1] = 201;
        for raw in [rtp, rtcp] {
            let read = SrtpHandler::new(&mut ctx).handle_read(TaggedRTCMessageInternal {
                now: Instant::now(),
                transport: TransportContext::default(),
                message: RTCMessageInternal::Rtp(RTPMessage::Raw(raw)),
            });
            assert!(read.is_err());
        }
        assert!(SrtpHandler::new(&mut ctx).poll_read().is_none());
    }

    fn context(key_byte: u8) -> Context {
        let provider = crypto::default_provider().expect("a built-in crypto provider");
        Context::new(
            &[key_byte; 16],
            &[key_byte; 14],
            srtp::protection_profile::ProtectionProfile::Aes128CmHmacSha1_80,
            None,
            None,
            provider.crypto(),
        )
        .expect("an SRTP context")
    }

    fn handshake_complete(ctx: &mut SrtpHandlerContext, key_byte: u8) {
        SrtpHandler::new(ctx)
            .handle_event(TaggedRTCEventInternal {
                now: Instant::now(),
                event: RTCEventInternal::DTLSHandshakeComplete(
                    Some(context(key_byte)),
                    Some(context(key_byte)),
                ),
            })
            .unwrap();
    }

    fn protected(ctx: &mut SrtpHandlerContext, sequence_number: u16) -> BytesMut {
        let mut packet = rtp_packet();
        packet.header.sequence_number = sequence_number;
        write(ctx, RTPMessage::Packet(Packet::Rtp(packet))).unwrap();
        match SrtpHandler::new(ctx).poll_write().unwrap().message {
            RTCMessageInternal::Rtp(RTPMessage::Raw(protected)) => protected,
            other => panic!("unexpected {other:?}"),
        }
    }

    /// RFC 5764 section 4.1.3: "there MUST be only one SRTP master key in use at a time". The
    /// keys a DTLS handshake hands over replace the ones in place, in both directions: after a
    /// second handshake (a new association), packets are protected with the new key only.
    #[test]
    fn a_new_handshake_replaces_the_srtp_keys() {
        let mut ctx = SrtpHandlerContext::default();
        handshake_complete(&mut ctx, 1);
        let first = protected(&mut ctx, 1);
        assert!(context(1).decrypt_rtp(&first).is_ok());

        handshake_complete(&mut ctx, 2);
        let second = protected(&mut ctx, 2);
        assert!(context(2).decrypt_rtp(&second).is_ok());
        assert!(
            context(1).decrypt_rtp(&second).is_err(),
            "the first association's key no longer protects packets"
        );
        // Inbound, too: a packet under the old key is refused.
        let old = context(1)
            .encrypt_rtp(&rtp_packet().marshal().unwrap())
            .unwrap();
        let read = SrtpHandler::new(&mut ctx).handle_read(TaggedRTCMessageInternal {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: RTCMessageInternal::Rtp(RTPMessage::Raw(old)),
        });
        assert!(read.is_err());
    }

    /// RFC 5764 section 7.3.1: a packet that fails SRTP authentication produces no DTLS alert
    /// (and nothing else on the wire): it is an error for the pipeline to log, and the
    /// contexts go on.
    #[test]
    fn an_srtp_failure_sends_nothing() {
        let mut ctx = SrtpHandlerContext::default();
        handshake_complete(&mut ctx, 1);
        let mut forged = context(9)
            .encrypt_rtp(&rtp_packet().marshal().unwrap())
            .unwrap();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        let read = SrtpHandler::new(&mut ctx).handle_read(TaggedRTCMessageInternal {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: RTCMessageInternal::Rtp(RTPMessage::Raw(forged)),
        });
        assert!(read.is_err());
        let mut handler = SrtpHandler::new(&mut ctx);
        assert!(handler.poll_write().is_none());
        assert!(handler.poll_read().is_none());
        assert!(
            handler.poll_event().is_some(),
            "only the handshake event itself"
        );
        assert!(handler.poll_event().is_none());
        // A genuine packet is still read.
        let genuine = context(1)
            .encrypt_rtp(&rtp_packet().marshal().unwrap())
            .unwrap();
        SrtpHandler::new(&mut ctx)
            .handle_read(TaggedRTCMessageInternal {
                now: Instant::now(),
                transport: TransportContext::default(),
                message: RTCMessageInternal::Rtp(RTPMessage::Raw(genuine)),
            })
            .unwrap();
        assert!(SrtpHandler::new(&mut ctx).poll_read().is_some());
    }

    /// The RTCP packets read from one protected datagram.
    fn read_rtcp(ctx: &mut SrtpHandlerContext, plain: &[u8]) -> Vec<Box<dyn rtcp::Packet>> {
        let protected = context(1).encrypt_rtcp(plain).unwrap();
        SrtpHandler::new(ctx)
            .handle_read(TaggedRTCMessageInternal {
                now: Instant::now(),
                transport: TransportContext::default(),
                message: RTCMessageInternal::Rtp(RTPMessage::Raw(protected)),
            })
            .unwrap();
        match SrtpHandler::new(ctx).poll_read().map(|m| m.message) {
            Some(RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(packets)))) => packets,
            other => panic!("unexpected {other:?}"),
        }
    }

    fn sender_report() -> Vec<u8> {
        rtcp::sender_report::SenderReport {
            ssrc: 0x0102_0304,
            ntp_time: 1,
            rtp_time: 2,
            packet_count: 3,
            octet_count: 4,
            ..Default::default()
        }
        .marshal()
        .unwrap()
        .to_vec()
    }

    fn source_description() -> Vec<u8> {
        rtcp::source_description::SourceDescription {
            chunks: vec![rtcp::source_description::SourceDescriptionChunk {
                source: 0x0102_0304,
                items: vec![rtcp::source_description::SourceDescriptionItem {
                    sdes_type: rtcp::source_description::SdesType::SdesCname,
                    text: bytes::Bytes::from_static(b"cname"),
                }],
            }],
        }
        .marshal()
        .unwrap()
        .to_vec()
    }

    /// RFC 8834 section 4.1 ("process the known packet types and ignore the unknown"), RFC
    /// 3550 section 6.1: a compound packet whose middle packet is a receiver report that does
    /// not parse (it says one report block, its length holds none) still delivers the sender
    /// report before it and the SDES after it; the broken one comes along as a raw packet.
    #[test]
    fn a_broken_packet_in_a_compound_packet_does_not_cost_the_others() {
        let mut ctx = SrtpHandlerContext::default();
        handshake_complete(&mut ctx, 1);
        // V=2, RC=1, PT=201 (RR), length 1: the reporter's SSRC and no room for its block.
        let broken_receiver_report = [0x81u8, 201, 0, 1, 0, 0, 0, 9];
        let mut plain = sender_report();
        plain.extend_from_slice(&broken_receiver_report);
        plain.extend_from_slice(&source_description());

        let packets = read_rtcp(&mut ctx, &plain);
        assert_eq!(3, packets.len(), "{packets:?}");
        assert!(
            packets[0]
                .as_any()
                .downcast_ref::<rtcp::sender_report::SenderReport>()
                .is_some()
        );
        let raw = packets[1]
            .as_any()
            .downcast_ref::<rtcp::raw_packet::RawPacket>()
            .expect("the broken packet as it came");
        assert_eq!(&raw.0[..], &broken_receiver_report[..]);
        assert!(
            packets[2]
                .as_any()
                .downcast_ref::<rtcp::source_description::SourceDescription>()
                .is_some()
        );
    }

    /// RFC 8834 section 4.1, RFC 3550 section 6.1: a packet of a type this endpoint does not
    /// know (here 210) between known ones is skipped by its length; the known ones are read.
    #[test]
    fn a_packet_of_an_unknown_type_in_a_compound_packet_is_passed_over() {
        let mut ctx = SrtpHandlerContext::default();
        handshake_complete(&mut ctx, 1);
        let unknown = [0x80u8, 210, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8];
        let mut plain = sender_report();
        plain.extend_from_slice(&unknown);
        plain.extend_from_slice(&source_description());

        let packets = read_rtcp(&mut ctx, &plain);
        assert_eq!(3, packets.len(), "{packets:?}");
        assert!(
            packets[0]
                .as_any()
                .downcast_ref::<rtcp::sender_report::SenderReport>()
                .is_some()
        );
        assert!(
            packets[2]
                .as_any()
                .downcast_ref::<rtcp::source_description::SourceDescription>()
                .is_some()
        );
    }
}
