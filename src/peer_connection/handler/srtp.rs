use crate::peer_connection::event::{
    RTCEventInternal, RTCPeerConnectionEvent, TaggedRTCEventInternal,
};
use crate::peer_connection::message::internal::{
    RTCMessageInternal, RTPMessage, TaggedRTCMessageInternal,
};

use crate::peer_connection::cryptex::RTCRtpHeaderEncryptionPolicy;
use interceptor::Packet;
use log::{debug, warn};
use shared::error::{Error, Result};
use shared::marshal::{Marshal, Unmarshal};
use shared::util::is_rtcp;
use srtp::context::Context;
use srtp::cryptex::Cryptex;
use srtp::header_extension::EncryptedHeaderExtensions;
use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

/// How long the inbound context of the association before a new one is kept, for packets
/// it protected that arrive late (RFC 5764 section 4.3).
pub(crate) const PREVIOUS_SRTP_KEYS_LINGER: Duration = Duration::from_secs(10);

#[derive(Default)]
pub(crate) struct SrtpHandlerContext {
    pub(crate) local_srtp_context: Option<Context>,
    pub(crate) remote_srtp_context: Option<Context>,
    /// RFC 5764 section 4.3: "DTLS-SRTP implementations SHOULD store multiple SRTP keys sets
    /// during a rekey in order to avoid the need for receivers to drop packets for which they
    /// lack a key." The inbound context a new handshake replaced, and until when it is kept.
    /// It only unprotects: nothing is sent with it.
    pub(crate) previous_remote_srtp_context: Option<(Context, Instant)>,
    /// The SSRCs whose packets the current inbound context has authenticated: from then on,
    /// their packets are not tried with the previous context (it has a later sender's key
    /// behind it, so an old-key packet now is a replay of the old association, not a late one).
    pub(crate) ssrcs_under_current_keys: HashSet<u32>,

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
    /// Received RTCP is held to RFC 3550 Appendix A.2 and section 6.4.1
    /// (`SettingEngineBuilder::with_strict_rtcp_validity`).
    pub(crate) strict_rtcp_validity: bool,
    /// Reduced-size RTCP was negotiated (RFC 5506): under the strict form a datagram need
    /// not start with an SR or RR.
    pub(crate) rtcp_reduced_size: bool,
}

/// Parses a decrypted RTCP datagram for the chain.
///
/// RFC 8834 section 4.1 (RFC 3550 section 6.1): of a compound packet, the packets that can be
/// understood are processed. One of a known type that fails its own parse is passed on as a
/// raw packet; it does not cost the others. The framing (version, lengths) has to hold.
///
/// That is all the default asks. RFC 3550 Appendix A.2 also discards a datagram whose first
/// packet is not an SR or RR or has its padding bit set, and section 6.4.1 one with padding on
/// a packet that is not the last; libwebrtc pads a packet in the middle of a compound packet
/// (its TWCC feedback), so accepting those is the default and `strict` the RFC's form. Under
/// it the first-packet rule is RFC 5506's when reduced-size RTCP was negotiated: any RTCP
/// packet type may come first.
pub(crate) fn parse_received_rtcp(
    decrypted: &[u8],
    strict: bool,
    reduced_size: bool,
) -> Result<Vec<Box<dyn rtcp::packet::Packet>>> {
    if strict {
        if reduced_size {
            rtcp::compound_packet::validate_reduced_size(decrypted)?;
        } else {
            rtcp::compound_packet::validate_compound_headers(decrypted)?;
        }
    }
    let packets = rtcp::packet::unmarshal_lenient(&mut &decrypted[..])?;
    if packets.is_empty() {
        return Err(Error::Other("empty rtcp_packets".to_string()));
    }
    Ok(packets)
}

impl SrtpHandlerContext {
    /// Unprotects an inbound SRTP (`rtcp` false) or SRTCP packet with the current keys, or,
    /// for a packet of a stream the current keys have not authenticated yet, with the keys
    /// of the association before while they are kept (RFC 5764 section 4.3).
    fn unprotect(&mut self, now: Instant, message: &[u8], rtcp: bool) -> Result<bytes::BytesMut> {
        let ssrc_at = if rtcp { 4..8 } else { 8..12 };
        let ssrc = message
            .get(ssrc_at)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
        if self
            .previous_remote_srtp_context
            .as_ref()
            .is_some_and(|(_, until)| now >= *until)
        {
            self.previous_remote_srtp_context = None;
        }
        if let (Some((previous, _)), Some(ssrc)) =
            (self.previous_remote_srtp_context.as_mut(), ssrc)
            && !self.ssrcs_under_current_keys.contains(&ssrc)
        {
            let late = if rtcp {
                previous.decrypt_rtcp(message)
            } else {
                previous.decrypt_rtp(message)
            };
            // What the old context has to say is not the application's concern: a packet it
            // refuses is tried with the current keys, which report it.
            while previous.poll_event().is_some() {}
            if let Ok(plain) = late {
                return Ok(plain);
            }
        }
        let context = self
            .remote_srtp_context
            .as_mut()
            .ok_or_else(|| Error::Other("no inbound SRTP context".to_owned()))?;
        let plain = if rtcp {
            context.decrypt_rtcp(message)?
        } else {
            context.decrypt_rtp(message)?
        };
        if let Some(ssrc) = ssrc
            && self.previous_remote_srtp_context.is_some()
        {
            self.ssrcs_under_current_keys.insert(ssrc);
        }
        Ok(plain)
    }

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
                    ContextEvent::PacketDiscarded {
                        kind,
                        ssrc,
                        index,
                        reason,
                    } => {
                        // RFC 3711 section 3.3: logged, and told to the application.
                        warn!("{kind:?} packet discarded: SSRC {ssrc}, index {index}, {reason:?}");
                        RTCEventInternal::RTCPeerConnectionEvent(
                            RTCPeerConnectionEvent::OnSrtpPacketDiscarded {
                                rtcp: kind == PacketKind::Rtcp,
                                ssrc,
                                index,
                                replay: reason == srtp::keying::DiscardReason::Replay,
                            },
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
                if self.ctx.remote_srtp_context.is_some() {
                    let decrypted = self.ctx.unprotect(msg.now, &message, true)?;
                    let rtcp_packets = parse_received_rtcp(
                        &decrypted,
                        self.ctx.strict_rtcp_validity,
                        self.ctx.rtcp_reduced_size,
                    )?;

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
                if self.ctx.remote_srtp_context.is_some() {
                    let mut decrypted = self.ctx.unprotect(msg.now, &message, false)?;
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
            let previous = std::mem::replace(
                &mut self.ctx.remote_srtp_context,
                remote_srtp_context.take(),
            );
            // RFC 5764 section 4.3: the keys of the association before are kept a while for
            // its packets still on their way.
            self.ctx.previous_remote_srtp_context = previous
                .filter(|_| self.ctx.remote_srtp_context.is_some())
                .map(|context| (context, evt.now + PREVIOUS_SRTP_KEYS_LINGER));
            self.ctx.ssrcs_under_current_keys.clear();
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

    /// An RR with no report blocks, its padding bit set and four octets of padding, then a
    /// PLI: padding on a packet that is not the last of the compound packet.
    fn padded_report_then_pli() -> Vec<u8> {
        let mut datagram = vec![0xA0, 201, 0, 2, 0, 0, 0, 1, 0, 0, 0, 4];
        datagram.extend_from_slice(&pli());
        datagram
    }

    fn pli() -> [u8; 12] {
        [0x81, 206, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2]
    }

    /// RFC 8834 section 4.1 and libwebrtc's compound packets: by default padding on a packet
    /// in the middle costs nothing, both packets are processed.
    #[test]
    fn padding_on_a_packet_that_is_not_the_last_is_accepted_by_default() {
        let packets = parse_received_rtcp(&padded_report_then_pli(), false, false).unwrap();
        assert_eq!(2, packets.len());
    }

    /// RFC 3550 section 6.4.1 ("the padding bit MUST be set only on that packet", the last)
    /// and Appendix A.2 (the first packet's padding bit is zero), with the strict setting.
    #[test]
    fn the_strict_rtcp_validity_discards_padding_on_a_packet_that_is_not_the_last() {
        assert!(parse_received_rtcp(&padded_report_then_pli(), true, false).is_err());
        assert!(parse_received_rtcp(&padded_report_then_pli(), true, true).is_err());
    }

    /// RFC 3550 Appendix A.2: the first packet of a compound packet is an SR or RR; RFC 5506
    /// section 3.4.2 lifts that where reduced-size RTCP was negotiated. The default takes a
    /// lone feedback packet either way.
    #[test]
    fn the_strict_rtcp_validity_wants_a_report_first_unless_reduced_size_was_negotiated() {
        assert!(parse_received_rtcp(&pli(), true, false).is_err());
        assert_eq!(1, parse_received_rtcp(&pli(), true, true).unwrap().len());
        assert_eq!(1, parse_received_rtcp(&pli(), false, false).unwrap().len());
    }

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
        // Inbound, too: once the new key has carried a stream's packets, a packet of that
        // stream under the old key is refused.
        let mut sender = context(2);
        read_raw(
            &mut ctx,
            sender
                .encrypt_rtp(&rtp_packet().marshal().unwrap())
                .unwrap(),
        )
        .unwrap();
        let old = context(1)
            .encrypt_rtp(&rtp_packet().marshal().unwrap())
            .unwrap();
        assert!(read_raw(&mut ctx, old).is_err());
    }

    fn read_raw(ctx: &mut SrtpHandlerContext, raw: BytesMut) -> Result<()> {
        read_raw_at(ctx, raw, Instant::now())
    }

    fn read_raw_at(ctx: &mut SrtpHandlerContext, raw: BytesMut, now: Instant) -> Result<()> {
        SrtpHandler::new(ctx).handle_read(TaggedRTCMessageInternal {
            now,
            transport: TransportContext::default(),
            message: RTCMessageInternal::Rtp(RTPMessage::Raw(raw)),
        })?;
        SrtpHandler::new(ctx).poll_read();
        Ok(())
    }

    fn rtp_with_ssrc(ssrc: u32, sequence_number: u16) -> Vec<u8> {
        let mut packet = rtp_packet();
        packet.header.ssrc = ssrc;
        packet.header.sequence_number = sequence_number;
        packet.marshal().unwrap().to_vec()
    }

    /// RFC 5764 section 4.3: "DTLS-SRTP implementations SHOULD store multiple SRTP keys sets
    /// during a rekey in order to avoid the need for receivers to drop packets for which they
    /// lack a key." After a new handshake, a packet the peer protected with the old key and
    /// that arrives late is still read, for a stream the new key has not carried yet and for
    /// a while; nothing is sent with the old key.
    #[test]
    fn a_late_packet_under_the_previous_keys_is_still_read() {
        let start = Instant::now();
        let mut ctx = SrtpHandlerContext::default();
        handshake_complete(&mut ctx, 1);
        let mut old_sender = context(1);
        let late_a = old_sender.encrypt_rtp(&rtp_with_ssrc(0xa, 10)).unwrap();
        let late_b = old_sender.encrypt_rtp(&rtp_with_ssrc(0xb, 10)).unwrap();
        let late_c = old_sender.encrypt_rtp(&rtp_with_ssrc(0xc, 10)).unwrap();
        let late_rtcp = old_sender.encrypt_rtcp(&sender_report()).unwrap();

        SrtpHandler::new(&mut ctx)
            .handle_event(TaggedRTCEventInternal {
                now: start,
                event: RTCEventInternal::DTLSHandshakeComplete(Some(context(2)), Some(context(2))),
            })
            .unwrap();
        assert!(
            context(2).decrypt_rtp(&protected(&mut ctx, 3)).is_ok(),
            "sent with the new key only"
        );
        read_raw_at(&mut ctx, late_a, start).expect("a late packet under the old key");
        read_raw_at(&mut ctx, late_rtcp, start).expect("a late SRTCP packet under the old key");

        // Stream 0xb has a packet under the new key: an old-key one after it is refused.
        let mut new_sender = context(2);
        read_raw_at(
            &mut ctx,
            new_sender.encrypt_rtp(&rtp_with_ssrc(0xb, 11)).unwrap(),
            start,
        )
        .unwrap();
        assert!(read_raw_at(&mut ctx, late_b, start).is_err());

        // After the old keys' time, nothing under them is read.
        assert!(read_raw_at(&mut ctx, late_c, start + PREVIOUS_SRTP_KEYS_LINGER).is_err());
        assert!(ctx.previous_remote_srtp_context.is_none());
    }

    /// RFC 5764 section 7.3.1: a packet that fails SRTP authentication produces no DTLS alert
    /// (and nothing else on the wire): it is an error for the pipeline, and the contexts go
    /// on. RFC 3711 section 3.3 step 5: the failure is logged and reported to the
    /// application (`OnSrtpPacketDiscarded`).
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
            matches!(
                handler.poll_event().map(|e| e.event),
                Some(RTCEventInternal::DTLSHandshakeComplete(..))
            ),
            "the handshake event itself"
        );
        assert!(matches!(
            handler.poll_event().map(|e| e.event),
            Some(RTCEventInternal::RTCPeerConnectionEvent(
                RTCPeerConnectionEvent::OnSrtpPacketDiscarded {
                    rtcp: false,
                    ssrc: 0x1234_5678,
                    index: 1,
                    replay: false,
                }
            ))
        ));
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

    /// RFC 3711 section 3.3 step 2: a replayed packet is discarded, and the event is logged
    /// and reported to the application (`OnSrtpPacketDiscarded` with `replay`).
    #[test]
    fn a_replayed_srtp_packet_is_reported() {
        let provider = crypto::default_provider().expect("a built-in crypto provider");
        let replay_protected = || {
            Context::new(
                &[1; 16],
                &[1; 14],
                srtp::protection_profile::ProtectionProfile::Aes128CmHmacSha1_80,
                Some(srtp::option::srtp_replay_protection(64).unwrap()),
                None,
                provider.crypto(),
            )
            .expect("an SRTP context")
        };
        let mut ctx = SrtpHandlerContext::default();
        SrtpHandler::new(&mut ctx)
            .handle_event(TaggedRTCEventInternal {
                now: Instant::now(),
                event: RTCEventInternal::DTLSHandshakeComplete(
                    Some(replay_protected()),
                    Some(replay_protected()),
                ),
            })
            .unwrap();
        let packet = context(1)
            .encrypt_rtp(&rtp_packet().marshal().unwrap())
            .unwrap();
        for (i, raw) in [packet.clone(), packet].into_iter().enumerate() {
            let read = SrtpHandler::new(&mut ctx).handle_read(TaggedRTCMessageInternal {
                now: Instant::now(),
                transport: TransportContext::default(),
                message: RTCMessageInternal::Rtp(RTPMessage::Raw(raw)),
            });
            assert_eq!(read.is_ok(), i == 0);
        }
        let mut handler = SrtpHandler::new(&mut ctx);
        let events: Vec<_> = std::iter::from_fn(|| handler.poll_event().map(|e| e.event)).collect();
        assert!(
            events.iter().any(|e| matches!(
                e,
                RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnSrtpPacketDiscarded {
                        rtcp: false,
                        ssrc: 0x1234_5678,
                        index: 1,
                        replay: true,
                    }
                )
            )),
            "{} events, none the replay",
            events.len()
        );
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

    /// RFC 4588 section 12: the RTX stream gets at least the protection of the stream it
    /// repairs. A retransmission (its own SSRC and payload type) is protected under the same
    /// SRTP session as the media: it leaves encrypted and authenticated, and the receiving
    /// context opens it.
    #[test]
    fn a_retransmission_is_protected_like_the_media() {
        let mut ctx = SrtpHandlerContext::default();
        handshake_complete(&mut ctx, 1);
        let mut rtx = rtp_packet();
        rtx.header.ssrc = 0x0BAD_F00D;
        rtx.header.payload_type = 97;
        rtx.payload = bytes::Bytes::from_static(b"\x00\x2amedia");
        let plain = rtx.marshal().unwrap();
        write(&mut ctx, RTPMessage::Packet(Packet::Rtp(rtx))).unwrap();
        let protected = match SrtpHandler::new(&mut ctx).poll_write().unwrap().message {
            RTCMessageInternal::Rtp(RTPMessage::Raw(protected)) => protected,
            other => panic!("unexpected {other:?}"),
        };
        assert_ne!(
            &plain[12..],
            &protected[12..plain.len()],
            "the payload is encrypted"
        );
        assert!(
            protected.len() > plain.len(),
            "an authentication tag is added"
        );
        assert_eq!(&plain[..], &context(1).decrypt_rtp(&protected).unwrap()[..]);
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
