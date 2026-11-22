//! Bundling of control chunks (RFC 9260 sections 6.10 and 12.4): what answers one received
//! packet leaves in one packet, a SACK that is due travels with it or with outbound DATA, and
//! so does a FORWARD TSN (RFC 3758 3.5 F2).

use super::*;
use crate::chunk::chunk_type::{
    CT_COOKIE_ACK, CT_ERROR, CT_HEARTBEAT, CT_HEARTBEAT_ACK, CT_I_DATA, CT_PAYLOAD_DATA, CT_SACK,
};
use crate::util::get_padding_size;

/// Room kept in the packet that answers a received packet for the SACK that goes with it:
/// the chunk without Gap Ack Blocks, and a few duplicate TSNs.
const SACK_RESERVE: usize = CHUNK_HEADER_SIZE + SELECTIVE_ACK_HEADER_SIZE + 4 * 8;

fn chunk_wire_size(c: &dyn Chunk) -> usize {
    let len = CHUNK_HEADER_SIZE + c.value_length();
    len + get_padding_size(len)
}

fn packet_wire_size(p: &Packet) -> usize {
    COMMON_HEADER_SIZE as usize
        + p.chunks
            .iter()
            .map(|c| chunk_wire_size(c.as_ref()))
            .sum::<usize>()
}

impl Association {
    /// Whether `p` may share a packet with other control chunks: it goes to the peer with
    /// the association's tag, and holds none of the chunks that travel alone (INIT, INIT
    /// ACK and SHUTDOWN COMPLETE by RFC 9260 6.10; ABORT, COOKIE ECHO and the SHUTDOWN
    /// chunks by choice, each being the one thing its packet is for).
    fn is_bundle(&self, p: &Packet) -> bool {
        p.common_header.verification_tag == self.peer_verification_tag
            && self.peer_verification_tag != 0
            && p.common_header.source_port == self.source_port
            && p.common_header.destination_port == self.destination_port
            && !p.chunks.is_empty()
            && p.chunks.iter().all(|c| {
                let typ = c.header().typ;
                [
                    CT_SACK,
                    CT_HEARTBEAT,
                    CT_HEARTBEAT_ACK,
                    CT_ERROR,
                    CT_COOKIE_ACK,
                    CT_RECONFIG,
                    CT_FORWARD_TSN,
                    CT_I_FORWARD_TSN,
                ]
                .contains(&typ)
            })
    }

    /// RFC 9260 6.10: control packets that follow one another become one packet while they
    /// fit the MTU. `sack`, when one is due, joins the last of them if it fits and is taken;
    /// otherwise it is left for `gather_outbound_sack_packets`.
    pub(super) fn bundle_control_packets(
        &self,
        packets: Vec<Packet>,
        sack: &mut Option<ChunkSelectiveAck>,
    ) -> Vec<Packet> {
        let mtu = self.mtu as usize;
        let mut out: Vec<Packet> = Vec::with_capacity(packets.len());
        for p in packets {
            if self.is_bundle(&p)
                && let Some(last) = out.last_mut()
                && self.is_bundle(last)
                && packet_wire_size(last) + packet_wire_size(&p) - COMMON_HEADER_SIZE as usize
                    <= mtu
            {
                last.chunks.extend(p.chunks);
            } else {
                out.push(p);
            }
        }
        if let Some(chunk) = sack.take() {
            match out.last_mut() {
                Some(last)
                    if self.is_bundle(last)
                        && packet_wire_size(last) + chunk_wire_size(&chunk) <= mtu =>
                {
                    last.chunks.push(Box::new(chunk));
                }
                _ => *sack = Some(chunk),
            }
        }
        out
    }

    /// RFC 9260 12.4: "an SCTP receiver MUST NOT respond with more than one packet containing
    /// chunks other than DATA chunks" to one received packet. The packets queued since the
    /// control queue held `before` of them are the answers to the packet just processed:
    /// they become one packet, and the chunks that do not fit it are not sent (the sender
    /// of two hundred HEARTBEATs in a packet gets as many HEARTBEAT ACKs as fit one).
    pub(super) fn bundle_replies(&mut self, before: usize) {
        if self.control_queue.len() <= before + 1 {
            return;
        }
        let replies: Vec<Packet> = self.control_queue.drain(before..).collect();
        // An ABORT is the whole answer.
        if let Some(abort) = replies
            .iter()
            .position(|p| p.chunks.iter().any(|c| c.as_any().is::<ChunkAbort>()))
        {
            self.control_queue
                .extend(replies.into_iter().skip(abort).take(1));
            return;
        }
        let room = (self.mtu as usize).saturating_sub(if self.immediate_ack_triggered {
            SACK_RESERVE
        } else {
            0
        });
        let mut bundle: Option<Packet> = None;
        let mut alone: Option<Packet> = None;
        for p in replies {
            if !self.is_bundle(&p) {
                // A chunk that travels alone (an INIT ACK, a SHUTDOWN ACK): it is the answer.
                alone.get_or_insert(p);
                continue;
            }
            match bundle.as_mut() {
                None => bundle = Some(p),
                Some(b) => {
                    let mut size = packet_wire_size(b);
                    for c in p.chunks {
                        let wire = chunk_wire_size(c.as_ref());
                        if size + wire <= room {
                            size += wire;
                            b.chunks.push(c);
                        } else {
                            debug!(
                                "[{}] a reply chunk does not fit the one packet of answers",
                                self.side
                            );
                        }
                    }
                }
            }
        }
        match (alone, bundle) {
            (Some(alone), _) => self.control_queue.push_back(alone),
            (None, Some(bundle)) => self.control_queue.push_back(bundle),
            (None, None) => {}
        }
    }

    /// Puts a control chunk into the first packet of DATA gathered so far that has room for
    /// it, ahead of the DATA chunks (RFC 9260 6.10: control chunks come first). `false` when
    /// no packet has room: the chunk then travels in a packet of its own.
    pub(super) fn bundle_with_data(
        &self,
        chunk: &dyn Chunk,
        raw_packets: &mut [Bytes],
        first_data_packet: usize,
    ) -> bool {
        let wire = chunk_wire_size(chunk);
        let header = COMMON_HEADER_SIZE as usize;
        let Some(slot) = raw_packets.iter_mut().skip(first_data_packet).find(|raw| {
            raw.len() > header
                && (raw[header] == CT_PAYLOAD_DATA.0 || raw[header] == CT_I_DATA.0)
                && raw.len() + wire <= self.mtu as usize
        }) else {
            return false;
        };
        let common_header = CommonHeader {
            verification_tag: self.peer_verification_tag,
            source_port: self.source_port,
            destination_port: self.destination_port,
        };
        let mut buf = BytesMut::with_capacity(slot.len() + wire);
        if Packet::write_framed(&common_header, std::iter::once(chunk), &mut buf).is_err() {
            return false;
        }
        buf.extend_from_slice(&slot[header..]);
        // The checksum covers the packet with its checksum field zero.
        buf[8..12].copy_from_slice(&[0; 4]);
        let checksum = crc32c::crc32c(&buf);
        buf[8..12].copy_from_slice(&checksum.to_le_bytes());
        *slot = buf.freeze();
        true
    }
}
