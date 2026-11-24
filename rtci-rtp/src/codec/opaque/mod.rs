//! A format-agnostic payload: arbitrary bytes split into RTP payloads without being parsed,
//! for frames whose content the RTP layer cannot read, such as SFrame ciphertexts (RFC 9605
//! sections 4.2 and 6.2: a whole-frame ciphertext spans packets; the codec payloaders all
//! parse what they are given, an encrypted frame cannot be).
//!
//! Each payload starts with one byte of flags, so that the start and the end of a unit are
//! explicit in the payload rather than only in the RTP marker bit (several units, one per
//! layer, can share an RTP timestamp, and only the last carries the marker):
//!
//! ```text
//!  0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+
//! |S|E|  reserved |
//! +-+-+-+-+-+-+-+-+
//! ```
//!
//! `S` is set on the first payload of a unit, `E` on its last; reserved bits are sent as zero
//! and ignored. This is the engine's own framing, not the SFrame RTP payload format of
//! draft-ietf-avtcore-rtp-sframe, whose layout and negotiation are still to be adopted.

#[cfg(test)]
mod opaque_test;

use crate::packetizer::{Depacketizer, Payloader};
use bytes::{BufMut, Bytes, BytesMut};
use shared::error::{Error, Result};

/// Size of the payload header.
pub const OPAQUE_HEADER_SIZE: usize = 1;
/// The start-of-unit flag.
pub const OPAQUE_START: u8 = 0x80;
/// The end-of-unit flag.
pub const OPAQUE_END: u8 = 0x40;

/// Splits a unit of arbitrary bytes into payloads of at most `mtu`, each behind the flags
/// byte. An empty unit is one payload with both flags.
#[derive(Default, Debug, Copy, Clone)]
pub struct OpaquePayloader;

impl Payloader for OpaquePayloader {
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        let chunk = mtu
            .checked_sub(OPAQUE_HEADER_SIZE)
            .filter(|&chunk| chunk > 0)
            .ok_or(Error::ErrShortBuffer)?;
        let mut out = Vec::with_capacity(payload.len() / chunk + 1);
        let mut rest = payload.as_ref();
        let mut first = true;
        loop {
            let take = rest.len().min(chunk);
            let last = take == rest.len();
            let mut flags = 0;
            if first {
                flags |= OPAQUE_START;
            }
            if last {
                flags |= OPAQUE_END;
            }
            let mut buf = BytesMut::with_capacity(OPAQUE_HEADER_SIZE + take);
            buf.put_u8(flags);
            buf.put_slice(&rest[..take]);
            out.push(buf.freeze());
            rest = &rest[take..];
            first = false;
            if last {
                return Ok(out);
            }
        }
    }

    fn clone_to(&self) -> Box<dyn Payloader> {
        Box::new(*self)
    }
}

/// Reassembles the units [`OpaquePayloader`] split. A unit is returned when its `E` payload
/// arrives; a payload that continues a unit whose start was not seen (a lost packet) drops
/// the unit whole: the bytes of a ciphertext are useless without all of them.
#[derive(Default, Debug, Clone)]
pub struct OpaqueDepacketizer {
    unit: Option<BytesMut>,
}

impl Depacketizer for OpaqueDepacketizer {
    /// Returns the reassembled unit on its last payload, and an empty `Bytes` before then (or
    /// for a payload of a unit whose start was lost).
    fn depacketize(&mut self, payload: &Bytes) -> Result<Bytes> {
        let Some((&flags, data)) = payload.split_first() else {
            return Err(Error::ErrShortPacket);
        };
        if flags & OPAQUE_START != 0 {
            self.unit = Some(BytesMut::new());
        }
        let Some(unit) = self.unit.as_mut() else {
            return Ok(Bytes::new());
        };
        unit.put_slice(data);
        if flags & OPAQUE_END != 0 {
            return Ok(self.unit.take().map(BytesMut::freeze).unwrap_or_default());
        }
        Ok(Bytes::new())
    }

    fn is_partition_head(&self, payload: &Bytes) -> bool {
        payload
            .first()
            .is_some_and(|flags| flags & OPAQUE_START != 0)
    }

    fn is_partition_tail(&self, _marker: bool, payload: &Bytes) -> bool {
        payload.first().is_some_and(|flags| flags & OPAQUE_END != 0)
    }
}
