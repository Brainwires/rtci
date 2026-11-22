#[cfg(test)]
mod csrc_audio_level_extension_test;

use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut};

/// The most levels one element carries: one per CSRC, and a packet has at most 15 CSRCs
/// (RFC 6465 section 4, RFC 3550 section 5.1).
pub const CSRC_AUDIO_LEVEL_MAX_COUNT: usize = 15;
/// The level of digital silence, and the quietest level there is: -127 dBov.
pub const CSRC_AUDIO_LEVEL_SILENCE: u8 = 127;

/// The mixer-to-client audio level extension ([RFC 6465]): the level of each contributing
/// source of a mixed packet, in the order of the packet's CSRC list.
///
/// One-byte form, for three CSRCs (`len` is the count less one):
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  ID   | len=2 |0|   level 1   |0|   level 2   |0|   level 3   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// In the two-byte form `len` is the count. Each level is 0 to 127, meaning 0 to -127 dBov;
/// the top bit of each byte is reserved: written as 0 and ignored when read.
///
/// [RFC 6465]: https://datatracker.ietf.org/doc/html/rfc6465
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct CsrcAudioLevelExtension {
    /// One level per CSRC, in the order of the CSRC list: 0 (loudest) to 127 (silence).
    pub levels: Vec<u8>,
}

impl CsrcAudioLevelExtension {
    /// Pairs each level with its contributing source.
    ///
    /// # Errors
    ///
    /// Fails when the number of levels is not the number of CSRCs: the two lists match in
    /// number and order (RFC 6465 section 3), so anything else cannot be attributed.
    pub fn pair_with(&self, csrc: &[u32]) -> Result<Vec<(u32, u8)>> {
        if self.levels.len() != csrc.len() {
            return Err(Error::Other(format!(
                "csrc-audio-level: {} levels for {} CSRCs",
                self.levels.len(),
                csrc.len()
            )));
        }
        Ok(csrc
            .iter()
            .copied()
            .zip(self.levels.iter().copied())
            .collect())
    }
}

impl Unmarshal for CsrcAudioLevelExtension {
    /// Reads the whole buffer: one level per byte. An empty element has no level.
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if raw_packet.remaining() > CSRC_AUDIO_LEVEL_MAX_COUNT {
            return Err(Error::Other(format!(
                "csrc-audio-level: {} levels, more than the {CSRC_AUDIO_LEVEL_MAX_COUNT} CSRCs \
                 a packet can have",
                raw_packet.remaining()
            )));
        }
        let mut levels = Vec::with_capacity(raw_packet.remaining());
        while raw_packet.has_remaining() {
            // The top bit is reserved.
            levels.push(raw_packet.get_u8() & 0x7F);
        }
        Ok(CsrcAudioLevelExtension { levels })
    }
}

impl MarshalSize for CsrcAudioLevelExtension {
    fn marshal_size(&self) -> usize {
        self.levels.len()
    }
}

impl Marshal for CsrcAudioLevelExtension {
    /// # Errors
    ///
    /// Fails for more than 15 levels (RFC 6465 section 4: they MUST NOT be included) and for a
    /// level above 127.
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if self.levels.len() > CSRC_AUDIO_LEVEL_MAX_COUNT {
            return Err(Error::TooManyCSRCs(self.levels.len()));
        }
        if buf.remaining_mut() < self.levels.len() {
            return Err(Error::ErrBufferTooSmall);
        }
        for &level in &self.levels {
            if level > CSRC_AUDIO_LEVEL_SILENCE {
                return Err(Error::AudioLevelOverflow);
            }
            buf.put_u8(level);
        }
        Ok(self.levels.len())
    }
}
