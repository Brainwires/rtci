#[cfg(test)]
mod chandata_test;

use super::channum::*;
use shared::error::{Error, Result};

const PADDING: usize = 4;

fn nearest_padded_value_length(l: usize) -> usize {
    let mut n = PADDING * (l / PADDING);
    if n < l {
        n += PADDING;
    }
    n
}

const CHANNEL_DATA_LENGTH_SIZE: usize = 2;
const CHANNEL_DATA_NUMBER_SIZE: usize = CHANNEL_DATA_LENGTH_SIZE;
const CHANNEL_DATA_HEADER_SIZE: usize = CHANNEL_DATA_LENGTH_SIZE + CHANNEL_DATA_NUMBER_SIZE;

/// `ChannelData` represents the `ChannelData` Message defined in
/// [RFC 8656 Section 12.4](https://www.rfc-editor.org/rfc/rfc8656#section-12.4).
#[derive(Default, Debug)]
pub struct ChannelData {
    /// The relayed payload. May be a subslice of [`Self::raw`].
    pub data: Vec<u8>, // can be subslice of Raw
    /// The channel this data belongs to, which identifies the peer.
    pub number: ChannelNumber,
    /// The full encoded message, header included.
    pub raw: Vec<u8>,
}

impl PartialEq for ChannelData {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.number == other.number
    }
}

impl ChannelData {
    /// Resets length, [`Self::data`] and [`Self::raw`] length.
    #[inline]
    pub fn reset(&mut self) {
        self.raw.clear();
        self.data.clear();
    }

    /// Encodes this to [`Self::raw`].
    ///
    /// # Errors
    ///
    /// Fails if [`Self::data`] is longer than the 16-bit length field can say (65 535 bytes,
    /// RFC 8656 §12.4). Nothing is written then.
    pub fn encode(&mut self) -> Result<()> {
        if self.data.len() > usize::from(u16::MAX) {
            return Err(Error::ErrBadChannelDataLength);
        }
        self.raw.clear();
        self.write_header()?;
        self.raw.extend_from_slice(&self.data);
        let padded = nearest_padded_value_length(self.raw.len());
        let bytes_to_add = padded - self.raw.len();
        if bytes_to_add > 0 {
            self.raw.extend_from_slice(&vec![0; bytes_to_add]);
        }
        Ok(())
    }

    /// Decodes this from [`Self::raw`].
    pub fn decode(&mut self) -> Result<()> {
        let buf = &self.raw;
        if buf.len() < CHANNEL_DATA_HEADER_SIZE {
            return Err(Error::ErrUnexpectedEof);
        }
        let num = u16::from_be_bytes([buf[0], buf[1]]);
        self.number = ChannelNumber(num);
        if !self.number.valid() {
            return Err(Error::ErrInvalidChannelNumber);
        }
        let l = u16::from_be_bytes([
            buf[CHANNEL_DATA_NUMBER_SIZE],
            buf[CHANNEL_DATA_NUMBER_SIZE + 1],
        ]) as usize;
        if l > buf[CHANNEL_DATA_HEADER_SIZE..].len() {
            return Err(Error::ErrBadChannelDataLength);
        }
        self.data = buf[CHANNEL_DATA_HEADER_SIZE..CHANNEL_DATA_HEADER_SIZE + l].to_vec();

        Ok(())
    }

    /// Writes channel number and length.
    ///
    /// # Errors
    ///
    /// Fails if [`Self::data`] is longer than the length field can say; the header is left
    /// as it was.
    pub fn write_header(&mut self) -> Result<()> {
        let length = u16::try_from(self.data.len()).map_err(|_| Error::ErrBadChannelDataLength)?;
        if self.raw.len() < CHANNEL_DATA_HEADER_SIZE {
            // Making WriteHeader call valid even when c.Raw
            // is nil or len(c.Raw) is less than needed for header.
            self.raw
                .resize(self.raw.len() + CHANNEL_DATA_HEADER_SIZE, 0);
        }
        self.raw[..CHANNEL_DATA_NUMBER_SIZE].copy_from_slice(&self.number.0.to_be_bytes());
        self.raw[CHANNEL_DATA_NUMBER_SIZE..CHANNEL_DATA_HEADER_SIZE]
            .copy_from_slice(&length.to_be_bytes());
        Ok(())
    }

    /// Returns `true` if `buf` looks like the `ChannelData` Message.
    pub fn is_channel_data(buf: &[u8]) -> bool {
        if buf.len() < CHANNEL_DATA_HEADER_SIZE {
            return false;
        }

        if u16::from_be_bytes([
            buf[CHANNEL_DATA_NUMBER_SIZE],
            buf[CHANNEL_DATA_NUMBER_SIZE + 1],
        ]) > buf[CHANNEL_DATA_HEADER_SIZE..].len() as u16
        {
            return false;
        }

        // Quick check for channel number.
        let num = ChannelNumber(u16::from_be_bytes([buf[0], buf[1]]));
        num.valid()
    }
}
