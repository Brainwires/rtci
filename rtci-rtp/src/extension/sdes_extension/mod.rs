//! RTCP source description items carried in RTP header extensions ([RFC 7941]): the media
//! identification (MID, [RFC 8843]) and the RTP stream identifiers (RtpStreamId and
//! RepairedRtpStreamId, [RFC 8852]).
//!
//! The element is the item's text and nothing else: UTF-8, not null terminated, 1 to 16 bytes
//! in the one-byte header form and up to 255 in the two-byte form (RFC 7941 section 4.1).
//!
//! [RFC 7941]: https://datatracker.ietf.org/doc/html/rfc7941
//! [RFC 8843]: https://datatracker.ietf.org/doc/html/rfc8843
//! [RFC 8852]: https://datatracker.ietf.org/doc/html/rfc8852
#[cfg(test)]
mod sdes_extension_test;

use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut};

use crate::header::ONE_BYTE_EXTENSION_MAX_LEN;

/// The longest SDES item text: the RTCP SDES length field is one octet (RFC 3550 section 6.5).
pub const SDES_ITEM_MAX_LEN: usize = 255;

fn check_text(what: &str, text: &str) -> Result<()> {
    if text.is_empty() || text.len() > SDES_ITEM_MAX_LEN {
        return Err(Error::Other(format!(
            "{what}: {} bytes, where 1 to {SDES_ITEM_MAX_LEN} are allowed",
            text.len()
        )));
    }
    Ok(())
}

fn check_rid(what: &str, text: &str) -> Result<()> {
    check_text(what, text)?;
    // RFC 8852 section 3: ASCII alphanumerics only (48-57, 65-90, 97-122).
    if !text.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(Error::Other(format!(
            "{what}: only ASCII letters and digits are allowed"
        )));
    }
    Ok(())
}

fn read_text<B: Buf>(what: &str, buf: &mut B) -> Result<String> {
    let bytes = buf.copy_to_bytes(buf.remaining());
    // Text that is not UTF-8 is not a value: an error, not an empty identifier.
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Error::Other(format!("{what}: not UTF-8")))?;
    Ok(text.to_owned())
}

macro_rules! sdes_item {
    ($(#[$doc:meta])* $name:ident, $what:literal, $check:ident) => {
        $(#[$doc])*
        #[derive(PartialEq, Eq, Debug, Clone, Hash)]
        pub struct $name(String);

        impl $name {
            /// Checks the value and wraps it.
            ///
            /// # Errors
            ///
            /// Fails for a value this item cannot hold: see the type's description.
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                $check($what, &value)?;
                Ok(Self(value))
            }

            /// The value.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Whether the value fits an element of the one-byte header form, which holds at
            /// most 16 bytes. A longer value needs the two-byte form, and then every element
            /// of the packet uses it (RFC 7941 section 4.2.1).
            pub fn fits_one_byte_form(&self) -> bool {
                self.0.len() <= ONE_BYTE_EXTENSION_MAX_LEN
            }
        }

        impl Unmarshal for $name {
            /// Reads the whole buffer as the item's text.
            fn unmarshal<B>(buf: &mut B) -> Result<Self>
            where
                Self: Sized,
                B: Buf,
            {
                Self::new(read_text($what, buf)?)
            }
        }

        impl MarshalSize for $name {
            fn marshal_size(&self) -> usize {
                self.0.len()
            }
        }

        impl Marshal for $name {
            fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
                if buf.remaining_mut() < self.0.len() {
                    return Err(Error::ErrBufferTooSmall);
                }
                buf.put_slice(self.0.as_bytes());
                Ok(self.0.len())
            }
        }
    };
}

sdes_item!(
    /// The media identification of RFC 8843, `urn:ietf:params:rtp-hdrext:sdes:mid`: the
    /// `a=mid` value of the media section the packet belongs to. UTF-8 text of 1 to 255 bytes.
    Mid,
    "sdes:mid",
    check_text
);
sdes_item!(
    /// The RTP stream identifier of RFC 8852, `urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id`:
    /// the `a=rid` value of the encoding a stream carries. 1 to 255 ASCII letters and digits
    /// (RFC 8852 section 3); anything else is refused.
    RtpStreamId,
    "sdes:rtp-stream-id",
    check_rid
);
sdes_item!(
    /// The repaired RTP stream identifier of RFC 8852,
    /// `urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id`: on a redundancy stream (RTX,
    /// FEC), the RtpStreamId of the stream it repairs. Same values as [`RtpStreamId`].
    RepairedRtpStreamId,
    "sdes:repaired-rtp-stream-id",
    check_rid
);
