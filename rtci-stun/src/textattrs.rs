#[cfg(test)]
mod textattrs_test;

use crate::attributes::*;
use crate::checks::*;
use crate::message::*;
use shared::error::*;

use std::fmt;

/// The longest USERNAME that is sent: "fewer than 509 bytes" (RFC 8489 section 14.3).
pub const MAX_USERNAME_B: usize = 508;
/// The longest REALM, NONCE, SOFTWARE or reason phrase that is sent, in bytes (RFC 8489
/// sections 14.8 to 14.10 and 14.14).
pub const MAX_TEXT_B: usize = 509;
/// REALM, NONCE, SOFTWARE and the reason phrase are fewer than this many characters.
pub const MAX_TEXT_CHARS: usize = 128;
/// The longest ALTERNATE-DOMAIN, in bytes (RFC 8489 section 14.16).
pub const MAX_ALTERNATE_DOMAIN_B: usize = 255;

/// USERNAME attribute.
///
/// RFC 8489 Section 14.3.
pub type Username = TextAttribute;

/// REALM attribute.
///
/// RFC 8489 Section 14.9.
pub type Realm = TextAttribute;

/// NONCE attribute.
///
/// RFC 8489 Section 14.10.
pub type Nonce = TextAttribute;

/// SOFTWARE attribute.
///
/// RFC 8489 Section 14.14.
pub type Software = TextAttribute;

/// ALTERNATE-DOMAIN attribute.
///
/// RFC 8489 Section 14.16.
pub type AlternateDomain = TextAttribute;

/// Whether `name` is a DNS host name as RFC 1123 section 2.1 has it (A-labels included):
/// labels of 1 to 63 letters, digits and hyphens that neither start nor end with a hyphen,
/// separated by dots, 255 bytes at most. A trailing dot is allowed.
fn is_dns_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= MAX_ALTERNATE_DOMAIN_B
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

// TextAttribute is helper for adding and getting text attributes.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
/// A text-valued attribute: `USERNAME`, `REALM`, `NONCE`, `SOFTWARE` or `ALTERNATE-DOMAIN`.
///
/// What is sent keeps the limits of RFC 8489: a USERNAME is fewer than 509 bytes; a REALM, a
/// NONCE and a SOFTWARE are fewer than 128 characters and at most 509 bytes; an
/// ALTERNATE-DOMAIN is a DNS name of at most 255 bytes. What is received is taken at any
/// length (the RFC asks for at least 763 bytes), as long as it is UTF-8.
///
/// USERNAME and REALM are to be OpaqueString-processed (RFC 8265) before they are sent: see
/// [`opaque_string`](crate::opaque::opaque_string).
pub struct TextAttribute {
    /// Which attribute this text belongs to.
    pub attr: AttrType,
    /// The text value.
    pub text: String,
}

impl fmt::Display for TextAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

impl Setter for TextAttribute {
    /// Adds the attribute to `m`.
    ///
    /// # Errors
    ///
    /// Fails with `ErrAttributeSizeOverflow` when the text is longer than RFC 8489 lets the
    /// attribute be, and for an ALTERNATE-DOMAIN that is not a DNS name.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        let text = self.text.as_bytes();
        let (max_len, max_chars) = match self.attr {
            ATTR_USERNAME => (MAX_USERNAME_B, None),
            ATTR_REALM | ATTR_SOFTWARE | ATTR_NONCE => (MAX_TEXT_B, Some(MAX_TEXT_CHARS)),
            ATTR_ALTERNATE_DOMAIN => (MAX_ALTERNATE_DOMAIN_B, None),
            _ => return Err(Error::Other(format!("Unsupported AttrType {}", self.attr))),
        };

        check_overflow(self.attr, text.len(), max_len)?;
        if let Some(max_chars) = max_chars
            && self.text.chars().count() >= max_chars
        {
            return Err(Error::ErrAttributeSizeOverflow);
        }
        if self.attr == ATTR_ALTERNATE_DOMAIN && !is_dns_name(&self.text) {
            return Err(Error::Other(format!(
                "ALTERNATE-DOMAIN {:?} is not a DNS name",
                self.text
            )));
        }
        m.add(self.attr, text);
        Ok(())
    }
}

impl Getter for TextAttribute {
    fn get_from(&mut self, m: &Message) -> Result<()> {
        let attr = self.attr;
        *self = TextAttribute::get_from_as(m, attr)?;
        Ok(())
    }
}

impl TextAttribute {
    /// A text attribute of type `attr` holding `text`.
    pub fn new(attr: AttrType, text: String) -> Self {
        TextAttribute { attr, text }
    }

    /// Get_from_as gets t attribute from m and appends its value to reset v.
    pub fn get_from_as(m: &Message, attr: AttrType) -> Result<Self> {
        match attr {
            ATTR_USERNAME => {}
            ATTR_REALM => {}
            ATTR_SOFTWARE => {}
            ATTR_NONCE => {}
            ATTR_ALTERNATE_DOMAIN => {}
            _ => return Err(Error::Other(format!("Unsupported AttrType {attr}"))),
        };

        let a = m.get(attr)?;
        let text = String::from_utf8(a)?;
        if attr == ATTR_ALTERNATE_DOMAIN && !is_dns_name(&text) {
            return Err(Error::Other(format!(
                "ALTERNATE-DOMAIN {text:?} is not a DNS name"
            )));
        }
        Ok(TextAttribute { attr, text })
    }
}
