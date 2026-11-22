//! `a=fingerprint` (RFC 8122), `a=setup` (RFC 4145), `a=tls-id` (RFC 8842) and
//! `a=identity` (RFC 8827).

use std::fmt;

use shared::error::Result;

use super::{TypedAttribute, string_attribute};
use crate::grammar::{self, invalid, syntax};
use crate::util::ConnectionRole;

/// `a=fingerprint:<hash-func> <fingerprint>` (RFC 8122 section 5).
///
/// ```text
/// fingerprint-attribute = "fingerprint" ":" hash-func SP fingerprint
/// hash-func             = "sha-1" / "sha-224" / "sha-256" / "sha-384" / "sha-512"
///                       / "md5" / "md2" / token
/// fingerprint           = 2UHEX *(":" 2UHEX)
/// ```
///
/// Two things are wider or narrower than that grammar. Lower-case hexadecimal digits are
/// accepted (`UHEX` is upper case only, and some endpoints write lower case); compare
/// fingerprints by [`Fingerprint::bytes`], not as text. And for the hash functions the
/// grammar names, the fingerprint must have the length of that hash: a `sha-256`
/// fingerprint that is not 32 bytes cannot match any certificate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    /// The hash function, as written. RFC 8122 writes them in lower case; compare without
    /// regard to case.
    pub hash_function: String,
    /// The digest.
    pub bytes: Vec<u8>,
}

impl Fingerprint {
    /// The digest length of a hash function the RFC 8122 grammar names.
    fn digest_len(hash_function: &str) -> Option<usize> {
        Some(match hash_function.to_ascii_lowercase().as_str() {
            "md2" | "md5" => 16,
            "sha-1" => 20,
            "sha-224" => 28,
            "sha-256" => 32,
            "sha-384" => 48,
            "sha-512" => 64,
            _ => return None,
        })
    }
}

impl TypedAttribute for Fingerprint {
    const NAME: &'static str = "fingerprint";

    fn parse(value: &str) -> Result<Self> {
        let Some((hash_function, fingerprint)) = value.split_once(' ') else {
            return Err(syntax("a=fingerprint", value));
        };
        if !grammar::is_token(hash_function) {
            return Err(syntax("a=fingerprint", value));
        }
        let mut bytes = Vec::with_capacity(fingerprint.len() / 3 + 1);
        for pair in fingerprint.split(':') {
            match pair.as_bytes() {
                [high, low] if high.is_ascii_hexdigit() && low.is_ascii_hexdigit() => {
                    let digit = |b: u8| (b as char).to_digit(16).unwrap_or(0) as u8;
                    bytes.push(digit(*high) << 4 | digit(*low));
                }
                _ => return Err(syntax("a=fingerprint", value)),
            }
        }
        if Self::digest_len(hash_function).is_some_and(|len| len != bytes.len()) {
            return Err(invalid("a=fingerprint length", value));
        }
        Ok(Fingerprint {
            hash_function: hash_function.to_owned(),
            bytes,
        })
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", self.hash_function)?;
        for (i, byte) in self.bytes.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

/// `a=setup:<role>` (RFC 4145 section 4): `active`, `passive`, `actpass` or `holdconn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setup(pub ConnectionRole);

impl TypedAttribute for Setup {
    const NAME: &'static str = "setup";

    fn parse(value: &str) -> Result<Self> {
        match ConnectionRole::from(value) {
            ConnectionRole::Unspecified => Err(syntax("a=setup", value)),
            role => Ok(Setup(role)),
        }
    }
}

impl fmt::Display for Setup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

string_attribute!(
    /// `a=tls-id:<id>` (RFC 8842 section 4): `20*255(tls-id-char)`,
    /// `tls-id-char = ALPHA / DIGIT / "+" / "/" / "-" / "_"`.
    TlsId,
    "tls-id",
    "a=tls-id",
    |v| (20..=255).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_'))
);

/// `a=identity:<assertion> *(SP <extension>)` (RFC 8827 section 5).
///
/// ```text
/// identity-assertion       = identity-assertion-value *(SP identity-extension)
/// identity-assertion-value = base64
/// identity-extension       = extension-name [ "=" extension-value ]
/// extension-name           = token
/// extension-value          = 1*(%x01-09 / %x0b-0c / %x0e-3a / %x3c-ff)
/// ```
///
/// This is the syntax only: the engine does not implement identity providers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The assertion, base64 text as written (it decodes to a JSON object).
    pub assertion: String,
    /// The extensions, as `(name, value)`, in order.
    pub extensions: Vec<(String, Option<String>)>,
}

impl TypedAttribute for Identity {
    const NAME: &'static str = "identity";

    fn parse(value: &str) -> Result<Self> {
        let mut fields = grammar::fields("a=identity", value)?.into_iter();
        let assertion = fields.next().unwrap_or_default();
        if !grammar::is_base64(assertion) {
            return Err(syntax("a=identity", "(assertion)"));
        }
        let mut extensions = Vec::new();
        for extension in fields {
            let (name, extension_value) = match extension.split_once('=') {
                Some((name, v)) => (name, Some(v)),
                None => (extension, None),
            };
            if !grammar::is_token(name)
                || !extension_value.is_none_or(|v| !v.is_empty() && !v.contains(';'))
            {
                return Err(syntax("a=identity extension", extension));
            }
            extensions.push((name.to_owned(), extension_value.map(str::to_owned)));
        }
        Ok(Identity {
            assertion: assertion.to_owned(),
            extensions,
        })
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.assertion)?;
        for (name, value) in &self.extensions {
            write!(f, " {name}")?;
            if let Some(value) = value {
                write!(f, "={value}")?;
            }
        }
        Ok(())
    }
}
