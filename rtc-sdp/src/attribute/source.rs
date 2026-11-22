//! `a=ssrc` and `a=ssrc-group` (RFC 5576).

use std::fmt;

use shared::error::Result;

use super::{Fmtp, Msid, TypedAttribute};
use crate::grammar::{self, syntax};

/// `ssrc-id`: "0 .. 2**32 - 1", written without leading zeroes.
fn ssrc_id(what: &str, value: &str) -> Result<u32> {
    grammar::digits_no_leading_zero(what, value)
}

/// `a=ssrc:<ssrc-id> <attribute>[:<value>]` (RFC 5576 section 4.1): one source attribute of
/// one synchronization source.
///
/// A source with several attributes has several lines. The source attributes RFC 5576
/// defines are `cname` (section 6.1), `previous-ssrc` (section 6.2) and `fmtp`
/// (section 6.3); WebRTC endpoints also write `msid` (draft-ietf-mmusic-msid, before
/// RFC 8830 moved it to the media level) and the unregistered `mslabel` and `label`. Any
/// other attribute name is kept: [`Ssrc::attribute`] and [`Ssrc::value`] always hold what
/// the line said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssrc {
    /// The synchronization source.
    pub id: u32,
    /// The source attribute's name, a token.
    pub attribute: String,
    /// The source attribute's value: what follows the name's colon.
    pub value: Option<String>,
}

impl Ssrc {
    /// The value of this line's source attribute when it is `name`.
    fn value_if(&self, name: &str) -> Option<&str> {
        if self.attribute == name {
            self.value.as_deref()
        } else {
            None
        }
    }

    /// `cname:<cname>` (RFC 5576 section 6.1): the source's RTCP canonical name.
    pub fn cname(&self) -> Option<&str> {
        self.value_if("cname")
    }

    /// `previous-ssrc:<ssrc-id> *(SP <ssrc-id>)` (RFC 5576 section 6.2): the SSRCs this
    /// source used before. `None` when this line is another attribute.
    pub fn previous_ssrcs(&self) -> Option<Result<Vec<u32>>> {
        let value = self.value_if("previous-ssrc")?;
        Some(grammar::fields("previous-ssrc", value).and_then(|ids| {
            ids.into_iter()
                .map(|id| ssrc_id("previous-ssrc", id))
                .collect()
        }))
    }

    /// `fmtp:<format> <format specific parameters>` (RFC 5576 section 6.3): format
    /// parameters that apply to this source only.
    pub fn fmtp(&self) -> Option<Result<Fmtp>> {
        self.value_if("fmtp").map(Fmtp::parse)
    }

    /// `msid:<id> [<appdata>]`: the MediaStream and track of this source, as endpoints
    /// wrote it before RFC 8830.
    pub fn msid(&self) -> Option<Result<Msid>> {
        self.value_if("msid").map(Msid::parse)
    }
}

impl TypedAttribute for Ssrc {
    const NAME: &'static str = "ssrc";

    fn parse(value: &str) -> Result<Self> {
        let Some((id, attribute)) = value.split_once(' ') else {
            return Err(syntax("a=ssrc", value));
        };
        let id = ssrc_id("a=ssrc", id)?;
        let (name, attribute_value) = match attribute.split_once(':') {
            Some((name, v)) => (name, Some(v)),
            None => (attribute, None),
        };
        if !grammar::is_token(name) || !attribute_value.is_none_or(grammar::is_byte_string) {
            return Err(syntax("a=ssrc", value));
        }
        let parsed = Ssrc {
            id,
            attribute: name.to_owned(),
            value: attribute_value.map(str::to_owned),
        };
        // The attributes whose grammar is known are checked here, so that a parsed `Ssrc`
        // has none that is malformed.
        match name {
            "cname" if parsed.value.is_none() => return Err(syntax("a=ssrc cname", value)),
            "previous-ssrc" => {
                parsed
                    .previous_ssrcs()
                    .ok_or_else(|| syntax("a=ssrc previous-ssrc", value))??;
            }
            "fmtp" => {
                parsed
                    .fmtp()
                    .ok_or_else(|| syntax("a=ssrc fmtp", value))??;
            }
            "msid" => {
                parsed
                    .msid()
                    .ok_or_else(|| syntax("a=ssrc msid", value))??;
            }
            _ => {}
        }
        Ok(parsed)
    }
}

impl fmt::Display for Ssrc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.id, self.attribute)?;
        if let Some(value) = &self.value {
            write!(f, ":{value}")?;
        }
        Ok(())
    }
}

/// `a=ssrc-group:<semantics> *(SP <ssrc-id>)` (RFC 5576 section 4.2).
///
/// The semantics is a token: `FID` (flow identification: a stream and its retransmission,
/// RFC 4588), `FEC` (RFC 5576), `FEC-FR` (RFC 5956), `DUP` (RFC 7104), `SIM` (the
/// pre-standard simulcast grouping some endpoints write) or any other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsrcGroup {
    /// The semantics token, as written.
    pub semantics: String,
    /// The grouped sources, in order: the order carries meaning (in `FID`, the first is the
    /// media stream).
    pub ssrcs: Vec<u32>,
}

impl TypedAttribute for SsrcGroup {
    const NAME: &'static str = "ssrc-group";

    fn parse(value: &str) -> Result<Self> {
        let mut fields = grammar::fields("a=ssrc-group", value)?.into_iter();
        let semantics = fields.next().unwrap_or_default();
        if !grammar::is_token(semantics) {
            return Err(syntax("a=ssrc-group", value));
        }
        Ok(SsrcGroup {
            semantics: semantics.to_owned(),
            ssrcs: fields
                .map(|id| ssrc_id("a=ssrc-group", id))
                .collect::<Result<_>>()?,
        })
    }
}

impl fmt::Display for SsrcGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.semantics)?;
        for ssrc in &self.ssrcs {
            write!(f, " {ssrc}")?;
        }
        Ok(())
    }
}
