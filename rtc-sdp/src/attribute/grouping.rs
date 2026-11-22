//! `a=group`, `a=mid` (RFC 5888, RFC 9143) and `a=msid`, `a=msid-semantic` (RFC 8830).

use std::fmt;

use shared::error::Result;

use super::{TypedAttribute, string_attribute};
use crate::description::session::SEMANTIC_TOKEN_BUNDLE;
use crate::grammar::{self, syntax};

/// `a=group:<semantics> *(SP <identification-tag>)` (RFC 5888 section 5).
///
/// The semantics is a token: `LS` and `FID` (RFC 5888), `BUNDLE` (RFC 9143), `SRF`
/// (RFC 3524), `ANAT` (RFC 4091), `FEC` (RFC 4756), `FEC-FR` (RFC 5956), `CS` (RFC 5432),
/// `DDP` (RFC 5583), `DUP` (RFC 7104), or any other registered one. A group may be empty:
/// RFC 9143 section 7.3.1 has an answerer write `a=group:BUNDLE` with no tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// The semantics token, as written (it is case-sensitive).
    pub semantics: String,
    /// The identification tags (the `a=mid` values) of the grouped m= sections, in order.
    pub mids: Vec<String>,
}

impl Group {
    /// Whether this is a `BUNDLE` group (RFC 9143).
    pub fn is_bundle(&self) -> bool {
        self.semantics == SEMANTIC_TOKEN_BUNDLE
    }

    /// Whether `mid` is in the group.
    pub fn contains(&self, mid: &str) -> bool {
        self.mids.iter().any(|m| m == mid)
    }
}

impl TypedAttribute for Group {
    const NAME: &'static str = "group";

    fn parse(value: &str) -> Result<Self> {
        let mut fields = grammar::fields("a=group", value)?.into_iter();
        // `fields` never returns an empty list.
        let semantics = fields.next().unwrap_or_default();
        let mids: Vec<String> = fields.map(str::to_owned).collect();
        if !grammar::is_token(semantics) || !mids.iter().all(|m| grammar::is_token(m)) {
            return Err(syntax("a=group", value));
        }
        Ok(Group {
            semantics: semantics.to_owned(),
            mids,
        })
    }
}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.semantics)?;
        for mid in &self.mids {
            write!(f, " {mid}")?;
        }
        Ok(())
    }
}

string_attribute!(
    /// `a=mid:<identification-tag>` (RFC 5888 section 4): a token.
    Mid,
    "mid",
    "a=mid",
    |v| grammar::is_token(v)
);

/// `1*64token-char`.
fn is_msid_token(value: &str) -> bool {
    value.len() <= 64 && grammar::is_token(value)
}

/// `a=msid:<msid-id> [SP <msid-appdata>]` (RFC 8830 section 2).
///
/// The id names a MediaStream, or is `-` for a track that is in none (RFC 9429 section
/// 5.2.1); the application data, when present, is the track id. A media section has one
/// line per MediaStream its track is in.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Msid {
    /// The MediaStream id: 1 to 64 token characters.
    pub id: String,
    /// The application data: 1 to 64 token characters.
    pub appdata: Option<String>,
}

impl TypedAttribute for Msid {
    const NAME: &'static str = "msid";

    fn parse(value: &str) -> Result<Self> {
        let (id, appdata) = match value.split_once(' ') {
            Some((id, appdata)) => (id, Some(appdata)),
            None => (value, None),
        };
        if !is_msid_token(id) || !appdata.is_none_or(is_msid_token) {
            return Err(syntax("a=msid", value));
        }
        Ok(Msid {
            id: id.to_owned(),
            appdata: appdata.map(str::to_owned),
        })
    }
}

impl fmt::Display for Msid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.id)?;
        if let Some(appdata) = &self.appdata {
            write!(f, " {appdata}")?;
        }
        Ok(())
    }
}

/// `a=msid-semantic:<semantic> *(SP <msid-id>)`.
///
/// draft-ietf-mmusic-msid defined it and RFC 8830 dropped it, but browsers still write
/// `a=msid-semantic: WMS` (Chrome, with a space after the colon) or
/// `a=msid-semantic:WMS *` (Firefox). One leading space is accepted for that reason; the
/// ids are tokens, or `*` for "all".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsidSemantic {
    /// The semantic token: `WMS` for WebRTC MediaStreams.
    pub semantic: String,
    /// The MediaStream ids the semantic applies to; `*` stands for all of them.
    pub ids: Vec<String>,
}

impl TypedAttribute for MsidSemantic {
    const NAME: &'static str = "msid-semantic";

    fn parse(value: &str) -> Result<Self> {
        let mut fields =
            grammar::fields("a=msid-semantic", value.strip_prefix(' ').unwrap_or(value))?
                .into_iter();
        let semantic = fields.next().unwrap_or_default();
        let ids: Vec<String> = fields.map(str::to_owned).collect();
        if !grammar::is_token(semantic) || !ids.iter().all(|id| is_msid_token(id)) {
            return Err(syntax("a=msid-semantic", value));
        }
        Ok(MsidSemantic {
            semantic: semantic.to_owned(),
            ids,
        })
    }
}

impl fmt::Display for MsidSemantic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.semantic)?;
        for id in &self.ids {
            write!(f, " {id}")?;
        }
        Ok(())
    }
}
