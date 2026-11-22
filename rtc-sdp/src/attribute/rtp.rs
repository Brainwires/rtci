//! `a=rtpmap`, `a=fmtp`, `a=ptime`, `a=maxptime`, `a=framerate` (RFC 8866 section 6),
//! `a=imageattr` (RFC 6236) and `a=content` (RFC 4796).

use std::fmt;

use shared::error::Result;

use super::TypedAttribute;
use crate::grammar::{self, invalid, syntax};

/// An RTP payload type: `zero-based-integer`, 0 to 127.
pub(crate) fn payload_type(what: &str, value: &str) -> Result<u8> {
    let pt: u8 = grammar::digits_no_leading_zero(what, value)?;
    if pt > 127 {
        return Err(invalid(what, value));
    }
    Ok(pt)
}

/// `a=rtpmap:<payload type> <encoding name>/<clock rate>[/<encoding params>]` (RFC 8866
/// section 6.6).
///
/// ```text
/// rtpmap-value    = payload-type SP encoding-name "/" clock-rate [ "/" encoding-params ]
/// payload-type    = zero-based-integer
/// encoding-name   = token
/// clock-rate      = integer
/// encoding-params = channels
/// channels        = integer
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RtpMap {
    /// The payload type, 0 to 127.
    pub payload_type: u8,
    /// The encoding name, as written. Names are compared without regard to case
    /// (section 6.6): see [`RtpMap::is_encoding`].
    pub encoding_name: String,
    /// The RTP clock rate, in Hz. Never zero.
    pub clock_rate: u32,
    /// The number of audio channels, when the line gives it. Section 6.6: it "MAY be
    /// omitted if the number of channels is one".
    pub channels: Option<u32>,
}

impl RtpMap {
    /// Whether the encoding is `name`, compared as media subtypes are: without regard to
    /// case.
    pub fn is_encoding(&self, name: &str) -> bool {
        self.encoding_name.eq_ignore_ascii_case(name)
    }
}

impl TypedAttribute for RtpMap {
    const NAME: &'static str = "rtpmap";

    fn parse(value: &str) -> Result<Self> {
        let Some((pt, encoding)) = value.split_once(' ') else {
            return Err(syntax("a=rtpmap", value));
        };
        let mut parts = encoding.split('/');
        let (Some(name), Some(clock_rate)) = (parts.next(), parts.next()) else {
            return Err(syntax("a=rtpmap", value));
        };
        let channels = parts.next();
        let integer = |what: &str, v: &str| -> Result<u32> {
            if !grammar::is_integer(v) {
                return Err(syntax(what, value));
            }
            v.parse().map_err(|_| invalid(what, value))
        };
        if parts.next().is_some() || !grammar::is_token(name) {
            return Err(syntax("a=rtpmap", value));
        }
        Ok(RtpMap {
            payload_type: payload_type("a=rtpmap payload type", pt)?,
            encoding_name: name.to_owned(),
            clock_rate: integer("a=rtpmap clock rate", clock_rate)?,
            channels: channels
                .map(|c| integer("a=rtpmap channels", c))
                .transpose()?,
        })
    }
}

impl fmt::Display for RtpMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}/{}",
            self.payload_type, self.encoding_name, self.clock_rate
        )?;
        if let Some(channels) = self.channels {
            write!(f, "/{channels}")?;
        }
        Ok(())
    }
}

/// `a=fmtp:<format> <format specific parameters>` (RFC 8866 section 6.15).
///
/// The parameters are a byte-string that SDP conveys "unchanged" to the format: everything
/// after the first space, spaces included. [`Fmtp::parameter_list`] reads the
/// `name=value;name=value` shape most RTP payload formats use (RFC 4855), without changing
/// the text or the order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fmtp {
    /// The format: for RTP, a payload type.
    pub format: String,
    /// The format-specific parameters, exactly as written.
    pub parameters: String,
}

impl Fmtp {
    /// The format as an RTP payload type, when it is one.
    pub fn payload_type(&self) -> Option<u8> {
        payload_type("fmt", &self.format).ok()
    }

    /// The parameters split at `;`, each into its name and (after the first `=`) its
    /// value, with the white space around them removed, in the order written.
    ///
    /// A part without `=` has no value: `a=fmtp:101 0-16` (RFC 4733 events) is one such
    /// part. Empty parts (a trailing `;`) are skipped.
    pub fn parameter_list(&self) -> Vec<(&str, Option<&str>)> {
        self.parameters
            .split(';')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(|part| match part.split_once('=') {
                Some((name, value)) => (name.trim_end(), Some(value.trim_start())),
                None => (part, None),
            })
            .collect()
    }

    /// The value of the parameter `name`, compared without regard to case (RFC 4855
    /// section 3: parameter names are case-insensitive). The first one wins.
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.parameter_list()
            .into_iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .and_then(|(_, value)| value)
    }
}

impl TypedAttribute for Fmtp {
    const NAME: &'static str = "fmtp";

    fn parse(value: &str) -> Result<Self> {
        match value.split_once(' ') {
            Some((format, parameters))
                if grammar::is_token(format) && grammar::is_byte_string(parameters) =>
            {
                Ok(Fmtp {
                    format: format.to_owned(),
                    parameters: parameters.to_owned(),
                })
            }
            _ => Err(syntax("a=fmtp", value)),
        }
    }
}

impl fmt::Display for Fmtp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.format, self.parameters)
    }
}

/// A value attribute whose value is a `non-zero-int-or-real`.
macro_rules! real_attribute {
    ($(#[$doc:meta])* $name:ident, $key:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// The value as written: an integer, or a real without a trailing zero.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// The value as a number. It is never zero.
            pub fn value(&self) -> f64 {
                // Checked by `parse`: digits with at most one point.
                self.0.parse().unwrap_or(f64::NAN)
            }
        }

        impl TypedAttribute for $name {
            const NAME: &'static str = $key;

            fn parse(value: &str) -> Result<Self> {
                if grammar::is_non_zero_int_or_real(value) {
                    Ok($name(value.to_owned()))
                } else {
                    Err(syntax(concat!("a=", $key), value))
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

real_attribute!(
    /// `a=ptime:<packet time>` (RFC 8866 section 6.4): the length of media in a packet the
    /// receiver prefers, in milliseconds.
    Ptime,
    "ptime"
);
real_attribute!(
    /// `a=maxptime:<maximum packet time>` (RFC 8866 section 6.5): the most media a packet
    /// may carry, in milliseconds.
    MaxPtime,
    "maxptime"
);
real_attribute!(
    /// `a=framerate:<frame rate>` (RFC 8866 section 6.13): the maximum video frame rate, in
    /// frames per second.
    FrameRate,
    "framerate"
);

/// `a=content:<tag>[,<tag>...]` (RFC 4796 section 5): what a media stream shows.
///
/// The tags RFC 4796 defines are `slides`, `speaker`, `sl`, `main` and `alt`; any token is
/// accepted, and one that is not known is to be ignored (section 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    /// The tags, in order. Never empty.
    pub tags: Vec<String>,
}

impl TypedAttribute for Content {
    const NAME: &'static str = "content";

    fn parse(value: &str) -> Result<Self> {
        let tags: Vec<String> = value.split(',').map(str::to_owned).collect();
        if !tags.iter().all(|tag| grammar::is_token(tag)) {
            return Err(syntax("a=content", value));
        }
        Ok(Content { tags })
    }
}

impl fmt::Display for Content {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.tags.join(","))
    }
}

/// A range of an `a=imageattr` set: `xyrange` for `x=` and `y=`, `srange` for `sar=`.
#[derive(Debug, Clone, PartialEq)]
pub enum ImageAttrRange<T> {
    /// One value.
    Value(T),
    /// `[min:max]` or `[min:step:max]` for pixels, `[min-max]` for an aspect ratio.
    Range {
        /// The lower bound.
        min: T,
        /// The step between values, for pixel ranges that give one.
        step: Option<T>,
        /// The upper bound.
        max: T,
    },
    /// `[a,b,...]`: any of the listed values, at least two.
    List(Vec<T>),
}

/// One `[x=...,y=...,...]` set of an `a=imageattr` line.
#[derive(Debug, Clone, PartialEq)]
pub struct ImageAttrSet {
    /// `x=`: the image width, in pixels.
    pub x: ImageAttrRange<u32>,
    /// `y=`: the image height, in pixels.
    pub y: ImageAttrRange<u32>,
    /// `sar=`: the sample (pixel) aspect ratio.
    pub sar: Option<ImageAttrRange<f64>>,
    /// `par=[min-max]`: the picture aspect ratio.
    pub par: Option<(f64, f64)>,
    /// `q=`: the preference for this set, 0.0 to 1.0; 0.5 when absent.
    pub q: Option<f64>,
}

/// The attribute list of one direction of an `a=imageattr` line.
#[derive(Debug, Clone, PartialEq)]
pub enum ImageAttrList {
    /// `*`: no restriction is stated.
    Any,
    /// One or more sets.
    Sets(Vec<ImageAttrSet>),
}

/// `a=imageattr:<pt> (send|recv) <attr-list> [(send|recv) <attr-list>]` (RFC 6236 section
/// 3.1).
///
/// ```text
/// image-attr = "imageattr:" PT 1*2( 1*WSP ( "send" / "recv" ) 1*WSP attr-list )
/// PT         = 1*DIGIT / "*"
/// attr-list  = ( set *(1*WSP set) ) / "*"
/// set        = "[" "x=" xyrange "," "y=" xyrange *( "," key-value ) "]"
/// key-value  = ( "sar=" srange ) / ( "par=" prange ) / ( "q=" qvalue )
/// xyrange    = ( "[" xyvalue ":" [ step ":" ] xyvalue "]" )
///            / ( "[" xyvalue 1*( "," xyvalue ) "]" ) / ( xyvalue )
/// srange     = ( "[" spvalue 1*( "," spvalue ) "]" ) / ( "[" spvalue "-" spvalue "]" )
///            / ( spvalue )
/// prange     = ( "[" spvalue "-" spvalue "]" )
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ImageAttr {
    /// The payload type; `None` for `*`, every payload type of the section.
    pub payload_type: Option<u8>,
    /// What the endpoint sends.
    pub send: Option<ImageAttrList>,
    /// What the endpoint receives.
    pub recv: Option<ImageAttrList>,
    /// Whether `recv` was written before `send`. Both orders mean the same.
    pub recv_first: bool,
}

/// `xyvalue = onetonine *5DIGIT`.
fn xyvalue(value: &str, v: &str) -> Result<u32> {
    if !grammar::is_integer(v) || v.len() > 6 {
        return Err(syntax("a=imageattr x/y value", value));
    }
    v.parse().map_err(|_| syntax("a=imageattr", value))
}

/// `spvalue = ( "0" "." onetonine *3DIGIT ) / ( onetonine "." 1*4DIGIT )`.
fn spvalue(value: &str, v: &str) -> Result<f64> {
    let b = v.as_bytes();
    let ok = b.len() >= 3
        && b.len() <= 6
        && b[1] == b'.'
        && b[2..].iter().all(u8::is_ascii_digit)
        && match b[0] {
            b'0' => b[2] != b'0',
            b'1'..=b'9' => true,
            _ => false,
        };
    if !ok {
        return Err(syntax("a=imageattr aspect ratio", value));
    }
    v.parse().map_err(|_| syntax("a=imageattr", value))
}

/// `qvalue = ( "0" "." 1*2DIGIT ) / ( "1" "." 1*2("0") )`.
fn qvalue(value: &str, v: &str) -> Result<f64> {
    let b = v.as_bytes();
    let ok = (3..=4).contains(&b.len())
        && b[1] == b'.'
        && match b[0] {
            b'0' => b[2..].iter().all(u8::is_ascii_digit),
            b'1' => b[2..].iter().all(|d| *d == b'0'),
            _ => false,
        };
    if !ok {
        return Err(syntax("a=imageattr q", value));
    }
    v.parse().map_err(|_| syntax("a=imageattr", value))
}

fn xyrange(value: &str, v: &str) -> Result<ImageAttrRange<u32>> {
    let Some(inner) = v.strip_prefix('[') else {
        return xyvalue(value, v).map(ImageAttrRange::Value);
    };
    let inner = inner
        .strip_suffix(']')
        .ok_or_else(|| syntax("a=imageattr", value))?;
    if inner.contains(':') {
        let parts: Vec<&str> = inner.split(':').collect();
        let (min, step, max) = match parts[..] {
            [min, max] => (min, None, max),
            [min, step, max] => (min, Some(step), max),
            _ => return Err(syntax("a=imageattr range", value)),
        };
        return Ok(ImageAttrRange::Range {
            min: xyvalue(value, min)?,
            step: step.map(|s| xyvalue(value, s)).transpose()?,
            max: xyvalue(value, max)?,
        });
    }
    let list = inner
        .split(',')
        .map(|x| xyvalue(value, x))
        .collect::<Result<Vec<_>>>()?;
    if list.len() < 2 {
        return Err(syntax("a=imageattr list", value));
    }
    Ok(ImageAttrRange::List(list))
}

fn srange(value: &str, v: &str) -> Result<ImageAttrRange<f64>> {
    let Some(inner) = v.strip_prefix('[') else {
        return spvalue(value, v).map(ImageAttrRange::Value);
    };
    let inner = inner
        .strip_suffix(']')
        .ok_or_else(|| syntax("a=imageattr", value))?;
    if let Some((min, max)) = inner.split_once('-') {
        return Ok(ImageAttrRange::Range {
            min: spvalue(value, min)?,
            step: None,
            max: spvalue(value, max)?,
        });
    }
    let list = inner
        .split(',')
        .map(|x| spvalue(value, x))
        .collect::<Result<Vec<_>>>()?;
    if list.len() < 2 {
        return Err(syntax("a=imageattr list", value));
    }
    Ok(ImageAttrRange::List(list))
}

/// Splits the inside of a set at the commas that are not inside a bracketed range.
fn split_top_level(inner: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (i, b) in inner.bytes().enumerate() {
        match b {
            b'[' => depth += 1,
            b']' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                parts.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&inner[start..]);
    parts
}

fn image_set(value: &str, set: &str) -> Result<ImageAttrSet> {
    let inner = set
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| syntax("a=imageattr set", value))?;
    let parts = split_top_level(inner);
    let (Some(x), Some(y)) = (
        parts.first().and_then(|p| p.strip_prefix("x=")),
        parts.get(1).and_then(|p| p.strip_prefix("y=")),
    ) else {
        return Err(syntax("a=imageattr set", value));
    };
    let mut out = ImageAttrSet {
        x: xyrange(value, x)?,
        y: xyrange(value, y)?,
        sar: None,
        par: None,
        q: None,
    };
    for part in &parts[2..] {
        if let Some(sar) = part.strip_prefix("sar=") {
            out.sar = Some(srange(value, sar)?);
        } else if let Some(par) = part.strip_prefix("par=") {
            let (min, max) = par
                .strip_prefix('[')
                .and_then(|p| p.strip_suffix(']'))
                .and_then(|p| p.split_once('-'))
                .ok_or_else(|| syntax("a=imageattr par", value))?;
            out.par = Some((spvalue(value, min)?, spvalue(value, max)?));
        } else if let Some(q) = part.strip_prefix("q=") {
            out.q = Some(qvalue(value, q)?);
        } else {
            return Err(syntax("a=imageattr key", value));
        }
    }
    Ok(out)
}

impl TypedAttribute for ImageAttr {
    const NAME: &'static str = "imageattr";

    fn parse(value: &str) -> Result<Self> {
        // 1*WSP separates everything, and nothing inside a set has white space.
        let mut tokens = value
            .split([' ', '\t'])
            .filter(|t| !t.is_empty())
            .peekable();
        if value.starts_with([' ', '\t']) || value.ends_with([' ', '\t']) {
            return Err(syntax("a=imageattr", value));
        }
        let pt = match tokens.next() {
            Some("*") => None,
            Some(pt) => Some(payload_type("a=imageattr payload type", pt)?),
            None => return Err(syntax("a=imageattr", value)),
        };

        let mut out = ImageAttr {
            payload_type: pt,
            send: None,
            recv: None,
            recv_first: false,
        };
        let mut directions = 0;
        while let Some(direction) = tokens.next() {
            let slot = match direction {
                "send" => &mut out.send,
                "recv" => {
                    out.recv_first = directions == 0;
                    &mut out.recv
                }
                _ => return Err(syntax("a=imageattr direction", value)),
            };
            if slot.is_some() {
                return Err(syntax("a=imageattr: a direction occurs twice", value));
            }
            let list = if tokens.peek() == Some(&"*") {
                tokens.next();
                ImageAttrList::Any
            } else {
                let mut sets = Vec::new();
                while let Some(set) = tokens.next_if(|t| t.starts_with('[')) {
                    sets.push(image_set(value, set)?);
                }
                if sets.is_empty() {
                    return Err(syntax("a=imageattr attr-list", value));
                }
                ImageAttrList::Sets(sets)
            };
            *slot = Some(list);
            directions += 1;
        }
        if directions == 0 {
            return Err(syntax("a=imageattr", value));
        }
        Ok(out)
    }
}

fn write_range<T: fmt::Display>(
    f: &mut fmt::Formatter<'_>,
    range: &ImageAttrRange<T>,
    range_separator: char,
) -> fmt::Result {
    match range {
        ImageAttrRange::Value(v) => write!(f, "{v}"),
        ImageAttrRange::Range { min, step, max } => {
            write!(f, "[{min}{range_separator}")?;
            if let Some(step) = step {
                write!(f, "{step}{range_separator}")?;
            }
            write!(f, "{max}]")
        }
        ImageAttrRange::List(list) => {
            f.write_str("[")?;
            for (i, v) in list.iter().enumerate() {
                if i > 0 {
                    f.write_str(",")?;
                }
                write!(f, "{v}")?;
            }
            f.write_str("]")
        }
    }
}

/// An aspect ratio or a preference with the decimal point the grammar requires.
struct Decimal(f64);

impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.fract() == 0.0 {
            write!(f, "{:.1}", self.0)
        } else {
            write!(f, "{}", self.0)
        }
    }
}

impl fmt::Display for ImageAttrSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[x=")?;
        write_range(f, &self.x, ':')?;
        f.write_str(",y=")?;
        write_range(f, &self.y, ':')?;
        if let Some(sar) = &self.sar {
            f.write_str(",sar=")?;
            let sar = match sar {
                ImageAttrRange::Value(v) => ImageAttrRange::Value(Decimal(*v)),
                ImageAttrRange::Range { min, max, .. } => ImageAttrRange::Range {
                    min: Decimal(*min),
                    step: None,
                    max: Decimal(*max),
                },
                ImageAttrRange::List(list) => {
                    ImageAttrRange::List(list.iter().map(|v| Decimal(*v)).collect())
                }
            };
            write_range(f, &sar, '-')?;
        }
        if let Some((min, max)) = self.par {
            write!(f, ",par=[{}-{}]", Decimal(min), Decimal(max))?;
        }
        if let Some(q) = self.q {
            write!(f, ",q={}", Decimal(q))?;
        }
        f.write_str("]")
    }
}

impl fmt::Display for ImageAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.payload_type {
            Some(pt) => write!(f, "{pt}")?,
            None => f.write_str("*")?,
        }
        let (send, recv) = (("send", &self.send), ("recv", &self.recv));
        let order = if self.recv_first {
            [recv, send]
        } else {
            [send, recv]
        };
        for (direction, list) in order {
            match list {
                None => {}
                Some(ImageAttrList::Any) => write!(f, " {direction} *")?,
                Some(ImageAttrList::Sets(sets)) => {
                    write!(f, " {direction}")?;
                    for set in sets {
                        write!(f, " {set}")?;
                    }
                }
            }
        }
        Ok(())
    }
}
