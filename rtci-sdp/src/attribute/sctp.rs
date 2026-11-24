//! The SCTP attributes of RFC 8841: `sctp-port`, `max-message-size`, and the `sctpmap`
//! they replaced.

use std::fmt;

use shared::error::Result;

use super::TypedAttribute;
use crate::grammar::{self, syntax};

/// `a=sctp-port:<port>` (RFC 8841 section 5): `1*5(DIGIT)`, 0 to 65535, "leading zeroes
/// MUST NOT be used".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SctpPort(pub u16);

impl TypedAttribute for SctpPort {
    const NAME: &'static str = "sctp-port";

    fn parse(value: &str) -> Result<Self> {
        grammar::digits_no_leading_zero("a=sctp-port", value).map(SctpPort)
    }
}

impl fmt::Display for SctpPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// `a=max-message-size:<octets>` (RFC 8841 section 6): `1*DIGIT` without leading zeroes.
/// 0 means the endpoint handles messages of any size; an absent attribute means 64
/// kilobytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MaxMessageSize(pub u64);

impl TypedAttribute for MaxMessageSize {
    const NAME: &'static str = "max-message-size";

    fn parse(value: &str) -> Result<Self> {
        grammar::digits_no_leading_zero("a=max-message-size", value).map(MaxMessageSize)
    }
}

impl fmt::Display for MaxMessageSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// `a=sctpmap:<port> <app> [<streams>]` (draft-ietf-mmusic-sctp-sdp-05), what data sections
/// carried before `a=sctp-port`: the SCTP port, the application protocol
/// (`webrtc-datachannel`) and the number of streams.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SctpMap {
    /// The SCTP port: the `<fmt>` of the old-style m= line.
    pub port: u16,
    /// The application protocol, a token.
    pub app: String,
    /// The number of streams, when given.
    pub streams: Option<u32>,
}

impl TypedAttribute for SctpMap {
    const NAME: &'static str = "sctpmap";

    fn parse(value: &str) -> Result<Self> {
        let fields = grammar::fields("a=sctpmap", value)?;
        let (port, app, streams) = match fields[..] {
            [port, app] => (port, app, None),
            [port, app, streams] => (port, app, Some(streams)),
            _ => return Err(syntax("a=sctpmap", value)),
        };
        if !grammar::is_token(app) {
            return Err(syntax("a=sctpmap", value));
        }
        Ok(SctpMap {
            port: grammar::digits("a=sctpmap port", port)?,
            app: app.to_owned(),
            streams: streams
                .map(|s| grammar::digits("a=sctpmap streams", s))
                .transpose()?,
        })
    }
}

impl fmt::Display for SctpMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.port, self.app)?;
        if let Some(streams) = self.streams {
            write!(f, " {streams}")?;
        }
        Ok(())
    }
}
