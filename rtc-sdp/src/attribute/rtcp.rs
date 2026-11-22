//! `a=rtcp` (RFC 3605), `a=rtcp-fb` (RFC 4585, RFC 5104 and later) and `a=rtcp-xr`
//! (RFC 3611).

use std::fmt;

use shared::error::Result;

use super::TypedAttribute;
use crate::description::common::Address;
use crate::grammar::{self, invalid, syntax};

/// `a=rtcp:<port> [<nettype> <addrtype> <connection-address>]` (RFC 3605 section 2.1): the
/// port, and optionally the address, RTCP is sent to when it is not the one after the RTP
/// port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rtcp {
    /// The RTCP port.
    pub port: u16,
    /// The RTCP address, when the line gives one.
    pub address: Option<RtcpAddress>,
}

/// The address of an `a=rtcp` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpAddress {
    /// The network type, `IN`.
    pub network_type: String,
    /// The address type, `IP4` or `IP6`.
    pub address_type: String,
    /// The address.
    pub address: String,
}

impl TypedAttribute for Rtcp {
    const NAME: &'static str = "rtcp";

    fn parse(value: &str) -> Result<Self> {
        let fields = grammar::fields("a=rtcp", value)?;
        let address = match fields[1..] {
            [] => None,
            [network_type, address_type, address] => {
                if !grammar::is_token(network_type) || !grammar::is_token(address_type) {
                    return Err(syntax("a=rtcp", value));
                }
                // The same connection-address as a c= line.
                Address::parse(address_type, address)?;
                Some(RtcpAddress {
                    network_type: network_type.to_owned(),
                    address_type: address_type.to_owned(),
                    address: address.to_owned(),
                })
            }
            _ => return Err(syntax("a=rtcp", value)),
        };
        Ok(Rtcp {
            port: grammar::port(fields[0])?,
            address,
        })
    }
}

impl fmt::Display for Rtcp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.port)?;
        if let Some(a) = &self.address {
            write!(f, " {} {} {}", a.network_type, a.address_type, a.address)?;
        }
        Ok(())
    }
}

/// `rtcp-fb-pt`: the formats an `a=rtcp-fb` line applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RtcpFbPayloadType {
    /// `*`: every format of the media section.
    All,
    /// One RTP payload type.
    PayloadType(u8),
}

impl fmt::Display for RtcpFbPayloadType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RtcpFbPayloadType::All => f.write_str("*"),
            RtcpFbPayloadType::PayloadType(pt) => write!(f, "{pt}"),
        }
    }
}

/// What an `a=rtcp-fb` line stands for: the feedback messages the specifications define,
/// and [`RtcpFbKind::Other`] for the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpFbKind {
    /// `ack`: positive acknowledgements (RFC 4585).
    Ack,
    /// `ack rpsi`: reference picture selection indication as an acknowledgement.
    AckRpsi,
    /// `ack app [...]`: application-defined acknowledgement.
    AckApp,
    /// `nack`: generic NACK (RFC 4585 section 6.2.1).
    Nack,
    /// `nack pli`: picture loss indication (RFC 4585 section 6.3.1).
    NackPli,
    /// `nack sli`: slice loss indication (RFC 4585 section 6.3.2).
    NackSli,
    /// `nack rpsi`: reference picture selection indication (RFC 4585 section 6.3.3).
    NackRpsi,
    /// `nack app [...]`: application layer feedback (RFC 4585 section 6.4).
    NackApp,
    /// `nack rai`: rapid acquisition (RFC 6285).
    NackRai,
    /// `nack tllei`: transport layer third-party loss early indication (RFC 6642).
    NackTllei,
    /// `nack pslei`: payload-specific third-party loss early indication (RFC 6642).
    NackPslei,
    /// `nack ecn`: ECN feedback (RFC 6679).
    NackEcn,
    /// `trr-int <ms>`: the minimum interval between regular RTCP packets (RFC 4585).
    TrrInt(u32),
    /// `ccm fir`: full intra request (RFC 5104 section 4.3.1).
    CcmFir,
    /// `ccm tmmbr [smaxpr=<n>]`: temporary maximum media bit rate request (RFC 5104
    /// section 4.2.1), with the optional maximum packet rate.
    CcmTmmbr {
        /// `smaxpr`, the sender's maximum packet rate.
        smaxpr: Option<u64>,
    },
    /// `ccm tstr`: temporal-spatial trade-off request (RFC 5104 section 4.3.2).
    CcmTstr,
    /// `ccm vbcm *(<subMessageType>)`: H.271 video back channel message (RFC 5104 section
    /// 4.3.4).
    CcmVbcm(Vec<u32>),
    /// `goog-remb`: receiver estimated maximum bitrate
    /// (draft-alvestrand-rmcat-remb).
    GoogRemb,
    /// `transport-cc`: transport-wide congestion control feedback
    /// (draft-holmer-rmcat-transport-wide-cc-extensions).
    TransportCc,
    /// Any other feedback type: read [`RtcpFb::id`], [`RtcpFb::param`] and
    /// [`RtcpFb::rest`].
    Other,
}

/// `a=rtcp-fb:<pt> <id> [<param> [<rest>]]` (RFC 4585 section 4.2).
///
/// ```text
/// rtcp-fb-syntax = "a=rtcp-fb:" rtcp-fb-pt SP rtcp-fb-val CRLF
/// rtcp-fb-pt     = "*" / fmt
/// rtcp-fb-val    = "ack" rtcp-fb-ack-param / "nack" rtcp-fb-nack-param
///                / "trr-int" SP 1*DIGIT / rtcp-fb-id rtcp-fb-param
/// rtcp-fb-id     = 1*(alpha-numeric / "-" / "_")
/// rtcp-fb-param  = SP "app" [SP byte-string] / SP token [SP byte-string] / ; empty
/// ```
///
/// RFC 5104 section 7.1 adds `ccm`, whose parameter is required. Every feedback type has
/// this shape, so the line is kept as its three parts and [`RtcpFb::kind`] names the ones
/// the specifications define.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpFb {
    /// The formats the line applies to.
    pub payload_type: RtcpFbPayloadType,
    /// The feedback type: `ack`, `nack`, `trr-int`, `ccm`, `goog-remb`, `transport-cc`, ...
    pub id: String,
    /// The first parameter, a token: `pli`, `fir`, `app`, ... For `trr-int`, the interval.
    pub param: Option<String>,
    /// What follows the first parameter.
    pub rest: Option<String>,
}

impl RtcpFb {
    /// The feedback type and its parameters as one string, as it follows the payload type:
    /// `nack pli`, `goog-remb`, `ccm fir`.
    pub fn feedback(&self) -> String {
        let mut out = self.id.clone();
        for part in [&self.param, &self.rest].into_iter().flatten() {
            out.push(' ');
            out.push_str(part);
        }
        out
    }

    /// Whether the line applies to payload type `pt`.
    pub fn applies_to(&self, pt: u8) -> bool {
        match self.payload_type {
            RtcpFbPayloadType::All => true,
            RtcpFbPayloadType::PayloadType(own) => own == pt,
        }
    }

    /// Which feedback message this is.
    pub fn kind(&self) -> RtcpFbKind {
        let (param, rest) = (self.param.as_deref(), self.rest.as_deref());
        match (self.id.as_str(), param, rest) {
            ("ack", None, _) => RtcpFbKind::Ack,
            ("ack", Some("rpsi"), None) => RtcpFbKind::AckRpsi,
            ("ack", Some("app"), _) => RtcpFbKind::AckApp,
            ("nack", None, _) => RtcpFbKind::Nack,
            ("nack", Some("pli"), None) => RtcpFbKind::NackPli,
            ("nack", Some("sli"), None) => RtcpFbKind::NackSli,
            ("nack", Some("rpsi"), None) => RtcpFbKind::NackRpsi,
            ("nack", Some("app"), _) => RtcpFbKind::NackApp,
            ("nack", Some("rai"), None) => RtcpFbKind::NackRai,
            ("nack", Some("tllei"), None) => RtcpFbKind::NackTllei,
            ("nack", Some("pslei"), None) => RtcpFbKind::NackPslei,
            ("nack", Some("ecn"), None) => RtcpFbKind::NackEcn,
            ("trr-int", Some(interval), None) => interval
                .parse()
                .map(RtcpFbKind::TrrInt)
                .unwrap_or(RtcpFbKind::Other),
            ("ccm", Some("fir"), None) => RtcpFbKind::CcmFir,
            ("ccm", Some("tstr"), None) => RtcpFbKind::CcmTstr,
            ("ccm", Some("tmmbr"), None) => RtcpFbKind::CcmTmmbr { smaxpr: None },
            ("ccm", Some("tmmbr"), Some(rest)) => match rest
                .strip_prefix("smaxpr=")
                .filter(|n| grammar::is_digits(n) && n.len() <= 15)
                .and_then(|n| n.parse().ok())
            {
                Some(smaxpr) => RtcpFbKind::CcmTmmbr {
                    smaxpr: Some(smaxpr),
                },
                None => RtcpFbKind::Other,
            },
            ("ccm", Some("vbcm"), rest) => {
                let types: Option<Vec<u32>> = rest
                    .map(|r| {
                        r.split(' ')
                            .map(|t| {
                                (grammar::is_digits(t) && t.len() <= 8)
                                    .then(|| t.parse().ok())
                                    .flatten()
                            })
                            .collect()
                    })
                    .unwrap_or_else(|| Some(vec![]));
                types.map(RtcpFbKind::CcmVbcm).unwrap_or(RtcpFbKind::Other)
            }
            ("goog-remb", None, None) => RtcpFbKind::GoogRemb,
            ("transport-cc", None, None) => RtcpFbKind::TransportCc,
            _ => RtcpFbKind::Other,
        }
    }
}

impl TypedAttribute for RtcpFb {
    const NAME: &'static str = "rtcp-fb";

    fn parse(value: &str) -> Result<Self> {
        let mut parts = value.splitn(4, ' ');
        let (Some(pt), Some(id)) = (parts.next(), parts.next()) else {
            return Err(syntax("a=rtcp-fb", value));
        };
        let (param, rest) = (parts.next(), parts.next());

        let payload_type = if pt == "*" {
            RtcpFbPayloadType::All
        } else {
            let pt: u8 = grammar::digits_no_leading_zero("a=rtcp-fb payload type", pt)?;
            if pt > 127 {
                return Err(invalid("a=rtcp-fb payload type", value));
            }
            RtcpFbPayloadType::PayloadType(pt)
        };

        let well_formed = grammar::is_alnum_dash_underscore(id)
            && param.is_none_or(grammar::is_token)
            && rest.is_none_or(grammar::is_byte_string)
            && match id {
                // "trr-int" SP 1*DIGIT
                "trr-int" => param.is_some_and(grammar::is_digits) && rest.is_none(),
                // RFC 5104: every alternative of rtcp-fb-ccm-param starts with SP.
                "ccm" => param.is_some(),
                _ => true,
            };
        if !well_formed {
            return Err(syntax("a=rtcp-fb", value));
        }

        Ok(RtcpFb {
            payload_type,
            id: id.to_owned(),
            param: param.map(str::to_owned),
            rest: rest.map(str::to_owned),
        })
    }
}

impl fmt::Display for RtcpFb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.payload_type, self.feedback())
    }
}

/// `rcvr-rtt-mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RtcpXrRttMode {
    /// `all`: every receiver may send receiver reference time reports.
    All,
    /// `sender`: only media senders may.
    Sender,
}

/// `stat-flag`: a statistic of the `stat-summary` report block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RtcpXrStatFlag {
    /// `loss`
    Loss,
    /// `dup`
    Dup,
    /// `jitt`
    Jitt,
    /// `TTL`
    Ttl,
    /// `HL`
    Hl,
}

impl RtcpXrStatFlag {
    fn as_str(self) -> &'static str {
        match self {
            RtcpXrStatFlag::Loss => "loss",
            RtcpXrStatFlag::Dup => "dup",
            RtcpXrStatFlag::Jitt => "jitt",
            RtcpXrStatFlag::Ttl => "TTL",
            RtcpXrStatFlag::Hl => "HL",
        }
    }
}

/// One `xr-format` of an `a=rtcp-xr` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpXrFormat {
    /// `pkt-loss-rle[=<max-size>]`
    PktLossRle(Option<u32>),
    /// `pkt-dup-rle[=<max-size>]`
    PktDupRle(Option<u32>),
    /// `pkt-rcpt-times[=<max-size>]`
    PktRcptTimes(Option<u32>),
    /// `rcvr-rtt=<mode>[:<max-size>]`
    RcvrRtt {
        /// Who may send receiver reference time reports.
        mode: RtcpXrRttMode,
        /// The largest report block, in octets.
        max_size: Option<u32>,
    },
    /// `stat-summary[=<flag>,...]`
    StatSummary(Vec<RtcpXrStatFlag>),
    /// `voip-metrics`
    VoipMetrics,
    /// `format-ext`: a report block this crate does not know, as written.
    Other(String),
}

/// `a=rtcp-xr:[<xr-format> *(SP <xr-format>)]` (RFC 3611 section 5.1). An empty list turns
/// extended reports off.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RtcpXr {
    /// The report blocks, in order.
    pub formats: Vec<RtcpXrFormat>,
}

fn max_size(value: &str, size: Option<&str>) -> Result<Option<u32>> {
    size.map(|s| grammar::digits("a=rtcp-xr max-size", s).map_err(|_| syntax("a=rtcp-xr", value)))
        .transpose()
}

impl TypedAttribute for RtcpXr {
    const NAME: &'static str = "rtcp-xr";

    fn parse(value: &str) -> Result<Self> {
        if value.is_empty() {
            return Ok(RtcpXr::default());
        }
        let mut formats = Vec::new();
        for format in grammar::fields("a=rtcp-xr", value)? {
            let (name, argument) = match format.split_once('=') {
                Some((name, argument)) => (name, Some(argument)),
                None => (format, None),
            };
            formats.push(match (name, argument) {
                ("pkt-loss-rle", size) => RtcpXrFormat::PktLossRle(max_size(value, size)?),
                ("pkt-dup-rle", size) => RtcpXrFormat::PktDupRle(max_size(value, size)?),
                ("pkt-rcpt-times", size) => RtcpXrFormat::PktRcptTimes(max_size(value, size)?),
                ("rcvr-rtt", Some(argument)) => {
                    let (mode, size) = match argument.split_once(':') {
                        Some((mode, size)) => (mode, Some(size)),
                        None => (argument, None),
                    };
                    RtcpXrFormat::RcvrRtt {
                        mode: match mode {
                            "all" => RtcpXrRttMode::All,
                            "sender" => RtcpXrRttMode::Sender,
                            _ => return Err(syntax("a=rtcp-xr rcvr-rtt", value)),
                        },
                        max_size: max_size(value, size)?,
                    }
                }
                ("rcvr-rtt", None) => return Err(syntax("a=rtcp-xr rcvr-rtt", value)),
                ("stat-summary", flags) => RtcpXrFormat::StatSummary(
                    flags
                        .map(|flags| {
                            flags
                                .split(',')
                                .map(|flag| match flag {
                                    "loss" => Ok(RtcpXrStatFlag::Loss),
                                    "dup" => Ok(RtcpXrStatFlag::Dup),
                                    "jitt" => Ok(RtcpXrStatFlag::Jitt),
                                    "TTL" => Ok(RtcpXrStatFlag::Ttl),
                                    "HL" => Ok(RtcpXrStatFlag::Hl),
                                    _ => Err(syntax("a=rtcp-xr stat-summary", value)),
                                })
                                .collect::<Result<Vec<_>>>()
                        })
                        .transpose()?
                        .unwrap_or_default(),
                ),
                ("voip-metrics", None) => RtcpXrFormat::VoipMetrics,
                // format-ext = non-ws-string
                _ if grammar::is_non_ws_string(format) => RtcpXrFormat::Other(format.to_owned()),
                _ => return Err(syntax("a=rtcp-xr", value)),
            });
        }
        Ok(RtcpXr { formats })
    }
}

impl fmt::Display for RtcpXr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let size = |f: &mut fmt::Formatter<'_>, name: &str, size: &Option<u32>| match size {
            Some(size) => write!(f, "{name}={size}"),
            None => f.write_str(name),
        };
        for (i, format) in self.formats.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            match format {
                RtcpXrFormat::PktLossRle(s) => size(f, "pkt-loss-rle", s)?,
                RtcpXrFormat::PktDupRle(s) => size(f, "pkt-dup-rle", s)?,
                RtcpXrFormat::PktRcptTimes(s) => size(f, "pkt-rcpt-times", s)?,
                RtcpXrFormat::RcvrRtt { mode, max_size } => {
                    f.write_str(match mode {
                        RtcpXrRttMode::All => "rcvr-rtt=all",
                        RtcpXrRttMode::Sender => "rcvr-rtt=sender",
                    })?;
                    if let Some(max_size) = max_size {
                        write!(f, ":{max_size}")?;
                    }
                }
                RtcpXrFormat::StatSummary(flags) => {
                    f.write_str("stat-summary")?;
                    for (j, flag) in flags.iter().enumerate() {
                        f.write_str(if j == 0 { "=" } else { "," })?;
                        f.write_str(flag.as_str())?;
                    }
                }
                RtcpXrFormat::VoipMetrics => f.write_str("voip-metrics")?,
                RtcpXrFormat::Other(other) => f.write_str(other)?,
            }
        }
        Ok(())
    }
}
