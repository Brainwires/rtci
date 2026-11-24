//! The RFC 8859 multiplexing category of every SDP attribute, as data.
//!
//! When several m= sections share one transport (a BUNDLE group, RFC 9143), RFC 8859
//! section 4 says for each attribute how its values in those sections relate: free
//! ([`MuxCategory::Normal`]), equal ([`MuxCategory::Identical`]), taken from the section that
//! sets up the transport ([`MuxCategory::Transport`]), and so on. Section 5 and the IANA
//! tables of section 15.2 classify every attribute registered when it was written; the RFCs
//! that registered an attribute later state its category themselves.
//!
//! This module is those tables: [`attribute`] for an attribute name, [`bandwidth`] for a
//! `b=` modifier, [`rtcp_fb`] for a feedback type, [`group_semantics`] and
//! [`ssrc_group_semantics`] for grouping semantics, [`source_attribute`] for the
//! attributes of `a=ssrc`. It holds no logic about a description: the layer that negotiates
//! BUNDLE asks it what to compare.
//!
//! # Where the tables come from
//!
//! * Names and categories: the "attribute-name" table of RFC 8859 section 15.2.2, which is
//!   what IANA's registry was filled from. Entries of the form `name:value` there are
//!   values, not attributes, and are left out.
//! * Levels: the section 5 tables. Section 15.2.2 lists a few attributes that section 5
//!   does not; they have no level here unless the RFC that defines them leaves no doubt
//!   (`group`, `mid`, `depend`, `loopback`, `cs-correlation`).
//! * `ike-setup` and `psk-fingerprint` are IDENTICAL in section 15.2.2 and CAUTION in
//!   section 5.45; the registry table is followed. `ike-esp` and `ike-esp-udpencap` are in
//!   section 5.45 only.
//! * Attributes registered after RFC 8859, each with the category its own RFC gives:
//!   `msid` (RFC 8830), `rid` (RFC 8851), `simulcast` (RFC 8853), `extmap-allow-mixed`
//!   (RFC 8285), `rtcp-mux-only` (RFC 8858), `ice-pacing` and the re-registered ICE
//!   attributes (RFC 8839), `end-of-candidates` (RFC 8840), `tls-id` (RFC 8842),
//!   `sctp-port` and `max-message-size` (RFC 8841), `identity` (RFC 8827), `cryptex`
//!   (RFC 9335), `bundle-only` (RFC 9143).
//! * `ice-options` and `tls-id` are registered for one level, and RFC 9429 section 5.8
//!   reads them at both, as browsers write them: their level here is
//!   [`AttributeLevel::Both`].
//! * The RFC 8840 row (`end-of-candidates`: either level, IDENTICAL) was written without the
//!   RFC's text at hand; it is the one row of this table not checked against its source.
//!
//! `msid-semantic` and `sctpmap` were never registered and are not in the table.

use super::RtcpFb;

/// How the values of an attribute in the m= sections of one BUNDLE group relate (RFC 8859
/// section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MuxCategory {
    /// Section 4.1: independent in each m= section.
    Normal,
    /// Section 4.2: not advised under multiplexing; the outcome is undefined.
    Caution,
    /// Section 4.3: present with the same value in every bundled m= section (RFC 9143
    /// section 7.1.3: or only in the tagged one, which then speaks for all).
    Identical,
    /// Section 4.4: the session value is the sum over the bundled m= sections.
    Sum,
    /// Section 4.5: only the value of the m= section that sets up the transport counts.
    Transport,
    /// Section 4.6: encapsulates other attributes, whose categories apply.
    Inherit,
    /// Section 4.7: the same value wherever the same payload type is repeated.
    IdenticalPerPt,
    /// Section 4.8: the rule is in the specification that defines the attribute.
    Special,
    /// Section 4.9: not analysed; not to be multiplexed.
    Tbd,
}

/// Where an attribute may appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttributeLevel {
    /// Session level only (`S`).
    Session,
    /// Media level only (`M`).
    Media,
    /// Either level (`B`).
    Both,
    /// Source level: inside `a=ssrc` (`SR`).
    Source,
}

impl AttributeLevel {
    /// Whether an attribute of this level may be written at the session level.
    pub fn allows_session(self) -> bool {
        matches!(self, AttributeLevel::Session | AttributeLevel::Both)
    }

    /// Whether an attribute of this level may be written in a media description.
    pub fn allows_media(self) -> bool {
        matches!(self, AttributeLevel::Media | AttributeLevel::Both)
    }
}

/// One row of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeInfo {
    /// The attribute name. Names are case-sensitive.
    pub name: &'static str,
    /// The level, when the specifications state it.
    pub level: Option<AttributeLevel>,
    /// The multiplexing category.
    pub category: MuxCategory,
    /// Where the row comes from.
    pub reference: &'static str,
}

use MuxCategory as C;

const S: Option<AttributeLevel> = Some(AttributeLevel::Session);
const M: Option<AttributeLevel> = Some(AttributeLevel::Media);
const B: Option<AttributeLevel> = Some(AttributeLevel::Both);
const SR: Option<AttributeLevel> = Some(AttributeLevel::Source);

const fn row(
    name: &'static str,
    level: Option<AttributeLevel>,
    category: MuxCategory,
    reference: &'static str,
) -> AttributeInfo {
    AttributeInfo {
        name,
        level,
        category,
        reference,
    }
}

/// Every attribute with a multiplexing category, sorted by name (byte order).
pub static ATTRIBUTES: &[AttributeInfo] = &[
    row("3GPP-Adaptation-Support", M, C::Caution, "RFC 8859"),
    row("3GPP-Adaption-Support", None, C::Caution, "RFC 8859"),
    row(
        "3GPP-Asset-Information",
        B,
        C::Caution,
        "RFC 8859 section 5.48",
    ),
    row("3GPP-Integrity-Key", S, C::Caution, "RFC 8859 section 5.48"),
    row("3GPP-QoE-Metrics", M, C::Caution, "RFC 8859 section 5.48"),
    row("3GPP-SDP-Auth", S, C::Caution, "RFC 8859 section 5.48"),
    row("3GPP-SRTP-Config", M, C::Caution, "RFC 8859 section 5.48"),
    row(
        "3gpp-videopostdecbufsize",
        M,
        C::Caution,
        "RFC 8859 section 5.48",
    ),
    row("3gpp.iut.replication", None, C::Tbd, "RFC 8859"),
    row("FEC", None, C::Normal, "RFC 8859"),
    row("FEC-OTI-extension", None, C::Tbd, "RFC 8859"),
    row("FEC-declaration", None, C::Tbd, "RFC 8859"),
    row("PSCid", S, C::Normal, "RFC 8859 section 5.50"),
    row("SRTPAuthentication", M, C::Tbd, "RFC 8859 section 5.44"),
    row("SRTPROCTxRate", M, C::Tbd, "RFC 8859 section 5.44"),
    row("T38FaxFillBitRemoval", M, C::Tbd, "RFC 8859 section 5.52"),
    row("T38FaxMaxBuffer", M, C::Tbd, "RFC 8859 section 5.52"),
    row("T38FaxMaxDatagram", M, C::Tbd, "RFC 8859 section 5.52"),
    row("T38FaxMaxIFP", M, C::Tbd, "RFC 8859 section 5.52"),
    row("T38FaxRateManagement", M, C::Tbd, "RFC 8859 section 5.52"),
    row("T38FaxTranscodingJBIG", M, C::Tbd, "RFC 8859 section 5.52"),
    row("T38FaxTranscodingMMR", M, C::Tbd, "RFC 8859 section 5.52"),
    row("T38FaxUdpEC", M, C::Tbd, "RFC 8859 section 5.52"),
    row("T38FaxUdpECDepth", M, C::Tbd, "RFC 8859 section 5.52"),
    row("T38FaxUdpFECMaxSpan", M, C::Tbd, "RFC 8859 section 5.52"),
    row("T38FaxVersion", M, C::Tbd, "RFC 8859 section 5.52"),
    row("T38MaxBitRate", M, C::Tbd, "RFC 8859 section 5.52"),
    row("T38ModemType", M, C::Tbd, "RFC 8859 section 5.52"),
    row("T38VendorInfo", M, C::Tbd, "RFC 8859 section 5.52"),
    row("X-decbyterate", M, C::Caution, "RFC 8859 section 5.48"),
    row(
        "X-initpostdecbufperiod",
        M,
        C::Caution,
        "RFC 8859 section 5.48",
    ),
    row(
        "X-initpredecbufperiod",
        M,
        C::Caution,
        "RFC 8859 section 5.48",
    ),
    row("X-predecbufsize", M, C::Caution, "RFC 8859 section 5.48"),
    row("aal2CPS", B, C::Caution, "RFC 8859 section 5.49"),
    row("aal2CPSSDUrate", B, C::Caution, "RFC 8859 section 5.49"),
    row(
        "aal2sscs3661assured",
        B,
        C::Caution,
        "RFC 8859 section 5.49",
    ),
    row(
        "aal2sscs3661unassured",
        B,
        C::Caution,
        "RFC 8859 section 5.49",
    ),
    row("aal2sscs3662", B, C::Caution, "RFC 8859 section 5.49"),
    row("aal5sscop", B, C::Caution, "RFC 8859 section 5.49"),
    row("aalApp", B, C::Caution, "RFC 8859 section 5.49"),
    row("aalType", B, C::Caution, "RFC 8859 section 5.49"),
    row("abrParms", B, C::Caution, "RFC 8859 section 5.49"),
    row("abrSetup", B, C::Caution, "RFC 8859 section 5.49"),
    row("acap", B, C::Inherit, "RFC 8859 section 5.32"),
    row("accept-types", M, C::Tbd, "RFC 8859 section 5.55"),
    row("accept-wrapped-types", M, C::Tbd, "RFC 8859 section 5.55"),
    row("acfg", M, C::Special, "RFC 8859 section 5.32"),
    row("alt", M, C::Caution, "RFC 8859 section 5.48"),
    row("alt-default-id", M, C::Caution, "RFC 8859 section 5.48"),
    row("alt-group", S, C::Caution, "RFC 8859 section 5.48"),
    row("altc", M, C::Transport, "RFC 8859 section 5.41"),
    row("anycast", B, C::Caution, "RFC 8859 section 5.49"),
    row("atmQOSparms", B, C::Caution, "RFC 8859 section 5.49"),
    row("atmTrfcDesc", B, C::Caution, "RFC 8859 section 5.49"),
    row("atmmap", B, C::Caution, "RFC 8859 section 5.49"),
    row("bc_program", S, C::Normal, "RFC 8859 section 5.50"),
    row("bc_service", S, C::Normal, "RFC 8859 section 5.50"),
    row("bc_service_package", S, C::Normal, "RFC 8859 section 5.50"),
    row("bcap", B, C::Inherit, "RFC 8859 section 5.34"),
    row("bcastversion", S, C::Normal, "RFC 8859 section 5.44"),
    row("bcob", B, C::Caution, "RFC 8859 section 5.49"),
    row("bearerSigIE", B, C::Caution, "RFC 8859 section 5.49"),
    row("bearerType", B, C::Caution, "RFC 8859 section 5.49"),
    row("bundle-only", M, C::Normal, "RFC 9143"),
    row("cache", B, C::Caution, "RFC 8859 section 5.49"),
    row("calgextmap", B, C::Normal, "RFC 8859 section 5.19"),
    row("candidate", M, C::Transport, "RFC 8859 section 5.12"),
    row("capability", B, C::Caution, "RFC 8859 section 5.49"),
    row("cat", S, C::Normal, "RFC 8859 section 5.1"),
    row("cbrRate", B, C::Caution, "RFC 8859 section 5.49"),
    row("ccap", B, C::Identical, "RFC 8859 section 5.34"),
    row("cdsc", B, C::Normal, "RFC 8859 section 5.24"),
    row("cfw-id", M, C::Normal, "RFC 8859 section 5.21"),
    row("chain", B, C::Caution, "RFC 8859 section 5.49"),
    row("channel", M, C::Normal, "RFC 8859 section 5.11"),
    row("charset", S, C::Normal, "RFC 8859 section 5.1"),
    row("chatroom", None, C::Tbd, "RFC 8859"),
    row("clkrec", B, C::Caution, "RFC 8859 section 5.49"),
    row("cmid", M, C::Normal, "RFC 8859 section 5.11"),
    row("cname", SR, C::Normal, "RFC 8859 section 5.15"),
    row("codecconfig", B, C::Caution, "RFC 8859 section 5.49"),
    row("conf", M, C::Caution, "RFC 8859 section 5.4"),
    row("confid", M, C::Tbd, "RFC 8859 section 5.27"),
    row("connection", B, C::Transport, "RFC 8859 section 5.40"),
    row("content", M, C::Normal, "RFC 8859 section 5.23"),
    row("content-desc", None, C::Tbd, "RFC 8859"),
    row("control", B, C::Caution, "RFC 8859 section 5.46"),
    row("cpar", B, C::Inherit, "RFC 8859 section 5.24"),
    row("cparmax", B, C::Special, "RFC 8859 section 5.24"),
    row("cparmin", B, C::Special, "RFC 8859 section 5.24"),
    row("cpsSDUsize", B, C::Caution, "RFC 8859 section 5.49"),
    row("creq", B, C::Normal, "RFC 8859 section 5.32"),
    row("cryptex", B, C::Transport, "RFC 9335"),
    row("crypto", M, C::Transport, "RFC 8859 section 5.7"),
    row("cs-correlation", M, C::Tbd, "RFC 8859"),
    row("csup", B, C::Normal, "RFC 8859 section 5.32"),
    row("curr", M, C::Caution, "RFC 8859 section 5.4"),
    row("dccp-port", M, C::Caution, "RFC 8859 section 5.9"),
    row("dccp-service-code", M, C::Caution, "RFC 8859 section 5.8"),
    row("depend", M, C::IdenticalPerPt, "RFC 8859"),
    row("des", M, C::Caution, "RFC 8859 section 5.4"),
    row("dsel", B, C::Caution, "RFC 8859 section 5.49"),
    row("duplication-delay", B, C::Normal, "RFC 8859 section 5.18"),
    row("ecan", B, C::Caution, "RFC 8859 section 5.49"),
    row("ecn-capable-rtp", M, C::Identical, "RFC 8859 section 7.4"),
    row("eecid", B, C::Caution, "RFC 8859 section 5.49"),
    row("end-of-candidates", B, C::Identical, "RFC 8840"),
    row("etag", B, C::Caution, "RFC 8859 section 5.46"),
    row("extmap", B, C::Special, "RFC 8859 section 5.13"),
    row("extmap-allow-mixed", B, C::Identical, "RFC 8285"),
    row("fec", B, C::Caution, "RFC 8859 section 5.49"),
    row("fec-repair-flow", M, C::Special, "RFC 8859 section 5.22"),
    row("fec-source-flow", M, C::Special, "RFC 8859 section 5.22"),
    row("file-date", M, C::Tbd, "RFC 8859 section 5.28"),
    row("file-disposition", M, C::Tbd, "RFC 8859 section 5.28"),
    row("file-icon", M, C::Tbd, "RFC 8859 section 5.28"),
    row("file-range", M, C::Tbd, "RFC 8859 section 5.28"),
    row("file-selector", M, C::Tbd, "RFC 8859 section 5.28"),
    row("file-transfer-id", M, C::Tbd, "RFC 8859 section 5.28"),
    row("fingerprint", B, C::Transport, "RFC 8859 section 5.36"),
    row("floorctrl", M, C::Tbd, "RFC 8859 section 5.27"),
    row("floorid", M, C::Tbd, "RFC 8859 section 5.27"),
    row("flute-ch", None, C::Tbd, "RFC 8859"),
    row("flute-tsi", None, C::Tbd, "RFC 8859"),
    row("fmtp", M, C::IdenticalPerPt, "RFC 8859 section 5.1"),
    row("framerate", M, C::IdenticalPerPt, "RFC 8859 section 5.1"),
    row("framesize", M, C::Caution, "RFC 8859 section 5.48"),
    row("fsel", B, C::Caution, "RFC 8859 section 5.49"),
    row("gc", B, C::Caution, "RFC 8859 section 5.49"),
    row("group", S, C::Normal, "RFC 8859"),
    row("h248item", B, C::Special, "RFC 8859 section 5.54"),
    row("icap", B, C::Normal, "RFC 8859 section 5.34"),
    row("ice-lite", S, C::Normal, "RFC 8859 section 5.12"),
    row("ice-mismatch", M, C::Normal, "RFC 8839"),
    row(
        "ice-options",
        B,
        C::Normal,
        "RFC 8839; RFC 9429 section 5.8 reads it at both levels",
    ),
    row("ice-pacing", S, C::Normal, "RFC 8839"),
    row("ice-pwd", B, C::Transport, "RFC 8859 section 5.12"),
    row("ice-ufrag", B, C::Transport, "RFC 8859 section 5.12"),
    row("identity", S, C::Normal, "RFC 8827"),
    row("ike-esp", B, C::Caution, "RFC 8859"),
    row("ike-esp-udpencap", B, C::Caution, "RFC 8859"),
    row("ike-setup", B, C::Identical, "RFC 8859 section 5.45"),
    row("imageattr", M, C::IdenticalPerPt, "RFC 8859 section 5.17"),
    row("inactive", B, C::Normal, "RFC 8859 section 5.1"),
    row("ipbcp", S, C::Special, "RFC 8859 section 5.53"),
    row("isup_usi", B, C::Caution, "RFC 8859 section 5.49"),
    row("key-mgmt", B, C::Identical, "RFC 8859 section 5.35"),
    row("keywds", S, C::Normal, "RFC 8859 section 5.1"),
    row("label", M, C::Normal, "RFC 8859 section 5.5"),
    row("lang", B, C::Normal, "RFC 8859 section 5.1"),
    row("lcfg", B, C::Special, "RFC 8859 section 5.33"),
    row("lij", B, C::Caution, "RFC 8859 section 5.49"),
    row("loopback", M, C::Normal, "RFC 8859"),
    row("loopback-mirror", M, C::Normal, "RFC 8859 section 5.29"),
    row("loopback-source", M, C::Normal, "RFC 8859 section 5.29"),
    row("max-message-size", M, C::Caution, "RFC 8841"),
    row("max-size", M, C::Tbd, "RFC 8859 section 5.55"),
    row("maxprate", B, C::Special, "RFC 8859 section 6.3"),
    row("maxptime", M, C::IdenticalPerPt, "RFC 8859 section 5.1"),
    row("mbms-flowid", M, C::Caution, "RFC 8859 section 5.48"),
    row("mbms-mode", B, C::Caution, "RFC 8859 section 5.48"),
    row("mbms-repair", B, C::Caution, "RFC 8859 section 5.48"),
    row("mediaclk", B, C::Normal, "RFC 8859 section 5.16"),
    row("mfcap", B, C::IdenticalPerPt, "RFC 8859 section 5.33"),
    row("mid", M, C::Normal, "RFC 8859"),
    row("mscap", B, C::Inherit, "RFC 8859 section 5.33"),
    row("msid", M, C::Normal, "RFC 8830"),
    row("msrp-cema", M, C::Tbd, "RFC 8859 section 5.26"),
    row("mtag", B, C::Caution, "RFC 8859 section 5.46"),
    row("multicast-rtcp", B, C::Identical, "RFC 8859 section 5.38"),
    row("omcap", B, C::Normal, "RFC 8859 section 5.33"),
    row("omr-codecs", M, C::Normal, "RFC 8859 section 5.51"),
    row("omr-m-att", M, C::Normal, "RFC 8859 section 5.51"),
    row("omr-m-bw", M, C::Normal, "RFC 8859 section 5.51"),
    row("omr-m-cksum", M, C::Normal, "RFC 8859 section 5.51"),
    row("omr-s-att", M, C::Normal, "RFC 8859 section 5.51"),
    row("omr-s-bw", M, C::Normal, "RFC 8859 section 5.51"),
    row("omr-s-cksum", M, C::Normal, "RFC 8859 section 5.51"),
    row("onewaySel", B, C::Caution, "RFC 8859 section 5.49"),
    row("orient", M, C::Normal, "RFC 8859 section 5.1"),
    row("path", M, C::Tbd, "RFC 8859 section 5.55"),
    row("pcfg", M, C::Special, "RFC 8859 section 5.32"),
    row("portmapping-req", M, C::Caution, "RFC 8859 section 5.25"),
    row("previous-ssrc", SR, C::Normal, "RFC 8859 section 5.15"),
    row("profileDesc", B, C::Caution, "RFC 8859 section 5.49"),
    row("prtfl", B, C::Caution, "RFC 8859 section 5.49"),
    row("psk-fingerprint", B, C::Identical, "RFC 8859 section 5.45"),
    row("ptime", M, C::IdenticalPerPt, "RFC 8859 section 5.1"),
    row("qos-mech-recv", B, C::Transport, "RFC 8859 section 5.6"),
    row("qos-mech-send", B, C::Transport, "RFC 8859 section 5.6"),
    row("qosClass", B, C::Caution, "RFC 8859 section 5.49"),
    row("quality", M, C::Normal, "RFC 8859 section 5.1"),
    row("rams-updates", M, C::Caution, "RFC 8859 section 5.20"),
    row("range", B, C::Caution, "RFC 8859 section 5.46"),
    row("recvonly", B, C::Normal, "RFC 8859 section 5.1"),
    row(
        "remote-candidates",
        M,
        C::Transport,
        "RFC 8859 section 5.12",
    ),
    row("repair-window", M, C::Special, "RFC 8859 section 5.22"),
    row("resource", M, C::Normal, "RFC 8859 section 5.11"),
    row("rid", M, C::Special, "RFC 8851"),
    row("rmcap", B, C::IdenticalPerPt, "RFC 8859 section 5.33"),
    row("rtcp", M, C::Transport, "RFC 8859 section 5.14"),
    row("rtcp-fb", M, C::IdenticalPerPt, "RFC 8859 section 5.2"),
    row("rtcp-idms", M, C::Normal, "RFC 8859 section 5.43"),
    row("rtcp-mux", M, C::Identical, "RFC 8859 section 5.3"),
    row("rtcp-mux-only", M, C::Identical, "RFC 8858"),
    row("rtcp-rsize", M, C::Identical, "RFC 8859 section 5.10"),
    row("rtcp-unicast", M, C::Identical, "RFC 8859 section 5.30"),
    row("rtcp-xr", B, C::Normal, "RFC 8859 section 5.31"),
    row("rtpmap", M, C::IdenticalPerPt, "RFC 8859 section 5.1"),
    row("rtpred1", M, C::Caution, "RFC 8859 section 5.56"),
    row("rtpred2", M, C::Caution, "RFC 8859 section 5.56"),
    row("rtsp-ice-d-m", None, C::Tbd, "RFC 8859"),
    row("sbc", B, C::Caution, "RFC 8859 section 5.49"),
    row("sctp-port", M, C::Caution, "RFC 8841"),
    row("sdplang", B, C::Normal, "RFC 8859 section 5.1"),
    row("secondary-realm", M, C::Transport, "RFC 8859 section 5.51"),
    row("sendonly", B, C::Normal, "RFC 8859 section 5.1"),
    row("sendrecv", B, C::Normal, "RFC 8859 section 5.1"),
    row("sescap", S, C::Caution, "RFC 8859 section 5.33"),
    row("setup", B, C::Transport, "RFC 8859 section 5.40"),
    row("silenceSupp", B, C::Caution, "RFC 8859 section 5.49"),
    row("simulcast", M, C::Normal, "RFC 8853"),
    row("source-filter", B, C::Identical, "RFC 8859 section 5.37"),
    row("sqn", B, C::Normal, "RFC 8859 section 5.24"),
    row("ssrc", M, C::Normal, "RFC 8859 section 5.15"),
    row("ssrc-group", M, C::Normal, "RFC 8859 section 5.15"),
    row("stc", B, C::Caution, "RFC 8859 section 5.49"),
    row("stkmstream", B, C::Normal, "RFC 8859 section 5.44"),
    row("structure", B, C::Caution, "RFC 8859 section 5.49"),
    row("tcap", B, C::Inherit, "RFC 8859 section 5.32"),
    row(
        "tls-id",
        B,
        C::Identical,
        "RFC 8842; RFC 9429 section 5.8.1 reads it at both levels",
    ),
    row("tool", S, C::Normal, "RFC 8859 section 5.1"),
    row("ts-refclk", B, C::Normal, "RFC 8859 section 5.16"),
    row("type", S, C::Normal, "RFC 8859 section 5.1"),
    row("uiLayer1_Prot", B, C::Caution, "RFC 8859 section 5.49"),
    row("upcc", B, C::Caution, "RFC 8859 section 5.49"),
    row("userid", M, C::Tbd, "RFC 8859 section 5.27"),
    row("visited-realm", M, C::Transport, "RFC 8859 section 5.51"),
    row("vsel", B, C::Caution, "RFC 8859 section 5.49"),
    row("zrtp-hash", M, C::Transport, "RFC 8859 section 5.39"),
];

/// The row of the attribute `name`, or `None` for an attribute without a registered
/// multiplexing category (RFC 8859 section 4.9 treats those as TBD: not to be multiplexed
/// until analysed; a WebRTC endpoint simply ignores an attribute it does not know).
pub fn attribute(name: &str) -> Option<&'static AttributeInfo> {
    ATTRIBUTES
        .binary_search_by(|row| row.name.as_bytes().cmp(name.as_bytes()))
        .ok()
        .map(|index| &ATTRIBUTES[index])
}

/// The multiplexing category of the attribute `name`.
pub fn category(name: &str) -> Option<MuxCategory> {
    attribute(name).map(|row| row.category)
}

/// The category of a source attribute, the ones written inside `a=ssrc` (RFC 8859 section
/// 5.15): `cname` and `previous-ssrc` are NORMAL, `fmtp` is IDENTICAL-PER-PT.
pub fn source_attribute(name: &str) -> Option<MuxCategory> {
    match name {
        "cname" | "previous-ssrc" => Some(C::Normal),
        "fmtp" => Some(C::IdenticalPerPt),
        _ => None,
    }
}

/// The category of a `b=` modifier (RFC 8859 section 6): `CT` is NORMAL; `AS`, `RS` and
/// `RR` are SUM; `TIAS` is SPECIAL.
pub fn bandwidth(bwtype: &str) -> Option<MuxCategory> {
    match bwtype {
        "CT" => Some(C::Normal),
        "AS" | "RS" | "RR" => Some(C::Sum),
        "TIAS" => Some(C::Special),
        _ => None,
    }
}

/// The category of an `a=rtcp-fb` line (RFC 8859 section 7): IDENTICAL-PER-PT for `ack`,
/// `nack`, `trr-int` and `ccm` with the parameters the RFC lists, SPECIAL for
/// `ack app` and `nack app`, IDENTICAL for `nack ecn`. `None` for a feedback type RFC 8859
/// does not classify (`goog-remb`, `transport-cc`, ...); those follow the attribute's own
/// category, IDENTICAL-PER-PT.
pub fn rtcp_fb(feedback: &RtcpFb) -> Option<MuxCategory> {
    let param = feedback.param.as_deref();
    match (feedback.id.as_str(), param) {
        ("ack" | "nack", Some("app")) => Some(C::Special),
        ("nack", Some("ecn")) => Some(C::Identical),
        ("ack", None | Some("rpsi")) => Some(C::IdenticalPerPt),
        ("nack", None | Some("pli" | "sli" | "rpsi" | "rai" | "tllei" | "pslei")) => {
            Some(C::IdenticalPerPt)
        }
        ("trr-int", _) => Some(C::IdenticalPerPt),
        ("ccm", Some("fir" | "tmmbr" | "tstr" | "vbcm")) => Some(C::IdenticalPerPt),
        _ => None,
    }
}

/// The category of an `a=group` semantics (RFC 8859 section 8; RFC 9143 for `BUNDLE`):
/// `ANAT` is CAUTION, the others NORMAL.
pub fn group_semantics(semantics: &str) -> Option<MuxCategory> {
    match semantics {
        "ANAT" => Some(C::Caution),
        "LS" | "FID" | "SRF" | "FEC" | "FEC-FR" | "CS" | "DDP" | "DUP" | "BUNDLE" => {
            Some(C::Normal)
        }
        _ => None,
    }
}

/// The category of an `a=ssrc-group` semantics (RFC 8859 section 9): all NORMAL.
pub fn ssrc_group_semantics(semantics: &str) -> Option<MuxCategory> {
    match semantics {
        "FID" | "FEC" | "FEC-FR" | "DUP" => Some(C::Normal),
        _ => None,
    }
}

/// The category of an `a=content` value (RFC 8859 section 12): all NORMAL.
pub fn content(tag: &str) -> Option<MuxCategory> {
    match tag {
        "slides" | "speaker" | "sl" | "main" | "alt" | "g.3gpp.cat" | "g.3gpp.crs" => {
            Some(C::Normal)
        }
        _ => None,
    }
}
