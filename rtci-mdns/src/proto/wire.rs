//! The mDNS messages [`Mdns`](super::Mdns) reads and writes.
//!
//! Reading keeps what a host-name responder and resolver acts on: every question, and of every
//! record its name, type, class, cache-flush bit, TTL and, for address and restricted-form NSEC
//! records, its data. A record of any other type is stepped over by its RDLENGTH, so one this
//! code does not know never hides the records after it (RFC 6762 section 6.1). Names are decoded
//! by [`Name`], compression included.
//!
//! Writing produces queries (probes included), responses and legacy unicast replies with A, AAAA
//! and NSEC records, names compressed (RFC 6762 section 18.14).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::message::header::{Header, HeaderInternal};
use crate::message::name::Name;

pub(crate) const TYPE_A: u16 = 1;
pub(crate) const TYPE_OPT: u16 = 41;
pub(crate) const TYPE_AAAA: u16 = 28;
pub(crate) const TYPE_NSEC: u16 = 47;
pub(crate) const TYPE_ANY: u16 = 255;

pub(crate) const CLASS_IN: u16 = 1;
pub(crate) const CLASS_ANY: u16 = 255;

/// The top bit of the class field: unicast-response in a question (RFC 6762 section 18.12),
/// cache-flush in a record (section 18.13). It is not part of the class.
pub(crate) const CLASS_TOP_BIT: u16 = 0x8000;

/// Header bits of a query: everything zero (RFC 6762 section 18).
pub(crate) const FLAGS_QUERY: u16 = 0;
/// Header bits of a response: QR and AA (RFC 6762 sections 18.2, 18.4).
pub(crate) const FLAGS_RESPONSE: u16 = 0x8400;
/// The TC bit (RFC 6762 section 18.5).
pub(crate) const FLAG_TRUNCATED: u16 = 0x0200;

/// The largest mDNS message, IP and UDP headers included (RFC 6762 section 17). A longer
/// datagram is not an mDNS message.
pub(crate) const MAX_INBOUND_MESSAGE: usize = 9000;

/// The largest message written: what fits one unfragmented datagram on an Ethernet link, over
/// IPv4 or IPv6 (RFC 6762 section 17). More records than fit go out in further messages.
pub(crate) const MAX_OUTBOUND_MESSAGE: usize = 1452;

/// Questions kept from one message; the rest are stepped over.
pub(crate) const MAX_MESSAGE_QUESTIONS: usize = 256;

/// Records kept from one message, over its three record sections; the rest are stepped over.
pub(crate) const MAX_MESSAGE_RECORDS: usize = 512;

/// A question of a received message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InQuestion {
    /// The name as sent, with its trailing dot.
    pub(crate) name: String,
    /// The name in ASCII lower case: DNS names compare without regard to ASCII case
    /// (RFC 1035 section 2.3.3, RFC 6762 section 16).
    pub(crate) key: String,
    pub(crate) typ: u16,
    /// The class without its top bit.
    pub(crate) class: u16,
    /// The unicast-response bit (a "QU" question).
    pub(crate) unicast: bool,
}

/// What a received record carries, as far as this crate reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InData {
    /// An A or AAAA record's address.
    Addr(IpAddr),
    /// A restricted-form NSEC record (RFC 6762 section 6.1): the bitmap of the types 0 to 255
    /// that exist under the name, most significant bit first.
    Nsec([u8; 32]),
    /// Anything else, an NSEC record of another form included.
    Other,
}

/// A record of a received message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InRecord {
    /// The name in ASCII lower case, with its trailing dot.
    pub(crate) key: String,
    pub(crate) typ: u16,
    /// The class without its top bit.
    pub(crate) class: u16,
    /// The cache-flush bit.
    pub(crate) flush: bool,
    pub(crate) ttl: u32,
    pub(crate) data: InData,
}

impl InRecord {
    pub(crate) fn addr(&self) -> Option<IpAddr> {
        match self.data {
            InData::Addr(ip) => Some(ip),
            _ => None,
        }
    }

    /// The record's data as RFC 6762 section 8.2 compares it: the raw address bytes. Empty for
    /// a record whose data is not kept, which never decides a comparison against an address
    /// record (the types differ).
    pub(crate) fn rdata(&self) -> Vec<u8> {
        match self.data {
            InData::Addr(IpAddr::V4(ip)) => ip.octets().to_vec(),
            InData::Addr(IpAddr::V6(ip)) => ip.octets().to_vec(),
            _ => Vec::new(),
        }
    }

    /// Whether an NSEC record says a record of `typ` exists under its name.
    pub(crate) fn nsec_has(&self, typ: u16) -> Option<bool> {
        match &self.data {
            InData::Nsec(bitmap) if typ < 256 => {
                Some(bitmap[usize::from(typ / 8)] & (0x80 >> (typ % 8)) != 0)
            }
            _ => None,
        }
    }
}

/// A received message.
#[derive(Debug, Default)]
pub(crate) struct Inbound {
    pub(crate) header: Header,
    pub(crate) questions: Vec<InQuestion>,
    pub(crate) answers: Vec<InRecord>,
    pub(crate) authorities: Vec<InRecord>,
    pub(crate) additionals: Vec<InRecord>,
}

fn read_u16(msg: &[u8], off: usize) -> Option<u16> {
    let bytes = msg.get(off..off.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(msg: &[u8], off: usize) -> Option<u32> {
    let bytes = msg.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// The name at `off` and the offset after it. A name that is laid out correctly but cannot be
/// decoded (labels that are not UTF-8, RFC 6762 section 16; a pointer loop) is `None`: its
/// record is stepped over, not matched.
fn read_name(msg: &[u8], off: usize) -> Option<(Option<String>, usize)> {
    let mut name = Name::default();
    match name.unpack(msg, off) {
        Ok(next) => Some((Some(name.data), next)),
        Err(_) => Name::skip(msg, off).ok().map(|next| (None, next)),
    }
}

/// The type bitmap of a restricted-form NSEC record: the next domain name, then one window,
/// number 0, of 1 to 32 bytes (RFC 6762 section 6.1). The next domain name is not looked at.
fn read_nsec(msg: &[u8], off: usize, end: usize) -> Option<[u8; 32]> {
    let bitmap_off = Name::skip(msg, off).ok()?;
    let window = *msg.get(bitmap_off)?;
    let len = usize::from(*msg.get(bitmap_off + 1)?);
    let bits_off = bitmap_off + 2;
    if window != 0 || !(1..=32).contains(&len) || bits_off + len != end {
        return None;
    }
    let mut bitmap = [0u8; 32];
    bitmap[..len].copy_from_slice(msg.get(bits_off..end)?);
    Some(bitmap)
}

/// The record at `off` (`None` when it is not kept) and the offset after it.
fn read_record(msg: &[u8], off: usize) -> Option<(Option<InRecord>, usize)> {
    let (name, off) = read_name(msg, off)?;
    let typ = read_u16(msg, off)?;
    let class = read_u16(msg, off + 2)?;
    let ttl = read_u32(msg, off + 4)?;
    let len = usize::from(read_u16(msg, off + 8)?);
    let data_off = off + 10;
    let end = data_off.checked_add(len)?;
    let rdata = msg.get(data_off..end)?;
    // An OPT pseudo-record is not DNS data, and its class field is a payload size
    // (RFC 6762 section 10.2).
    let Some(name) = name.filter(|_| typ != TYPE_OPT) else {
        return Some((None, end));
    };
    let data = match typ {
        TYPE_A => <[u8; 4]>::try_from(rdata)
            .map(|a| InData::Addr(IpAddr::V4(Ipv4Addr::from(a))))
            .unwrap_or(InData::Other),
        TYPE_AAAA => <[u8; 16]>::try_from(rdata)
            .map(|a| InData::Addr(IpAddr::V6(Ipv6Addr::from(a))))
            .unwrap_or(InData::Other),
        TYPE_NSEC => read_nsec(msg, data_off, end)
            .map(InData::Nsec)
            .unwrap_or(InData::Other),
        _ => InData::Other,
    };
    Some((
        Some(InRecord {
            key: name.to_ascii_lowercase(),
            typ,
            class: class & !CLASS_TOP_BIT,
            flush: class & CLASS_TOP_BIT != 0,
            ttl,
            data,
        }),
        end,
    ))
}

/// Reads a message. `None` when it is longer than an mDNS message may be, or its header or
/// question section is cut short. A record section that is cut short ends the message there:
/// the records before the cut are kept.
pub(crate) fn parse(msg: &[u8]) -> Option<Inbound> {
    if msg.len() > MAX_INBOUND_MESSAGE {
        return None;
    }
    let mut counts = HeaderInternal::default();
    let mut off = counts.unpack(msg, 0).ok()?;
    let mut inbound = Inbound {
        header: counts.header(),
        ..Default::default()
    };

    for _ in 0..counts.questions {
        let (name, next) = read_name(msg, off)?;
        let typ = read_u16(msg, next)?;
        let class = read_u16(msg, next + 2)?;
        off = next + 4;
        if let Some(name) = name
            && inbound.questions.len() < MAX_MESSAGE_QUESTIONS
        {
            inbound.questions.push(InQuestion {
                key: name.to_ascii_lowercase(),
                name,
                typ,
                class: class & !CLASS_TOP_BIT,
                unicast: class & CLASS_TOP_BIT != 0,
            });
        }
    }

    let mut kept = 0;
    for (section, count) in [counts.answers, counts.authorities, counts.additionals]
        .into_iter()
        .enumerate()
    {
        for _ in 0..count {
            let Some((record, next)) = read_record(msg, off) else {
                return Some(inbound);
            };
            off = next;
            if let Some(record) = record
                && kept < MAX_MESSAGE_RECORDS
            {
                kept += 1;
                match section {
                    0 => inbound.answers.push(record),
                    1 => inbound.authorities.push(record),
                    _ => inbound.additionals.push(record),
                }
            }
        }
    }
    Some(inbound)
}

/// A question to write. `class` carries the unicast-response bit when it is wanted.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OutQuestion<'a> {
    pub(crate) name: &'a str,
    pub(crate) typ: u16,
    pub(crate) class: u16,
}

/// A record to write: the address record of `name`, or (`nsec`) the NSEC record saying that
/// the address record's type is the only one under `name`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OutRecord<'a> {
    pub(crate) name: &'a str,
    pub(crate) ip: IpAddr,
    pub(crate) nsec: bool,
    /// The cache-flush bit.
    pub(crate) flush: bool,
    pub(crate) ttl: u32,
}

/// The record type of an address.
pub(crate) fn addr_type(ip: IpAddr) -> u16 {
    match ip {
        IpAddr::V4(_) => TYPE_A,
        IpAddr::V6(_) => TYPE_AAAA,
    }
}

struct Writer {
    buf: Vec<u8>,
    /// Where each name suffix written so far starts, for compression.
    suffixes: Vec<(String, usize)>,
}

impl Writer {
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Writes `name` (with its trailing dot), pointing at an earlier occurrence of the longest
    /// suffix already in the message. `None` when it is not a name: over 255 bytes, an empty
    /// label, or a label over 63 bytes.
    fn name(&mut self, name: &str) -> Option<()> {
        if name == "." {
            self.buf.push(0);
            return Some(());
        }
        let body = name.strip_suffix('.')?;
        // 255 bytes on the wire (RFC 1035 section 2.3.4): each label's dot becomes its length
        // byte, and the root label adds one.
        if body.is_empty() || name.len() > 254 {
            return None;
        }
        let mut rest = name;
        for label in body.split('.') {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            if let Some((_, at)) = self.suffixes.iter().find(|(suffix, _)| suffix == rest) {
                self.u16(0xC000 | *at as u16);
                return Some(());
            }
            if self.buf.len() <= 0x3FFF {
                self.suffixes.push((rest.to_owned(), self.buf.len()));
            }
            self.buf.push(label.len() as u8);
            self.buf.extend_from_slice(label.as_bytes());
            rest = &rest[label.len() + 1..];
        }
        self.buf.push(0);
        Some(())
    }

    fn record(&mut self, record: &OutRecord<'_>) -> Option<()> {
        self.name(record.name)?;
        let typ = addr_type(record.ip);
        self.u16(if record.nsec { TYPE_NSEC } else { typ });
        self.u16(CLASS_IN | if record.flush { CLASS_TOP_BIT } else { 0 });
        self.u32(record.ttl);
        let len_at = self.buf.len();
        self.u16(0);
        if record.nsec {
            // The restricted form (RFC 6762 section 6.1): the next domain name is the record's
            // own name, then window 0 with the one type that exists. The NSEC bit itself stays
            // clear.
            self.name(record.name)?;
            let len = typ / 8 + 1;
            self.buf.push(0);
            self.buf.push(len as u8);
            for byte in 0..len {
                self.buf.push(if byte == typ / 8 {
                    0x80 >> (typ % 8)
                } else {
                    0
                });
            }
        } else {
            match record.ip {
                IpAddr::V4(ip) => self.buf.extend_from_slice(&ip.octets()),
                IpAddr::V6(ip) => self.buf.extend_from_slice(&ip.octets()),
            }
        }
        let len = (self.buf.len() - len_at - 2) as u16;
        self.buf[len_at..len_at + 2].copy_from_slice(&len.to_be_bytes());
        Some(())
    }
}

/// Packs a message. `None` when a name in it cannot be written.
pub(crate) fn pack(
    id: u16,
    flags: u16,
    questions: &[OutQuestion<'_>],
    answers: &[OutRecord<'_>],
    authorities: &[OutRecord<'_>],
    additionals: &[OutRecord<'_>],
) -> Option<Vec<u8>> {
    let mut w = Writer {
        buf: Vec::with_capacity(512),
        suffixes: Vec::new(),
    };
    w.u16(id);
    w.u16(flags);
    for count in [
        questions.len(),
        answers.len(),
        authorities.len(),
        additionals.len(),
    ] {
        w.u16(u16::try_from(count).ok()?);
    }
    for question in questions {
        w.name(question.name)?;
        w.u16(question.typ);
        w.u16(question.class);
    }
    for record in answers.iter().chain(authorities).chain(additionals) {
        w.record(record)?;
    }
    Some(w.buf)
}

/// Packs the given items into one message; with `false`, without what is optional.
pub(crate) type Build<'a> = &'a dyn Fn(&[usize], bool) -> Option<Vec<u8>>;

/// One message of a set made by [`split`]: the items it carries, its bytes (`None` when the
/// items cannot be written at all), and whether the optional part was left out to make it fit.
pub(crate) struct Packed {
    pub(crate) items: Vec<usize>,
    pub(crate) bytes: Option<Vec<u8>>,
    pub(crate) trimmed: bool,
}

/// Packs `items` into as few messages of at most [`MAX_OUTBOUND_MESSAGE`] bytes as halving
/// gives. `build(items, full)` packs one message; with `full` false it leaves out what is
/// optional (the Additional section). An item that does not fit a message by itself still goes
/// out alone (RFC 6762 section 17).
pub(crate) fn split(items: &[usize], build: Build<'_>, out: &mut Vec<Packed>) {
    if items.is_empty() {
        return;
    }
    for full in [true, false] {
        match build(items, full) {
            Some(bytes) if bytes.len() <= MAX_OUTBOUND_MESSAGE || (!full && items.len() == 1) => {
                out.push(Packed {
                    items: items.to_vec(),
                    bytes: Some(bytes),
                    trimmed: !full,
                });
                return;
            }
            Some(_) => {}
            None if items.len() == 1 => {
                out.push(Packed {
                    items: items.to_vec(),
                    bytes: None,
                    trimmed: !full,
                });
                return;
            }
            None => break,
        }
    }
    let (first, second) = items.split_at(items.len() / 2);
    split(first, build, out);
    split(second, build, out);
}
