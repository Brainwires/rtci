//! What the RTCP session tests share: a session that repeats (its random numbers are fixed),
//! packets to feed it, and a way to run it over virtual time.
#![allow(dead_code)]

use rtci_interceptor::{
    Attribute, AttributedPacket, Interceptor, Packet, RTCPFeedback, Registry, RtcpRandom,
    RtcpSessionBuilder, RtcpSessionControl, RtcpSessionEvent, Slot, StreamInfo, TaggedPacket,
};
use rtcp::goodbye::Goodbye;
use rtcp::receiver_report::ReceiverReport;
use rtcp::sender_report::SenderReport;
use rtcp::source_description::{SdesType, SourceDescription};
use shared::TransportContext;
use std::time::{Duration, Instant};

/// Random numbers that repeat: every interval is varied by exactly 1.0 (`unit` is 0.5), and
/// the SSRCs chosen count up from `0x5000_0001`.
pub struct Fixed(pub u32);

impl Default for Fixed {
    fn default() -> Self {
        Self(0x5000_0000)
    }
}

impl RtcpRandom for Fixed {
    fn next_u32(&mut self) -> u32 {
        self.0 = self.0.wrapping_add(1);
        self.0
    }

    fn unit(&mut self) -> f64 {
        0.5
    }
}

/// The first SSRC a session with [`Fixed`] chooses to report from. (The CNAME takes the
/// three draws before it.)
pub const REPORTER: u32 = 0x5000_0004;

pub fn builder() -> RtcpSessionBuilder {
    RtcpSessionBuilder::new().with_random(Fixed::default())
}

pub fn chain(builder: RtcpSessionBuilder) -> impl Interceptor {
    Registry::new()
        .with(Slot::RtcpSession, builder.build())
        .build()
}

pub fn feedback(typ: &str, parameter: &str) -> RTCPFeedback {
    RTCPFeedback {
        typ: typ.to_string(),
        parameter: parameter.to_string(),
    }
}

pub fn video(ssrc: u32) -> StreamInfo {
    StreamInfo {
        ssrc,
        clock_rate: 90_000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        rtcp_feedback: vec![feedback("nack", ""), feedback("nack", "pli")],
        ..Default::default()
    }
}

pub fn audio(ssrc: u32) -> StreamInfo {
    StreamInfo {
        ssrc,
        clock_rate: 48_000,
        mime_type: "audio/opus".to_string(),
        payload_type: 111,
        ..Default::default()
    }
}

pub fn rtp(now: Instant, ssrc: u32, sequence_number: u16, timestamp: u32) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                ssrc,
                payload_type: 96,
                sequence_number,
                timestamp,
                ..Default::default()
            },
            payload: vec![0u8; 100].into(),
        })),
    }
}

pub fn rtcp(now: Instant, packets: Vec<Box<dyn rtcp::Packet>>) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(packets)),
    }
}

pub fn control(chain: &mut impl Interceptor, now: Instant, control: RtcpSessionControl) {
    chain.handle_write(control.into_packet(now)).unwrap();
}

/// One RTCP datagram the session wrote, and when.
pub struct Sent {
    pub at: Instant,
    pub packets: Vec<Box<dyn rtcp::Packet>>,
}

impl Sent {
    pub fn get<T: 'static>(&self) -> Vec<&T> {
        self.packets
            .iter()
            .filter_map(|packet| packet.as_any().downcast_ref::<T>())
            .collect()
    }

    pub fn has<T: 'static>(&self) -> bool {
        !self.get::<T>().is_empty()
    }

    /// Whether the first packet is an SR or an RR (RFC 3550 6.1: a compound packet).
    pub fn is_compound(&self) -> bool {
        self.packets.first().is_some_and(|first| {
            first.as_any().is::<SenderReport>() || first.as_any().is::<ReceiverReport>()
        })
    }

    /// The SSRC of the leading report.
    pub fn leader(&self) -> Option<u32> {
        let first = self.packets.first()?.as_any();
        first
            .downcast_ref::<SenderReport>()
            .map(|sr| sr.ssrc)
            .or_else(|| first.downcast_ref::<ReceiverReport>().map(|rr| rr.ssrc))
    }

    /// The `(source, CNAME)` pairs of the SDES.
    pub fn cnames(&self) -> Vec<(u32, String)> {
        self.get::<SourceDescription>()
            .iter()
            .flat_map(|sdes| &sdes.chunks)
            .flat_map(|chunk| {
                chunk
                    .items
                    .iter()
                    .filter(|item| item.sdes_type == SdesType::SdesCname)
                    .map(|item| (chunk.source, String::from_utf8(item.text.to_vec()).unwrap()))
            })
            .collect()
    }

    /// Whether a BYE is in it, and last (RFC 3550 6.1).
    pub fn goodbye(&self) -> Option<&Goodbye> {
        self.packets.last()?.as_any().downcast_ref::<Goodbye>()
    }

    /// The SSRCs of the report blocks it carries.
    pub fn reported(&self) -> Vec<u32> {
        let mut ssrcs = vec![];
        for packet in &self.packets {
            if let Some(sr) = packet.as_any().downcast_ref::<SenderReport>() {
                ssrcs.extend(sr.reports.iter().map(|report| report.ssrc));
            } else if let Some(rr) = packet.as_any().downcast_ref::<ReceiverReport>() {
                ssrcs.extend(rr.reports.iter().map(|report| report.ssrc));
            }
        }
        ssrcs
    }
}

/// Takes what the chain has written so far: the RTCP datagrams.
pub fn written(chain: &mut impl Interceptor) -> Vec<Sent> {
    let mut sent = vec![];
    while let Some(tagged) = chain.poll_write() {
        if let Packet::Rtcp(packets) = tagged.message.packet {
            assert!(!packets.is_empty(), "an empty RTCP packet reached the wire");
            sent.push(Sent {
                at: tagged.now,
                packets,
            });
        }
    }
    sent
}

/// Runs the chain's timers up to `until`, returning the RTCP datagrams written.
pub fn run(chain: &mut impl Interceptor, until: Instant) -> Vec<Sent> {
    let mut sent = written(chain);
    for _ in 0..100_000 {
        match chain.poll_timeout() {
            Some(at) if at <= until => {
                chain.handle_timeout(at).unwrap();
                sent.extend(written(chain));
            }
            _ => break,
        }
    }
    chain.handle_timeout(until).unwrap();
    sent.extend(written(chain));
    sent
}

/// Takes what the chain passed towards the application: the packets and the session events,
/// but for the announcements of the reporting SSRC ([`read_all`] keeps those).
pub fn read(chain: &mut impl Interceptor) -> (Vec<TaggedPacket>, Vec<RtcpSessionEvent>) {
    let (packets, mut events) = read_all(chain);
    events.retain(|event| !matches!(event, RtcpSessionEvent::ReportingSsrc { .. }));
    (packets, events)
}

/// [`read`], every session event kept.
pub fn read_all(chain: &mut impl Interceptor) -> (Vec<TaggedPacket>, Vec<RtcpSessionEvent>) {
    let mut packets = vec![];
    let mut events = vec![];
    while let Some(tagged) = chain.poll_read() {
        for attribute in &tagged.message.attributes {
            if let Attribute::Custom(value) = attribute
                && let Some(event) = value.downcast_ref::<RtcpSessionEvent>()
            {
                events.push(event.clone());
            }
        }
        if !matches!(&tagged.message.packet, Packet::Rtcp(packets) if packets.is_empty()) {
            packets.push(tagged);
        }
    }
    (packets, events)
}

pub fn secs(seconds: f64) -> Duration {
    Duration::from_secs_f64(seconds)
}
