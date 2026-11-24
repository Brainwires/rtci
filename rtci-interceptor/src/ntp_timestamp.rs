//! Rapid synchronisation (RFC 6051 section 3.3): an NTP-format timestamp in the RTP header
//! extension `urn:ietf:params:rtp-hdrext:ntp-64` (or `ntp-56`) of the packets of a local
//! stream that negotiated it, so a receiver can map the stream's RTP timestamps to the
//! sender's wall clock (and synchronise it with the sender's other streams) before, or
//! without, an RTCP sender report.
//!
//! Which packets carry it: every packet in a stream's first [`NtpTimestampBuilder::with_initial_window`]
//! (5 seconds by default, longer than the sender's first RTCP report takes, RFC 3550 6.2: half
//! the minimum interval at most 1.5 times), and from then on the packets of one RTP timestamp
//! (one frame) every [`NtpTimestampBuilder::with_interval`] (1 second), so a receiver that
//! joins late or switches to the stream synchronises within about a second. RFC 6051 section
//! 3.3 lets a sender include it in "any RTP packets" it chooses and asks for it on video random
//! access points and the audio packets beside them: the engine cannot tell a random access
//! point in every payload format, and the once-a-second frames stand in for them. Regular SRs
//! go on whatever this does ("regular RTCP SR packets MUST be sent").
//!
//! The timestamp is the instant the packet passes, on the clock the RTCP session's sender
//! reports take theirs from ([`SystemInstant::shared`], or the anchor
//! [`NtpTimestampBuilder::with_wall_clock`] gives, which the RTCP session must be given too): the report generator relates a
//! stream's RTP timestamps to the same instants (the packet's passage), so both describe one
//! mapping, as section 3.3 requires ("MUST correspond to the same time instant as the RTP
//! timestamp ... MUST be derived from the same clock used to generate the NTP-format
//! timestamps included in RTCP SR packets").
//!
//! # Where it belongs
//!
//! `Slot::Custom(NTP_TIMESTAMP_SLOT)` (1_850): wire-ward of the pacer, so the instant is the
//! one the packet leaves at; application-ward of the FEC wire-image tap (1_500), so FEC protects
//! the packet as it leaves.

use crate::stream_info::StreamInfo;
use crate::{Attribute, Interceptor, Packet, TaggedPacket};
use rtp::extension::ntp_timestamp_extension::{
    NTP_56_URI, NTP_64_URI, Ntp56Extension, Ntp64Extension,
};
use sansio::Protocol;
use shared::error::Error;
use shared::marshal::Marshal;
use shared::time::SystemInstant;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Where [`NtpTimestampInterceptor`] sits in the default set: `Slot::Custom(1_850)`.
pub const NTP_TIMESTAMP_SLOT: usize = 1_850;

/// How long from a stream's first packet every packet carries the timestamp, by default.
pub const NTP_TIMESTAMP_INITIAL_WINDOW: Duration = Duration::from_secs(5);

/// How often a frame carries the timestamp after the initial window, by default.
pub const NTP_TIMESTAMP_INTERVAL: Duration = Duration::from_secs(1);

/// Builder for [`NtpTimestampInterceptor`].
#[derive(Debug, Clone)]
pub struct NtpTimestampBuilder {
    initial_window: Duration,
    interval: Duration,
    wall_clock: Option<SystemInstant>,
}

impl Default for NtpTimestampBuilder {
    fn default() -> Self {
        Self {
            initial_window: NTP_TIMESTAMP_INITIAL_WINDOW,
            interval: NTP_TIMESTAMP_INTERVAL,
            wall_clock: None,
        }
    }
}

impl NtpTimestampBuilder {
    /// The defaults: every packet for 5 seconds, then a frame a second.
    pub fn new() -> Self {
        Self::default()
    }

    /// How long from a stream's first packet every packet carries the timestamp.
    pub fn with_initial_window(mut self, window: Duration) -> Self {
        self.initial_window = window;
        self
    }

    /// How often, after the initial window, the packets of one frame carry it. `Duration::ZERO`
    /// stamps every packet.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// The wall-clock anchor the timestamps derive from: the one the RTCP session's sender
    /// reports use (RFC 6051 section 3.3). Default: the process-wide
    /// [`SystemInstant::shared`]. Give one per peer connection for reproducible virtual-time
    /// runs: two runs in one process otherwise map the same instants to NTP times as far apart
    /// as the real time between them.
    pub fn with_wall_clock(mut self, anchor: SystemInstant) -> Self {
        self.wall_clock = Some(anchor);
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> NtpTimestampInterceptor {
        NtpTimestampInterceptor {
            initial_window: self.initial_window,
            interval: self.interval,
            wall_clock: self.wall_clock,
            streams: HashMap::new(),
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

/// The extension a stream negotiated: its id and whether it is the 56-bit variant.
#[derive(Debug, Clone, Copy)]
struct Stamped {
    id: u8,
    short: bool,
    first_packet: Option<Instant>,
    /// The RTP timestamp of the last frame stamped after the initial window, and when.
    last_frame: Option<(u32, Instant)>,
}

/// Stamps an RFC 6051 NTP-format timestamp on the packets of local streams that negotiated
/// `ntp-64` or `ntp-56`; see the `ntp_timestamp` module's source documentation for which packets.
pub struct NtpTimestampInterceptor {
    initial_window: Duration,
    interval: Duration,
    /// [`NtpTimestampBuilder::with_wall_clock`].
    wall_clock: Option<SystemInstant>,
    /// By media SSRC.
    streams: HashMap<u32, Stamped>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl NtpTimestampInterceptor {
    /// An interceptor with the default windows.
    pub fn new() -> Self {
        NtpTimestampBuilder::new().build()
    }

    /// Whether the packet of RTP timestamp `timestamp` of `stream` sent at `now` carries it.
    fn wanted(&self, stream: &mut Stamped, timestamp: u32, now: Instant) -> bool {
        let first = *stream.first_packet.get_or_insert(now);
        if now.saturating_duration_since(first) < self.initial_window {
            return true;
        }
        match stream.last_frame {
            Some((frame, _)) if frame == timestamp => true,
            Some((_, at)) if now.saturating_duration_since(at) < self.interval => false,
            _ => {
                stream.last_frame = Some((timestamp, now));
                true
            }
        }
    }
}

impl Default for NtpTimestampInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for NtpTimestampInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        // A retransmission keeps the header extensions of its first transmission.
        let retransmission = msg
            .message
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, Attribute::Retransmission));
        if let Packet::Rtp(packet) = &mut msg.message.packet
            && !retransmission
            && let Some(mut stream) = self.streams.get(&packet.header.ssrc).copied()
        {
            if self.wanted(&mut stream, packet.header.timestamp, msg.now) {
                let ntp = self
                    .wall_clock
                    .unwrap_or_else(|| SystemInstant::shared(msg.now))
                    .ntp(msg.now);
                let value = if stream.short {
                    Ntp56Extension::new(ntp).marshal()
                } else {
                    Ntp64Extension { ntp_time: ntp }.marshal()
                };
                if let Ok(value) = value {
                    let _ = packet
                        .header
                        .set_extension_upgrading(stream.id, value.freeze());
                }
            }
            self.streams.insert(packet.header.ssrc, stream);
        }
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }
}

impl Interceptor for NtpTimestampInterceptor {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        let id = |uri: &str| {
            info.rtp_header_extensions
                .iter()
                .find(|ext| ext.uri == uri)
                .and_then(|ext| u8::try_from(ext.id).ok())
                .filter(|id| *id != 0)
        };
        let negotiated = id(NTP_64_URI)
            .map(|id| (id, false))
            .or_else(|| id(NTP_56_URI).map(|id| (id, true)));
        match negotiated {
            Some((id, short)) => {
                self.streams.entry(info.ssrc).or_insert(Stamped {
                    id,
                    short,
                    first_packet: None,
                    last_frame: None,
                });
            }
            None => {
                self.streams.remove(&info.ssrc);
            }
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}
