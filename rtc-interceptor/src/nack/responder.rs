//! NACK Responder Interceptor - Responds to NACK requests by retransmitting packets.

use super::send_buffer::SendBuffer;
use super::stream_supports_nack;
use crate::Interceptor;
use crate::cc::probe::ProbeRequest;
use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use shared::marshal::MarshalSize;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Builder for the NackResponderInterceptor.
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Slot, Registry, NackResponderBuilder};
///
/// let chain = Registry::new()
///     .with(Slot::NackResponder, NackResponderBuilder::new()
///         .with_size(1024)
///         .build())
///     .build();
/// ```
pub struct NackResponderBuilder {
    /// Size of the send buffer (must be power of 2: 1, 2, 4, ..., 32768).
    size: u16,
    /// How long a sent packet stays available for retransmission.
    max_packet_age: Option<Duration>,
    /// How retransmissions are held to the congestion controller's target.
    rate_limit: RetransmissionRateLimit,
}

impl Default for NackResponderBuilder {
    fn default() -> Self {
        Self {
            size: 1024,
            max_packet_age: None,
            rate_limit: RetransmissionRateLimit::default(),
        }
    }
}

/// How the NACK responder holds its retransmissions to the congestion controller's target
/// (RFC 4588 section 7), read from [`Attribute::TargetBitrateChanged`] as it passes on the read
/// leg. Until a target has passed, and in a chain without a congestion controller, nothing is
/// held back.
///
/// The rate is counted over the last [`RETRANSMISSION_RATE_WINDOW`]. A NACKed packet that
/// does not fit is not retransmitted (section 7: the sender "MAY selectively retransmit only
/// the packets that it deems important and ignore NACK messages for other packets in order to
/// limit the bitrate"); the receiver asks again a round trip later.
///
/// The default is libwebrtc's rule, [`UpToTarget`](Self::UpToTarget), not the RFC's
/// [`WithinTarget`](Self::WithinTarget), measured in `tests/capacity_cap_video_rtc2rtc.rs` (a
/// video call whose path drops to 300 kbit/s, six seeds): with the RFC's rule the sender, its
/// encoder at the controller's floor, had almost nothing left to repair with and the picture
/// froze for 2.7 to 3.1 s; with retransmissions up to the target it froze for at most 1.2 s,
/// and without any limit the retransmissions (about 300, five times the link) filled the 300 ms
/// queue, three in four were dropped there, and it froze for up to 1.6 s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RetransmissionRateLimit {
    /// RFC 4588 section 7: "the acceptable packet rate and bitrate include both the original
    /// and retransmitted data". Retransmissions take what the original packets of every local
    /// stream leave of the target.
    WithinTarget,
    /// libwebrtc's rule (`RateLimiter` on the retransmissions, its maximum the target): the
    /// retransmissions alone stay under the target, whatever the original packets take. A
    /// sender whose encoder sits at or above the target (at the congestion controller's
    /// floor, or with a codec's minimum rate) still repairs at up to the target.
    #[default]
    UpToTarget,
    /// No limit beyond the per-stream budget (one retransmission per original packet sent): the
    /// fork's behaviour before. Retransmissions are then not congestion controlled.
    Unlimited,
}

/// The window [`RetransmissionRateLimit`] measures the rates over (libwebrtc's
/// `kRetransmitWindowSizeMs`).
pub const RETRANSMISSION_RATE_WINDOW: Duration = Duration::from_secs(1);

/// Octets sent within the last [`RETRANSMISSION_RATE_WINDOW`].
#[derive(Default)]
struct RateWindow {
    sent: VecDeque<(Instant, usize)>,
    octets: usize,
}

impl RateWindow {
    fn expire(&mut self, now: Instant) {
        while let Some(&(at, octets)) = self.sent.front() {
            if now.saturating_duration_since(at) < RETRANSMISSION_RATE_WINDOW {
                break;
            }
            self.sent.pop_front();
            self.octets -= octets;
        }
    }

    fn add(&mut self, now: Instant, octets: usize) {
        self.sent.push_back((now, octets));
        self.octets += octets;
    }
}

impl NackResponderBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the size of the send buffer.
    ///
    /// Size must be a power of 2 between 1 and 32768 (inclusive).
    /// Larger buffers can retransmit older packets but use more memory.
    pub fn with_size(mut self, size: u16) -> Self {
        self.size = size;
        self
    }

    /// Set how long a sent packet is kept for retransmission: the `rtx-time` of RFC 4588
    /// 8.1, when one is signalled. A NACK for a packet sent longer ago is not answered.
    ///
    /// Default: `None`, a packet is available for as long as the buffer holds it.
    pub fn with_max_packet_age(mut self, max_packet_age: Option<Duration>) -> Self {
        self.max_packet_age = max_packet_age;
        self
    }

    /// Set how retransmissions are held to the congestion controller's target (RFC 4588
    /// section 7). Default: [`RetransmissionRateLimit::UpToTarget`];
    /// [`RetransmissionRateLimit::WithinTarget`] is the RFC's form.
    pub fn with_rate_limit(mut self, rate_limit: RetransmissionRateLimit) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> NackResponderInterceptor {
        let mut interceptor = NackResponderInterceptor::new(self.size);
        interceptor.max_packet_age = self.max_packet_age;
        interceptor.rate_limit = self.rate_limit;
        interceptor
    }
}

/// The RID header extension (RFC 8852 3.1).
const RTP_STREAM_ID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";
/// The repaired-RID header extension (RFC 8852 3.2), which an RTX packet carries instead.
const REPAIRED_RTP_STREAM_ID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id";

/// The one-byte or two-byte id `info` negotiated for `uri`.
fn extension_id(info: &StreamInfo, uri: &str) -> Option<u8> {
    info.rtp_header_extensions
        .iter()
        .find(|extension| extension.uri == uri)
        .and_then(|extension| u8::try_from(extension.id).ok())
}

/// Per-stream state for the responder.
struct LocalStream {
    /// Buffer of sent packets for retransmission.
    send_buffer: SendBuffer,
    /// RTX SSRC for RFC4588 retransmission (if configured).
    ssrc_rtx: Option<u32>,
    /// RTX payload type for RFC4588 retransmission (if configured).
    payload_type_rtx: Option<u8>,
    /// Sequence number counter for RTX packets.
    rtx_sequence_number: u16,
    /// The sequence number of the packet sent last, and when.
    last_sent: Option<(u16, Instant)>,
    /// When each sequence number was last retransmitted, so a repeated NACK within
    /// [`MIN_RETRANSMIT_INTERVAL`] does not resend it again.
    last_retransmit: HashMap<u16, Instant>,
    /// The RID extension id, if negotiated.
    rid_extension_id: Option<u8>,
    /// The repaired-RID extension id, if negotiated.
    repaired_rid_extension_id: Option<u8>,
    /// Retransmissions this stream may still send: one more for each original packet sent, up
    /// to the send buffer's size, and one less per retransmission. A NACK naming the whole buffer
    /// may be answered once in full, but repeated NACKs cannot make the stream retransmit faster
    /// than it sends, so the peer cannot turn its NACKs into a multiple of our send rate.
    retransmit_budget: usize,
    /// The budget's ceiling: the send buffer's size.
    retransmit_budget_max: usize,
    /// When each buffered packet was sent, by its place in the send buffer (the sequence
    /// number modulo the buffer size), with the sequence number the entry is for.
    sent_at: Vec<Option<(u16, Instant)>>,
}

/// The most octets one probe cluster is filled with.
const MAX_PROBE_FILL_OCTETS: usize = crate::cc::probe::PROBE_MAX_OCTETS;

/// The most packets one probe cluster is filled with.
const MAX_PROBE_FILL_PACKETS: usize = 128;

/// The padding octets of one probe packet: the most RFC 3550 section 5.1 padding holds (its
/// count is one octet).
pub const PROBE_PADDING_OCTETS: u8 = 255;

/// A sequence number is retransmitted at most once per this interval, however often it is
/// NACKed. Receivers repeat NACKs while the repair is in flight; without this a peer can make
/// us resend the same packets as fast as it can send RTCP (an amplifier).
pub const MIN_RETRANSMIT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

/// Most retransmissions queued and not yet taken by `poll_write`. Past it further NACKed
/// packets are not queued until the queue drains.
pub const MAX_QUEUED_RETRANSMISSIONS: usize = 1024;

/// The most retransmission SSRCs whose next sequence number is remembered after their stream
/// was unbound.
const MAX_REMEMBERED_RTX_SSRCS: usize = 1024;

/// Interceptor that responds to NACK requests by retransmitting packets.
///
/// This interceptor buffers outgoing RTP packets on local streams and
/// retransmits them when RTCP TransportLayerNack packets are received.
pub struct NackResponderInterceptor {
    /// Configuration
    size: u16,

    /// How long a sent packet stays available for retransmission (`rtx-time`).
    max_packet_age: Option<Duration>,
    /// The `rtx-time` this endpoint announced, by retransmission payload type
    /// ([`NackControl::LocalRtxTime`](super::NackControl::LocalRtxTime)): it replaces
    /// `max_packet_age` for the streams repaired under that payload type.
    local_rtx_times: HashMap<u8, Duration>,

    /// Send buffers per local stream SSRC
    streams: HashMap<u32, LocalStream>,

    /// The next sequence number of each retransmission SSRC this interceptor has sent on,
    /// kept when its stream is unbound: a stream bound again with the same RTX SSRC (a
    /// renegotiation re-binding it) carries on from here. Starting over would repeat sequence
    /// numbers on a live SSRC, which SRTP refuses to protect twice (the packet index is the
    /// SSRC's rollover counter and sequence number).
    rtx_sequence_numbers: HashMap<u32, u16>,

    /// Queue for retransmitted packets
    write_queue: VecDeque<TaggedPacket>,
    /// Retransmissions in `write_queue` not yet taken by `poll_write`.
    retransmissions_queued: usize,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
    /// The RTP session (transport) of each SSRC, from the peer connection's
    /// [`RtpSessionAssignment`](crate::RtpSessionAssignment)s; empty while there is one.
    sessions: HashMap<u32, usize>,

    /// See [`NackResponderBuilder::with_rate_limit`].
    rate_limit: RetransmissionRateLimit,
    /// The congestion controller's latest target, bits per second.
    target_bps: Option<f64>,
    /// The original packets of the local streams, and the retransmissions, sent lately.
    originals: RateWindow,
    retransmitted: RateWindow,
}

impl NackResponderInterceptor {
    fn new(size: u16) -> Self {
        Self {
            read_queue: VecDeque::new(),
            size,
            max_packet_age: None,
            local_rtx_times: HashMap::new(),
            streams: HashMap::new(),
            rtx_sequence_numbers: HashMap::new(),
            write_queue: VecDeque::new(),
            retransmissions_queued: 0,
            sessions: HashMap::new(),
            rate_limit: RetransmissionRateLimit::default(),
            target_bps: None,
            originals: RateWindow::default(),
            retransmitted: RateWindow::default(),
        }
    }

    /// The octets retransmissions may still take within the window, `None` for no limit.
    fn retransmission_allowance(&mut self, now: Instant) -> Option<usize> {
        let target_bps = self.target_bps?;
        self.originals.expire(now);
        self.retransmitted.expire(now);
        let target = (target_bps / 8.0 * RETRANSMISSION_RATE_WINDOW.as_secs_f64()) as usize;
        let limit = match self.rate_limit {
            RetransmissionRateLimit::WithinTarget => target.saturating_sub(self.originals.octets),
            RetransmissionRateLimit::UpToTarget => target,
            RetransmissionRateLimit::Unlimited => return None,
        };
        Some(limit.saturating_sub(self.retransmitted.octets))
    }

    /// Fills a probe cluster ([`ProbeRequest`]) with padding-only packets on the RTX stream of
    /// the media stream that sent most recently.
    ///
    /// A probe needs a burst of packets at a multiple of the target rate, and an application
    /// that follows the target does not have one waiting. Each packet is an RTP packet of the
    /// RTX stream with no payload and [`PROBE_PADDING_OCTETS`] of padding (RFC 3550 section
    /// 5.1): an RTX packet too short to hold the original sequence number of RFC 4588 section
    /// 4 carries no media, and every receiver drops it after its transport-wide sequence
    /// number has been recorded (this crate's endpoint, libwebrtc's `RtxReceiveStream`). A
    /// retransmission of a packet already delivered would be a duplicate the receiving
    /// application may play twice. The header is the newest packet's, with its extensions
    /// (MID, the repaired RID in place of the RID), so the packet is demultiplexed as that
    /// stream's repair flow. Without RTX negotiated nothing is added: padding under the media
    /// SSRC would take sequence numbers the application owns. Not charged to the NACK budget:
    /// it answers no NACK.
    ///
    /// With several RTP sessions (transports) a cluster is the session's that asked for it
    /// (the request carries its [`RtpSession`](crate::RtpSession)): it is filled on a stream of
    /// that session only, so the probe travels the path whose capacity it measures (RFC 8836
    /// section 2: each path its own capacity).
    fn fill_probe(&mut self, now: Instant, request: &ProbeRequest, session: Option<usize>) {
        let sessions = &self.sessions;
        let Some(stream) = self
            .streams
            .iter_mut()
            .filter(|(ssrc, _)| match session {
                Some(session) if !sessions.is_empty() => sessions.get(ssrc) == Some(&session),
                _ => true,
            })
            .map(|(_, stream)| stream)
            .filter(|stream| stream.ssrc_rtx.is_some() && stream.payload_type_rtx.is_some())
            .filter(|stream| stream.last_sent.is_some())
            .max_by_key(|stream| stream.last_sent.map(|(_, at)| at))
        else {
            return;
        };
        let (Some(ssrc_rtx), Some(pt_rtx), Some((newest, _))) =
            (stream.ssrc_rtx, stream.payload_type_rtx, stream.last_sent)
        else {
            return;
        };

        // The newest packet still held gives the header.
        let Some(template) = stream.send_buffer.get(newest).cloned() else {
            return;
        };

        let wanted = request.octets.min(MAX_PROBE_FILL_OCTETS);
        let mut filled = 0usize;
        for _ in 0..MAX_PROBE_FILL_PACKETS {
            if filled >= wanted || self.retransmissions_queued >= MAX_QUEUED_RETRANSMISSIONS {
                break;
            }
            let packet = padding_packet(
                &mut stream.rtx_sequence_number,
                (stream.rid_extension_id, stream.repaired_rid_extension_id),
                &template,
                ssrc_rtx,
                pt_rtx,
            );
            filled += packet.marshal_size();
            self.retransmissions_queued += 1;
            self.write_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(packet)).with(Attribute::Retransmission),
            });
        }
    }

    /// Handle a NACK request by queuing retransmissions.
    fn handle_nack(
        &mut self,
        now: Instant,
        nack: &rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack,
    ) {
        // Collect sequence numbers to retransmit
        let mut seqs_to_retransmit = Vec::new();

        for nack_pair in &nack.nacks {
            // Check the base packet ID
            seqs_to_retransmit.push(nack_pair.packet_id);

            // Check each bit in lost_packets bitmap
            for i in 0..16 {
                if nack_pair.lost_packets & (1 << i) != 0 {
                    let seq = nack_pair.packet_id.wrapping_add(i + 1);
                    seqs_to_retransmit.push(seq);
                }
            }
        }

        let mut allowance = self.retransmission_allowance(now);
        let Some(stream) = self.streams.get_mut(&nack.media_ssrc) else {
            return;
        };

        // A NACK may name the same packet in several pairs; resend each once.
        seqs_to_retransmit.sort_unstable();
        seqs_to_retransmit.dedup();
        // Forget suppression entries old enough not to matter.
        stream
            .last_retransmit
            .retain(|_, at| now.saturating_duration_since(*at) < MIN_RETRANSMIT_INTERVAL);

        // Queue retransmissions
        for seq in seqs_to_retransmit {
            if self.retransmissions_queued >= MAX_QUEUED_RETRANSMISSIONS {
                break;
            }
            if stream.last_retransmit.contains_key(&seq) {
                continue;
            }
            if stream.retransmit_budget == 0 {
                break;
            }
            let Some(original_packet) = stream.send_buffer.get(seq) else {
                continue;
            };
            // RFC 4588 8.1 (`rtx-time`): a packet is kept for retransmission that long. What
            // the session description announced for the stream's retransmission format is
            // the value; without one, the configured age.
            if let Some(max_packet_age) = stream
                .payload_type_rtx
                .and_then(|payload_type_rtx| self.local_rtx_times.get(&payload_type_rtx))
                .copied()
                .or(self.max_packet_age)
                && let Some((_, sent)) = stream.sent_at[usize::from(seq) % stream.sent_at.len()]
                    .filter(|(sequence_number, _)| *sequence_number == seq)
                && now.saturating_duration_since(sent) > max_packet_age
            {
                continue;
            }
            // RFC 4588 section 7: the retransmissions stay within the congestion controller's
            // rate. Asked for oldest first, so what does not fit now is the newest; the
            // receiver asks for it again a round trip later.
            let size = original_packet.marshal_size()
                + if stream.ssrc_rtx.is_some() && stream.payload_type_rtx.is_some() {
                    2
                } else {
                    0
                };
            if let Some(left) = allowance.as_mut() {
                if size > *left {
                    break;
                }
                *left -= size;
            }
            stream.last_retransmit.insert(seq, now);
            stream.retransmit_budget -= 1;
            self.retransmissions_queued += 1;

            let packet = if let (Some(ssrc_rtx), Some(pt_rtx)) =
                (stream.ssrc_rtx, stream.payload_type_rtx)
            {
                rtx_packet(
                    &mut stream.rtx_sequence_number,
                    (stream.rid_extension_id, stream.repaired_rid_extension_id),
                    original_packet,
                    ssrc_rtx,
                    pt_rtx,
                )
            } else {
                // No RTX: retransmit original packet as-is
                original_packet.clone()
            };
            self.retransmitted.add(now, size);

            // Tagged so a send history downstream counts it as new bytes on the wire rather
            // than as the original transmission. A bandwidth estimator that cannot tell the two
            // apart under-counts exactly when the path is lossy — it sees fewer bytes than are
            // really being sent, infers headroom, and raises the target during loss.
            self.write_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(packet)).with(Attribute::Retransmission),
            });
        }
    }
}

/// The RTX packet (RFC 4588 section 4) that carries `original` again: the RTX SSRC and
/// payload type, the next sequence number of the RTX stream, and the original sequence number
/// ahead of the payload.
fn rtx_packet(
    rtx_sequence_number: &mut u16,
    rid_extension_ids: (Option<u8>, Option<u8>),
    original_packet: &rtp::Packet,
    ssrc_rtx: u32,
    pt_rtx: u8,
) -> rtp::Packet {
    let (rid_extension_id, repaired_rid_extension_id) = rid_extension_ids;
    let original_seq = original_packet.header.sequence_number;
    let mut rtx_payload = Vec::with_capacity(2 + original_packet.payload.len());
    rtx_payload.extend_from_slice(&original_seq.to_be_bytes());
    rtx_payload.extend_from_slice(&original_packet.payload);

    let rtx_seq = *rtx_sequence_number;
    *rtx_sequence_number = rtx_sequence_number.wrapping_add(1);

    // RFC 4588 4: the RTX packet carries the original's header "as is" apart from the SSRC,
    // payload type and sequence number, so its CSRCs and header extensions (audio level,
    // abs-send-time, mid, ...) go with it. Building a fresh header used to drop them. Version
    // is set explicitly: a buffered packet built with a defaulted header is version 0, which
    // receivers discard on arrival. Padding is not carried: the RTX payload is the original
    // payload alone.
    let mut header = original_packet.header.clone();
    header.version = 2;
    header.ssrc = ssrc_rtx;
    header.payload_type = pt_rtx;
    header.sequence_number = rtx_seq;
    header.padding = false;
    header.padding_size = 0;
    // RFC 8852 3.2: a repair packet names the stream it repairs with the repaired-RID, not
    // the RID, so a receiver never takes the RTX SSRC for a simulcast layer of its own.
    if let Some(rid_id) = rid_extension_id
        && let Some(rid) = header.get_extension(rid_id)
    {
        let _ = header.del_extension(rid_id);
        if let Some(repaired_id) = repaired_rid_extension_id {
            let _ = header.set_extension(repaired_id, rid);
        }
    }

    rtp::Packet {
        header,
        payload: rtx_payload.into(),
    }
}

/// A padding-only packet of the RTX stream (a bandwidth probe): `template`'s header on the RTX
/// SSRC and payload type with the next RTX sequence number, no payload, and
/// [`PROBE_PADDING_OCTETS`] of padding.
fn padding_packet(
    rtx_sequence_number: &mut u16,
    rid_extension_ids: (Option<u8>, Option<u8>),
    template: &rtp::Packet,
    ssrc_rtx: u32,
    pt_rtx: u8,
) -> rtp::Packet {
    let mut packet = rtx_packet(
        rtx_sequence_number,
        rid_extension_ids,
        template,
        ssrc_rtx,
        pt_rtx,
    );
    packet.payload = bytes::Bytes::new();
    packet.header.marker = false;
    packet.header.padding = true;
    packet.header.padding_size = PROBE_PADDING_OCTETS;
    packet
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for NackResponderInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // The congestion controller's target, which the retransmissions are held to.
        if let Some(Attribute::TargetBitrateChanged { bits_per_second }) =
            msg.message.get(&Attribute::TargetBitrateChanged {
                bits_per_second: 0.0,
            })
            && bits_per_second.is_finite()
            && *bits_per_second >= 0.0
        {
            self.target_bps = Some(*bits_per_second);
        }

        // A probe cluster the congestion controller asks for: fill it.
        if let Some(request) = msg.message.custom::<ProbeRequest>().copied() {
            let session = crate::RtpSession::of(&msg.message);
            self.fill_probe(msg.now, &request, session);
        }

        // Process NACK packets
        if let Packet::Rtcp(ref rtcp_packets) = msg.message.packet {
            for rtcp_packet in rtcp_packets {
                if let Some(nack) = rtcp_packet
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>()
                {
                    self.handle_nack(msg.now, nack);
                }
            }
        }

        self.read_queue.push_back(msg);

        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Some(assignment) = msg.message.custom::<crate::RtpSessionAssignment>() {
            for ssrc in &assignment.ssrcs {
                self.sessions.insert(*ssrc, assignment.session);
            }
        }
        if let Some(super::NackControl::LocalRtxTime {
            payload_type_rtx,
            rtx_time,
        }) = msg.message.custom::<super::NackControl>()
        {
            match rtx_time {
                Some(rtx_time) => self.local_rtx_times.insert(*payload_type_rtx, *rtx_time),
                None => self.local_rtx_times.remove(payload_type_rtx),
            };
        }
        // Every original packet counts against the target (RFC 4588 section 7), whether or
        // not its stream is repaired.
        if let Packet::Rtp(ref rtp_packet) = msg.message.packet
            && !msg.message.has(&Attribute::Retransmission)
        {
            self.originals.expire(msg.now);
            self.originals.add(msg.now, rtp_packet.marshal_size());
        }
        // Buffer outgoing RTP packets
        if let Packet::Rtp(ref rtp_packet) = msg.message.packet
            && let Some(stream) = self.streams.get_mut(&rtp_packet.header.ssrc)
        {
            stream.send_buffer.add(rtp_packet.clone());
            stream.last_sent = Some((rtp_packet.header.sequence_number, msg.now));
            let slot = usize::from(rtp_packet.header.sequence_number) % stream.sent_at.len();
            stream.sent_at[slot] = Some((rtp_packet.header.sequence_number, msg.now));
            stream.retransmit_budget =
                (stream.retransmit_budget + 1).min(stream.retransmit_budget_max);
        }

        self.write_queue.push_back(msg);

        Ok(())
    }

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        // First drain retransmitted packets
        let packet = self.write_queue.pop_front()?;
        if packet.message.has(&Attribute::Retransmission) {
            self.retransmissions_queued = self.retransmissions_queued.saturating_sub(1);
        }
        Some(packet)
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Due at once while packets wait in the write queue. A retransmission or a probe cluster's
    /// padding is made on the read leg (a NACK, a [`ProbeRequest`]), which a driver reaches
    /// after its `poll_write` (`poll_write`, `poll_event`, `poll_read`, then `poll_timeout`
    /// and sleep, as the crate's event loop has it): without a deadline the packets would wait
    /// for whatever wakes the driver next, a timer or an incoming datagram, which can be a
    /// long time on a connection with little traffic. The deadline is the instant they were
    /// made, so the driver's `handle_timeout` and the `poll_write` after it take them out at
    /// once; it is gone when the queue is drained.
    fn poll_timeout(&mut self) -> Option<Self::Time> {
        self.write_queue.front().map(|packet| packet.now)
    }
}

impl Interceptor for NackResponderInterceptor {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        if stream_supports_nack(info)
            && let Some(send_buffer) = SendBuffer::new(self.size)
        {
            // RFC 4588 4: the initial sequence number of the retransmission stream is random
            // (RFC 3550 5.1), and the stream is the RTX SSRC's, not the binding's: a stream
            // bound again continues where the SSRC left off.
            let rtx_sequence_number = info
                .ssrc_rtx
                .and_then(|ssrc_rtx| self.rtx_sequence_numbers.get(&ssrc_rtx).copied())
                .unwrap_or_else(rand::random::<u16>);
            self.streams.insert(
                info.ssrc,
                LocalStream {
                    send_buffer,
                    ssrc_rtx: info.ssrc_rtx,
                    payload_type_rtx: info.payload_type_rtx,
                    rtx_sequence_number,
                    last_sent: None,
                    last_retransmit: HashMap::new(),
                    rid_extension_id: extension_id(info, RTP_STREAM_ID_URI),
                    repaired_rid_extension_id: extension_id(info, REPAIRED_RTP_STREAM_ID_URI),
                    retransmit_budget: usize::from(self.size),
                    retransmit_budget_max: usize::from(self.size),
                    sent_at: vec![None; usize::from(self.size).max(1)],
                },
            );
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        if let Some(stream) = self.streams.remove(&info.ssrc)
            && let Some(ssrc_rtx) = stream.ssrc_rtx
        {
            if self.rtx_sequence_numbers.len() >= MAX_REMEMBERED_RTX_SSRCS
                && !self.rtx_sequence_numbers.contains_key(&ssrc_rtx)
            {
                self.rtx_sequence_numbers.clear();
            }
            self.rtx_sequence_numbers
                .insert(ssrc_rtx, stream.rtx_sequence_number);
        }
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}
