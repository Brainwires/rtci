//! The temporal-spatial trade-off and the video back channel of RFC 5104 (sections 4.3.2 to
//! 4.3.4): command sequence numbers for the requests an application sends, and the
//! notification a media sender owes each request it receives.

use crate::stream_info::StreamInfo;
use crate::{AttributedPacket, Interceptor, Packet, TaggedPacket};
use bytes::Bytes;
use rtcp::payload_feedbacks::temporal_spatial_tradeoff::{
    TemporalSpatialTradeoffNotification, TemporalSpatialTradeoffRequest, TstEntry,
};
use rtcp::payload_feedbacks::video_back_channel_message::{VbcmEntry, VideoBackChannelMessage};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Instant;

/// Whether `a` is after `b` in the 8-bit command sequence space (RFC 5104 4.3.3.2: "the
/// highest (modulo 256) sequence number").
fn newer(a: u8, b: u8) -> bool {
    let distance = a.wrapping_sub(b);
    distance != 0 && distance < 128
}

/// Command sequence numbers for TSTR (RFC 5104 section 4.3.2.1: "The sequence number space
/// is unique for each pairing of the SSRC of command source and the SSRC of the command
/// target. The sequence number SHALL be increased by 1 modulo 256 for each new command. A
/// repetition SHALL NOT increase the sequence number").
///
/// ```
/// use rtci_interceptor::TstrCommands;
///
/// let mut commands = TstrCommands::new();
/// let first = commands.request(0x1111, 0x2222, 31);
/// let again = commands.repeat(0x1111, 0x2222).expect("sent before");
/// let next = commands.request(0x1111, 0x2222, 0);
/// assert_eq!(first.entries[0].sequence_number, again.entries[0].sequence_number);
/// assert_eq!(
///     first.entries[0].sequence_number.wrapping_add(1),
///     next.entries[0].sequence_number
/// );
/// ```
#[derive(Debug, Default, Clone)]
pub struct TstrCommands {
    /// The last command to each media sender: its sequence number and index.
    last: HashMap<u32, (u8, u8)>,
}

impl TstrCommands {
    /// No command sent yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// A new request to `media_ssrc`, from `sender_ssrc`, for the trade-off `index` (0 to
    /// 31; larger values are cut to 31).
    pub fn request(
        &mut self,
        sender_ssrc: u32,
        media_ssrc: u32,
        index: u8,
    ) -> TemporalSpatialTradeoffRequest {
        let sequence_number = match self.last.get(&media_ssrc) {
            Some((last, _)) => last.wrapping_add(1),
            None => 0,
        };
        let index = index.min(31);
        self.last.insert(media_ssrc, (sequence_number, index));
        Self::packet(sender_ssrc, media_ssrc, sequence_number, index)
    }

    /// The last request to `media_ssrc` again, or `None` when none was sent.
    pub fn repeat(
        &self,
        sender_ssrc: u32,
        media_ssrc: u32,
    ) -> Option<TemporalSpatialTradeoffRequest> {
        self.last.get(&media_ssrc).map(|&(sequence_number, index)| {
            Self::packet(sender_ssrc, media_ssrc, sequence_number, index)
        })
    }

    fn packet(
        sender_ssrc: u32,
        media_ssrc: u32,
        sequence_number: u8,
        index: u8,
    ) -> TemporalSpatialTradeoffRequest {
        TemporalSpatialTradeoffRequest {
            sender_ssrc,
            entries: vec![TstEntry {
                ssrc: media_ssrc,
                sequence_number,
                index,
            }],
        }
    }
}

/// Command sequence numbers for VBCM (RFC 5104 section 4.3.4.1: "The sequence number SHALL
/// be increased by 1 modulo 256 for each new command. A repetition SHALL NOT increase the
/// sequence number").
#[derive(Debug, Default, Clone)]
pub struct VbcmCommands {
    last: HashMap<u32, VbcmEntry>,
}

impl VbcmCommands {
    /// No command sent yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// A new message to `media_ssrc`, from `sender_ssrc`: the H.271 `octet_string` for the
    /// payload type `payload_type`.
    pub fn request(
        &mut self,
        sender_ssrc: u32,
        media_ssrc: u32,
        payload_type: u8,
        octet_string: Bytes,
    ) -> VideoBackChannelMessage {
        let sequence_number = match self.last.get(&media_ssrc) {
            Some(last) => last.sequence_number.wrapping_add(1),
            None => 0,
        };
        let entry = VbcmEntry {
            ssrc: media_ssrc,
            sequence_number,
            payload_type,
            octet_string,
        };
        self.last.insert(media_ssrc, entry.clone());
        VideoBackChannelMessage {
            sender_ssrc,
            entries: vec![entry],
        }
    }

    /// The last message to `media_ssrc` again, or `None` when none was sent.
    pub fn repeat(&self, sender_ssrc: u32, media_ssrc: u32) -> Option<VideoBackChannelMessage> {
        self.last
            .get(&media_ssrc)
            .map(|entry| VideoBackChannelMessage {
                sender_ssrc,
                entries: vec![entry.clone()],
            })
    }
}

/// Whether a stream negotiated `a=rtcp-fb:<pt> ccm tstr` (RFC 5104 section 7.1).
fn negotiated_tstr(info: &StreamInfo) -> bool {
    info.rtcp_feedback
        .iter()
        .any(|feedback| feedback.typ == "ccm" && feedback.parameter == "tstr")
}

/// Builder for [`TstnResponderInterceptor`].
#[derive(Debug, Clone, Default)]
pub struct TstnResponderBuilder {
    fixed_index: Option<u8>,
    unnegotiated: bool,
}

impl TstnResponderBuilder {
    /// Notifications carry the index requested last.
    pub fn new() -> Self {
        Self::default()
    }

    /// The index an encoder that keeps one trade-off whatever is asked uses: every
    /// notification carries it (RFC 5104 4.3.3.2: "the Temporal-Spatial Trade-off index that
    /// will be used as a result of the request. This is not necessarily the same index as
    /// requested").
    pub fn with_fixed_index(mut self, index: u8) -> Self {
        self.fixed_index = Some(index.min(31));
        self
    }

    /// Answer requests to streams that did not negotiate `ccm tstr` too (RFC 5104 7.2 has
    /// CCM used only where both sides indicated it; this is the lenient setting).
    pub fn with_unnegotiated(mut self, unnegotiated: bool) -> Self {
        self.unnegotiated = unnegotiated;
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> TstnResponderInterceptor {
        TstnResponderInterceptor {
            fixed_index: self.fixed_index,
            unnegotiated: self.unnegotiated,
            local: HashSet::new(),
            index: HashMap::new(),
            acknowledged: HashMap::new(),
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

/// Answers each TSTR a local media sender receives with a TSTN (RFC 5104 section 4.3.3.2).
///
/// The request itself goes on to the application, which owns the encoder and takes it into
/// account (section 4.3.2.2). The notification names every requester of the compound packet
/// once, with the highest sequence number it sent (modulo 256), repetitions included, and the
/// one index that will be used in all its entries: the last requested, or the fixed index the
/// builder was given.
pub struct TstnResponderInterceptor {
    fixed_index: Option<u8>,
    unnegotiated: bool,
    /// Local media SSRCs that negotiated `ccm tstr`, and those bound without it.
    local: HashSet<u32>,
    /// The index in use for each local media SSRC.
    index: HashMap<u32, u8>,
    /// The highest sequence number answered, by (media SSRC, requester).
    acknowledged: HashMap<(u32, u32), u8>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl TstnResponderInterceptor {
    fn answer(&mut self, now: Instant, requests: &[TemporalSpatialTradeoffRequest]) {
        // By media sender, by requester: the highest sequence number and its index.
        let mut asked: BTreeMap<u32, BTreeMap<u32, (u8, u8)>> = BTreeMap::new();
        for request in requests {
            for entry in &request.entries {
                if !self.local.contains(&entry.ssrc) {
                    continue;
                }
                let by_requester = asked.entry(entry.ssrc).or_default();
                match by_requester.get(&request.sender_ssrc) {
                    Some((seen, _)) if !newer(entry.sequence_number, *seen) => {}
                    _ => {
                        by_requester
                            .insert(request.sender_ssrc, (entry.sequence_number, entry.index));
                    }
                }
            }
        }
        for (media_ssrc, by_requester) in asked {
            let mut entries = vec![];
            let mut requested = None;
            for (requester, (sequence_number, index)) in by_requester {
                let key = (media_ssrc, requester);
                if let Some(last) = self.acknowledged.get(&key)
                    && newer(*last, sequence_number)
                {
                    // Older than one already answered: a stale request.
                    continue;
                }
                if self.acknowledged.get(&key) != Some(&sequence_number) {
                    requested = Some(index);
                }
                self.acknowledged.insert(key, sequence_number);
                entries.push((requester, sequence_number));
            }
            if entries.is_empty() {
                continue;
            }
            let index = match (self.fixed_index, requested) {
                (Some(fixed), _) => fixed,
                (None, Some(requested)) => requested,
                (None, None) => *self.index.get(&media_ssrc).unwrap_or(&0),
            };
            self.index.insert(media_ssrc, index);
            let notification = TemporalSpatialTradeoffNotification {
                sender_ssrc: media_ssrc,
                entries: entries
                    .into_iter()
                    .map(|(ssrc, sequence_number)| TstEntry {
                        ssrc,
                        sequence_number,
                        index,
                    })
                    .collect(),
            };
            self.write_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(notification)])),
            });
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for TstnResponderInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtcp(packets) = &msg.message.packet {
            let requests: Vec<TemporalSpatialTradeoffRequest> = packets
                .iter()
                .filter_map(|p| {
                    p.as_any()
                        .downcast_ref::<TemporalSpatialTradeoffRequest>()
                        .cloned()
                })
                .collect();
            if !requests.is_empty() {
                self.answer(msg.now, &requests);
            }
        }
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
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

impl Interceptor for TstnResponderInterceptor {
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn bind_local_stream(&mut self, info: &StreamInfo) {
        if self.unnegotiated || negotiated_tstr(info) {
            self.local.insert(info.ssrc);
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.local.remove(&info.ssrc);
        self.index.remove(&info.ssrc);
        self.acknowledged
            .retain(|(media, _), _| *media != info.ssrc);
    }
}

#[cfg(test)]
#[path = "tst_test.rs"]
mod tst_test;
