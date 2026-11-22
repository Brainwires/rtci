#[cfg(test)]
mod packetizer_rules_test;
#[cfg(test)]
mod packetizer_test;

use crate::{extension::abs_send_time_extension::*, header::*, packet::*, sequence::*};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize},
    time::SystemInstant,
};

use bytes::{Bytes, BytesMut};
use std::fmt;
use std::time::Instant;

/// Bytes of fixed RTP header a packetizer leaves room for in the MTU (RFC 3550 section 5.1).
pub const RTP_FIXED_HEADER_SIZE: usize = 12;

/// Which packets of a payload format carry the RTP marker bit. The bit's meaning is the
/// profile's and the payload format's (RFC 3550 section 5.1), so the payloader says.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum MarkerRule {
    /// Video: the last packet of the frame, which is the last payload of a
    /// [`Packetizer::packetize`] call (RFC 6184 section 5.1, RFC 7798 section 4.1, RFC 7741
    /// section 4.1).
    #[default]
    LastPacketOfFrame,
    /// Audio: the first packet of a talkspurt, that is the first packet after a silence the
    /// caller reported with [`Packetizer::skip_samples`], and no other (RFC 3551 section 4.1,
    /// RFC 7587 section 4.1). A stream without silence suppression never sets it.
    FirstPacketOfTalkspurt,
    /// Never set: comfort noise (RFC 3389 section 4).
    Never,
}

/// Payloader payloads a byte array for use as rtp.Packet payloads
pub trait Payloader: Send + Sync + fmt::Debug {
    /// Splits one encoded frame into payloads no larger than `mtu`.
    ///
    /// # Errors
    ///
    /// Fails if the frame is malformed for this codec, or `mtu` is too small to make progress.
    fn payload(&mut self, mtu: usize, b: &Bytes) -> Result<Vec<Bytes>>;
    /// Which packets carry the marker bit. Video unless the payloader says otherwise.
    fn marker_rule(&self) -> MarkerRule {
        MarkerRule::LastPacketOfFrame
    }
    /// For a sample-based format, the RTP timestamp units one payload of
    /// [`payload`](Payloader::payload) covers, so that a frame split over several packets gets
    /// a timestamp per packet (RFC 3551 section 4.3: the timestamp is the sampling instant of
    /// the packet's first sample). `None`, the default, is a frame-based format: every packet
    /// of the frame carries the frame's timestamp.
    fn payload_duration(&self, _payload: &Bytes) -> Option<u32> {
        None
    }
    /// Clones this payloader behind a trait object.
    fn clone_to(&self) -> Box<dyn Payloader>;
}

impl Clone for Box<dyn Payloader> {
    fn clone(&self) -> Box<dyn Payloader> {
        self.clone_to()
    }
}

/// Packetizer packetizes a payload
pub trait Packetizer: Send + Sync + fmt::Debug {
    /// Attaches the absolute-send-time header extension under id `value`.
    fn enable_abs_send_time(&mut self, value: u8);
    /// Packetizes one frame, advancing the timestamp by `samples`.
    ///
    /// Assigns sequence numbers, sets the marker bit as the payload format has it (see
    /// [`MarkerRule`]: the final packet of a video frame, the first packet of an audio
    /// talkspurt) and applies any enabled header extensions. `now` is the instant the frame is being sent at; it is what
    /// the absolute-send-time extension is derived from, so the caller supplies it rather than
    /// the packetizer sampling a clock of its own.
    ///
    /// # Errors
    ///
    /// Propagates payloader failures, and fails when the MTU leaves no room for a payload
    /// after the 12-byte RTP header.
    fn packetize(&mut self, now: Instant, payload: &Bytes, samples: u32) -> Result<Vec<Packet>>;
    /// Advances the timestamp without sending anything, for dropped or silent frames. For an
    /// audio format this is a silence period: the next packet starts a talkspurt and carries
    /// the marker bit (RFC 3551 section 4.1; Opus DTX, RFC 7587 section 3.1.3).
    fn skip_samples(&mut self, skipped_samples: u32);
    /// Clones this packetizer behind a trait object.
    fn clone_to(&self) -> Box<dyn Packetizer>;
}

impl Clone for Box<dyn Packetizer> {
    fn clone(&self) -> Box<dyn Packetizer> {
        self.clone_to()
    }
}

/// Depacketizer depacketizes a RTP payload, removing any RTP specific data from the payload
pub trait Depacketizer {
    /// Reassembles a frame from one RTP payload, buffering fragments as needed.
    ///
    /// # Errors
    ///
    /// Fails if the payload is malformed for this codec.
    fn depacketize(&mut self, b: &Bytes) -> Result<Bytes>;

    /// Checks if the packet is at the beginning of a partition.  This
    /// should return false if the result could not be determined, in
    /// which case the caller will detect timestamp discontinuities.
    fn is_partition_head(&self, payload: &Bytes) -> bool;

    /// Checks if the packet is at the end of a partition.  This should
    /// return false if the result could not be determined.
    fn is_partition_tail(&self, marker: bool, payload: &Bytes) -> bool;
}

#[derive(Clone)]
pub(crate) struct PacketizerImpl {
    pub(crate) mtu: usize,
    pub(crate) payload_type: u8,
    pub(crate) ssrc: u32,
    pub(crate) payloader: Box<dyn Payloader>,
    pub(crate) sequencer: Box<dyn Sequencer>,
    pub(crate) timestamp: u32,
    pub(crate) clock_rate: u32,
    pub(crate) abs_send_time_ext_id: u8, //http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
    pub(crate) time_baseline: SystemInstant,
    /// A silence was skipped since the last packet: the next one starts a talkspurt.
    pub(crate) talkspurt_start: bool,
}

impl fmt::Debug for PacketizerImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketizerImpl")
            .field("mtu", &self.mtu)
            .field("payload_type", &self.payload_type)
            .field("ssrc", &self.ssrc)
            .field("timestamp", &self.timestamp)
            .field("clock_rate", &self.clock_rate)
            .field("abs_send_time_ext_id", &self.abs_send_time_ext_id)
            .finish()
    }
}

/// Builds a packetizer for one outbound stream.
///
/// Ties together the codec's payloader, a sequencer, and the SSRC, payload type, MTU and clock
/// rate the stream was negotiated with.
pub fn new_packetizer(
    now: Instant,
    mtu: usize,
    payload_type: u8,
    ssrc: u32,
    payloader: Box<dyn Payloader>,
    sequencer: Box<dyn Sequencer>,
    clock_rate: u32,
) -> impl Packetizer {
    PacketizerImpl {
        mtu,
        payload_type,
        ssrc,
        payloader,
        sequencer,
        timestamp: rand::random::<u32>(),
        clock_rate,
        abs_send_time_ext_id: 0,
        time_baseline: SystemInstant::now(now),
        talkspurt_start: false,
    }
}

impl Packetizer for PacketizerImpl {
    fn enable_abs_send_time(&mut self, id: u8) {
        self.abs_send_time_ext_id = id
    }

    fn packetize(&mut self, now: Instant, payload: &Bytes, samples: u32) -> Result<Vec<Packet>> {
        // What the MTU leaves once the fixed header is written. An MTU that leaves nothing
        // cannot carry media.
        let payload_mtu = self
            .mtu
            .checked_sub(RTP_FIXED_HEADER_SIZE)
            .filter(|&payload_mtu| payload_mtu > 0)
            .ok_or_else(|| {
                Error::Other(format!(
                    "an RTP MTU of {} bytes leaves no room for a payload after the \
                     {RTP_FIXED_HEADER_SIZE}-byte header",
                    self.mtu
                ))
            })?;
        let payloads = self.payloader.payload(payload_mtu, payload)?;
        let payloads_len = payloads.len();
        let marker_rule = self.payloader.marker_rule();
        let mut packets = Vec::with_capacity(payloads_len);
        // A sample-based payload split over several packets: each packet's timestamp is that
        // of its first sample (RFC 3551 section 4.3).
        let mut timestamp = self.timestamp;
        for (i, payload) in payloads.into_iter().enumerate() {
            let marker = match marker_rule {
                MarkerRule::LastPacketOfFrame => i == payloads_len - 1,
                MarkerRule::FirstPacketOfTalkspurt => std::mem::take(&mut self.talkspurt_start),
                MarkerRule::Never => false,
            };
            let duration = self.payloader.payload_duration(&payload);
            packets.push(Packet {
                header: Header {
                    version: 2,
                    padding: false,
                    extension: false,
                    marker,
                    payload_type: self.payload_type,
                    sequence_number: self.sequencer.next_sequence_number(),
                    timestamp,
                    ssrc: self.ssrc,
                    ..Default::default()
                },
                payload,
            });
            if let Some(duration) = duration {
                timestamp = timestamp.wrapping_add(duration);
            }
        }

        self.timestamp = self.timestamp.wrapping_add(samples);

        if payloads_len != 0 && self.abs_send_time_ext_id != 0 {
            let send_time = AbsSendTimeExtension::new(self.time_baseline.ntp(now));
            //apply http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
            let mut raw = BytesMut::with_capacity(send_time.marshal_size());
            raw.resize(send_time.marshal_size(), 0);
            let _ = send_time.marshal_to(&mut raw)?;
            packets[payloads_len - 1]
                .header
                .set_extension(self.abs_send_time_ext_id, raw.freeze())?;
        }

        Ok(packets)
    }

    /// skip_samples causes a gap in sample count between Packetize requests so the
    /// RTP payloads produced have a gap in timestamps
    fn skip_samples(&mut self, skipped_samples: u32) {
        self.timestamp = self.timestamp.wrapping_add(skipped_samples);
        self.talkspurt_start = true;
    }

    fn clone_to(&self) -> Box<dyn Packetizer> {
        Box::new(self.clone())
    }
}
