#[cfg(test)]
mod h264_writer_port_test;
#[cfg(test)]
mod h26x_writer_test;

use std::io::Write;

use bytes::Bytes;
use rtp::codec::h264::H264Packet;
use rtp::codec::h265::H265Packet;
use rtp::packetizer::Depacketizer;

use crate::io::Writer;
use shared::error::Result;

const NALU_TTYPE_STAP_A: u32 = 24;
const NALU_TTYPE_SPS: u32 = 7;
const NALU_TYPE_BITMASK: u32 = 0x1F;
const ANNEXB_NALUSTART_CODE: &[u8] = &[0x00, 0x00, 0x00, 0x01];
/// Largest H.265 NAL unit reassembled from fragmentation units, as for H.264 FU-A
/// (`rtp::codec::h264::MAX_FUA_NALU_SIZE`). The depacketizer enforces it.
pub const MAX_H265_FU_NALU_SIZE: usize = rtp::codec::h265::MAX_H265_FU_NALU_SIZE;

fn is_key_frame(data: &[u8]) -> bool {
    if data.len() < 4 {
        false
    } else {
        let word = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let nalu_type = (word >> 24) & NALU_TYPE_BITMASK;
        (nalu_type == NALU_TTYPE_STAP_A && (word & NALU_TYPE_BITMASK) == NALU_TTYPE_SPS)
            || (nalu_type == NALU_TTYPE_SPS)
    }
}

enum H26xPacket {
    H264(H264Packet),
    H265(H265Packet),
}

impl H26xPacket {
    fn depacketize(&mut self, payload: &Bytes) -> Result<Bytes> {
        match self {
            H26xPacket::H264(p) => p.depacketize(payload),
            H26xPacket::H265(p) => p.depacketize(payload),
        }
    }
}

/// H26xWriter is used to take RTP packets, parse them and
/// write the data to an io.Writer.
/// Supports both H264 and H265 codecs based on the is_hevc flag.
pub struct H26xWriter<W: Write> {
    writer: W,
    packet: H26xPacket,
    is_hevc: bool,
    // H264-specific fields
    has_key_frame: bool,
}

impl<W: Write> H26xWriter<W> {
    /// new initializes a new H26x writer with an io.Writer output
    /// is_hevc: true for H265, false for H264
    pub fn new(writer: W, is_hevc: bool) -> Self {
        H26xWriter {
            writer,
            packet: if is_hevc {
                H26xPacket::H265(H265Packet::default())
            } else {
                H26xPacket::H264(H264Packet::default())
            },
            is_hevc,
            has_key_frame: false,
        }
    }
}

impl<W: Write> Writer for H26xWriter<W> {
    /// write_rtp adds a new packet and writes the appropriate headers for it
    fn write_rtp(&mut self, packet: &rtp::Packet) -> Result<()> {
        if packet.payload.is_empty() {
            return Ok(());
        }

        if self.is_hevc {
            self.write_h265(packet)
        } else {
            self.write_h264(packet)
        }
    }

    /// close closes the underlying writer
    fn close(&mut self) -> Result<()> {
        // A NAL unit whose last fragment never came stays in the depacketizer: an incomplete
        // NAL unit is not written.
        self.writer.flush()?;
        Ok(())
    }
}

impl<W: Write> H26xWriter<W> {
    fn write_h264(&mut self, packet: &rtp::Packet) -> Result<()> {
        if !self.has_key_frame {
            self.has_key_frame = is_key_frame(&packet.payload);
            if !self.has_key_frame {
                // key frame not defined yet. discarding packet
                return Ok(());
            }
        }

        let payload = self
            .packet
            .depacketize(&Bytes::copy_from_slice(&packet.payload))?;
        self.writer.write_all(&payload)?;

        Ok(())
    }

    fn write_h265(&mut self, packet: &rtp::Packet) -> Result<()> {
        // The depacketizer returns the NAL units the packet completes, as Annex B: a single
        // NAL unit, the units of an aggregation packet, a NAL unit reassembled from its
        // fragmentation units (bounded), or what a PACI packet carries. Nothing of type 48 to
        // 63 is among them (RFC 7798 section 6).
        let data = self
            .packet
            .depacketize(&Bytes::copy_from_slice(&packet.payload))?;
        self.writer.write_all(&data)?;

        Ok(())
    }
}
