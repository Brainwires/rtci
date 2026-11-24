use super::*;

const VM_REPORT_BLOCK_LENGTH: u16 = 4 + 4 + 2 * 4 + 10 + 2 * 3;

/// VoIPMetricsReportBlock encodes a VoIP Metrics Report Block as described
/// in RFC 3611, section 4.7.
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     BT=7      |   reserved    |       block length = 8        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        ssrc of source                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   loss rate   | discard rate  | burst density |  gap density  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       burst duration          |         gap duration          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     round trip delay          |       end system delay        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | signal level  |  noise level  |     RERL      |     Gmin      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   R factor    | ext. R factor |    MOS-LQ     |    MOS-CQ     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   RX config   |   reserved    |          JB nominal           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          JB maximum           |          JB abs max           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VoIPMetricsReportBlock {
    /// The SSRC these metrics describe.
    pub ssrc: u32,
    /// Fraction of packets lost, as 256ths.
    pub loss_rate: u8,
    /// Fraction of packets discarded by the jitter buffer, as 256ths.
    pub discard_rate: u8,
    /// Fraction of packets lost or discarded during bursts, as 256ths.
    pub burst_density: u8,
    /// Fraction lost or discarded during gaps between bursts, as 256ths.
    pub gap_density: u8,
    /// Mean burst length in milliseconds.
    pub burst_duration: u16,
    /// Mean gap length in milliseconds.
    pub gap_duration: u16,
    /// Round-trip delay in milliseconds.
    pub round_trip_delay: u16,
    /// End-system delay in milliseconds, covering encode, buffer and decode.
    pub end_system_delay: u16,
    /// Signal level in dBm0.
    pub signal_level: u8,
    /// Noise level in dBm0.
    pub noise_level: u8,
    /// Residual echo return loss, in dB.
    pub rerl: u8,
    /// The gap threshold: consecutive received packets needed to end a burst.
    pub gmin: u8,
    /// The R factor, a 0–100 voice-quality estimate.
    pub rfactor: u8,
    /// An external-network R factor, for the segment beyond this one.
    pub ext_rfactor: u8,
    /// Listening-quality mean opinion score, in tenths.
    pub mos_lq: u8,
    /// Conversational-quality mean opinion score, in tenths.
    pub mos_cq: u8,
    /// Receiver configuration: packet-loss concealment and jitter-buffer flags.
    pub rx_config: u8,
    /// Reserved; sent as zero.
    pub reserved: u8,
    /// Nominal jitter-buffer delay in milliseconds.
    pub jb_nominal: u16,
    /// Maximum jitter-buffer delay in milliseconds.
    pub jb_maximum: u16,
    /// The absolute maximum the jitter buffer can grow to, in milliseconds.
    pub jb_abs_max: u16,
}

/// The value of a metric that is not available (RFC 3611 §4.7.4, §4.7.5).
pub const VOIP_METRIC_UNAVAILABLE: u8 = 127;
/// The Gmin RFC 3611 §4.7.2 recommends.
pub const VOIP_METRICS_DEFAULT_GMIN: u8 = 16;

impl Default for VoIPMetricsReportBlock {
    /// A block that reports nothing: every metric that has an "unavailable" value carries it
    /// (127 for the signal, noise and echo levels, the R factors and the MOS scores), Gmin is
    /// the recommended 16, and the rest is zero, which RFC 3611 §4.7 defines as "none" or
    /// "unknown" for those fields. Fill in what is measured over `..Default::default()`.
    fn default() -> Self {
        VoIPMetricsReportBlock {
            ssrc: 0,
            loss_rate: 0,
            discard_rate: 0,
            burst_density: 0,
            gap_density: 0,
            burst_duration: 0,
            gap_duration: 0,
            round_trip_delay: 0,
            end_system_delay: 0,
            signal_level: VOIP_METRIC_UNAVAILABLE,
            noise_level: VOIP_METRIC_UNAVAILABLE,
            rerl: VOIP_METRIC_UNAVAILABLE,
            gmin: VOIP_METRICS_DEFAULT_GMIN,
            rfactor: VOIP_METRIC_UNAVAILABLE,
            ext_rfactor: VOIP_METRIC_UNAVAILABLE,
            mos_lq: VOIP_METRIC_UNAVAILABLE,
            mos_cq: VOIP_METRIC_UNAVAILABLE,
            rx_config: 0,
            reserved: 0,
            jb_nominal: 0,
            jb_maximum: 0,
            jb_abs_max: 0,
        }
    }
}

/// RFC 3611 4.7.5: an R factor is 0 to 100, or 127 when it is not available.
fn valid_rfactor(value: u8) -> bool {
    value <= 100 || value == VOIP_METRIC_UNAVAILABLE
}

/// RFC 3611 4.7.5: a MOS score is 10 to 50 (1.0 to 5.0), or 127 when it is not available.
fn valid_mos(value: u8) -> bool {
    (10..=50).contains(&value) || value == VOIP_METRIC_UNAVAILABLE
}

impl fmt::Display for VoIPMetricsReportBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl VoIPMetricsReportBlock {
    /// The XR block header describing this block's type and length.
    pub fn xr_header(&self) -> XRHeader {
        XRHeader {
            block_type: BlockType::VoIPMetrics,
            type_specific: 0,
            block_length: (self.raw_size() / 4 - 1) as u16,
        }
    }
}

impl Packet for VoIPMetricsReportBlock {
    fn header(&self) -> Header {
        Header::default()
    }

    /// destination_ssrc returns an array of ssrc values that this report block refers to.
    fn destination_ssrc(&self) -> Vec<u32> {
        vec![self.ssrc]
    }

    fn raw_size(&self) -> usize {
        XR_HEADER_LENGTH + VM_REPORT_BLOCK_LENGTH as usize
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
    fn equal(&self, other: &dyn Packet) -> bool {
        other.as_any().downcast_ref::<VoIPMetricsReportBlock>() == Some(self)
    }
    fn cloned(&self) -> Box<dyn Packet> {
        Box::new(self.clone())
    }
}

impl MarshalSize for VoIPMetricsReportBlock {
    fn marshal_size(&self) -> usize {
        self.raw_size()
    }
}

impl Marshal for VoIPMetricsReportBlock {
    /// marshal_to encodes the VoIPMetricsReportBlock in binary
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        // RFC 3611 4.7.5: values other than 127 and the valid range "MUST NOT be sent".
        if !valid_rfactor(self.rfactor)
            || !valid_rfactor(self.ext_rfactor)
            || !valid_mos(self.mos_lq)
            || !valid_mos(self.mos_cq)
        {
            return Err(Error::InvalidHeader);
        }
        // RFC 3611 4.7.6: "Gmin MUST not be zero".
        if self.gmin == 0 {
            return Err(Error::InvalidHeader);
        }
        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::BufferTooShort);
        }

        let h = self.xr_header();
        let n = h.marshal_to(buf)?;
        buf = &mut buf[n..];

        buf.put_u32(self.ssrc);
        buf.put_u8(self.loss_rate);
        buf.put_u8(self.discard_rate);
        buf.put_u8(self.burst_density);
        buf.put_u8(self.gap_density);
        buf.put_u16(self.burst_duration);
        buf.put_u16(self.gap_duration);
        buf.put_u16(self.round_trip_delay);
        buf.put_u16(self.end_system_delay);
        buf.put_u8(self.signal_level);
        buf.put_u8(self.noise_level);
        buf.put_u8(self.rerl);
        buf.put_u8(self.gmin);
        buf.put_u8(self.rfactor);
        buf.put_u8(self.ext_rfactor);
        buf.put_u8(self.mos_lq);
        buf.put_u8(self.mos_cq);
        buf.put_u8(self.rx_config);
        // "This field is reserved for future definition ... MUST be set to zero".
        buf.put_u8(0);
        buf.put_u16(self.jb_nominal);
        buf.put_u16(self.jb_maximum);
        buf.put_u16(self.jb_abs_max);

        Ok(self.marshal_size())
    }
}

impl Unmarshal for VoIPMetricsReportBlock {
    /// Unmarshal decodes the VoIPMetricsReportBlock from binary
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if raw_packet.remaining() < XR_HEADER_LENGTH {
            return Err(Error::PacketTooShort);
        }

        let xr_header = XRHeader::unmarshal(raw_packet)?;
        if xr_header.block_type != BlockType::VoIPMetrics {
            return Err(Error::WrongType);
        }
        let block_length = match xr_header.block_length.checked_mul(4) {
            Some(length) => length,
            None => return Err(Error::InvalidBlockSize),
        };
        if block_length != VM_REPORT_BLOCK_LENGTH || raw_packet.remaining() < block_length as usize
        {
            return Err(Error::PacketTooShort);
        }

        let ssrc = raw_packet.get_u32();
        let loss_rate = raw_packet.get_u8();
        let discard_rate = raw_packet.get_u8();
        let burst_density = raw_packet.get_u8();
        let gap_density = raw_packet.get_u8();
        let burst_duration = raw_packet.get_u16();
        let gap_duration = raw_packet.get_u16();
        let round_trip_delay = raw_packet.get_u16();
        let end_system_delay = raw_packet.get_u16();
        let signal_level = raw_packet.get_u8();
        let noise_level = raw_packet.get_u8();
        let rerl = raw_packet.get_u8();
        let gmin = raw_packet.get_u8();
        // RFC 3611 4.7.5: values other than 127 and the valid range "MUST be ignored by the
        // receiving system": such a value reads as not available.
        let unless = |valid: fn(u8) -> bool, value: u8| {
            if valid(value) {
                value
            } else {
                VOIP_METRIC_UNAVAILABLE
            }
        };
        let rfactor = unless(valid_rfactor, raw_packet.get_u8());
        let ext_rfactor = unless(valid_rfactor, raw_packet.get_u8());
        let mos_lq = unless(valid_mos, raw_packet.get_u8());
        let mos_cq = unless(valid_mos, raw_packet.get_u8());
        let rx_config = raw_packet.get_u8();
        // The reserved octet is ignored.
        raw_packet.advance(1);
        let reserved = 0;
        let jb_nominal = raw_packet.get_u16();
        let jb_maximum = raw_packet.get_u16();
        let jb_abs_max = raw_packet.get_u16();

        Ok(VoIPMetricsReportBlock {
            ssrc,
            loss_rate,
            discard_rate,
            burst_density,
            gap_density,
            burst_duration,
            gap_duration,
            round_trip_delay,
            end_system_delay,
            signal_level,
            noise_level,
            rerl,
            gmin,
            rfactor,
            ext_rfactor,
            mos_lq,
            mos_cq,
            rx_config,
            reserved,
            jb_nominal,
            jb_maximum,
            jb_abs_max,
        })
    }
}
