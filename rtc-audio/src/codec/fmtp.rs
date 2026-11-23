//! The Opus SDP parameters (RFC 7587 section 6) and what they make the encoder do.
//!
//! Every Opus parameter in `a=fmtp` describes what its **sender** (the side that wrote the
//! description) wants to **receive**, or, for `sprop-*`, what it will send (RFC 7587 section
//! 6.1). So the encoder is configured from the remote description's parameters
//! ([`OpusEncoderConfig::for_remote`]: after negotiation the engine's negotiated codec carries
//! the remote line), and the local description states this endpoint's receive preferences
//! (the line registered in the `MediaEngine`, [`OpusFmtp::to_fmtp_line`]).

/// The Opus format parameters of RFC 7587 section 6.1.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpusFmtp {
    /// `maxplaybackrate`: the highest sample rate the receiver renders (8000 to 48000).
    pub max_playback_rate: Option<u32>,
    /// `sprop-maxcapturerate`: the highest rate the sender captures.
    pub sprop_max_capture_rate: Option<u32>,
    /// `maxptime`, milliseconds (usually `a=maxptime`; accepted here too).
    pub max_ptime: Option<u32>,
    /// `ptime`, milliseconds (usually `a=ptime`; accepted here too).
    pub ptime: Option<u32>,
    /// `minptime`, milliseconds (not in RFC 7587; WebRTC endpoints write it).
    pub min_ptime: Option<u32>,
    /// `maxaveragebitrate`, bits per second; values outside 6000..=510000 are ignored
    /// (section 6.1: "values outside this range are ignored").
    pub max_average_bitrate: Option<u32>,
    /// `stereo=1`: the receiver prefers stereo.
    pub stereo: bool,
    /// `sprop-stereo=1`: the sender is likely to send stereo.
    pub sprop_stereo: bool,
    /// `cbr=1`: the receiver prefers constant bitrate.
    pub cbr: bool,
    /// `useinbandfec=1`: the receiver can use in-band FEC.
    pub use_inband_fec: bool,
    /// `usedtx=1`: the receiver prefers DTX.
    pub use_dtx: bool,
}

fn flag(v: &str) -> bool {
    v.trim() == "1"
}

impl OpusFmtp {
    /// Parses an `a=fmtp` parameter list (`name=value;name=value`); unknown names are
    /// ignored (RFC 7587 section 7.1), malformed values are left unset.
    pub fn parse(line: &str) -> Self {
        let mut f = Self::default();
        for part in line.split(';') {
            let Some((name, value)) = part.split_once('=') else {
                continue;
            };
            let value = value.trim();
            let num = || value.parse::<u32>().ok();
            match name.trim().to_ascii_lowercase().as_str() {
                "maxplaybackrate" => f.max_playback_rate = num().filter(|r| *r > 0),
                "sprop-maxcapturerate" => f.sprop_max_capture_rate = num().filter(|r| *r > 0),
                "maxptime" => f.max_ptime = num().filter(|p| *p > 0),
                "ptime" => f.ptime = num().filter(|p| *p > 0),
                "minptime" => f.min_ptime = num().filter(|p| *p > 0),
                "maxaveragebitrate" => {
                    f.max_average_bitrate = num().filter(|b| (6000..=510_000).contains(b))
                }
                "stereo" => f.stereo = flag(value),
                "sprop-stereo" => f.sprop_stereo = flag(value),
                "cbr" => f.cbr = flag(value),
                "useinbandfec" => f.use_inband_fec = flag(value),
                "usedtx" => f.use_dtx = flag(value),
                _ => {}
            }
        }
        f
    }

    /// The parameter list, in RFC 7587's order, only what differs from the defaults.
    pub fn to_fmtp_line(&self) -> String {
        let mut parts = Vec::new();
        if let Some(v) = self.min_ptime {
            parts.push(format!("minptime={v}"));
        }
        if let Some(v) = self.max_playback_rate {
            parts.push(format!("maxplaybackrate={v}"));
        }
        if let Some(v) = self.sprop_max_capture_rate {
            parts.push(format!("sprop-maxcapturerate={v}"));
        }
        if let Some(v) = self.max_ptime {
            parts.push(format!("maxptime={v}"));
        }
        if let Some(v) = self.ptime {
            parts.push(format!("ptime={v}"));
        }
        if let Some(v) = self.max_average_bitrate {
            parts.push(format!("maxaveragebitrate={v}"));
        }
        for (on, name) in [
            (self.stereo, "stereo"),
            (self.sprop_stereo, "sprop-stereo"),
            (self.cbr, "cbr"),
            (self.use_inband_fec, "useinbandfec"),
            (self.use_dtx, "usedtx"),
        ] {
            if on {
                parts.push(format!("{name}=1"));
            }
        }
        parts.join(";")
    }

    /// What a WebRTC endpoint usually states for itself: `minptime=10;useinbandfec=1` (the
    /// engine's default Opus line).
    pub fn webrtc_default() -> Self {
        Self {
            min_ptime: Some(10),
            use_inband_fec: true,
            ..Default::default()
        }
    }
}

/// The audio bandwidths an Opus encoder can be limited to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MaxBandwidth {
    /// 4 kHz.
    Narrowband,
    /// 6 kHz.
    Mediumband,
    /// 8 kHz.
    Wideband,
    /// 12 kHz.
    Superwideband,
    /// 20 kHz.
    Fullband,
}

impl MaxBandwidth {
    /// The widest bandwidth a receiver rendering at `rate` can use (RFC 7587 section 6.1,
    /// `maxplaybackrate`: 8000 Hz is narrowband, 16000 wideband, 24000 super-wideband).
    pub fn for_playback_rate(rate: u32) -> Self {
        match rate {
            0..=8000 => Self::Narrowband,
            8001..=12_000 => Self::Mediumband,
            12_001..=16_000 => Self::Wideband,
            16_001..=24_000 => Self::Superwideband,
            _ => Self::Fullband,
        }
    }
}

/// How an Opus encoder is set up.
#[derive(Debug, Clone, PartialEq)]
pub struct OpusEncoderConfig {
    /// Channels coded: 1 or 2.
    pub channels: u16,
    /// Milliseconds of audio per packet: 10, 20, 40 or 60.
    pub frame_ms: u32,
    /// The starting bitrate, bits per second.
    pub bitrate: u32,
    /// The ceiling any later target is clamped to (`maxaveragebitrate`).
    pub max_bitrate: u32,
    /// The widest audio bandwidth coded (`maxplaybackrate`).
    pub max_bandwidth: MaxBandwidth,
    /// Constant bitrate (`cbr`).
    pub cbr: bool,
    /// In-band FEC (`useinbandfec` of the receiver).
    pub fec: bool,
    /// Discontinuous transmission (`usedtx` of the receiver).
    pub dtx: bool,
    /// Encoder complexity, 0 to 10 (libwebrtc uses 9 on desktop, 5 on mobile).
    pub complexity: u8,
    /// The share of packets the receiver loses, 0 to 100, for the encoder's FEC decision.
    pub packet_loss_percent: u8,
}

impl Default for OpusEncoderConfig {
    fn default() -> Self {
        Self {
            channels: 1,
            frame_ms: 20,
            bitrate: 32_000,
            max_bitrate: 510_000,
            max_bandwidth: MaxBandwidth::Fullband,
            cbr: false,
            fec: true,
            dtx: false,
            complexity: 9,
            packet_loss_percent: 0,
        }
    }
}

impl OpusEncoderConfig {
    /// The packet times an Opus encoder produces.
    pub const FRAME_MS: [u32; 4] = [10, 20, 40, 60];

    /// The encoder for a receiver that stated `remote` (its fmtp), and `remote_ptime` /
    /// `remote_maxptime` (its `a=ptime` / `a=maxptime`), sending audio captured with
    /// `capture_channels` channels:
    ///
    /// - stereo only when the receiver asked for it (`stereo=1`) and the capture is stereo
    ///   (RFC 7587 section 6.1: "a sender MUST NOT send stereo ... when stereo is 0");
    /// - bandwidth no wider than `maxplaybackrate` allows;
    /// - bitrate no higher than `maxaveragebitrate`, starting where libwebrtc starts (32
    ///   kbit/s per channel for full band, 20 for wideband, 12 for narrowband);
    /// - `cbr`, in-band FEC and DTX as the receiver asked;
    /// - the receiver's `ptime` (or 20 ms) as the packet time, no longer than its `maxptime`,
    ///   rounded down to a duration Opus codes.
    pub fn for_remote(
        remote: &OpusFmtp,
        remote_ptime: Option<u32>,
        remote_maxptime: Option<u32>,
        capture_channels: u16,
    ) -> Self {
        let channels = if remote.stereo && capture_channels >= 2 {
            2
        } else {
            1
        };
        let max_bandwidth = remote
            .max_playback_rate
            .map(MaxBandwidth::for_playback_rate)
            .unwrap_or(MaxBandwidth::Fullband);
        let per_channel = match max_bandwidth {
            MaxBandwidth::Narrowband | MaxBandwidth::Mediumband => 12_000,
            MaxBandwidth::Wideband => 20_000,
            _ => 32_000,
        };
        let max_bitrate = remote.max_average_bitrate.unwrap_or(510_000);
        let bitrate = (per_channel * u32::from(channels)).min(max_bitrate);
        let max_ptime = remote_maxptime.or(remote.max_ptime).unwrap_or(120);
        let want = remote_ptime.or(remote.ptime).unwrap_or(20).min(max_ptime);
        let frame_ms = Self::FRAME_MS
            .iter()
            .rev()
            .copied()
            .find(|&f| f <= want)
            .unwrap_or(10);
        Self {
            channels,
            frame_ms,
            bitrate,
            max_bitrate,
            max_bandwidth,
            cbr: remote.cbr,
            fec: remote.use_inband_fec,
            dtx: remote.use_dtx,
            ..Self::default()
        }
    }

    /// Samples per channel of one frame at 48 kHz.
    pub fn frame_samples(&self) -> usize {
        (self.frame_ms * 48) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_parse_and_write_back() {
        let f = OpusFmtp::parse(
            "minptime=10; useinbandfec=1;stereo=1;sprop-stereo=0;maxplaybackrate=16000;\
             maxaveragebitrate=24000;cbr=1;usedtx=1;maxptime=40;foo=bar",
        );
        assert_eq!(f.min_ptime, Some(10));
        assert!(f.use_inband_fec && f.stereo && !f.sprop_stereo && f.cbr && f.use_dtx);
        assert_eq!(f.max_playback_rate, Some(16_000));
        assert_eq!(f.max_average_bitrate, Some(24_000));
        assert_eq!(f.max_ptime, Some(40));
        assert_eq!(OpusFmtp::parse(&f.to_fmtp_line()), f);
        assert_eq!(
            OpusFmtp::webrtc_default().to_fmtp_line(),
            "minptime=10;useinbandfec=1"
        );
    }

    #[test]
    fn a_max_average_bitrate_outside_the_range_is_ignored() {
        assert_eq!(
            OpusFmtp::parse("maxaveragebitrate=5999").max_average_bitrate,
            None
        );
        assert_eq!(
            OpusFmtp::parse("maxaveragebitrate=510001").max_average_bitrate,
            None
        );
        assert_eq!(
            OpusFmtp::parse("maxaveragebitrate=6000").max_average_bitrate,
            Some(6000)
        );
    }

    #[test]
    fn the_encoder_follows_what_the_receiver_stated() {
        let browser = OpusFmtp::parse("minptime=10;useinbandfec=1");
        let c = OpusEncoderConfig::for_remote(&browser, None, None, 2);
        assert_eq!((c.channels, c.frame_ms, c.bitrate), (1, 20, 32_000));
        assert!(c.fec && !c.dtx && !c.cbr);
        assert_eq!(c.max_bandwidth, MaxBandwidth::Fullband);

        let narrow =
            OpusFmtp::parse("maxplaybackrate=8000;maxaveragebitrate=10000;stereo=1;usedtx=1;cbr=1");
        let c = OpusEncoderConfig::for_remote(&narrow, Some(60), Some(40), 2);
        assert_eq!(c.channels, 2);
        assert_eq!(c.max_bandwidth, MaxBandwidth::Narrowband);
        assert_eq!(c.bitrate, 10_000);
        assert_eq!(c.max_bitrate, 10_000);
        assert_eq!(c.frame_ms, 40);
        assert!(c.dtx && c.cbr && !c.fec);
        // Stereo is not sent from a mono capture, whatever the receiver prefers.
        assert_eq!(
            OpusEncoderConfig::for_remote(&narrow, None, None, 1).channels,
            1
        );
        // A ptime Opus cannot code is rounded down.
        assert_eq!(
            OpusEncoderConfig::for_remote(&browser, Some(30), None, 1).frame_ms,
            20
        );
    }
}
