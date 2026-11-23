//! The limits an encoding is sent under: its `a=rid` restrictions combined with the other ways
//! a description restricts a stream (RFC 8851 section 8).
//!
//! RFC 8851 section 8: the rid restrictions are "intended to impose additional restrictions
//! beyond those communicated in other techniques", so the stream conforms to the smaller of each
//! pair: the codec's format parameters that are receiver limits (VP8 `max-fr`, `max-fs`, RFC 7741
//! section 6.1; H.264 `max-fs`, `max-mbps`, `max-br`, RFC 6184 section 8.1, sections 8.1.1 to
//! 8.2.4 of RFC 8851) and the section's bandwidth (`b=TIAS`, else `b=AS`, RFC 3890, RFC 8866
//! section 5.8). The image sizes of `a=imageattr` are applied by
//! [`RTCRtpSender::send_resolution`](crate::rtp_transceiver::rtp_sender::RTCRtpSender::send_resolution).

use crate::peer_connection::configuration::media_engine::{MIME_TYPE_H264, MIME_TYPE_VP8};
use crate::rtp_transceiver::rtp_sender::RTCRtpRidRestrictions;
use sdp::description::media::MediaDescription;

/// Pixels per macroblock (16 x 16), the conversion factor of RFC 8851 sections 8.1.2, 8.2.3
/// and 8.2.4.
const MACROBLOCK_PIXELS: u64 = 256;
/// A macroblock's width and height, in pixels.
const MACROBLOCK_SIDE: u64 = 16;
/// H.264 `max-br` is in units of 1200 bits per second for the NAL HRD (RFC 6184 section 8.1,
/// `cpbBrNalFactor` of H.264 Table A-1), the bit stream an RTP stream carries; RFC 8851 section
/// 8.2.2 names 1000 or 1200.
const H264_MAX_BR_FACTOR: u64 = 1200;

fn tighter(current: Option<u64>, other: Option<u64>) -> Option<u64> {
    match (current, other) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The `name=value` of an `a=fmtp` parameter list (`;`-separated), as a number.
fn fmtp_number(fmtp: &str, name: &str) -> Option<u64> {
    fmtp.split(';').find_map(|parameter| {
        let (key, value) = parameter.trim().split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

/// The section's bandwidth, in bits per second: `b=TIAS`, else `b=AS` (kilobits).
pub(crate) fn section_bandwidth(media: &MediaDescription) -> Option<u64> {
    let of = |kind: &str| {
        media
            .bandwidth
            .iter()
            .find(|b| !b.experimental && b.bandwidth_type.eq_ignore_ascii_case(kind))
            .map(|b| b.bandwidth)
    };
    of("TIAS").or_else(|| of("AS").map(|kbps| kbps.saturating_mul(1000)))
}

/// `restrictions` (an encoding's `a=rid` restrictions) tightened by the receiver limits in the
/// format parameters of the codec it is sent with (`mime_type`, `fmtp`: the remote
/// description's) and by the section's bandwidth (`bandwidth`, bits per second): each limit is
/// the smaller of the two (RFC 8851 section 8).
pub(crate) fn combined_send_restrictions(
    restrictions: &RTCRtpRidRestrictions,
    mime_type: &str,
    fmtp: &str,
    bandwidth: Option<u64>,
) -> RTCRtpRidRestrictions {
    let mut combined = restrictions.clone();
    if mime_type.eq_ignore_ascii_case(MIME_TYPE_VP8) {
        // RFC 8851 section 8.1.1: `max-fr` is `max-fps`.
        combined.max_fps = tighter(combined.max_fps, fmtp_number(fmtp, "max-fr"));
        // Section 8.1.2: `max-fs` (macroblocks) bounds the frame size, and the width and
        // height by `int(sqrt(max-fs * 8))` macroblocks (RFC 7741 section 6.1).
        if let Some(max_fs) = fmtp_number(fmtp, "max-fs") {
            combined.max_fs = tighter(
                combined.max_fs,
                Some(max_fs.saturating_mul(MACROBLOCK_PIXELS)),
            );
            let side = ((max_fs.saturating_mul(8)) as f64).sqrt() as u64 * MACROBLOCK_SIDE;
            combined.max_width = tighter(combined.max_width, Some(side));
            combined.max_height = tighter(combined.max_height, Some(side));
        }
    } else if mime_type.eq_ignore_ascii_case(MIME_TYPE_H264) {
        // Sections 8.2.2 to 8.2.4. The level's own limits (H.264 Table A-1) are not applied:
        // only parameters the description states.
        combined.max_br = tighter(
            combined.max_br,
            fmtp_number(fmtp, "max-br").map(|br| br.saturating_mul(H264_MAX_BR_FACTOR)),
        );
        combined.max_fs = tighter(
            combined.max_fs,
            fmtp_number(fmtp, "max-fs").map(|fs| fs.saturating_mul(MACROBLOCK_PIXELS)),
        );
        combined.max_pps = tighter(
            combined.max_pps,
            fmtp_number(fmtp, "max-mbps").map(|mbps| mbps.saturating_mul(MACROBLOCK_PIXELS)),
        );
    }
    combined.max_br = tighter(combined.max_br, bandwidth);
    combined
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_smaller_of_each_rid_and_format_limit_applies() {
        let rid = RTCRtpRidRestrictions {
            max_fps: Some(30),
            max_width: Some(1280),
            max_br: Some(2_000_000),
            ..Default::default()
        };
        // VP8 max-fs=3600 macroblocks: 921600 pixels, sides up to int(sqrt(28800)) = 169
        // macroblocks (2704 pixels), so the rid's width stays.
        let vp8 = combined_send_restrictions(&rid, MIME_TYPE_VP8, "max-fr=15;max-fs=3600", None);
        assert_eq!(vp8.max_fps, Some(15));
        assert_eq!(vp8.max_fs, Some(921_600));
        assert_eq!(vp8.max_width, Some(1280));
        assert_eq!(vp8.max_height, Some(2704));
        assert_eq!(vp8.max_br, Some(2_000_000));

        let h264 = combined_send_restrictions(
            &rid,
            MIME_TYPE_H264,
            "profile-level-id=42e01f; max-br=1000; max-mbps=40500",
            Some(500_000),
        );
        assert_eq!(h264.max_br, Some(500_000), "b=TIAS is the tighter");
        assert_eq!(h264.max_pps, Some(40_500 * 256));
        assert_eq!(h264.max_fps, Some(30), "H.264 states no frame rate");
    }
}
